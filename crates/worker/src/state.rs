use bitcoin::{Block, CompactTarget, params::Params};
use strata_asm_common::{AnchorState, AuxData, HeaderVerificationState};
use strata_asm_logs::extract_next_predicate_from_logs;
use strata_asm_stf::AsmStfOutput;
use strata_btc_types::BlockHashExt;
use strata_btc_verification::{
    TxidInclusionProof, compute_block_hash, get_relative_difficulty_adjustment_height,
};
use strata_identifiers::L1BlockCommitment;
use strata_predicate::PredicateKey;
use strata_service::ServiceState;
use tracing::field::Empty;

use crate::{
    AnchorMismatch, ExecutionRegistry, L1DataProvider, ManifestMmrStore, Subscribers,
    WorkerContext, WorkerError, WorkerResult, aux_resolver::AuxDataResolver, constants,
};

/// Service state for the ASM worker.
///
/// Resolves the parent's execution predicate before preprocessing and execution.
#[derive(Debug)]
pub struct AsmWorkerServiceState<W> {
    /// Context for the state to interact with outer world.
    pub(crate) context: W,

    registry: ExecutionRegistry,
    genesis_block: L1BlockCommitment,
    genesis_predicate: PredicateKey,
    next_predicate: PredicateKey,

    /// Current ASM anchor state.
    pub anchor: AnchorState,

    /// Current anchor block.
    pub blkid: L1BlockCommitment,

    /// L1 genesis block height. The MMR is height-indexed and prefilled with
    /// sentinels for heights `0..=genesis_height`, so this is the height just
    /// below the first real manifest.
    pub(crate) genesis_height: u64,

    /// Registry of ASM-commit subscribers. After each successful anchor commit
    /// the service fans the new commitment out to these; see
    /// [`crate::AsmWorkerHandle::subscribe_blocks`].
    pub(crate) subscribers: Subscribers<L1BlockCommitment>,
}

impl<W> AsmWorkerServiceState<W>
where
    W: WorkerContext + Send + Sync + 'static,
{
    /// Creates a new service state, loading the latest anchor or creating genesis.
    ///
    /// Construction goes through [`crate::AsmWorkerBuilder`], which owns the
    /// shared [`Subscribers`] registry — hence `pub(crate)`.
    pub(crate) fn new(
        context: W,
        genesis_state: AnchorState,
        genesis_predicate: PredicateKey,
        registry: ExecutionRegistry,
        subscribers: Subscribers<L1BlockCommitment>,
    ) -> WorkerResult<Self> {
        if registry.resolve(&genesis_predicate)?.spec_id() != genesis_state.spec_id {
            return Err(WorkerError::GenesisSpecMismatch);
        }
        let genesis_block = genesis_state.last_processed_block();
        let genesis_height = u64::from(genesis_block.height());

        // Align the manifest MMR with L1 heights before processing any block:
        // it is height-indexed, prefilled with sentinels for heights
        // `0..=genesis_height` so the manifest for height `h` lands at index
        // `h`. Idempotent, so safe to run on every startup.
        context.prefill_manifest_mmr(genesis_height)?;

        // The configured anchor is otherwise trusted blindly: a wrong block,
        // target, epoch timestamp, or network would only surface one L1 block
        // later when header verification rejects the anchor's successor. Build
        // the genesis state once (it carries the anchor-derived header
        // verification fields) and validate it against the L1 source on every
        // startup, before adopting either stored or genesis state.
        validate_anchor_against_l1(&context, &genesis_state.chain_view.pow_state)?;

        let latest = context.get_latest_anchor_state()?;
        match context.get_anchor_state(&genesis_block) {
            Ok(stored) if stored != genesis_state => return Err(WorkerError::GenesisStateMismatch),
            Err(WorkerError::MissingAsmState(_)) if latest.is_some() => {
                return Err(WorkerError::MissingGenesisState);
            }
            Ok(_) | Err(WorkerError::MissingAsmState(_)) => {}
            Err(error) => return Err(error),
        }
        let anchor = match latest {
            Some(state) => {
                tracing::info!(blkid = %state.last_processed_block(), "ASM worker resuming from stored anchor state");
                state
            }
            None => {
                tracing::info!(genesis_blk = %genesis_state.last_processed_block(), "no stored ASM state; initializing genesis anchor");

                context.store_anchor_state(&genesis_state)?;
                genesis_state
            }
        };
        let blkid = anchor.last_processed_block();

        let next_predicate = recover_from_context(
            &context,
            &registry,
            genesis_block,
            &genesis_predicate,
            &anchor,
        )?;
        Ok(Self {
            context,
            registry,
            genesis_block,
            genesis_predicate,
            next_predicate,
            anchor,
            blkid,
            genesis_height,
            subscribers,
        })
    }

    /// L1 block height of the chain genesis (anchor) block.
    pub(crate) fn genesis_height(&self) -> u64 {
        self.genesis_height
    }

    /// Returns the actual ASM STF results and the auxiliary data used during the transition.
    ///
    /// A caller is responsible for ensuring the current anchor is a parent of a passed block.
    pub fn transition(&self, block: &Block) -> WorkerResult<(AsmStfOutput, AuxData)> {
        let cur_state = &self.anchor;
        let target = self.registry.resolve(&self.next_predicate)?;

        // Pre process transition next block against current anchor state.
        let pre_process = {
            let span = tracing::debug_span!("asm.stf.pre_process", protocol_txs = Empty);
            let _guard = span.enter();

            let result = target
                .preprocess(cur_state, block)
                .map_err(WorkerError::AsmError)?;

            span.record("protocol_txs", result.txs.len());
            result
        };

        // Resolve auxiliary data requests from subprotocols
        let aux_data = {
            let span = tracing::debug_span!("asm.stf.aux_resolve");
            let _guard = span.enter();

            // Snapshot proofs at the accumulator's own leaf count: a verifier
            // checks them against this accumulator's committed root, so the
            // snapshot size must be that accumulator's.
            let accumulator = &cur_state.chain_view.history_accumulator;
            let resolver = AuxDataResolver::new(&self.context, accumulator.num_entries());
            resolver.resolve(&pre_process.aux_requests)?
        };

        // Asm transition.
        let stf_span = tracing::debug_span!("asm.stf.process");
        let _stf_guard = stf_span.enter();

        // The block comes from our own L1 source, so it has a coinbase and this is `Some`. It is
        // `None` only for a block with no transactions, which the STF then rejects with
        // `L1BodyError::EmptyBlock`.
        let coinbase_inclusion_proof = TxidInclusionProof::generate(&block.txdata, 0);

        target
            .transition(
                cur_state,
                block,
                &aux_data,
                coinbase_inclusion_proof.as_ref(),
            )
            .map(|output| (output, aux_data))
            .map_err(WorkerError::AsmError)
    }

    /// Restores authority from the selected anchor and its own committed manifest.
    pub(crate) fn restore_anchor(
        &mut self,
        anchor: AnchorState,
        block: L1BlockCommitment,
    ) -> WorkerResult<()> {
        if block != self.blkid {
            let predicate = recover_from_context(
                &self.context,
                &self.registry,
                self.genesis_block,
                &self.genesis_predicate,
                &anchor,
            )?;
            self.next_predicate = predicate;
        }
        self.update_anchor_state(anchor, block);
        Ok(())
    }

    /// Advances execution authority only after all block writes have succeeded.
    pub(crate) fn accept_output(&mut self, output: AsmStfOutput, block: L1BlockCommitment) {
        if let Some(predicate) = extract_next_predicate_from_logs(output.manifest.logs()) {
            self.next_predicate = predicate;
        }
        self.update_anchor_state(output.state, block);
    }

    /// Updates anchor related bookkeeping.
    pub(crate) fn update_anchor_state(&mut self, anchor: AnchorState, blkid: L1BlockCommitment) {
        self.anchor = anchor;
        self.blkid = blkid;
    }
}

impl<W> ServiceState for AsmWorkerServiceState<W>
where
    W: WorkerContext + Send + Sync + 'static,
{
    fn name(&self) -> &str {
        constants::SERVICE_NAME
    }
}

fn recover_from_context<C: ManifestMmrStore>(
    context: &C,
    registry: &ExecutionRegistry,
    genesis: L1BlockCommitment,
    genesis_predicate: &PredicateKey,
    anchor: &AnchorState,
) -> WorkerResult<PredicateKey> {
    let block = anchor.last_processed_block();
    // Genesis has no STF manifest; its authority is validated during worker initialization.
    if block == genesis {
        return Ok(genesis_predicate.clone());
    }
    if block.height() <= genesis.height() {
        return Err(WorkerError::InvalidRecoveryAnchor(block));
    }
    let manifest = context.get_manifest(&block)?;
    registry.recover_predicate(anchor, &manifest)
}

/// Validates that the configured anchor matches the actual L1 chain.
///
/// The anchor in `params` is the trusted point from which header verification
/// begins; if any of its fields is wrong the error only surfaces one L1 block
/// later, when the anchor's successor fails verification. Re-derive every field
/// from the L1 source at startup and reject a mismatch up front. `pow_state` is
/// the header-verification state built from the configured anchor.
///
/// Checked, against the block at the anchor height and its difficulty-epoch
/// start block on the active chain:
///
/// - `network` matches the backing L1 source;
/// - `last_verified_block` is the block actually at that height;
/// - `epoch_start_timestamp` is the timestamp of the current epoch's first block;
/// - `next_block_target` is the target the anchor's successor must satisfy.
fn validate_anchor_against_l1<W: L1DataProvider>(
    context: &W,
    pow_state: &HeaderVerificationState,
) -> WorkerResult<()> {
    let height = pow_state.last_verified_block.height();

    // Network must match the backing L1 source.
    let l1_network = context.get_network()?;
    let anchor_network = pow_state.network();
    if l1_network != anchor_network {
        return Err(AnchorMismatch::Network {
            anchor: anchor_network,
            l1: l1_network,
        }
        .into());
    }
    let btc_params = Params::from(l1_network);

    // The anchor must commit to the block actually at that height on the chain.
    let anchor_header = context.get_l1_block_header_at_height(height)?;
    let actual_blkid = compute_block_hash(&anchor_header).to_l1_block_id();
    let anchor_blkid = *pow_state.last_verified_block.blkid();
    if actual_blkid != anchor_blkid {
        return Err(AnchorMismatch::Block {
            height: height as u64,
            anchor: anchor_blkid,
            l1: actual_blkid,
        }
        .into());
    }

    // The epoch-start timestamp must be the timestamp of the first block of the
    // anchor's current difficulty-adjustment epoch.
    let epoch_start_height = get_relative_difficulty_adjustment_height(0, height, &btc_params);
    let epoch_start_header = context.get_l1_block_header_at_height(epoch_start_height)?;
    if epoch_start_header.time != pow_state.epoch_start_timestamp() {
        return Err(AnchorMismatch::EpochStartTimestamp {
            epoch_start_height: epoch_start_height as u64,
            anchor: pow_state.epoch_start_timestamp(),
            l1: epoch_start_header.time,
        }
        .into());
    }

    // The next-block target must match what the anchor's successor is required
    // to satisfy: a freshly retargeted value when the successor lands on a
    // difficulty-adjustment boundary, otherwise the anchor block's own target.
    let interval = btc_params.difficulty_adjustment_interval();
    let expected_next_target = if (height as u64 + 1).is_multiple_of(interval) {
        CompactTarget::from_next_work_required(
            anchor_header.bits,
            (anchor_header.time.saturating_sub(epoch_start_header.time)) as u64,
            &btc_params,
        )
        .to_consensus()
    } else {
        anchor_header.bits.to_consensus()
    };
    if expected_next_target != pow_state.next_block_target() {
        return Err(AnchorMismatch::NextTarget {
            anchor: pow_state.next_block_target(),
            l1: expected_next_target,
        }
        .into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use bitcoin::Network;
    use bitcoind_async_client::{Auth, Client, traits::Reader};
    use strata_asm_common::{AsmLogEntry, AsmManifest, AsmSpec};
    use strata_asm_logs::AsmStfUpdate;
    use strata_btc_verification::L1Anchor;
    use strata_identifiers::{Buf32, L1BlockId};
    use strata_test_utils_btc::BtcMainnetSegment;
    use strata_test_utils_btcio::mine_blocks;

    use super::*;
    use crate::{
        AnchorStateStore, L1DataProvider, ManifestMmrStore,
        test_utils::{
            TestAsmWorkerContext,
            fixtures::{self, TestAsmSpec},
            get_l1_anchor,
        },
    };

    /// `transition` runs the STF for a child of the current anchor.
    #[tokio::test]
    async fn recovery_reads_only_the_selected_manifest_and_skips_genesis() {
        // The context uses real local stores; recovery must not need Bitcoin RPC.
        let client = Client::new(
            "http://127.0.0.1:1".into(),
            Auth::UserPass("test".into(), "test".into()),
            None,
            None,
            None,
        )
        .unwrap();
        let context = TestAsmWorkerContext::new(client);
        let block = BtcMainnetSegment::load_full_block();
        let genesis = L1BlockCommitment::new(
            block.bip34_block_height().unwrap() as u32 - 1,
            block.header.prev_blockhash.to_l1_block_id(),
        );
        let anchor = TestAsmSpec.construct_genesis_state(&fixtures::TestAsmParams {
            anchor: L1Anchor {
                block: genesis,
                next_target: block.header.bits.to_consensus(),
                epoch_start_timestamp: 0,
                network: Network::Bitcoin,
            },
            magic: (*b"test").into(),
        });
        let initial = PredicateKey::always_accept();
        let mut registry = ExecutionRegistry::default();
        registry.register(initial.clone(), TestAsmSpec).unwrap();
        assert_eq!(
            recover_from_context(&context, &registry, genesis, &initial, &anchor).unwrap(),
            initial
        );
        let mut selected = anchor.clone();
        selected.chain_view.pow_state.last_verified_block = L1BlockCommitment::new(
            genesis.height() + 100_000,
            L1BlockId::from(Buf32::from([1; 32])),
        );
        let tip = selected.last_processed_block();
        assert!(matches!(
            recover_from_context(&context, &registry, genesis, &initial, &selected),
            Err(WorkerError::MissingManifest(block)) if block == tip
        ));
        context
            .put_manifest(
                AsmManifest::new(
                    tip.height(),
                    *tip.blkid(),
                    Buf32::from([0; 32]).into(),
                    vec![],
                )
                .unwrap(),
            )
            .unwrap();
        // No earlier manifests exist, so a backward scan would fail.
        assert_eq!(
            recover_from_context(&context, &registry, genesis, &initial, &selected).unwrap(),
            initial
        );
        let update =
            AsmLogEntry::from_log(&AsmStfUpdate::new(PredicateKey::never_accept())).unwrap();
        context
            .put_manifest(
                AsmManifest::new(
                    tip.height(),
                    *tip.blkid(),
                    Buf32::from([0; 32]).into(),
                    vec![update],
                )
                .unwrap(),
            )
            .unwrap();
        assert_eq!(
            recover_from_context(&context, &registry, genesis, &initial, &selected).unwrap(),
            PredicateKey::never_accept()
        );
        selected.chain_view.pow_state.last_verified_block =
            L1BlockCommitment::new(genesis.height(), *tip.blkid());
        assert!(matches!(
            recover_from_context(&context, &registry, genesis, &initial, &selected),
            Err(WorkerError::InvalidRecoveryAnchor(_))
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn transition_processes_child_of_anchor() {
        let fx = fixtures::setup_state(101).await;
        // A child of the genesis anchor: height 102, parent 101.
        let hashes = mine_blocks(&fx.node, &fx.client, 1, None)
            .await
            .expect("mine child block");
        let block = fx.client.get_block(&hashes[0]).await.expect("fetch block");

        fx.state
            .transition(&block)
            .expect("transition of the anchor's child should succeed");
    }

    /// Over an empty store, `new` constructs and persists the genesis anchor.
    #[tokio::test(flavor = "multi_thread")]
    async fn new_creates_genesis_when_store_empty() {
        let fx = fixtures::setup_state(101).await;

        assert_eq!(
            fx.state.blkid.height(),
            101,
            "genesis sits at the anchor height",
        );
        assert!(
            fx.state.context.get_anchor_state(&fx.state.blkid).is_ok(),
            "genesis anchor persisted",
        );
        let latest = fx.state.context.get_latest_anchor_state().unwrap();
        assert_eq!(
            latest.map(|s| s.last_processed_block()),
            Some(fx.state.blkid)
        );
    }

    /// When the store already holds a latest anchor, `new` adopts it — a worker
    /// restart resumes from the DB rather than reconstructing genesis.
    #[tokio::test(flavor = "multi_thread")]
    async fn new_adopts_stored_latest() {
        let seed = fixtures::setup_state(101).await;

        // Prior progress: process one real block so a genuine anchor for height
        // 102 lands in the store as the new latest.
        let advanced = fixtures::mine(&seed.node, &seed.client, 1).await[0]; // 102
        let block = seed
            .state
            .context
            .get_l1_block(advanced.blkid())
            .expect("fetch block 102");
        let (out, _aux) = seed.state.transition(&block).expect("process block 102");
        seed.state
            .context
            .record_manifest(out.manifest.clone())
            .unwrap();
        seed.state
            .context
            .store_anchor_state(&out.state)
            .expect("store the processed anchor");

        // A fresh service over the same store resumes from that stored anchor
        // rather than reconstructing genesis.
        let params = fixtures::genesis_params(&seed.client, 101).await;
        let reloaded = fixtures::new_state(seed.state.context.clone(), params).unwrap();

        assert_eq!(
            reloaded.blkid, advanced,
            "adopted the stored latest, not genesis",
        );
    }

    /// Builds the genesis `pow_state` for an anchor pinned at `height`, after
    /// optionally tampering with the anchor's fields.
    async fn pow_state_for(
        client: &Client,
        height: u64,
        tamper: impl FnOnce(&mut L1Anchor),
    ) -> HeaderVerificationState {
        let hash = client.get_block_hash(height).await.unwrap();
        let mut anchor = get_l1_anchor(client, &hash).await.unwrap();
        tamper(&mut anchor);
        let params = fixtures::TestAsmParams {
            anchor,
            magic: strata_l1_txfmt::MagicBytes::new(*b"ALPN"),
        };
        TestAsmSpec
            .construct_genesis_state(&params)
            .chain_view
            .pow_state
    }

    /// A correctly derived anchor passes L1 validation. (Implicitly exercised by
    /// every `setup_state` call, since `new` validates — asserted directly here.)
    #[tokio::test(flavor = "multi_thread")]
    async fn validate_anchor_accepts_correct_anchor() {
        let fx = fixtures::setup_context(101).await;
        let pow = pow_state_for(&fx.client, 101, |_| {}).await;
        validate_anchor_against_l1(&fx.context, &pow).expect("a correct anchor validates");
    }

    /// An anchor that commits to the wrong block at its height is rejected.
    #[tokio::test(flavor = "multi_thread")]
    async fn validate_anchor_rejects_wrong_block() {
        let fx = fixtures::setup_context(101).await;
        let wrong = fx.client.get_block_hash(50).await.unwrap();
        let pow = pow_state_for(&fx.client, 101, |a| {
            a.block = L1BlockCommitment::new(101, wrong.to_l1_block_id());
        })
        .await;

        let err = validate_anchor_against_l1(&fx.context, &pow).unwrap_err();
        assert!(
            matches!(
                err,
                WorkerError::AnchorMismatch(AnchorMismatch::Block { .. })
            ),
            "expected AnchorMismatch::Block, got {err:?}",
        );
    }

    /// An anchor whose epoch-start timestamp doesn't match L1 is rejected.
    #[tokio::test(flavor = "multi_thread")]
    async fn validate_anchor_rejects_wrong_epoch_timestamp() {
        let fx = fixtures::setup_context(101).await;
        let pow = pow_state_for(&fx.client, 101, |a| {
            a.epoch_start_timestamp = a.epoch_start_timestamp.wrapping_add(1);
        })
        .await;

        let err = validate_anchor_against_l1(&fx.context, &pow).unwrap_err();
        assert!(
            matches!(
                err,
                WorkerError::AnchorMismatch(AnchorMismatch::EpochStartTimestamp { .. })
            ),
            "expected AnchorMismatch::EpochStartTimestamp, got {err:?}",
        );
    }

    /// An anchor whose next-block target doesn't match L1 is rejected.
    #[tokio::test(flavor = "multi_thread")]
    async fn validate_anchor_rejects_wrong_next_target() {
        let fx = fixtures::setup_context(101).await;
        let pow = pow_state_for(&fx.client, 101, |a| {
            a.next_target = a.next_target.wrapping_add(1);
        })
        .await;

        let err = validate_anchor_against_l1(&fx.context, &pow).unwrap_err();
        assert!(
            matches!(
                err,
                WorkerError::AnchorMismatch(AnchorMismatch::NextTarget { .. })
            ),
            "expected AnchorMismatch::NextTarget, got {err:?}",
        );
    }

    /// An anchor declaring a different network than the L1 source is rejected.
    #[tokio::test(flavor = "multi_thread")]
    async fn validate_anchor_rejects_wrong_network() {
        let fx = fixtures::setup_context(101).await;
        let pow = pow_state_for(&fx.client, 101, |a| {
            a.network = bitcoin::Network::Bitcoin;
        })
        .await;

        let err = validate_anchor_against_l1(&fx.context, &pow).unwrap_err();
        assert!(
            matches!(
                err,
                WorkerError::AnchorMismatch(AnchorMismatch::Network { .. })
            ),
            "expected AnchorMismatch::Network, got {err:?}",
        );
    }

    /// `new` prefills the manifest MMR with one sentinel per height up to genesis,
    /// and re-running it on the same store is a no-op (restart safety).
    #[tokio::test(flavor = "multi_thread")]
    async fn new_prefills_mmr_to_genesis_height() {
        let fx = fixtures::setup_state(101).await;
        // Sentinels for heights 0..=101.
        assert_eq!(fx.state.context.mmr_leaf_count(), 102);

        let context = fx.state.context.clone();
        let params = fixtures::genesis_params(&fx.client, 101).await;
        fixtures::new_state(context, params).unwrap();

        assert_eq!(
            fx.state.context.mmr_leaf_count(),
            102,
            "prefill is idempotent across restart",
        );
    }
}
