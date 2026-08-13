use bitcoin::{Block, CompactTarget, params::Params};
use strata_asm_common::{AnchorState, AsmLogEntry, AsmSpec, AuxData, HeaderVerificationState};
use strata_asm_logs::AsmStfUpdate;
use strata_asm_params::{SpecSchedule, SpecScheduleError};
use strata_asm_stf::AsmStfOutput;
use strata_btc_types::BlockHashExt;
use strata_btc_verification::{
    TxidInclusionProof, compute_block_hash, get_relative_difficulty_adjustment_height,
};
use strata_identifiers::{L1BlockCommitment, L1Height};
use strata_service::ServiceState;
use tracing::field::Empty;

use crate::{
    AnchorMismatch, L1DataProvider, SpecActivationRecord, Subscribers, WorkerContext, WorkerError,
    WorkerResult, aux_resolver::AuxDataResolver, constants,
};

/// Service state for the ASM worker.
///
/// Generic over the worker context `W` and the ASM spec `S`, so callers can
/// inject alternative specs wrapping `StrataAsmSpec` (e.g. for testing) without
/// forking the worker.
#[derive(Debug)]
pub struct AsmWorkerServiceState<W, S: AsmSpec> {
    /// Context for the state to interact with outer world.
    pub(crate) context: W,

    /// ASM spec driving the subprotocol pipeline.
    pub(crate) spec: S,

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

    /// Base spec schedule, as configured via params.
    pub(crate) base_spec_schedule: SpecSchedule,

    /// Effective schedule: `base_spec_schedule` overlaid with every
    /// discovered activation. This is what discovery validates against, and
    /// what params threading into the STF will consume once it lands.
    pub(crate) spec_schedule: SpecSchedule,
}

impl<W, S> AsmWorkerServiceState<W, S>
where
    W: WorkerContext + Send + Sync + 'static,
    S: AsmSpec + Send + Sync + 'static,
    S::Params: Send + Sync + 'static,
{
    /// Creates a new service state, loading the latest anchor or creating genesis.
    ///
    /// `spec_schedule` is the configured base schedule; activations
    /// discovered before a restart are overlaid to resume the effective
    /// schedule.
    ///
    /// Construction goes through [`crate::AsmWorkerBuilder`], which owns the
    /// shared [`Subscribers`] registry — hence `pub(crate)`.
    pub(crate) fn new(
        context: W,
        spec: S,
        params: S::Params,
        spec_schedule: SpecSchedule,
        subscribers: Subscribers<L1BlockCommitment>,
    ) -> WorkerResult<Self> {
        let genesis_height = spec.genesis_l1_height(&params);

        let base_spec_schedule = spec_schedule;
        let activations = context.list_spec_activations()?;
        let spec_schedule = effective_schedule(&base_spec_schedule, &activations)?;
        if !activations.is_empty() {
            tracing::info!(
                ?activations,
                "resuming with persisted spec activations applied"
            );
        }

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
        let genesis_state = spec.construct_genesis_state(&params);
        validate_anchor_against_l1(&context, &genesis_state.chain_view.pow_state)?;

        let anchor = match context.get_latest_anchor_state()? {
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

        Ok(Self {
            context,
            spec,
            anchor,
            blkid,
            genesis_height,
            subscribers,
            base_spec_schedule,
            spec_schedule,
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

        // Pre process transition next block against current anchor state.
        let pre_process = {
            let span = tracing::debug_span!("asm.stf.pre_process", protocol_txs = Empty);
            let _guard = span.enter();

            let result = strata_asm_stf::pre_process_asm(&self.spec, cur_state, block)
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

        let coinbase_inclusion_proof = TxidInclusionProof::generate(&block.txdata, 0);

        strata_asm_stf::compute_asm_transition(
            &self.spec,
            cur_state,
            block,
            &aux_data,
            Some(&coinbase_inclusion_proof),
        )
        .map(|output| (output, aux_data))
        .map_err(WorkerError::AsmError)
    }

    /// Updates anchor related bookkeeping.
    pub(crate) fn update_anchor_state(&mut self, anchor: AnchorState, blkid: L1BlockCommitment) {
        self.anchor = anchor;
        self.blkid = blkid;
    }

    /// Scans a processed block's logs for enacted ASM VK upgrades and derives
    /// the spec activation each one triggers, without touching any state;
    /// [`Self::apply_spec_activations`] enacts them.
    ///
    /// The upgrade log does not name a version — the artifact enacting an
    /// upgrade may predate the version it activates, so the wire cannot
    /// require knowing it. Instead each upgrade activates the successor of
    /// the newest version the effective schedule knows
    /// ([`SpecSchedule::schedule_successor`]), chaining through upgrades
    /// earlier in the same block.
    ///
    /// An error means the block must not be committed: either the successor
    /// id has no [`SpecId`](strata_asm_params::SpecId) variant
    /// ([`WorkerError::UnsupportedSpecActivation`]), so the worker is running
    /// old software past an upgrade it cannot execute and must halt until
    /// restarted with an image that supports the version — or the upgrade
    /// would activate below a height the configured schedule already put its
    /// predecessor at ([`WorkerError::InconsistentSpecSchedule`]).
    ///
    /// Collects into a `Vec` deliberately: every update must validate before
    /// [`Self::apply_spec_activations`] persists anything, so a flawed update
    /// cannot leave a prefix of the block's activations on disk.
    pub(crate) fn discover_spec_activations(
        &self,
        block_id: &L1BlockCommitment,
        logs: &[AsmLogEntry],
    ) -> WorkerResult<Vec<SpecActivationRecord>> {
        let enacting_height = block_id.height();
        let stuck_height = enacting_height.saturating_sub(1);
        let activation_height = enacting_height.saturating_add(1);
        // Scheduled on a scratch copy so an upgrade earlier in this block
        // moves the successor forward for the ones after it, without touching
        // the schedule before the whole block validates.
        let mut schedule = self.spec_schedule.clone();
        logs.iter()
            .filter_map(|l| l.try_into_log::<AsmStfUpdate>().ok())
            .map(|update| {
                let version = schedule
                    .schedule_successor(activation_height)
                    .map_err(|err| match err {
                        SpecScheduleError::UnknownSuccessor(version) => {
                            WorkerError::UnsupportedSpecActivation {
                                version,
                                block_height: enacting_height,
                                stuck_height,
                            }
                        }
                        err => WorkerError::InconsistentSpecSchedule(err),
                    })?;
                Ok(SpecActivationRecord::new(
                    enacting_height,
                    version,
                    update.into_new_predicate(),
                ))
            })
            .collect()
    }

    /// Persists each discovered activation and applies it to the in-memory
    /// effective schedule.
    ///
    /// MUST run before the enacting block's anchor state is committed:
    /// persisting the activation first guarantees a committed anchor never
    /// lacks the activation it enacted (crash-replay simply rewrites the same
    /// record).
    pub(crate) fn apply_spec_activations(
        &mut self,
        activations: Vec<SpecActivationRecord>,
    ) -> WorkerResult<()> {
        for activation in activations {
            let version = activation.version();
            let enacting_height = activation.enacting_height();
            let activation_height = activation.activation_height();
            self.context.record_spec_activation(activation)?;
            self.spec_schedule.schedule(version, activation_height)?;
            tracing::info!(
                ?version,
                activation_height,
                enacting_height,
                "spec version activated by ASM VK upgrade"
            );
        }
        Ok(())
    }

    /// Drops spec activations enacted strictly above `base_height` and
    /// recomputes the effective schedule.
    ///
    /// Called when a sync rebases onto an ancestor (reorg): activations
    /// enacted on the abandoned branch must not leak into re-processing;
    /// any still on the new branch are re-discovered as its blocks re-apply.
    pub(crate) fn rollback_spec_activations(&mut self, base_height: L1Height) -> WorkerResult<()> {
        self.context.prune_spec_activations_after(base_height)?;
        let activations = self.context.list_spec_activations()?;
        self.spec_schedule = effective_schedule(&self.base_spec_schedule, &activations)?;
        Ok(())
    }
}

/// Overlays `activations` onto the `base` schedule.
///
/// Errs when a record does not fit the base schedule
/// ([`WorkerError::InconsistentSpecSchedule`]) — the store and the configured
/// params disagree, so the worker must not start on a schedule missing
/// activations it already committed blocks under.
fn effective_schedule(
    base: &SpecSchedule,
    activations: &[SpecActivationRecord],
) -> WorkerResult<SpecSchedule> {
    let mut schedule = base.clone();
    for activation in activations {
        schedule.schedule(activation.version(), activation.activation_height())?;
    }
    Ok(schedule)
}

impl<W, S> ServiceState for AsmWorkerServiceState<W, S>
where
    W: WorkerContext + Send + Sync + 'static,
    S: AsmSpec + Send + Sync + 'static,
    S::Params: Send + Sync + 'static,
{
    fn name(&self) -> &str {
        constants::SERVICE_NAME
    }
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
    let anchor_header = context.get_l1_block_header_at_height(height as u64)?;
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
    let epoch_start_header = context.get_l1_block_header_at_height(epoch_start_height as u64)?;
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
    use bitcoind_async_client::{Client, traits::Reader};
    use strata_btc_verification::L1Anchor;
    use strata_test_utils_btcio::mine_blocks;

    use super::*;
    use crate::{
        AnchorStateStore, L1DataProvider,
        test_utils::{
            fixtures::{self, TestAsmSpec},
            get_l1_anchor,
        },
    };

    /// `transition` runs the STF for a child of the current anchor.
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
            .store_anchor_state(&out.state)
            .expect("store the processed anchor");

        // A fresh service over the same store resumes from that stored anchor
        // rather than reconstructing genesis.
        let params = fixtures::genesis_params(&seed.client, 101).await;
        let reloaded = AsmWorkerServiceState::new(
            seed.state.context.clone(),
            TestAsmSpec,
            params,
            SpecSchedule::genesis(),
            Subscribers::default(),
        )
        .unwrap();

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
        AsmWorkerServiceState::new(
            context,
            TestAsmSpec,
            params,
            SpecSchedule::genesis(),
            Subscribers::default(),
        )
        .unwrap();

        assert_eq!(
            fx.state.context.mmr_leaf_count(),
            102,
            "prefill is idempotent across restart",
        );
    }

    mod spec_activation {
        use strata_asm_logs::AsmStfUpdate;
        use strata_asm_params::SpecId;
        use strata_identifiers::Buf32;
        use strata_predicate::{PredicateKey, PredicateTypeId};

        use super::*;
        use crate::SpecActivationStore;

        /// Stands in for the upgraded artifact's VK, persisted with the
        /// activation discovery records.
        fn upgrade_predicate() -> PredicateKey {
            PredicateKey::new(PredicateTypeId::Bip340Schnorr, vec![0x33; 32])
        }

        fn upgrade_log() -> AsmLogEntry {
            AsmLogEntry::from_log(&AsmStfUpdate::new(upgrade_predicate()))
                .expect("AsmStfUpdate encoding is infallible")
        }

        fn block_at(height: L1Height) -> L1BlockCommitment {
            L1BlockCommitment::new(height, Buf32::new([0xEE; 32]).into())
        }

        /// An upgrade log yields the activation of the successor of the
        /// newest scheduled version; applying it activates that version at
        /// H+1, in memory and on disk. Discovery alone touches nothing.
        #[tokio::test(flavor = "multi_thread")]
        async fn discover_then_apply_activates_successor_version() {
            let mut fx = fixtures::setup_state(101).await;

            let discovered = fx
                .state
                .discover_spec_activations(&block_at(150), &[upgrade_log()])
                .unwrap();

            let expected = vec![SpecActivationRecord::new(
                150,
                SpecId::V1,
                upgrade_predicate(),
            )];
            assert_eq!(discovered, expected);
            assert_eq!(fx.state.spec_schedule, SpecSchedule::genesis());
            assert!(fx.state.context.list_spec_activations().unwrap().is_empty());

            fx.state.apply_spec_activations(discovered).unwrap();

            assert_eq!(
                fx.state.spec_schedule.activation_height_of(SpecId::V1),
                Some(151)
            );
            assert_eq!(fx.state.context.list_spec_activations().unwrap(), expected);
        }

        /// An upgrade whose successor this binary has no variant for prevents
        /// the enacting block from being committed at all.
        #[tokio::test(flavor = "multi_thread")]
        async fn discover_rejects_unknown_successor() {
            let mut fx = fixtures::setup_state(101).await;
            // Every known version is already scheduled, so the next upgrade's
            // successor (2) falls past the known set.
            fx.state
                .spec_schedule
                .schedule(SpecId::V1, 10)
                .expect("schedule V1");

            let err = fx
                .state
                .discover_spec_activations(&block_at(150), &[upgrade_log()])
                .unwrap_err();

            assert!(
                matches!(
                    err,
                    WorkerError::UnsupportedSpecActivation {
                        version: 2,
                        block_height: 150,
                        stuck_height: 149,
                    }
                ),
                "expected unsupported spec activation error, got {err:?}",
            );
            assert!(fx.state.context.list_spec_activations().unwrap().is_empty());
        }

        /// A flawed update anywhere in the block's logs fails discovery as a
        /// whole: the valid earlier update must not slip through, so nothing
        /// is ever persisted for a block the worker refuses to commit. This
        /// also exercises chaining within a block: the second upgrade's
        /// successor is 2 only because the first one moved it past V1.
        #[tokio::test(flavor = "multi_thread")]
        async fn discover_rejects_block_with_valid_and_flawed_updates() {
            let fx = fixtures::setup_state(101).await;
            let logs = [upgrade_log(), upgrade_log()];

            let err = fx
                .state
                .discover_spec_activations(&block_at(150), &logs)
                .unwrap_err();

            assert!(
                matches!(
                    err,
                    WorkerError::UnsupportedSpecActivation { version: 2, .. }
                ),
                "expected unsupported spec activation error, got {err:?}",
            );
            assert_eq!(fx.state.spec_schedule, SpecSchedule::genesis());
            assert!(fx.state.context.list_spec_activations().unwrap().is_empty());
        }

        /// A restart resumes the effective schedule from persisted
        /// activations.
        #[tokio::test(flavor = "multi_thread")]
        async fn new_resumes_persisted_activations() {
            let fx = fixtures::setup_state(101).await;
            let context = fx.state.context.clone(); // shares the sled store
            context
                .record_spec_activation(SpecActivationRecord::new(
                    120,
                    SpecId::V1,
                    upgrade_predicate(),
                ))
                .unwrap();

            let params = fixtures::genesis_params(&fx.client, 101).await;
            let reloaded = AsmWorkerServiceState::new(
                context,
                TestAsmSpec,
                params,
                SpecSchedule::genesis(),
                Subscribers::default(),
            )
            .unwrap();

            assert_eq!(
                reloaded.spec_schedule.activation_height_of(SpecId::V1),
                Some(121),
                "restart must resume the discovered activation",
            );
        }

        /// A reorg rollback prunes activations above the base and recomputes
        /// the effective schedule from what survives.
        #[tokio::test(flavor = "multi_thread")]
        async fn rollback_prunes_and_recomputes() {
            let mut fx = fixtures::setup_state(101).await;
            let logs = [upgrade_log()];

            let activations = fx
                .state
                .discover_spec_activations(&block_at(150), &logs)
                .unwrap();
            fx.state.apply_spec_activations(activations).unwrap();
            assert!(fx.state.spec_schedule.is_active(SpecId::V1, 151));

            // Reorg to a base below the enacting block: back to the base schedule.
            fx.state.rollback_spec_activations(140).unwrap();
            assert_eq!(
                fx.state.spec_schedule,
                SpecSchedule::genesis(),
                "activation enacted above the base must be dropped",
            );
            assert!(fx.state.context.list_spec_activations().unwrap().is_empty());

            // A rollback at or above the enacting height keeps the activation.
            let activations = fx
                .state
                .discover_spec_activations(&block_at(150), &logs)
                .unwrap();
            fx.state.apply_spec_activations(activations).unwrap();
            fx.state.rollback_spec_activations(150).unwrap();
            assert!(fx.state.spec_schedule.is_active(SpecId::V1, 151));
        }
    }
}
