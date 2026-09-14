use std::sync::Arc;

use bitcoin::{Block, CompactTarget, params::Params};
use strata_asm_common::{AnchorState, AsmBootstrap, AuxData, HeaderVerificationState};
use strata_asm_stf::{AsmStfOutput, AsmTargetSet, PreStateValidation};
use strata_btc_types::BlockHashExt;
use strata_btc_verification::{
    TxidInclusionProof, compute_block_hash, get_relative_difficulty_adjustment_height,
};
use strata_identifiers::L1BlockCommitment;
use strata_predicate::PredicateKey;
use strata_service::ServiceState;
use tracing::field::Empty;

use crate::{
    AnchorMismatch, L1DataProvider, Subscribers, WorkerContext, WorkerError, WorkerResult,
    aux_resolver::AuxDataResolver, constants,
};

/// Service state for the ASM worker.
///
/// Generic over the worker context `W` and the target set `T` — the
/// specifications this build can execute, keyed by the predicate that
/// authorizes each. Which one runs a given block is not a property of the
/// worker; it is decided per block by the parent's handover.
#[derive(Debug)]
pub struct AsmWorkerServiceState<W, T> {
    /// Context for the state to interact with outer world.
    pub(crate) context: W,

    /// The specifications this build can execute.
    pub(crate) targets: T,

    /// Predicate that bootstraps the handover chain.
    ///
    /// Retained so a later rollback to genesis can reject an offline-altered
    /// handover even when the substitute predicate maps to the same spec.
    pub(crate) genesis_predicate: PredicateKey,

    /// Predicate authorizing the *next* block to execute.
    ///
    /// Held in memory as well as persisted so the per-block path does not read
    /// storage to answer "which rules now?". Seeded from the handover recorded
    /// for the current anchor, and advanced as each block commits.
    pub(crate) predicate: PredicateKey,

    /// The chain's validated bootstrap. Every genesis-derived fact the worker
    /// needs — the anchor block, its height — comes from here.
    pub(crate) bootstrap: Arc<AsmBootstrap>,

    /// Current ASM anchor state.
    pub anchor: AnchorState,

    /// Current anchor block.
    pub blkid: L1BlockCommitment,

    /// Registry of ASM-commit subscribers. After each successful anchor commit
    /// the service fans the new commitment out to these; see
    /// [`crate::AsmWorkerHandle::subscribe_blocks`].
    pub(crate) subscribers: Subscribers<L1BlockCommitment>,
}

impl<W, T> AsmWorkerServiceState<W, T>
where
    W: WorkerContext + Send + Sync + 'static,
    T: AsmTargetSet,
{
    /// Creates a new service state, loading the latest anchor or creating genesis.
    ///
    /// Construction goes through [`crate::AsmWorkerBuilder`], which owns the
    /// shared [`Subscribers`] registry — hence `pub(crate)`.
    pub(crate) fn new(
        context: W,
        targets: T,
        genesis_predicate: PredicateKey,
        bootstrap: Arc<AsmBootstrap>,
        subscribers: Subscribers<L1BlockCommitment>,
    ) -> WorkerResult<Self> {
        let genesis_height = bootstrap.anchor_l1_height();

        // The configured anchor is otherwise trusted blindly: a wrong block,
        // target, epoch timestamp, or network would only surface one L1 block
        // later when header verification rejects the anchor's successor. Build
        // the genesis state once (it carries the anchor-derived header
        // verification fields) and validate it against the L1 source on every
        // startup, before adopting either stored or genesis state.
        let genesis_state = bootstrap.genesis_state();
        validate_anchor_against_l1(&context, &genesis_state.chain_view.pow_state)?;
        let genesis_blkid = genesis_state.last_processed_block();

        let stored_anchor = context.get_latest_anchor_state()?;
        let has_stored_anchor = stored_anchor.is_some();
        let (blkid, anchor) = match stored_anchor {
            Some((selected, state)) => {
                validate_anchor_commitment(selected, &state)?;
                tracing::info!(blkid = %selected, "ASM worker resuming from stored anchor state");
                (selected, state)
            }
            None => {
                tracing::info!(genesis_blk = %genesis_blkid, "no stored ASM state; initializing genesis anchor");
                (genesis_blkid, genesis_state.clone())
            }
        };

        // No transition runs at or below the bootstrap boundary. A stored state
        // selected there must therefore be the exact state already validated
        // from the chain configuration, not merely a value with a compatible
        // section schema.
        validate_bootstrap_boundary(blkid, &anchor, genesis_state)?;

        // The predicate authorizing the next block is the one the current
        // anchor handed over. At genesis nothing has handed over yet, so the
        // release's genesis predicate seeds the chain and is recorded like any
        // other handover — leaving one rule, not two, for every later block.
        // A non-genesis committed anchor without a handover is corruption: using
        // the genesis predicate there would silently execute the wrong rules
        // after an upgrade or an interrupted reorg.
        let (predicate, seed_genesis) = resolve_initial_predicate(
            context.get_next_predicate(&blkid)?,
            blkid,
            genesis_blkid,
            &genesis_predicate,
        )?;

        let target =
            targets
                .spec_id_for(&predicate)
                .ok_or_else(|| WorkerError::UnsupportedPredicate {
                    predicate: format!("{predicate:?}"),
                    block: blkid,
                })?;
        if blkid == genesis_blkid && bootstrap.spec_id() != target {
            return Err(WorkerError::BootstrapTargetMismatch {
                block: blkid,
                bootstrap: bootstrap.spec_id(),
                target,
            });
        }

        validate_stored_anchor(
            &context,
            &targets,
            &anchor,
            &predicate,
            target,
            genesis_blkid,
        )?;

        // Validation above is deliberately read-only. Only after the selected
        // anchor, its payloads, and any activation boundary are known-good may
        // startup touch durable state. This keeps a failed startup from
        // prefilling the MMR or seeding a handover around an unusable anchor.
        context.prefill_manifest_mmr(genesis_height)?;
        if !has_stored_anchor {
            context.store_anchor_state(genesis_state)?;
        }
        if seed_genesis {
            context.store_next_predicate(&blkid, &predicate)?;
        }

        Ok(Self {
            context,
            targets,
            predicate,
            genesis_predicate,
            bootstrap,
            anchor,
            blkid,
            subscribers,
        })
    }

    /// Returns the predicate authorizing the next block to execute.
    pub(crate) fn predicate(&self) -> &PredicateKey {
        &self.predicate
    }

    /// L1 block height of the chain genesis (anchor) block.
    pub(crate) fn genesis_height(&self) -> u64 {
        self.bootstrap.anchor_l1_height()
    }

    /// Returns the actual ASM STF results and the auxiliary data used during the transition.
    ///
    /// A caller is responsible for ensuring the current anchor is a parent of a passed block.
    pub fn transition(&self, block: &Block) -> WorkerResult<(AsmStfOutput, AuxData)> {
        // Which rules apply is decided here and nowhere else: by the predicate
        // the parent handed over. A predicate this build cannot execute is a
        // halt, not a fallback — continuing would produce state no proof can
        // ever be made for.
        let predicate = &self.predicate;
        if self.targets.spec_id_for(predicate).is_none() {
            return Err(WorkerError::UnsupportedPredicate {
                predicate: format!("{predicate:?}"),
                block: self.blkid,
            });
        }

        let cur_state = &self.anchor;

        // Pre process transition next block against current anchor state.
        let pre_process = {
            let span = tracing::debug_span!("asm.stf.pre_process", protocol_txs = Empty);
            let _guard = span.enter();

            let result = self
                .targets
                .pre_process(predicate, cur_state, block)
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

        self.targets
            .transition(
                predicate,
                cur_state,
                block,
                &aux_data,
                coinbase_inclusion_proof.as_ref(),
            )
            .map(|output| (output, aux_data))
            .map_err(WorkerError::AsmError)
    }

    /// Advances the in-memory handover after a block commits.
    pub(crate) fn adopt_predicate(&mut self, predicate: PredicateKey) {
        self.predicate = predicate;
    }

    /// Validates a retained base before a reorg adopts it, returning the
    /// predicate that authorizes its child.
    ///
    /// The predicate is read by the full block commitment, so retained
    /// handovers from another branch cannot authorize `base`'s child. They are
    /// deliberately not height-pruned: anchor states from those branches are
    /// retained too and must keep their handovers for crash recovery or a later
    /// switch back to an already-processed branch.
    ///
    /// This method is read-only. The caller persists the validated base first,
    /// then updates the in-memory anchor and predicate together. A validation
    /// error therefore leaves both durable and in-memory active tips unchanged.
    pub(crate) fn validate_rebase_anchor(
        &self,
        base: L1BlockCommitment,
        anchor: &AnchorState,
    ) -> WorkerResult<PredicateKey> {
        validate_anchor_commitment(base, anchor)?;
        validate_bootstrap_boundary(base, anchor, self.bootstrap.genesis_state())?;
        let predicate = self
            .context
            .get_next_predicate(&base)?
            .ok_or(WorkerError::MissingHandover { block: base })?;

        if base == self.bootstrap.anchor_block() && predicate != self.genesis_predicate {
            return Err(WorkerError::BootstrapHandoverMismatch {
                block: base,
                expected: format!("{:?}", self.genesis_predicate),
                actual: format!("{predicate:?}"),
            });
        }

        let target = self.targets.spec_id_for(&predicate).ok_or_else(|| {
            WorkerError::UnsupportedPredicate {
                predicate: format!("{predicate:?}"),
                block: base,
            }
        })?;

        validate_stored_anchor(
            &self.context,
            &self.targets,
            anchor,
            &predicate,
            target,
            self.bootstrap.anchor_block(),
        )?;

        Ok(predicate)
    }

    /// Updates anchor related bookkeeping.
    pub(crate) fn update_anchor_state(&mut self, anchor: AnchorState, blkid: L1BlockCommitment) {
        self.anchor = anchor;
        self.blkid = blkid;
    }
}

/// Validates a stored state before startup or reorg adoption against its
/// authenticated target.
///
/// The parent's handover identifies the specification that executed `anchor`;
/// the state must be canonical target-schema output under that producer. The
/// anchor's own handover identifies the target for its child. A different target
/// is accepted only when it declares the producer as its direct predecessor and
/// its migration preflight accepts this exact state. These independent checks
/// reject both an impossible producer/state pairing and a forged upgrade edge.
fn validate_stored_anchor<W, T>(
    context: &W,
    targets: &T,
    anchor: &AnchorState,
    next_predicate: &PredicateKey,
    target: strata_asm_common::AsmSpecId,
    genesis_anchor: L1BlockCommitment,
) -> WorkerResult<()>
where
    W: WorkerContext,
    T: AsmTargetSet,
{
    let block = anchor.last_processed_block();
    if block == genesis_anchor {
        return match validate_for_next_target(targets, anchor, next_predicate, target, block)? {
            PreStateValidation::TargetSchema => Ok(()),
            PreStateValidation::DirectPredecessor { spec: predecessor } => {
                Err(WorkerError::PredecessorStateAtBootstrap {
                    block,
                    target,
                    predecessor,
                })
            }
        };
    }

    let header = context.get_l1_block_header(block.blkid())?;
    let parent = L1BlockCommitment::new(block.height() - 1, header.prev_blockhash.to_l1_block_id());
    let producer_predicate = context
        .get_next_predicate(&parent)?
        .ok_or(WorkerError::MissingHandover { block: parent })?;
    let producer = targets.spec_id_for(&producer_predicate).ok_or_else(|| {
        WorkerError::UnsupportedPredicate {
            predicate: format!("{producer_predicate:?}"),
            block: parent,
        }
    })?;

    let producer_validation = targets
        .validate_pre_state(&producer_predicate, anchor)
        .map_err(|source| WorkerError::InvalidStoredProducerState {
            block,
            parent,
            producer,
            predicate: format!("{producer_predicate:?}"),
            source: Box::new(source),
        })?;
    if let PreStateValidation::DirectPredecessor { spec: state_spec } = producer_validation {
        return Err(WorkerError::StoredAnchorNotProducerOutput {
            block,
            parent,
            producer,
            state_spec,
        });
    }

    let declared_predecessor = targets.direct_predecessor_of(target);
    if target != producer && declared_predecessor != Some(producer) {
        return Err(WorkerError::InvalidStoredTargetSuccession {
            block,
            producer,
            target,
            declared_predecessor,
        });
    }

    match validate_for_next_target(targets, anchor, next_predicate, target, block)? {
        PreStateValidation::TargetSchema => Ok(()),
        PreStateValidation::DirectPredecessor { spec: predecessor }
            if target != producer && predecessor == producer =>
        {
            Ok(())
        }
        PreStateValidation::DirectPredecessor { spec: predecessor } => {
            Err(WorkerError::InvalidPredecessorBoundary {
                block,
                parent,
                target,
                expected: predecessor,
                actual: producer,
            })
        }
    }
}

/// Runs the target-side canonical-state or migration-preflight check and gives
/// it one consistent worker error at both startup and reorg adoption.
fn validate_for_next_target<T: AsmTargetSet>(
    targets: &T,
    anchor: &AnchorState,
    next_predicate: &PredicateKey,
    target: strata_asm_common::AsmSpecId,
    block: L1BlockCommitment,
) -> WorkerResult<PreStateValidation> {
    targets
        .validate_pre_state(next_predicate, anchor)
        .map_err(|source| WorkerError::InvalidStoredAnchor {
            block,
            target,
            predicate: format!("{next_predicate:?}"),
            source: Box::new(source),
        })
}

/// Binds a decoded state to the independently selected storage commitment.
fn validate_anchor_commitment(
    expected: L1BlockCommitment,
    anchor: &AnchorState,
) -> WorkerResult<()> {
    let actual = anchor.last_processed_block();
    if actual != expected {
        return Err(WorkerError::StoredAnchorCommitmentMismatch { expected, actual });
    }
    Ok(())
}

/// Requires the only state at or below the configured bootstrap boundary to be
/// the exact independently validated bootstrap state.
fn validate_bootstrap_boundary(
    selected: L1BlockCommitment,
    anchor: &AnchorState,
    bootstrap: &AnchorState,
) -> WorkerResult<()> {
    let bootstrap_block = bootstrap.last_processed_block();
    if selected.height() <= bootstrap_block.height() && anchor != bootstrap {
        return Err(WorkerError::StoredBootstrapMismatch {
            bootstrap: bootstrap_block,
            actual: selected,
        });
    }
    Ok(())
}

/// Resolves the predicate at startup and reports whether it must be seeded.
///
/// Only the exact bootstrap anchor may synthesize a handover. Every later
/// anchor is committed after its handover, so an absent entry is corruption.
fn resolve_initial_predicate(
    recorded: Option<PredicateKey>,
    anchor: L1BlockCommitment,
    genesis_anchor: L1BlockCommitment,
    genesis_predicate: &PredicateKey,
) -> WorkerResult<(PredicateKey, bool)> {
    match recorded {
        Some(predicate) if anchor == genesis_anchor && predicate != *genesis_predicate => {
            Err(WorkerError::BootstrapHandoverMismatch {
                block: anchor,
                expected: format!("{genesis_predicate:?}"),
                actual: format!("{predicate:?}"),
            })
        }
        Some(predicate) => Ok((predicate, false)),
        None if anchor == genesis_anchor => Ok((genesis_predicate.clone(), true)),
        None => Err(WorkerError::MissingHandover { block: anchor }),
    }
}

impl<W, T> ServiceState for AsmWorkerServiceState<W, T>
where
    W: WorkerContext + Send + Sync + 'static,
    T: AsmTargetSet,
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
    use bitcoind_async_client::{Client, traits::Reader};
    use strata_asm_common::{AsmError, SectionState, SectionStateExt, Subprotocol, prepare_state};
    use strata_btc_verification::L1Anchor;
    use strata_identifiers::{Buf32, L1BlockId};
    use strata_predicate::{PredicateKey, PredicateTypeId};
    use strata_test_utils_btcio::mine_blocks;

    use super::*;
    use crate::{
        AnchorStateStore, AsmHandoverStore, AuxDataStore, L1DataProvider,
        test_utils::{
            TestAsmWorkerContext,
            fixtures::{self},
            get_l1_anchor,
        },
    };

    async fn baseline_child(fixture: &fixtures::StateFixture) -> (L1BlockCommitment, AnchorState) {
        let commitment = fixtures::mine(&fixture.node, &fixture.client, 1).await[0];
        let block = fixture
            .state
            .context
            .get_l1_block(commitment.blkid())
            .expect("fetch baseline child");
        let output = fixture
            .state
            .transition(&block)
            .expect("process baseline child")
            .0;
        (commitment, output.state)
    }

    fn unknown_predicate() -> PredicateKey {
        PredicateKey::try_new(PredicateTypeId::AlwaysAccept, vec![0xfe])
            .expect("valid unknown test predicate")
    }

    #[test]
    fn startup_seeds_a_missing_handover_only_at_the_bootstrap_anchor() {
        let genesis = L1BlockCommitment::new(100, L1BlockId::from(Buf32::from([1u8; 32])));
        let later = L1BlockCommitment::new(101, L1BlockId::from(Buf32::from([2u8; 32])));
        let predicate = fixtures::test_predicate();

        let (resolved, seed) =
            resolve_initial_predicate(None, genesis, genesis, &predicate).unwrap();
        assert_eq!(resolved, predicate);
        assert!(seed);

        let error = resolve_initial_predicate(None, later, genesis, &predicate).unwrap_err();
        assert!(matches!(error, WorkerError::MissingHandover { block } if block == later));

        let (resolved, seed) =
            resolve_initial_predicate(Some(predicate.clone()), later, genesis, &predicate).unwrap();
        assert_eq!(resolved, predicate);
        assert!(!seed);

        let substitute = fixtures::test_rotated_baseline_predicate();
        let error =
            resolve_initial_predicate(Some(substitute), genesis, genesis, &predicate).unwrap_err();
        assert!(matches!(
            error,
            WorkerError::BootstrapHandoverMismatch { block, .. } if block == genesis
        ));
    }

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
        assert_eq!(latest.map(|(block, _state)| block), Some(fx.state.blkid));
    }

    /// A stored row at the bootstrap commitment is not an independently valid
    /// genesis merely because its schema and payload encoding are valid. The
    /// chain configuration already fixes the exact genesis values.
    #[tokio::test(flavor = "multi_thread")]
    async fn startup_rejects_a_semantically_different_stored_bootstrap_without_writes() {
        let fixture = fixtures::setup_context(101).await;
        let bootstrap = fixtures::genesis_bootstrap(&fixture.client, 101).await;
        let genesis = bootstrap.anchor_block();
        let mut tampered = bootstrap.genesis_state().clone();
        tampered.sections[0] =
            SectionState::from_state::<fixtures::TestSubprotocolV0>(&7).expect("test state fits");

        fixture
            .context
            .store_next_predicate(&genesis, &fixtures::test_predicate())
            .expect("store genesis handover");
        fixture
            .context
            .store_anchor_state(&tampered)
            .expect("store alternate bootstrap state");
        let latest_before = fixture.context.get_latest_anchor_state().unwrap();

        let error = AsmWorkerServiceState::new(
            fixture.context.clone(),
            fixtures::TestAsmTargets,
            fixtures::test_predicate(),
            bootstrap,
            Subscribers::default(),
        )
        .expect_err("the stored bootstrap must equal the validated bootstrap exactly");

        assert!(matches!(
            error,
            WorkerError::StoredBootstrapMismatch {
                bootstrap,
                actual,
            } if bootstrap == genesis && actual == genesis
        ));
        assert_eq!(
            fixture.context.get_latest_anchor_state().unwrap(),
            latest_before
        );
        assert_eq!(fixture.context.mmr_leaf_count(), 0);
        assert_eq!(
            fixture.context.get_next_predicate(&genesis).unwrap(),
            Some(fixtures::test_predicate()),
        );
    }

    /// No ASM transition runs at bootstrap, so a persisted predicate there must
    /// equal the configured genesis predicate byte-for-byte. Mapping a different
    /// predicate to the same semantic spec does not authorize it.
    #[tokio::test(flavor = "multi_thread")]
    async fn startup_rejects_a_same_spec_genesis_predicate_substitution_without_writes() {
        let fixture = fixtures::setup_context(101).await;
        let bootstrap = fixtures::genesis_bootstrap(&fixture.client, 101).await;
        let genesis = bootstrap.anchor_block();
        fixture
            .context
            .store_anchor_state(bootstrap.genesis_state())
            .expect("store exact bootstrap state");
        fixture
            .context
            .store_next_predicate(&genesis, &fixtures::test_rotated_baseline_predicate())
            .expect("store unauthorized same-spec handover");
        let latest_before = fixture.context.get_latest_anchor_state().unwrap();

        let error = AsmWorkerServiceState::new(
            fixture.context.clone(),
            fixtures::TestAsmTargets,
            fixtures::test_predicate(),
            bootstrap,
            Subscribers::default(),
        )
        .expect_err("bootstrap cannot enact a same-spec predicate rotation");

        assert!(matches!(
            error,
            WorkerError::BootstrapHandoverMismatch { block, .. } if block == genesis
        ));
        assert_eq!(
            fixture.context.get_latest_anchor_state().unwrap(),
            latest_before
        );
        assert_eq!(fixture.context.mmr_leaf_count(), 0);
        assert_eq!(
            fixture.context.get_next_predicate(&genesis).unwrap(),
            Some(fixtures::test_rotated_baseline_predicate()),
        );
    }

    /// When the store already holds a latest anchor, `new` adopts it — a worker
    /// restart resumes from the DB rather than reconstructing genesis.
    #[tokio::test(flavor = "multi_thread")]
    async fn startup_accepts_and_adopts_stored_target_steady_state() {
        let seed = fixtures::setup_state(101).await;

        // Prior progress: process one real block so a genuine anchor for height
        // 102 lands in the store as the new latest.
        let (advanced, anchor) = baseline_child(&seed).await;
        seed.state
            .context
            .store_next_predicate(&advanced, &fixtures::test_predicate())
            .expect("store child handover");
        seed.state
            .context
            .store_anchor_state(&anchor)
            .expect("store the processed anchor");

        // A fresh service over the same store resumes from that stored anchor
        // rather than reconstructing genesis.
        let bootstrap = fixtures::genesis_bootstrap(&seed.client, 101).await;
        let reloaded = AsmWorkerServiceState::new(
            seed.state.context.clone(),
            fixtures::TestAsmTargets,
            fixtures::test_predicate(),
            bootstrap,
            Subscribers::default(),
        )
        .unwrap();

        assert_eq!(
            reloaded.blkid, advanced,
            "adopted the stored latest, not genesis",
        );
    }

    /// A restart at the activation anchor accepts predecessor-form state only
    /// after preflighting its migration. It keeps the stored state untouched;
    /// the next real block performs the migration as part of its transition.
    #[tokio::test(flavor = "multi_thread")]
    async fn startup_accepts_a_valid_direct_predecessor_boundary_without_rewriting_it() {
        let seed = fixtures::setup_state(101).await;
        let (activation, predecessor_state) = baseline_child(&seed).await;
        seed.state
            .context
            .store_next_predicate(&activation, &fixtures::test_successor_predicate())
            .expect("store successor handover");
        seed.state
            .context
            .store_anchor_state(&predecessor_state)
            .expect("store activation anchor");

        let bootstrap = fixtures::genesis_bootstrap(&seed.client, 101).await;
        let reloaded = AsmWorkerServiceState::new(
            seed.state.context.clone(),
            fixtures::TestAsmTargets,
            fixtures::test_predicate(),
            bootstrap,
            Subscribers::default(),
        )
        .expect("the exact predecessor at a real handover boundary is valid");

        assert_eq!(reloaded.blkid, activation);
        assert_eq!(reloaded.predicate(), &fixtures::test_successor_predicate());
        assert_eq!(
            reloaded.anchor, predecessor_state,
            "migration preflight must not replace the committed boundary state",
        );
        assert_eq!(
            seed.state
                .context
                .get_anchor_state(&activation)
                .expect("read stored activation state"),
            predecessor_state,
            "startup must not persist the preflight output",
        );
    }

    /// Canonical successor bytes are still impossible at a block whose parent
    /// authorized baseline execution. Producer validation is independent from
    /// whether the anchor's own handover selects that successor for its child.
    #[tokio::test(flavor = "multi_thread")]
    async fn startup_rejects_successor_state_under_a_baseline_producer() {
        let seed = fixtures::setup_state(101).await;
        let (activation, baseline_state) = baseline_child(&seed).await;
        let impossible_successor = prepare_state::<fixtures::TestAsmSuccessorSpec>(&baseline_state)
            .expect("construct canonical successor-form state")
            .into_owned();
        seed.state
            .context
            .store_next_predicate(&activation, &fixtures::test_successor_predicate())
            .expect("store successor handover");
        seed.state
            .context
            .store_anchor_state(&impossible_successor)
            .expect("store impossible producer/state pairing");

        let error = AsmWorkerServiceState::new(
            seed.state.context.clone(),
            fixtures::TestAsmTargets,
            fixtures::test_predicate(),
            fixtures::genesis_bootstrap(&seed.client, 101).await,
            Subscribers::default(),
        )
        .expect_err("baseline rules could not have emitted successor state");

        assert!(matches!(
            error,
            WorkerError::InvalidStoredProducerState {
                block,
                parent,
                producer: strata_asm_common::AsmSpecId::V0,
                ..
            } if block == activation && parent == seed.state.blkid
        ));
    }

    /// A schema that belongs to neither the target nor its declared direct
    /// predecessor is rejected before the worker reports ready.
    #[tokio::test(flavor = "multi_thread")]
    async fn startup_rejects_an_unrelated_section_schema() {
        let seed = fixtures::setup_state(101).await;
        let (activation, mut unrelated) = baseline_child(&seed).await;
        unrelated.sections[0].version = 2;
        seed.state
            .context
            .store_next_predicate(&activation, &fixtures::test_successor_predicate())
            .expect("store successor handover");
        seed.state
            .context
            .store_anchor_state(&unrelated)
            .expect("store unrelated schema");

        let error = AsmWorkerServiceState::new(
            seed.state.context.clone(),
            fixtures::TestAsmTargets,
            fixtures::test_predicate(),
            fixtures::genesis_bootstrap(&seed.client, 101).await,
            Subscribers::default(),
        )
        .expect_err("an unrelated schema must fail startup");

        assert!(
            matches!(
                error,
                WorkerError::InvalidStoredProducerState {
                    ref source,
                    ..
                } if matches!(source.as_ref(), AsmError::StateValidation(_))
            ),
            "expected a producer-schema rejection, got {error:?}",
        );
    }

    /// Matching section ids and codec versions are insufficient: stored
    /// payload bytes must decode canonically under the selected target.
    #[tokio::test(flavor = "multi_thread")]
    async fn startup_rejects_a_malformed_target_section_payload() {
        let seed = fixtures::setup_state(101).await;
        let (advanced, mut malformed) = baseline_child(&seed).await;
        malformed.sections[0] = SectionState::new(
            <fixtures::TestSubprotocolV0 as Subprotocol>::ID,
            <fixtures::TestSubprotocolV0 as Subprotocol>::STATE_VERSION,
            vec![0u8; 3],
        )
        .expect("malformed payload still fits the section envelope");
        seed.state
            .context
            .store_next_predicate(&advanced, &fixtures::test_predicate())
            .expect("store steady handover");
        seed.state
            .context
            .store_anchor_state(&malformed)
            .expect("store malformed section payload");

        let error = AsmWorkerServiceState::new(
            seed.state.context.clone(),
            fixtures::TestAsmTargets,
            fixtures::test_predicate(),
            fixtures::genesis_bootstrap(&seed.client, 101).await,
            Subscribers::default(),
        )
        .expect_err("malformed target payload must fail startup");

        assert!(
            matches!(
                error,
                WorkerError::InvalidStoredProducerState {
                    ref source,
                    ..
                } if matches!(source.as_ref(), AsmError::Deserialization(_, _))
            ),
            "expected a payload decoding failure, got {error:?}",
        );
    }

    /// An anchor's persisted handover must resolve before its state is
    /// interpreted. Unknown rules halt rather than falling back to a known spec.
    #[tokio::test(flavor = "multi_thread")]
    async fn startup_rejects_an_unknown_anchor_handover() {
        let seed = fixtures::setup_state(101).await;
        let (advanced, anchor) = baseline_child(&seed).await;
        seed.state
            .context
            .store_next_predicate(&advanced, &unknown_predicate())
            .expect("store unknown handover");
        seed.state
            .context
            .store_anchor_state(&anchor)
            .expect("store advanced anchor");

        let error = AsmWorkerServiceState::new(
            seed.state.context.clone(),
            fixtures::TestAsmTargets,
            fixtures::test_predicate(),
            fixtures::genesis_bootstrap(&seed.client, 101).await,
            Subscribers::default(),
        )
        .expect_err("unknown target must fail startup");

        assert!(
            matches!(error, WorkerError::UnsupportedPredicate { block, .. } if block == advanced),
            "expected an unsupported-predicate halt, got {error:?}",
        );
    }

    /// The bootstrap's semantic spec tag must agree with the genesis
    /// predicate, even if two specifications ever share a state schema.
    #[tokio::test(flavor = "multi_thread")]
    async fn startup_rejects_a_bootstrap_built_for_another_target_without_writes() {
        let fixture = fixtures::setup_context(101).await;
        let bootstrap = fixtures::genesis_bootstrap(&fixture.client, 101).await;
        let genesis = bootstrap.anchor_block();

        let error = AsmWorkerServiceState::new(
            fixture.context.clone(),
            fixtures::TestAsmTargets,
            fixtures::test_successor_predicate(),
            bootstrap,
            Subscribers::default(),
        )
        .expect_err("a baseline bootstrap cannot seed successor rules");

        assert!(matches!(
            error,
            WorkerError::BootstrapTargetMismatch {
                block,
                bootstrap: strata_asm_common::AsmSpecId::V0,
                target: strata_asm_common::AsmSpecId::V1,
            } if block == genesis
        ));
        assert_eq!(fixture.context.mmr_leaf_count(), 0);
        assert!(fixture.context.get_latest_anchor_state().unwrap().is_none());
        assert_eq!(fixture.context.get_next_predicate(&genesis).unwrap(), None,);
    }

    /// A block executed under successor rules cannot emit predecessor-form
    /// state: migration occurs before execution and its output uses the
    /// successor schema.
    #[tokio::test(flavor = "multi_thread")]
    async fn startup_rejects_a_predecessor_not_authorized_by_its_parent() {
        let seed = fixtures::setup_state(101).await;
        let parent = seed.state.blkid;
        let (activation, predecessor_state) = baseline_child(&seed).await;
        seed.state
            .context
            .store_next_predicate(&parent, &fixtures::test_successor_predicate())
            .expect("replace parent handover with wrong authorizer");
        seed.state
            .context
            .store_next_predicate(&activation, &fixtures::test_successor_predicate())
            .expect("store successor child handover");
        seed.state
            .context
            .store_anchor_state(&predecessor_state)
            .expect("store predecessor-form state");

        let error = AsmWorkerServiceState::new(
            seed.state.context.clone(),
            fixtures::TestAsmTargets,
            fixtures::test_predicate(),
            fixtures::genesis_bootstrap(&seed.client, 101).await,
            Subscribers::default(),
        )
        .expect_err("successor execution cannot emit predecessor state");

        assert!(
            matches!(
                error,
                WorkerError::StoredAnchorNotProducerOutput {
                    block,
                    parent: recorded_parent,
                    producer: strata_asm_common::AsmSpecId::V1,
                    state_spec: strata_asm_common::AsmSpecId::V0,
                } if block == activation && recorded_parent == parent
            ),
            "expected an impossible producer-output rejection, got {error:?}",
        );
    }

    /// Validation failures happen before any startup write. Use a fresh context
    /// whose state and handover rows are deliberately prepared while its MMR is
    /// still empty, so an early prefill would be observable.
    #[tokio::test(flavor = "multi_thread")]
    async fn failed_startup_does_not_mutate_state_handover_or_mmr_stores() {
        let seed = fixtures::setup_state(101).await;
        let parent = seed.state.blkid;
        let (activation, mut unrelated) = baseline_child(&seed).await;
        unrelated.sections[0].version = 2;

        let context = TestAsmWorkerContext::new((*seed.client).clone());
        context
            .store_next_predicate(&parent, &fixtures::test_predicate())
            .expect("store parent handover");
        context
            .store_next_predicate(&activation, &fixtures::test_successor_predicate())
            .expect("store activation handover");
        context
            .store_anchor_state(&unrelated)
            .expect("store invalid active anchor");

        let state_before = context.get_latest_anchor_state().expect("snapshot state");
        let parent_handover_before = context
            .get_next_predicate(&parent)
            .expect("snapshot parent handover");
        let activation_handover_before = context
            .get_next_predicate(&activation)
            .expect("snapshot activation handover");
        assert_eq!(context.mmr_leaf_count(), 0, "fresh MMR starts empty");
        assert!(context.get_manifest(&activation).is_none());
        assert!(context.get_aux_data(&activation).is_err());

        AsmWorkerServiceState::new(
            context.clone(),
            fixtures::TestAsmTargets,
            fixtures::test_predicate(),
            fixtures::genesis_bootstrap(&seed.client, 101).await,
            Subscribers::default(),
        )
        .expect_err("invalid state must fail before startup writes");

        assert_eq!(context.get_latest_anchor_state().unwrap(), state_before);
        assert_eq!(
            context.get_next_predicate(&parent).unwrap(),
            parent_handover_before,
        );
        assert_eq!(
            context.get_next_predicate(&activation).unwrap(),
            activation_handover_before,
        );
        assert_eq!(context.mmr_leaf_count(), 0, "MMR must not be prefilled");
        assert!(context.get_manifest(&activation).is_none());
        assert!(context.get_aux_data(&activation).is_err());
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
        HeaderVerificationState::init(anchor)
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
        let bootstrap = fixtures::genesis_bootstrap(&fx.client, 101).await;
        AsmWorkerServiceState::new(
            context,
            fixtures::TestAsmTargets,
            fixtures::test_predicate(),
            bootstrap,
            Subscribers::default(),
        )
        .unwrap();

        assert_eq!(
            fx.state.context.mmr_leaf_count(),
            102,
            "prefill is idempotent across restart",
        );
    }
}
