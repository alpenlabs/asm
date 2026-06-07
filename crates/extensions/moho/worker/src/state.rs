//! Service state for the Moho worker.

use moho_types::MohoState;
use strata_identifiers::L1BlockCommitment;
use strata_predicate::PredicateKey;
use strata_service::ServiceState;
use tracing::{info, warn};

use crate::{MohoWorkerContext, MohoWorkerError, MohoWorkerResult, compute, constants};

/// In-memory state for the Moho worker.
///
/// The worker is a deterministic forward-only fold over the ASM commit stream:
/// it holds the most recently derived [`MohoState`] and the block it is anchored
/// to, and each incoming commitment chains forward from that. There is no chain
/// view of its own — whatever block sequence the ASM worker commits (and emits)
/// is the sequence the Moho worker folds.
#[derive(Debug)]
pub struct MohoWorkerServiceState<W> {
    /// Context for reading ASM anchor states and persisting Moho states.
    pub(crate) context: W,

    /// The most recently derived (or genesis-seeded) Moho state.
    cur_moho: MohoState,

    /// The L1 block `cur_moho` is anchored to. The next commitment must be its
    /// immediate successor in height.
    cur_block: L1BlockCommitment,

    /// Number of commits folded since launch (excludes the genesis seed).
    processed: u64,
}

impl<W: MohoWorkerContext> MohoWorkerServiceState<W> {
    /// Creates the service state, resuming from the latest stored Moho state or
    /// seeding the genesis entry when the store is empty.
    ///
    /// Genesis is seeded from the ASM anchor state already committed for
    /// `genesis_block`; `asm_predicate` becomes the genesis Moho predicate.
    pub(crate) fn new(
        context: W,
        genesis_block: L1BlockCommitment,
        asm_predicate: PredicateKey,
    ) -> MohoWorkerResult<Self> {
        let (cur_block, cur_moho) = match context.get_latest_moho_state()? {
            Some((blk, moho)) => {
                info!(%blk, "resuming Moho worker from stored state");
                (blk, moho)
            }
            None => {
                let genesis_anchor = context.get_anchor_state(&genesis_block)?;
                let moho = compute::construct_genesis_moho_state(asm_predicate, &genesis_anchor);
                context.store_moho_state(&genesis_block, &moho)?;
                info!(%genesis_block, "seeded genesis Moho state");
                (genesis_block, moho)
            }
        };

        Ok(Self {
            context,
            cur_moho,
            cur_block,
            processed: 0,
        })
    }

    /// The block the worker has most recently committed a Moho state for.
    pub fn cur_block(&self) -> L1BlockCommitment {
        self.cur_block
    }

    /// Number of ASM commits folded since launch.
    pub fn processed(&self) -> u64 {
        self.processed
    }

    /// Folds a single ASM commit into a new [`MohoState`] and persists it.
    ///
    /// The commit must be the immediate height-successor of the current block.
    /// A stale or duplicate commit (height `<=` current) is ignored; a gap
    /// (height `>` current + 1) is rejected — the worker cannot chain across
    /// anchor states it never saw.
    pub(crate) fn process(&mut self, block: L1BlockCommitment) -> MohoWorkerResult<()> {
        let cur_height = self.cur_block.height();
        let got = block.height();

        if got <= cur_height {
            warn!(%block, cur = %self.cur_block, "ignoring stale or duplicate ASM commit");
            return Ok(());
        }

        let expected = cur_height + 1;
        if got != expected {
            return Err(MohoWorkerError::NonContiguousBlock {
                expected: u64::from(expected),
                got: u64::from(got),
            });
        }

        let anchor_state = self.context.get_anchor_state(&block)?;
        let logs = self.context.get_anchor_logs(&block)?;
        let moho = compute::construct_next_moho_state(&self.cur_moho, &anchor_state, &logs);
        self.context.store_moho_state(&block, &moho)?;

        self.cur_moho = moho;
        self.cur_block = block;
        self.processed += 1;

        info!(%block, "committed Moho state");
        Ok(())
    }
}

impl<W: MohoWorkerContext + Send + Sync + 'static> ServiceState for MohoWorkerServiceState<W> {
    fn name(&self) -> &str {
        constants::SERVICE_NAME
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::HashMap};

    use moho_runtime_interface::MohoProgram;
    use strata_asm_common::{AnchorState, AsmLogEntry};
    use strata_asm_params::AsmParams;
    use strata_asm_proof_impl::moho_program::program::AsmStfProgram;
    use strata_asm_spec::construct_genesis_state;
    use strata_identifiers::{L1BlockCommitment, L1BlockId};
    use strata_predicate::PredicateKey;
    use strata_test_utils_arb::ArbitraryGenerator;

    use super::*;
    use crate::{AsmStateProvider, MohoStateStore};

    /// In-memory context backing both concern traits.
    #[derive(Debug, Default)]
    struct MockContext {
        anchors: RefCell<HashMap<L1BlockCommitment, AnchorState>>,
        logs: RefCell<HashMap<L1BlockCommitment, Vec<AsmLogEntry>>>,
        moho: RefCell<HashMap<L1BlockCommitment, MohoState>>,
        latest: RefCell<Option<(L1BlockCommitment, MohoState)>>,
    }

    impl MockContext {
        fn insert_anchor(&self, blk: L1BlockCommitment, state: AnchorState) {
            self.anchors.borrow_mut().insert(blk, state);
        }
    }

    impl AsmStateProvider for MockContext {
        fn get_anchor_state(&self, blockid: &L1BlockCommitment) -> MohoWorkerResult<AnchorState> {
            self.anchors
                .borrow()
                .get(blockid)
                .cloned()
                .ok_or(MohoWorkerError::MissingAsmState(*blockid))
        }

        fn get_anchor_logs(
            &self,
            blockid: &L1BlockCommitment,
        ) -> MohoWorkerResult<Vec<AsmLogEntry>> {
            Ok(self.logs.borrow().get(blockid).cloned().unwrap_or_default())
        }
    }

    impl MohoStateStore for MockContext {
        fn get_latest_moho_state(
            &self,
        ) -> MohoWorkerResult<Option<(L1BlockCommitment, MohoState)>> {
            Ok(self.latest.borrow().clone())
        }

        fn store_moho_state(
            &self,
            blockid: &L1BlockCommitment,
            state: &MohoState,
        ) -> MohoWorkerResult<()> {
            self.moho.borrow_mut().insert(*blockid, state.clone());
            let mut latest = self.latest.borrow_mut();
            if latest
                .as_ref()
                .is_none_or(|(b, _)| blockid.height() >= b.height())
            {
                *latest = Some((*blockid, state.clone()));
            }
            Ok(())
        }
    }

    /// Builds a genesis anchor state and its commitment from arbitrary params.
    fn genesis_anchor() -> (L1BlockCommitment, AnchorState) {
        let params: AsmParams = ArbitraryGenerator::new().generate();
        let anchor = construct_genesis_state(&params);
        let commitment = anchor.chain_view.pow_state.last_verified_block;
        (commitment, anchor)
    }

    /// Reuses `anchor` as the next block's anchor state. The fold does not
    /// validate the anchor against the block, so reusing it is fine for
    /// exercising the chaining logic.
    fn child(anchor: &AnchorState) -> AnchorState {
        anchor.clone()
    }

    fn commitment_after(prev: L1BlockCommitment) -> L1BlockCommitment {
        L1BlockCommitment::new(prev.height() + 1, L1BlockId::default())
    }

    #[test]
    fn seeds_genesis_when_store_empty() {
        let (genesis_blk, anchor) = genesis_anchor();
        let ctx = MockContext::default();
        ctx.insert_anchor(genesis_blk, anchor.clone());

        let state =
            MohoWorkerServiceState::new(ctx, genesis_blk, PredicateKey::always_accept()).unwrap();

        assert_eq!(state.cur_block(), genesis_blk);
        assert_eq!(state.processed(), 0);
        // Genesis moho was persisted and its inner commitment matches the anchor.
        let stored = state
            .context
            .moho
            .borrow()
            .get(&genesis_blk)
            .cloned()
            .unwrap();
        assert_eq!(
            stored.inner_state(),
            AsmStfProgram::compute_state_commitment(&anchor)
        );
    }

    #[test]
    fn resumes_from_latest_without_reseeding_genesis() {
        let (genesis_blk, anchor) = genesis_anchor();
        let ctx = MockContext::default();
        ctx.insert_anchor(genesis_blk, anchor.clone());

        // Pre-populate a "later" stored moho state to resume from.
        let later_blk = commitment_after(genesis_blk);
        let later_moho =
            compute::construct_genesis_moho_state(PredicateKey::always_accept(), &anchor);
        ctx.store_moho_state(&later_blk, &later_moho).unwrap();

        let state =
            MohoWorkerServiceState::new(ctx, genesis_blk, PredicateKey::always_accept()).unwrap();

        assert_eq!(state.cur_block(), later_blk);
    }

    #[test]
    fn folds_contiguous_commits_forward() {
        let (genesis_blk, anchor) = genesis_anchor();
        let ctx = MockContext::default();
        ctx.insert_anchor(genesis_blk, anchor.clone());

        let blk1 = commitment_after(genesis_blk);
        let blk2 = commitment_after(blk1);
        ctx.insert_anchor(blk1, child(&anchor));
        ctx.insert_anchor(blk2, child(&anchor));

        let mut state =
            MohoWorkerServiceState::new(ctx, genesis_blk, PredicateKey::always_accept()).unwrap();

        state.process(blk1).unwrap();
        state.process(blk2).unwrap();

        assert_eq!(state.cur_block(), blk2);
        assert_eq!(state.processed(), 2);
        assert!(state.context.moho.borrow().contains_key(&blk1));
        assert!(state.context.moho.borrow().contains_key(&blk2));
    }

    #[test]
    fn rejects_gap_in_commit_stream() {
        let (genesis_blk, anchor) = genesis_anchor();
        let ctx = MockContext::default();
        ctx.insert_anchor(genesis_blk, anchor.clone());

        let gap_blk = L1BlockCommitment::new(genesis_blk.height() + 2, L1BlockId::default());
        ctx.insert_anchor(gap_blk, child(&anchor));

        let mut state =
            MohoWorkerServiceState::new(ctx, genesis_blk, PredicateKey::always_accept()).unwrap();

        let err = state.process(gap_blk).unwrap_err();
        assert!(matches!(err, MohoWorkerError::NonContiguousBlock { .. }));
    }

    #[test]
    fn ignores_stale_commit() {
        let (genesis_blk, anchor) = genesis_anchor();
        let ctx = MockContext::default();
        ctx.insert_anchor(genesis_blk, anchor.clone());

        let mut state =
            MohoWorkerServiceState::new(ctx, genesis_blk, PredicateKey::always_accept()).unwrap();

        // Re-emitting genesis (height == current) is a no-op, not an error.
        state.process(genesis_blk).unwrap();
        assert_eq!(state.processed(), 0);
    }
}
