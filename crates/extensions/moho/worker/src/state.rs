//! Service state for the Moho worker.

use strata_identifiers::L1BlockCommitment;
use strata_predicate::PredicateKey;
use strata_service::ServiceState;
use tracing::info;

use crate::{MohoWorkerContext, MohoWorkerResult, compute, constants};

/// In-memory state for the Moho worker.
///
/// The worker folds each ASM commit into a [`MohoState`](moho_types::MohoState)
/// by resolving the commit's parent, loading the Moho state already committed
/// for that parent, and chaining forward onto the incoming block's anchor
/// state. Resolving the *actual* parent each time — rather than assuming height
/// contiguity — is what lets the fold follow L1 reorgs: a commit building on an
/// earlier fork point chains from that fork's Moho state, not from whichever
/// commit was processed last. It keeps no chain view of its own; the parent
/// linkage and the committed states in the store are the only inputs.
#[derive(Debug)]
pub struct MohoWorkerServiceState<W> {
    /// Context for reading ASM anchor states, resolving parents, and persisting
    /// Moho states.
    pub(crate) context: W,

    /// The L1 block the worker most recently committed a Moho state for. Tracked
    /// for status reporting only — the fold chains off each commit's stored
    /// parent, not this field.
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
        let cur_block = match context.get_latest_moho_state()? {
            Some((blk, _)) => {
                info!(%blk, "resuming Moho worker from stored state");
                blk
            }
            None => {
                let genesis_anchor = context.get_anchor_state(&genesis_block)?;
                let moho = compute::construct_genesis_moho_state(asm_predicate, &genesis_anchor);
                context.store_moho_state(&genesis_block, &moho)?;
                info!(%genesis_block, "seeded genesis Moho state");
                genesis_block
            }
        };

        Ok(Self {
            context,
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

    /// Folds a single ASM commit into a new [`MohoState`](moho_types::MohoState)
    /// and persists it.
    ///
    /// Resolves the commit's parent, loads the Moho state already committed for
    /// that parent, and chains it forward onto this block's anchor state and
    /// logs. Resolving the real parent (rather than assuming the commit is the
    /// height-successor of the last one processed) is what lets the fold follow
    /// L1 reorgs.
    pub(crate) fn process(&mut self, block: L1BlockCommitment) -> MohoWorkerResult<()> {
        let parent_block = self.context.get_parent_block(&block)?;
        let parent_moho = self.context.get_moho_state(&parent_block)?;

        let anchor_state = self.context.get_anchor_state(&block)?;
        let logs = self.context.get_anchor_logs(&block)?;
        let moho = compute::construct_next_moho_state(&parent_moho, &anchor_state, &logs);
        self.context.store_moho_state(&block, &moho)?;

        self.cur_block = block;
        self.processed += 1;

        info!(%block, parent = %parent_block, "committed Moho state");
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
    use moho_types::MohoState;
    use strata_asm_common::{AnchorState, AsmLogEntry};
    use strata_asm_params::AsmParams;
    use strata_asm_proof_impl::moho_program::program::AsmStfProgram;
    use strata_asm_spec::construct_genesis_state;
    use strata_identifiers::{Buf32, L1BlockCommitment, L1BlockId};
    use strata_predicate::PredicateKey;
    use strata_test_utils_arb::ArbitraryGenerator;

    use super::*;
    use crate::{AsmStateProvider, L1ProviderContext, MohoStateStore, MohoWorkerError};

    /// In-memory context backing the three concern traits.
    #[derive(Debug, Default)]
    struct MockContext {
        anchors: RefCell<HashMap<L1BlockCommitment, AnchorState>>,
        logs: RefCell<HashMap<L1BlockCommitment, Vec<AsmLogEntry>>>,
        parents: RefCell<HashMap<L1BlockCommitment, L1BlockCommitment>>,
        moho: RefCell<HashMap<L1BlockCommitment, MohoState>>,
        latest: RefCell<Option<(L1BlockCommitment, MohoState)>>,
    }

    impl MockContext {
        fn insert_anchor(&self, blk: L1BlockCommitment, state: AnchorState) {
            self.anchors.borrow_mut().insert(blk, state);
        }

        /// Registers `parent` as the parent of `blk` for parent resolution.
        fn link_parent(&self, blk: L1BlockCommitment, parent: L1BlockCommitment) {
            self.parents.borrow_mut().insert(blk, parent);
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

    impl L1ProviderContext for MockContext {
        fn get_parent_block(
            &self,
            block: &L1BlockCommitment,
        ) -> MohoWorkerResult<L1BlockCommitment> {
            self.parents
                .borrow()
                .get(block)
                .copied()
                .ok_or(MohoWorkerError::MissingParentBlock(*block))
        }
    }

    impl MohoStateStore for MockContext {
        fn get_latest_moho_state(
            &self,
        ) -> MohoWorkerResult<Option<(L1BlockCommitment, MohoState)>> {
            Ok(self.latest.borrow().clone())
        }

        fn get_moho_state(&self, blockid: &L1BlockCommitment) -> MohoWorkerResult<MohoState> {
            self.moho
                .borrow()
                .get(blockid)
                .cloned()
                .ok_or(MohoWorkerError::MissingMohoState(*blockid))
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

    /// A commitment one height above `prev`, with a caller-chosen id so that
    /// sibling blocks at the same height — a reorg — stay distinguishable.
    fn commitment_after_with_id(prev: L1BlockCommitment, id: u8) -> L1BlockCommitment {
        L1BlockCommitment::new(prev.height() + 1, L1BlockId::from(Buf32::from([id; 32])))
    }

    fn commitment_after(prev: L1BlockCommitment) -> L1BlockCommitment {
        commitment_after_with_id(prev, 0)
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
        ctx.link_parent(blk1, genesis_blk);
        ctx.link_parent(blk2, blk1);

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
    fn folds_reorged_sibling_from_shared_parent() {
        // Two siblings at the same height both build on genesis (a reorg). Each
        // must fold from genesis's Moho state; the old height-successor logic
        // would have dropped the second as a "stale" same-height commit.
        let (genesis_blk, anchor) = genesis_anchor();
        let ctx = MockContext::default();
        ctx.insert_anchor(genesis_blk, anchor.clone());

        let blk_a = commitment_after_with_id(genesis_blk, 0xaa);
        let blk_b = commitment_after_with_id(genesis_blk, 0xbb);
        ctx.insert_anchor(blk_a, child(&anchor));
        ctx.insert_anchor(blk_b, child(&anchor));
        ctx.link_parent(blk_a, genesis_blk);
        ctx.link_parent(blk_b, genesis_blk);

        let mut state =
            MohoWorkerServiceState::new(ctx, genesis_blk, PredicateKey::always_accept()).unwrap();

        state.process(blk_a).unwrap();
        state.process(blk_b).unwrap();

        // The second sibling was folded, not ignored.
        assert_eq!(state.processed(), 2);
        let moho = state.context.moho.borrow();
        assert!(moho.contains_key(&blk_a));
        assert!(moho.contains_key(&blk_b));
        // Both fold from the shared genesis state onto the same anchor, so their
        // inner commitments match.
        let inner = AsmStfProgram::compute_state_commitment(&anchor);
        assert_eq!(moho.get(&blk_a).unwrap().inner_state(), inner);
        assert_eq!(moho.get(&blk_b).unwrap().inner_state(), inner);
    }

    #[test]
    fn errors_when_parent_moho_missing() {
        let (genesis_blk, anchor) = genesis_anchor();
        let ctx = MockContext::default();
        ctx.insert_anchor(genesis_blk, anchor.clone());

        // `orphan`'s parent was never committed, so its Moho state is absent.
        let missing_parent = commitment_after(genesis_blk);
        let orphan = commitment_after(missing_parent);
        ctx.insert_anchor(orphan, child(&anchor));
        ctx.link_parent(orphan, missing_parent);

        let mut state =
            MohoWorkerServiceState::new(ctx, genesis_blk, PredicateKey::always_accept()).unwrap();

        let err = state.process(orphan).unwrap_err();
        assert!(matches!(err, MohoWorkerError::MissingMohoState(_)));
    }

    #[test]
    fn errors_when_parent_unresolvable() {
        let (genesis_blk, anchor) = genesis_anchor();
        let ctx = MockContext::default();
        ctx.insert_anchor(genesis_blk, anchor.clone());

        // No parent link registered, so the provider cannot resolve the parent.
        let blk = commitment_after(genesis_blk);
        ctx.insert_anchor(blk, child(&anchor));

        let mut state =
            MohoWorkerServiceState::new(ctx, genesis_blk, PredicateKey::always_accept()).unwrap();

        let err = state.process(blk).unwrap_err();
        assert!(matches!(err, MohoWorkerError::MissingParentBlock(_)));
    }
}
