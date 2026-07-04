//! Service state for the Moho worker.

use moho_types::MohoState;
use strata_asm_worker::Subscribers;
use strata_identifiers::L1BlockCommitment;
use strata_predicate::PredicateKey;
use strata_service::ServiceState;
use tracing::info;

use crate::{MohoWorkerContext, MohoWorkerResult, compute, constants};

/// In-memory state for the Moho worker.
///
/// Holds the most recently folded [`MohoState`] and the block it is anchored to.
/// Each ASM commit is folded onto its parent's Moho state: in the common
/// in-order case the parent is the block already held here, so the fold reads
/// straight from memory; on an L1 reorg the incoming commit builds on a
/// different block, so the orchestration re-anchors from the parent's committed
/// state in the store. It keeps no chain view of its own.
///
/// Mirrors `strata-asm-worker`'s `AsmWorkerServiceState`, which likewise holds
/// the current `AnchorState` in memory and re-anchors on reorg. The fold
/// orchestration lives in the service layer's `process_block`; this type just
/// holds the data and the small `update_moho_state` mutation that advances it.
#[derive(Debug)]
pub struct MohoWorkerServiceState<W> {
    /// Context for reading ASM anchor states, resolving parents, and persisting
    /// Moho states.
    pub(crate) context: W,

    /// The most recently folded (or genesis-seeded) Moho state. The fold chains
    /// directly onto this when the next commit builds on `cur_block`.
    cur_moho: MohoState,

    /// The L1 block `cur_moho` is anchored to.
    cur_block: L1BlockCommitment,

    /// The chain genesis block. Its Moho state is always seeded, so it is the
    /// floor the startup sync walk terminates at.
    genesis_block: L1BlockCommitment,

    /// Registry of Moho-commit subscribers. After each live commit's Moho state
    /// is durably stored, the service fans the block out to these so downstream
    /// consumers (the prover) chain off the Moho commit rather than racing the
    /// ASM one; see [`crate::MohoWorkerHandle::subscribe_blocks`].
    pub(crate) subscribers: Subscribers<L1BlockCommitment>,
}

impl<W: MohoWorkerContext> MohoWorkerServiceState<W> {
    /// Creates the service state, resuming from the latest stored Moho state or
    /// seeding the genesis entry when the store is empty.
    ///
    /// Genesis is seeded from the ASM anchor state already committed for
    /// `genesis_block`; `asm_predicate` becomes the genesis Moho predicate.
    ///
    /// `subscribers` is the same registry the handle hands out [`Subscription`]s
    /// from, so the service emits into the list the handle registers into.
    /// Construction goes through [`MohoWorkerBuilder`], which owns it.
    ///
    /// [`Subscription`]: strata_asm_worker::Subscription
    /// [`MohoWorkerBuilder`]: crate::MohoWorkerBuilder
    pub(crate) fn new(
        context: W,
        genesis_block: L1BlockCommitment,
        asm_predicate: PredicateKey,
        subscribers: Subscribers<L1BlockCommitment>,
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
            genesis_block,
            subscribers,
        })
    }

    /// The block the worker has most recently committed a Moho state for.
    pub fn cur_block(&self) -> L1BlockCommitment {
        self.cur_block
    }

    /// L1 height of the chain genesis block — the floor the sync walk stops
    /// at. Mirrors `strata-asm-worker`'s `genesis_height`.
    pub(crate) fn genesis_height(&self) -> u64 {
        self.genesis_block.height() as u64
    }

    /// The most recently folded (or genesis-seeded) Moho state.
    pub fn cur_moho(&self) -> &MohoState {
        &self.cur_moho
    }

    /// Advances the in-memory state to `moho` at `blk` after a successful fold.
    /// Mirrors `strata-asm-worker`'s `update_anchor_state`.
    pub(crate) fn update_moho_state(&mut self, moho: MohoState, blk: L1BlockCommitment) {
        self.cur_moho = moho;
        self.cur_block = blk;
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
    use strata_identifiers::{Buf32, L1BlockCommitment, L1BlockId};
    use strata_predicate::PredicateKey;
    use strata_test_utils_arb::ArbitraryGenerator;

    use super::*;
    use crate::{
        AsmStateProvider, ExportEntryStore, L1ProviderContext, MohoStateStore, MohoWorkerError,
        service::{process_block, sync_to_tip},
    };

    /// In-memory context backing the four concern traits.
    #[derive(Debug, Default)]
    struct MockContext {
        anchors: RefCell<HashMap<L1BlockCommitment, AnchorState>>,
        logs: RefCell<HashMap<L1BlockCommitment, Vec<AsmLogEntry>>>,
        parents: RefCell<HashMap<L1BlockCommitment, L1BlockCommitment>>,
        moho: RefCell<HashMap<L1BlockCommitment, MohoState>>,
        latest: RefCell<Option<(L1BlockCommitment, MohoState)>>,
        asm_latest: RefCell<Option<L1BlockCommitment>>,
        export_entries: RefCell<Vec<(u8, u32, [u8; 32])>>,
    }

    impl MockContext {
        fn insert_anchor(&self, blk: L1BlockCommitment, state: AnchorState) {
            self.anchors.borrow_mut().insert(blk, state);
            // Track the highest-height anchor as the ASM tip, mirroring the ASM
            // store's `latest` pointer.
            let mut latest = self.asm_latest.borrow_mut();
            if latest.is_none_or(|b| blk.height() >= b.height()) {
                *latest = Some(blk);
            }
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

        fn get_latest_asm_block(&self) -> MohoWorkerResult<Option<L1BlockCommitment>> {
            Ok(*self.asm_latest.borrow())
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

    impl ExportEntryStore for MockContext {
        fn store_export_entries(
            &self,
            container_id: u8,
            height: u32,
            entries: Vec<[u8; 32]>,
        ) -> MohoWorkerResult<()> {
            let mut store = self.export_entries.borrow_mut();
            for entry in entries {
                store.push((container_id, height, entry));
            }
            Ok(())
        }

        fn prune_export_entries_from(&self, height: u32) -> MohoWorkerResult<()> {
            self.export_entries
                .borrow_mut()
                .retain(|(_, h, _)| *h < height);
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

        let state = MohoWorkerServiceState::new(
            ctx,
            genesis_blk,
            PredicateKey::always_accept(),
            Subscribers::default(),
        )
        .unwrap();

        assert_eq!(state.cur_block(), genesis_blk);
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

        let state = MohoWorkerServiceState::new(
            ctx,
            genesis_blk,
            PredicateKey::always_accept(),
            Subscribers::default(),
        )
        .unwrap();

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

        let mut state = MohoWorkerServiceState::new(
            ctx,
            genesis_blk,
            PredicateKey::always_accept(),
            Subscribers::default(),
        )
        .unwrap();

        process_block(&mut state, blk1).unwrap();
        process_block(&mut state, blk2).unwrap();

        assert_eq!(state.cur_block(), blk2);
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

        let mut state = MohoWorkerServiceState::new(
            ctx,
            genesis_blk,
            PredicateKey::always_accept(),
            Subscribers::default(),
        )
        .unwrap();

        process_block(&mut state, blk_a).unwrap();
        // blk_b's parent (genesis) is no longer the in-memory cur_block (blk_a),
        // so this exercises the store re-anchor path, not the fast path.
        process_block(&mut state, blk_b).unwrap();

        let moho = state.context.moho.borrow();
        // The second sibling was folded, not ignored.
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

        let mut state = MohoWorkerServiceState::new(
            ctx,
            genesis_blk,
            PredicateKey::always_accept(),
            Subscribers::default(),
        )
        .unwrap();

        let err = process_block(&mut state, orphan).unwrap_err();
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

        let mut state = MohoWorkerServiceState::new(
            ctx,
            genesis_blk,
            PredicateKey::always_accept(),
            Subscribers::default(),
        )
        .unwrap();

        let err = process_block(&mut state, blk).unwrap_err();
        assert!(matches!(err, MohoWorkerError::MissingParentBlock(_)));
    }

    #[test]
    fn sync_folds_full_gap_to_asm_tip() {
        // The ASM worker is three blocks ahead of an empty Moho store (the worst
        // case: a crash before the first fold). Sync must fold genesis+1..tip.
        let (genesis_blk, anchor) = genesis_anchor();
        let ctx = MockContext::default();
        ctx.insert_anchor(genesis_blk, anchor.clone());

        let blk1 = commitment_after(genesis_blk);
        let blk2 = commitment_after(blk1);
        let blk3 = commitment_after(blk2);
        for (blk, parent) in [(blk1, genesis_blk), (blk2, blk1), (blk3, blk2)] {
            ctx.insert_anchor(blk, child(&anchor));
            ctx.link_parent(blk, parent);
        }

        // Seeds genesis Moho state; ASM tip is blk3.
        let mut state = MohoWorkerServiceState::new(
            ctx,
            genesis_blk,
            PredicateKey::always_accept(),
            Subscribers::default(),
        )
        .unwrap();

        sync_to_tip(&mut state).unwrap();

        assert_eq!(state.cur_block(), blk3);
        let moho = state.context.moho.borrow();
        assert!(moho.contains_key(&blk1));
        assert!(moho.contains_key(&blk2));
        assert!(moho.contains_key(&blk3));
    }

    #[test]
    fn sync_folds_partial_gap_after_resume() {
        // Crash between the ASM commit for blk2 and the Moho fold for blk2: Moho
        // resumes at blk1, ASM tip is blk2. Only blk2 needs folding.
        let (genesis_blk, anchor) = genesis_anchor();
        let ctx = MockContext::default();
        ctx.insert_anchor(genesis_blk, anchor.clone());

        let blk1 = commitment_after(genesis_blk);
        let blk2 = commitment_after(blk1);
        for (blk, parent) in [(blk1, genesis_blk), (blk2, blk1)] {
            ctx.insert_anchor(blk, child(&anchor));
            ctx.link_parent(blk, parent);
        }
        // Moho progressed through blk1 before the crash.
        let moho1 = compute::construct_genesis_moho_state(PredicateKey::always_accept(), &anchor);
        ctx.store_moho_state(&genesis_blk, &moho1).unwrap();
        ctx.store_moho_state(&blk1, &moho1).unwrap();

        // Resumes at blk1 (the Moho tip), ASM tip is blk2.
        let mut state = MohoWorkerServiceState::new(
            ctx,
            genesis_blk,
            PredicateKey::always_accept(),
            Subscribers::default(),
        )
        .unwrap();
        assert_eq!(state.cur_block(), blk1);

        sync_to_tip(&mut state).unwrap();

        assert_eq!(state.cur_block(), blk2);
        assert!(state.context.moho.borrow().contains_key(&blk2));
    }

    #[test]
    fn sync_is_noop_when_caught_up() {
        // Moho tip already equals the ASM tip: nothing to fold.
        let (genesis_blk, anchor) = genesis_anchor();
        let ctx = MockContext::default();
        ctx.insert_anchor(genesis_blk, anchor.clone());

        let mut state = MohoWorkerServiceState::new(
            ctx,
            genesis_blk,
            PredicateKey::always_accept(),
            Subscribers::default(),
        )
        .unwrap();

        sync_to_tip(&mut state).unwrap();

        assert_eq!(state.cur_block(), genesis_blk);
    }

    #[test]
    fn sync_reanchors_across_reorg() {
        // The Moho store resumes on sibling blk_a, but the ASM tip is sibling
        // blk_b (a reorg during downtime). Walking parents lands on the shared
        // genesis, whose Moho state is stored, so blk_b folds from there.
        let (genesis_blk, anchor) = genesis_anchor();
        let ctx = MockContext::default();
        ctx.insert_anchor(genesis_blk, anchor.clone());

        let blk_a = commitment_after_with_id(genesis_blk, 0xaa);
        let blk_b = commitment_after_with_id(genesis_blk, 0xbb);
        ctx.insert_anchor(blk_a, child(&anchor));
        ctx.insert_anchor(blk_b, child(&anchor));
        ctx.link_parent(blk_a, genesis_blk);
        ctx.link_parent(blk_b, genesis_blk);

        // Moho committed the now-orphaned sibling blk_a before the crash.
        let moho = compute::construct_genesis_moho_state(PredicateKey::always_accept(), &anchor);
        ctx.store_moho_state(&genesis_blk, &moho).unwrap();
        ctx.store_moho_state(&blk_a, &moho).unwrap();

        // Resumes at blk_a; ASM tip is the winning sibling blk_b.
        let mut state = MohoWorkerServiceState::new(
            ctx,
            genesis_blk,
            PredicateKey::always_accept(),
            Subscribers::default(),
        )
        .unwrap();
        assert_eq!(state.cur_block(), blk_a);

        sync_to_tip(&mut state).unwrap();

        assert_eq!(state.cur_block(), blk_b);
        assert!(state.context.moho.borrow().contains_key(&blk_b));
    }

    #[test]
    fn live_commit_notifies_subscribers() {
        // A subscription taken from the registry handed to `new` sees a block
        // once the worker emits it on the live path. `process_input` is
        // `process_block` + `emit`; the service bound (`Send + Sync`) keeps the
        // RefCell mock out of `process_input`, so this exercises the same two
        // steps directly to confirm the state holds the shared registry.
        let (genesis_blk, anchor) = genesis_anchor();
        let ctx = MockContext::default();
        ctx.insert_anchor(genesis_blk, anchor.clone());

        let blk1 = commitment_after(genesis_blk);
        ctx.insert_anchor(blk1, child(&anchor));
        ctx.link_parent(blk1, genesis_blk);

        let subscribers = Subscribers::default();
        let mut sub = subscribers.subscribe();
        let mut state = MohoWorkerServiceState::new(
            ctx,
            genesis_blk,
            PredicateKey::always_accept(),
            subscribers,
        )
        .unwrap();

        process_block(&mut state, blk1).unwrap();
        state.subscribers.emit(blk1);

        assert_eq!(sub.try_recv(), Ok(blk1));
    }

    #[test]
    fn startup_sync_does_not_notify_subscribers() {
        // `sync_to_tip` folds the gap through `process_block`, which must not
        // emit: the catch-up runs before any subscriber attaches and the stream
        // has no replay, so emitting here would deliver blocks out of band. This
        // pins emission to the live `process_input` path only.
        let (genesis_blk, anchor) = genesis_anchor();
        let ctx = MockContext::default();
        ctx.insert_anchor(genesis_blk, anchor.clone());

        let blk1 = commitment_after(genesis_blk);
        let blk2 = commitment_after(blk1);
        for (blk, parent) in [(blk1, genesis_blk), (blk2, blk1)] {
            ctx.insert_anchor(blk, child(&anchor));
            ctx.link_parent(blk, parent);
        }

        let subscribers = Subscribers::default();
        let sub = subscribers.subscribe();
        let mut state = MohoWorkerServiceState::new(
            ctx,
            genesis_blk,
            PredicateKey::always_accept(),
            subscribers,
        )
        .unwrap();

        sync_to_tip(&mut state).unwrap();

        assert_eq!(state.cur_block(), blk2);
        // Genesis seeding and the catch-up fold both stayed silent.
        assert_eq!(sub.backlog(), 0);
    }
}
