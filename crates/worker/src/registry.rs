//! Host-only dispatch from chain-authorized predicates to compiled ASM specs.

use std::fmt::Debug;

use bitcoin::Block;
use strata_asm_common::{AnchorState, AsmManifest, AsmResult, AsmSpec, AuxData, SpecId};
use strata_asm_logs::extract_next_predicate_from_logs;
use strata_asm_stf::{AsmPreProcessOutput, AsmStfOutput, compute_asm_transition, pre_process_asm};
use strata_btc_verification::TxidInclusionProof;
use strata_identifiers::L1BlockCommitment;
use strata_predicate::PredicateKey;

use crate::{WorkerError, WorkerResult};

/// Object-safe host adapter; guest execution continues to use a concrete [`AsmSpec`].
pub trait AsmExecutor: Debug + Send + Sync {
    /// Identifies the ruleset implemented by this target.
    fn spec_id(&self) -> SpecId;
    /// Computes witness requirements under this target's rules.
    fn preprocess<'b>(
        &self,
        state: &AnchorState,
        block: &'b Block,
    ) -> AsmResult<AsmPreProcessOutput<'b>>;
    /// Executes with the witness requested by this target.
    fn transition(
        &self,
        state: &AnchorState,
        block: &Block,
        aux: &AuxData,
        coinbase: Option<&TxidInclusionProof>,
    ) -> AsmResult<AsmStfOutput>;
}

impl<S: AsmSpec + Debug + Send + Sync> AsmExecutor for S {
    fn spec_id(&self) -> SpecId {
        S::ID
    }
    fn preprocess<'b>(
        &self,
        state: &AnchorState,
        block: &'b Block,
    ) -> AsmResult<AsmPreProcessOutput<'b>> {
        pre_process_asm(self, state, block)
    }
    fn transition(
        &self,
        state: &AnchorState,
        block: &Block,
        aux: &AuxData,
        coinbase: Option<&TxidInclusionProof>,
    ) -> AsmResult<AsmStfOutput> {
        compute_asm_transition(self, state, block, aux, coinbase)
    }
}

/// Supported implementations; entries describe capabilities, never activation authority.
///
/// Each spec ID has exactly one predicate. This association is immutable for a chain,
/// including across restarts: changing an artifact's predicate requires a new spec ID.
/// Recovery relies on this contract when a committed block emits no upgrade.
#[derive(Debug, Default)]
pub struct ExecutionRegistry {
    targets: Vec<(PredicateKey, Box<dyn AsmExecutor>)>,
}

impl ExecutionRegistry {
    /// Registers a compiled spec under an independently specified predicate.
    /// Rejects duplicate predicates or spec IDs to keep recovery unambiguous.
    pub fn register<S: AsmSpec + Debug + Send + Sync + 'static>(
        &mut self,
        predicate: PredicateKey,
        spec: S,
    ) -> WorkerResult<()> {
        if self.targets.iter().any(|(key, _)| key == &predicate) {
            return Err(WorkerError::DuplicateExecutionPredicate);
        }
        if self
            .targets
            .iter()
            .any(|(_, target)| target.spec_id() == S::ID)
        {
            return Err(WorkerError::DuplicateExecutionSpec(S::ID));
        }
        self.targets.push((predicate, Box::new(spec)));
        Ok(())
    }

    /// Recovers child authority from one committed anchor and its matching manifest.
    /// An upgrade takes precedence over the producing spec's registered predicate.
    pub(crate) fn recover_predicate(
        &self,
        anchor: &AnchorState,
        manifest: &AsmManifest,
    ) -> WorkerResult<PredicateKey> {
        let block = anchor.last_processed_block();
        if manifest.height() != block.height() || manifest.blkid() != block.blkid() {
            return Err(WorkerError::RecoveryManifestMismatch {
                anchor: block,
                manifest: L1BlockCommitment::new(manifest.height(), *manifest.blkid()),
            });
        }
        if let Some(predicate) = extract_next_predicate_from_logs(manifest.logs()) {
            return Ok(predicate);
        }
        self.targets
            .iter()
            .find(|(_, target)| target.spec_id() == anchor.spec_id)
            .map(|(predicate, _)| predicate.clone())
            .ok_or(WorkerError::UnsupportedExecutionSpec(anchor.spec_id))
    }

    /// Resolves the exact predicate authorized by a parent; unknown keys never fall back.
    pub fn resolve(&self, predicate: &PredicateKey) -> WorkerResult<&dyn AsmExecutor> {
        self.targets
            .iter()
            .find(|(key, _)| key == predicate)
            .map(|(_, target)| target.as_ref())
            .ok_or_else(|| WorkerError::UnsupportedExecutionPredicate(predicate.clone()))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use bitcoin::Network;
    use strata_asm_common::{
        AsmHistoryAccumulatorState, AsmLogEntry, ChainViewState, HeaderVerificationState, Stage,
    };
    use strata_asm_logs::AsmStfUpdate;
    use strata_btc_types::BlockHashExt;
    use strata_btc_verification::L1Anchor;
    use strata_identifiers::{Buf32, L1BlockId};
    use strata_test_utils_btc::BtcMainnetSegment;

    use super::*;

    #[derive(Debug)]
    struct ObservedSpec<const ID: SpecId>(Arc<AtomicUsize>);
    impl<const ID: SpecId> AsmSpec for ObservedSpec<ID> {
        const ID: SpecId = ID;
        type GenesisParams = ();
        fn prepare(&self, source: &AnchorState) -> AnchorState {
            self.0.fetch_add(1, Ordering::SeqCst);
            let mut state = source.clone();
            state.spec_id = ID;
            state
        }
        fn call_subprotocols(&self, _: &mut impl Stage) {}
        fn construct_genesis_state(&self, _: &()) -> AnchorState {
            unreachable!()
        }
        fn genesis_l1_height(&self, _: &()) -> u64 {
            unreachable!()
        }
    }

    fn parent_anchor(block: &Block) -> AnchorState {
        let height = block.bip34_block_height().unwrap() as u32 - 1;
        AnchorState {
            spec_id: 0,
            magic: AnchorState::magic_ssz((*b"test").into()),
            chain_view: ChainViewState {
                history_accumulator: AsmHistoryAccumulatorState::new(u64::from(height)),
                pow_state: HeaderVerificationState::init(L1Anchor {
                    block: L1BlockCommitment::new(
                        height,
                        block.header.prev_blockhash.to_l1_block_id(),
                    ),
                    next_target: block.header.bits.to_consensus(),
                    epoch_start_timestamp: 0,
                    network: Network::Bitcoin,
                }),
            },
            sections: vec![].try_into().unwrap(),
        }
    }

    #[test]
    fn selected_spec_drives_both_preprocessing_and_transition() {
        let block = BtcMainnetSegment::load_full_block();
        let parent = parent_anchor(&block);
        let calls0 = Arc::new(AtomicUsize::new(0));
        let calls1 = Arc::new(AtomicUsize::new(0));
        let mut registry = ExecutionRegistry::default();
        registry
            .register(
                PredicateKey::always_accept(),
                ObservedSpec::<0>(calls0.clone()),
            )
            .unwrap();
        registry
            .register(
                PredicateKey::never_accept(),
                ObservedSpec::<1>(calls1.clone()),
            )
            .unwrap();
        let selected = registry.resolve(&PredicateKey::never_accept()).unwrap();
        assert_eq!(selected.spec_id(), 1);
        selected.preprocess(&parent, &block).unwrap();
        let proof = TxidInclusionProof::generate(&block.txdata, 0);
        let output = selected
            .transition(&parent, &block, &AuxData::default(), proof.as_ref())
            .unwrap();
        assert_eq!(output.state.spec_id, 1);
        assert_eq!(parent.spec_id, 0);
        assert_eq!(calls0.load(Ordering::SeqCst), 0);
        assert_eq!(calls1.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn duplicate_predicates_and_spec_ids_are_rejected() {
        let mut registry = ExecutionRegistry::default();
        let spec = || ObservedSpec::<0>(Arc::new(AtomicUsize::new(0)));
        registry
            .register(PredicateKey::always_accept(), spec())
            .unwrap();
        assert!(matches!(
            registry.register(PredicateKey::always_accept(), spec()),
            Err(WorkerError::DuplicateExecutionPredicate)
        ));
        assert!(matches!(
            registry.resolve(&PredicateKey::never_accept()),
            Err(WorkerError::UnsupportedExecutionPredicate(_))
        ));
        assert!(matches!(
            registry.register(PredicateKey::never_accept(), spec()),
            Err(WorkerError::DuplicateExecutionSpec(0))
        ));
        assert!(matches!(
            registry.resolve(&PredicateKey::never_accept()),
            Err(WorkerError::UnsupportedExecutionPredicate(_))
        ));
    }

    fn manifest(anchor: &AnchorState, logs: Vec<AsmLogEntry>) -> AsmManifest {
        let block = anchor.last_processed_block();
        AsmManifest::new(
            block.height(),
            *block.blkid(),
            Buf32::from([0; 32]).into(),
            logs,
        )
        .unwrap()
    }

    #[test]
    fn recovery_uses_upgrade_then_producing_spec_on_each_fork() {
        let mut registry = ExecutionRegistry::default();
        registry
            .register(
                PredicateKey::always_accept(),
                ObservedSpec::<0>(Arc::default()),
            )
            .unwrap();
        registry
            .register(
                PredicateKey::never_accept(),
                ObservedSpec::<1>(Arc::default()),
            )
            .unwrap();
        let old_anchor = parent_anchor(&BtcMainnetSegment::load_full_block());
        let update =
            AsmLogEntry::from_log(&AsmStfUpdate::new(PredicateKey::never_accept())).unwrap();
        assert_eq!(
            registry
                .recover_predicate(&old_anchor, &manifest(&old_anchor, vec![update]))
                .unwrap(),
            PredicateKey::never_accept()
        );

        // After the upgrade, an ordinary block carries the new spec ID.
        let mut new_anchor = old_anchor.clone();
        new_anchor.spec_id = 1;
        new_anchor.chain_view.pow_state.last_verified_block = L1BlockCommitment::new(
            old_anchor.last_processed_block().height() + 1,
            L1BlockId::from(Buf32::from([1; 32])),
        );
        assert_eq!(
            registry
                .recover_predicate(&new_anchor, &manifest(&new_anchor, vec![]))
                .unwrap(),
            PredicateKey::never_accept()
        );

        // A sibling that never upgraded must recover the old authority.
        let mut sibling = new_anchor.clone();
        sibling.spec_id = 0;
        sibling.chain_view.pow_state.last_verified_block = L1BlockCommitment::new(
            new_anchor.last_processed_block().height(),
            L1BlockId::from(Buf32::from([2; 32])),
        );
        assert_eq!(
            registry
                .recover_predicate(&sibling, &manifest(&sibling, vec![]))
                .unwrap(),
            PredicateKey::always_accept()
        );
        assert!(matches!(
            registry.recover_predicate(&sibling, &manifest(&new_anchor, vec![])),
            Err(WorkerError::RecoveryManifestMismatch { .. })
        ));
    }

    #[test]
    fn recovery_does_not_guess_unknown_specs_or_require_the_upgrade_target() {
        let registry = ExecutionRegistry::default();
        let anchor = parent_anchor(&BtcMainnetSegment::load_full_block());
        assert!(matches!(
            registry.recover_predicate(&anchor, &manifest(&anchor, vec![])),
            Err(WorkerError::UnsupportedExecutionSpec(0))
        ));
        // Recover authority even if execution must subsequently stop for an unknown target.
        let update =
            AsmLogEntry::from_log(&AsmStfUpdate::new(PredicateKey::never_accept())).unwrap();
        assert_eq!(
            registry
                .recover_predicate(&anchor, &manifest(&anchor, vec![update]))
                .unwrap(),
            PredicateKey::never_accept()
        );
    }
}
