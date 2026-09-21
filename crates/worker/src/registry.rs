//! Host-only dispatch from chain-authorized predicates to compiled ASM specs.

use std::fmt::Debug;

use bitcoin::Block;
use strata_asm_common::{AnchorState, AsmResult, AsmSpec, AuxData, SpecId};
use strata_asm_stf::{AsmPreProcessOutput, AsmStfOutput, compute_asm_transition, pre_process_asm};
use strata_btc_verification::TxidInclusionProof;
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
#[derive(Debug, Default)]
pub struct ExecutionRegistry {
    targets: Vec<(PredicateKey, Box<dyn AsmExecutor>)>,
}

impl ExecutionRegistry {
    /// Registers a compiled spec under an independently specified predicate.
    /// Multiple predicates may implement the same spec, but a predicate has one entry.
    pub fn register<S: AsmSpec + Debug + Send + Sync + 'static>(
        &mut self,
        predicate: PredicateKey,
        spec: S,
    ) -> WorkerResult<()> {
        if self.targets.iter().any(|(key, _)| key == &predicate) {
            return Err(WorkerError::DuplicateExecutionPredicate);
        }
        self.targets.push((predicate, Box::new(spec)));
        Ok(())
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
        AsmHistoryAccumulatorState, ChainViewState, HeaderVerificationState, Stage,
    };
    use strata_btc_types::BlockHashExt;
    use strata_btc_verification::L1Anchor;
    use strata_identifiers::L1BlockCommitment;
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

    #[test]
    fn selected_spec_drives_both_preprocessing_and_transition() {
        let block = BtcMainnetSegment::load_full_block();
        let height = block.bip34_block_height().unwrap() as u32 - 1;
        let parent = AnchorState {
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
        };
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
    fn duplicate_and_unknown_predicates_are_rejected() {
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
        registry
            .register(PredicateKey::never_accept(), spec())
            .unwrap();
        assert_eq!(
            registry
                .resolve(&PredicateKey::never_accept())
                .unwrap()
                .spec_id(),
            0
        );
    }
}
