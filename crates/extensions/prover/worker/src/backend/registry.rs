//! Predicate-based lookup of the ASM hosts this prover can drive.
//!
//! Hosts are loaded once at startup from the configured artifact list, so
//! memory is bounded by that list and a wrong artifact fails before the worker
//! runs rather than on first use.

use strata_predicate::PredicateKey;

use super::AsmProofHost;
use crate::{ProverError, ProverResult};

/// ASM hosts loaded at startup, looked up by the predicate a parent state authorizes.
///
/// Each spec and each predicate appears at most once, matching native execution.
#[derive(Debug)]
pub struct AsmHostRegistry<H> {
    hosts: Vec<AsmProofHost<H>>,
}

impl<H> AsmHostRegistry<H> {
    /// Builds a registry from hosts already bound to their spec and predicate.
    ///
    /// # Errors
    ///
    /// - [`ProverError::NoAsmArtifacts`] if `hosts` is empty.
    /// - [`ProverError::DuplicateArtifact`] if two hosts share a spec or a predicate.
    pub fn new(hosts: Vec<AsmProofHost<H>>) -> ProverResult<Self> {
        if hosts.is_empty() {
            return Err(ProverError::NoAsmArtifacts);
        }
        for (index, host) in hosts.iter().enumerate() {
            let descriptor = host.descriptor();
            if hosts[..index].iter().any(|earlier| {
                earlier.descriptor().spec_id() == descriptor.spec_id()
                    || earlier.descriptor().predicate() == descriptor.predicate()
            }) {
                return Err(ProverError::DuplicateArtifact);
            }
        }
        Ok(Self { hosts })
    }

    /// Returns the host whose program matches `predicate`.
    ///
    /// # Errors
    ///
    /// [`ProverError::UnknownArtifact`] if no configured artifact has that predicate.
    pub fn get(&self, predicate: &PredicateKey) -> ProverResult<&AsmProofHost<H>> {
        self.hosts
            .iter()
            .find(|host| host.descriptor().predicate() == predicate)
            .ok_or_else(|| ProverError::UnknownArtifact(predicate.clone()))
    }
}

#[cfg(test)]
mod tests {
    use k256::schnorr::SigningKey;
    use strata_asm_common::{AnchorState, AsmSpec, SpecId, Stage};
    use strata_asm_proof_impl::statements::process_asm_stf;
    use strata_asm_spec::StrataAsmSpec;
    use zkaleido_native_adapter::NativeHost;

    use super::*;

    /// A second spec identity; the registry only inspects its ID.
    struct OtherSpec;

    impl AsmSpec for OtherSpec {
        const ID: SpecId = StrataAsmSpec::ID + 1;
        type GenesisParams = <StrataAsmSpec as AsmSpec>::GenesisParams;

        fn prepare(&self, state: &AnchorState) -> AnchorState {
            StrataAsmSpec.prepare(state)
        }

        fn call_subprotocols(&self, stage: &mut impl Stage) {
            StrataAsmSpec.call_subprotocols(stage);
        }

        fn construct_genesis_state(&self, params: &Self::GenesisParams) -> AnchorState {
            StrataAsmSpec.construct_genesis_state(params)
        }

        fn genesis_l1_height(&self, params: &Self::GenesisParams) -> u64 {
            StrataAsmSpec.genesis_l1_height(params)
        }
    }

    fn host<S: AsmSpec>(seed: u8) -> AsmProofHost<NativeHost> {
        let key = SigningKey::from_bytes(&[seed; 32]).expect("valid test key");
        let host = NativeHost::new(key, |zkvm| process_asm_stf(zkvm, &StrataAsmSpec));
        AsmProofHost::bind::<S>(host).expect("native host binds")
    }

    #[test]
    fn empty_artifact_list_is_rejected() {
        assert!(matches!(
            AsmHostRegistry::<NativeHost>::new(Vec::new()),
            Err(ProverError::NoAsmArtifacts)
        ));
    }

    #[test]
    fn duplicate_predicate_is_rejected() {
        let hosts = vec![host::<StrataAsmSpec>(1), host::<OtherSpec>(1)];
        assert!(matches!(
            AsmHostRegistry::new(hosts),
            Err(ProverError::DuplicateArtifact)
        ));
    }

    #[test]
    fn duplicate_spec_is_rejected() {
        let hosts = vec![host::<StrataAsmSpec>(1), host::<StrataAsmSpec>(2)];
        assert!(matches!(
            AsmHostRegistry::new(hosts),
            Err(ProverError::DuplicateArtifact)
        ));
    }

    #[test]
    fn lookup_returns_the_matching_host() {
        let first = host::<StrataAsmSpec>(1);
        let second = host::<OtherSpec>(2);
        let second_predicate = second.descriptor().predicate().clone();
        let registry = AsmHostRegistry::new(vec![first, second]).unwrap();

        let found = registry.get(&second_predicate).unwrap();
        assert_eq!(found.descriptor().spec_id(), OtherSpec::ID);
        assert_eq!(found.descriptor().predicate(), &second_predicate);
    }

    #[test]
    fn unknown_predicate_is_reported() {
        let registry = AsmHostRegistry::new(vec![host::<StrataAsmSpec>(1)]).unwrap();
        let missing = PredicateKey::always_accept();
        assert!(matches!(
            registry.get(&missing),
            Err(ProverError::UnknownArtifact(predicate)) if predicate == missing
        ));
    }
}
