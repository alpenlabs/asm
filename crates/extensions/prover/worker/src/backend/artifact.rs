//! Binding between a loaded ASM proof host and its declared spec.

use moho_runtime_impl::RuntimeInput;
use strata_asm_common::{AsmSpec, SpecId};
use strata_asm_proof_impl::program::AsmStfProofProgram;
use strata_predicate::PredicateKey;
use zkaleido::{ZkVmHost, ZkVmRemoteHost, ZkVmRemoteProgram};

use super::resolve_predicate;
use crate::{ProverError, ProverResult};

/// Identity of a loaded ASM program; it does not authorize a chain upgrade.
///
/// The predicate is derived from the host's verifying key. The spec is declared
/// by code assembling the backend; an ELF's semantics cannot be inferred from
/// its VK. Release qualification must establish that the artifact implements
/// the declared spec. Multiple artifacts may implement the same spec.
#[derive(Debug)]
pub struct AsmProgramDescriptor {
    spec_id: SpecId,
    predicate: PredicateKey,
}

impl AsmProgramDescriptor {
    /// Returns the spec declared by the program's assembly code.
    pub fn spec_id(&self) -> SpecId {
        self.spec_id
    }

    /// Returns the predicate derived from the loaded host.
    pub fn predicate(&self) -> &PredicateKey {
        &self.predicate
    }
}

/// Keeps an ASM host and its derived identity together through proof submission.
#[derive(Debug)]
pub struct AsmProofHost<H> {
    host: H,
    descriptor: AsmProgramDescriptor,
}

impl<H: ZkVmHost> AsmProofHost<H> {
    /// Derives the host predicate and binds it to the declared spec.
    ///
    /// The caller must supply an artifact implementing `S`; this declaration
    /// does not verify ELF semantics or authorize it for a particular parent.
    pub fn bind<S: AsmSpec>(host: H) -> ProverResult<Self> {
        let predicate = resolve_predicate(&host)?;
        Ok(Self {
            host,
            descriptor: AsmProgramDescriptor {
                spec_id: S::ID,
                predicate,
            },
        })
    }

    /// Binds a host after checking its predicate against an independent artifact record.
    ///
    /// The caller is responsible for associating `S` with the expected predicate.
    /// This verifies loaded program identity, not the program's protocol semantics.
    pub fn bind_expected<S: AsmSpec>(
        host: H,
        expected_predicate: &PredicateKey,
    ) -> ProverResult<Self> {
        let bound = Self::bind::<S>(host)?;
        if bound.descriptor.predicate() != expected_predicate {
            return Err(ProverError::AsmArtifactMismatch { spec_id: S::ID });
        }
        Ok(bound)
    }
}

impl<H: ZkVmRemoteHost + Sync> AsmProofHost<H> {
    /// Submits only inputs whose parent predicate matches this bound host.
    pub(crate) async fn start_proving(&self, input: &RuntimeInput) -> ProverResult<H::ProofId> {
        self.require_predicate(input.moho_pre_state().next_predicate())?;
        AsmStfProofProgram::start_proving(input, &self.host)
            .await
            .map_err(ProverError::RemoteSubmit)
    }
}

impl<H> AsmProofHost<H> {
    /// Returns the identity derived when this host was bound.
    pub fn descriptor(&self) -> &AsmProgramDescriptor {
        &self.descriptor
    }

    /// Checks that the parent predicate permits this host before submission.
    fn require_predicate(&self, predicate: &PredicateKey) -> ProverResult<()> {
        if self.descriptor.predicate() != predicate {
            return Err(ProverError::UnsupportedAsmPredicate {
                spec_id: self.descriptor.spec_id,
            });
        }
        Ok(())
    }

    /// Borrows the bound host for submission and remote proof retrieval.
    pub(crate) fn host(&self) -> &H {
        &self.host
    }
}

#[cfg(test)]
mod tests {
    use k256::schnorr::SigningKey;
    use strata_asm_proof_impl::statements::process_asm_stf;
    use strata_asm_spec::StrataAsmSpec;
    use zkaleido_native_adapter::NativeHost;

    use super::*;

    #[test]
    fn bound_host_uses_its_key_and_allows_same_spec_key_rotation() {
        let bind = |seed| {
            let key = SigningKey::from_bytes(&[seed; 32]).expect("valid test key");
            let host = NativeHost::new(key, |zkvm| process_asm_stf(zkvm, &StrataAsmSpec));
            AsmProofHost::bind::<StrataAsmSpec>(host).expect("native host binds")
        };
        let first = bind(1);
        let rebuilt = bind(2);
        let restarted = bind(1);

        assert_eq!(first.descriptor().spec_id(), StrataAsmSpec::ID);
        assert_eq!(first.descriptor().spec_id(), rebuilt.descriptor().spec_id());
        assert_eq!(
            first.descriptor().predicate(),
            restarted.descriptor().predicate()
        );
        assert_ne!(
            first.descriptor().predicate(),
            rebuilt.descriptor().predicate()
        );
        first
            .require_predicate(first.descriptor().predicate())
            .unwrap();
        assert!(matches!(
            first.require_predicate(rebuilt.descriptor().predicate()),
            Err(ProverError::UnsupportedAsmPredicate { .. })
        ));
        assert!(
            first
                .require_predicate(&PredicateKey::always_accept())
                .is_err()
        );
    }
    #[test]
    fn checked_binding_rejects_a_different_program_key() {
        let host = |seed| {
            NativeHost::new(
                SigningKey::from_bytes(&[seed; 32]).expect("valid test key"),
                |zkvm| process_asm_stf(zkvm, &StrataAsmSpec),
            )
        };
        // A separately constructed record stands in for the registry's expected identity.
        let record = AsmProofHost::bind::<StrataAsmSpec>(host(1)).unwrap();
        let expected = record.descriptor().predicate();
        let matching = AsmProofHost::bind_expected::<StrataAsmSpec>(host(1), expected).unwrap();
        assert_eq!(matching.descriptor().predicate(), expected);
        assert!(matches!(
            AsmProofHost::bind_expected::<StrataAsmSpec>(host(2), expected),
            Err(ProverError::AsmArtifactMismatch { .. })
        ));
    }

    #[tokio::test]
    async fn mismatched_parent_never_reaches_the_prover() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };

        use moho_types::{ExportState, InnerStateCommitment, MohoState};

        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let host = NativeHost::new(
            SigningKey::from_bytes(&[3; 32]).expect("valid test key"),
            move |_| {
                observed.fetch_add(1, Ordering::SeqCst);
            },
        );
        let bound = AsmProofHost::bind::<StrataAsmSpec>(host).unwrap();
        let input = |predicate| {
            RuntimeInput::new(
                MohoState::new(
                    InnerStateCommitment::new([0; 32]),
                    predicate,
                    ExportState::new(vec![]).unwrap(),
                ),
                vec![],
                vec![],
            )
        };

        let rejected = input(PredicateKey::always_accept());
        assert!(matches!(
            bound.start_proving(&rejected).await,
            Err(ProverError::UnsupportedAsmPredicate { .. })
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        let accepted = input(bound.descriptor().predicate().clone());
        bound.start_proving(&accepted).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
