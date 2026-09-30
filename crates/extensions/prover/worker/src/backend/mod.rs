//! ZK proof backend setup for the prover worker.
//!
//! Bundles the feature-gated selection of the ZK proof backend in one place:
//! host construction (SP1 or native, in [`sp1`] / [`native`]) and derivation of
//! the [`PredicateKey`] that authorizes proofs from each host. The result is
//! exposed as a single [`ProofBackend`] value that the runner builds once at
//! startup and threads into the proof orchestrator and the input builder.

mod artifact;
mod native;
mod registry;
mod sp1;

pub use artifact::{AsmProgramDescriptor, AsmProofHost};
pub use registry::AsmHostRegistry;
use strata_asm_common::AsmSpec;
use strata_predicate::PredicateKey;
use zkaleido::{ZkVm, ZkVmHost};
#[cfg(feature = "sp1")]
use zkaleido_sp1_host::SP1Host;

use crate::{
    config::ArtifactSource,
    errors::{ProverError, ProverResult},
};

/// Concrete host type used by the proof orchestrator.
///
/// Resolves to [`SP1Host`] when the `sp1` feature is enabled, otherwise to
/// the in-process [`zkaleido_native_adapter::NativeHost`].
#[cfg(feature = "sp1")]
pub type ProofHost = SP1Host;

#[cfg(not(feature = "sp1"))]
pub type ProofHost = zkaleido_native_adapter::NativeHost;

/// ZK proof backend used by the runner.
///
/// Bundles the ASM host registry, the fixed Moho host, and the
/// [`PredicateKey`] that Moho proofs verify against. Constructed once at
/// startup via [`ProofBackend::new`] and consumed by the proof orchestrator
/// (hosts) and the input builder (predicate).
#[derive(Debug)]
pub struct ProofBackend {
    pub asm_hosts: AsmHostRegistry<ProofHost>,
    pub moho_host: ProofHost,
    pub moho_predicate: PredicateKey,
}

impl ProofBackend {
    /// Builds the ZK proof backend from the Moho source and ASM hosts already
    /// loaded with [`load_spec_host`].
    ///
    /// # Errors
    ///
    /// - Returns an error if the Moho source does not match the binary's build features (e.g. `Sp1`
    ///   without the `sp1` feature), its host cannot be constructed, or its verifying key cannot be
    ///   turned into a [`PredicateKey`].
    /// - Returns an error if `asm_hosts` is empty or repeats a spec or predicate.
    pub async fn new(
        moho: &ArtifactSource,
        asm_hosts: Vec<AsmProofHost<ProofHost>>,
    ) -> ProverResult<Self> {
        let moho_host = match moho {
            ArtifactSource::Sp1 { elf_path } => sp1::load_host(elf_path).await?,
            ArtifactSource::Native { signing_key } => native::moho_host(signing_key)?,
        };
        let asm_hosts = AsmHostRegistry::new(asm_hosts)?;
        let moho_predicate = resolve_predicate(&moho_host)?;
        Ok(Self {
            asm_hosts,
            moho_host,
            moho_predicate,
        })
    }
}

/// Loads the ASM host from `source` and binds it to spec `S`.
///
/// The caller is responsible for pairing `expected` with the spec it
/// implements (the execution registry records that pairing).
///
/// # Errors
///
/// - Returns an error if the source does not match the binary's build features or its host cannot
///   be constructed.
/// - Returns [`ProverError::AsmArtifactMismatch`] if the loaded host's predicate differs from
///   `expected`, so a wrong ELF or key fails at startup.
pub async fn load_spec_host<S: AsmSpec + Send + Sync + 'static>(
    source: &ArtifactSource,
    expected: &PredicateKey,
    spec: S,
) -> ProverResult<AsmProofHost<ProofHost>> {
    let host = match source {
        ArtifactSource::Sp1 { elf_path } => sp1::load_host(elf_path).await?,
        ArtifactSource::Native { signing_key } => native::asm_host(signing_key.clone(), spec)?,
    };
    AsmProofHost::bind_expected::<S>(host, expected)
}

/// Resolves the [`PredicateKey`] for proofs produced by `host`, dispatching on
/// its [`ZkVm`] backend.
///
/// # Errors
///
/// - For SP1 hosts, returns an error if the verifying key cannot be decoded or the Groth16 verifier
///   cannot be loaded (and, when built without the `sp1` feature, that the feature is required).
/// - For Risc0 hosts, returns an error because predicate resolution is not yet implemented.
fn resolve_predicate(host: &impl ZkVmHost) -> ProverResult<PredicateKey> {
    match host.zkvm() {
        ZkVm::Native => native::resolve_native_predicate(host),
        ZkVm::SP1 => sp1::resolve_sp1_predicate(host),
        // Risc0 support is not yet wired up; surface a clear error rather
        // than panicking so callers can fail gracefully.
        ZkVm::Risc0 => Err(ProverError::BackendUnavailable(
            "predicate key resolution is not implemented for Risc0",
        )),
    }
}
