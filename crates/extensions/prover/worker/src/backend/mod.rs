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
pub use registry::{AsmHostLoader, AsmHostRegistry};
use strata_asm_common::{AsmSpec, SpecId};
use strata_predicate::PredicateKey;
use zkaleido::{ZkVm, ZkVmHost};
#[cfg(feature = "sp1")]
use zkaleido_sp1_host::SP1Host;

use crate::{
    config::{AsmArtifactConfig, AsmArtifactSource, BackendConfig, OrchestratorConfig},
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
/// Owns the lazy ASM host registry, the fixed Moho host, and its predicate.
/// The node supplies the loader that knows its compiled specs.
#[derive(Debug)]
pub struct ProofBackend<L: AsmHostLoader> {
    pub asm_host: AsmHostRegistry<L>,
    pub moho_host: L::Host,
    pub moho_predicate: PredicateKey,
}

impl<L: AsmHostLoader<Host = ProofHost>> ProofBackend<L> {
    /// Builds the ZK proof backend.
    ///
    /// Constructs the fixed Moho host and registers ASM artifact data.
    /// Each ASM key is checked against its declared predicate when first loaded.
    ///
    /// # Errors
    ///
    /// - Returns an error if the requested [`BackendConfig`] variant does not match the binary's
    ///   build features (e.g. `Sp1` requested without the `sp1` feature).
    /// - Returns an error for unsupported or duplicate ASM registrations, or if the Moho host
    ///   cannot be constructed. ASM loading and key validation happen on first use.
    pub async fn new(
        config: &OrchestratorConfig,
        initial_spec: SpecId,
        loader: L,
    ) -> ProverResult<Self> {
        let (source, moho_host) = match &config.backend {
            BackendConfig::Sp1 {
                asm_elf_path,
                moho_elf_path,
            } => (
                AsmArtifactSource::Sp1 {
                    elf_path: asm_elf_path.clone(),
                },
                sp1::load_host(moho_elf_path).await?,
            ),
            BackendConfig::Native {
                asm_schnorr_signing_key,
                moho_schnorr_signing_key,
            } => (
                AsmArtifactSource::Native {
                    signing_key: asm_schnorr_signing_key.clone(),
                },
                native::moho_host(moho_schnorr_signing_key)?,
            ),
        };
        let mut asm_host = AsmHostRegistry::new(config.max_loaded_asm_hosts, loader);
        asm_host.register(AsmArtifactConfig {
            spec_id: initial_spec,
            predicate: config.asm_predicate.clone(),
            source,
        })?;
        for artifact in &config.asm_artifacts {
            if !matches!(
                (&config.backend, &artifact.source),
                (BackendConfig::Sp1 { .. }, AsmArtifactSource::Sp1 { .. })
                    | (
                        BackendConfig::Native { .. },
                        AsmArtifactSource::Native { .. }
                    )
            ) {
                return Err(ProverError::BackendUnavailable(
                    "ASM artifacts must use the node's configured backend",
                ));
            }
            asm_host.register(artifact.clone())?;
        }
        let moho_predicate = resolve_predicate(&moho_host)?;
        Ok(Self {
            asm_host,
            moho_host,
            moho_predicate,
        })
    }
}

/// Loads a proof host bound to a concrete spec and derives its descriptor.
/// The registry checks this descriptor against the configured spec and predicate.
pub async fn load_spec_host<S: AsmSpec + Send + Sync + 'static>(
    source: &AsmArtifactSource,
    spec: S,
) -> ProverResult<AsmProofHost<ProofHost>> {
    let host = match source {
        AsmArtifactSource::Sp1 { elf_path } => sp1::load_host(elf_path).await?,
        AsmArtifactSource::Native { signing_key } => native::asm_host(signing_key.clone(), spec)?,
    };
    AsmProofHost::bind::<S>(host)
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
