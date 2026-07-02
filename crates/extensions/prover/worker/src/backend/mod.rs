//! ZK proof backend setup for the prover worker.
//!
//! Bundles the feature-gated selection of the ZK proof backend in one place:
//! host construction (SP1 or native, in [`sp1`] / [`native`]) and derivation of
//! the [`PredicateKey`] that authorizes proofs from each host. The result is
//! exposed as a single [`ProofBackend`] value that the runner builds once at
//! startup and threads into the proof orchestrator and the input builder.

mod native;
mod sp1;

use strata_predicate::PredicateKey;
use zkaleido::{ZkVm, ZkVmHost};
#[cfg(feature = "sp1")]
use zkaleido_sp1_host::SP1Host;

use crate::{
    config::BackendConfig,
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
/// Bundles the `(asm, moho)` host pair together with the [`PredicateKey`] that
/// each one's proofs verify against. Constructed once at startup via
/// [`ProofBackend::new`] and consumed by the proof orchestrator (hosts) and
/// the input builder (predicates).
#[derive(Debug)]
pub struct ProofBackend {
    pub asm_host: ProofHost,
    pub moho_host: ProofHost,
    pub asm_predicate: PredicateKey,
    pub moho_predicate: PredicateKey,
}

impl ProofBackend {
    /// Builds the ZK proof backend.
    ///
    /// Constructs both proof hosts and resolves the [`PredicateKey`] each
    /// host's proofs verify against.
    ///
    /// # Errors
    ///
    /// - Returns an error if the requested [`BackendConfig`] variant does not match the binary's
    ///   build features (e.g. `Sp1` requested without the `sp1` feature).
    /// - Returns an error if either host cannot be constructed (e.g. a guest ELF cannot be read in
    ///   `sp1` builds) or if either host's verifying key cannot be turned into a [`PredicateKey`].
    pub async fn new(cfg: &BackendConfig) -> ProverResult<Self> {
        let (asm_host, moho_host) = build_proof_hosts(cfg).await?;
        let asm_predicate = resolve_predicate(&asm_host)?;
        let moho_predicate = resolve_predicate(&moho_host)?;
        Ok(Self {
            asm_host,
            moho_host,
            asm_predicate,
            moho_predicate,
        })
    }
}

/// Builds the `(asm, moho)` host pair used by the proof orchestrator.
///
/// Dispatches on the [`BackendConfig`] variant. If the variant does not
/// match the binary's build features, the corresponding builder surfaces a
/// clear startup error rather than failing later in the proving path.
async fn build_proof_hosts(cfg: &BackendConfig) -> ProverResult<(ProofHost, ProofHost)> {
    match cfg {
        BackendConfig::Sp1 {
            asm_elf_path,
            moho_elf_path,
        } => sp1::build_sp1_hosts(asm_elf_path, moho_elf_path).await,
        BackendConfig::Native {
            asm_schnorr_signing_key,
            moho_schnorr_signing_key,
        } => native::build_native_hosts(asm_schnorr_signing_key, moho_schnorr_signing_key).await,
    }
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
