//! ZK proof backend setup for the prover worker.
//!
//! Bundles the feature-gated selection of the ZK proof backend in one place:
//! host construction (SP1 or native, in [`sp1`] / [`native`]) and derivation of
//! the [`PredicateKey`] that authorizes proofs from each host. The result is
//! exposed as a single [`ProofBackend`] value that the runner builds once at
//! startup and threads into the proof orchestrator and the input builder.
//!
//! The ASM side is plural. One artifact implements one specification, so a node
//! that spans an upgrade boundary loads one artifact per specification and picks
//! between them per block — see [`AsmHosts`]. Each artifact's predicate is
//! *derived* from its own verifying key rather than configured, so the predicate
//! a node proves under cannot drift from the artifact it actually loaded.

mod native;
mod sp1;

use sha2::{Digest, Sha256};
use strata_asm_common::{AsmSpecId, GuestArtifactId};
use strata_predicate::PredicateKey;
use zkaleido::{ZkVm, ZkVmHost};
#[cfg(feature = "sp1")]
use zkaleido_sp1_host::SP1Host;

use crate::{
    config::BackendConfig,
    errors::{ProverError, ProverResult},
    hosts::{ArtifactQualification, AsmHost, AsmHosts},
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
/// Bundles the ASM artifact set together with the Moho host and the
/// [`PredicateKey`] its proofs verify against. Constructed once at startup via
/// [`ProofBackend::new`] and consumed by the proof orchestrator.
#[derive(Debug)]
pub struct ProofBackend {
    /// ASM proving artifacts, keyed by the predicate each one's proofs verify
    /// against.
    pub asm: AsmHosts<ProofHost>,
    pub moho_host: ProofHost,
    pub moho_predicate: PredicateKey,
    /// Stable identity of the exact Moho artifact used for recursive jobs.
    pub moho_artifact_id: GuestArtifactId,
}

impl ProofBackend {
    /// Builds the ZK proof backend.
    ///
    /// Constructs every configured host and resolves the [`PredicateKey`] each
    /// host's proofs verify against, then validates the ASM artifact set (see
    /// [`AsmHosts::new`]).
    ///
    /// # Errors
    ///
    /// - Returns an error if the requested [`BackendConfig`] variant does not match the binary's
    ///   build features (e.g. `Sp1` requested without the `sp1` feature).
    /// - Returns an error if any host cannot be constructed (e.g. a guest ELF cannot be read in
    ///   `sp1` builds) or if a host's verifying key cannot be turned into a [`PredicateKey`].
    /// - Returns an error if the ASM artifact set is empty, or if two artifacts claim the same
    ///   predicate.
    pub async fn new(cfg: &BackendConfig) -> ProverResult<Self> {
        let (asm_hosts, moho) = build_proof_hosts(cfg).await?;
        let qualification = if cfg.is_unqualified_development() {
            ArtifactQualification::Development
        } else {
            ArtifactQualification::Release
        };

        let mut artifacts = Vec::with_capacity(asm_hosts.len());
        for (qualified_id, spec_id, host) in asm_hosts {
            let predicate = resolve_predicate(&host)?;
            let artifact_id = qualified_id
                .unwrap_or_else(|| development_artifact_id("asm", Some(spec_id), &predicate));
            artifacts.push(AsmHost {
                artifact_id,
                spec_id,
                predicate,
                host,
            });
        }

        let asm = AsmHosts::new(artifacts, qualification)?;
        let moho_predicate = resolve_predicate(&moho.host)?;
        let moho_artifact_id = moho
            .qualified_id
            .unwrap_or_else(|| development_artifact_id("moho", None, &moho_predicate));

        Ok(Self {
            asm,
            moho_host: moho.host,
            moho_predicate,
            moho_artifact_id,
        })
    }
}

/// Builds the ASM hosts — one per configured specification — and the Moho host.
///
/// Dispatches on the [`BackendConfig`] variant. If the variant does not
/// match the binary's build features, the corresponding builder surfaces a
/// clear startup error rather than failing later in the proving path.
async fn build_proof_hosts(
    cfg: &BackendConfig,
) -> ProverResult<(Vec<PreparedAsmHost>, PreparedMohoHost)> {
    match cfg {
        BackendConfig::Sp1 {
            asm_guests,
            moho_guest,
        } => sp1::build_sp1_hosts(asm_guests, moho_guest).await,
        BackendConfig::NativeDevelopment {
            asm_guests,
            moho_schnorr_signing_key,
        } => native::build_native_hosts(asm_guests, moho_schnorr_signing_key).await,
    }
}

type PreparedAsmHost = (Option<GuestArtifactId>, AsmSpecId, ProofHost);

struct PreparedMohoHost {
    qualified_id: Option<GuestArtifactId>,
    host: ProofHost,
}

fn development_artifact_id(
    program: &str,
    spec_id: Option<AsmSpecId>,
    predicate: &PredicateKey,
) -> GuestArtifactId {
    let mut hasher = Sha256::new();
    hasher.update(b"strata-asm-unqualified-native-development-artifact-v1");
    hasher.update(u64::try_from(program.len()).unwrap().to_le_bytes());
    hasher.update(program.as_bytes());
    match spec_id {
        Some(spec_id) => {
            hasher.update([1]);
            hasher.update(spec_id.as_u16().to_le_bytes());
        }
        None => hasher.update([0]),
    }
    hasher.update([predicate.id()]);
    hasher.update(
        u64::try_from(predicate.condition().len())
            .unwrap()
            .to_le_bytes(),
    );
    hasher.update(predicate.condition());
    GuestArtifactId::new(hasher.finalize().into())
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
