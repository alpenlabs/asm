//! ZK proof backend setup for the prover worker.
//!
//! Bundles the feature-gated selection of the ZK proof backend in one place:
//! host construction (SP1 or native, in [`sp1`] / [`native`]) and derivation of
//! the [`PredicateKey`] that authorizes proofs from each host. The result is
//! exposed as a single [`ProofBackend`] value that the runner builds once at
//! startup and threads into the proof orchestrator and the input builder.

mod native;
mod sp1;

use anyhow::{Result, bail, ensure};
use strata_predicate::PredicateKey;
use zkaleido::{ZkVm, ZkVmHost};
#[cfg(feature = "sp1")]
use zkaleido_sp1_host::SP1Host;

use crate::config::BackendConfig;

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
/// Bundles the ASM host set — one host per configured proving artifact, each
/// paired with the [`PredicateKey`] its proofs verify against — with the
/// single Moho host. Multiple ASM hosts let the prover span an ASM VK
/// upgrade: each block's step proof is produced by the host matching the
/// predicate the parent `MohoState` advertises. Constructed once at startup
/// via [`ProofBackend::new`] and consumed by the proof orchestrator.
#[derive(Debug)]
pub struct ProofBackend {
    /// ASM hosts in config order; index 0 is the genesis-time artifact.
    pub asm_hosts: Vec<(PredicateKey, ProofHost)>,
    pub moho_host: ProofHost,
    pub moho_predicate: PredicateKey,
}

impl ProofBackend {
    /// Builds the ZK proof backend.
    ///
    /// Constructs every proof host and resolves the [`PredicateKey`] each
    /// host's proofs verify against.
    ///
    /// # Errors
    ///
    /// - Returns an error if the requested [`BackendConfig`] variant does not match the binary's
    ///   build features (e.g. `Sp1` requested without the `sp1` feature).
    /// - Returns an error if no ASM proving artifact is configured.
    /// - Returns an error if a host cannot be constructed (e.g. a guest ELF cannot be read in `sp1`
    ///   builds) or if a host's verifying key cannot be turned into a [`PredicateKey`].
    pub async fn new(cfg: &BackendConfig) -> Result<Self> {
        let (asm_hosts, moho_host) = match cfg {
            BackendConfig::Sp1 {
                asm_elf_paths,
                moho_elf_path,
            } => sp1::build_sp1_hosts(asm_elf_paths, moho_elf_path).await?,
            BackendConfig::Native {
                asm_entries,
                moho_schnorr_signing_key,
            } => native::build_native_hosts(asm_entries, moho_schnorr_signing_key).await?,
        };
        ensure!(
            !asm_hosts.is_empty(),
            "at least one ASM proving artifact must be configured"
        );

        let asm_hosts = asm_hosts
            .into_iter()
            .map(|host| Ok((resolve_predicate(&host)?, host)))
            .collect::<Result<Vec<_>>>()?;
        let moho_predicate = resolve_predicate(&moho_host)?;

        Ok(Self {
            asm_hosts,
            moho_host,
            moho_predicate,
        })
    }

    /// Predicate of the genesis-time ASM artifact (config entry 0), which
    /// seeds the genesis Moho state.
    pub fn genesis_asm_predicate(&self) -> &PredicateKey {
        &self.asm_hosts[0].0
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
fn resolve_predicate(host: &impl ZkVmHost) -> Result<PredicateKey> {
    match host.zkvm() {
        ZkVm::Native => native::resolve_native_predicate(host),
        ZkVm::SP1 => sp1::resolve_sp1_predicate(host),
        // Risc0 support is not yet wired up; surface a clear error rather
        // than panicking so callers can fail gracefully.
        ZkVm::Risc0 => bail!("predicate key resolution is not implemented for Risc0"),
    }
}
