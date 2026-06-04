//! ZK proof backend setup for the runner.
//!
//! Bundles the feature-gated selection of the ZK proof backend in one place:
//! host construction (SP1 or native), and derivation of the [`PredicateKey`]
//! that authorizes proofs from each host. The result is exposed as a single
//! [`ProofBackend`] value that the runner builds once at startup and threads
//! into the proof orchestrator and the input builder.

use std::path::Path;

use anyhow::{Result, bail};
use k256::schnorr::SigningKey;
use strata_predicate::{PredicateKey, PredicateTypeId};
use zkaleido::{ZkVm, ZkVmHost};
#[cfg(feature = "sp1")]
use {
    anyhow::Context,
    sp1_sdk::{HashableKey, SP1VerifyingKey},
    sp1_verifier::{GROTH16_VK_BYTES, VK_ROOT_BYTES},
    zkaleido_sp1_groth16_verifier::SP1Groth16Verifier,
    zkaleido_sp1_host::SP1Host,
};

use crate::prover::config::BackendConfig;

/// Concrete host type used by the proof orchestrator.
///
/// Resolves to [`SP1Host`] when the `sp1` feature is enabled, otherwise to
/// the in-process [`zkaleido_native_adapter::NativeHost`].
#[cfg(feature = "sp1")]
pub(crate) type ProofHost = SP1Host;

#[cfg(not(feature = "sp1"))]
pub(crate) type ProofHost = zkaleido_native_adapter::NativeHost;

/// ZK proof backend used by the runner.
///
/// Bundles the `(asm, moho)` host pair together with the [`PredicateKey`] that
/// each one's proofs verify against. Constructed once at startup via
/// [`ProofBackend::new`] and consumed by the proof orchestrator (hosts) and
/// the input builder (predicates).
#[derive(Debug)]
pub(crate) struct ProofBackend {
    pub(crate) asm_host: ProofHost,
    pub(crate) moho_host: ProofHost,
    pub(crate) asm_predicate: PredicateKey,
    pub(crate) moho_predicate: PredicateKey,
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
    pub(crate) async fn new(cfg: &BackendConfig) -> Result<Self> {
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
/// match the binary's build features, surfaces a clear startup error rather
/// than failing later in the proving path.
async fn build_proof_hosts(cfg: &BackendConfig) -> Result<(ProofHost, ProofHost)> {
    match cfg {
        BackendConfig::Sp1 {
            asm_elf_path,
            moho_elf_path,
        } => build_sp1_hosts(asm_elf_path, moho_elf_path).await,
        BackendConfig::Native {
            asm_schnorr_signing_key,
            moho_schnorr_signing_key,
        } => build_native_hosts(asm_schnorr_signing_key, moho_schnorr_signing_key).await,
    }
}

#[cfg(feature = "sp1")]
async fn build_sp1_hosts(
    asm_elf_path: &Path,
    moho_elf_path: &Path,
) -> Result<(ProofHost, ProofHost)> {
    use std::fs;

    let asm_elf = fs::read(asm_elf_path)
        .with_context(|| format!("failed to read ASM guest ELF at {}", asm_elf_path.display()))?;
    let moho_elf = fs::read(moho_elf_path).with_context(|| {
        format!(
            "failed to read Moho guest ELF at {}",
            moho_elf_path.display()
        )
    })?;

    Ok((
        SP1Host::init(&asm_elf).await,
        SP1Host::init(&moho_elf).await,
    ))
}

#[cfg(not(feature = "sp1"))]
async fn build_sp1_hosts(
    _asm_elf_path: &Path,
    _moho_elf_path: &Path,
) -> Result<(ProofHost, ProofHost)> {
    bail!("sp1 backend requested but binary was built without the `sp1` feature");
}

#[cfg(feature = "sp1")]
async fn build_native_hosts(
    _asm_signing_key: &SigningKey,
    _moho_signing_key: &SigningKey,
) -> Result<(ProofHost, ProofHost)> {
    bail!("native backend requested but binary was built with the `sp1` feature");
}

#[cfg(not(feature = "sp1"))]
async fn build_native_hosts(
    asm_signing_key: &SigningKey,
    moho_signing_key: &SigningKey,
) -> Result<(ProofHost, ProofHost)> {
    // Bypass the `*::native_host()` convenience constructors: they call
    // `NativeHost::new_with_random_key`, which would make each host's
    // verifying key — and therefore its derived `PredicateKey` — different
    // on every restart. The orchestrator needs stable predicate identities
    // across runs, so we construct `NativeHost` directly with the keys
    // supplied by config.
    use moho_recursive_proof::process_recursive_moho_proof;
    use strata_asm_proof_impl::statements::process_asm_stf;
    use zkaleido_native_adapter::NativeHost;

    Ok((
        NativeHost::new(asm_signing_key.clone(), process_asm_stf),
        NativeHost::new(moho_signing_key.clone(), process_recursive_moho_proof),
    ))
}

/// Resolves the [`PredicateKey`] for proofs produced by `host`.
///
/// The returned key carries both the predicate type (matching the host's
/// [`ZkVm`] backend) and the encoded verifying-key material required to
/// validate proofs from that host.
///
/// # Errors
///
/// - For SP1 hosts, returns an error if the host's verifying key cannot be deserialized into an
///   `SP1VerifyingKey` or if the SP1 Groth16 verifier cannot be loaded for the resulting program
///   hash.
/// - For Risc0 hosts, returns an error because predicate resolution is not yet implemented for that
///   backend.
/// - When built without the `sp1` feature, an SP1 host returns an error because the SP1
///   verifying-key handling is gated behind that feature.
fn resolve_predicate(host: &impl ZkVmHost) -> Result<PredicateKey> {
    match host.zkvm() {
        // Native execution does not produce a real cryptographic proof; the
        // predicate simply carries the verifying-key bytes verbatim under the
        // BIP-340 Schnorr type as a placeholder identifier.
        ZkVm::Native => Ok(PredicateKey::new(
            PredicateTypeId::Bip340Schnorr,
            host.vk().as_bytes().to_vec(),
        )),

        // SP1 proofs are wrapped in a Groth16 proof, so the on-chain
        // predicate must identify the SP1 Groth16 verifying key (not the SP1
        // program vk itself). The conversion is:
        //   1. Decode the SP1 verifying key from the host's raw bytes.
        //   2. Hash it to obtain the program commitment expected by the Groth16 verifier.
        //   3. Load the matching Groth16 verifier and serialize its vk into the predicate key.
        #[cfg(feature = "sp1")]
        ZkVm::SP1 => {
            let vk = host.vk();
            let sp1_vk: SP1VerifyingKey = bincode::deserialize(vk.as_bytes())
                .context("failed to deserialize SP1 verifying key")?;

            let verifier = SP1Groth16Verifier::load(
                &GROTH16_VK_BYTES,
                sp1_vk.bytes32_raw(),
                *VK_ROOT_BYTES,
                true,
            )
            .context("failed to load SP1 Groth16 verifier")?;

            Ok(PredicateKey::new(
                PredicateTypeId::Sp1Groth16,
                verifier.to_uncompressed_bytes(),
            ))
        }
        #[cfg(not(feature = "sp1"))]
        ZkVm::SP1 => bail!("SP1 predicate key resolution requires the `sp1` feature"),

        // Risc0 support is not yet wired up; surface a clear error rather
        // than panicking so callers can fail gracefully.
        ZkVm::Risc0 => bail!("predicate key resolution is not implemented for Risc0"),
    }
}
