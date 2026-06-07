//! SP1 proof host construction and predicate resolution.

use std::path::Path;

use anyhow::Result;
use strata_predicate::PredicateKey;
use zkaleido::ZkVmHost;
#[cfg(feature = "sp1")]
use {
    anyhow::Context,
    sp1_sdk::{HashableKey, SP1VerifyingKey},
    sp1_verifier::{GROTH16_VK_BYTES, VK_ROOT_BYTES},
    strata_predicate::PredicateTypeId,
    zkaleido_sp1_groth16_verifier::SP1Groth16Verifier,
    zkaleido_sp1_host::SP1Host,
};

use super::ProofHost;

#[cfg(feature = "sp1")]
pub(super) async fn build_sp1_hosts(
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
pub(super) async fn build_sp1_hosts(
    _asm_elf_path: &Path,
    _moho_elf_path: &Path,
) -> Result<(ProofHost, ProofHost)> {
    anyhow::bail!("sp1 backend requested but binary was built without the `sp1` feature");
}

/// Resolves the [`PredicateKey`] for an SP1 host.
///
/// SP1 proofs are wrapped in a Groth16 proof, so the on-chain predicate must
/// identify the SP1 Groth16 verifying key (not the SP1 program vk itself). The
/// conversion is:
///   1. Decode the SP1 verifying key from the host's raw bytes.
///   2. Hash it to obtain the program commitment expected by the Groth16 verifier.
///   3. Load the matching Groth16 verifier and serialize its vk into the predicate key.
#[cfg(feature = "sp1")]
pub(super) fn resolve_sp1_predicate(host: &impl ZkVmHost) -> Result<PredicateKey> {
    let vk = host.vk();
    let sp1_vk: SP1VerifyingKey =
        bincode::deserialize(vk.as_bytes()).context("failed to deserialize SP1 verifying key")?;

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
pub(super) fn resolve_sp1_predicate(_host: &impl ZkVmHost) -> Result<PredicateKey> {
    anyhow::bail!("SP1 predicate key resolution requires the `sp1` feature");
}
