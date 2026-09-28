//! SP1 proof host construction and predicate resolution.

use std::path::Path;

use strata_predicate::PredicateKey;
use zkaleido::ZkVmHost;
#[cfg(feature = "sp1")]
use {
    sp1_sdk::{HashableKey, SP1VerifyingKey},
    sp1_verifier::{GROTH16_VK_BYTES, VK_ROOT_BYTES},
    std::fs,
    strata_predicate::PredicateTypeId,
    zkaleido_sp1_groth16_verifier::SP1Groth16Verifier,
    zkaleido_sp1_host::SP1Host,
};

use super::ProofHost;
use crate::errors::{ProverError, ProverResult};

/// Loads an SP1 host from the guest ELF at `path`.
///
/// Runs at startup before worker tasks begin. The ELF read is synchronous;
/// host setup uses the SDK async API.
#[cfg(feature = "sp1")]
pub(super) async fn load_host(path: &Path) -> ProverResult<ProofHost> {
    let elf = fs::read(path).map_err(|e| ProverError::backend("failed to read guest ELF", e))?;
    Ok(SP1Host::init(&elf).await)
}

#[cfg(not(feature = "sp1"))]
pub(super) async fn load_host(_path: &Path) -> ProverResult<ProofHost> {
    Err(ProverError::BackendUnavailable(
        "sp1 artifact requested but binary was built without the `sp1` feature",
    ))
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
pub(super) fn resolve_sp1_predicate(host: &impl ZkVmHost) -> ProverResult<PredicateKey> {
    let vk = host.vk();
    let sp1_vk: SP1VerifyingKey = bincode::deserialize(vk.as_bytes())
        .map_err(|e| ProverError::backend("failed to deserialize SP1 verifying key", e))?;

    let verifier = SP1Groth16Verifier::load(
        &GROTH16_VK_BYTES,
        sp1_vk.bytes32_raw(),
        *VK_ROOT_BYTES,
        true,
    )
    .map_err(|e| ProverError::backend("failed to load SP1 Groth16 verifier", e))?;

    PredicateKey::try_new(
        PredicateTypeId::Sp1Groth16,
        verifier.to_uncompressed_bytes(),
    )
    .map_err(|e| ProverError::backend("failed to construct SP1 predicate key", e))
}

#[cfg(not(feature = "sp1"))]
pub(super) fn resolve_sp1_predicate(_host: &impl ZkVmHost) -> ProverResult<PredicateKey> {
    Err(ProverError::BackendUnavailable(
        "SP1 predicate key resolution requires the `sp1` feature",
    ))
}
