//! Native (in-process) proof host construction and predicate resolution.

use k256::schnorr::SigningKey;
use strata_predicate::{PredicateKey, PredicateTypeId};
use zkaleido::ZkVmHost;
#[cfg(not(feature = "sp1"))]
use {strata_asm_common::AsmSpec, strata_asm_proof_impl::statements::process_asm_stf};

use super::ProofHost;
use crate::errors::{ProverError, ProverResult};

/// Resolves the [`PredicateKey`] for a native host.
///
/// Native execution does not produce a real cryptographic proof; the predicate
/// simply carries the verifying-key bytes verbatim under the BIP-340 Schnorr
/// type as a placeholder identifier.
pub(super) fn resolve_native_predicate(host: &impl ZkVmHost) -> ProverResult<PredicateKey> {
    PredicateKey::try_new(
        PredicateTypeId::Bip340Schnorr,
        host.vk().as_bytes().to_vec(),
    )
    .map_err(|e| ProverError::backend("failed to construct native predicate key", e))
}

/// Builds native execution with the concrete spec captured outside the witness.
#[cfg(not(feature = "sp1"))]
pub(super) fn asm_host<S: AsmSpec + Send + Sync + 'static>(
    key: SigningKey,
    spec: S,
) -> ProverResult<ProofHost> {
    Ok(ProofHost::new(key, move |zkvm| {
        process_asm_stf(zkvm, &spec)
    }))
}

#[cfg(feature = "sp1")]
pub(super) fn asm_host<S>(_: SigningKey, _: S) -> ProverResult<ProofHost> {
    Err(ProverError::BackendUnavailable(
        "native requires a non-SP1 build",
    ))
}

#[cfg(not(feature = "sp1"))]
pub(super) fn moho_host(key: &SigningKey) -> ProverResult<ProofHost> {
    Ok(ProofHost::new(
        key.clone(),
        moho_recursive_proof::process_recursive_moho_proof,
    ))
}

#[cfg(feature = "sp1")]
pub(super) fn moho_host(_: &SigningKey) -> ProverResult<ProofHost> {
    Err(ProverError::BackendUnavailable(
        "native requires a non-SP1 build",
    ))
}
