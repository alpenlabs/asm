//! Native (in-process) proof host construction and predicate resolution.

use k256::schnorr::SigningKey;
#[cfg(not(feature = "sp1"))]
use strata_asm_common::AsmSpecId;
use strata_predicate::{PredicateKey, PredicateTypeId};
use zkaleido::ZkVmHost;

use super::{PreparedAsmHost, PreparedMohoHost};
use crate::{
    config::NativeAsmGuestConfig,
    errors::{ProverError, ProverResult},
};

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

#[cfg(feature = "sp1")]
pub(super) async fn build_native_hosts(
    _asm_guests: &[NativeAsmGuestConfig],
    _moho_signing_key: &SigningKey,
) -> ProverResult<(Vec<PreparedAsmHost>, PreparedMohoHost)> {
    Err(ProverError::BackendUnavailable(
        "native backend requested but binary was built with the `sp1` feature",
    ))
}

#[cfg(not(feature = "sp1"))]
pub(super) async fn build_native_hosts(
    asm_guests: &[NativeAsmGuestConfig],
    moho_signing_key: &SigningKey,
) -> ProverResult<(Vec<PreparedAsmHost>, PreparedMohoHost)> {
    // Bypass the `*::native_host()` convenience constructors: they call
    // `NativeHost::new_with_random_key`, which would make each host's
    // verifying key — and therefore its derived `PredicateKey` — different
    // on every restart. The orchestrator needs stable predicate identities
    // across runs, so we construct `NativeHost` directly with the keys
    // supplied by config.
    use moho_recursive_proof::process_recursive_moho_proof;
    use strata_asm_proof_impl::statements::{process_asm_stf, process_asm_stf_v0};
    use zkaleido_native_adapter::NativeHost;

    let asm_hosts = asm_guests
        .iter()
        .map(|guest| {
            let key = guest.schnorr_signing_key.clone();
            // The statement is what fixes the rules a native host executes,
            // exactly as a built ELF does for the SP1 backend. The match is
            // exhaustive, so a new specification cannot be added without
            // deciding which statement stands for it here.
            let host = match guest.spec {
                AsmSpecId::V0 => NativeHost::new(key, process_asm_stf_v0),
                AsmSpecId::V1 => NativeHost::new(key, process_asm_stf),
            };
            (None, guest.spec, host)
        })
        .collect();

    Ok((
        asm_hosts,
        PreparedMohoHost {
            qualified_id: None,
            host: NativeHost::new(moho_signing_key.clone(), process_recursive_moho_proof),
        },
    ))
}
