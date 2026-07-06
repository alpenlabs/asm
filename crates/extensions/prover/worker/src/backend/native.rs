//! Native (in-process) proof host construction and predicate resolution.

use anyhow::Result;
use k256::schnorr::SigningKey;
use strata_predicate::{PredicateKey, PredicateTypeId};
use zkaleido::ZkVmHost;

use super::ProofHost;
use crate::config::NativeAsmEntry;

/// Resolves the [`PredicateKey`] for a native host.
///
/// Native execution does not produce a real cryptographic proof; the predicate
/// simply carries the verifying-key bytes verbatim under the BIP-340 Schnorr
/// type as a placeholder identifier.
pub(super) fn resolve_native_predicate(host: &impl ZkVmHost) -> Result<PredicateKey> {
    Ok(PredicateKey::new(
        PredicateTypeId::Bip340Schnorr,
        host.vk().as_bytes().to_vec(),
    ))
}

#[cfg(feature = "sp1")]
pub(super) async fn build_native_hosts(
    _asm_entries: &[NativeAsmEntry],
    _moho_signing_key: &SigningKey,
) -> Result<(Vec<ProofHost>, ProofHost)> {
    anyhow::bail!("native backend requested but binary was built with the `sp1` feature");
}

#[cfg(not(feature = "sp1"))]
pub(super) async fn build_native_hosts(
    asm_entries: &[NativeAsmEntry],
    moho_signing_key: &SigningKey,
) -> Result<(Vec<ProofHost>, ProofHost)> {
    // Bypass the `*::native_host()` convenience constructors: they call
    // `NativeHost::new_with_random_key`, which would make each host's
    // verifying key — and therefore its derived `PredicateKey` — different
    // on every restart. The orchestrator needs stable predicate identities
    // across runs, so we construct `NativeHost` directly with the keys
    // supplied by config.
    use moho_recursive_proof::process_recursive_moho_proof;
    use strata_asm_proof_impl::statements::process_asm_stf;
    use zkaleido_native_adapter::NativeHost;

    // Each entry's STF params are baked into its execution closure, exactly
    // as a guest ELF hardcodes its own params.
    let asm_hosts = asm_entries
        .iter()
        .map(|entry| {
            let stf_params = entry.stf_params.clone();
            NativeHost::new(entry.schnorr_signing_key.clone(), move |env| {
                process_asm_stf(env, stf_params.clone())
            })
        })
        .collect();

    Ok((
        asm_hosts,
        NativeHost::new(moho_signing_key.clone(), process_recursive_moho_proof),
    ))
}
