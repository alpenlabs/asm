//! SP1 proof host construction and predicate resolution.

use strata_predicate::PredicateKey;
use zkaleido::ZkVmHost;
#[cfg(feature = "sp1")]
use {
    sp1_sdk::{HashableKey, SP1VerifyingKey},
    sp1_verifier::{GROTH16_VK_BYTES, VK_ROOT_BYTES},
    strata_asm_spec::{GuestProgram, qualified_guest_artifacts},
    strata_predicate::PredicateTypeId,
    zkaleido_sp1_groth16_verifier::SP1Groth16Verifier,
    zkaleido_sp1_host::SP1Host,
};

use super::{PreparedAsmHost, PreparedMohoHost};
use crate::{
    config::AsmGuestConfig,
    errors::{ProverError, ProverResult},
};

#[cfg(feature = "sp1")]
pub(super) async fn build_sp1_hosts(
    asm_guests: &[AsmGuestConfig],
    moho_guest: &AsmGuestConfig,
) -> ProverResult<(Vec<PreparedAsmHost>, PreparedMohoHost)> {
    let releases = qualified_guest_artifacts()
        .map_err(|e| ProverError::backend("failed to load qualified guest manifests", e))?;

    let mut asm_hosts = Vec::with_capacity(asm_guests.len());
    for guest in asm_guests {
        let (manifest, artifact) = releases.resolve(&guest.artifact_id).ok_or_else(|| {
            ProverError::UnknownQualifiedArtifact {
                artifact_id: guest.artifact_id.to_string(),
            }
        })?;
        if artifact.program != GuestProgram::Asm {
            return Err(ProverError::ArtifactRoleMismatch {
                artifact_id: guest.artifact_id.to_string(),
                expected: "asm",
                actual: "moho",
            });
        }
        let spec_id = artifact
            .asm_spec_id
            .expect("validated ASM artifacts always carry asm_spec_id");
        let expected_predicate = artifact.predicate.clone();
        let verified = manifest
            .verify_artifact_files(artifact, &guest.elf_path, &guest.vk_path)
            .map_err(|e| ProverError::backend("ASM artifact integrity check failed", e))?;
        let host = SP1Host::init(&verified.elf).await;
        let actual_predicate = resolve_sp1_predicate(&host)?;
        if actual_predicate != expected_predicate {
            return Err(ProverError::ArtifactPredicateMismatch {
                artifact_id: guest.artifact_id.to_string(),
                expected: format!("{expected_predicate:?}"),
                actual: format!("{actual_predicate:?}"),
            });
        }
        asm_hosts.push((Some(guest.artifact_id), spec_id, host));
    }

    let (manifest, artifact) = releases.resolve(&moho_guest.artifact_id).ok_or_else(|| {
        ProverError::UnknownQualifiedArtifact {
            artifact_id: moho_guest.artifact_id.to_string(),
        }
    })?;
    if artifact.program != GuestProgram::Moho {
        return Err(ProverError::ArtifactRoleMismatch {
            artifact_id: moho_guest.artifact_id.to_string(),
            expected: "moho",
            actual: "asm",
        });
    }
    let expected_predicate = artifact.predicate.clone();
    let verified = manifest
        .verify_artifact_files(artifact, &moho_guest.elf_path, &moho_guest.vk_path)
        .map_err(|e| ProverError::backend("Moho artifact integrity check failed", e))?;
    let host = SP1Host::init(&verified.elf).await;
    let actual_predicate = resolve_sp1_predicate(&host)?;
    if actual_predicate != expected_predicate {
        return Err(ProverError::ArtifactPredicateMismatch {
            artifact_id: moho_guest.artifact_id.to_string(),
            expected: format!("{expected_predicate:?}"),
            actual: format!("{actual_predicate:?}"),
        });
    }

    Ok((
        asm_hosts,
        PreparedMohoHost {
            qualified_id: Some(moho_guest.artifact_id),
            host,
        },
    ))
}

#[cfg(not(feature = "sp1"))]
pub(super) async fn build_sp1_hosts(
    _asm_guests: &[AsmGuestConfig],
    _moho_guest: &AsmGuestConfig,
) -> ProverResult<(Vec<PreparedAsmHost>, PreparedMohoHost)> {
    Err(ProverError::BackendUnavailable(
        "sp1 backend requested but binary was built without the `sp1` feature",
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
///
/// The vk is the artifact's own, so the predicate this yields identifies the ELF
/// that was actually loaded — which is what lets the artifact set double as the
/// predicate-to-specification table.
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
