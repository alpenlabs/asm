//! Predicate-to-specification bindings qualified by released artifacts.
//!
//! A predicate authorizes a program, but does not encode this crate's semantic
//! [`AsmSpecId`](strata_asm_common::AsmSpecId). A node without proving artifacts therefore cannot
//! derive which native target a predicate selects. Its only safe authority is a binding reviewed
//! with the release artifact and compiled into the runner.
//!
//! Entries are append-only. The baseline binding below is the predicate published with
//! `v0.3.0-rc.2`; it lets a non-proving node replay the existing L1 history under baseline rules.
//! The successor binding must be appended only after the successor ELF is qualified. Until then a
//! non-proving node deliberately halts at that handover instead of guessing.

use crate::{
    ReleaseManifestError, StrataAsmTarget, StrataAsmTargets, TargetTableError,
    qualified_guest_artifacts,
};

/// A checked-in release binding could not be loaded.
#[derive(Debug, thiserror::Error)]
pub enum ReleaseTargetError {
    /// A checked-in artifact manifest is malformed or self-inconsistent.
    #[error(transparent)]
    InvalidManifest(#[from] ReleaseManifestError),

    /// The release table violates the one-predicate-to-one-specification rule.
    #[error(transparent)]
    InvalidTable(#[from] TargetTableError),
}

/// Builds the predicate-to-target table backed by qualified release artifacts.
///
/// The current table intentionally contains only the released baseline artifact. This is enough
/// to replay existing L1 transactions correctly. The final release-qualification change appends
/// the successor artifact binding; an enacted predicate absent from this table remains a hard
/// stop in the worker.
pub fn qualified_release_targets() -> Result<StrataAsmTargets, ReleaseTargetError> {
    let artifacts = qualified_guest_artifacts()?;
    let bindings = artifacts
        .asm_artifacts()
        .map(|artifact| {
            let spec_id = artifact
                .asm_spec_id
                .expect("ASM artifact manifests require asm_spec_id");
            (
                artifact.predicate.clone(),
                StrataAsmTarget::for_spec_id(spec_id),
            )
        })
        .collect();

    Ok(StrataAsmTargets::new(bindings)?)
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};
    use strata_asm_common::AsmSpecId;

    use super::*;

    const BASELINE_PREDICATE_JSON: &str = include_str!("../release/v0.3.0-rc.2/asm-vk.json");

    /// Digest published beside `asm-vk.json` in the `v0.3.0-rc.2` GitHub release.
    const BASELINE_PREDICATE_SHA256: &str =
        "d3303f17e741960aa648534ad1ada2d20db396815c7baa1012d881082982e31a";

    #[test]
    fn released_baseline_predicate_selects_baseline_rules() {
        let targets = qualified_release_targets().expect("release table is valid");
        assert_eq!(targets.entries().len(), 1);

        let (predicate, target) = &targets.entries()[0];
        assert_eq!(*target, StrataAsmTarget::V0);
        assert_eq!(targets.resolve(predicate), Some(StrataAsmTarget::V0));
        assert_eq!(target.spec_id(), AsmSpecId::V0);
    }

    #[test]
    fn checked_in_predicate_matches_the_published_release_asset() {
        // Source files conventionally end in LF; the published JSON asset does not. The parsed
        // JSON is identical, and hashing the release payload bytes must reproduce its published
        // checksum.
        let release_bytes = BASELINE_PREDICATE_JSON
            .strip_suffix('\n')
            .unwrap_or(BASELINE_PREDICATE_JSON)
            .as_bytes();
        let actual = Sha256::digest(release_bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();

        assert_eq!(actual, BASELINE_PREDICATE_SHA256);
    }
}
