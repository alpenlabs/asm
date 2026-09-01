//! The ASM proving artifacts a node can use, keyed by authorizing predicate.
//!
//! A guest artifact bakes in the rules it executes, so one artifact proves one
//! specification. Which specification a block ran under is decided by the
//! predicate its parent handed over — the value the recursive proof verifies each
//! step against — so proving a block means selecting the artifact whose own
//! predicate is that value.
//!
//! Nothing here guesses. A predicate with no artifact is an error, never a
//! fallback to whichever artifact happens to be loaded: a proof produced by the
//! wrong artifact does not verify, and submitting one wastes a proving job while
//! reporting success.

use strata_asm_common::{AsmArtifactId, AsmSpecId};
use strata_predicate::PredicateKey;

use crate::errors::{ProverError, ProverResult};

/// One ASM guest artifact: the rules it implements, the predicate its proofs
/// verify against, and the host that proves with it.
#[derive(Debug, Clone)]
pub struct AsmHost<H> {
    /// Stable identity of the qualified artifact statement.
    pub artifact_id: AsmArtifactId,

    /// The specification this artifact implements.
    pub spec_id: AsmSpecId,

    /// The predicate proofs from this artifact verify against, derived from the
    /// artifact's own verifying key.
    pub predicate: PredicateKey,

    /// The proving host bound to this artifact.
    pub host: H,
}

/// Whether an artifact came from the immutable release registry or the
/// explicitly unproven native-development backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactQualification {
    /// The artifact and its semantic binding are release-qualified.
    Release,
    /// A domain-separated native artifact used only by regtest development.
    Development,
}

/// The ASM artifacts one node can prove with.
///
/// Ordered as supplied; lookup is by predicate. The set is small — one entry per
/// specification the chain has run under — so a linear scan is the right shape.
#[derive(Debug, Clone)]
pub struct AsmHosts<H> {
    entries: Vec<AsmHost<H>>,
    qualification: ArtifactQualification,
}

impl<H> AsmHosts<H> {
    /// Builds the artifact set, rejecting anything that would make selection
    /// ambiguous or impossible.
    ///
    /// Both checks are about the *set*, and both are fatal at startup rather
    /// than per block:
    ///
    /// - an empty set could prove nothing, so a prover configured with no ASM artifact is a
    ///   misconfiguration, not a node that quietly proves nothing.
    /// - a predicate bound to two artifacts would make which artifact proves a block depend on
    ///   lookup order.
    ///
    /// Two artifacts *may* share a specification: rebuilding the same rules with
    /// a different verifying key produces a second predicate for the same
    /// specification, and both must stay provable across the rotation.
    pub fn new(
        entries: Vec<AsmHost<H>>,
        qualification: ArtifactQualification,
    ) -> ProverResult<Self> {
        if entries.is_empty() {
            return Err(ProverError::NoAsmArtifacts);
        }

        for (index, entry) in entries.iter().enumerate() {
            if entries[..index]
                .iter()
                .any(|prior| prior.predicate == entry.predicate)
            {
                return Err(ProverError::AmbiguousAsmArtifact {
                    predicate: format!("{:?}", entry.predicate),
                });
            }
            if entries[..index]
                .iter()
                .any(|prior| prior.artifact_id == entry.artifact_id)
            {
                return Err(ProverError::DuplicateAsmArtifactId {
                    artifact_id: entry.artifact_id.to_string(),
                });
            }
        }

        Ok(Self {
            entries,
            qualification,
        })
    }

    /// Returns the host that proves blocks `predicate` authorizes.
    pub fn resolve(&self, predicate: &PredicateKey) -> Option<&H> {
        self.resolve_artifact(predicate).map(|entry| &entry.host)
    }

    /// Returns the full qualified artifact metadata selected by `predicate`.
    pub fn resolve_artifact(&self, predicate: &PredicateKey) -> Option<&AsmHost<H>> {
        self.entries
            .iter()
            .find(|entry| &entry.predicate == predicate)
    }

    /// Returns the artifact with this stable release identity.
    pub fn resolve_artifact_id(&self, artifact_id: &AsmArtifactId) -> Option<&AsmHost<H>> {
        self.entries
            .iter()
            .find(|entry| &entry.artifact_id == artifact_id)
    }

    /// Returns the host that proves blocks `predicate` authorizes, or a typed
    /// error when this node did not load that artifact.
    pub fn require(&self, predicate: &PredicateKey) -> ProverResult<&H> {
        self.resolve(predicate)
            .ok_or_else(|| ProverError::MissingAsmArtifact {
                predicate: format!("{predicate:?}"),
            })
    }

    /// Returns the `(predicate, specification)` binding each artifact carries.
    ///
    /// This is what a proving node hands the ASM worker as its target table: the
    /// bindings are then derived from the artifacts actually loaded rather than
    /// authored separately and kept in agreement.
    pub fn bindings(&self) -> impl Iterator<Item = (&PredicateKey, AsmSpecId)> {
        self.entries
            .iter()
            .map(|entry| (&entry.predicate, entry.spec_id))
    }

    /// Returns every loaded artifact and its release identity.
    pub fn artifacts(&self) -> impl Iterator<Item = &AsmHost<H>> {
        self.entries.iter()
    }

    /// Reports whether this set is release-qualified or development-only.
    pub const fn qualification(&self) -> ArtifactQualification {
        self.qualification
    }

    /// Returns any one host, for operations that need only its network client.
    ///
    /// Querying a remote proof's status is addressed by proof id alone, so any
    /// host using the same backend client serves. Do not use this to retrieve a
    /// completed proof: the SP1 adapter attaches the calling host's program ID
    /// to the returned receipt, so retrieval must use the artifact that
    /// submitted the job. Never use this to *prove*: that is what
    /// [`require`](Self::require) is for.
    pub fn client(&self) -> &H {
        &self
            .entries
            .first()
            .expect("a non-empty artifact set is an invariant of AsmHosts::new")
            .host
    }
}

#[cfg(test)]
mod tests {
    use strata_predicate::PredicateTypeId;

    use super::*;

    fn predicate(seed: u8) -> PredicateKey {
        PredicateKey::try_new(PredicateTypeId::Bip340Schnorr, vec![seed; 32])
            .expect("valid predicate")
    }

    /// Hosts are opaque here; a label is enough to tell one from another.
    fn artifact(spec_id: AsmSpecId, seed: u8, host: &'static str) -> AsmHost<&'static str> {
        AsmHost {
            artifact_id: AsmArtifactId::new([seed; 32]),
            spec_id,
            predicate: predicate(seed),
            host,
        }
    }

    #[test]
    fn each_predicate_selects_its_own_artifact() {
        let hosts = AsmHosts::new(
            vec![
                artifact(AsmSpecId::V0, 1, "v0"),
                artifact(AsmSpecId::V1, 2, "v1"),
            ],
            ArtifactQualification::Release,
        )
        .expect("valid artifact set");

        assert_eq!(hosts.resolve(&predicate(1)), Some(&"v0"));
        assert_eq!(hosts.resolve(&predicate(2)), Some(&"v1"));
    }

    /// The property the whole selection model rests on: a predicate this node
    /// has no artifact for resolves to nothing, never to a silent fallback that
    /// would produce a proof nothing accepts. The caller turns that into a
    /// refusal to submit the job; see `schedule`.
    #[test]
    fn an_unknown_predicate_resolves_to_nothing() {
        let hosts = AsmHosts::new(
            vec![artifact(AsmSpecId::V1, 2, "v1")],
            ArtifactQualification::Release,
        )
        .expect("valid set");

        assert_eq!(hosts.resolve(&predicate(9)), None);
        assert!(matches!(
            hosts.require(&predicate(9)),
            Err(ProverError::MissingAsmArtifact { .. })
        ));
    }

    #[test]
    fn a_predicate_bound_twice_is_rejected() {
        assert!(matches!(
            AsmHosts::new(
                vec![
                    artifact(AsmSpecId::V0, 1, "v0"),
                    artifact(AsmSpecId::V1, 1, "v1"),
                ],
                ArtifactQualification::Release,
            ),
            Err(ProverError::AmbiguousAsmArtifact { .. })
        ));
    }

    /// A verifying-key rotation that changes no rules yields a second predicate
    /// for the same specification, and both must keep proving.
    #[test]
    fn two_artifacts_may_share_a_specification() {
        let hosts = AsmHosts::new(
            vec![
                artifact(AsmSpecId::V1, 1, "old-key"),
                artifact(AsmSpecId::V1, 2, "new-key"),
            ],
            ArtifactQualification::Release,
        )
        .expect("a rotation without a rule change is valid");

        assert_eq!(hosts.resolve(&predicate(1)), Some(&"old-key"));
        assert_eq!(hosts.resolve(&predicate(2)), Some(&"new-key"));
    }

    #[test]
    fn an_empty_set_is_rejected() {
        assert!(matches!(
            AsmHosts::<&str>::new(Vec::new(), ArtifactQualification::Release),
            Err(ProverError::NoAsmArtifacts)
        ));
    }

    /// The bindings a proving node hands the ASM worker come straight from the
    /// artifacts it loaded, so the two cannot disagree.
    #[test]
    fn bindings_mirror_the_loaded_artifacts() {
        let hosts = AsmHosts::new(
            vec![
                artifact(AsmSpecId::V0, 1, "v0"),
                artifact(AsmSpecId::V1, 2, "v1"),
            ],
            ArtifactQualification::Release,
        )
        .expect("valid artifact set");

        assert_eq!(
            hosts.bindings().collect::<Vec<_>>(),
            vec![
                (&predicate(1), AsmSpecId::V0),
                (&predicate(2), AsmSpecId::V1),
            ],
        );
    }
}
