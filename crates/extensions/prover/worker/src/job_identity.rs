//! Durable proof-job identity derivation and restart validation.

use strata_asm_prover_types::{
    AsmProofJobIdentity, MohoProofJobIdentity, ProofId, ProofJobIdentity, RemoteProofJob,
};

use crate::{
    ProverContext,
    errors::{ProverError, ProverResult},
    hosts::AsmHosts,
    input::InputBuilder,
};

/// Derives the only qualified artifact identity valid for `proof_id` now.
pub(crate) async fn expected_job_identity<C, H>(
    ctx: &C,
    input_builder: &InputBuilder,
    asm: &AsmHosts<H>,
    moho: &MohoProofJobIdentity,
    proof_id: &ProofId,
) -> ProverResult<ProofJobIdentity>
where
    C: ProverContext + Send + Sync,
{
    match proof_id {
        ProofId::Asm(range) => {
            let predicate = input_builder.asm_predicate(ctx, range).await?;
            let artifact = asm.resolve_artifact(&predicate).ok_or_else(|| {
                ProverError::MissingAsmArtifact {
                    predicate: format!("{predicate:?}"),
                }
            })?;
            Ok(ProofJobIdentity::Asm(AsmProofJobIdentity {
                predicate,
                spec_id: artifact.spec_id,
                artifact_id: artifact.artifact_id,
            }))
        }
        ProofId::Moho(_) => Ok(ProofJobIdentity::Moho(moho.clone())),
    }
}

/// Validates an active job against authenticated state and this release's
/// qualified artifacts, binding a migrated legacy marker exactly once.
pub(crate) async fn validate_or_bind_job_identity<C, H>(
    ctx: &C,
    input_builder: &InputBuilder,
    asm: &AsmHosts<H>,
    moho: &MohoProofJobIdentity,
    job: RemoteProofJob,
) -> ProverResult<RemoteProofJob>
where
    C: ProverContext + Send + Sync,
{
    let expected = expected_job_identity(ctx, input_builder, asm, moho, &job.proof_id).await?;
    let is_matching_legacy = matches!(
        (&job.identity, &expected),
        (
            ProofJobIdentity::LegacyUnqualifiedAsm,
            ProofJobIdentity::Asm(_)
        ) | (
            ProofJobIdentity::LegacyUnqualifiedMoho,
            ProofJobIdentity::Moho(_)
        )
    );

    if is_matching_legacy {
        return ctx
            .bind_legacy_remote_proof_job(&job.remote_id, expected)
            .await
            .map_err(|error| {
                ProverError::storage("failed to bind legacy proof job identity", error)
            });
    }

    if job.identity != expected {
        return Err(ProverError::ProofJobIdentityMismatch {
            proof_id: job.proof_id.to_string(),
            stored: format!("{:?}", job.identity),
            expected: format!("{expected:?}"),
        });
    }

    Ok(job)
}

#[cfg(test)]
mod tests {
    use strata_asm_common::{AsmArtifactId, AsmSpecId, GuestArtifactId};
    use strata_asm_prover_types::{L1Range, RemoteProofId};
    use strata_identifiers::{L1BlockCommitment, L1BlockId};
    use strata_predicate::{PredicateKey, PredicateTypeId};
    use zkaleido::RemoteProofStatus;

    use super::*;

    fn predicate(seed: u8) -> PredicateKey {
        PredicateKey::try_new(PredicateTypeId::Bip340Schnorr, vec![seed; 32]).unwrap()
    }

    fn block(height: u32) -> L1BlockCommitment {
        L1BlockCommitment::new(height, L1BlockId::default())
    }

    #[test]
    fn exact_artifact_identity_is_part_of_equality() {
        let proof_id = ProofId::Asm(L1Range::single(block(42)));
        let first = RemoteProofJob {
            proof_id,
            remote_id: RemoteProofId(vec![1]),
            identity: ProofJobIdentity::Asm(AsmProofJobIdentity {
                predicate: predicate(1),
                spec_id: AsmSpecId::V1,
                artifact_id: AsmArtifactId::new([1; 32]),
            }),
            status: RemoteProofStatus::Requested,
        };
        let mut rebuilt = first.clone();
        let ProofJobIdentity::Asm(identity) = &mut rebuilt.identity else {
            unreachable!()
        };
        identity.artifact_id = GuestArtifactId::new([2; 32]);

        assert_ne!(first.identity, rebuilt.identity);
    }
}
