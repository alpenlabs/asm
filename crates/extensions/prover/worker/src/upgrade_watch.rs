//! Early warning for queued ASM upgrades this node cannot prove.
//!
//! An ASM verifying-key update waits in the admin queue until its activation
//! height. Once it activates, the next ASM step needs the new program, and a
//! node without that artifact stops with
//! [`ProverError::UnknownArtifact`](crate::ProverError::UnknownArtifact).
//! Checking the queue on every committed block gives the operator the whole
//! confirmation window to add the artifact before that happens.

use strata_asm_common::{AnchorState, AsmResult, SectionStateExt, Subprotocol};
use strata_asm_proto_admin::{AdministrationSubprotocol, QueuedUpdate};
use strata_asm_proto_admin_txs::actions::UpdateAction;
use strata_identifiers::L1BlockCommitment;
use strata_predicate::PredicateKey;
use tracing::warn;

use crate::{AnchorStateReader, AsmHostRegistry};

/// Warns once for each queued ASM verifying-key update in the anchor state at
/// `block` whose program is missing from `asm`.
///
/// This is a diagnostic only, so read and decode failures are logged rather
/// than returned. Proof scheduling reads the same state and reports its own
/// failures.
pub(crate) fn warn_unprovable_asm_upgrades<C, H>(
    ctx: &C,
    asm: &AsmHostRegistry<H>,
    block: &L1BlockCommitment,
) where
    C: AnchorStateReader,
{
    let anchor = match ctx.get_anchor_state(block) {
        Ok(anchor) => anchor,
        Err(e) => {
            warn!(?e, %block, "failed to read anchor state for queued ASM upgrade check");
            return;
        }
    };
    let queued = match queued_admin_updates(&anchor) {
        Ok(queued) => queued,
        Err(e) => {
            warn!(?e, %block, "failed to decode admin state for queued ASM upgrade check");
            return;
        }
    };
    for (update, predicate) in unprovable_asm_upgrades(&queued, asm) {
        warn!(
            %block,
            update_id = update.id(),
            activation_height = update.activation_height(),
            %predicate,
            "queued ASM upgrade has no configured artifact; the prover will stop when it activates"
        );
    }
}

/// Returns the admin queue from `anchor`, or an empty one if the anchor state
/// has no admin section.
fn queued_admin_updates(anchor: &AnchorState) -> AsmResult<Vec<QueuedUpdate>> {
    let Some(section) = anchor.find_section(AdministrationSubprotocol::ID) else {
        return Ok(Vec::new());
    };
    let admin = section.try_to_state::<AdministrationSubprotocol>()?;
    Ok(admin.queued().to_vec())
}

/// Yields each queued ASM verifying-key update whose predicate has no host in `asm`.
fn unprovable_asm_upgrades<'a, H>(
    queued: &'a [QueuedUpdate],
    asm: &'a AsmHostRegistry<H>,
) -> impl Iterator<Item = (&'a QueuedUpdate, &'a PredicateKey)> {
    queued.iter().filter_map(|update| match update.action() {
        UpdateAction::AsmStfVk(vk) if asm.get(vk.key()).is_err() => Some((update, vk.key())),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use k256::schnorr::SigningKey;
    use strata_asm_proof_impl::statements::process_asm_stf;
    use strata_asm_proto_admin_txs::actions::updates::{AsmStfVkUpdate, OlStfVkUpdate};
    use strata_asm_spec::StrataAsmSpec;
    use zkaleido_native_adapter::NativeHost;

    use super::*;
    use crate::AsmProofHost;

    /// Returns a registry with one host, and that host's predicate.
    fn registry() -> (AsmHostRegistry<NativeHost>, PredicateKey) {
        let key = SigningKey::from_bytes(&[1; 32]).expect("valid test key");
        let host = NativeHost::new(key, |zkvm| process_asm_stf(zkvm, &StrataAsmSpec));
        let host = AsmProofHost::bind::<StrataAsmSpec>(host).expect("native host binds");
        let predicate = host.descriptor().predicate().clone();
        let registry = AsmHostRegistry::new(vec![host]).expect("one host is a valid registry");
        (registry, predicate)
    }

    #[test]
    fn flags_only_asm_upgrades_without_an_artifact() {
        let (asm, known) = registry();
        let unknown = PredicateKey::always_accept();
        let queued = vec![
            QueuedUpdate::new(0, UpdateAction::AsmStfVk(AsmStfVkUpdate::new(known)), 10),
            QueuedUpdate::new(
                1,
                UpdateAction::AsmStfVk(AsmStfVkUpdate::new(unknown.clone())),
                20,
            ),
            // Other verifying keys are proven elsewhere and must not be flagged.
            QueuedUpdate::new(
                2,
                UpdateAction::OlStfVk(OlStfVkUpdate::new(unknown.clone())),
                30,
            ),
        ];

        let flagged: Vec<_> = unprovable_asm_upgrades(&queued, &asm)
            .map(|(update, predicate)| (*update.id(), predicate.clone()))
            .collect();
        assert_eq!(flagged, vec![(1, unknown)]);
    }
}
