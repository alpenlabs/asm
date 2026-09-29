//! Frozen baseline checkpoint proofs bind the manifest commitment as well as its bytes.

use ssz::{Decode, Encode};
use ssz_types::VariableList;
use strata_asm_checkpoint_types::{CheckpointClaim, CheckpointPayload, CheckpointTip};
use strata_asm_manifest_types::{
    AsmLogEntry, AsmManifest, AsmManifestHash, compute_asm_manifests_hash,
    compute_asm_manifests_hash_from_leaves,
};
use strata_identifiers::{Buf32, L1BlockId, WtxidsRoot};
use strata_predicate::PredicateKey;
use tree_hash::{Sha256Hasher, TreeHash};

use crate::{
    CheckpointL1Range, CheckpointState, CheckpointValidationError,
    errors::InvalidCheckpointPayload, verification::construct_full_claim, verify_progression,
};

/// The fixture producer's manifest schema, with the log list bounded at 1,024 entries.
///
/// It uses the production SSZ derives, so the test records the effect of the bound
/// whichever bound production currently uses.
#[derive(ssz_derive::Encode, tree_hash_derive::TreeHash)]
struct BaselineManifest {
    height: u32,
    blkid: L1BlockId,
    wtxids_root: WtxidsRoot,
    logs: VariableList<AsmLogEntry, 1024>,
}

impl BaselineManifest {
    fn from_manifest(manifest: &AsmManifest) -> Self {
        Self {
            height: manifest.height(),
            blkid: *manifest.blkid(),
            wtxids_root: *manifest.wtxids_root(),
            logs: VariableList::new(manifest.logs().to_vec()).unwrap(),
        }
    }

    fn root(&self) -> AsmManifestHash {
        AsmManifestHash::from(self.tree_hash_root::<Sha256Hasher>().0)
    }
}

#[test]
fn baseline_signed_checkpoint_advances_with_production_manifest_commitment() {
    let previous =
        CheckpointTip::from_ssz_bytes(include_bytes!("../test-data/baseline/previous-tip.ssz"))
            .unwrap();
    let payload =
        CheckpointPayload::from_ssz_bytes(include_bytes!("../test-data/baseline/checkpoint.ssz"))
            .unwrap();
    let predicate =
        PredicateKey::from_ssz_bytes(include_bytes!("../test-data/baseline/predicate.ssz"))
            .unwrap();
    let baseline_claim = include_bytes!("../test-data/baseline/claim.ssz");
    let manifest_bytes = include_bytes!("../test-data/baseline/manifest.ssz");
    let manifest = AsmManifest::from_ssz_bytes(manifest_bytes).unwrap();
    let baseline = BaselineManifest::from_manifest(&manifest);
    assert_eq!(baseline.as_ssz_bytes(), manifest_bytes);

    assert_eq!(manifest.compute_hash(), baseline.root());
    let baseline_range = compute_asm_manifests_hash(&[manifest]);
    let reconstructed = construct_full_claim(
        &previous,
        payload.new_tip(),
        payload.sidecar(),
        baseline_range,
    )
    .unwrap();
    assert_eq!(reconstructed.as_ssz_bytes(), baseline_claim);
    assert_eq!(
        reconstructed,
        CheckpointClaim::from_ssz_bytes(baseline_claim).unwrap()
    );
    assert_ne!(predicate, PredicateKey::always_accept());
    let state = CheckpointState::new(Buf32::from([1; 32]), predicate, previous);
    assert!(matches!(
        verify_progression(
            state.verified_tip(),
            payload.new_tip(),
            101,
            state.next_transition()
        )
        .unwrap(),
        CheckpointL1Range::Range {
            start_height: 100,
            end_height: 100
        }
    ));

    // Exercise state advancement, not only standalone signature verification.
    let mut accepted = state.clone();
    assert!(
        accepted
            .advance(&payload, baseline_range)
            .unwrap()
            .is_empty()
    );
    assert_eq!(accepted.verified_tip(), payload.new_tip());

    // The same signed checkpoint payload cannot advance state against a different leaf.
    let mut changed_bytes = manifest_bytes.to_vec();
    changed_bytes[4] ^= 1;
    let changed = AsmManifest::from_ssz_bytes(&changed_bytes).unwrap();
    let changed_range =
        compute_asm_manifests_hash_from_leaves(&[BaselineManifest::from_manifest(&changed).root()]);
    let mut rejected = state.clone();
    assert!(matches!(
        rejected.advance(&payload, changed_range),
        Err(CheckpointValidationError::InvalidPayload(
            InvalidCheckpointPayload::CheckpointPredicateVerification(_)
        ))
    ));
    assert_eq!(
        rejected, state,
        "a rejected checkpoint must not mutate state"
    );
}
