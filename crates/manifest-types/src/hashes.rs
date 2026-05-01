//! Strongly-typed wrappers around [`Buf32`] for ASM manifest hashes.

#[cfg(feature = "arbitrary")]
use arbitrary::Arbitrary;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use strata_identifiers::{Buf32, impl_buf_wrapper, impl_ssz_transparent_wrapper};

/// Hash of a single ASM manifest (one L1 block's manifest).
///
/// Produced by [`AsmManifest::compute_hash`](crate::AsmManifest::compute_hash); consumed by
/// [`compute_asm_manifests_hash_from_leaves`](crate::compute_asm_manifests_hash_from_leaves)
/// when committing to a range of manifests.
#[derive(
    Copy,
    Clone,
    Eq,
    Default,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Encode,
    Decode,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
pub struct AsmManifestHash(Buf32);

impl_buf_wrapper!(AsmManifestHash, Buf32, 32);
impl_ssz_transparent_wrapper!(AsmManifestHash, Buf32);

impl From<[u8; 32]> for AsmManifestHash {
    fn from(bytes: [u8; 32]) -> Self {
        Self(Buf32::from(bytes))
    }
}

/// Commitment hash over the ASM manifests covered by a checkpoint's L1 range.
///
/// Produced by [`compute_asm_manifests_hash`](crate::compute_asm_manifests_hash) and
/// [`compute_asm_manifests_hash_from_leaves`](crate::compute_asm_manifests_hash_from_leaves).
#[derive(
    Copy,
    Clone,
    Eq,
    Default,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Encode,
    Decode,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
pub struct AsmManifestRangeHash(Buf32);

impl AsmManifestRangeHash {
    /// All-zero range hash.
    ///
    /// Returned by [`compute_asm_manifests_hash`](crate::compute_asm_manifests_hash) and
    /// [`compute_asm_manifests_hash_from_leaves`](crate::compute_asm_manifests_hash_from_leaves)
    /// when there are no manifests in the range — i.e. when a checkpoint's L1 range is empty
    /// (zero L1 progress). Callers may use it directly as a sentinel for empty-range commitments.
    pub const ZERO: Self = Self(Buf32::zero());
}

impl_buf_wrapper!(AsmManifestRangeHash, Buf32, 32);
impl_ssz_transparent_wrapper!(AsmManifestRangeHash, Buf32);

impl From<[u8; 32]> for AsmManifestRangeHash {
    fn from(bytes: [u8; 32]) -> Self {
        Self(Buf32::from(bytes))
    }
}
