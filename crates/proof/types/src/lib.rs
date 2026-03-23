//! Proof-related types used across the bridge.

use std::cmp::Ordering;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use strata_identifiers::L1BlockCommitment;
use zkaleido::ProofReceiptWithMetadata;

/// ASM step proof for a range of L1 blocks.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct AsmProof(pub ProofReceiptWithMetadata);

/// Moho recursive proof, valid up to some L1 block commitment.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct MohoProof(pub ProofReceiptWithMetadata);

/// Identifies a proof by its kind and block reference.
///
/// Ordered by ascending height (smallest height first). For ASM proofs the
/// start height of the range is used. When an ASM proof and a Moho proof share
/// the same height, the ASM proof comes first because the ASM proof is a
/// prerequisite for Moho construction at that height.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub enum ProofId {
    /// An ASM step proof covering an L1 range.
    Asm(L1Range),
    /// A Moho recursive proof anchored at an L1 block commitment.
    Moho(L1BlockCommitment),
}

impl ProofId {
    /// Returns the height used for ordering.
    ///
    /// For ASM proofs this is the start height; for Moho proofs the anchor height.
    fn ordering_height(&self) -> u32 {
        match self {
            ProofId::Asm(range) => range.start().height(),
            ProofId::Moho(commitment) => commitment.height(),
        }
    }

    /// Returns a discriminant used to break ties at the same height.
    ///
    /// ASM = 0 (comes first), Moho = 1.
    const fn variant_rank(&self) -> u8 {
        match self {
            ProofId::Asm(_) => 0,
            ProofId::Moho(_) => 1,
        }
    }
}

impl Ord for ProofId {
    fn cmp(&self, other: &Self) -> Ordering {
        self.ordering_height()
            .cmp(&other.ordering_height())
            .then_with(|| self.variant_rank().cmp(&other.variant_rank()))
            .then_with(|| {
                // Within the same variant and height, break ties by full key.
                match (self, other) {
                    (ProofId::Asm(a), ProofId::Asm(b)) => a.cmp(b),
                    (ProofId::Moho(a), ProofId::Moho(b)) => a.cmp(b),
                    // Different variants at same height already handled by variant_rank.
                    _ => Ordering::Equal,
                }
            })
    }
}

impl PartialOrd for ProofId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Opaque identifier assigned by the remote prover service.
///
/// Wraps raw bytes since zkaleido's `ZkVmRemoteProver::ProofId` associated type
/// has `Into<Vec<u8>> + TryFrom<Vec<u8>>` bounds, allowing any backend's ID
/// to be stored generically.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RemoteProofId(pub Vec<u8>);

/// A range of L1 blocks defined by start and end commitments.
///
/// Ordered by start commitment first, then end commitment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, BorshSerialize, BorshDeserialize)]
pub struct L1Range {
    /// The start of the range (inclusive).
    start: L1BlockCommitment,
    /// The end of the range (inclusive).
    end: L1BlockCommitment,
}

impl L1Range {
    /// Creates a new `L1Range` from start and end commitments.
    ///
    /// Returns `None` if `end` height is strictly less than `start` height.
    pub fn new(start: L1BlockCommitment, end: L1BlockCommitment) -> Option<Self> {
        if end.height() < start.height() {
            return None;
        }
        Some(Self { start, end })
    }

    /// Creates a range that covers a single block (start == end).
    pub const fn single(block: L1BlockCommitment) -> Self {
        Self {
            start: block,
            end: block,
        }
    }

    /// Returns the start of the range.
    pub const fn start(&self) -> L1BlockCommitment {
        self.start
    }

    /// Returns the end of the range.
    pub const fn end(&self) -> L1BlockCommitment {
        self.end
    }
}
