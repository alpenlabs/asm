//! Proof-related types used across the bridge.

use std::{cmp::Ordering, fmt};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use strata_asm_common::{AsmArtifactId, AsmSpecId, GuestArtifactId};
use strata_identifiers::L1BlockCommitment;
use strata_predicate::PredicateKey;
use zkaleido::{ProofReceiptWithMetadata, RemoteProofStatus};

/// Status snapshot of a prover worker.
///
/// Produced by the prover worker's service monitor and served over RPC, so
/// operators — and follower nodes deciding whether to fetch or fall back to
/// local proving — can judge how far a prover has progressed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProverStatus {
    /// Number of proofs queued but not yet submitted or fetched.
    pub pending: usize,

    /// Most recent block the Moho worker committed, if any — from the
    /// current session's commit subscription, or persisted state after a
    /// restart.
    pub last_committed: Option<L1BlockCommitment>,

    /// Highest block with a completed Moho recursive proof, if any. The gap
    /// between this and `last_committed` is the work still in flight or
    /// pending.
    pub last_proven: Option<L1BlockCommitment>,
}

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

impl fmt::Display for ProofId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProofId::Asm(range) => write!(f, "Asm({})", range),
            ProofId::Moho(commitment) => write!(f, "Moho({})", commitment),
        }
    }
}

impl ProofId {
    /// Returns the proof's L1 height.
    ///
    /// For ASM proofs this is the start height; for Moho proofs the anchor
    /// height. Also used for ordering.
    pub fn height(&self) -> u32 {
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
        self.height()
            .cmp(&other.height())
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
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize)]
pub struct RemoteProofId(pub Vec<u8>);

impl fmt::Display for RemoteProofId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Immutable identity of the qualified ASM artifact selected for a proof job.
///
/// The predicate says which program the recursive verifier authorizes, the
/// specification names the native rules that program implements, and the
/// artifact id commits to the canonical artifact entry plus the shared release
/// provenance that qualified the exact ELF.
/// Persisting all three prevents a restart or configuration change from
/// silently reinterpreting an already-submitted remote job.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AsmProofJobIdentity {
    /// Predicate committed by the parent Moho state.
    pub predicate: PredicateKey,
    /// Semantic ASM rules implemented by the selected artifact.
    pub spec_id: AsmSpecId,
    /// Digest of the canonical artifact entry plus shared release provenance.
    pub artifact_id: AsmArtifactId,
}

/// Immutable identity of the qualified Moho artifact selected for a proof job.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct MohoProofJobIdentity {
    /// Predicate identifying the recursive program's verifying key.
    pub predicate: PredicateKey,
    /// Digest of the canonical artifact entry plus shared release provenance.
    pub artifact_id: GuestArtifactId,
}

/// Program identity durably attached to a remote proof job.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum ProofJobIdentity {
    /// A fully qualified ASM guest selection.
    Asm(AsmProofJobIdentity),
    /// A fully qualified Moho recursive guest selection.
    Moho(MohoProofJobIdentity),
    /// An ASM job imported from the legacy mapping/status trees.
    ///
    /// Legacy rows did not record an artifact identity. The worker must bind
    /// this marker to a qualified artifact using the proof's authenticated
    /// parent predicate before it may retrieve the completed proof.
    LegacyUnqualifiedAsm,
    /// A Moho job imported from legacy storage without artifact provenance.
    ///
    /// The worker must bind this marker to its qualified recursive artifact
    /// before it may retrieve the result.
    LegacyUnqualifiedMoho,
}

/// One durable remote-proof lifecycle record.
///
/// The authoritative association between the logical task, the remote prover's
/// id, its last observed status, and the exact program identity that produced
/// it. The sled backend stores the record and its active index in one
/// transaction, so a mapping can never become visible without its status and
/// provenance.
///
/// Known gap: submission still writes local state after the remote call
/// accepts, so a crash in between can leave an attempt that exists remotely and
/// not locally. The fix is a prepared/acceptance-unknown/accepted lifecycle
/// replacing `status` and `remote_id` with a single state enum, so the two can
/// never disagree. Deferred: it is a crash-recovery change, independent of which
/// artifact proved a block, and belongs with the prover reliability work rather
/// than here. A drafted `RemoteProofJobDb` for it is not wired up.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RemoteProofJob {
    /// Logical proof task requested by the worker.
    pub proof_id: ProofId,
    /// Exact program and artifact identity used for the submission.
    ///
    /// Recorded so a completed proof can be decoded through the host that made
    /// it, and so a retry cannot silently reinterpret an attempt under a
    /// different artifact.
    pub identity: ProofJobIdentity,
    /// Remote prover's id for this submission.
    pub remote_id: RemoteProofId,
    /// Last observed remote status.
    pub status: RemoteProofStatus,
}

/// A range of L1 blocks defined by start and end commitments.
///
/// Ordered by start commitment first, then end commitment.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, BorshSerialize, BorshDeserialize,
)]
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

impl fmt::Display for L1Range {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.start == self.end {
            write!(f, "{}", self.start)
        } else {
            write!(f, "{}..={}", self.start, self.end)
        }
    }
}
