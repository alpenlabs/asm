//! Service state for the prover worker.

use async_trait::async_trait;
use jsonrpsee::http_client::HttpClient;
use strata_asm_prover_types::{L1Range, MohoProofJobIdentity, ProofId};
use strata_identifiers::L1BlockCommitment;
use strata_service::ServiceState;
use tracing::{debug, info, warn};
use zkaleido::ZkVmRemoteHost;

use crate::{
    ProverContext,
    config::OrchestratorConfig,
    constants,
    errors::{ProverError, ProverResult},
    hosts::AsmHosts,
    input::InputBuilder,
    job_identity::validate_or_bind_job_identity,
    queue::PendingProofQueue,
};

/// Service state for the prover worker.
///
/// Holds everything the [`ProverService`](crate::service::ProverService) mutates
/// or reads while processing inputs: the storage/chain context, the remote
/// hosts, the input builder, and the in-memory pending-proof queue. Generic over
/// the prover context `C` and the remote host `H`, mirroring how
/// [`AsmWorkerServiceState`](https://docs.rs/strata-asm-worker) is generic over
/// its worker context and ASM spec.
#[derive(Debug)]
pub struct ProverServiceState<C, H> {
    /// Context the service reads storage and chain data through.
    pub(crate) ctx: C,

    /// Remote hosts for ASM step proofs, keyed by the predicate each one's
    /// proofs verify against. Which one proves a block is decided per block, by
    /// the predicate the block's parent handed over.
    pub(crate) asm: AsmHosts<H>,

    /// Remote host for Moho recursive proofs.
    pub(crate) moho: H,

    /// Qualified identity of the Moho artifact used for every recursive job.
    pub(crate) moho_identity: MohoProofJobIdentity,

    /// Orchestration tuning (tick interval, concurrency limit).
    pub(crate) config: OrchestratorConfig,

    /// Assembles ZkVM inputs for each proof type.
    pub(crate) input_builder: InputBuilder,

    /// Proofs awaiting submission to the remote prover.
    pub(crate) queue: PendingProofQueue,

    /// Most recent block the Moho worker committed. Initialized from the
    /// latest persisted Moho state at construction and advanced by the commit
    /// subscription. Surfaced through
    /// [`ProverStatus`](strata_asm_prover_types::ProverStatus) for observability.
    pub(crate) last_committed: Option<L1BlockCommitment>,

    /// Highest block on the active Moho ancestry with a completed recursive
    /// proof. Recomputed from the durable active tip at construction and on
    /// every re-anchor; advanced only by proofs on that ancestry. Surfaced through
    /// [`ProverStatus`](strata_asm_prover_types::ProverStatus) for observability.
    pub(crate) last_proven: Option<L1BlockCommitment>,

    /// Whether canonical frontier derivation must be retried on the next tick.
    /// Set when an ancestry read fails after a commit notification has already
    /// been consumed; while dirty, `last_proven` is cleared rather than
    /// exposing a possibly orphaned block.
    pub(crate) frontier_dirty: bool,

    /// Peer asm-runner proofs are fetched from; present iff the worker runs
    /// in [`ProverMode::Follower`](crate::config::ProverMode::Follower).
    pub(crate) peer: Option<Peer>,
}

/// The peer a follower fetches proofs from, with its probe health.
#[derive(Debug)]
pub(crate) struct Peer {
    /// RPC client for the peer asm-runner, used through the
    /// `AsmProofApiClient` trait `strata-asm-rpc` generates.
    pub(crate) client: HttpClient,

    /// Consecutive failed status probes. Reset on the first success.
    pub(crate) failures: u32,
}

/// Exact-chain reads needed to derive the canonical proven frontier.
///
/// Kept narrower than [`ProverContext`] so reorg behavior can be tested without
/// constructing an entire worker backend.
#[async_trait]
trait CanonicalProofChain {
    async fn has_moho_proof(&self, block: L1BlockCommitment) -> ProverResult<bool>;

    async fn parent(&self, block: L1BlockCommitment) -> ProverResult<L1BlockCommitment>;
}

struct ContextChain<'a, C> {
    ctx: &'a C,
    input_builder: &'a InputBuilder,
}

#[async_trait]
impl<C> CanonicalProofChain for ContextChain<'_, C>
where
    C: ProverContext + Send + Sync,
{
    async fn has_moho_proof(&self, block: L1BlockCommitment) -> ProverResult<bool> {
        self.ctx
            .get_moho_proof(block)
            .await
            .map(|proof| proof.is_some())
            .map_err(|e| ProverError::storage("failed to check canonical Moho proof", e))
    }

    async fn parent(&self, block: L1BlockCommitment) -> ProverResult<L1BlockCommitment> {
        self.input_builder.parent_commitment(self.ctx, block).await
    }
}

/// Finds the greatest stored Moho proof on `tip`'s exact ancestry.
///
/// Proof storage retains orphan branches, so its highest key is not a chain
/// selection rule. Starting from the durable active Moho tip and walking down
/// makes both shorter and sibling reorgs deterministic without new metadata.
async fn greatest_proven_on_ancestry<S>(
    chain: &S,
    tip: L1BlockCommitment,
    genesis: L1BlockCommitment,
) -> ProverResult<Option<L1BlockCommitment>>
where
    S: CanonicalProofChain + Sync,
{
    let mut cursor = tip;
    while cursor.height() > genesis.height() {
        if chain.has_moho_proof(cursor).await? {
            return Ok(Some(cursor));
        }
        cursor = chain.parent(cursor).await?;
    }
    Ok(None)
}

/// Returns whether `candidate` belongs to `tip`'s active ancestry.
async fn is_on_ancestry<S>(
    chain: &S,
    candidate: L1BlockCommitment,
    tip: L1BlockCommitment,
    genesis: L1BlockCommitment,
) -> ProverResult<bool>
where
    S: CanonicalProofChain + Sync,
{
    if candidate.height() <= genesis.height() || candidate.height() > tip.height() {
        return Ok(false);
    }

    let mut cursor = tip;
    while cursor.height() > candidate.height() {
        cursor = chain.parent(cursor).await?;
    }
    Ok(cursor == candidate)
}

async fn is_direct_extension<S>(
    chain: &S,
    previous: L1BlockCommitment,
    next: L1BlockCommitment,
) -> ProverResult<bool>
where
    S: CanonicalProofChain + Sync,
{
    if previous.height().checked_add(1) != Some(next.height()) {
        return Ok(false);
    }
    Ok(chain.parent(next).await? == previous)
}

impl<C, H> ProverServiceState<C, H>
where
    C: ProverContext + Send + Sync,
{
    /// Creates the service state, seeding the pending queue with the Moho
    /// proof of the latest Moho-worker-committed block — mirroring how the
    /// workers resume from their stored state at construction.
    ///
    /// The latest Moho state is the exact watermark of the commit stream that
    /// drives the prover, and that stream only delivers blocks committed after
    /// subscribing — so proofs pending at shutdown would otherwise sit
    /// unrecovered until the next new L1 block arrives. The single seed is
    /// sufficient: the scheduler pulls a deferred proof's missing
    /// prerequisites back into the queue, recursively walking the chain down
    /// to the last block that already has a Moho proof. Already-completed or
    /// already-submitted proofs are filtered out by the scheduler, so this
    /// only resurrects the genuinely-missing work.
    ///
    /// The durable Moho active tip is also the chain-selection root for the
    /// proven frontier. Proof rows on retained orphan branches never outrank a
    /// lower proof on that active ancestry.
    pub(crate) async fn new(
        ctx: C,
        asm: AsmHosts<H>,
        moho: H,
        moho_identity: MohoProofJobIdentity,
        config: OrchestratorConfig,
        input_builder: InputBuilder,
        peer: Option<HttpClient>,
    ) -> ProverResult<Self> {
        // Fail startup before reporting ready if an in-flight job was created
        // under different artifact bindings. Legacy rows are qualified here
        // exactly once from authenticated chain state and the release registry.
        let active_jobs = ctx
            .get_all_active_remote_proof_jobs()
            .await
            .map_err(|error| {
                ProverError::storage("failed to load active remote proof jobs", error)
            })?;
        for job in active_jobs {
            validate_or_bind_job_identity(&ctx, &input_builder, &asm, &moho_identity, job).await?;
        }

        let last_committed = ctx
            .get_latest_moho_state()
            .await
            .map_err(|e| ProverError::storage("failed to fetch latest moho state", e))?
            .map(|(block, _)| block);
        let last_proven = match last_committed {
            Some(tip) => {
                let chain = ContextChain {
                    ctx: &ctx,
                    input_builder: &input_builder,
                };
                greatest_proven_on_ancestry(&chain, tip, input_builder.genesis()).await?
            }
            None => None,
        };

        let mut queue = PendingProofQueue::new();
        if let Some(seed) = last_committed {
            // Nothing to recover when the committed tip is already proven.
            // Compare blocks, not heights: an orphaned proof can outrank the
            // committed tip after a reorg to a shorter chain.
            //
            // Proofs exist only above genesis; seeding a Moho proof at or
            // below it would leave the scheduler chasing prerequisites that
            // can never be built.
            if last_proven != Some(seed) && seed.height() > input_builder.genesis().height() {
                info!(%seed, "seeding proof recovery from latest committed block");
                // The Moho proof alone is enough: its ASM step proof, if
                // missing, is pulled in by the prerequisite cascade.
                queue.enqueue(ProofId::Moho(seed));
            }
        }

        Ok(Self {
            ctx,
            asm,
            moho,
            moho_identity,
            config,
            input_builder,
            queue,
            last_committed,
            last_proven,
            frontier_dirty: false,
            peer: peer.map(|client| Peer {
                client,
                failures: 0,
            }),
        })
    }

    /// Expands a committed block into the proofs it requires and enqueues them.
    ///
    /// Each committed [`L1BlockCommitment`] maps to one ASM step proof and one
    /// Moho recursive proof. This also re-anchors the visible proven frontier
    /// when the commit is not a direct extension. Scheduling happens on the
    /// next tick.
    pub(crate) async fn enqueue_block_proofs(&mut self, block: L1BlockCommitment) {
        let chain = ContextChain {
            ctx: &self.ctx,
            input_builder: &self.input_builder,
        };
        let extends_previous = match self.last_committed {
            Some(previous) => is_direct_extension(&chain, previous, block).await,
            None => Ok(false),
        };

        // Direct extension preserves the current frontier's ancestry. Any
        // other transition is a re-anchor (shorter ancestor or sibling branch)
        // and must derive the frontier from the newly active chain.
        let refresh = match extends_previous {
            Ok(true) if !self.frontier_dirty => Ok(self.last_proven),
            Ok(_) => greatest_proven_on_ancestry(&chain, block, self.input_builder.genesis()).await,
            Err(error) => Err(error),
        };
        match refresh {
            Ok(frontier) => {
                self.last_proven = frontier;
                self.frontier_dirty = false;
            }
            Err(error) => {
                // The stream has no replay and the framework stops a service
                // whose message handler returns an error. Keep the consumed
                // commit, advertise no potentially-orphaned frontier, and let
                // the periodic tick retry the durable ancestry read.
                warn!(%block, %error, "failed to refresh canonical proven frontier; will retry");
                self.last_proven = None;
                self.frontier_dirty = true;
            }
        }

        debug!(%block, "moho worker committed block, enqueuing proofs");
        self.queue.enqueue(ProofId::Asm(L1Range::single(block)));
        self.queue.enqueue(ProofId::Moho(block));
        self.last_committed = Some(block);
    }

    /// Retries canonical frontier derivation after a transient ancestry read
    /// failure in the commit-message path.
    pub(crate) async fn refresh_proven_frontier(&mut self) -> ProverResult<()> {
        if !self.frontier_dirty {
            return Ok(());
        }
        let Some(tip) = self.last_committed else {
            self.last_proven = None;
            self.frontier_dirty = false;
            return Ok(());
        };

        let chain = ContextChain {
            ctx: &self.ctx,
            input_builder: &self.input_builder,
        };
        self.last_proven =
            greatest_proven_on_ancestry(&chain, tip, self.input_builder.genesis()).await?;
        self.frontier_dirty = false;
        Ok(())
    }

    /// Advances the proven frontier if `proof_id` is a canonical Moho proof
    /// above it.
    ///
    /// Called whenever a completed Moho proof lands in the proof store —
    /// whether reconciled from the remote prover or fetched from a peer.
    pub(crate) async fn advance_proven(&mut self, proof_id: &ProofId) -> ProverResult<()> {
        let ProofId::Moho(block) = proof_id else {
            return Ok(());
        };
        let Some(tip) = self.last_committed else {
            return Ok(());
        };
        if self
            .last_proven
            .is_some_and(|current| current.height() >= block.height())
        {
            return Ok(());
        }

        let chain = ContextChain {
            ctx: &self.ctx,
            input_builder: &self.input_builder,
        };
        if is_on_ancestry(&chain, *block, tip, self.input_builder.genesis()).await? {
            self.last_proven = Some(*block);
        }
        Ok(())
    }
}

impl<C, H> ServiceState for ProverServiceState<C, H>
where
    C: ProverContext + Send + Sync + 'static,
    H: ZkVmRemoteHost + Send + Sync + 'static,
{
    fn name(&self) -> &str {
        constants::SERVICE_NAME
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use strata_identifiers::{Buf32, L1BlockId};

    use super::*;

    #[derive(Default)]
    struct FakeChain {
        parents: HashMap<L1BlockCommitment, L1BlockCommitment>,
        proven: HashSet<L1BlockCommitment>,
    }

    impl FakeChain {
        fn link(mut self, child: L1BlockCommitment, parent: L1BlockCommitment) -> Self {
            self.parents.insert(child, parent);
            self
        }

        fn prove(mut self, block: L1BlockCommitment) -> Self {
            self.proven.insert(block);
            self
        }
    }

    #[async_trait]
    impl CanonicalProofChain for FakeChain {
        async fn has_moho_proof(&self, block: L1BlockCommitment) -> ProverResult<bool> {
            Ok(self.proven.contains(&block))
        }

        async fn parent(&self, block: L1BlockCommitment) -> ProverResult<L1BlockCommitment> {
            self.parents
                .get(&block)
                .copied()
                .ok_or(ProverError::NotFound("test parent not found"))
        }
    }

    fn block(height: u32, branch: u8) -> L1BlockCommitment {
        L1BlockCommitment::new(height, L1BlockId::from(Buf32::from([branch; 32])))
    }

    #[tokio::test]
    async fn restart_frontier_follows_a_shorter_active_branch_not_the_highest_orphan() {
        let genesis = block(100, 0);
        let a1 = block(101, 1);
        let a2 = block(102, 2);
        let orphan_a3 = block(103, 3);
        let chain = FakeChain::default()
            .link(a1, genesis)
            .link(a2, a1)
            .link(orphan_a3, a2)
            .prove(a1)
            .prove(orphan_a3);

        assert_eq!(
            greatest_proven_on_ancestry(&chain, a2, genesis)
                .await
                .unwrap(),
            Some(a1),
        );
    }

    #[tokio::test]
    async fn follower_visible_frontier_uses_the_active_sibling_branch() {
        let genesis = block(100, 0);
        let orphan_a1 = block(101, 1);
        let orphan_a2 = block(102, 2);
        let active_b1 = block(101, 11);
        let active_b2 = block(102, 12);
        let chain = FakeChain::default()
            .link(orphan_a1, genesis)
            .link(orphan_a2, orphan_a1)
            .link(active_b1, genesis)
            .link(active_b2, active_b1)
            .prove(orphan_a2)
            .prove(active_b1);

        assert_eq!(
            greatest_proven_on_ancestry(&chain, active_b2, genesis)
                .await
                .unwrap(),
            Some(active_b1),
        );
    }

    #[tokio::test]
    async fn orphan_completion_cannot_advance_the_active_frontier() {
        let genesis = block(100, 0);
        let orphan_a1 = block(101, 1);
        let orphan_a2 = block(102, 2);
        let active_b1 = block(101, 11);
        let active_b2 = block(102, 12);
        let chain = FakeChain::default()
            .link(orphan_a1, genesis)
            .link(orphan_a2, orphan_a1)
            .link(active_b1, genesis)
            .link(active_b2, active_b1);

        assert!(
            !is_on_ancestry(&chain, orphan_a2, active_b2, genesis)
                .await
                .unwrap()
        );
        assert!(
            is_on_ancestry(&chain, active_b1, active_b2, genesis)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn only_an_exact_child_preserves_the_existing_frontier() {
        let genesis = block(100, 0);
        let a1 = block(101, 1);
        let a2 = block(102, 2);
        let sibling_b2 = block(102, 12);
        let chain = FakeChain::default()
            .link(a1, genesis)
            .link(a2, a1)
            .link(sibling_b2, a1);

        assert!(is_direct_extension(&chain, a1, a2).await.unwrap());
        assert!(!is_direct_extension(&chain, a2, sibling_b2).await.unwrap());
        assert!(!is_direct_extension(&chain, a2, a1).await.unwrap());
    }
}
