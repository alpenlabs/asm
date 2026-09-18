//! Follower-mode proof acquisition.
//!
//! Instead of submitting proving jobs, a follower fetches completed proofs
//! from a peer asm-runner's proof RPC and persists them into the same proof
//! store the generator path writes to. Each tick the service probes the
//! peer's prover status and picks one of three actions ([`follow_action`]):
//!
//! - **Fetch** — the peer is healthy: pull every pending proof at or below the peer's proven
//!   frontier.
//! - **Fallback** — the peer cannot serve us (too many consecutive failed ticks, whether the status
//!   probe or the proof fetches failed) or its proven frontier trails our committed tip beyond the
//!   configured lag: schedule pending proofs on the local proving backend, exactly as in generator
//!   mode.
//! - **Wait** — the peer is healthy but has not proven what we need yet, or is flaky but still
//!   within tolerance.
//!
//! The decision is re-taken every tick, so a recovered peer immediately stops
//! new local submissions; local jobs already in flight are completed by the
//! regular reconcile pass that runs in both modes. Duplicated work is
//! harmless: the scheduler skips proofs that already exist, and the fetcher
//! skips proofs already stored.
//!
//! The loop control flow ([`fetch_with`]) is separated from the actual peer
//! fetch ([`ProofFetcher`]) so it can be unit-tested with a fake fetcher,
//! mirroring [`schedule_with`](super::orchestrator).

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use jsonrpsee::http_client::HttpClient;
use strata_asm_proof_db::SledProofDb;
use strata_asm_proof_types::{ProofId, ProverStatus};
use strata_asm_rpc::traits::AsmProofApiClient;
use strata_btc_types::L1BlockIdBitcoinExt;
use strata_identifiers::L1BlockCommitment;
use tracing::{debug, info, warn};

use super::{
    config::FollowerConfig,
    proof_store::{self, ProofSource},
    queue::PendingProofQueue,
};

/// The peer a follower fetches proofs from, with its probe health.
pub(super) struct Peer {
    /// RPC client for the peer asm-runner.
    pub(super) client: HttpClient,

    /// Consecutive failed ticks: a status probe that failed, or a fetch cycle
    /// in which at least one proof fetch errored. Reset by the first tick that
    /// finds the peer both reachable and able to serve what it was asked for.
    pub(super) failures: u32,
}

impl Peer {
    pub(super) fn new(client: HttpClient) -> Self {
        Self {
            client,
            failures: 0,
        }
    }
}

/// What one [`follow_proofs`] cycle did, for the orchestrator to act on.
pub(super) struct FollowOutcome {
    /// Proofs fetched from the peer this cycle, for advancing `last_proven`.
    pub(super) fetched: Vec<ProofId>,

    /// Whether the peer was judged unusable, so the caller should schedule the
    /// pending queue on the local proving backend instead. Set either by
    /// [`follow_action`] up front, or by a fetch cycle that pushed the failure
    /// count past the configured tolerance.
    pub(super) fall_back: bool,
}

/// Probes the peer and either fetches available proofs or reports that the
/// caller should fall back to local generation.
///
/// Fetching and falling back are kept apart: this function owns the peer and
/// the queue, while submitting to the proving backend needs the orchestrator's
/// hosts and input builder. Returning [`FollowOutcome`] lets the orchestrator
/// run its existing scheduling path unchanged.
pub(super) async fn follow_proofs(
    db: &SledProofDb,
    queue: &mut PendingProofQueue,
    peer: &mut Peer,
    config: &FollowerConfig,
    last_committed: Option<L1BlockCommitment>,
    genesis_height: u32,
) -> FollowOutcome {
    // The reset on success is deferred to the arms below: a peer that answers
    // probes but cannot serve proofs must not clear its own failure count.
    let status = match peer.client.get_prover_status().await {
        Ok(status) => Some(status),
        Err(e) => {
            peer.failures = peer.failures.saturating_add(1);
            warn!(%e, failures = peer.failures, "failed to probe peer prover status");
            None
        }
    };

    match follow_action(
        status.as_ref(),
        last_committed,
        genesis_height,
        config,
        peer.failures,
    ) {
        FollowAction::Fetch { up_to } => {
            let mut fetcher = DbFetcher {
                db,
                peer: &peer.client,
                fetched: Vec::new(),
            };
            let failed = fetch_with(queue, &mut fetcher, up_to, config.max_fetches_per_tick).await;

            // A peer that answers status probes but cannot serve the proofs we
            // ask for is as useless as an unreachable one, so fetch errors
            // advance the same counter as failed probes.
            //
            // Both the decision and the reset live in this branch. Deciding
            // inside it means falling back always rests on a failure just
            // recorded — comparing after a clean cycle would fall back on
            // every tick when `max_peer_failures` is 0, since the reset leaves
            // the count at the threshold. And `follow_action` above stays
            // probe-only, so the fetch is never suppressed: were it, the
            // follower would stop running the cycle that clears the count and
            // a recovered peer would never be picked back up.
            let fall_back = if failed {
                peer.failures = peer.failures.saturating_add(1);
                warn!(failures = peer.failures, "peer failed to serve a proof");
                let fall_back = peer.failures >= config.max_peer_failures;
                if fall_back {
                    warn!(
                        failures = peer.failures,
                        "peer cannot serve proofs, falling back to local proof generation"
                    );
                }
                fall_back
            } else {
                peer.failures = 0;
                false
            };

            FollowOutcome {
                fetched: fetcher.fetched,
                fall_back,
            }
        }
        FollowAction::Fallback(reason) => {
            match reason {
                FallbackReason::PeerUnavailable { failures } => {
                    warn!(
                        failures,
                        "peer unreachable, falling back to local proof generation"
                    );
                }
                FallbackReason::PeerLagging { lag } => {
                    // Reachable, just behind: lag drives this fallback on its
                    // own, so the failure count starts clean.
                    peer.failures = 0;
                    warn!(
                        lag,
                        "peer lagging excessively, falling back to local proof generation"
                    );
                }
            }
            FollowOutcome {
                fetched: Vec::new(),
                fall_back: true,
            }
        }
        FollowAction::Wait => {
            // Waiting on a peer that answered means it is healthy; waiting on a
            // failed probe is a blip still within tolerance, and that count
            // must stand.
            if status.is_some() {
                peer.failures = 0;
            }
            FollowOutcome {
                fetched: Vec::new(),
                fall_back: false,
            }
        }
    }
}

/// What the follower should do this tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FollowAction {
    /// Peer is healthy: fetch pending proofs at or below its proven frontier
    /// (an L1 height).
    Fetch { up_to: u32 },
    /// The peer cannot serve us: generate pending proofs locally.
    Fallback(FallbackReason),
    /// Nothing to do this tick.
    Wait,
}

/// Why the follower gave up on the peer this tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FallbackReason {
    /// Too many consecutive status probes failed.
    PeerUnavailable { failures: u32 },
    /// The peer's proven frontier trails our committed tip beyond the
    /// configured tolerance.
    PeerLagging { lag: u32 },
}

/// Decides the follower's action from the latest peer probe.
///
/// `peer_status` is `None` when this tick's probe failed; the probe-failure
/// count decides between waiting out a blip and declaring the peer
/// unavailable. A reachable peer is judged on lag alone: how far its proven
/// frontier (or `genesis_height`, when it has proven nothing yet) trails our
/// committed tip. A young chain therefore never trips the lag fallback, while
/// a peer that never proves anything eventually does.
// TODO(STR-4062): a peer on a different fork passes both checks forever — probes
// succeed and its proven frontier keeps pace — yet every hash-keyed fetch
// misses, so proof acquisition silently stalls. Judge lag against the peer's
// last proven block as confirmed on our own chain instead, so a diverged
// peer's confirmed progress freezes and the max_lag tolerance converts
// persistent divergence into local-proving fallback.
fn follow_action(
    peer_status: Option<&ProverStatus>,
    last_committed: Option<L1BlockCommitment>,
    genesis_height: u32,
    config: &FollowerConfig,
    peer_failures: u32,
) -> FollowAction {
    let Some(status) = peer_status else {
        if peer_failures >= config.max_peer_failures {
            return FollowAction::Fallback(FallbackReason::PeerUnavailable {
                failures: peer_failures,
            });
        }
        return FollowAction::Wait;
    };

    // Nothing committed yet means nothing pending either.
    let Some(committed) = last_committed else {
        return FollowAction::Wait;
    };

    let peer_proven = status
        .last_proven
        .map(|block| block.height())
        .unwrap_or(genesis_height);

    let lag = committed.height().saturating_sub(peer_proven);
    if lag > config.max_lag {
        return FollowAction::Fallback(FallbackReason::PeerLagging { lag });
    }

    FollowAction::Fetch { up_to: peer_proven }
}

/// Outcome of a single [`ProofFetcher::try_fetch`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FetchOutcome {
    /// Proof retrieved from the peer and persisted.
    Fetched,
    /// A completed proof already exists in local storage; nothing to fetch.
    AlreadyStored,
    /// The peer does not have this proof yet; caller should re-enqueue it.
    NotAvailable,
}

/// Fetches a single proof from the peer.
///
/// Abstracts the "fetch one proof" step so the loop in [`fetch_with`] can be
/// unit-tested against a fake fetcher.
#[async_trait]
trait ProofFetcher {
    async fn try_fetch(&mut self, proof_id: ProofId) -> Result<FetchOutcome>;
}

/// Runs the fetch loop: pulls pending proofs at or below the peer's proven
/// frontier `up_to` and fetches each through `fetcher`, up to `capacity`
/// peer round trips.
///
/// The cap mirrors the one [`schedule_with`](super::orchestrator) applies to
/// submissions, and for the same reason: the tick loop publishes no status,
/// drains no new requests and observes no shutdown while the cycle runs. Only
/// round trips count against it — an already-stored proof is a local read, so
/// a queue full of them drains in one pass as it does when scheduling.
///
/// The first error ends the cycle. Every fetch in it goes to the same peer
/// over the same client, so a failure is almost always about the peer rather
/// than the proof, and working through the rest of the queue only rediscovers
/// that once per item — at a request timeout each — while delaying the
/// fallback the error exists to trigger. A proof the peer genuinely cannot
/// serve is retried on later ticks, and once those trip `max_peer_failures`
/// the local backend generates it.
///
/// Proofs the peer cannot serve yet — and the one that errored — are parked
/// and re-enqueued at the end, to be retried on a later tick. "Not available
/// yet" is not a failure: that is the peer legitimately not having proven the
/// block. A fetch error is, and the returned flag is what the caller folds
/// into the peer's failure count — without it, a peer that answers status
/// probes while failing every fetch would keep the follower parking the same
/// work forever.
///
/// The queue pops lowest heights first, so the first item above `up_to` ends
/// the loop: everything behind it is above the frontier too. A Moho proof at
/// the frontier implies the peer holds every ASM and Moho proof below it, so
/// one pass drains all currently-servable work.
// TODO(STR-4012): entries for blocks orphaned by our own reorg are never served by the
// peer and are re-parked here forever (the generator at least proves its
// orphans away). Since a Moho proof subsumes everything below it, entries at
// heights at or below the proven frontier could be evicted outright when
// it advances — pending confirmation that the Moho worker re-commits blocks
// on a reorg back, which would make eviction safe in generator mode too.
async fn fetch_with<F: ProofFetcher>(
    queue: &mut PendingProofQueue,
    fetcher: &mut F,
    up_to: u32,
    mut capacity: usize,
) -> bool {
    let mut parked: Vec<ProofId> = Vec::new();
    let mut failed = false;

    while capacity > 0 {
        let Some(proof_id) = queue.dequeue_one() else {
            break;
        };
        if proof_id.height() > up_to {
            parked.push(proof_id);
            break;
        }
        match fetcher.try_fetch(proof_id).await {
            Ok(FetchOutcome::Fetched) => {
                capacity -= 1;
                info!(%proof_id, "proof fetched from peer");
            }
            Ok(FetchOutcome::AlreadyStored) => {
                debug!(%proof_id, "proof already stored, skipping");
            }
            Ok(FetchOutcome::NotAvailable) => {
                capacity -= 1;
                debug!(%proof_id, "proof not yet available on peer, re-enqueuing");
                parked.push(proof_id);
            }
            Err(e) => {
                warn!(%proof_id, %e, "failed to fetch proof from peer, re-enqueuing");
                failed = true;
                parked.push(proof_id);
                break;
            }
        }
    }

    for proof_id in parked {
        queue.enqueue(proof_id);
    }

    failed
}

/// [`ProofFetcher`] backed by the local proof DB and the peer's
/// `AsmProofApi` RPC client. Constructed inline by [`follow_proofs`] for the
/// duration of one fetch cycle.
///
/// No retry wrapper around the client: the follower probes the peer every
/// tick and tolerates a configured number of consecutive failures before
/// falling back to local proving, so the tick loop *is* the retry policy.
///
/// Fetched receipts are stored unverified. That trusts the peer exactly as
/// far as the generator path trusts its own proving backend, which holds for
/// the same-operator HA setup this mode is built for.
// TODO(STR-4011): if a follower is ever pointed at a third-party peer, verify fetched
// receipts against the expected verification key and public values before
// storing — hash-keyed lookups bind an *honest* peer's proofs to the right
// block, but nothing checks the receipt itself.
struct DbFetcher<'a> {
    db: &'a SledProofDb,
    peer: &'a HttpClient,
    /// Proofs fetched this cycle, for advancing the proven watermark once the
    /// loop's borrows are released.
    fetched: Vec<ProofId>,
}

#[async_trait]
impl ProofFetcher for DbFetcher<'_> {
    async fn try_fetch(&mut self, proof_id: ProofId) -> Result<FetchOutcome> {
        if proof_store::proof_exists(self.db, &proof_id).await? {
            return Ok(FetchOutcome::AlreadyStored);
        }

        let receipt = match &proof_id {
            ProofId::Asm(range) => {
                // The peer keys proofs by block hash, which can only address
                // single-block ranges — the only kind the orchestrator creates.
                if range.start() != range.end() {
                    return Err(anyhow!("peer cannot address a multi-block ASM range"));
                }
                self.peer
                    .get_asm_proof(range.end().blkid().to_block_hash())
                    .await
                    .context("failed to fetch ASM proof from peer")?
                    .map(|proof| proof.0)
            }
            ProofId::Moho(block) => self
                .peer
                .get_moho_proof(block.blkid().to_block_hash())
                .await
                .context("failed to fetch Moho proof from peer")?
                .map(|proof| proof.0),
        };
        let Some(receipt) = receipt else {
            return Ok(FetchOutcome::NotAvailable);
        };

        proof_store::store_completed_proof(self.db, proof_id, receipt, ProofSource::Peer).await?;
        self.fetched.push(proof_id);
        Ok(FetchOutcome::Fetched)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use strata_asm_proof_types::L1Range;
    use strata_identifiers::{L1BlockCommitment, L1BlockId};

    use super::*;

    fn commitment(height: u32) -> L1BlockCommitment {
        L1BlockCommitment::new(height, L1BlockId::default())
    }

    fn asm(height: u32) -> ProofId {
        ProofId::Asm(L1Range::single(commitment(height)))
    }

    fn moho(height: u32) -> ProofId {
        ProofId::Moho(commitment(height))
    }

    fn follower_config(max_lag: u32, max_peer_failures: u32) -> FollowerConfig {
        FollowerConfig {
            peer_url: "http://127.0.0.1:0".to_owned(),
            max_lag,
            max_peer_failures,
            max_fetches_per_tick: 256,
        }
    }

    fn peer_status(last_proven: Option<u32>) -> ProverStatus {
        ProverStatus {
            pending: 0,
            last_committed: None,
            last_proven: last_proven.map(commitment),
        }
    }

    const GENESIS: u32 = 100;

    // --- follow_action decision table ---

    #[test]
    fn probe_failures_below_threshold_wait() {
        let config = follower_config(6, 3);
        let action = follow_action(None, Some(commitment(105)), GENESIS, &config, 2);
        assert_eq!(action, FollowAction::Wait);
    }

    #[test]
    fn probe_failures_at_threshold_fall_back() {
        let config = follower_config(6, 3);
        let action = follow_action(None, Some(commitment(105)), GENESIS, &config, 3);
        assert_eq!(
            action,
            FollowAction::Fallback(FallbackReason::PeerUnavailable { failures: 3 })
        );
    }

    #[test]
    fn nothing_committed_waits() {
        let config = follower_config(6, 3);
        let status = peer_status(Some(104));
        let action = follow_action(Some(&status), None, GENESIS, &config, 0);
        assert_eq!(action, FollowAction::Wait);
    }

    #[test]
    fn peer_within_lag_fetches_up_to_its_frontier() {
        let config = follower_config(6, 3);
        let status = peer_status(Some(104));
        let action = follow_action(Some(&status), Some(commitment(106)), GENESIS, &config, 0);
        assert_eq!(action, FollowAction::Fetch { up_to: 104 });
    }

    /// The lag fallback is strict: lag equal to `max_lag` still fetches.
    #[test]
    fn lag_at_threshold_still_fetches() {
        let config = follower_config(6, 3);
        let status = peer_status(Some(100));
        let action = follow_action(Some(&status), Some(commitment(106)), GENESIS, &config, 0);
        assert_eq!(action, FollowAction::Fetch { up_to: 100 });
    }

    #[test]
    fn lag_beyond_threshold_falls_back() {
        let config = follower_config(6, 3);
        let status = peer_status(Some(100));
        let action = follow_action(Some(&status), Some(commitment(107)), GENESIS, &config, 0);
        assert_eq!(
            action,
            FollowAction::Fallback(FallbackReason::PeerLagging { lag: 7 })
        );
    }

    /// A peer with no proofs yet is measured from genesis: a young chain does
    /// not trip the fallback...
    #[test]
    fn unproven_peer_on_young_chain_fetches() {
        let config = follower_config(6, 3);
        let status = peer_status(None);
        let action = follow_action(Some(&status), Some(commitment(104)), GENESIS, &config, 0);
        assert_eq!(action, FollowAction::Fetch { up_to: GENESIS });
    }

    /// ...but a peer that never proves anything eventually does.
    #[test]
    fn unproven_peer_far_behind_falls_back() {
        let config = follower_config(6, 3);
        let status = peer_status(None);
        let action = follow_action(Some(&status), Some(commitment(120)), GENESIS, &config, 0);
        assert_eq!(
            action,
            FollowAction::Fallback(FallbackReason::PeerLagging { lag: 20 })
        );
    }

    // --- fetch_with loop control flow ---

    /// One scripted reply for [`FakeFetcher`].
    enum FakeResult {
        Outcome(FetchOutcome),
        Err,
    }

    /// Scriptable [`ProofFetcher`] for unit tests.
    ///
    /// Returns scripted results in order per `ProofId`. Missing or exhausted
    /// scripts default to `Fetched`.
    #[derive(Default)]
    struct FakeFetcher {
        script: HashMap<ProofId, Vec<FakeResult>>,
        call_log: Vec<ProofId>,
    }

    impl FakeFetcher {
        fn with(mut self, id: ProofId, outcomes: Vec<FetchOutcome>) -> Self {
            self.script
                .entry(id)
                .or_default()
                .extend(outcomes.into_iter().map(FakeResult::Outcome));
            self
        }

        fn with_err(mut self, id: ProofId) -> Self {
            self.script.entry(id).or_default().push(FakeResult::Err);
            self
        }
    }

    #[async_trait]
    impl ProofFetcher for FakeFetcher {
        async fn try_fetch(&mut self, id: ProofId) -> Result<FetchOutcome> {
            self.call_log.push(id);
            let next = self
                .script
                .get_mut(&id)
                .and_then(|v| (!v.is_empty()).then(|| v.remove(0)));
            match next {
                Some(FakeResult::Outcome(o)) => Ok(o),
                Some(FakeResult::Err) => Err(anyhow!("scripted error")),
                None => Ok(FetchOutcome::Fetched),
            }
        }
    }

    /// Everything at or below the frontier is fetched in ascending order and
    /// drained; everything above stays queued without a peer round-trip.
    #[tokio::test]
    async fn fetches_up_to_frontier_and_parks_the_rest() {
        let mut queue = PendingProofQueue::new();
        queue.enqueue(asm(3));
        queue.enqueue(moho(3));
        queue.enqueue(asm(4));
        queue.enqueue(moho(4));

        let mut fetcher = FakeFetcher::default();

        let failed = fetch_with(&mut queue, &mut fetcher, 3, 256).await;

        assert!(!failed);
        assert_eq!(fetcher.call_log, vec![asm(3), moho(3)]);
        assert_eq!(queue.len(), 2);
        assert_eq!(queue.dequeue_one(), Some(asm(4)));
        assert_eq!(queue.dequeue_one(), Some(moho(4)));
    }

    /// A proof the peer does not have yet is re-enqueued for the next tick.
    #[tokio::test]
    async fn not_available_reenqueued() {
        let mut queue = PendingProofQueue::new();
        queue.enqueue(asm(3));
        queue.enqueue(moho(3));

        let mut fetcher = FakeFetcher::default().with(moho(3), vec![FetchOutcome::NotAvailable]);

        let failed = fetch_with(&mut queue, &mut fetcher, 3, 256).await;

        // A peer that has not proven the block yet is not a failing peer.
        assert!(!failed);
        assert_eq!(fetcher.call_log, vec![asm(3), moho(3)]);
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.dequeue_one(), Some(moho(3)));
    }

    /// An already-stored proof is dropped from the queue without refetching.
    #[tokio::test]
    async fn already_stored_dropped() {
        let mut queue = PendingProofQueue::new();
        queue.enqueue(asm(3));

        let mut fetcher = FakeFetcher::default().with(asm(3), vec![FetchOutcome::AlreadyStored]);

        let failed = fetch_with(&mut queue, &mut fetcher, 3, 256).await;

        assert!(!failed);
        assert_eq!(fetcher.call_log, vec![asm(3)]);
        assert!(queue.is_empty());
    }

    /// A fetch error is counted so the caller can fall back, and ends the
    /// cycle rather than paying a request timeout per remaining item. Both the
    /// failed item and the untouched rest stay queued.
    #[tokio::test]
    async fn err_is_counted_and_ends_the_cycle() {
        let mut queue = PendingProofQueue::new();
        queue.enqueue(asm(3));
        queue.enqueue(moho(3));

        let mut fetcher = FakeFetcher::default().with_err(asm(3));

        let failed = fetch_with(&mut queue, &mut fetcher, 3, 256).await;

        assert!(failed);
        assert_eq!(fetcher.call_log, vec![asm(3)]);
        assert_eq!(queue.len(), 2);
        assert_eq!(queue.dequeue_one(), Some(asm(3)));
        assert_eq!(queue.dequeue_one(), Some(moho(3)));
    }

    /// The per-tick budget bounds peer round trips; the remainder stays queued
    /// for the next tick.
    #[tokio::test]
    async fn capacity_bounds_round_trips() {
        let mut queue = PendingProofQueue::new();
        queue.enqueue(asm(3));
        queue.enqueue(moho(3));
        queue.enqueue(asm(4));

        let mut fetcher = FakeFetcher::default();

        let failed = fetch_with(&mut queue, &mut fetcher, 4, 2).await;

        assert!(!failed);
        assert_eq!(fetcher.call_log, vec![asm(3), moho(3)]);
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.dequeue_one(), Some(asm(4)));
    }

    /// An already-stored proof is a local read, so it does not spend budget —
    /// mirroring how a skipped submission does not spend scheduling capacity.
    #[tokio::test]
    async fn already_stored_does_not_spend_capacity() {
        let mut queue = PendingProofQueue::new();
        queue.enqueue(asm(3));
        queue.enqueue(moho(3));
        queue.enqueue(asm(4));

        let mut fetcher = FakeFetcher::default()
            .with(asm(3), vec![FetchOutcome::AlreadyStored])
            .with(moho(3), vec![FetchOutcome::AlreadyStored]);

        let failed = fetch_with(&mut queue, &mut fetcher, 4, 1).await;

        assert!(!failed);
        assert_eq!(fetcher.call_log, vec![asm(3), moho(3), asm(4)]);
        assert!(queue.is_empty());
    }

    /// A zero budget is a no-op that leaves the queue intact.
    #[tokio::test]
    async fn zero_capacity_no_fetches() {
        let mut queue = PendingProofQueue::new();
        queue.enqueue(asm(3));

        let mut fetcher = FakeFetcher::default();

        let failed = fetch_with(&mut queue, &mut fetcher, 3, 0).await;

        assert!(!failed);
        assert!(fetcher.call_log.is_empty());
        assert_eq!(queue.len(), 1);
    }

    /// A frontier below every queued item is a no-op: no peer round-trips,
    /// nothing lost.
    #[tokio::test]
    async fn frontier_below_queue_no_fetches() {
        let mut queue = PendingProofQueue::new();
        queue.enqueue(asm(5));
        queue.enqueue(moho(5));

        let mut fetcher = FakeFetcher::default();

        let failed = fetch_with(&mut queue, &mut fetcher, 4, 256).await;

        assert!(!failed);
        assert!(fetcher.call_log.is_empty());
        assert_eq!(queue.len(), 2);
    }
}
