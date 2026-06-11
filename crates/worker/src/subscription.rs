//! Per-block notification stream shared by the worker services.
//!
//! After every successful commit, a worker fans the new item out to all live
//! subscribers over unbounded channels. Consumers run on their own tasks and
//! react to whatever sequence the worker commits — including any future reorg
//! re-emission — without sitting in the worker's hot path.
//!
//! The registry is generic over the emitted item ([`Subscribers<T>`]): the ASM
//! worker emits the [`L1BlockCommitment`] it just committed, and the Moho worker
//! reuses the same type to emit the block whose `MohoState` it just derived. The
//! prover chains off the Moho stream rather than the ASM one, so a block it sees
//! already has its `MohoState` persisted.
//!
//! `send` on an unbounded channel is one allocation plus an atomic, so the
//! worker never awaits a consumer: it fans out and returns to the next block.
//! The trade-off is that a stuck consumer is a memory leak; [`Subscription::backlog`]
//! exposes the queue depth so consumers (or alerting) can notice.

use std::{
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use futures::Stream;
#[cfg(doc)]
use strata_identifiers::L1BlockCommitment;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender, error::TryRecvError};

/// A live stream of items emitted by a worker, one per committed block.
///
/// Implements [`Stream`] and also exposes [`Subscription::recv`] for use in a
/// `select!` loop. There is no replay buffer: a subscription only sees events
/// emitted after it was created (see [`AsmWorkerHandle::subscribe_blocks`]).
///
/// [`AsmWorkerHandle::subscribe_blocks`]: crate::AsmWorkerHandle::subscribe_blocks
#[derive(Debug)]
pub struct Subscription<T> {
    rx: UnboundedReceiver<T>,
}

impl<T> Subscription<T> {
    fn new(rx: UnboundedReceiver<T>) -> Self {
        Self { rx }
    }

    /// Number of emitted items queued but not yet consumed.
    ///
    /// A persistently growing backlog means the consumer is falling behind the
    /// worker; the channel is unbounded, so this is the only back-pressure signal.
    pub fn backlog(&self) -> usize {
        self.rx.len()
    }

    /// Receives the next emitted item, or `None` once the worker has shut down
    /// (every sender dropped).
    pub async fn recv(&mut self) -> Option<T> {
        self.rx.recv().await
    }

    /// Pulls the next already-queued item without awaiting.
    ///
    /// Returns [`TryRecvError::Empty`] when nothing is queued right now, and
    /// [`TryRecvError::Disconnected`] once the worker has shut down and the
    /// backlog is drained. Lets a periodically-ticking consumer drain everything
    /// buffered at the top of each tick without parking on the channel.
    pub fn try_recv(&mut self) -> Result<T, TryRecvError> {
        self.rx.try_recv()
    }
}

impl<T> Stream for Subscription<T> {
    type Item = T;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<T>> {
        self.rx.poll_recv(cx)
    }
}

/// Producer-side registry of commit subscribers, generic over the emitted item.
///
/// Subscribers are notified only *after* the worker has successfully processed
/// and durably committed a block — not when a raw L1 block arrives. The ASM and
/// Moho workers both use `Subscribers<L1BlockCommitment>`; sharing one type is
/// what lets the prover subscribe to either worker's stream interchangeably.
///
/// Cloned so the service state (which emits) and the worker handle (which
/// registers new subscribers) share one list. Each entry is the sending half of
/// a [`Subscription`]'s channel; dead receivers are pruned lazily on the next
/// [`emit`](Self::emit). Mirrors `strata-bridge`'s `btc-tracker` subscriber pattern.
#[derive(Debug)]
pub struct Subscribers<T> {
    inner: Arc<Mutex<Vec<UnboundedSender<T>>>>,
}

// Manual `Clone`/`Default` rather than derives: the derives would demand
// `T: Clone`/`T: Default`, but the `Arc<Mutex<…>>` is clonable and empty-default
// for any `T`.
impl<T> Clone for Subscribers<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<T> Default for Subscribers<T> {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl<T: Clone> Subscribers<T> {
    /// Registers a new subscriber and returns its [`Subscription`].
    pub fn subscribe(&self) -> Subscription<T> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.inner
            .lock()
            .expect("subscribers lock poisoned")
            .push(tx);
        Subscription::new(rx)
    }

    /// Fans an item out to every live subscriber, pruning any whose receiver has
    /// been dropped. Never blocks: each `send` is an unbounded enqueue.
    pub fn emit(&self, item: T) {
        self.inner
            .lock()
            .expect("subscribers lock poisoned")
            .retain(|tx| tx.send(item.clone()).is_ok());
    }
}

#[cfg(test)]
mod tests {
    use strata_identifiers::{L1BlockCommitment, L1BlockId};

    use super::*;

    fn commitment(height: u32) -> L1BlockCommitment {
        L1BlockCommitment::new(height, L1BlockId::default())
    }

    #[tokio::test]
    async fn emit_delivers_to_subscriber_in_order() {
        let subs = Subscribers::<L1BlockCommitment>::default();
        let mut sub = subs.subscribe();

        subs.emit(commitment(1));
        subs.emit(commitment(2));

        assert_eq!(sub.backlog(), 2);
        assert_eq!(sub.recv().await, Some(commitment(1)));
        assert_eq!(sub.recv().await, Some(commitment(2)));
        assert_eq!(sub.backlog(), 0);
    }

    #[tokio::test]
    async fn fans_out_to_multiple_subscribers() {
        let subs = Subscribers::<L1BlockCommitment>::default();
        let mut a = subs.subscribe();
        let mut b = subs.subscribe();

        subs.emit(commitment(7));

        assert_eq!(a.recv().await, Some(commitment(7)));
        assert_eq!(b.recv().await, Some(commitment(7)));
    }

    #[tokio::test]
    async fn dropped_subscriber_is_pruned_on_next_emit() {
        let subs = Subscribers::<L1BlockCommitment>::default();
        let live = subs.subscribe();
        let dead = subs.subscribe();

        assert_eq!(subs.inner.lock().unwrap().len(), 2);

        drop(dead);
        // The emit that follows the drop prunes the dead slot.
        subs.emit(commitment(1));

        assert_eq!(subs.inner.lock().unwrap().len(), 1);
        drop(live);
    }

    #[tokio::test]
    async fn recv_returns_none_once_all_senders_dropped() {
        let subs = Subscribers::<L1BlockCommitment>::default();
        let mut sub = subs.subscribe();
        drop(subs);
        assert_eq!(sub.recv().await, None);
    }

    #[tokio::test]
    async fn try_recv_drains_then_reports_empty_and_disconnected() {
        let subs = Subscribers::<L1BlockCommitment>::default();
        let mut sub = subs.subscribe();

        subs.emit(commitment(1));
        subs.emit(commitment(2));

        assert_eq!(sub.try_recv(), Ok(commitment(1)));
        assert_eq!(sub.try_recv(), Ok(commitment(2)));
        // Backlog drained but the producer is still live.
        assert_eq!(sub.try_recv(), Err(TryRecvError::Empty));

        // Once every sender is gone, a drained subscription reports disconnect.
        drop(subs);
        assert_eq!(sub.try_recv(), Err(TryRecvError::Disconnected));
    }
}
