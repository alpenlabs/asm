//! Per-block notification stream for the ASM worker.
//!
//! After every successful anchor-state commit, the worker fans the new
//! [`L1BlockCommitment`] out to all live subscribers over unbounded channels.
//! Consumers run on their own tasks and react to whatever block sequence the
//! worker commits — including any future reorg re-emission — without sitting in
//! the worker's hot path.
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
use strata_identifiers::L1BlockCommitment;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

/// A live stream of items emitted by the ASM worker, one per committed block.
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
}

impl<T> Stream for Subscription<T> {
    type Item = T;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<T>> {
        self.rx.poll_recv(cx)
    }
}

/// Producer-side registry of ASM-commit subscribers.
///
/// Subscribers are notified only *after* the ASM worker has successfully
/// processed and durably committed a block — not when a raw L1 block arrives.
///
/// Cloned so the service state (which emits) and the worker handle (which
/// registers new subscribers) share one list. Each entry is the sending half of
/// a [`Subscription`]'s channel; dead receivers are pruned lazily on the next
/// [`emit`](Self::emit). Mirrors `strata-bridge`'s `btc-tracker` subscriber pattern.
#[derive(Clone, Default, Debug)]
pub(crate) struct AsmSubscribers {
    inner: Arc<Mutex<Vec<UnboundedSender<L1BlockCommitment>>>>,
}

impl AsmSubscribers {
    /// Registers a new subscriber and returns its [`Subscription`].
    pub(crate) fn subscribe(&self) -> Subscription<L1BlockCommitment> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.inner
            .lock()
            .expect("subscribers lock poisoned")
            .push(tx);
        Subscription::new(rx)
    }

    /// Fans a commitment out to every live subscriber, pruning any whose
    /// receiver has been dropped. Never blocks: each `send` is an unbounded
    /// enqueue.
    pub(crate) fn emit(&self, block: L1BlockCommitment) {
        self.inner
            .lock()
            .expect("subscribers lock poisoned")
            .retain(|tx| tx.send(block).is_ok());
    }
}

#[cfg(test)]
mod tests {
    use strata_identifiers::L1BlockId;

    use super::*;

    fn commitment(height: u32) -> L1BlockCommitment {
        L1BlockCommitment::new(height, L1BlockId::default())
    }

    #[tokio::test]
    async fn emit_delivers_to_subscriber_in_order() {
        let subs = AsmSubscribers::default();
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
        let subs = AsmSubscribers::default();
        let mut a = subs.subscribe();
        let mut b = subs.subscribe();

        subs.emit(commitment(7));

        assert_eq!(a.recv().await, Some(commitment(7)));
        assert_eq!(b.recv().await, Some(commitment(7)));
    }

    #[tokio::test]
    async fn dropped_subscriber_is_pruned_on_next_emit() {
        let subs = AsmSubscribers::default();
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
        let subs = AsmSubscribers::default();
        let mut sub = subs.subscribe();
        drop(subs);
        assert_eq!(sub.recv().await, None);
    }
}
