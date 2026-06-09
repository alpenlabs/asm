//! Minimal Bitcoin block watcher for the ASM runner.
//!
//! Subscribes to a bitcoind `hashblock` ZMQ topic and submits each new block
//! hash to the ASM worker. The worker resolves the height, then walks back from
//! the submitted block to its last stored anchor, so any heights skipped while
//! the runner was down (or dropped by ZMQ) are synced by the worker itself —
//! including across L1 reorgs. We subscribe to `hashblock` rather than
//! `rawblock` because the worker re-fetches each full block by RPC when it runs
//! the STF, so the 32-byte hash is all this watcher needs.
//!
//! ZMQ only forwards blocks mined after we subscribe, so on startup the worker
//! would sit at its persisted height until the next block is mined. To avoid
//! that idle wait, the watcher submits the current chain tip once after
//! subscribing; the worker walks back from it to catch up immediately.
//!
//! This is a glue-like replacement for the `btc-tracker` that asm-runner needs:
//! real-time block notification with `bury_depth=0` (no reorg tracking, no
//! tx monitoring). Written to avoid a painful dependency on `strata-bridge`.

use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use bitcoin::BlockHash;
use bitcoincore_zmq::{Message, SocketMessage, subscribe_async_wait_handshake};
use bitcoind_async_client::{Client, traits::Reader};
use futures::StreamExt;
use strata_asm_proof_types::{L1Range, ProofId};
use strata_asm_worker::AsmWorkerHandle;
use strata_tasks::ShutdownGuard;
use tokio::{sync::mpsc, time::timeout};
use tracing::{debug, error, info, warn};

use crate::config::BitcoinConfig;

/// Timeout for the initial ZMQ handshake with bitcoind.
const ZMQ_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);

/// Drives the ASM worker by subscribing to bitcoind's `hashblock` ZMQ topic and
/// submitting each new block hash. The worker syncs any skipped heights itself
/// by walking back from the submitted block to its last anchor, so this watcher
/// does not backfill.
///
/// N.B. Will be (eventually) onto SF rails and integrated with the worker "natively".
pub(crate) async fn drive_asm_from_bitcoin(
    config: BitcoinConfig,
    bitcoin_client: Arc<Client>,
    asm_worker: Arc<AsmWorkerHandle>,
    proof_tx: Option<mpsc::UnboundedSender<ProofId>>,
    shutdown: ShutdownGuard,
) -> Result<()> {
    info!("starting ASM block watcher");

    let socket = config.hashblock_connection_string.as_str();
    let stream = timeout(
        ZMQ_HANDSHAKE_TIMEOUT,
        subscribe_async_wait_handshake(&[socket]),
    )
    .await
    .context("timed out waiting for bitcoind ZMQ handshake")?
    .context("failed to subscribe to bitcoind ZMQ")?;

    let mut stream = stream;

    // Submit the current tip once to catch up from the persisted height without
    // waiting for the next mined block. This runs *after* subscribing so any
    // block mined in between still arrives over ZMQ — no gap between the
    // catch-up and the live stream. A failure here isn't fatal: the next ZMQ
    // block drives the same walk-back, just later. `getblockchaininfo` resolves
    // the tip hash in one call, so there's no window where a block mined between
    // a height read and a hash read could desync them.
    match bitcoin_client.get_blockchain_info().await {
        Ok(info) => {
            if let Err(err) = submit_block(&asm_worker, &proof_tx, info.best_block_hash).await {
                error!(?err, "failed to submit chain tip on startup");
            }
        }
        Err(err) => warn!(?err, "failed to fetch chain tip for startup catch-up"),
    }

    loop {
        let msg = tokio::select! {
            _ = shutdown.wait_for_shutdown() => {
                info!("ASM block watcher shutting down");
                return Ok(());
            }
            item = stream.next() => match item {
                Some(item) => item,
                None => {
                    warn!("ZMQ stream ended unexpectedly");
                    return Ok(());
                }
            }
        };

        let socket_msg = match msg {
            Ok(m) => m,
            Err(err) => {
                error!(?err, "ZMQ receive error");
                continue;
            }
        };

        let block_hash = match socket_msg {
            SocketMessage::Message(Message::HashBlock(hash, _)) => hash,
            // We only subscribe to hashblock, but ignore anything else defensively.
            _ => continue,
        };

        if let Err(err) = submit_block(&asm_worker, &proof_tx, block_hash).await {
            error!(?err, "failed to submit block from ZMQ");
        }
    }
}

/// Submit a block to the ASM worker and, optionally, enqueue proof requests for
/// every block the worker actually processed.
///
/// One submit can drive several blocks: the worker walks back from the submitted
/// block to its last stored anchor (startup catch-up, a ZMQ gap, or a reorg). We
/// enqueue ASM+Moho requests for each processed commitment the worker returns —
/// not just the submitted tip — so the Moho recursive chain stays gap-free (each
/// Moho(H) has its Moho(H-1)). The commitments come back oldest first, the order
/// Moho's recursion needs.
async fn submit_block(
    asm_worker: &AsmWorkerHandle,
    proof_tx: &Option<mpsc::UnboundedSender<ProofId>>,
    block_hash: BlockHash,
) -> Result<()> {
    let processed = asm_worker
        .submit_block_async(block_hash)
        .await
        .with_context(|| format!("submit_block_async for {block_hash}"))?;

    debug!(%block_hash, processed = processed.len(), "submitted block to ASM worker");

    let Some(tx) = proof_tx else {
        return Ok(());
    };

    for commitment in processed {
        let asm_proof_id = ProofId::Asm(L1Range::single(commitment));
        if let Err(err) = tx.send(asm_proof_id) {
            warn!(%commitment, ?err, "failed to enqueue ASM proof request");
        }
        let moho_proof_id = ProofId::Moho(commitment);
        if let Err(err) = tx.send(moho_proof_id) {
            warn!(%commitment, ?err, "failed to enqueue Moho proof request");
        }
    }

    Ok(())
}
