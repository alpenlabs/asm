//! Minimal Bitcoin block watcher for the ASM runner.
//!
//! Subscribes to a bitcoind `rawblock` ZMQ topic and feeds new blocks to the
//! ASM worker. If the ZMQ stream skips heights (bitcoind catch-up, missed
//! messages, restart), the gap is backfilled.
//!
//! This is a glue-like replacement for the `btc-tracker` that asm-runner needs:
//! real-time block notification with `bury_depth=0` (no reorg tracking, no
//! tx monitoring). Written to avoid a painful dependency on `strata-bridge`.

use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use bitcoin::Block;
use bitcoincore_zmq::{Message, SocketMessage, subscribe_async_wait_handshake};
use bitcoind_async_client::{Client, traits::Reader};
use futures::StreamExt;
use strata_asm_proof_types::{L1Range, ProofId};
use strata_asm_worker::AsmWorkerHandle;
use strata_btc_types::BlockHashExt;
use strata_identifiers::L1BlockCommitment;
use strata_tasks::ShutdownGuard;
use tokio::{sync::mpsc, time::timeout};
use tracing::{debug, error, info, warn};

use crate::config::BitcoinConfig;

/// Timeout for the initial ZMQ handshake with bitcoind.
const ZMQ_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);

/// Drives the ASM worker by subscribing to bitcoind's `rawblock` ZMQ topic
/// and submitting new blocks to the worker, backfilling any skipped heights.
///
/// N.B. Will be (eventually) onto SF rails and integrated with the worker "natively".
pub(crate) async fn drive_asm_from_bitcoin(
    config: BitcoinConfig,
    bitcoin_client: Arc<Client>,
    asm_worker: Arc<AsmWorkerHandle>,
    start_height: u64,
    proof_tx: Option<mpsc::UnboundedSender<ProofId>>,
    shutdown: ShutdownGuard,
) -> Result<()> {
    info!(%start_height, "starting ASM block watcher");

    let socket = config.rawblock_connection_string.as_str();
    let stream = timeout(
        ZMQ_HANDSHAKE_TIMEOUT,
        subscribe_async_wait_handshake(&[socket]),
    )
    .await
    .context("timed out waiting for bitcoind ZMQ handshake")?
    .context("failed to subscribe to bitcoind ZMQ")?;

    let mut stream = stream;
    let mut cursor = start_height;

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

        let block = match socket_msg {
            SocketMessage::Message(Message::Block(block, _)) => block,
            // We only subscribe to rawblock, but ignore anything else defensively.
            _ => continue,
        };

        let received_height = block.bip34_block_height().unwrap_or(0);

        if received_height < cursor {
            debug!(
                %received_height,
                %cursor,
                "block is older than cursor, skipping"
            );
            continue;
        }

        // Backfill any skipped heights [cursor, received_height). This covers
        // the common case of starting after a downtime, or rare ZMQ drops.
        if received_height > cursor {
            info!(
                from = %cursor,
                to = %received_height,
                "backfilling skipped blocks"
            );
            for height in cursor..received_height {
                match fetch_block_at_height(&bitcoin_client, height).await {
                    Ok(fetched) => {
                        if let Err(err) = submit_block(&asm_worker, &proof_tx, fetched).await {
                            error!(%height, ?err, "failed to submit backfill block");
                            // Stop backfilling on failure so we don't hand the
                            // worker a gap. The next ZMQ event will retry.
                            bail!("backfill interrupted at height {height}: {err}");
                        }
                    }
                    Err(err) => {
                        error!(%height, ?err, "failed to fetch backfill block");
                        bail!("backfill fetch failed at height {height}: {err}");
                    }
                }
            }
        }

        if let Err(err) = submit_block(&asm_worker, &proof_tx, block).await {
            error!(%received_height, ?err, "failed to submit block from ZMQ");
        }
        cursor = received_height + 1;
    }
}

/// Fetch a single block by height via the bitcoind RPC client.
async fn fetch_block_at_height(client: &Client, height: u64) -> Result<Block> {
    let hash = client
        .get_block_hash(height)
        .await
        .with_context(|| format!("get_block_hash({height})"))?;
    let block = client
        .get_block(&hash)
        .await
        .with_context(|| format!("get_block({hash})"))?;
    Ok(block)
}

/// Submit a block to the ASM worker and, optionally, enqueue a proof request.
async fn submit_block(
    asm_worker: &AsmWorkerHandle,
    proof_tx: &Option<mpsc::UnboundedSender<ProofId>>,
    block: Block,
) -> Result<()> {
    let height = block.bip34_block_height().unwrap_or(0);
    let hash = block.block_hash();
    let block_id = hash.to_l1_block_id();
    let commitment = L1BlockCommitment::new(height as u32, block_id);

    asm_worker
        .submit_block_async(commitment)
        .await
        .with_context(|| format!("submit_block_async for {hash} at {height}"))?;

    debug!(%height, %hash, "submitted block to ASM worker");

    if let Some(tx) = proof_tx {
        let proof_id = ProofId::Asm(L1Range::single(commitment));
        if let Err(err) = tx.send(proof_id) {
            warn!(%height, %hash, ?err, "failed to enqueue proof request");
        }
    }

    Ok(())
}
