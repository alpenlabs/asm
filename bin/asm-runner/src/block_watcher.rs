//! Minimal Bitcoin block watcher for the ASM runner.
//!
//! Subscribes to a bitcoind `rawblock` ZMQ topic and submits each new block to
//! the ASM worker. The worker walks back from the submitted block to its last
//! stored anchor, so any heights skipped while the runner was down (or dropped
//! by ZMQ) are synced by the worker itself — including across L1 reorgs.
//!
//! This is a glue-like replacement for the `btc-tracker` that asm-runner needs:
//! real-time block notification with `bury_depth=0` (no reorg tracking, no
//! tx monitoring). Written to avoid a painful dependency on `strata-bridge`.

use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use bitcoin::Block;
use bitcoincore_zmq::{Message, SocketMessage, subscribe_async_wait_handshake};
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

/// Drives the ASM worker by subscribing to bitcoind's `rawblock` ZMQ topic and
/// submitting each new block. The worker syncs any skipped heights itself by
/// walking back from the submitted block to its last anchor, so this watcher
/// does not backfill.
///
/// N.B. Will be (eventually) onto SF rails and integrated with the worker "natively".
pub(crate) async fn drive_asm_from_bitcoin(
    config: BitcoinConfig,
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

        // Blocks below the start height are already covered by the worker's
        // anchor; never feed it a pre-anchor block.
        if received_height < start_height {
            debug!(
                %received_height,
                %start_height,
                "block is below start height, skipping"
            );
            continue;
        }

        if let Err(err) = submit_block(&asm_worker, &proof_tx, block).await {
            error!(%received_height, ?err, "failed to submit block from ZMQ");
        }
    }
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
        let asm_proof_id = ProofId::Asm(L1Range::single(commitment));
        if let Err(err) = tx.send(asm_proof_id) {
            warn!(%height, %hash, ?err, "failed to enqueue ASM proof request");
        }
        let moho_proof_id = ProofId::Moho(commitment);
        if let Err(err) = tx.send(moho_proof_id) {
            warn!(%height, %hash, ?err, "failed to enqueue Moho proof request");
        }
    }

    Ok(())
}
