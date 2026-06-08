use bitcoin::Block;
use strata_asm_common::{AsmSpec, AuxData};
use strata_asm_stf::AsmStfOutput;
use strata_btc_verification::TxidInclusionProof;
use strata_identifiers::L1BlockCommitment;
use strata_service::ServiceState;
use tracing::field::Empty;

use crate::{
    AsmState, WorkerContext, WorkerError, WorkerResult, aux_resolver::AuxDataResolver, constants,
};

/// Service state for the ASM worker.
///
/// Generic over the worker context `W` and the ASM spec `S`, so callers can
/// inject alternative specs (e.g. `DebugAsmSpec` wrapping `StrataAsmSpec` for
/// testing) without forking the worker.
#[derive(Debug)]
pub struct AsmWorkerServiceState<W, S: AsmSpec> {
    /// Context for the state to interact with outer world.
    pub(crate) context: W,

    /// ASM spec driving the subprotocol pipeline.
    pub(crate) spec: S,

    /// Current ASM state.
    pub anchor: AsmState,

    /// Current anchor block.
    pub blkid: L1BlockCommitment,

    /// L1 genesis block height. The MMR is height-indexed and prefilled with
    /// sentinels for heights `0..=genesis_height`, so this is the height just
    /// below the first real manifest.
    pub(crate) genesis_height: u64,
}

impl<W, S> AsmWorkerServiceState<W, S>
where
    W: WorkerContext + Send + Sync + 'static,
    S: AsmSpec + Send + Sync + 'static,
    S::Params: Send + Sync + 'static,
{
    /// Creates a new service state, loading the latest anchor or creating genesis.
    pub fn new(context: W, spec: S, params: S::Params) -> WorkerResult<Self> {
        let genesis_height = spec.genesis_l1_height(&params);

        // Align the manifest MMR with L1 heights before processing any block:
        // it is height-indexed, prefilled with sentinels for heights
        // `0..=genesis_height` so the manifest for height `h` lands at index
        // `h`. Idempotent, so safe to run on every startup.
        context.prefill_manifest_mmr(genesis_height)?;

        let (anchor, blkid) = match context.get_latest_asm_state()? {
            Some((blkid, state)) => {
                tracing::info!(%blkid, "ASM worker resuming from stored anchor state");
                (state, blkid)
            }
            None => {
                // Create genesis anchor state.
                let genesis_state = spec.construct_genesis_state(&params);
                let genesis_blk = genesis_state.chain_view.pow_state.last_verified_block;
                tracing::info!(%genesis_blk, "no stored ASM state; initializing genesis anchor");

                let state = AsmState::new(genesis_state, vec![]);
                context.store_anchor_state(&genesis_blk, &state)?;
                (state, genesis_blk)
            }
        };

        Ok(Self {
            context,
            spec,
            anchor,
            blkid,
            genesis_height,
        })
    }

    /// L1 block height of the chain genesis (anchor) block.
    pub(crate) fn genesis_height(&self) -> u64 {
        self.genesis_height
    }

    /// Returns the actual ASM STF results and the auxiliary data used during the transition.
    ///
    /// A caller is responsible for ensuring the current anchor is a parent of a passed block.
    pub fn transition(&self, block: &Block) -> WorkerResult<(AsmStfOutput, AuxData)> {
        let cur_state = &self.anchor;

        // Pre process transition next block against current anchor state.
        let pre_process = {
            let span = tracing::debug_span!("asm.stf.pre_process", protocol_txs = Empty);
            let _guard = span.enter();

            let result = strata_asm_stf::pre_process_asm(&self.spec, cur_state.state(), block)
                .map_err(WorkerError::AsmError)?;

            span.record("protocol_txs", result.txs.len());
            result
        };

        // Resolve auxiliary data requests from subprotocols
        let aux_data = {
            let span = tracing::debug_span!("asm.stf.aux_resolve");
            let _guard = span.enter();

            // Snapshot proofs at the accumulator's own leaf count: a verifier
            // checks them against this accumulator's committed root, so the
            // snapshot size must be that accumulator's.
            let accumulator = &cur_state.state().chain_view.history_accumulator;
            let resolver = AuxDataResolver::new(&self.context, accumulator.num_entries());
            resolver.resolve(&pre_process.aux_requests)?
        };

        // Asm transition.
        let stf_span = tracing::debug_span!("asm.stf.process");
        let _stf_guard = stf_span.enter();

        let coinbase_inclusion_proof = TxidInclusionProof::generate(&block.txdata, 0);

        strata_asm_stf::compute_asm_transition(
            &self.spec,
            cur_state.state(),
            block,
            &aux_data,
            Some(&coinbase_inclusion_proof),
        )
        .map(|output| (output, aux_data))
        .map_err(WorkerError::AsmError)
    }

    /// Updates anchor related bookkeeping.
    pub(crate) fn update_anchor_state(&mut self, anchor: AsmState, blkid: L1BlockCommitment) {
        self.anchor = anchor;
        self.blkid = blkid;
    }
}

impl<W, S> ServiceState for AsmWorkerServiceState<W, S>
where
    W: WorkerContext + Send + Sync + 'static,
    S: AsmSpec + Send + Sync + 'static,
    S::Params: Send + Sync + 'static,
{
    fn name(&self) -> &str {
        constants::SERVICE_NAME
    }
}

#[cfg(test)]
mod tests {
    use bitcoind_async_client::traits::Reader;
    use strata_test_utils_btcio::mine_blocks;

    use super::*;
    use crate::{
        AnchorStateStore,
        test_utils::fixtures::{self, TestAsmSpec},
    };

    /// `transition` runs the STF for a child of the current anchor.
    #[tokio::test(flavor = "multi_thread")]
    async fn transition_processes_child_of_anchor() {
        let fx = fixtures::setup_state(101).await;
        // A child of the genesis anchor: height 102, parent 101.
        let hashes = mine_blocks(&fx.node, &fx.client, 1, None)
            .await
            .expect("mine child block");
        let block = fx.client.get_block(&hashes[0]).await.expect("fetch block");

        fx.state
            .transition(&block)
            .expect("transition of the anchor's child should succeed");
    }

    /// Over an empty store, `new` constructs and persists the genesis anchor.
    #[tokio::test(flavor = "multi_thread")]
    async fn new_creates_genesis_when_store_empty() {
        let fx = fixtures::setup_state(101).await;

        assert_eq!(
            fx.state.blkid.height(),
            101,
            "genesis sits at the anchor height",
        );
        assert!(
            fx.state.context.get_anchor_state(&fx.state.blkid).is_ok(),
            "genesis anchor persisted",
        );
        let latest = fx.state.context.get_latest_asm_state().unwrap();
        assert_eq!(latest.map(|(blk, _)| blk), Some(fx.state.blkid));
    }

    /// When the store already holds a latest anchor, `new` adopts it — a worker
    /// restart resumes from the DB rather than reconstructing genesis.
    #[tokio::test(flavor = "multi_thread")]
    async fn new_adopts_stored_latest() {
        let seed = fixtures::setup_state(101).await;
        let context = seed.state.context.clone(); // shares the in-memory store

        // Simulate prior progress: a later block becomes the latest anchor.
        let advanced = *fixtures::mine(&seed.node, &seed.client, 4)
            .await
            .last()
            .unwrap(); // 105
        context
            .store_anchor_state(&advanced, &seed.state.anchor)
            .unwrap();

        let params = fixtures::genesis_params(&seed.client, 101).await;
        let reloaded = AsmWorkerServiceState::new(context, TestAsmSpec, params).unwrap();

        assert_eq!(
            reloaded.blkid, advanced,
            "adopted the stored latest, not genesis",
        );
    }

    /// `new` prefills the manifest MMR with one sentinel per height up to genesis,
    /// and re-running it on the same store is a no-op (restart safety).
    #[tokio::test(flavor = "multi_thread")]
    async fn new_prefills_mmr_to_genesis_height() {
        let fx = fixtures::setup_state(101).await;
        // Sentinels for heights 0..=101.
        assert_eq!(fx.state.context.mmr_leaf_count(), 102);

        let context = fx.state.context.clone();
        let params = fixtures::genesis_params(&fx.client, 101).await;
        AsmWorkerServiceState::new(context, TestAsmSpec, params).unwrap();

        assert_eq!(
            fx.state.context.mmr_leaf_count(),
            102,
            "prefill is idempotent across restart",
        );
    }
}
