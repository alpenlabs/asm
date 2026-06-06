//! Test harness for running ASM worker as a service with Bitcoin regtest
//!
//! This module provides core infrastructure for integration tests:
//! - Bitcoin regtest node management
//! - ASM worker service lifecycle
//! - Block mining and submission
//! - State query utilities
//! - Generic SPS-50 transaction building
//!
//! # Architecture
//!
//! The harness provides subprotocol-agnostic infrastructure. Subprotocol-specific
//! functionality is added via extension traits in separate modules:
//! - `AdminExt` in `admin.rs` - admin subprotocol operations
//! - `CheckpointExt` in `checkpoint.rs` - checkpoint subprotocol operations
//! - (future) `BridgeExt` in `bridge.rs` - bridge subprotocol operations
//!
//! # Example
//!
//! ```ignore
//! use harness::test_harness::AsmTestHarnessBuilder;
//! use harness::admin::{create_test_admin_setup, sequencer_update, AdminExt};
//!
//! let (admin_config, mut ctx) = create_test_admin_setup(2);
//! let harness = AsmTestHarnessBuilder::default()
//!     .with_admin_config(admin_config)
//!     .build()
//!     .await?;
//! harness.submit_admin_action(&mut ctx, sequencer_update([1u8; 32])).await?;
//! ```

use std::{fmt, sync::Arc};

use bitcoin::{
    absolute::LockTime,
    blockdata::script,
    consensus::encode::serialize_hex,
    hashes::Hash,
    key::UntweakedKeypair,
    secp256k1::{All, Message, Secp256k1, XOnlyPublicKey, SECP256K1},
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo},
    transaction::Version,
    Address, Amount, Block, BlockHash, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
    TxOut, Txid, Witness,
};
use bitcoind_async_client::{
    traits::{Reader, Wallet},
    Client,
};
use corepc_node::Node;
use rand::RngCore;
use strata_asm_params::{AdministrationInitConfig, AsmParams, SubprotocolInstance};
use strata_asm_spec::StrataAsmSpec;
use strata_asm_worker::{
    test_utils::{get_l1_anchor, TestAsmWorkerContext},
    AnchorStateStore, AsmState, AsmWorkerBuilder, AsmWorkerHandle, ManifestMmrStore,
};
use strata_btc_types::BlockHashExt;
use strata_identifiers::L1BlockCommitment;
use strata_l1_envelope_fmt::builder::{build_envelope_script, EnvelopeScriptBuilder};
use strata_l1_txfmt::{ParseConfig, TagData};
use strata_tasks::{TaskExecutor, TaskManager};
use strata_test_utils_arb::ArbitraryGenerator;
use strata_test_utils_checkpoint::CheckpointTestHarness;
use tokio::{runtime::Handle, task::block_in_place};

use super::{
    admin::{create_test_admin_setup, AdminContext, DEFAULT_CONFIRMATION_DEPTH},
    bridge::{create_test_bridge_setup, BridgeContext, DEFAULT_NUM_OPERATORS},
    checkpoint::create_test_checkpoint_setup,
};

// Test Harness

/// Test harness that manages ASM worker service and Bitcoin regtest.
///
/// This struct provides core infrastructure for integration tests:
/// - Bitcoin regtest node and RPC client
/// - ASM worker service lifecycle
/// - Block mining and submission
/// - State queries
/// - Generic SPS-50 transaction building
///
/// Subprotocol-specific methods are provided via extension traits
/// (`AdminExt`, `CheckpointExt`, etc.) implemented in their respective modules.
#[derive(Debug)]
pub struct AsmTestHarness {
    /// Bitcoin regtest node
    pub bitcoind: Node,
    /// Bitcoin RPC client
    pub client: Arc<Client>,
    /// ASM worker handle for submitting blocks
    pub asm_handle: AsmWorkerHandle,
    /// ASM worker context for querying state
    pub context: TestAsmWorkerContext,
    /// ASM-specific parameters
    pub asm_params: Arc<AsmParams>,
    /// Task executor for spawning tasks
    pub executor: TaskExecutor,
    /// Genesis block height
    pub genesis_height: u64,
}

impl AsmTestHarness {
    /// Default transaction fee.
    pub const DEFAULT_FEE: Amount = Amount::from_sat(1000);

    // Block Mining

    /// Mine a block and wait for ASM worker to process it.
    ///
    /// This will:
    /// 1. Mine a block on regtest (coinbase to given address or a new one)
    /// 2. Fetch and cache the block
    /// 3. Submit the block commitment to ASM worker
    /// 4. Wait until ASM worker has processed the block
    ///
    /// When this method returns, the block is guaranteed to be processed by ASM.
    ///
    /// # Returns
    /// The block hash of the mined block
    pub async fn mine_block(&self, address: Option<bitcoin::Address>) -> anyhow::Result<BlockHash> {
        // Mine block
        let address = match address {
            Some(addr) => addr,
            None => self.client.get_new_address().await?,
        };

        let block_hashes =
            strata_test_utils_btcio::mine_blocks(&self.bitcoind, &self.client, 1, Some(address))
                .await?;

        let block_hash = block_hashes[0];

        // Get block height
        let height = self.client.get_block_height(&block_hash).await?;

        // Create L1BlockCommitment and submit to ASM worker
        let block_id = block_hash.to_l1_block_id();
        let block_commitment = L1BlockCommitment::new(height as u32, block_id);

        // Submit to ASM worker and wait for processing to complete.
        // `submit_block` uses `send_and_wait_blocking`, so the block is fully
        // processed when this returns.
        block_in_place(|| self.asm_handle.submit_block(block_commitment))?;

        Ok(block_hash)
    }

    /// Mine multiple blocks, waiting for each to be processed by ASM.
    ///
    /// # Arguments
    /// * `count` - Number of blocks to mine
    ///
    /// # Returns
    /// Vector of block hashes
    pub async fn mine_blocks(&self, count: usize) -> anyhow::Result<Vec<BlockHash>> {
        let mut hashes = Vec::new();
        for _ in 0..count {
            let hash = self.mine_block(None).await?;
            hashes.push(hash);
        }
        Ok(hashes)
    }

    /// Mine a single block containing exactly `txs`, in the given order, then process it.
    ///
    /// `generate_to_address` gives no ordering guarantee for independent transactions, so
    /// tests that depend on intra-block ordering (e.g. two checkpoints that must be
    /// validated epoch-by-epoch) use this instead. It relies on Bitcoin Core's
    /// `generateblock` RPC, which includes the listed transactions in the exact order given.
    ///
    /// `txs` must be reveal transactions whose funding parents are already in the mempool
    /// (as produced by [`Self::build_envelope_tx`]); a normal block is mined first to confirm
    /// those parents so the ordered block only carries the supplied transactions.
    pub async fn mine_block_with_ordered_txs(
        &self,
        txs: &[Transaction],
    ) -> anyhow::Result<BlockHash> {
        // Confirm the supplied txs' funding parents (still unconfirmed in the mempool).
        self.mine_block(None).await?;

        let output = self.client.get_new_address().await?.to_string();
        let raw: Vec<String> = txs.iter().map(serialize_hex).collect();

        let result = self.bitcoind.client.generate_block(&output, &raw, true)?;
        let block_hash: BlockHash = result.hash.parse()?;

        // Same post-step as `mine_block`: feed the block to the ASM worker.
        let height = self.client.get_block_height(&block_hash).await?;
        let block_id = block_hash.to_l1_block_id();
        let block_commitment = L1BlockCommitment::new(height as u32, block_id);
        block_in_place(|| self.asm_handle.submit_block(block_commitment))?;

        Ok(block_hash)
    }

    // Transaction Submission

    /// Submit a transaction to Bitcoin regtest mempool.
    ///
    /// Note: The transaction must be valid and properly funded
    pub async fn submit_transaction(
        &self,
        tx: &bitcoin::Transaction,
    ) -> anyhow::Result<bitcoin::Txid> {
        let result = self.bitcoind.client.send_raw_transaction(tx)?;
        Ok(result.0.parse()?)
    }

    /// Submit a transaction to mempool and mine blocks until it's included.
    ///
    /// Keeps mining blocks until the transaction is confirmed, then waits for
    /// ASM worker to process the block before returning.
    ///
    /// # Returns
    /// The block hash containing the transaction
    pub async fn submit_and_mine_tx(&self, tx: &Transaction) -> anyhow::Result<BlockHash> {
        let txid = self.submit_transaction(tx).await?;

        // Mine blocks until tx is confirmed
        for _ in 0..10 {
            let block_hash = self.mine_block(None).await?;
            let block = self.get_block(block_hash).await?;

            // Check if our tx is in this block
            if block.txdata.iter().any(|t| t.compute_txid() == txid) {
                return Ok(block_hash);
            }
        }

        anyhow::bail!("Transaction {txid} not included after 10 blocks")
    }

    // State Queries

    /// Get the current chain tip height from Bitcoin.
    pub async fn get_chain_tip(&self) -> anyhow::Result<u64> {
        Ok(self.client.get_blockchain_info().await?.blocks.into())
    }

    /// Get the current processed height from ASM state.
    pub fn get_processed_height(&self) -> anyhow::Result<u64> {
        let (commitment, _) = self
            .get_latest_asm_state()?
            .ok_or_else(|| anyhow::anyhow!("No ASM state available"))?;
        Ok(commitment.height() as u64)
    }

    /// Mine blocks until the ASM has processed at least up to `target_height`.
    ///
    /// No-op if the processed height already meets or exceeds `target_height`.
    pub async fn mine_until_processed(&self, target_height: u64) -> anyhow::Result<()> {
        while self.get_processed_height()? < target_height {
            self.mine_block(None).await?;
        }
        Ok(())
    }

    /// Get the latest ASM state from the worker context.
    pub fn get_latest_asm_state(&self) -> anyhow::Result<Option<(L1BlockCommitment, AsmState)>> {
        Ok(self.context.get_latest_asm_state()?)
    }

    /// Get ASM state at a specific block.
    pub fn get_asm_state_at(&self, blockid: &L1BlockCommitment) -> anyhow::Result<AsmState> {
        Ok(self.context.get_anchor_state(blockid)?)
    }

    /// Fetch a block from Bitcoin by hash.
    pub async fn get_block(&self, block_hash: BlockHash) -> anyhow::Result<Block> {
        Ok(self.context.client.get_block(&block_hash).await?)
    }

    /// Get the number of MMR leaves (manifest hashes) stored.
    pub fn get_mmr_leaf_count(&self) -> usize {
        self.context.mmr_leaf_count() as usize
    }

    /// Get a manifest hash by leaf index.
    pub fn get_manifest_hash(
        &self,
        index: u64,
    ) -> anyhow::Result<strata_asm_manifest_types::AsmManifestHash> {
        Ok(self.context.get_manifest_hash(index)?)
    }

    /// Get a snapshot of all stored manifests.
    pub fn get_stored_manifests(&self) -> Vec<strata_asm_manifest_types::AsmManifest> {
        self.context.inner.lock().unwrap().manifests.clone()
    }

    /// Get all MMR leaf hashes in leaf-index order.
    pub fn get_mmr_leaves(&self) -> Vec<[u8; 32]> {
        self.context.mmr_leaves()
    }

    // Funding & Wallet

    /// Create a funding UTXO for transaction building.
    ///
    /// This uses Bitcoin Core's send_to_address to create a new UTXO
    /// with the specified amount, which can then be used as an input.
    ///
    /// # Arguments
    /// * `address` - Address to send funds to
    /// * `amount` - Amount to send (including fees)
    ///
    /// # Returns
    /// (txid, vout) of the created UTXO
    pub(crate) async fn create_funding_utxo(
        &self,
        address: &Address,
        amount: Amount,
    ) -> anyhow::Result<(Txid, u32)> {
        let funding_txid_str = self
            .bitcoind
            .client
            .send_to_address(address, amount)?
            .0
            .to_string();
        let funding_txid: Txid = funding_txid_str.parse()?;

        let funding_tx = self
            .client
            .get_raw_transaction_verbosity_zero(&funding_txid)
            .await?
            .0;

        let prev_vout = funding_tx
            .output
            .iter()
            .enumerate()
            .find(|(_, output)| output.script_pubkey == address.script_pubkey())
            .map(|(idx, _)| idx as u32)
            .ok_or_else(|| anyhow::anyhow!("Could not find output in funding transaction"))?;

        Ok((funding_txid, prev_vout))
    }

    // SPS-50 Transaction Building

    /// Build a funded SPS-50 envelope transaction with real UTXOs.
    ///
    /// This creates a proper Bitcoin transaction that:
    /// 1. Spends a real UTXO (funded by mining blocks)
    /// 2. Contains the payload in taproot envelope script format (SPS-51)
    /// 3. Has SPS-50 compliant OP_RETURN tag
    ///
    /// # Arguments
    /// * `sps50_tag` - SPS-50 tag data (subprotocol ID + tx type)
    /// * `payload` - Serialized payload to embed in witness
    pub async fn build_envelope_tx(
        &self,
        sps50_tag: TagData,
        payload: Vec<u8>,
    ) -> anyhow::Result<Transaction> {
        self.build_envelope_tx_inner(sps50_tag, payload, None).await
    }

    /// Build a funded SPS-50 envelope transaction with a specific envelope keypair.
    ///
    /// The keypair's public key is embedded in the envelope script per SPS-51,
    /// and the tapscript spend is signed with the keypair's secret key.
    pub async fn build_envelope_tx_with_keypair(
        &self,
        sps50_tag: TagData,
        payload: Vec<u8>,
        envelope_keypair: &UntweakedKeypair,
    ) -> anyhow::Result<Transaction> {
        self.build_envelope_tx_inner(sps50_tag, payload, Some(envelope_keypair))
            .await
    }

    async fn build_envelope_tx_inner(
        &self,
        sps50_tag: TagData,
        payload: Vec<u8>,
        envelope_keypair: Option<&UntweakedKeypair>,
    ) -> anyhow::Result<Transaction> {
        let fee = Self::DEFAULT_FEE;
        let dust_amount = Amount::from_sat(1000);
        let funding_amount = fee + dust_amount + Amount::from_sat(1000);

        let secp = Secp256k1::new();

        // Generate a random keypair (used as internal key in both paths)
        let mut rng = rand::thread_rng();
        let mut key_bytes = [0u8; 32];
        rng.fill_bytes(&mut key_bytes);
        let random_keypair = UntweakedKeypair::from_seckey_slice(&secp, &key_bytes)?;

        let keypair = envelope_keypair.unwrap_or(&random_keypair);
        let (internal_key, _parity) = XOnlyPublicKey::from_keypair(keypair);

        // Build the reveal script. When an envelope keypair is provided, use the
        // real SPS-51 envelope format (pubkey + OP_CHECKSIG + data). Otherwise
        // use a simple OP_TRUE envelope for subprotocols that don't need SPS-51.
        let reveal_script = if envelope_keypair.is_some() {
            EnvelopeScriptBuilder::with_pubkey(&internal_key.serialize())?
                .add_envelope(&payload)?
                .build()?
        } else {
            build_simple_envelope_script(&payload)
        };

        // Create taproot spend info
        let taproot_spend_info =
            create_taproot_spend_info(&secp, internal_key, reveal_script.clone())?;

        // Create taproot address for the commit output
        let taproot_address = Address::p2tr(
            &secp,
            internal_key,
            taproot_spend_info.merkle_root(),
            Network::Regtest,
        );

        // Fund the taproot address (commit transaction)
        let (commit_txid, commit_vout) = self
            .create_funding_utxo(&taproot_address, funding_amount)
            .await?;
        let commit_outpoint = OutPoint::new(commit_txid, commit_vout);

        // Build SPS-50 compliant OP_RETURN tag
        let op_return_script =
            ParseConfig::new(self.asm_params.magic).encode_script_buf(&sps50_tag.as_ref())?;

        let op_return_output = TxOut {
            value: Amount::ZERO,
            script_pubkey: op_return_script,
        };

        // Change output
        let change_amount = funding_amount - fee;
        let change_address = self.client.get_new_address().await?;
        let change_output = TxOut {
            value: change_amount,
            script_pubkey: change_address.script_pubkey(),
        };

        // Build control block for tapscript spend
        let control_block = taproot_spend_info
            .control_block(&(reveal_script.clone(), LeafVersion::TapScript))
            .ok_or_else(|| anyhow::anyhow!("Failed to create control block"))?;

        // Build unsigned tx first
        let tx_input = TxIn {
            previous_output: commit_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        };

        let mut reveal_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![tx_input],
            output: vec![op_return_output, change_output],
        };

        // Build witness. SPS-51 envelopes need a Schnorr signature; simple
        // envelopes just need the script and control block.
        let mut witness = Witness::new();
        if envelope_keypair.is_some() {
            let commit_output = TxOut {
                value: funding_amount,
                script_pubkey: taproot_address.script_pubkey(),
            };
            let leaf_hash =
                bitcoin::TapLeafHash::from_script(&reveal_script, LeafVersion::TapScript);
            let sighash = SighashCache::new(&reveal_tx).taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(&[&commit_output]),
                leaf_hash,
                TapSighashType::Default,
            )?;
            let msg = Message::from_digest_slice(&sighash.to_byte_array())?;
            let signature = SECP256K1.sign_schnorr(&msg, keypair);
            witness.push(signature.as_ref());
        }
        witness.push(reveal_script.as_bytes());
        witness.push(control_block.serialize());
        reveal_tx.input[0].witness = witness;

        Ok(reveal_tx)
    }
}

// Helper Functions

/// Build a simple envelope script for subprotocols that don't need SPS-51 auth.
///
/// Creates an `OP_FALSE OP_IF <data> OP_ENDIF OP_TRUE` tapscript.
/// Uses [`build_envelope_script`] for the envelope body and appends `OP_TRUE`
/// so the tapscript leaves a truthy value on the stack (no CHECKSIG).
fn build_simple_envelope_script(payload: &[u8]) -> ScriptBuf {
    let envelope = build_envelope_script(payload).expect("envelope build should not fail in tests");
    script::Builder::from(envelope.into_bytes())
        .push_int(1)
        .into_script()
}

/// Create taproot spend info with reveal script.
///
/// Builds a taproot tree with the reveal script as a leaf.
fn create_taproot_spend_info(
    secp: &Secp256k1<All>,
    internal_key: XOnlyPublicKey,
    reveal_script: ScriptBuf,
) -> anyhow::Result<TaprootSpendInfo> {
    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, reveal_script)?
        .finalize(secp, internal_key)
        .map_err(|_| anyhow::anyhow!("Failed to finalize taproot spend info"))?;

    Ok(taproot_spend_info)
}

// Builder

/// A fully-configured test harness plus the contexts needed to drive each subprotocol.
///
/// [`AsmTestHarnessBuilder::build`] sets up the admin, bridge, and checkpoint subprotocols with
/// deterministic test configs and returns this bundle. Destructure the fields a test needs and
/// ignore the rest with `..`:
///
/// ```ignore
/// let Setup { harness, mut admin, .. } = AsmTestHarnessBuilder::default().build().await;
/// ```
///
/// The contexts are separate bindings (not fields on the harness) so a test can call
/// `harness.submit_admin_action(&mut admin, ..)` — borrowing the harness and a context at once.
#[expect(
    missing_debug_implementations,
    reason = "CheckpointTestHarness (a field) does not implement Debug"
)]
pub struct Setup {
    /// The running harness (Bitcoin regtest + ASM worker).
    pub harness: AsmTestHarness,
    /// Signing context for admin actions (mutable: tracks per-role sequence numbers).
    pub admin: AdminContext,
    /// Operator keys and denomination for building bridge deposits.
    pub bridge: BridgeContext,
    /// Builder for checkpoint payloads (mutable: tracks the verified tip).
    pub checkpoint: CheckpointTestHarness,
}

/// Builder for a [`Setup`]: a harness with all three subprotocols configured deterministically.
///
/// Defaults give an admin at [`DEFAULT_CONFIRMATION_DEPTH`], a [`DEFAULT_NUM_OPERATORS`]-operator
/// bridge, and a checkpoint anchored at the genesis height — override only what a test needs.
/// The genesis anchor state already carries every subprotocol section, so subprotocol state is
/// queryable immediately after `build()`; no init block is mined.
///
/// # Example
///
/// ```ignore
/// let Setup { harness, bridge, mut checkpoint, .. } =
///     AsmTestHarnessBuilder::default().with_txindex().build().await;
/// harness.submit_deposits(&bridge, 3).await?;
/// ```
/// A one-shot tweak applied to the generated admin config before genesis.
type AdminConfigCustomizer = Box<dyn FnOnce(&mut AdministrationInitConfig)>;

pub struct AsmTestHarnessBuilder {
    genesis_height: u64,
    admin_confirmation_depth: u16,
    admin_customize: Option<AdminConfigCustomizer>,
    num_operators: usize,
    txindex: bool,
}

impl Default for AsmTestHarnessBuilder {
    fn default() -> Self {
        Self {
            genesis_height: Self::DEFAULT_GENESIS_HEIGHT,
            admin_confirmation_depth: DEFAULT_CONFIRMATION_DEPTH,
            admin_customize: None,
            num_operators: DEFAULT_NUM_OPERATORS,
            txindex: false,
        }
    }
}

// Manual `Debug` because `admin_customize` holds a boxed closure (not `Debug`); report only
// whether one is set.
impl fmt::Debug for AsmTestHarnessBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AsmTestHarnessBuilder")
            .field("genesis_height", &self.genesis_height)
            .field("admin_confirmation_depth", &self.admin_confirmation_depth)
            .field("admin_customize", &self.admin_customize.is_some())
            .field("num_operators", &self.num_operators)
            .field("txindex", &self.txindex)
            .finish()
    }
}

impl AsmTestHarnessBuilder {
    /// Default genesis block height for tests.
    pub const DEFAULT_GENESIS_HEIGHT: u64 = 101;

    /// Sets the genesis block height (default: [`Self::DEFAULT_GENESIS_HEIGHT`]).
    pub fn with_genesis_height(mut self, height: u64) -> Self {
        self.genesis_height = height;
        self
    }

    /// Sets the confirmation depth applied to every admin update type
    /// (default: [`DEFAULT_CONFIRMATION_DEPTH`]).
    pub fn admin_confirmation_depth(mut self, depth: u16) -> Self {
        self.admin_confirmation_depth = depth;
        self
    }

    /// Tweaks the generated admin config before genesis — e.g. set one update type's confirmation
    /// depth to `0` so it applies immediately:
    ///
    /// ```ignore
    /// .customize_admin(|c| c.confirmation_depths.sequencer_update = 0)
    /// ```
    pub fn customize_admin(
        mut self,
        f: impl FnOnce(&mut AdministrationInitConfig) + 'static,
    ) -> Self {
        self.admin_customize = Some(Box::new(f));
        self
    }

    /// Sets the number of operators in the bridge notary set
    /// (default: [`DEFAULT_NUM_OPERATORS`]).
    pub fn num_operators(mut self, n: usize) -> Self {
        self.num_operators = n;
        self
    }

    /// Enables transaction indexing (`-txindex`) on the Bitcoin regtest node.
    ///
    /// Required for subprotocols that fetch confirmed non-wallet transactions
    /// as auxiliary data (e.g., bridge deposit processing needs the DRT).
    pub fn with_txindex(mut self) -> Self {
        self.txindex = true;
        self
    }

    /// Builds the harness and returns it alongside the per-subprotocol contexts. Panics on
    /// failure (test setup); see [`Setup`].
    pub async fn build(self) -> Setup {
        self.try_build()
            .await
            .expect("failed to build test harness")
    }

    async fn try_build(self) -> anyhow::Result<Setup> {
        let genesis_height = self.genesis_height;

        // 1. Start Bitcoin regtest (with txindex if requested)
        let (bitcoind, client) = if self.txindex {
            strata_test_utils_btcio::get_bitcoind_and_client_with_txindex()
        } else {
            strata_test_utils_btcio::get_bitcoind_and_client()
        };
        let client = Arc::new(client);

        // 2. Mine blocks to genesis height
        strata_test_utils_btcio::mine_blocks(&bitcoind, &client, genesis_height as usize, None)
            .await?;

        let genesis_hash = client.get_block_hash(genesis_height).await?;
        let genesis_view = get_l1_anchor(&client, &genesis_hash).await?;

        // 3. Generate deterministic per-subprotocol configs and the contexts tests drive them
        // with. `build()` owns this so a plain `AsmTestHarnessBuilder::default()` yields a known,
        // ready-to-use setup rather than the arbitrary defaults the params carry otherwise.
        let (mut admin_config, admin_ctx) = create_test_admin_setup(self.admin_confirmation_depth);
        if let Some(customize) = self.admin_customize {
            customize(&mut admin_config);
        }
        let (bridge_config, bridge_ctx) = create_test_bridge_setup(self.num_operators);
        let (checkpoint_config, checkpoint_harness) =
            create_test_checkpoint_setup(genesis_height as u32);

        // 4. Build AsmParams (arbitrary for non-subprotocol fields) and install our configs.
        let mut asm_params: AsmParams = ArbitraryGenerator::new().generate();
        asm_params.anchor = genesis_view;
        for instance in &mut asm_params.subprotocols {
            match instance {
                SubprotocolInstance::Admin(cfg) => *cfg = admin_config.clone(),
                SubprotocolInstance::Bridge(cfg) => *cfg = bridge_config.clone(),
                SubprotocolInstance::Checkpoint(cfg) => *cfg = checkpoint_config.clone(),
            }
        }
        let asm_params = Arc::new(asm_params);

        // 5. Create worker context. The worker prefills the height-indexed MMR
        // with sentinel leaves for L1 heights `0..=genesis_height` during
        // startup (`ManifestMmrStore::prefill_manifest_mmr`), matching the
        // proven (in-state) MMR's genesis prefill so external leaf indices
        // equal L1 block heights.
        let context = TestAsmWorkerContext::new((*client).clone());

        // 6. Create task executor
        let task_manager = TaskManager::new(Handle::current());
        let executor = task_manager.create_executor();

        // 7. Launch ASM worker service
        let asm_handle = AsmWorkerBuilder::new()
            .with_context(context.clone())
            .with_asm_spec(StrataAsmSpec)
            .with_params((*asm_params).clone())
            .launch(&executor)?;

        let harness = AsmTestHarness {
            bitcoind,
            client,
            asm_handle,
            context,
            asm_params,
            executor,
            genesis_height,
        };

        // Submit genesis block to ASM worker
        let genesis_block_id = genesis_hash.to_l1_block_id();
        let genesis_commitment = L1BlockCommitment::new(genesis_height as u32, genesis_block_id);

        // Submit genesis block and wait for processing to complete
        block_in_place(|| harness.asm_handle.submit_block(genesis_commitment))?;

        Ok(Setup {
            harness,
            admin: admin_ctx,
            bridge: bridge_ctx,
            checkpoint: checkpoint_harness,
        })
    }
}
