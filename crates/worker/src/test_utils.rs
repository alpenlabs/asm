//! Test utilities for the ASM worker.
//!
//! Provides [`TestAsmWorkerContext`], a [`WorkerContext`](crate::WorkerContext)
//! implementation backed by a Bitcoin regtest node (for L1 data) and the real
//! sled-backed [`asm_storage`] stores (for anchor state, the manifest-hash MMR,
//! manifests, and aux data), opened on a throwaway [`TempDir`]. Backing the
//! tests with the production storage — rather than bespoke in-memory maps —
//! exercises the same persistence path the runner uses. The worker's own unit
//! tests use it via `cfg(test)`; downstream integration tests pull it in with
//! the `test-utils` feature.

use std::sync::Arc;

use asm_storage::{
    SledAsmAuxDataDb, SledAsmHandoverDb, SledAsmManifestDb, SledAsmManifestMmrDb, SledAsmStateDb,
};
use bitcoin::{Block, BlockHash, Network, Txid, block::Header, params::Params};
use bitcoind_async_client::{Client, traits::Reader};
use strata_asm_common::{AnchorState, AsmManifest, AsmManifestHash};
use strata_btc_types::{BitcoinTxid, BlockHashExt, L1BlockIdBitcoinExt, RawBitcoinTx};
use strata_btc_verification::{L1Anchor, get_relative_difficulty_adjustment_height};
use strata_identifiers::{L1BlockCommitment, L1BlockId, L1Height};
use strata_merkle::MerkleProofB32;
use strata_predicate::PredicateKey;
use tempfile::TempDir;
use tokio::{runtime::Handle, task::block_in_place};

use crate::{
    AnchorStateStore, AsmHandoverStore, AuxDataStore, L1DataProvider, ManifestMmrStore,
    WorkerError, WorkerResult,
};

/// Sled-backed state stores for the test worker context.
///
/// Consolidating the stores — plus the temp dir that backs them — into one
/// struct lets the context hold a single `Arc<AsmWorkerState>` rather than one
/// `Arc` per store, and ties the whole storage lifetime together: the temp dir
/// (and its on-disk data) is deleted when the last clone of the context drops
/// this.
#[derive(Debug)]
pub struct AsmWorkerState {
    state_db: SledAsmStateDb,
    aux_db: SledAsmAuxDataDb,
    manifest_db: SledAsmManifestDb,
    mmr_db: SledAsmManifestMmrDb,
    handover_db: SledAsmHandoverDb,
    /// Temp dir the sled database lives in; deleted when this is dropped.
    _tempdir: TempDir,
}

/// Test implementation of WorkerContext for integration tests
///
/// Integrates with local regtest node via RPC client, and persists all ASM
/// state through the same sled-backed [`asm_storage`] stores the production
/// runner uses. The stores are opened on a [`TempDir`] that lives as long as the
/// context (and is deleted when the last clone drops), so each context is fully
/// isolated on disk.
#[derive(Clone, Debug)]
pub struct TestAsmWorkerContext {
    /// Bitcoin RPC client for fetching blocks
    pub client: Arc<Client>,
    /// Tokio runtime handle from the test runtime, used for async operations
    /// from the worker's dedicated OS thread (which has no tokio context).
    pub tokio_handle: Handle,
    /// Consolidated sled-backed state stores.
    state: Arc<AsmWorkerState>,
}

impl TestAsmWorkerContext {
    /// Create a new test context with a Bitcoin RPC client.
    ///
    /// Captures the current tokio runtime handle so the worker's dedicated OS
    /// thread can drive async operations on the original runtime (where the
    /// HTTP client's connection pool lives). Opens a fresh sled database in a
    /// throwaway temp directory to back all ASM state stores.
    pub fn new(client: Client) -> Self {
        let tempdir = tempfile::tempdir().expect("create temp dir for sled db");
        let db = sled::open(tempdir.path()).expect("open sled db");
        let state_db = SledAsmStateDb::open(&db).expect("open state db");
        let aux_db = SledAsmAuxDataDb::open(&db).expect("open aux db");
        let manifest_db = SledAsmManifestDb::open(&db).expect("open manifest db");
        let mmr_db = SledAsmManifestMmrDb::open(&db).expect("open manifest mmr db");
        let handover_db = SledAsmHandoverDb::open(&db).expect("open handover db");

        Self {
            client: Arc::new(client),
            tokio_handle: Handle::current(),
            state: Arc::new(AsmWorkerState {
                state_db,
                aux_db,
                manifest_db,
                mmr_db,
                handover_db,
                _tempdir: tempdir,
            }),
        }
    }

    /// Number of leaves in the manifest MMR (sentinels + real manifest hashes).
    /// Replaces the stored row for a state's own commitment without moving the
    /// active tip. Used by tests that need durable state to disagree with what
    /// the worker holds in memory.
    pub fn overwrite_anchor_snapshot(&self, state: &AnchorState) {
        self.state
            .state_db
            .put(state)
            .expect("overwrite anchor snapshot");
    }

    pub fn mmr_leaf_count(&self) -> u64 {
        self.state.mmr_db.leaf_count().expect("read mmr leaf count")
    }

    /// The full [`AsmManifest`] recorded for `blockid`, if any.
    ///
    /// A targeted lookup: tests fetch the one manifest they care about by block
    /// rather than snapshotting the whole store. Pair with
    /// [`get_manifest_hash`](ManifestMmrStore::get_manifest_hash) (by MMR index)
    /// for the leaf side.
    pub fn get_manifest(&self, blockid: &L1BlockCommitment) -> Option<AsmManifest> {
        self.state.manifest_db.get(blockid).expect("read manifest")
    }
}

impl L1DataProvider for TestAsmWorkerContext {
    fn get_l1_block(&self, blockid: &L1BlockId) -> WorkerResult<Block> {
        // Fetch from regtest. We must handle two calling contexts:
        // 1. From within a tokio runtime (test thread) — use `block_in_place` to avoid "cannot
        //    start a runtime from within a runtime" panic.
        // 2. From the worker's dedicated OS thread (spawned by `spawn_critical`, no tokio context)
        //    — use the stored handle to drive the future on the original runtime where the HTTP
        //    client's connection pool lives.
        let block_hash = blockid.to_block_hash();
        let client = self.client.clone();
        let fetch = || async { client.get_block(&block_hash).await };
        let block = if Handle::try_current().is_ok() {
            block_in_place(|| self.tokio_handle.block_on(fetch()))
        } else {
            self.tokio_handle.block_on(fetch())
        }
        .map_err(|_| WorkerError::MissingL1Block(*blockid))?;

        Ok(block)
    }

    fn get_l1_block_header(&self, blockid: &L1BlockId) -> WorkerResult<Header> {
        // See `get_l1_block` for the two-context branching rationale.
        let block_hash = blockid.to_block_hash();
        let client = self.client.clone();
        let fetch = || async { client.get_block_header(&block_hash).await };
        let header = if Handle::try_current().is_ok() {
            block_in_place(|| self.tokio_handle.block_on(fetch()))
        } else {
            self.tokio_handle.block_on(fetch())
        }
        .map_err(|_| WorkerError::MissingL1Block(*blockid))?;

        Ok(header)
    }

    fn get_l1_block_header_at_height(&self, height: L1Height) -> WorkerResult<Header> {
        // See `get_l1_block` for the two-context branching rationale.
        let client = self.client.clone();
        let fetch = || async move {
            let hash = client.get_block_hash(u64::from(height)).await?;
            client.get_block_header(&hash).await
        };
        let header = if Handle::try_current().is_ok() {
            block_in_place(|| self.tokio_handle.block_on(fetch()))
        } else {
            self.tokio_handle.block_on(fetch())
        }
        .map_err(|_| WorkerError::L1BlockNotFound { height })?;

        Ok(header)
    }

    fn get_l1_block_height(&self, blockid: &L1BlockId) -> WorkerResult<L1Height> {
        // See `get_l1_block` for the two-context branching rationale.
        let block_hash = blockid.to_block_hash();
        let client = self.client.clone();
        let fetch = || async move { client.get_block_height(&block_hash).await };
        let height = if Handle::try_current().is_ok() {
            block_in_place(|| self.tokio_handle.block_on(fetch()))
        } else {
            self.tokio_handle.block_on(fetch())
        }
        .map_err(|_| WorkerError::MissingL1Block(*blockid))?;

        L1Height::try_from(height).map_err(|_| WorkerError::HeightOutOfRange { height })
    }

    fn get_network(&self) -> WorkerResult<Network> {
        Ok(Network::Regtest)
    }

    fn get_bitcoin_tx(&self, txid: &BitcoinTxid) -> WorkerResult<RawBitcoinTx> {
        let txid_inner: Txid = (*txid).into();

        // See `get_l1_block` for the two-context branching rationale.
        let client = self.client.clone();
        let fetch = || async move { client.get_raw_transaction_verbosity_zero(&txid_inner).await };
        let raw_tx_result = if Handle::try_current().is_ok() {
            block_in_place(|| self.tokio_handle.block_on(fetch()))
        } else {
            self.tokio_handle.block_on(fetch())
        }
        .map_err(|_| WorkerError::BitcoinTxNotFound(*txid))?;

        Ok(RawBitcoinTx::from(raw_tx_result.0))
    }
}

impl AnchorStateStore for TestAsmWorkerContext {
    fn get_anchor_state(&self, blockid: &L1BlockCommitment) -> WorkerResult<AnchorState> {
        self.state
            .state_db
            .get(blockid)
            .map_err(WorkerError::DbError)?
            .ok_or(WorkerError::MissingAsmState(*blockid.blkid()))
    }

    fn get_latest_anchor_state(&self) -> WorkerResult<Option<(L1BlockCommitment, AnchorState)>> {
        self.state
            .state_db
            .get_latest()
            .map_err(WorkerError::DbError)
    }

    fn store_anchor_state(&self, state: &AnchorState) -> WorkerResult<()> {
        self.state
            .state_db
            .commit(state)
            .map_err(WorkerError::DbError)
    }
}

impl AsmHandoverStore for TestAsmWorkerContext {
    fn store_next_predicate(
        &self,
        block: &L1BlockCommitment,
        predicate: &PredicateKey,
    ) -> WorkerResult<()> {
        self.state
            .handover_db
            .put(block, predicate)
            .map_err(WorkerError::DbError)
    }

    fn get_next_predicate(&self, block: &L1BlockCommitment) -> WorkerResult<Option<PredicateKey>> {
        self.state
            .handover_db
            .get(block)
            .map_err(WorkerError::DbError)
    }
}

impl ManifestMmrStore for TestAsmWorkerContext {
    fn put_manifest(&self, manifest: AsmManifest) -> WorkerResult<()> {
        self.state
            .manifest_db
            .put(&manifest)
            .map_err(WorkerError::DbError)
    }

    fn put_manifest_hash(&self, height: u64, hash: AsmManifestHash) -> WorkerResult<()> {
        self.state
            .mmr_db
            .put_leaf(height, hash)
            .map_err(WorkerError::DbError)
    }

    fn manifest_mmr_leaf_count(&self) -> WorkerResult<u64> {
        self.state.mmr_db.leaf_count().map_err(WorkerError::DbError)
    }

    fn generate_mmr_proof_at(
        &self,
        index: u64,
        at_leaf_count: u64,
    ) -> WorkerResult<MerkleProofB32> {
        self.state
            .mmr_db
            .generate_proof(index, at_leaf_count)
            .map_err(|_| WorkerError::MmrProofFailed { index })
    }

    fn get_manifest_hash(&self, index: u64) -> WorkerResult<AsmManifestHash> {
        self.state
            .mmr_db
            .get_leaf(index)
            .map_err(WorkerError::DbError)?
            .ok_or(WorkerError::ManifestHashNotFound { index })
    }
}

impl AuxDataStore for TestAsmWorkerContext {
    fn store_aux_data(
        &self,
        blockid: &L1BlockCommitment,
        data: &strata_asm_common::AuxData,
    ) -> WorkerResult<()> {
        self.state
            .aux_db
            .put(blockid, data)
            .map_err(WorkerError::DbError)
    }

    fn get_aux_data(
        &self,
        blockid: &L1BlockCommitment,
    ) -> WorkerResult<strata_asm_common::AuxData> {
        self.state
            .aux_db
            .get(blockid)
            .map_err(WorkerError::DbError)?
            .ok_or(WorkerError::MissingAuxData(*blockid))
    }
}

/// Helper to construct [`L1Anchor`] from a block hash using the client.
pub async fn get_l1_anchor(client: &Client, hash: &BlockHash) -> anyhow::Result<L1Anchor> {
    let header: Header = client.get_block_header(hash).await?;
    let height = client.get_block_height(hash).await?;

    // Construct L1BlockCommitment
    let blkid = header.block_hash().to_l1_block_id();
    let blk_commitment = L1BlockCommitment::new(height as u32, blkid);

    let network = client.network().await?;
    let params = Params::from(network);

    // `epoch_start_timestamp` is the timestamp of the *first* block of the current difficulty
    // epoch (Bitcoin retargets every `difficulty_adjustment_interval` blocks), not this block's
    // own timestamp. Regtest never retargets so it doesn't affect these tests, but model it
    // correctly regardless.
    let epoch_start_height = get_relative_difficulty_adjustment_height(0, height as u32, &params);
    let epoch_start_hash = client.get_block_hash(epoch_start_height as u64).await?;
    let epoch_start_timestamp = client.get_block_header(&epoch_start_hash).await?.time;

    // `next_target` only changes at a retarget boundary, which these tests never cross; off a
    // boundary the next target is just this block's target.
    let next_target = header.bits.to_consensus();

    Ok(L1Anchor {
        block: blk_commitment,
        next_target,
        epoch_start_timestamp,
        network,
    })
}

/// Regtest-backed fixtures for the worker's own unit tests.
///
/// Gated on `cfg(test)` (not the `test-utils` feature), so this scaffolding —
/// and its heavier dev-dependencies (a real ASM spec, params, the regtest node)
/// — never leaks to downstream `test-utils` consumers.
#[cfg(test)]
pub(crate) mod fixtures {
    use std::sync::Arc;

    use bitcoin::{Block, BlockHash};
    use bitcoind_async_client::{Client, traits::Reader};
    use corepc_node::Node;
    use strata_asm_common::{
        ANCHOR_STATE_VERSION, AnchorState, AsmBootstrap, AsmError, AsmHistoryAccumulatorState,
        AsmResult, AsmSpec, AsmSpecId, AsmSpecPredecessor, AuxData, ChainViewState,
        HeaderVerificationState, MsgRelayer, NullMsg, SectionState, SectionStateExt, Stage,
        Subprotocol, TxInputRef, VerifiedAuxData,
    };
    use strata_asm_stf::{
        AsmPreProcessOutput, AsmStfOutput, AsmTargetSet, PreStateValidation, pre_process_for,
        transition_for, validate_pre_state_for, validate_pre_state_with_predecessor_for,
    };
    use strata_btc_verification::TxidInclusionProof;
    use strata_l1_txfmt::SubprotocolId;
    use strata_predicate::{PredicateKey, PredicateTypeId};

    /// Subprotocol id the test specifications key their single section on.
    const TEST_SUBPROTOCOL_ID: SubprotocolId = 42;
    use strata_btc_types::BlockHashExt;
    use strata_identifiers::L1BlockCommitment;
    use strata_l1_txfmt::MagicBytes;
    use strata_test_utils_btcio::{
        get_bitcoind_and_client, get_bitcoind_and_client_with_txindex, mine_blocks,
    };

    use super::{TestAsmWorkerContext, get_l1_anchor};
    use crate::{AsmWorkerServiceState, Subscribers};

    /// The single subprotocol the test specifications run, at the released
    /// codec version. Its state is a bare `u64` so tests can assert on the
    /// value that crosses the boundary.
    #[derive(Debug)]
    pub(crate) struct TestSubprotocolV0;

    impl Subprotocol for TestSubprotocolV0 {
        const ID: SubprotocolId = TEST_SUBPROTOCOL_ID;
        const STATE_VERSION: u8 = 0;
        type State = u64;
        type InitConfig = ();
        type Msg = NullMsg<TEST_SUBPROTOCOL_ID>;

        fn init(_config: &Self::InitConfig) -> Self::State {
            0
        }

        fn process_txs(
            _state: &mut Self::State,
            _txs: &[TxInputRef<'_>],
            _header_vs: &HeaderVerificationState,
            _verified_aux_data: &VerifiedAuxData,
            _relayer: &mut impl MsgRelayer,
        ) {
        }

        fn process_msgs(_state: &mut Self::State, _msgs: &[Self::Msg], _l1ref: &L1BlockCommitment) {
        }
    }

    /// The same subprotocol one codec version on. It shares a state type with
    /// [`TestSubprotocolV0`], so only the declared version separates them —
    /// exactly the situation a migration exists to resolve.
    #[derive(Debug)]
    pub(crate) struct TestSubprotocolV1;

    impl Subprotocol for TestSubprotocolV1 {
        const ID: SubprotocolId = TEST_SUBPROTOCOL_ID;
        const STATE_VERSION: u8 = 1;
        type State = u64;
        type InitConfig = ();
        type Msg = NullMsg<TEST_SUBPROTOCOL_ID>;

        fn init(_config: &Self::InitConfig) -> Self::State {
            0
        }

        fn process_txs(
            _state: &mut Self::State,
            _txs: &[TxInputRef<'_>],
            _header_vs: &HeaderVerificationState,
            _verified_aux_data: &VerifiedAuxData,
            _relayer: &mut impl MsgRelayer,
        ) {
        }

        fn process_msgs(_state: &mut Self::State, _msgs: &[Self::Msg], _l1ref: &L1BlockCommitment) {
        }
    }

    /// Stand-in for the released rules.
    #[derive(Debug)]
    pub(crate) struct TestAsmSpec;

    impl AsmSpec for TestAsmSpec {
        const ID: AsmSpecId = AsmSpecId::V0;

        fn call_subprotocols(stage: &mut impl Stage) {
            stage.invoke_subprotocol::<TestSubprotocolV0>();
        }
    }

    /// Stand-in for the successor rules. Its migration doubles the section
    /// value, so a test can tell migrated state from state that was passed
    /// through untouched.
    #[derive(Debug)]
    pub(crate) struct TestAsmSuccessorSpec;

    impl AsmSpec for TestAsmSuccessorSpec {
        const ID: AsmSpecId = AsmSpecId::V1;

        fn call_subprotocols(stage: &mut impl Stage) {
            stage.invoke_subprotocol::<TestSubprotocolV1>();
        }

        fn predecessor() -> Option<AsmSpecPredecessor> {
            Some(AsmSpecPredecessor::of::<TestAsmSpec>())
        }

        fn migrate_state(pre_state: &AnchorState) -> AsmResult<AnchorState> {
            let old = pre_state
                .find_section(TEST_SUBPROTOCOL_ID)
                .ok_or(AsmError::InvalidSubprotocolState(TEST_SUBPROTOCOL_ID))?
                .try_to_state::<TestSubprotocolV0>()?;
            let mut migrated = pre_state.clone();
            migrated.sections = vec![SectionState::from_state::<TestSubprotocolV1>(&(old * 2))?]
                .try_into()
                .map_err(AsmError::TooManySections)?;
            Ok(migrated)
        }
    }

    /// The two-entry table the worker resolves predicates against.
    #[derive(Debug, Clone, Copy)]
    pub(crate) struct TestAsmTargets;

    impl TestAsmTargets {
        /// Resolves `predicate` or refuses. A predicate this build cannot
        /// execute is a stop condition, never a fallback to some default.
        fn require(&self, predicate: &PredicateKey) -> AsmResult<AsmSpecId> {
            self.spec_id_for(predicate)
                .ok_or_else(|| AsmError::UnsupportedPredicate {
                    predicate: format!("{predicate:?}"),
                })
        }
    }

    impl AsmTargetSet for TestAsmTargets {
        fn spec_id_for(&self, predicate: &PredicateKey) -> Option<AsmSpecId> {
            if predicate == &test_predicate() || predicate == &test_rotated_baseline_predicate() {
                Some(AsmSpecId::V0)
            } else if predicate == &test_successor_predicate() {
                Some(AsmSpecId::V1)
            } else {
                None
            }
        }

        fn direct_predecessor_of(&self, target: AsmSpecId) -> Option<AsmSpecId> {
            match target {
                AsmSpecId::V1 => Some(AsmSpecId::V0),
                _ => None,
            }
        }

        fn validate_pre_state(
            &self,
            predicate: &PredicateKey,
            state: &AnchorState,
        ) -> AsmResult<PreStateValidation> {
            match self.require(predicate)? {
                AsmSpecId::V0 => validate_pre_state_for::<TestAsmSpec>(state),
                AsmSpecId::V1 => validate_pre_state_with_predecessor_for::<
                    TestAsmSuccessorSpec,
                    TestAsmSpec,
                >(state),
            }
        }

        fn pre_process<'b>(
            &self,
            predicate: &PredicateKey,
            pre_state: &AnchorState,
            block: &'b Block,
        ) -> AsmResult<AsmPreProcessOutput<'b>> {
            match self.require(predicate)? {
                AsmSpecId::V0 => pre_process_for::<TestAsmSpec>(pre_state, block),
                AsmSpecId::V1 => pre_process_for::<TestAsmSuccessorSpec>(pre_state, block),
            }
        }

        fn transition(
            &self,
            predicate: &PredicateKey,
            pre_state: &AnchorState,
            block: &Block,
            aux_data: &AuxData,
            coinbase_inclusion_proof: Option<&TxidInclusionProof>,
        ) -> AsmResult<AsmStfOutput> {
            match self.require(predicate)? {
                AsmSpecId::V0 => transition_for::<TestAsmSpec>(
                    pre_state,
                    block,
                    aux_data,
                    coinbase_inclusion_proof,
                ),
                AsmSpecId::V1 => transition_for::<TestAsmSuccessorSpec>(
                    pre_state,
                    block,
                    aux_data,
                    coinbase_inclusion_proof,
                ),
            }
        }
    }

    /// The predicate a test chain is bootstrapped under: the released rules.
    pub(crate) fn test_predicate() -> PredicateKey {
        predicate(0x01)
    }

    /// A different predicate that still resolves to the released rules, for
    /// asserting that a handover changed without changing the specification.
    pub(crate) fn test_rotated_baseline_predicate() -> PredicateKey {
        predicate(0x02)
    }

    /// The predicate that hands over to the successor rules.
    pub(crate) fn test_successor_predicate() -> PredicateKey {
        predicate(0x03)
    }

    fn predicate(seed: u8) -> PredicateKey {
        PredicateKey::try_new(PredicateTypeId::Bip340Schnorr, vec![seed; 32])
            .expect("test predicate is within the condition limit")
    }

    /// A validated genesis bootstrap anchored at `genesis_height`, under the
    /// released specification.
    pub(crate) async fn genesis_bootstrap(
        client: &Client,
        genesis_height: u64,
    ) -> Arc<AsmBootstrap> {
        let tip = client
            .get_block_hash(genesis_height)
            .await
            .expect("genesis tip hash");
        let anchor = get_l1_anchor(client, &tip).await.expect("genesis anchor");
        let chain_view = ChainViewState {
            history_accumulator: AsmHistoryAccumulatorState::new(genesis_height),
            pow_state: HeaderVerificationState::init(anchor),
        };
        let state = AnchorState {
            version: ANCHOR_STATE_VERSION,
            magic: AnchorState::magic_ssz(MagicBytes::new(*b"ALPN")),
            chain_view,
            sections: vec![
                SectionState::from_state::<TestSubprotocolV0>(&0).expect("test section fits"),
            ]
            .try_into()
            .expect("one section fits within capacity"),
        };
        Arc::new(
            AsmBootstrap::try_new::<TestAsmSpec>(state)
                .expect("test genesis is executable under v0"),
        )
    }

    /// A running regtest node, its client, and a worker state whose genesis
    /// anchor sits at the chain tip.
    pub(crate) struct StateFixture {
        /// Kept alive for the test's duration; dropping it stops `bitcoind`.
        pub node: Node,
        pub client: Arc<Client>,
        pub state: AsmWorkerServiceState<TestAsmWorkerContext, TestAsmTargets>,
    }

    /// Builds a worker state with genesis at `genesis_height`: mine that many
    /// blocks, point the ASM params' anchor at the tip, and run
    /// [`AsmWorkerServiceState::new`] (which stores the genesis anchor and
    /// prefills the manifest MMR).
    pub(crate) async fn setup_state(genesis_height: u64) -> StateFixture {
        let (node, client) = get_bitcoind_and_client();
        let client = Arc::new(client);
        mine_blocks(&node, &client, genesis_height as usize, None)
            .await
            .expect("mine genesis blocks");

        let bootstrap = genesis_bootstrap(&client, genesis_height).await;
        let context = TestAsmWorkerContext::new((*client).clone());
        let state = AsmWorkerServiceState::new(
            context,
            TestAsmTargets,
            test_predicate(),
            bootstrap,
            Subscribers::default(),
        )
        .expect("create service state");

        StateFixture {
            node,
            client,
            state,
        }
    }

    /// A running regtest node with a bare worker context (no anchors stored, no
    /// params). For tests that drive the context directly.
    pub(crate) struct ContextFixture {
        /// Kept alive for the test's duration; dropping it stops `bitcoind`.
        pub _node: Node,
        pub client: Arc<Client>,
        pub context: TestAsmWorkerContext,
    }

    /// Mines `height` blocks and wraps the node in a fresh, empty context.
    pub(crate) async fn setup_context(height: u64) -> ContextFixture {
        let (node, client) = get_bitcoind_and_client();
        let client = Arc::new(client);
        mine_blocks(&node, &client, height as usize, None)
            .await
            .expect("mine blocks");
        let context = TestAsmWorkerContext::new((*client).clone());
        ContextFixture {
            _node: node,
            client,
            context,
        }
    }

    /// Like [`setup_context`] but with `-txindex` enabled, so the context can
    /// fetch confirmed non-wallet transactions (e.g. coinbase txs) by txid via
    /// [`get_bitcoin_tx`](crate::L1DataProvider::get_bitcoin_tx).
    pub(crate) async fn setup_context_with_txindex(height: u64) -> ContextFixture {
        let (node, client) = get_bitcoind_and_client_with_txindex();
        let client = Arc::new(client);
        mine_blocks(&node, &client, height as usize, None)
            .await
            .expect("mine blocks");
        let context = TestAsmWorkerContext::new((*client).clone());
        ContextFixture {
            _node: node,
            client,
            context,
        }
    }

    /// Mines `n` blocks on the active chain and returns their commitments,
    /// oldest first.
    pub(crate) async fn mine(node: &Node, client: &Client, n: usize) -> Vec<L1BlockCommitment> {
        let hashes = mine_blocks(node, client, n, None)
            .await
            .expect("mine blocks");
        commitments(client, &hashes).await
    }

    /// Forces a reorg: invalidate the block at `invalidate_height` (dropping it
    /// and every block above it), then mine `new_len` blocks on the resulting
    /// tip. Returns the new branch's commitments, oldest first.
    ///
    /// `invalidate_block` is forceful — it marks the abandoned branch *invalid*,
    /// not merely shorter — so the newly mined branch becomes the active chain
    /// regardless of its length. Unlike a natural reorg, `new_len` need not
    /// exceed the abandoned branch: the new tip may land below, at, or above the
    /// old one (use a lower `new_len` to test a reorg to a lower height). The
    /// only requirement is `new_len >= 1`, so there is a new tip to target.
    pub(crate) async fn reorg(
        node: &Node,
        client: &Client,
        invalidate_height: u64,
        new_len: usize,
    ) -> Vec<L1BlockCommitment> {
        let bad = client
            .get_block_hash(invalidate_height)
            .await
            .expect("hash to invalidate");
        node.client.invalidate_block(bad).expect("invalidate block");
        mine(node, client, new_len).await
    }

    /// Resolves each block hash to its height-tagged commitment.
    async fn commitments(client: &Client, hashes: &[BlockHash]) -> Vec<L1BlockCommitment> {
        let mut out = Vec::with_capacity(hashes.len());
        for hash in hashes {
            let height = client.get_block_height(hash).await.expect("block height");
            out.push(L1BlockCommitment::new(height as u32, hash.to_l1_block_id()));
        }
        out
    }
}
