//! Fixtures for checkpoint subprotocol tests.

use std::any::Any;

use bitcoin::{
    Amount, OutPoint, ScriptBuf, Transaction, TxOut, WitnessProgram, WitnessVersion,
    XOnlyPublicKey, consensus, taproot::LeafVersion,
};
use strata_asm_checkpoint_types::{CheckpointInitConfig, CheckpointTip};
use strata_asm_common::{AsmLogEntry, InterprotoMsg, MsgRelayer, RawBitcoinTx, VerifiedAuxData};
use strata_asm_proto_checkpoint_txs::OL_STF_CHECKPOINT_TX_TAG;
use strata_asm_proto_txs_test_utils::{create_dummy_tx, create_reveal_transaction_stub_with_leaf};
use strata_checkpoint_verification::CheckpointState;
use strata_codec::encode_to_vec;
use strata_codec_utils::CodecSsz;
use strata_identifiers::OLBlockId;
use strata_test_utils_arb::ArbitraryGenerator;
use strata_test_utils_checkpoint::CheckpointTestHarness;

/// Relayer that records emitted logs and drops interprotocol messages.
#[derive(Debug, Default)]
pub(crate) struct RecordingRelayer {
    pub(crate) logs: Vec<AsmLogEntry>,
}

impl MsgRelayer for RecordingRelayer {
    fn relay_msg(&mut self, _m: &dyn InterprotoMsg) {}

    fn emit_log(&mut self, log: AsmLogEntry) {
        self.logs.push(log);
    }

    fn as_mut_any(&mut self) -> &mut dyn Any {
        self
    }
}

/// Returns a native P2TR locking script.
pub(crate) fn p2tr_script() -> ScriptBuf {
    witness_program_script(WitnessVersion::V1, &[0x11; 32])
}

/// Returns a segwit v2 locking script, which Bitcoin leaves unencumbered.
pub(crate) fn witness_v2_script() -> ScriptBuf {
    witness_program_script(WitnessVersion::V2, &[0x11; 32])
}

/// Returns the locking script of a `version` witness program.
pub(crate) fn witness_program_script(version: WitnessVersion, program: &[u8]) -> ScriptBuf {
    let program = WitnessProgram::new(version, program).expect("valid witness program");
    ScriptBuf::new_witness_program(&program)
}

/// A checkpoint state at genesis and a payload that passes every check after authentication.
pub(crate) struct CheckpointFixture {
    pub(crate) harness: CheckpointTestHarness,
    pub(crate) state: CheckpointState,
    pub(crate) new_tip: CheckpointTip,
    payload_bytes: Vec<u8>,
}

impl CheckpointFixture {
    pub(crate) fn new() -> Self {
        let genesis_l1_height = 100;
        let genesis_ol_blkid: OLBlockId = ArbitraryGenerator::new().generate();
        let harness = CheckpointTestHarness::new_with_genesis(genesis_l1_height, genesis_ol_blkid);
        let state = CheckpointState::init(CheckpointInitConfig {
            sequencer_key: harness.sequencer_key(),
            checkpoint_predicate: harness.checkpoint_predicate(),
            genesis_l1_height,
            genesis_ol_blkid,
        });
        let new_tip = harness.gen_new_tip();
        let payload = harness.build_payload_with_tip(new_tip);
        let payload_bytes = encode_to_vec(&CodecSsz::new(payload)).expect("payload encodes");

        Self {
            harness,
            state,
            new_tip,
            payload_bytes,
        }
    }

    /// The sequencer's x-only key.
    pub(crate) fn sequencer_key(&self) -> XOnlyPublicKey {
        XOnlyPublicKey::from_slice(self.harness.sequencer_pubkey())
            .expect("sequencer key is a valid x-only key")
    }

    /// Builds a funding transaction whose output 0 is locked by `prevout_script`, and a
    /// checkpoint carrier that spends it with an envelope leaf for `envelope_key` committed
    /// under `leaf_version`.
    pub(crate) fn build_carrier(
        &self,
        envelope_key: &XOnlyPublicKey,
        leaf_version: LeafVersion,
        prevout_script: ScriptBuf,
    ) -> (Transaction, Transaction) {
        let mut funding = create_dummy_tx(1, 0);
        funding.output.push(TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: prevout_script,
        });

        let mut carrier = create_reveal_transaction_stub_with_leaf(
            envelope_key,
            &self.payload_bytes,
            &OL_STF_CHECKPOINT_TX_TAG,
            leaf_version,
        );
        carrier.input[0].previous_output = OutPoint::new(funding.compute_txid(), 0);

        (funding, carrier)
    }

    /// Verified aux data carrying the manifest range for [`Self::new_tip`] and `funding`.
    pub(crate) fn verified_aux(&self, funding: &Transaction) -> VerifiedAuxData {
        let raw = RawBitcoinTx::from_raw_bytes(consensus::serialize(funding));
        self.harness
            .gen_verified_aux_with_txs(&self.new_tip, vec![raw])
    }
}
