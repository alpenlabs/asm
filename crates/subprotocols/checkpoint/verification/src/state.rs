use strata_asm_manifest_types::AsmManifestRangeHash;
use strata_asm_params::CheckpointInitConfig;
use strata_asm_proto_bridge_v1_types::WithdrawOutput;
use strata_asm_proto_checkpoint_types::{CheckpointPayload, CheckpointTip};
use strata_btc_types::BitcoinAmount;
use strata_identifiers::L2BlockCommitment;
use strata_predicate::PredicateKey;

use crate::{
    CheckpointState, DepositPool,
    errors::CheckpointValidationResult,
    verification::{extract_withdrawal_intents, verify_proof},
};

impl CheckpointState {
    /// Initializes checkpoint state from configuration.
    pub fn init(config: CheckpointInitConfig) -> Self {
        let genesis_epoch = 0;
        let genesis_l2_slot = 0;
        let genesis_l2_commitment =
            L2BlockCommitment::new(genesis_l2_slot, config.genesis_ol_blkid);
        let genesis_tip = CheckpointTip::new(
            genesis_epoch,
            config.genesis_l1_height,
            genesis_l2_commitment,
        );
        Self::new(
            config.sequencer_predicate,
            config.checkpoint_predicate,
            genesis_tip,
        )
    }

    /// Creates a new checkpoint state with the given predicates and tip.
    pub(crate) fn new(
        sequencer_predicate: PredicateKey,
        checkpoint_predicate: PredicateKey,
        verified_tip: CheckpointTip,
    ) -> Self {
        Self {
            sequencer_predicate,
            checkpoint_predicate,
            verified_tip,
            deposits: DepositPool::default(),
        }
    }

    /// Returns the sequencer predicate for signature verification.
    pub fn sequencer_predicate(&self) -> &PredicateKey {
        &self.sequencer_predicate
    }

    /// Returns the checkpoint predicate for proof verification.
    pub fn checkpoint_predicate(&self) -> &PredicateKey {
        &self.checkpoint_predicate
    }

    /// Returns the last verified checkpoint tip.
    pub fn verified_tip(&self) -> &CheckpointTip {
        &self.verified_tip
    }

    /// Returns the total available deposit value, in satoshis.
    pub fn available_deposit_sum(&self) -> u64 {
        self.deposits.total().to_sat()
    }

    /// Update the sequencer predicate with a new Schnorr public key.
    pub fn update_sequencer_predicate(&mut self, new_predicate: PredicateKey) {
        self.sequencer_predicate = new_predicate
    }

    /// Update the checkpoint predicate.
    pub fn update_checkpoint_predicate(&mut self, new_predicate: PredicateKey) {
        self.checkpoint_predicate = new_predicate;
    }

    /// Updates the verified checkpoint tip after successful verification.
    fn update_verified_tip(&mut self, new_tip: CheckpointTip) {
        self.verified_tip = new_tip
    }

    /// Records a processed deposit, incrementing the available UTXO count.
    pub fn record_deposit(&mut self, amount: BitcoinAmount) {
        self.deposits.record(amount);
    }

    /// Advances the verified tip to `payload.new_tip` after verifying the ZK proof against
    /// the precomputed ASM manifests hash and extracting withdrawal intents. On success,
    /// deducts the withdrawn funds and returns the extracted withdrawal intents for the
    /// caller to relay.
    pub fn advance(
        &mut self,
        payload: &CheckpointPayload,
        asm_manifests_hash: AsmManifestRangeHash,
    ) -> CheckpointValidationResult<Vec<WithdrawOutput>> {
        let withdrawal_intents = extract_withdrawal_intents(payload.sidecar().ol_logs())?;

        let token = self.deposits.verify_withdrawals(&withdrawal_intents)?;
        verify_proof(self, payload, asm_manifests_hash)?;

        self.deposits.apply_withdrawals(token);
        self.update_verified_tip(payload.new_tip);

        Ok(withdrawal_intents)
    }
}
