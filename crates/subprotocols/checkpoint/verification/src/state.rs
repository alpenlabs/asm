use strata_asm_bridge_types::WithdrawalIntent;
use strata_asm_checkpoint_types::{
    CheckpointInitConfig, CheckpointPayload, CheckpointTip, PendingPredicateTransition,
};
use strata_asm_manifest_types::AsmManifestRangeHash;
use strata_btc_types::BitcoinAmount;
use strata_identifiers::L2BlockCommitment;
use strata_predicate::PredicateKey;

use crate::{
    CheckpointState, DepositPool,
    errors::{CheckpointValidationResult, InvalidCheckpointPayload},
    verification::{CheckpointL1Range, extract_withdrawal_intents, verify_proof},
};

/// Which key verifies a checkpoint, and where it came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PredicateSelection {
    /// The currently active predicate.
    Active,
    /// The enacted transition awaiting activation.
    Pending,
}

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
            pending_transition: Default::default(),
            verified_tip,
            deposits: DepositPool::default(),
        }
    }

    /// Returns the sequencer predicate for signature verification.
    pub fn sequencer_predicate(&self) -> &PredicateKey {
        &self.sequencer_predicate
    }

    /// Returns the active checkpoint predicate for proof verification.
    pub fn checkpoint_predicate(&self) -> &PredicateKey {
        &self.checkpoint_predicate
    }

    /// Returns the enacted predicate transition awaiting checkpoint-sequence activation.
    pub fn pending_transition(&self) -> Option<&PendingPredicateTransition> {
        self.pending_transition.first()
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

    /// Selects the predicate governing `territory`, an L1 height whose inputs the
    /// checkpoint claims to have processed.
    ///
    /// A transition's `boundary` is the last height governed by the preceding predicate,
    /// so the pending key governs exactly `boundary + 1` and up.
    fn governing(&self, territory: u32) -> PredicateSelection {
        match self.pending_transition() {
            Some(transition) if transition.boundary() < territory => PredicateSelection::Pending,
            _ => PredicateSelection::Active,
        }
    }

    /// Selects the checkpoint predicate governed by the claimed L1 coverage.
    pub fn select_predicate(
        &self,
        coverage: &CheckpointL1Range,
    ) -> CheckpointValidationResult<PredicateSelection> {
        let (start_height, end_height) = match *coverage {
            // An empty range processes no new L1 inputs, so the territory it would claim
            // next decides: the first height the verified tip has not already covered.
            CheckpointL1Range::Empty => {
                return Ok(match self.verified_tip.l1_height().checked_add(1) {
                    Some(first_uncovered) => self.governing(first_uncovered),
                    // The tip sits at the top of the L1 height domain, so there is no
                    // uncovered height left and every boundary is behind it.
                    None if self.pending_transition().is_some() => PredicateSelection::Pending,
                    None => PredicateSelection::Active,
                });
            }
            CheckpointL1Range::Range {
                start_height,
                end_height,
            } => (start_height, end_height),
        };

        let start_selection = self.governing(start_height);
        if start_selection != self.governing(end_height) {
            let boundary = self
                .pending_transition()
                .map(PendingPredicateTransition::boundary)
                .expect("differing selections imply a pending transition inside the range");
            return Err(InvalidCheckpointPayload::RangeStraddlesPredicateBoundary {
                start: start_height,
                end: end_height,
                boundary,
            }
            .into());
        }

        Ok(start_selection)
    }

    /// Returns the predicate selected for checkpoint proof verification.
    pub fn predicate_for(&self, selection: PredicateSelection) -> &PredicateKey {
        match selection {
            PredicateSelection::Active => &self.checkpoint_predicate,
            PredicateSelection::Pending => self
                .pending_transition()
                .expect("pending selection implies a pending transition")
                .predicate(),
        }
    }

    /// Records an enacted checkpoint predicate transition.
    ///
    /// Administration refuses to authorize a rotation while another is queued or awaiting
    /// activation, so the slot is always free when an enactment arrives.
    pub fn queue_predicate_transition(&mut self, transition: PendingPredicateTransition) {
        self.pending_transition
            .push(transition)
            .expect("at most one OL predicate rotation is outstanding at a time");
    }

    /// Promotes the pending transition if it verified this checkpoint.
    ///
    /// Returns whether a transition was promoted.
    pub fn promote(&mut self, selection: PredicateSelection) -> bool {
        if selection != PredicateSelection::Pending {
            return false;
        }

        let transition = self
            .pending_transition()
            .expect("pending selection implies a pending transition");
        self.checkpoint_predicate = transition.predicate().clone();
        self.pending_transition = Default::default();
        true
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
    /// deducts the withdrawn funds, promotes the selected predicate, and returns the extracted
    /// withdrawal intents plus whether a pending transition was promoted.
    ///
    /// `selection` comes from [`Self::select_predicate`], which the caller runs against the
    /// coverage before resolving ASM manifests: a range that straddles the boundary is
    /// rejected there, so no manifest work is spent on a checkpoint that cannot be accepted.
    pub fn advance(
        &mut self,
        payload: &CheckpointPayload,
        asm_manifests_hash: AsmManifestRangeHash,
        selection: PredicateSelection,
    ) -> CheckpointValidationResult<(Vec<WithdrawalIntent>, bool)> {
        let withdrawal_intents = extract_withdrawal_intents(payload.sidecar().ol_logs())?;

        let token = self.deposits.verify_withdrawals(&withdrawal_intents)?;
        verify_proof(
            self.predicate_for(selection),
            &self.verified_tip,
            payload,
            asm_manifests_hash,
        )?;

        self.deposits.apply_withdrawals(token);
        self.update_verified_tip(payload.new_tip);
        let promoted = self.promote(selection);

        Ok((withdrawal_intents, promoted))
    }
}
