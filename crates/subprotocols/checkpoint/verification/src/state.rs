use strata_asm_bridge_types::WithdrawalIntent;
use strata_asm_checkpoint_types::{
    CheckpointInitConfig, CheckpointPayload, CheckpointTip, MAX_PENDING_PREDICATE_TRANSITIONS,
    PendingPredicateTransition, PendingTransitionCount,
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
    /// The enacted transition at the selected pending-queue index.
    Pending(usize),
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
            pending_transitions: Default::default(),
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

    /// Returns the ordered enacted predicate transitions awaiting checkpoint promotion.
    pub fn pending_transitions(&self) -> &[PendingPredicateTransition] {
        &self.pending_transitions
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
    /// A transition's `boundary` is the last height governed by the preceding predicate.
    /// The transition at index `i` therefore governs after its boundary through the next
    /// transition's boundary, if any.
    fn governing(&self, territory: u32) -> PredicateSelection {
        let successor_count = self
            .pending_transitions()
            .partition_point(|transition| transition.boundary() < territory);
        match successor_count.checked_sub(1) {
            Some(index) => PredicateSelection::Pending(index),
            None => PredicateSelection::Active,
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
                    None if !self.pending_transitions().is_empty() => {
                        PredicateSelection::Pending(self.pending_transitions().len() - 1)
                    }
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
                .pending_transitions()
                .iter()
                .find(|transition| {
                    start_height <= transition.boundary() && transition.boundary() < end_height
                })
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
            PredicateSelection::Pending(index) => self.pending_transitions[index].predicate(),
        }
    }

    /// Records an enacted checkpoint predicate transition.
    ///
    /// Boundaries arrive in nondecreasing enactment order. A later update enacted at the same
    /// boundary replaces the prior entry, so the latest `UpdateId` governs the following
    /// territory without growing the queue.
    pub fn queue_predicate_transition(&mut self, transition: PendingPredicateTransition) {
        if let Some(last) = self.pending_transitions.last_mut() {
            assert!(
                transition.boundary() >= last.boundary(),
                "checkpoint predicate transitions must arrive in boundary order"
            );
            if transition.boundary() == last.boundary() {
                *last = transition;
                return;
            }
        }

        self.pending_transitions
            .push(transition)
            .unwrap_or_else(|_| {
                panic!(
                    "administration must cap distinct pending transitions at \
                 {MAX_PENDING_PREDICATE_TRANSITIONS}"
                )
            });
    }

    /// Promotes the selected pending transition if it verified this checkpoint.
    ///
    /// Returns the number of transitions pruned through the promoted entry.
    pub fn promote(&mut self, selection: PredicateSelection) -> PendingTransitionCount {
        let PredicateSelection::Pending(index) = selection else {
            return 0;
        };

        self.checkpoint_predicate = self.pending_transitions[index].predicate().clone();
        let pruned = PendingTransitionCount::try_from(index + 1)
            .expect("pending transition capacity fits the acknowledgement count type");
        self.pending_transitions = self.pending_transitions[index + 1..]
            .to_vec()
            .try_into()
            .expect("pruning cannot exceed the pending transition capacity");
        pruned
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
    /// withdrawal intents plus the number of pending transitions pruned by promotion.
    ///
    /// `selection` comes from [`Self::select_predicate`], which the caller runs against the
    /// coverage before resolving ASM manifests: a range that straddles the boundary is
    /// rejected there, so no manifest work is spent on a checkpoint that cannot be accepted.
    pub fn advance(
        &mut self,
        payload: &CheckpointPayload,
        asm_manifests_hash: AsmManifestRangeHash,
        selection: PredicateSelection,
    ) -> CheckpointValidationResult<(Vec<WithdrawalIntent>, PendingTransitionCount)> {
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
        let pruned = self.promote(selection);

        Ok((withdrawal_intents, pruned))
    }
}
