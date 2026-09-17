use strata_asm_bridge_types::WithdrawalIntent;
use strata_asm_checkpoint_types::{
    CheckpointInitConfig, CheckpointPayload, CheckpointTip, PendingPredicateTransition,
};
use strata_asm_manifest_types::AsmManifestRangeHash;
use strata_btc_types::BitcoinAmount;
use strata_identifiers::{Buf32, L2BlockCommitment};
use strata_predicate::PredicateKey;
use zkaleido_logging as logging;

use crate::{
    CheckpointState, DepositPool, MAX_PENDING_PREDICATE_TRANSITIONS,
    errors::{CheckpointValidationResult, InvalidCheckpointPayload},
    verification::{CheckpointL1Range, extract_withdrawal_intents, verify_proof},
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
            config.sequencer_key,
            config.checkpoint_predicate,
            genesis_tip,
        )
    }

    /// Creates a new checkpoint state with the given sequencer key, predicate, and tip.
    pub(crate) fn new(
        sequencer_key: Buf32,
        checkpoint_predicate: PredicateKey,
        verified_tip: CheckpointTip,
    ) -> Self {
        Self {
            sequencer_key,
            checkpoint_predicate,
            pending_transition: Default::default(),
            verified_tip,
            deposits: DepositPool::default(),
        }
    }

    /// Returns the sequencer key that must sign the checkpoint envelope.
    pub fn sequencer_key(&self) -> &Buf32 {
        &self.sequencer_key
    }

    /// Returns the active checkpoint predicate for proof verification.
    pub fn checkpoint_predicate(&self) -> &PredicateKey {
        &self.checkpoint_predicate
    }

    /// Returns the transition that activates next, if any.
    ///
    /// Boundaries are strictly increasing, so this is the front of the queue and the only
    /// boundary a checkpoint's coverage can run into.
    pub fn next_transition(&self) -> Option<&PendingPredicateTransition> {
        self.pending_transition.first()
    }

    /// Returns the enacted predicate transitions awaiting activation, ordered by boundary.
    pub fn pending_transitions(&self) -> &[PendingPredicateTransition] {
        &self.pending_transition
    }

    /// Returns the last verified checkpoint tip.
    pub fn verified_tip(&self) -> &CheckpointTip {
        &self.verified_tip
    }

    /// Returns the total available deposit value, in satoshis.
    pub fn available_deposit_sum(&self) -> u64 {
        self.deposits.total().to_sat()
    }

    /// Update the sequencer key with a new Schnorr public key.
    pub fn update_sequencer_key(&mut self, new_key: Buf32) {
        self.sequencer_key = new_key
    }

    /// Rejects a coverage range that crosses the next predicate boundary.
    ///
    /// Every queued transition has a boundary strictly above the verified tip (see
    /// `pending_transition`), so a range always starts inside the active predicate's
    /// territory. It must also end there: a range reaching past the next boundary would
    /// claim heights the active key does not govern.
    pub fn verify_coverage_boundary(
        &self,
        coverage: &CheckpointL1Range,
    ) -> CheckpointValidationResult<()> {
        // An empty range claims no new L1 heights, so it cannot cross a boundary.
        let CheckpointL1Range::Range {
            start_height,
            end_height,
        } = *coverage
        else {
            return Ok(());
        };

        if let Some(next) = self.next_transition()
            && next.boundary() < end_height
        {
            return Err(InvalidCheckpointPayload::RangeStraddlesPredicateBoundary {
                start: start_height,
                end: end_height,
                boundary: next.boundary(),
            }
            .into());
        }

        Ok(())
    }

    /// Records an enacted checkpoint predicate transition.
    ///
    /// An enactment cannot be refused: its `CheckpointPredicateEnacted` log is already in the
    /// manifest of the block being processed. So a full queue drops its oldest entry, whose
    /// key then never activates. That is the newest-intent-wins reading of a situation that
    /// needs [`MAX_PENDING_PREDICATE_TRANSITIONS`] rotations with no checkpoint in between.
    ///
    /// # Panics
    ///
    /// Panics if `transition` does not sit strictly after the last queued boundary.
    /// Administration accepts at most one rotation per block and applies a fixed confirmation
    /// depth, so enactment heights are strictly increasing.
    pub fn queue_predicate_transition(&mut self, transition: PendingPredicateTransition) {
        if let Some(last) = self.pending_transition.last() {
            assert!(
                last.boundary() < transition.boundary(),
                "predicate transition boundaries must strictly increase: {} follows {}",
                transition.boundary(),
                last.boundary()
            );
        }

        if self.pending_transition.len()
            == usize::try_from(MAX_PENDING_PREDICATE_TRANSITIONS)
                .expect("the queue capacity fits in a usize")
        {
            let mut queue: Vec<_> = self.pending_transition.to_vec();
            let evicted = queue.remove(0);
            logging::warn!(
                boundary = evicted.boundary(),
                predicate = evicted.predicate().id(),
                "pending predicate transition queue is full, dropping the oldest rotation"
            );
            self.pending_transition = queue
                .try_into()
                .expect("a shrunk queue still fits the original capacity");
        }

        self.pending_transition
            .push(transition)
            .expect("the queue has room after eviction");
    }

    /// Activates every transition whose boundary the verified tip has now reached.
    ///
    /// A transition governs the heights strictly after its boundary, so once the tip sits at
    /// or past that boundary the successor key governs every height a future checkpoint can
    /// claim. Promoting here — rather than when a checkpoint first verifies under the
    /// successor key — keeps the invariant that the active predicate governs `verified_tip +
    /// 1`, which is what makes key selection a non-choice.
    /// Returns whether any transition was promoted.
    fn promote_elapsed_transitions(&mut self) -> bool {
        let tip_height = self.verified_tip.l1_height();
        let elapsed = self
            .pending_transition
            .iter()
            .take_while(|transition| transition.boundary() <= tip_height)
            .count();
        if elapsed == 0 {
            return false;
        }

        // Boundaries are strictly increasing, so the last elapsed transition is the one
        // that ends up active; the earlier ones governed territory this tip has already
        // passed through under a key that was itself superseded.
        let mut remaining: Vec<_> = self.pending_transition.to_vec();
        let activated = remaining
            .drain(..elapsed)
            .next_back()
            .expect("a non-zero elapsed count yields at least one transition");
        self.checkpoint_predicate = activated.predicate().clone();
        self.pending_transition = remaining
            .try_into()
            .expect("a shrunk queue still fits the original capacity");
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
    /// deducts the withdrawn funds, activates any transition the new tip has reached, and
    /// returns the extracted withdrawal intents plus whether a transition was promoted.
    ///
    /// The proof is always verified under the active predicate. The caller must first run
    /// [`Self::verify_coverage_boundary`] against the coverage — before resolving ASM
    /// manifests, so no manifest work is spent on a checkpoint that cannot be accepted —
    /// which is what establishes that the active predicate governs the whole range.
    pub fn advance(
        &mut self,
        payload: &CheckpointPayload,
        asm_manifests_hash: AsmManifestRangeHash,
    ) -> CheckpointValidationResult<(Vec<WithdrawalIntent>, bool)> {
        let withdrawal_intents = extract_withdrawal_intents(payload.sidecar().ol_logs())?;

        let token = self.deposits.verify_withdrawals(&withdrawal_intents)?;
        verify_proof(
            &self.checkpoint_predicate,
            &self.verified_tip,
            payload,
            asm_manifests_hash,
        )?;

        self.deposits.apply_withdrawals(token);
        self.update_verified_tip(payload.new_tip);
        let promoted = self.promote_elapsed_transitions();

        Ok((withdrawal_intents, promoted))
    }
}
