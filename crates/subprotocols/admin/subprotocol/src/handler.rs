use strata_asm_admin_types::Role;
use strata_asm_bridge_types::SafeHarbourAddress;
use strata_asm_checkpoint_types::PendingPredicateTransition;
use strata_asm_common::{
    AsmLogEntry, MsgRelayer,
    logging::{debug, error, info},
};
use strata_asm_logs::{AsmStfUpdate, CheckpointPredicateEnacted, EePredicateKeyUpdate};
use strata_asm_proto_admin_txs::{
    actions::{MultisigAction, UpdateAction},
    parser::SignedPayload,
};
use strata_asm_proto_bridge_msgs::{BridgeIncomingMsg, DefconPayload, UpdateOperatorSetPayload};
use strata_asm_proto_checkpoint_msgs::CheckpointIncomingMsg;
use strata_identifiers::{AccountSerial, Buf32, L1Height, SYSTEM_RESERVED_ACCTS};
use strata_predicate::{PredicateKey, PredicateTypeId};

use crate::{
    error::AdministrationError, queued_update::QueuedUpdate, state::AdministrationSubprotoState,
};

/// Per-block guard for the one authoritative ASM predicate handover.
///
/// This is execution context, not consensus state. Replaying a block reconstructs it from
/// `false`, and both queued enactments and incoming transactions share the same instance.
#[derive(Debug, Default)]
pub(crate) struct AsmEmissionGuard {
    emitted: bool,
}

/// Processes and applies all queued updates that are ready to be enacted at the current height.
///
/// This function retrieves all update actions from the queue that are ready to be applied
/// and processes them sequentially. If an error occurs during the execution of any update,
/// an error log is emitted and processing continues with the next queued update.
///
/// This function should not return an error - it handles all errors internally by logging
/// them and continuing with the next update to ensure system resilience.
pub(crate) fn handle_pending_updates(
    state: &mut AdministrationSubprotoState,
    relayer: &mut impl MsgRelayer,
    current_height: L1Height,
    asm_guard: &mut AsmEmissionGuard,
) {
    // Get all the update actions that are ready to be enacted, in queue order. The queue
    // preserves insertion order across cancellations, so this drain is deterministic.
    let queued_updates = state.process_queued(current_height);
    if queued_updates.is_empty() {
        return;
    }

    debug!(
        count = queued_updates.len(),
        %current_height,
        "enacting queued admin updates that reached activation height"
    );
    for queued in queued_updates {
        let (update_id, action) = queued.into_id_and_action();
        let tx_type = action.update_tx_type();
        let role = action.required_role();
        match handle_update(state, relayer, action, current_height, asm_guard) {
            Ok(()) => info!(%update_id, %tx_type, %role, "enacted queued admin update"),
            Err(e) => {
                error!(%update_id, %tx_type, %role, error = %e, "failed to enact queued admin update")
            }
        }
    }
}

/// Processes a multisig action (an admin "change" message) by validating the signature set
/// and executing the requested operation.
///
/// This function handles the complete lifecycle of a multisig action:
/// 1. Determines the required role based on the action type
/// 2. Validates that the signature set meets the threshold requirements for that role
/// 3. Processes the action based on its type:
///    - `Update`: Queues the action for later execution, or applies it immediately if the
///      configured confirmation depth for that update variant is zero
///    - `Cancel`: Removes a previously queued action from the queue
/// 4. Increments the authority's sequence number to prevent replay attacks
///
/// # Returns
/// * `Ok(())` if the action was successfully processed
/// * `Err(AdministrationError)` if validation failed or the action could not be processed
pub(crate) fn handle_action(
    state: &mut AdministrationSubprotoState,
    payload: SignedPayload,
    current_height: L1Height,
    relayer: &mut impl MsgRelayer,
    asm_guard: &mut AsmEmissionGuard,
) -> Result<(), AdministrationError> {
    // Determine the required role; both update and cancel actions are self-describing.
    let role = state.resolve_action_role(&payload.action);

    // Get the authority for this role and validate the action with the aggregated signature
    let authority = state
        .authority(role)
        .ok_or(AdministrationError::UnknownRole)?;
    let seqno_token = authority.verify_action_signature(&payload, state.max_seqno_gap())?;

    // Process the action based on its type
    match payload.action {
        MultisigAction::Update(update) => {
            // Generate a unique ID for this update
            let id = state.next_update_id();
            let tx_type = update.update_tx_type();
            let activation_height = match state.confirmation_depth(tx_type) {
                Some(delay) => Some(current_height.checked_add(u32::from(delay)).ok_or(
                    AdministrationError::ActivationHeightOverflow {
                        current_height,
                        delay,
                    },
                )?),
                None => None,
            };

            // At most one OL predicate rotation may be outstanding. Rejecting the second here
            // — rather than deferring its enactment later — keeps the exit window that the
            // first rotation's boundary fixed meaningful: a rotation that is authorized is a
            // rotation that will enact at exactly `current_height + delay`.
            if matches!(update, UpdateAction::OlStfVk(_))
                && state.has_outstanding_ol_stf_vk_update()
            {
                return Err(AdministrationError::OlStfVkUpdateAlreadyOutstanding);
            }
            // A block hands over exactly one ASM predicate. Delayed rotations conflict only
            // when they target the same activation height; rotations scheduled for distinct
            // blocks are independently representable. A zero-depth update emits now, so it
            // uses the shared block-local guard.
            if matches!(update, UpdateAction::AsmStfVk(_)) {
                match activation_height {
                    Some(height) if state.has_asm_stf_vk_update_at(height) => {
                        return Err(AdministrationError::AsmStfVkUpdateAlreadyScheduled {
                            activation_height: height,
                        });
                    }
                    None if asm_guard.emitted => {
                        return Err(AdministrationError::AsmStfVkUpdateAlreadyEmitted);
                    }
                    Some(_) | None => {}
                }
            }

            // Updates with a non-zero confirmation depth are queued and enacted only after
            // `delay` more L1 blocks; until then they remain cancellable. A depth of zero
            // (surfaced as `None`) means "apply immediately" and bypasses the queue.
            match activation_height {
                Some(activation_height) => {
                    let delay = state
                        .confirmation_depth(tx_type)
                        .expect("an activation height exists only for a non-zero delay");
                    let queued_update = QueuedUpdate::new(id, update, activation_height);
                    state.enqueue(queued_update);
                    info!(
                        update_id = %id,
                        %tx_type,
                        %role,
                        %activation_height,
                        delay,
                        "queued admin update for delayed enactment"
                    );
                }
                None => {
                    info!(
                        update_id = %id,
                        %tx_type,
                        %role,
                        "applying admin update immediately (zero confirmation depth)"
                    );
                    if let Err(e) = handle_update(state, relayer, update, current_height, asm_guard)
                    {
                        error!(update_id = %id, %tx_type, %role, error = %e, "failed to apply admin update");
                    }
                }
            }

            // Increment the update ID counter for the next action
            state.increment_next_update_id();
        }
        MultisigAction::Cancel(cancel) => {
            // The signature already covers the embedded update, so this equality check is
            // belt-and-suspenders: turn what would otherwise be a generic verification
            // failure into a precise, actionable error.
            let queued = state
                .find_queued(cancel.target_id())
                .ok_or(AdministrationError::UnknownAction(*cancel.target_id()))?;
            if queued.action() != cancel.update() {
                return Err(AdministrationError::CancelUpdateMismatch {
                    target_id: *cancel.target_id(),
                });
            }
            state.remove_queued(cancel.target_id());
            info!(target_id = %cancel.target_id(), %role, "cancelled queued admin update");
        }
    }

    // Advance the sequence number using the verified token to prevent replay attacks
    let authority = state
        .authority_mut(role)
        .ok_or(AdministrationError::UnknownRole)?;
    authority.update_last_seqno(seqno_token);

    Ok(())
}

/// Applies a single update action by performing its side effects on `state` and `relayer`.
///
/// Shared by both apply paths: the queue-drain in [`handle_pending_updates`] and the
/// immediate-apply branch in [`handle_action`] for updates whose confirmation depth is
/// zero. Only multisig config updates can fail.
fn handle_update(
    state: &mut AdministrationSubprotoState,
    relayer: &mut impl MsgRelayer,
    update: UpdateAction,
    current_height: L1Height,
    asm_guard: &mut AsmEmissionGuard,
) -> Result<(), AdministrationError> {
    match update {
        UpdateAction::StrataAdminMultisig(update) => {
            state.apply_multisig_update(Role::StrataAdministrator, update.config())?;
        }
        UpdateAction::StrataSeqManagerMultisig(update) => {
            state.apply_multisig_update(Role::StrataSequencerManager, update.config())?;
        }
        UpdateAction::AlpenAdminMultisig(update) => {
            state.apply_multisig_update(Role::AlpenAdministrator, update.config())?;
        }
        UpdateAction::StrataSecurityCouncilMultisig(update) => {
            state.apply_multisig_update(Role::StrataSecurityCouncil, update.config())?;
        }
        UpdateAction::OperatorSet(update) => {
            let (add_members, remove_members) = update.into_inner();
            relay_bridge_operator_set_update(relayer, add_members, remove_members);
        }
        UpdateAction::Sequencer(update) => {
            let new_key = update.into_inner();
            relay_checkpoint_sequencer_update(relayer, new_key);
        }
        UpdateAction::OlStfVk(update) => {
            enact_checkpoint_predicate_transition(
                state,
                relayer,
                update.into_key(),
                current_height,
            );
        }
        UpdateAction::AsmStfVk(update) => {
            if asm_guard.emitted {
                return Err(AdministrationError::AsmStfVkUpdateAlreadyEmitted);
            }
            let key = update.into_key();
            debug!(?key, "new ASM STF verifying key");
            let log_entry = AsmLogEntry::from_log(&AsmStfUpdate::new(key))
                .expect("AsmStfUpdate encoding is infallible");
            relayer.emit_log(log_entry);
            asm_guard.emitted = true;
            info!("emitted ASM STF verifying key update log");
        }
        UpdateAction::EeStfVk(update) => {
            relay_alpen_predicate_update(relayer, update.into_key());
        }
        UpdateAction::Defcon1(_) | UpdateAction::Defcon3(_) => relay_bridge_defcon(relayer),
        UpdateAction::SafeHarbourAddress(update) => {
            relay_bridge_safe_harbour_address_update(relayer, update.into_inner());
        }
    }

    Ok(())
}

fn relay_alpen_predicate_update(relayer: &mut impl MsgRelayer, key: PredicateKey) {
    // Alpen is the first account on the OL, so its serial is the first
    // non-reserved account index.
    const ALPEN_EE_ACCOUNT_SERIAL: AccountSerial = AccountSerial::new(SYSTEM_RESERVED_ACCTS);
    debug!(?key, "new EE predicate key");
    let log_entry = AsmLogEntry::from_log(&EePredicateKeyUpdate::new(ALPEN_EE_ACCOUNT_SERIAL, key))
        .expect("EePredicateKeyUpdate encoding is infallible");
    relayer.emit_log(log_entry);
    info!(%ALPEN_EE_ACCOUNT_SERIAL, "emitted EE predicate key update log");
}

fn relay_checkpoint_sequencer_update(relayer: &mut impl MsgRelayer, new_key: Buf32) {
    let predicate = PredicateKey::try_new(PredicateTypeId::Bip340Schnorr, new_key.0.to_vec())
        .expect("a 32-byte sequencer key is within the predicate condition limit");
    let msg = CheckpointIncomingMsg::UpdateSequencerKey(predicate);
    relayer.relay_msg(&msg);
    debug!(?new_key, "new sequencer key");
    info!("forwarded sequencer key update to checkpoint subprotocol");
}

/// Enacts an OL predicate rotation at `current_height`, the boundary `B`.
///
/// Infallible by construction: [`handle_action`] refuses to authorize a rotation while
/// another is queued or awaiting activation, so checkpoint's single pending-transition slot
/// is always free here. That matters because the announcement cannot be retracted — the
/// enactment log rides in this block's manifest, and a rotation the checkpoint subprotocol
/// failed to record would switch the OL onto rules the ASM holds no key for.
fn enact_checkpoint_predicate_transition(
    state: &mut AdministrationSubprotoState,
    relayer: &mut impl MsgRelayer,
    predicate: PredicateKey,
    current_height: L1Height,
) {
    debug!(?predicate, boundary = %current_height, "enacting checkpoint predicate transition");
    state.set_ol_transition_pending();
    let transition = PendingPredicateTransition::new(predicate.clone(), current_height);
    let msg = CheckpointIncomingMsg::QueueCheckpointPredicateTransition(transition);
    relayer.relay_msg(&msg);
    let log_entry = AsmLogEntry::from_log(&CheckpointPredicateEnacted::new(predicate))
        .expect("CheckpointPredicateEnacted encoding is infallible");
    relayer.emit_log(log_entry);
    info!("queued rollup verifying key transition and emitted enactment log");
}

fn relay_bridge_operator_set_update(
    relayer: &mut impl MsgRelayer,
    add_members: Vec<strata_crypto::EvenPublicKey>,
    remove_members: Vec<u32>,
) {
    debug!(?add_members, ?remove_members, "bridge operator set update");
    let msg = BridgeIncomingMsg::UpdateOperatorSet(UpdateOperatorSetPayload {
        add_members,
        remove_members,
    });
    relayer.relay_msg(&msg);
    info!("forwarded operator set update to bridge subprotocol");
}

fn relay_bridge_defcon(relayer: &mut impl MsgRelayer) {
    relayer.relay_msg(&BridgeIncomingMsg::Defcon(DefconPayload::default()));
    info!("forwarded Defcon signal to bridge subprotocol");
}

fn relay_bridge_safe_harbour_address_update(
    relayer: &mut impl MsgRelayer,
    address: SafeHarbourAddress,
) {
    debug!(?address, "new safe harbour address");
    relayer.relay_msg(&BridgeIncomingMsg::UpdateSafeHarbourAddress(address));
    info!("forwarded safe harbour address update to bridge subprotocol");
}

#[cfg(test)]
mod tests {
    use std::{any::Any, num::NonZero};

    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
    use rand::{rngs::OsRng, seq::SliceRandom, thread_rng};
    use strata_asm_admin_types::{AdministrationInitConfig, ConfirmationDepths, Role};
    use strata_asm_bridge_types::SafeHarbourAddress;
    use strata_asm_common::{AsmLogEntry, InterprotoMsg, MsgRelayer, Subprotocol};
    use strata_asm_logs::{AsmStfUpdate, CheckpointPredicateEnacted};
    use strata_asm_proto_admin_msgs::AdministrationIncomingMsg;
    use strata_asm_proto_admin_txs::{
        actions::{
            CancelAction, MultisigAction, UpdateAction,
            updates::{
                AsmStfVkUpdate, Defcon1Update, Defcon3Update, OlStfVkUpdate,
                SafeHarbourAddressUpdate, SequencerUpdate,
            },
        },
        parser::SignedPayload,
        test_utils::create_signature_set,
    };
    use strata_asm_proto_bridge_msgs::BridgeIncomingMsg;
    use strata_asm_proto_checkpoint_msgs::CheckpointIncomingMsg;
    use strata_crypto::{
        keys::compressed::CompressedPublicKey, threshold_signature::ThresholdConfig,
    };
    use strata_identifiers::{Buf32, L1BlockCommitment, L1Height};
    use strata_predicate::{PredicateKey, PredicateTypeId};
    use strata_test_utils_arb::ArbitraryGenerator;

    use super::{
        AsmEmissionGuard, handle_action as handle_action_in_block,
        handle_pending_updates as handle_pending_updates_in_block,
    };
    use crate::{
        error::AdministrationError, queued_update::QueuedUpdate,
        state::AdministrationSubprotoState, subprotocol::AdministrationSubprotocol,
    };

    /// Most unit tests exercise one administration operation in isolation. Full-block guard
    /// behavior has dedicated tests below, so these wrappers give isolated calls a fresh block.
    fn handle_action(
        state: &mut AdministrationSubprotoState,
        payload: SignedPayload,
        current_height: L1Height,
        relayer: &mut impl MsgRelayer,
    ) -> Result<(), AdministrationError> {
        handle_action_in_block(
            state,
            payload,
            current_height,
            relayer,
            &mut AsmEmissionGuard::default(),
        )
    }

    fn handle_pending_updates(
        state: &mut AdministrationSubprotoState,
        relayer: &mut impl MsgRelayer,
        current_height: L1Height,
    ) {
        handle_pending_updates_in_block(
            state,
            relayer,
            current_height,
            &mut AsmEmissionGuard::default(),
        );
    }

    struct MockRelayer<M> {
        logs: Vec<AsmLogEntry>,
        messages: Vec<M>,
    }

    impl<M> MockRelayer<M> {
        fn new() -> Self {
            Self {
                logs: Vec::new(),
                messages: Vec::new(),
            }
        }

        fn messages(&self) -> &[M] {
            &self.messages
        }
    }

    impl<M> MsgRelayer for MockRelayer<M>
    where
        M: InterprotoMsg + Clone + 'static,
    {
        fn relay_msg(&mut self, m: &dyn InterprotoMsg) {
            if let Some(msg) = m.as_dyn_any().downcast_ref::<M>() {
                self.messages.push(msg.clone());
            }
        }

        fn emit_log(&mut self, log: AsmLogEntry) {
            self.logs.push(log);
        }

        fn as_mut_any(&mut self) -> &mut dyn Any {
            self
        }
    }

    fn create_test_params() -> (
        AdministrationInitConfig,
        Vec<SecretKey>,
        Vec<SecretKey>,
        Vec<SecretKey>,
    ) {
        let secp = Secp256k1::new();

        let strata_admin_sks: Vec<SecretKey> = (0..3).map(|_| SecretKey::new(&mut OsRng)).collect();
        let strata_admin_pks: Vec<CompressedPublicKey> = strata_admin_sks
            .iter()
            .map(|sk| CompressedPublicKey::from(PublicKey::from_secret_key(&secp, sk)))
            .collect();
        let strata_administrator =
            ThresholdConfig::try_new(strata_admin_pks, NonZero::new(2).unwrap()).unwrap();

        let strata_seq_manager_sks: Vec<SecretKey> =
            (0..3).map(|_| SecretKey::new(&mut OsRng)).collect();
        let strata_seq_manager_pks: Vec<CompressedPublicKey> = strata_seq_manager_sks
            .iter()
            .map(|sk| CompressedPublicKey::from(PublicKey::from_secret_key(&secp, sk)))
            .collect();
        let strata_sequencer_manager =
            ThresholdConfig::try_new(strata_seq_manager_pks, NonZero::new(2).unwrap()).unwrap();

        let alpen_admin_sks: Vec<SecretKey> = (0..3).map(|_| SecretKey::new(&mut OsRng)).collect();
        let alpen_admin_pks: Vec<CompressedPublicKey> = alpen_admin_sks
            .iter()
            .map(|sk| CompressedPublicKey::from(PublicKey::from_secret_key(&secp, sk)))
            .collect();
        let alpen_administrator =
            ThresholdConfig::try_new(alpen_admin_pks, NonZero::new(2).unwrap()).unwrap();

        let strata_security_council_sks: Vec<SecretKey> =
            (0..3).map(|_| SecretKey::new(&mut OsRng)).collect();
        let strata_security_council_pks: Vec<CompressedPublicKey> = strata_security_council_sks
            .iter()
            .map(|sk| CompressedPublicKey::from(PublicKey::from_secret_key(&secp, sk)))
            .collect();
        let strata_security_council =
            ThresholdConfig::try_new(strata_security_council_pks, NonZero::new(2).unwrap())
                .unwrap();

        let config = AdministrationInitConfig {
            strata_administrator,
            strata_sequencer_manager,
            alpen_administrator,
            strata_security_council,
            confirmation_depths: uniform_confirmation_depths(2016),
            max_seqno_gap: 10.try_into().unwrap(),
        };

        (
            config,
            strata_admin_sks,
            strata_seq_manager_sks,
            strata_security_council_sks,
        )
    }

    fn uniform_confirmation_depths(depth: u16) -> ConfirmationDepths {
        ConfirmationDepths {
            strata_admin_multisig_update: depth,
            strata_seq_manager_multisig_update: depth,
            alpen_admin_multisig_update: depth,
            strata_security_council_multisig_update: depth,
            operator_update: depth,
            sequencer_update: depth,
            ol_stf_vk_update: depth,
            asm_stf_vk_update: depth,
            ee_stf_vk_update: depth,
            defcon3: depth,
            safe_harbour_address_update: depth,
        }
    }

    /// Draws `count` random updates authorized by the Strata administrator.
    ///
    /// Yields at most one `OlStfVk` and one `AsmStfVk` action. These callers submit every
    /// generated action at the same height: a second OL rotation would violate its global pending
    /// slot, while a second ASM rotation would target the same handover block. Both rules have
    /// dedicated tests; these callers are about generic queueing.
    fn get_strata_administrator_update_actions(count: usize) -> Vec<UpdateAction> {
        let mut arb = ArbitraryGenerator::new();
        let mut actions = Vec::new();
        let mut drew_ol_rotation = false;
        let mut drew_asm_rotation = false;

        while actions.len() < count {
            let action: UpdateAction = arb.generate();
            if action.required_role() != Role::StrataAdministrator {
                continue;
            }
            if matches!(action, UpdateAction::OlStfVk(_)) {
                if drew_ol_rotation {
                    continue;
                }
                drew_ol_rotation = true;
            }
            if matches!(action, UpdateAction::AsmStfVk(_)) {
                if drew_asm_rotation {
                    continue;
                }
                drew_asm_rotation = true;
            }
            actions.push(action);
        }
        actions
    }

    fn test_predicate(tag: u8) -> PredicateKey {
        PredicateKey::try_new(PredicateTypeId::Sp1Groth16, vec![tag])
            .expect("test predicate is within the condition limit")
    }

    /// Signs and submits an `OlStfVk` rotation as the Strata administrator.
    fn authorize_ol_rotation(
        state: &mut AdministrationSubprotoState,
        relayer: &mut MockRelayer<CheckpointIncomingMsg>,
        admin_sks: &[SecretKey],
        predicate: PredicateKey,
        seqno: u64,
        current_height: L1Height,
    ) -> Result<(), AdministrationError> {
        let action = MultisigAction::Update(UpdateAction::OlStfVk(OlStfVkUpdate::new(predicate)));
        let sig_set = create_signature_set(admin_sks, &[0, 2], &action, seqno);
        let payload = SignedPayload::new(seqno, action, sig_set);
        handle_action(state, payload, current_height, relayer)
    }

    /// Signs and submits an `AsmStfVk` rotation as the Strata administrator.
    fn authorize_asm_rotation(
        state: &mut AdministrationSubprotoState,
        relayer: &mut MockRelayer<CheckpointIncomingMsg>,
        admin_sks: &[SecretKey],
        predicate: PredicateKey,
        seqno: u64,
        current_height: L1Height,
    ) -> Result<(), AdministrationError> {
        authorize_asm_rotation_in_block(
            state,
            relayer,
            admin_sks,
            predicate,
            seqno,
            current_height,
            &mut AsmEmissionGuard::default(),
        )
    }

    fn authorize_asm_rotation_in_block(
        state: &mut AdministrationSubprotoState,
        relayer: &mut MockRelayer<CheckpointIncomingMsg>,
        admin_sks: &[SecretKey],
        predicate: PredicateKey,
        seqno: u64,
        current_height: L1Height,
        asm_guard: &mut AsmEmissionGuard,
    ) -> Result<(), AdministrationError> {
        let action = MultisigAction::Update(UpdateAction::AsmStfVk(AsmStfVkUpdate::new(predicate)));
        let sig_set = create_signature_set(admin_sks, &[0, 2], &action, seqno);
        let payload = SignedPayload::new(seqno, action, sig_set);
        handle_action_in_block(state, payload, current_height, relayer, asm_guard)
    }

    /// Test that Strata Administrator update actions are properly handled:
    /// - Authority sequence number is incremented
    /// - Update ID is incremented
    /// - Actions are queued with correct activation height
    /// - Queued actions can be found in state
    #[test]
    fn test_strata_administrator_update_actions() {
        let (params, admin_sks, _, _) = create_test_params();
        let mut state = AdministrationSubprotoState::new(&params);
        let mut relayer = MockRelayer::<CheckpointIncomingMsg>::new();
        let current_height = 1000;

        // Generate 5 random update actions that require StrataAdministrator role
        let updates = get_strata_administrator_update_actions(5);

        // Create signer indices (signers 0 and 2)
        let signer_indices = [0u8, 2u8];

        for update in updates {
            // Capture initial state before processing the update
            let last_seqno = state
                .authority(update.required_role())
                .unwrap()
                .last_seqno();
            let initial_next_id = state.next_update_id();
            let initial_queued_len = state.queued().len();

            let seqno = last_seqno + 1;
            let action = MultisigAction::Update(update.clone());
            let sig_set = create_signature_set(&admin_sks, &signer_indices, &action, seqno);
            let payload = SignedPayload::new(seqno, action, sig_set);
            handle_action(&mut state, payload, current_height, &mut relayer).unwrap();

            // Verify state changes after processing
            let new_last_seqno = state
                .authority(update.required_role())
                .unwrap()
                .last_seqno();
            let new_next_id = state.next_update_id();
            let new_queued_len = state.queued().len();

            // Authority sequence number should increment by 1
            assert_eq!(new_last_seqno, seqno);
            // Next update ID should increment by 1
            assert_eq!(new_next_id, initial_next_id + 1);
            // Queue should contain one more item
            assert_eq!(new_queued_len, initial_queued_len + 1);

            // Verify the queued update has correct activation height
            let queued_update = state
                .find_queued(&initial_next_id)
                .expect("queued action must be found");

            let depth = params
                .confirmation_depths
                .get(update.update_tx_type())
                .expect("test config uses non-zero depths");
            assert_eq!(
                queued_update.activation_height(),
                current_height + depth as u32
            );
        }
    }

    #[test]
    fn test_activation_height_overflow_rejects_update_without_advancing_state() {
        let (mut params, admin_sks, _, _) = create_test_params();
        params.confirmation_depths.ol_stf_vk_update = 2;
        let mut state = AdministrationSubprotoState::new(&params);
        let mut relayer = MockRelayer::<CheckpointIncomingMsg>::new();
        let current_height = u32::MAX - 1;
        let update = UpdateAction::OlStfVk(OlStfVkUpdate::new(PredicateKey::always_accept()));
        let action = MultisigAction::Update(update);
        let seqno = 1;
        let sig_set = create_signature_set(&admin_sks, &[0, 2], &action, seqno);
        let payload = SignedPayload::new(seqno, action, sig_set);

        let result = handle_action(&mut state, payload, current_height, &mut relayer);

        assert_eq!(
            result,
            Err(AdministrationError::ActivationHeightOverflow {
                current_height,
                delay: 2,
            })
        );
        assert!(state.queued().is_empty());
        assert_eq!(state.next_update_id(), 0);
        assert_eq!(
            state
                .authority(Role::StrataAdministrator)
                .unwrap()
                .last_seqno(),
            0
        );
    }

    /// Test that multisig actions reject invalid sequence numbers.
    ///
    /// Verifies that sequence number validation prevents replay attacks by rejecting
    /// duplicate and out-of-order sequence numbers for StrataAdministrator actions.
    #[test]
    fn test_strata_administrator_incorrect_seqno() {
        let (params, admin_sks, _, _) = create_test_params();
        let mut state = AdministrationSubprotoState::new(&params);
        let mut relayer = MockRelayer::<CheckpointIncomingMsg>::new();
        let current_height = 1000;
        let last_seqno = 0;

        // Generate a random update action that require StrataAdministrator role
        let update = get_strata_administrator_update_actions(1)[0].clone();

        // Create signer indices (signers 0 and 2)
        let signer_indices = [0u8, 2u8];

        // Create an action and queue it with a valid seqno (> current authority seqno of 0).
        let valid_seqno = last_seqno + 1;
        let action = MultisigAction::Update(update.clone());
        let sig_set = create_signature_set(&admin_sks, &signer_indices, &action, valid_seqno);
        let payload = SignedPayload::new(valid_seqno, action, sig_set);
        let res = handle_action(&mut state, payload, current_height, &mut relayer);
        assert!(res.is_ok());

        // Authority seqno is now 1. Try replaying with seqno 1 (<= current).
        let action = MultisigAction::Update(update.clone());
        let sig_set = create_signature_set(&admin_sks, &signer_indices, &action, 1);

        let payload = SignedPayload::new(1, action, sig_set);
        let res = handle_action(&mut state, payload, current_height, &mut relayer);

        assert!(res.is_err());
        assert!(matches!(
            res,
            Err(AdministrationError::InvalidSeqno {
                role: Role::StrataAdministrator,
                payload_seqno: 1,
                last_seqno: 1,
            })
        ));

        // Try with seqno 0, which is also <= current seqno of 1.
        let action = MultisigAction::Update(update.clone());
        let sig_set = create_signature_set(&admin_sks, &signer_indices, &action, 0);
        let payload = SignedPayload::new(0, action, sig_set);
        let res = handle_action(&mut state, payload, current_height, &mut relayer);
        assert!(matches!(res, Err(AdministrationError::InvalidSeqno { .. })));
    }

    /// Test that updates whose configured confirmation depth is zero apply immediately:
    /// - Authority sequence number is incremented
    /// - Update ID is incremented
    /// - Actions are NOT queued (applied immediately)
    /// - No queued actions can be found in state
    ///
    /// Uses sequencer updates as the depth-zero variant; the immediate-apply branch is the
    /// same regardless of which update type carries the zero depth.
    #[test]
    fn test_zero_depth_update_applies_immediately() {
        let mut arb = ArbitraryGenerator::new();
        let (mut params, _, seq_manager_sks, _) = create_test_params();
        params.confirmation_depths.sequencer_update = 0;
        let mut state = AdministrationSubprotoState::new(&params);

        let mut relayer = MockRelayer::<CheckpointIncomingMsg>::new();
        let current_height = 1000;

        // Generate random sequencer update actions
        let updates: Vec<SequencerUpdate> = arb.generate();
        let update_count = updates.len();

        // Create signer indices (signers 0 and 2)
        let signer_indices = [0u8, 2u8];

        for update in updates {
            let update: UpdateAction = update.into();
            // Capture initial state before processing the update
            let last_seqno = state
                .authority(update.required_role())
                .unwrap()
                .last_seqno();
            let initial_next_id = state.next_update_id();
            let initial_queued_len = state.queued().len();

            let payload_seqno = last_seqno + 1;
            let action = MultisigAction::Update(update.clone());
            let sig_set =
                create_signature_set(&seq_manager_sks, &signer_indices, &action, payload_seqno);

            let payload = SignedPayload::new(payload_seqno, action, sig_set);
            handle_action(&mut state, payload, current_height, &mut relayer).unwrap();

            // Verify state changes after processing
            let new_last_seqno = state
                .authority(update.required_role())
                .unwrap()
                .last_seqno();
            let new_next_id = state.next_update_id();
            let new_queued_len = state.queued().len();

            // Authority sequence number should increment by 1
            assert_eq!(new_last_seqno, last_seqno + 1);
            // Next update ID should increment by 1
            assert_eq!(new_next_id, initial_next_id + 1);
            // Queue length should remain the same (zero-depth updates bypass the queue)
            assert_eq!(new_queued_len, initial_queued_len);

            // Verify the update was not queued (applied immediately)
            assert!(state.find_queued(&initial_next_id).is_none());
        }

        let checkpoint_msgs = relayer.messages();
        assert_eq!(checkpoint_msgs.len(), update_count);
        assert!(
            checkpoint_msgs
                .iter()
                .all(|msg| matches!(msg, CheckpointIncomingMsg::UpdateSequencerKey(_)))
        );
    }

    #[test]
    fn test_rollup_verifying_key_update_forwarded_to_checkpoint() {
        let (params, _, _, _) = create_test_params();
        let mut state = AdministrationSubprotoState::new(&params);
        let mut relayer = MockRelayer::<CheckpointIncomingMsg>::new();

        let predicate = PredicateKey::always_accept();

        let update = UpdateAction::OlStfVk(OlStfVkUpdate::new(predicate.clone()));
        let update_id = state.next_update_id();
        let activation_height = 42;
        state.enqueue(QueuedUpdate::new(update_id, update, activation_height));

        handle_pending_updates(&mut state, &mut relayer, activation_height);

        assert!(state.queued().is_empty());
        let checkpoint_msgs = relayer.messages();
        assert_eq!(checkpoint_msgs.len(), 1);
        match checkpoint_msgs
            .first()
            .expect("checkpoint message expected")
        {
            CheckpointIncomingMsg::QueueCheckpointPredicateTransition(transition) => {
                assert_eq!(transition.predicate(), &predicate);
                assert_eq!(transition.boundary(), activation_height);
            }
            _ => panic!("expected rollup verifying key update to checkpoint"),
        }
        let enactment = relayer.logs[0]
            .try_into_log::<CheckpointPredicateEnacted>()
            .expect("log should deserialize as CheckpointPredicateEnacted");
        assert_eq!(enactment.new_predicate(), &predicate);
    }

    /// Authorizing a second rotation while one is still queued must fail.
    ///
    /// The checkpoint subprotocol holds a single pending-transition slot, and the boundary a
    /// rotation announces is fixed the moment its transaction lands. Rejecting here keeps both
    /// facts true: the slot cannot be double-booked, and no authorized rotation ever has its
    /// enactment height pushed out from under the exit window it promised.
    #[test]
    fn test_second_ol_rotation_rejected_while_one_is_queued() {
        let (params, admin_sks, _, _) = create_test_params();
        let mut state = AdministrationSubprotoState::new(&params);
        let mut relayer = MockRelayer::<CheckpointIncomingMsg>::new();
        let current_height = 1000;

        let first = authorize_ol_rotation(
            &mut state,
            &mut relayer,
            &admin_sks,
            test_predicate(1),
            1,
            current_height,
        );
        assert!(first.is_ok());
        assert_eq!(state.queued().len(), 1);

        let second = authorize_ol_rotation(
            &mut state,
            &mut relayer,
            &admin_sks,
            test_predicate(2),
            2,
            current_height,
        );

        assert_eq!(
            second,
            Err(AdministrationError::OlStfVkUpdateAlreadyOutstanding)
        );
        assert_eq!(state.queued().len(), 1);
    }

    /// The rejection must outlive enactment: the rotation stops being queued at `B` but keeps
    /// occupying checkpoint's pending slot until a checkpoint covering `B + 1` is accepted.
    #[test]
    fn test_second_ol_rotation_rejected_while_one_awaits_activation() {
        let (params, admin_sks, _, _) = create_test_params();
        let mut state = AdministrationSubprotoState::new(&params);
        let mut relayer = MockRelayer::<CheckpointIncomingMsg>::new();
        let activation_height = 42;

        state.enqueue(QueuedUpdate::new(
            0,
            UpdateAction::OlStfVk(OlStfVkUpdate::new(test_predicate(1))),
            activation_height,
        ));
        handle_pending_updates(&mut state, &mut relayer, activation_height);

        assert!(state.queued().is_empty());
        assert!(state.ol_transition_pending());

        let result = authorize_ol_rotation(
            &mut state,
            &mut relayer,
            &admin_sks,
            test_predicate(2),
            1,
            activation_height,
        );

        assert_eq!(
            result,
            Err(AdministrationError::OlStfVkUpdateAlreadyOutstanding)
        );
        assert!(state.queued().is_empty());
    }

    /// Checkpoint's acknowledgement is what reopens authorization: the pending slot is not
    /// observable from administration state, so nothing else can clear the flag.
    #[test]
    fn test_ol_transition_ack_reopens_authorization() {
        let (params, admin_sks, _, _) = create_test_params();
        let mut state = AdministrationSubprotoState::new(&params);
        let mut relayer = MockRelayer::<CheckpointIncomingMsg>::new();
        let activation_height = 42;

        state.enqueue(QueuedUpdate::new(
            0,
            UpdateAction::OlStfVk(OlStfVkUpdate::new(test_predicate(1))),
            activation_height,
        ));
        handle_pending_updates(&mut state, &mut relayer, activation_height);
        assert!(state.ol_transition_pending());

        AdministrationSubprotocol::process_msgs(
            &mut state,
            &[AdministrationIncomingMsg::OlTransitionPromoted],
            &L1BlockCommitment::default(),
        );

        assert!(!state.ol_transition_pending());
        let result = authorize_ol_rotation(
            &mut state,
            &mut relayer,
            &admin_sks,
            test_predicate(2),
            1,
            activation_height,
        );
        assert!(result.is_ok());
        assert_eq!(state.queued().len(), 1);
    }

    /// A cancellation must not reorder the updates that survive it.
    ///
    /// `process_queued` drains in queue order and enactment side effects are not commutative,
    /// so the drain order is consensus-critical for every update type, not just OL rotations.
    /// A swap-remove would move the queue's last entry into the cancelled slot and silently
    /// permute everything that enacts afterwards.
    #[test]
    fn test_cancellation_preserves_queue_drain_order() {
        let (params, _, _, _) = create_test_params();
        let mut state = AdministrationSubprotoState::new(&params);
        let mut relayer = MockRelayer::<CheckpointIncomingMsg>::new();
        let activation_height = 42;
        let first_key = Buf32::from([1; 32]);
        let second_key = Buf32::from([2; 32]);
        let third_key = Buf32::from([3; 32]);

        state.enqueue(QueuedUpdate::new(
            0,
            UpdateAction::AsmStfVk(AsmStfVkUpdate::new(test_predicate(0))),
            activation_height,
        ));
        for (id, key) in [(1, first_key), (2, second_key), (3, third_key)] {
            state.enqueue(QueuedUpdate::new(
                id,
                UpdateAction::Sequencer(SequencerUpdate::new(key)),
                activation_height,
            ));
        }

        // Cancelling the head is the case a swap-remove gets wrong: it would pull id 3 forward.
        state.remove_queued(&0);

        handle_pending_updates(&mut state, &mut relayer, activation_height);

        let relayed_keys: Vec<_> = relayer
            .messages()
            .iter()
            .filter_map(|msg| match msg {
                CheckpointIncomingMsg::UpdateSequencerKey(predicate) => {
                    Some(predicate.condition().to_vec())
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            relayed_keys,
            [
                first_key.0.to_vec(),
                second_key.0.to_vec(),
                third_key.0.to_vec()
            ]
        );
    }

    #[test]
    fn test_defcon1_update_forwarded_to_bridge() {
        let (params, _, _, _) = create_test_params();
        let mut state = AdministrationSubprotoState::new(&params);
        let mut relayer = MockRelayer::<BridgeIncomingMsg>::new();

        let update = UpdateAction::Defcon1(Defcon1Update);
        let update_id = state.next_update_id();
        let activation_height = 42;
        state.enqueue(QueuedUpdate::new(update_id, update, activation_height));

        handle_pending_updates(&mut state, &mut relayer, activation_height);

        assert!(state.queued().is_empty());
        let bridge_msgs = relayer.messages();
        assert_eq!(bridge_msgs.len(), 1);
        assert!(
            matches!(bridge_msgs.first(), Some(BridgeIncomingMsg::Defcon(_))),
            "expected Defcon message to bridge, got {:?}",
            bridge_msgs.first()
        );
    }

    #[test]
    fn test_defcon3_update_forwarded_to_bridge() {
        let (params, _, _, _) = create_test_params();
        let mut state = AdministrationSubprotoState::new(&params);
        let mut relayer = MockRelayer::<BridgeIncomingMsg>::new();

        let update = UpdateAction::Defcon3(Defcon3Update);
        let update_id = state.next_update_id();
        let activation_height = 42;
        state.enqueue(QueuedUpdate::new(update_id, update, activation_height));

        handle_pending_updates(&mut state, &mut relayer, activation_height);

        assert!(state.queued().is_empty());
        let bridge_msgs = relayer.messages();
        assert_eq!(bridge_msgs.len(), 1);
        assert!(
            matches!(bridge_msgs.first(), Some(BridgeIncomingMsg::Defcon(_))),
            "expected Defcon message to bridge, got {:?}",
            bridge_msgs.first()
        );
    }

    #[test]
    fn test_safe_harbour_address_update_forwarded_to_bridge() {
        let (params, _, _, _) = create_test_params();
        let mut state = AdministrationSubprotoState::new(&params);
        let mut relayer = MockRelayer::<BridgeIncomingMsg>::new();

        let new_address: SafeHarbourAddress = ArbitraryGenerator::new().generate();
        let expected_address = new_address.clone();
        let update = UpdateAction::SafeHarbourAddress(SafeHarbourAddressUpdate::new(new_address));
        let update_id = state.next_update_id();
        let activation_height = 42;
        state.enqueue(QueuedUpdate::new(update_id, update, activation_height));

        handle_pending_updates(&mut state, &mut relayer, activation_height);

        assert!(state.queued().is_empty());
        let bridge_msgs = relayer.messages();
        assert_eq!(bridge_msgs.len(), 1);
        assert!(
            matches!(
                bridge_msgs.first(),
                Some(BridgeIncomingMsg::UpdateSafeHarbourAddress(addr)) if addr == &expected_address
            ),
            "expected UpdateSafeHarbourAddress message to bridge, got {:?}",
            bridge_msgs.first()
        );
    }

    #[test]
    fn test_asm_verifying_key_update_emits_log() {
        let (params, _, _, _) = create_test_params();
        let mut state = AdministrationSubprotoState::new(&params);
        let mut relayer = MockRelayer::<CheckpointIncomingMsg>::new();

        let predicate = PredicateKey::always_accept();

        let update = UpdateAction::AsmStfVk(AsmStfVkUpdate::new(predicate.clone()));
        let update_id = state.next_update_id();
        let activation_height = 42;
        state.enqueue(QueuedUpdate::new(update_id, update, activation_height));

        handle_pending_updates(&mut state, &mut relayer, activation_height);

        assert!(state.queued().is_empty());
        // No inter-protocol messages should be sent for ASM updates
        assert!(relayer.messages().is_empty());
        // Exactly one log should be emitted
        assert_eq!(relayer.logs.len(), 1);

        let log_entry = &relayer.logs[0];
        let asm_update = log_entry
            .try_into_log::<AsmStfUpdate>()
            .expect("log should deserialize as AsmStfUpdate");
        assert_eq!(asm_update.new_predicate(), &predicate);
    }

    #[test]
    fn test_second_asm_rotation_rejected_while_one_is_queued() {
        let (params, admin_sks, _, _) = create_test_params();
        let mut state = AdministrationSubprotoState::new(&params);
        let mut relayer = MockRelayer::<CheckpointIncomingMsg>::new();
        let current_height = 1_000;

        assert!(
            authorize_asm_rotation(
                &mut state,
                &mut relayer,
                &admin_sks,
                test_predicate(1),
                1,
                current_height,
            )
            .is_ok()
        );
        assert_eq!(state.queued().len(), 1);

        assert_eq!(
            authorize_asm_rotation(
                &mut state,
                &mut relayer,
                &admin_sks,
                test_predicate(2),
                2,
                current_height,
            ),
            Err(AdministrationError::AsmStfVkUpdateAlreadyScheduled {
                activation_height: current_height + 2016,
            }),
        );
        assert_eq!(state.queued().len(), 1);
        assert_eq!(state.next_update_id(), 1);
        assert_eq!(
            state
                .authority(Role::StrataAdministrator)
                .expect("authority")
                .last_seqno(),
            1,
        );
    }

    #[test]
    fn test_asm_rotations_at_distinct_activation_heights_can_be_queued() {
        let (params, admin_sks, _, _) = create_test_params();
        let mut state = AdministrationSubprotoState::new(&params);
        let mut relayer = MockRelayer::<CheckpointIncomingMsg>::new();

        authorize_asm_rotation(
            &mut state,
            &mut relayer,
            &admin_sks,
            test_predicate(1),
            1,
            1_000,
        )
        .expect("first future handover is scheduled");
        authorize_asm_rotation(
            &mut state,
            &mut relayer,
            &admin_sks,
            test_predicate(2),
            2,
            1_001,
        )
        .expect("a later block has an independent handover slot");

        assert_eq!(state.queued().len(), 2);
        assert_eq!(state.queued()[0].activation_height(), 3_016);
        assert_eq!(state.queued()[1].activation_height(), 3_017);
    }

    #[test]
    fn test_second_immediate_asm_rotation_rejected_in_the_same_block() {
        let (mut params, admin_sks, _, _) = create_test_params();
        params.confirmation_depths.asm_stf_vk_update = 0;
        let mut state = AdministrationSubprotoState::new(&params);
        let mut relayer = MockRelayer::<CheckpointIncomingMsg>::new();
        let current_height = 1_000;
        let mut asm_guard = AsmEmissionGuard::default();

        assert!(
            authorize_asm_rotation_in_block(
                &mut state,
                &mut relayer,
                &admin_sks,
                test_predicate(1),
                1,
                current_height,
                &mut asm_guard,
            )
            .is_ok()
        );
        assert_eq!(relayer.logs.len(), 1);

        assert_eq!(
            authorize_asm_rotation_in_block(
                &mut state,
                &mut relayer,
                &admin_sks,
                test_predicate(2),
                2,
                current_height,
                &mut asm_guard,
            ),
            Err(AdministrationError::AsmStfVkUpdateAlreadyEmitted),
        );
        assert_eq!(
            relayer.logs.len(),
            1,
            "the rejected update emitted a handover"
        );
        assert_eq!(state.next_update_id(), 1);
        assert_eq!(
            state
                .authority(Role::StrataAdministrator)
                .expect("authority")
                .last_seqno(),
            1,
        );
    }

    #[test]
    fn test_due_rotation_blocks_an_immediate_second_handover_in_the_same_block() {
        let (mut params, admin_sks, _, _) = create_test_params();
        params.confirmation_depths.asm_stf_vk_update = 0;
        let mut state = AdministrationSubprotoState::new(&params);
        let mut relayer = MockRelayer::<CheckpointIncomingMsg>::new();
        let current_height = 1_000;
        state.enqueue(QueuedUpdate::new(
            0,
            UpdateAction::AsmStfVk(AsmStfVkUpdate::new(test_predicate(1))),
            current_height,
        ));

        let mut asm_guard = AsmEmissionGuard::default();
        handle_pending_updates_in_block(&mut state, &mut relayer, current_height, &mut asm_guard);
        assert_eq!(relayer.logs.len(), 1);

        assert_eq!(
            authorize_asm_rotation_in_block(
                &mut state,
                &mut relayer,
                &admin_sks,
                test_predicate(2),
                1,
                current_height,
                &mut asm_guard,
            ),
            Err(AdministrationError::AsmStfVkUpdateAlreadyEmitted),
        );
        assert_eq!(relayer.logs.len(), 1);
    }

    #[test]
    fn test_next_block_can_authorize_another_immediate_asm_rotation() {
        let (mut params, admin_sks, _, _) = create_test_params();
        params.confirmation_depths.asm_stf_vk_update = 0;
        let mut state = AdministrationSubprotoState::new(&params);
        let mut relayer = MockRelayer::<CheckpointIncomingMsg>::new();

        let mut first_block = AsmEmissionGuard::default();
        authorize_asm_rotation_in_block(
            &mut state,
            &mut relayer,
            &admin_sks,
            test_predicate(1),
            1,
            1_000,
            &mut first_block,
        )
        .expect("first block may hand over once");
        let mut second_block = AsmEmissionGuard::default();
        authorize_asm_rotation_in_block(
            &mut state,
            &mut relayer,
            &admin_sks,
            test_predicate(2),
            2,
            1_001,
            &mut second_block,
        )
        .expect("the child block may hand over again under its selected rules");

        assert_eq!(relayer.logs.len(), 2);
    }

    /// Test that cancel actions properly remove queued updates:
    /// - First queue 5 update actions.
    /// - Then cancel each one individually.
    /// - Verify sequence numbers increment, queue shrinks, and updates are removed.
    #[test]
    fn test_strata_administrator_cancel_action() {
        let (params, admin_sks, _, _) = create_test_params();
        let mut state = AdministrationSubprotoState::new(&params);
        let mut relayer = MockRelayer::<CheckpointIncomingMsg>::new();
        let no_of_updates = 5;
        let current_height = 1000;

        // create signer indices (signers 0 and 2)
        let signer_indices = [0u8, 2u8];

        // First, queue 5 update actions
        let updates = get_strata_administrator_update_actions(no_of_updates);

        for update in updates {
            let last_seqno = state
                .authority(update.required_role())
                .unwrap()
                .last_seqno();
            let payload_seqno = last_seqno + 1;
            let update_action = MultisigAction::Update(update);

            let sig_set =
                create_signature_set(&admin_sks, &signer_indices, &update_action, payload_seqno);

            let payload = SignedPayload::new(payload_seqno, update_action, sig_set);
            handle_action(&mut state, payload, current_height, &mut relayer).unwrap();
        }

        // Then create a random order in which the actions are cancelled.
        let mut cancel_order: Vec<u32> = (0..no_of_updates as u32).collect();
        cancel_order.shuffle(&mut thread_rng());

        // Then cancel each queued update one by one based on the random order.
        for id in cancel_order {
            let queued_action = state.find_queued(&id).unwrap().action().clone();
            let authorized_role = queued_action.required_role();
            let cancel_action = MultisigAction::Cancel(CancelAction::new(id, queued_action));
            // Capture initial state before cancellation
            let last_seqno = state.authority(authorized_role).unwrap().last_seqno();
            let payload_seqno = last_seqno + 1;
            let initial_next_id = state.next_update_id();
            let initial_queued_len = state.queued().len();

            let sig_set =
                create_signature_set(&admin_sks, &signer_indices, &cancel_action, payload_seqno);

            let payload = SignedPayload::new(payload_seqno, cancel_action, sig_set);
            handle_action(&mut state, payload, current_height, &mut relayer).unwrap();

            // Verify state changes after cancellation
            let new_last_seqno = state.authority(authorized_role).unwrap().last_seqno();
            let new_next_id = state.next_update_id();
            let new_queued_len = state.queued().len();

            // Authority sequence number should increment by 1
            assert_eq!(new_last_seqno, last_seqno + 1);
            // Next update ID should remain unchanged (cancellation doesn't create new IDs)
            assert_eq!(new_next_id, initial_next_id);
            // Queue should shrink by 1
            assert_eq!(new_queued_len, initial_queued_len - 1);
            // The cancelled update should no longer be found
            assert!(state.find_queued(&id).is_none());
        }
    }

    /// Test that attempting to cancel a non-existent action returns an error:
    /// - Generate a random cancel action for an ID that doesn't exist
    /// - Verify that handle_action returns UnknownAction error
    #[test]
    fn test_strata_administrator_non_existent_cancel() {
        let (params, admin_sks, _, _) = create_test_params();
        let mut state = AdministrationSubprotoState::new(&params);
        let mut relayer = MockRelayer::<CheckpointIncomingMsg>::new();
        let current_height = 1000;
        let signer_indices = [0u8, 2u8];

        // Build a cancel whose embedded update routes to StrataAdministrator (so admin_sks
        // can sign it), but whose target_id is not in the (empty) queue.
        let nonexistent_id = 42;
        let update = get_strata_administrator_update_actions(1).pop().unwrap();
        let cancel_action = MultisigAction::Cancel(CancelAction::new(nonexistent_id, update));

        let payload_seqno = 1;
        let sig_set =
            create_signature_set(&admin_sks, &signer_indices, &cancel_action, payload_seqno);
        let payload = SignedPayload::new(payload_seqno, cancel_action, sig_set);
        let res = handle_action(&mut state, payload, current_height, &mut relayer);

        assert!(matches!(res, Err(AdministrationError::UnknownAction(_))));
    }

    /// Test that attempting to cancel a same action twice returns an error:
    /// - Generate a random update action and queue it.
    /// - Cancel the update action.
    /// - Verify that cancelling the update action again returns an UnknownAction error.
    #[test]
    fn test_strata_administrator_duplicate_cancels() {
        let (params, admin_sks, _, _) = create_test_params();
        let mut relayer = MockRelayer::<CheckpointIncomingMsg>::new();
        let mut state = AdministrationSubprotoState::new(&params);
        let last_seqno = 0;
        let current_height = 1000;

        // Create an update action
        let update_id = state.next_update_id();
        let update = get_strata_administrator_update_actions(1)
            .first()
            .unwrap()
            .clone();
        let update_action = MultisigAction::Update(update.clone());

        // create signer indices (signers 0 and 2)
        let signer_indices = [0u8, 2u8];

        // Use seqno > initial (0) to pass validation
        let update_seqno = last_seqno + 1;
        let sig_set =
            create_signature_set(&admin_sks, &signer_indices, &update_action, update_seqno);

        let payload = SignedPayload::new(update_seqno, update_action, sig_set);
        handle_action(&mut state, payload, current_height, &mut relayer).unwrap();

        // Cancel the update action (authority seqno is now 1, use seqno 2)
        let cancel_action = MultisigAction::Cancel(CancelAction::new(update_id, update.clone()));
        let cancel_seqno = last_seqno + 2;
        let sig_set =
            create_signature_set(&admin_sks, &signer_indices, &cancel_action, cancel_seqno);

        let payload = SignedPayload::new(cancel_seqno, cancel_action, sig_set);
        let res = handle_action(&mut state, payload, current_height, &mut relayer);

        assert!(res.is_ok());

        // Try cancelling the update action again (authority seqno is now 2, use seqno 3)
        let cancel_action = MultisigAction::Cancel(CancelAction::new(update_id, update));
        let retry_seqno = last_seqno + 3;
        let sig_set =
            create_signature_set(&admin_sks, &signer_indices, &cancel_action, retry_seqno);
        let payload = SignedPayload::new(retry_seqno, cancel_action, sig_set);
        let res = handle_action(&mut state, payload, current_height, &mut relayer);
        assert!(res.is_err());
        assert!(matches!(res, Err(AdministrationError::UnknownAction(_))));
    }

    /// Test that consecutive updates with a sequence number gap within the allowed
    /// `max_seqno_gap` are accepted.
    #[test]
    fn test_seqno_gap_within_limit_succeeds() {
        let (params, admin_sks, _, _) = create_test_params();
        let mut state = AdministrationSubprotoState::new(&params);
        let mut relayer = MockRelayer::<CheckpointIncomingMsg>::new();
        let current_height = 1000;
        let signer_indices = [0u8, 2u8];

        let updates = get_strata_administrator_update_actions(2);

        // First action at seqno 1 (last_seqno is 0)
        let action = MultisigAction::Update(updates[0].clone());
        let sig_set = create_signature_set(&admin_sks, &signer_indices, &action, 1);
        let payload = SignedPayload::new(1, action, sig_set);
        handle_action(&mut state, payload, current_height, &mut relayer).unwrap();

        // Second action at seqno 11 (last_seqno is 1, gap = 10 = max_seqno_gap)
        let gap_seqno = 1 + state.max_seqno_gap().get() as u64;
        let action = MultisigAction::Update(updates[1].clone());
        let sig_set = create_signature_set(&admin_sks, &signer_indices, &action, gap_seqno);
        let payload = SignedPayload::new(gap_seqno, action, sig_set);
        let res = handle_action(&mut state, payload, current_height, &mut relayer);

        assert!(
            res.is_ok(),
            "seqno gap of exactly max_seqno_gap should succeed"
        );
    }

    /// Test that a sequence number gap exceeding `max_seqno_gap` is rejected.
    #[test]
    fn test_seqno_gap_exceeds_limit_fails() {
        let (params, admin_sks, _, _) = create_test_params();
        let mut state = AdministrationSubprotoState::new(&params);
        let mut relayer = MockRelayer::<CheckpointIncomingMsg>::new();
        let current_height = 1000;
        let signer_indices = [0u8, 2u8];

        let update = get_strata_administrator_update_actions(1)[0].clone();

        // Try action at seqno 11 (last_seqno is 0, gap = 11 > max_seqno_gap of 10)
        let too_far_seqno = state.max_seqno_gap().get() as u64 + 1;
        let action = MultisigAction::Update(update);
        let sig_set = create_signature_set(&admin_sks, &signer_indices, &action, too_far_seqno);
        let payload = SignedPayload::new(too_far_seqno, action, sig_set);
        let res = handle_action(&mut state, payload, current_height, &mut relayer);

        assert!(res.is_err());
        assert!(matches!(
            res,
            Err(AdministrationError::SeqnoGapTooLarge {
                role: Role::StrataAdministrator,
                payload_seqno: 11,
                last_seqno: 0,
                max_gap,
            }) if max_gap.get() == 10
        ));
    }
}
