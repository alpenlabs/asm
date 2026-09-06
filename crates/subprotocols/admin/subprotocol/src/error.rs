use std::num::NonZero;

use strata_asm_admin_types::Role;
use strata_asm_proto_admin_txs::actions::UpdateId;
use strata_crypto::threshold_signature::ThresholdSignatureError;
use strata_identifiers::L1Height;
use thiserror::Error;

/// Top-level error type for the administration subprotocol, composed of smaller error categories.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum AdministrationError {
    /// The specified role is not recognized.
    #[error("the specified role is not recognized")]
    UnknownRole,

    /// The specified action ID does not correspond to any pending update.
    #[error("no pending update found for action_id = {0:?}")]
    UnknownAction(UpdateId),

    /// The cancel's embedded update does not match the queued action at the target id.
    #[error("cancel target_id {target_id} update payload does not match queued action")]
    CancelUpdateMismatch { target_id: UpdateId },

    /// An OL STF verifying-key rotation is already queued or awaiting activation.
    ///
    /// Only one rotation may be outstanding at a time: the checkpoint subprotocol holds a
    /// single pending-transition slot, and a second rotation would either overwrite a
    /// boundary the OL has already been told about or announce an enactment that checkpoint
    /// state cannot record.
    #[error("an OL STF verifying key update is already queued or awaiting activation")]
    OlStfVkUpdateAlreadyOutstanding,

    /// Another ASM STF verifying-key rotation already targets the same activation block.
    ///
    /// The handover chain can authorize only one predicate for a block's child. Rotations at
    /// distinct heights remain valid and may be scheduled concurrently.
    #[error(
        "an ASM STF verifying key update is already scheduled for L1 height {activation_height}"
    )]
    AsmStfVkUpdateAlreadyScheduled {
        /// Activation height already occupied by another ASM rotation.
        activation_height: L1Height,
    },

    /// This block already emitted its one ASM predicate handover.
    #[error("this L1 block already emitted an ASM STF verifying key update")]
    AsmStfVkUpdateAlreadyEmitted,

    /// The activation height cannot be represented in the L1 height domain.
    #[error(
        "activation height overflow: current height {current_height} plus confirmation delay \
         {delay} exceeds the maximum L1 height"
    )]
    ActivationHeightOverflow {
        current_height: L1Height,
        delay: u16,
    },

    /// The payload's sequence number is not greater than the last executed sequence number.
    #[error(
        "invalid seqno for {role:?}: payload seqno {payload_seqno} must be greater than \
         last seqno {last_seqno}"
    )]
    InvalidSeqno {
        role: Role,
        payload_seqno: u64,
        last_seqno: u64,
    },

    /// The gap between payload seqno and last seqno exceeds the configured maximum.
    #[error(
        "seqno gap too large for {role:?}: payload seqno {payload_seqno} exceeds \
         last seqno {last_seqno} by more than max gap {max_gap}"
    )]
    SeqnoGapTooLarge {
        role: Role,
        payload_seqno: u64,
        last_seqno: u64,
        max_gap: NonZero<u8>,
    },

    /// Indicates a threshold signature error (configuration or signature validation).
    #[error(transparent)]
    ThresholdSignature(#[from] ThresholdSignatureError),
}
