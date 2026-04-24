use std::num::NonZero;

use ssz_derive::{Decode, Encode};
use strata_asm_params::Role;
use strata_asm_proto_admin_txs::{
    parser::SignedPayload, signing_message::compute_signing_message_hash,
};
use strata_crypto::threshold_signature::{ThresholdConfig, verify_threshold_signatures};

use crate::error::AdministrationError;

/// Opaque proof token for a verified sequence number.
///
/// Produced by [`MultisigAuthority::verify_action_signature`] and consumed by
/// [`MultisigAuthority::update_last_seqno`], enforcing at the type level that the sequence number
/// can only advance after successful signature verification.
///
/// This type has no public constructor or accessors, and is neither [`Clone`] nor [`Copy`],
/// so that each verification produces exactly one state update.
#[derive(Debug)]
pub struct SeqNoToken(u64);

/// Manages threshold signature operations for a given role and key set, with replay protection via
/// a sequence number.
#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
pub struct MultisigAuthority {
    /// The role of this threshold signature authority.
    role: Role,
    /// The public keys of all grant-holders authorized to sign.
    config: ThresholdConfig,
    /// Last sequence number that was successfully executed. Used to prevent replay attacks.
    last_seqno: u64,
}

impl MultisigAuthority {
    /// Creates a new authority with `last_seqno` initialized to 0.
    ///
    /// Since `verify_action_signature` requires `payload.seqno > self.last_seqno`, the first
    /// valid payload must have `seqno >= 1`.
    pub fn new(role: Role, config: ThresholdConfig) -> Self {
        Self {
            role,
            config,
            last_seqno: 0,
        }
    }

    /// The role authorized to perform threshold signature operations.
    pub fn role(&self) -> Role {
        self.role
    }

    /// Borrow the current threshold configuration.
    pub fn config(&self) -> &ThresholdConfig {
        &self.config
    }

    /// Mutably borrow the threshold configuration.
    pub(crate) fn config_mut(&mut self) -> &mut ThresholdConfig {
        &mut self.config
    }

    /// Verifies a set of ECDSA signatures against the canonical admin signing message.
    pub fn verify_action_signature(
        &self,
        payload: &SignedPayload,
        max_seqno_gap: NonZero<u8>,
    ) -> Result<SeqNoToken, AdministrationError> {
        if payload.seqno <= self.last_seqno {
            return Err(AdministrationError::InvalidSeqno {
                role: self.role,
                payload_seqno: payload.seqno,
                last_seqno: self.last_seqno,
            });
        }

        if payload.seqno > self.last_seqno + max_seqno_gap.get() as u64 {
            return Err(AdministrationError::SeqnoGapTooLarge {
                role: self.role,
                payload_seqno: payload.seqno,
                last_seqno: self.last_seqno,
                max_gap: max_seqno_gap,
            });
        }
        let message_hash = compute_signing_message_hash(&payload.action, payload.seqno, self.role);

        verify_threshold_signatures(
            &self.config,
            payload.signatures.signatures(),
            &message_hash.into(),
        )?;

        Ok(SeqNoToken(payload.seqno))
    }

    /// Updates the last executed seqno.
    ///
    /// Requires a [`SeqNoToken`] token, which can only be obtained from
    /// [`verify_action_signature`](Self::verify_action_signature).
    pub(crate) fn update_last_seqno(&mut self, seqno: SeqNoToken) {
        self.last_seqno = seqno.0;
    }

    /// Returns the last successfully executed sequence number.
    pub fn last_seqno(&self) -> u64 {
        self.last_seqno
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZero;

    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
    use rand::rngs::OsRng;
    use strata_asm_params::Role;
    use strata_asm_proto_admin_txs::{
        actions::{MultisigAction, UpdateAction, updates::seq::SequencerUpdate},
        parser::SignedPayload,
        test_utils::create_signature_set,
    };
    use strata_crypto::{
        keys::compressed::CompressedPublicKey, threshold_signature::ThresholdConfig,
    };
    use strata_identifiers::Buf32;

    use super::*;

    fn create_test_authority(role: Role) -> (MultisigAuthority, SecretKey) {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::new(&mut OsRng);
        let public_key = CompressedPublicKey::from(PublicKey::from_secret_key(&secp, &secret_key));
        let config = ThresholdConfig::try_new(vec![public_key], NonZero::new(1).expect("non-zero"))
            .expect("valid config");

        (MultisigAuthority::new(role, config), secret_key)
    }

    fn sample_action() -> MultisigAction {
        MultisigAction::Update(UpdateAction::Sequencer(SequencerUpdate::new(Buf32::from(
            [7u8; 32],
        ))))
    }

    #[test]
    fn verify_action_signature_accepts_payload_signed_over_rendered_message() {
        let (authority, secret_key) = create_test_authority(Role::StrataSequencerManager);
        let action = sample_action();
        let seqno = 1;
        let signatures = create_signature_set(
            &[secret_key],
            &[0],
            &action,
            Role::StrataSequencerManager,
            seqno,
        );
        let payload = SignedPayload::new(seqno, action, signatures);

        let result =
            authority.verify_action_signature(&payload, NonZero::new(10).expect("non-zero"));

        assert!(result.is_ok());
    }

    #[test]
    fn verify_action_signature_rejects_payload_signed_for_wrong_role() {
        let (authority, secret_key) = create_test_authority(Role::StrataAdministrator);
        let action = sample_action();
        let seqno = 1;
        let signatures = create_signature_set(
            &[secret_key],
            &[0],
            &action,
            Role::StrataSequencerManager,
            seqno,
        );
        let payload = SignedPayload::new(seqno, action, signatures);

        let result =
            authority.verify_action_signature(&payload, NonZero::new(10).expect("non-zero"));

        assert!(matches!(
            result,
            Err(AdministrationError::ThresholdSignature(_))
        ));
    }
}
