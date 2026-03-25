//! Checkpoint v0 data structures
//!
//! This module defines data structures that maintain compatibility with the current
//! checkpoint implementation while incorporating SPS-62 concepts where applicable.
//!
//! NOTE: This is checkpoint v0 which focuses on feature parity with the current
//! checkpoint system. Future versions will be fully SPS-62 compatible.

use ssz_derive::{Decode, Encode};
use strata_checkpoint_types::Checkpoint;
use strata_identifiers::Epoch;
use strata_predicate::PredicateKey;
use strata_primitives::{L1Height, block_credential::CredRule, buf::Buf32, l1::L1BlockCommitment};

/// Checkpoint verifier state for checkpoint v0
///
/// NOTE: This maintains state similar to the current core subprotocol but
/// simplified for checkpoint v0 compatibility
#[derive(Clone, Debug, Encode, Decode)]
pub struct CheckpointV0VerifierState {
    /// The last verified checkpoint
    #[ssz(with = "legacy_checkpoint_ssz")]
    pub last_checkpoint: Option<Checkpoint>,

    /// Last L1 block where we got a valid checkpoint
    pub last_checkpoint_l1_height: L1Height,

    /// Current epoch we've verified up to
    pub current_verified_epoch: Epoch,

    /// Credential rule governing signature verification
    #[ssz(with = "cred_rule_ssz")]
    pub cred_rule: CredRule,

    /// Predicate used to verify the validity of the checkpoint
    pub predicate: PredicateKey,
}

/// Verification parameters for checkpoint v0
///
/// NOTE: This bridges to the current verification system while maintaining
/// some SPS-62 concepts for future compatibility.
/// Configuration parameters don't need serialization - they're provided at init.
#[derive(Clone, Debug)]
pub struct CheckpointV0VerificationParams {
    /// Genesis L1 block commitment
    pub genesis_l1_block: L1BlockCommitment,

    /// Credential rule governing signature verification
    pub cred_rule: CredRule,

    /// Predicate used to verify the validity of the checkpoint
    pub predicate: PredicateKey,
}

/// Compatibility functions for working with current checkpoint types
impl CheckpointV0VerifierState {
    /// Initialize from genesis parameters
    pub fn new(params: &CheckpointV0VerificationParams) -> Self {
        Self {
            last_checkpoint: None,
            last_checkpoint_l1_height: params.genesis_l1_block.height(),
            current_verified_epoch: 0,
            cred_rule: params.cred_rule.clone(),
            predicate: params.predicate.clone(),
        }
    }

    /// Update state with a newly verified checkpoint
    pub fn update_with_checkpoint(&mut self, checkpoint: Checkpoint, l1_height: L1Height) {
        let epoch = checkpoint.batch_info().epoch();
        self.last_checkpoint = Some(checkpoint);
        self.last_checkpoint_l1_height = l1_height;
        self.current_verified_epoch = epoch;
    }

    /// Get the latest verified epoch
    pub fn current_epoch(&self) -> Epoch {
        self.current_verified_epoch
    }

    /// Get the epoch value we expect for the next checkpoint.
    pub fn expected_next_epoch(&self) -> Epoch {
        match &self.last_checkpoint {
            Some(_) => self.current_verified_epoch + 1,
            None => 0,
        }
    }

    /// Check if we can accept a checkpoint for the given epoch
    ///
    /// Returns `true` if the epoch is exactly one greater than the current verified epoch.
    /// This enforces sequential epoch progression without gaps.
    ///
    /// # Arguments
    /// * `epoch` - The epoch number to validate
    ///
    /// # Returns
    /// `true` if the epoch can be accepted, `false` otherwise
    pub fn can_accept_epoch(&self, epoch: Epoch) -> bool {
        epoch == self.expected_next_epoch()
    }

    /// Update the sequencer public key used to validate checkpoint signatures.
    pub fn update_sequencer_key(&mut self, new_pubkey: Buf32) {
        self.cred_rule = CredRule::SchnorrKey(new_pubkey);
    }

    /// Update the rollup verifying key used for proof verification.
    pub fn update_predicate(&mut self, new_predicate: PredicateKey) {
        self.predicate = new_predicate;
    }
}

#[expect(unreachable_pub, reason = "used by ssz_derive field adapters")]
mod cred_rule_ssz {
    use super::{Buf32, CredRule};

    #[derive(Debug, ssz_derive::Encode, ssz_derive::Decode)]
    struct CredRuleSsz {
        kind: u8,
        key: Buf32,
    }

    pub mod encode {
        use ssz::Encode as SszEncode;

        use super::{Buf32, CredRule, CredRuleSsz};

        pub fn is_ssz_fixed_len() -> bool {
            <CredRuleSsz as SszEncode>::is_ssz_fixed_len()
        }

        pub fn ssz_fixed_len() -> usize {
            <CredRuleSsz as SszEncode>::ssz_fixed_len()
        }

        pub fn ssz_bytes_len(value: &CredRule) -> usize {
            to_ssz(value).ssz_bytes_len()
        }

        pub fn ssz_append(value: &CredRule, buf: &mut Vec<u8>) {
            to_ssz(value).ssz_append(buf);
        }

        fn to_ssz(value: &CredRule) -> CredRuleSsz {
            match value {
                CredRule::Unchecked => CredRuleSsz {
                    kind: 0,
                    key: Buf32::zero(),
                },
                CredRule::SchnorrKey(key) => CredRuleSsz { kind: 1, key: *key },
            }
        }
    }

    pub mod decode {
        use ssz::{Decode as SszDecode, DecodeError};

        use super::{CredRule, CredRuleSsz};

        pub fn is_ssz_fixed_len() -> bool {
            <CredRuleSsz as SszDecode>::is_ssz_fixed_len()
        }

        pub fn ssz_fixed_len() -> usize {
            <CredRuleSsz as SszDecode>::ssz_fixed_len()
        }

        pub fn from_ssz_bytes(bytes: &[u8]) -> Result<CredRule, DecodeError> {
            let value = CredRuleSsz::from_ssz_bytes(bytes)?;
            match value.kind {
                0 => Ok(CredRule::Unchecked),
                1 => Ok(CredRule::SchnorrKey(value.key)),
                kind => Err(DecodeError::BytesInvalid(format!(
                    "invalid cred rule kind {kind}"
                ))),
            }
        }
    }
}

#[expect(unreachable_pub, reason = "used by ssz_derive field adapters")]
mod legacy_checkpoint_ssz {
    use ssz_derive::{Decode, Encode};

    use super::Checkpoint;

    #[derive(Debug, Encode, Decode)]
    struct LegacyCheckpointSsz {
        has_checkpoint: bool,
        checkpoint_bytes: Vec<u8>,
    }

    pub mod encode {
        use ssz::Encode as SszEncode;

        use super::{Checkpoint, LegacyCheckpointSsz};

        pub fn is_ssz_fixed_len() -> bool {
            <LegacyCheckpointSsz as SszEncode>::is_ssz_fixed_len()
        }

        pub fn ssz_fixed_len() -> usize {
            <LegacyCheckpointSsz as SszEncode>::ssz_fixed_len()
        }

        pub fn ssz_bytes_len(value: &Option<Checkpoint>) -> usize {
            to_ssz(value).ssz_bytes_len()
        }

        pub fn ssz_append(value: &Option<Checkpoint>, buf: &mut Vec<u8>) {
            to_ssz(value).ssz_append(buf);
        }

        fn to_ssz(value: &Option<Checkpoint>) -> LegacyCheckpointSsz {
            #[expect(
                deprecated,
                reason = "checkpoint-v0 persists the last verified legacy checkpoint payload"
            )]
            let checkpoint_bytes = value
                .as_ref()
                .map(Checkpoint::to_raw_bytes)
                .transpose()
                .expect("checkpoint-v0 state serialization should not fail")
                .unwrap_or_default();

            LegacyCheckpointSsz {
                has_checkpoint: value.is_some(),
                checkpoint_bytes,
            }
        }
    }

    pub mod decode {
        use ssz::{Decode as SszDecode, DecodeError};

        use super::{Checkpoint, LegacyCheckpointSsz};

        pub fn is_ssz_fixed_len() -> bool {
            <LegacyCheckpointSsz as SszDecode>::is_ssz_fixed_len()
        }

        pub fn ssz_fixed_len() -> usize {
            <LegacyCheckpointSsz as SszDecode>::ssz_fixed_len()
        }

        pub fn from_ssz_bytes(bytes: &[u8]) -> Result<Option<Checkpoint>, DecodeError> {
            let value = LegacyCheckpointSsz::from_ssz_bytes(bytes)?;
            if value.has_checkpoint {
                #[expect(
                    deprecated,
                    reason = "checkpoint-v0 state may still contain a legacy checkpoint payload"
                )]
                Checkpoint::from_raw_bytes(&value.checkpoint_bytes)
                    .map(Some)
                    .map_err(|err| DecodeError::BytesInvalid(err.to_string()))
            } else {
                Ok(None)
            }
        }
    }
}
