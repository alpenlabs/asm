use arbitrary::Arbitrary;
use serde::{Deserialize, Serialize};
use std::num::NonZero;
use strata_asm_params::Role;
use strata_crypto::keys::compressed::CompressedPublicKey;
use strata_crypto::threshold_signature::ThresholdConfigUpdate;

use crate::{actions::Sighash, constants::AdminTxType};

/// An update to a threshold configuration for a specific role:
/// - adds new members
/// - removes old members
/// - updates the threshold
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MultisigUpdate {
    add_members: Vec<CompressedPublicKey>,
    remove_members: Vec<CompressedPublicKey>,
    new_threshold: NonZero<u8>,
    role: Role,
}

impl<'a> Arbitrary<'a> for MultisigUpdate {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let update = ThresholdConfigUpdate::arbitrary(u)?;
        let role = Role::arbitrary(u)?;
        Ok(Self::new(update, role))
    }
}

impl MultisigUpdate {
    /// Create a `MultisigUpdate` with given config and role.
    pub fn new(config: ThresholdConfigUpdate, role: Role) -> Self {
        let (add_members, remove_members, new_threshold) = config.into_inner();
        Self {
            add_members,
            remove_members,
            new_threshold,
            role,
        }
    }

    /// Borrow the threshold config update.
    pub fn config(&self) -> ThresholdConfigUpdate {
        ThresholdConfigUpdate::new(
            self.add_members.clone(),
            self.remove_members.clone(),
            self.new_threshold,
        )
    }

    /// Get the role this update applies to.
    pub fn role(&self) -> Role {
        self.role
    }

    /// Consume and return the inner config and role.
    pub fn into_inner(self) -> (ThresholdConfigUpdate, Role) {
        (
            ThresholdConfigUpdate::new(self.add_members, self.remove_members, self.new_threshold),
            self.role,
        )
    }
}

impl Sighash for MultisigUpdate {
    fn tx_type(&self) -> AdminTxType {
        match self.role {
            Role::StrataAdministrator => AdminTxType::StrataAdminMultisigUpdate,
            Role::StrataSequencerManager => AdminTxType::StrataSeqManagerMultisigUpdate,
        }
    }

    /// Returns `len(add) ‖ add[0] ‖ … ‖ add[n] ‖ len(rem) ‖ rem[0] ‖ … ‖ rem[m] ‖ threshold`
    /// where lengths are big-endian `u32` and members are 33-byte compressed public keys.
    ///
    /// Only the config is included because the role is already covered by the
    /// [`AdminTxType`] returned from [`tx_type`](Self::tx_type).
    fn sighash_payload(&self) -> Vec<u8> {
        let add = &self.add_members;
        let rem = &self.remove_members;
        let mut buf = Vec::with_capacity(4 + add.len() * 33 + 4 + rem.len() * 33 + 1);
        buf.extend_from_slice(&(add.len() as u32).to_be_bytes());
        for member in add {
            buf.extend_from_slice(&member.serialize());
        }
        buf.extend_from_slice(&(rem.len() as u32).to_be_bytes());
        for member in rem {
            buf.extend_from_slice(&member.serialize());
        }
        buf.push(self.new_threshold.get());
        buf
    }
}
