use std::fmt;

#[cfg(feature = "arbitrary")]
use arbitrary::Arbitrary;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};

/// Roles with authority in the administration subprotocol.
#[derive(
    Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Encode, Decode,
)]
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[repr(u8)]
#[ssz(enum_behaviour = "tag")]
pub enum Role {
    /// The multisig authority that has exclusive ability to:
    /// 1. update (add/remove) bridge signers
    /// 2. update (add/remove) bridge operators
    /// 3. update the definition of what is considered a valid bridge deposit address for:
    ///    - registering deposit UTXOs
    ///    - accepting and minting bridge deposits
    ///    - assigning registered UTXOs to withdrawal requests
    /// 4. update the verifying key for the OL STF
    StrataAdministrator,

    /// The multisig authority that has exclusive ability to change the canonical
    /// public key of the default orchestration layer sequencer.
    StrataSequencerManager,

    /// The multisig authority that has exclusive ability to update the `update_vk`
    /// (predicate key) of EE snark accounts, emitting an `EePredicateKeyUpdate`
    /// log that the OL STF applies during manifest processing.
    AlpenAdministrator,
}

impl Role {
    /// Canonical name used in the signing-message payload.
    ///
    /// Must remain byte-stable: external signers (hardware wallets, signing services) hash
    /// the rendered payload, so changing these labels invalidates already-signed messages.
    pub fn name(&self) -> &'static str {
        match self {
            Role::StrataAdministrator => "Strata Administrator",
            Role::StrataSequencerManager => "Strata Sequencer Manager",
            Role::AlpenAdministrator => "Alpen Administrator",
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}
