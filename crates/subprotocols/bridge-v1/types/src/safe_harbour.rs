//! Safe harbour address.
//!
//! A safe harbour is a Bitcoin output script descriptor used to redirect flows
//! under emergency conditions. Activation is restricted to the strata security
//! council; the address itself can be changed by the strata administrator.

use arbitrary::Arbitrary;
use bitcoin_bosd::Descriptor;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};

/// A safe harbour address with an activation flag.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Arbitrary, Encode, Decode)]
pub struct SafeHarbour {
    address: Descriptor,
    activated: bool,
}

impl SafeHarbour {
    /// Creates a new deactivated safe harbour for the given address.
    pub fn new(address: Descriptor) -> Self {
        Self {
            address,
            activated: false,
        }
    }

    /// Returns the configured safe harbour address.
    pub fn address(&self) -> &Descriptor {
        &self.address
    }

    /// Returns `Some(&address)` when activated, otherwise `None`.
    pub fn active_address(&self) -> Option<&Descriptor> {
        self.activated.then_some(&self.address)
    }

    /// Returns whether the safe harbour is currently activated.
    pub fn is_activated(&self) -> bool {
        self.activated
    }

    /// Sets the activation flag.
    pub fn set_activated(&mut self, activated: bool) {
        self.activated = activated;
    }

    /// Updates the address
    pub fn update_address(&mut self, address: Descriptor) {
        self.address = address
    }
}
