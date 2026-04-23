//! Safe harbour address management.
//!
//! A safe harbour is a predefined Bitcoin output script descriptor that can be
//! activated by the security council (admin multisig) to redirect flows under
//! emergency conditions. The address is fixed at bridge initialization; only the
//! activation flag changes at runtime.

use arbitrary::Arbitrary;
use bitcoin_bosd::Descriptor;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};

/// A predefined safe harbour address with an activation flag.
///
/// The [`Descriptor`] is set once (via the bridge init config) and cannot be
/// changed at runtime. Activation is toggled by the admin multisig.
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
}
