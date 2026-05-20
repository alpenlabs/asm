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

#[cfg(test)]
mod tests {
    use ssz::{Decode, Encode};

    use super::*;

    fn descriptor_a() -> Descriptor {
        Descriptor::new_p2wpkh(&[0xAA; 20])
    }

    fn descriptor_b() -> Descriptor {
        Descriptor::new_p2wpkh(&[0xBB; 20])
    }

    #[test]
    fn new_is_deactivated() {
        let sh = SafeHarbour::new(descriptor_a());
        assert!(!sh.is_activated());
        assert_eq!(sh.address(), &descriptor_a());
        assert_eq!(sh.active_address(), None);
    }

    #[test]
    fn set_activated_toggles_flag_and_active_address() {
        let mut sh = SafeHarbour::new(descriptor_a());

        sh.set_activated(true);
        assert!(sh.is_activated());
        assert_eq!(sh.active_address(), Some(&descriptor_a()));

        sh.set_activated(false);
        assert!(!sh.is_activated());
        assert_eq!(sh.active_address(), None);
    }

    #[test]
    fn update_address_preserves_activation_flag() {
        let mut sh = SafeHarbour::new(descriptor_a());
        sh.update_address(descriptor_b());
        assert_eq!(sh.address(), &descriptor_b());
        assert!(!sh.is_activated());

        sh.set_activated(true);
        sh.update_address(descriptor_a());
        assert_eq!(sh.address(), &descriptor_a());
        // Updating the address must not deactivate an already-active safe harbour.
        assert!(sh.is_activated());
        assert_eq!(sh.active_address(), Some(&descriptor_a()));
    }

    #[test]
    fn ssz_roundtrip() {
        let mut sh = SafeHarbour::new(descriptor_a());
        sh.set_activated(true);
        let bytes = sh.as_ssz_bytes();
        let decoded = SafeHarbour::from_ssz_bytes(&bytes).expect("ssz decode");
        assert_eq!(sh, decoded);
    }

    /// The RPC `getSafeHarbour` endpoint returns `SafeHarbour` as JSON, so the
    /// serde representation must round-trip and stay in sync with what clients
    /// consume.
    #[test]
    fn json_serde_roundtrip() {
        let mut sh = SafeHarbour::new(descriptor_a());
        sh.set_activated(true);
        let json = serde_json::to_string(&sh).expect("serialize");
        let decoded: SafeHarbour = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(sh, decoded);
        assert!(json.contains("\"activated\":true"));
        assert!(json.contains("\"address\""));
    }
}
