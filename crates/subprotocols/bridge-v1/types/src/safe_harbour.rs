//! Safe harbour address.
//!
//! A safe harbour is a Bitcoin output script descriptor used to redirect flows
//! under emergency conditions. Activation (via Defcon signals) is restricted to
//! the strata security council; address rotation is restricted to the strata
//! administrator, so the same authority cannot both trigger a sweep and pick
//! its destination. Once activated, the address is frozen — further rotation
//! is rejected so bridge nodes always observe a single destination.

use arbitrary::Arbitrary;
use bitcoin_bosd::{Descriptor, DescriptorType};
use serde::{Deserialize, Serialize};
use ssz::{Decode as SszDecode, DecodeError};
use ssz_derive::{Decode, Encode};
/// A safe harbour [`Descriptor`] restricted to taproot (P2TR) outputs.
///
/// Constructible only via [`SafeHarbourAddress::new`]. Both [`Deserialize`]
/// and [`SszDecode`] re-apply the P2TR check so the invariant cannot be
/// bypassed by supplying arbitrary wire bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Encode)]
pub struct SafeHarbourAddress(Descriptor);

/// Wire-format wrapper that decodes a descriptor without imposing the P2TR
/// invariant during parsing. The check happens after decoding so [`Deserialize`]
/// and [`SszDecode`] for [`SafeHarbourAddress`] can share the validation in
/// [`SafeHarbourAddress::new`].
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Decode)]
struct SafeHarbourAddressRaw(Descriptor);

impl SafeHarbourAddress {
    /// Wraps `descriptor` if its type tag is [`DescriptorType::P2tr`].
    pub fn new(descriptor: Descriptor) -> Option<Self> {
        if descriptor.type_tag() == DescriptorType::P2tr {
            Some(SafeHarbourAddress(descriptor))
        } else {
            None
        }
    }

    /// Returns a reference to the underlying P2TR descriptor.
    pub fn as_descriptor(&self) -> &Descriptor {
        &self.0
    }
}

impl<'de> Deserialize<'de> for SafeHarbourAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let SafeHarbourAddressRaw(descriptor) = SafeHarbourAddressRaw::deserialize(deserializer)?;
        SafeHarbourAddress::new(descriptor).ok_or_else(|| {
            serde::de::Error::custom("safe harbour address must be a P2TR descriptor")
        })
    }
}

impl SszDecode for SafeHarbourAddress {
    fn is_ssz_fixed_len() -> bool {
        SafeHarbourAddressRaw::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        SafeHarbourAddressRaw::ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let SafeHarbourAddressRaw(descriptor) = SafeHarbourAddressRaw::from_ssz_bytes(bytes)?;
        SafeHarbourAddress::new(descriptor).ok_or_else(|| {
            DecodeError::BytesInvalid("safe harbour address must be a P2TR descriptor".to_string())
        })
    }
}

/// A safe harbour address with an activation flag. The address is mutable
/// while deactivated and frozen once activated.
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

    /// Updates the address if the safe harbour is not currently activated.
    ///
    /// Returns `true` if the address was updated, `false` if the update was
    /// rejected because the safe harbour is already activated. The address
    /// is frozen on activation so bridge nodes always observe a single
    /// destination.
    pub fn update_address(&mut self, address: Descriptor) -> bool {
        if self.activated {
            return false;
        }
        self.address = address;
        true
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
    fn update_address_when_deactivated_succeeds() {
        let mut sh = SafeHarbour::new(descriptor_a());
        assert!(sh.update_address(descriptor_b()));
        assert_eq!(sh.address(), &descriptor_b());
        assert!(!sh.is_activated());
    }

    #[test]
    fn update_address_when_activated_is_rejected() {
        let mut sh = SafeHarbour::new(descriptor_a());
        sh.set_activated(true);

        assert!(!sh.update_address(descriptor_b()));
        // Address must remain unchanged when the update is rejected.
        assert_eq!(sh.address(), &descriptor_a());
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

    fn p2tr_descriptor() -> Descriptor {
        // x-only public key for the generator point G.
        let payload = [
            0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87,
            0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B,
            0x16, 0xF8, 0x17, 0x98,
        ];
        Descriptor::new_p2tr(&payload).expect("valid x-only public key")
    }

    #[test]
    fn safe_harbour_address_rejects_non_p2tr() {
        assert!(SafeHarbourAddress::new(descriptor_a()).is_none());
    }

    #[test]
    fn safe_harbour_address_accepts_p2tr() {
        let addr = SafeHarbourAddress::new(p2tr_descriptor()).expect("p2tr accepted");
        assert_eq!(addr.as_descriptor(), &p2tr_descriptor());
    }

    #[test]
    fn safe_harbour_address_ssz_roundtrip() {
        let addr = SafeHarbourAddress::new(p2tr_descriptor()).expect("p2tr accepted");
        let bytes = addr.as_ssz_bytes();
        let decoded = SafeHarbourAddress::from_ssz_bytes(&bytes).expect("ssz decode");
        assert_eq!(addr, decoded);
    }

    /// SSZ decoding must reject wire bytes whose inner descriptor is not P2TR,
    /// even though those bytes parse as a valid `Descriptor`.
    #[test]
    fn safe_harbour_address_ssz_rejects_non_p2tr() {
        #[derive(Encode)]
        struct NonP2tr(Descriptor);

        let bytes = NonP2tr(descriptor_a()).as_ssz_bytes();
        let err = SafeHarbourAddress::from_ssz_bytes(&bytes)
            .expect_err("non-P2TR descriptor must be rejected");
        assert!(matches!(err, ssz::DecodeError::BytesInvalid(_)));
    }

    #[test]
    fn safe_harbour_address_json_roundtrip() {
        let addr = SafeHarbourAddress::new(p2tr_descriptor()).expect("p2tr accepted");
        let json = serde_json::to_string(&addr).expect("serialize");
        let decoded: SafeHarbourAddress = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(addr, decoded);
    }

    /// JSON deserialization must reject a descriptor whose type is not P2TR,
    /// preserving the invariant against untrusted wire input.
    #[test]
    fn safe_harbour_address_json_rejects_non_p2tr() {
        let json = serde_json::to_string(&descriptor_a()).expect("serialize");
        let err = serde_json::from_str::<SafeHarbourAddress>(&json)
            .expect_err("non-P2TR descriptor must be rejected");
        assert!(err.to_string().contains("P2TR"));
    }
}
