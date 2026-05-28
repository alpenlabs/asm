//! Safe harbour address.
//!
//! A safe harbour is a Bitcoin output script descriptor used to redirect flows
//! under emergency conditions. Activation (via Defcon signals) is restricted to
//! the strata security council; address rotation is restricted to the strata
//! administrator, so the same authority cannot both trigger a sweep and pick
//! its destination. Once activated, the address is frozen — further rotation
//! is rejected so bridge nodes always observe a single destination.

#[cfg(feature = "arbitrary")]
use arbitrary::Arbitrary;
#[cfg(feature = "arbitrary")]
use bitcoin::secp256k1::{Keypair, SECP256K1, SecretKey};
use bitcoin_bosd::{Descriptor, DescriptorType};
use serde::{Deserialize, Serialize, de::Error as _};
use ssz::{Decode as SszDecode, DecodeError};
use ssz_derive::{Decode, Encode};
use thiserror::Error;

/// A safe harbour [`Descriptor`] restricted to taproot (P2TR) outputs.
///
/// Constructible only via [`TryFrom<Descriptor>`]. Deserialization, SSZ
/// decoding, and the `arbitrary`-gated [`Arbitrary`] impl all enforce the
/// P2TR check so the invariant cannot be bypassed by supplying arbitrary
/// wire bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Encode)]
pub struct SafeHarbourAddress(Descriptor);

/// Wire-format wrapper that decodes a descriptor without imposing the P2TR
/// invariant during parsing. The check happens after decoding so [`Deserialize`]
/// and [`SszDecode`] for [`SafeHarbourAddress`] can share the validation in
/// [`TryFrom<Descriptor>`].
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Decode)]
struct SafeHarbourAddressRaw(Descriptor);

impl SafeHarbourAddress {
    /// Returns a reference to the underlying P2TR descriptor.
    pub fn as_descriptor(&self) -> &Descriptor {
        &self.0
    }

    /// Consumes the wrapper and returns the underlying P2TR descriptor.
    pub fn into_descriptor(self) -> Descriptor {
        self.0
    }
}

/// Error returned when constructing a [`SafeHarbourAddress`] from a descriptor
/// whose type tag is not [`DescriptorType::P2tr`].
#[derive(Debug, Error, PartialEq)]
#[error("safe harbour address must be a P2TR descriptor, got {0:?}")]
pub struct NotP2trDescriptor(DescriptorType);

impl TryFrom<Descriptor> for SafeHarbourAddress {
    type Error = NotP2trDescriptor;

    fn try_from(descriptor: Descriptor) -> Result<Self, Self::Error> {
        let type_tag = descriptor.type_tag();
        if type_tag == DescriptorType::P2tr {
            Ok(SafeHarbourAddress(descriptor))
        } else {
            Err(NotP2trDescriptor(type_tag))
        }
    }
}

impl<'de> Deserialize<'de> for SafeHarbourAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let SafeHarbourAddressRaw(descriptor) = SafeHarbourAddressRaw::deserialize(deserializer)?;
        SafeHarbourAddress::try_from(descriptor).map_err(D::Error::custom)
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for SafeHarbourAddress {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        // Derive a P2TR descriptor from a fresh secp256k1 keypair so the
        // x-only pubkey is always on the curve. The only realistic rejection
        // from `SecretKey::from_slice` is the all-zero scalar (overflow is
        // ~2^-128); patch that one case rather than re-drawing entropy.
        let mut secret_bytes = [0u8; 32];
        u.fill_buffer(&mut secret_bytes)?;
        if secret_bytes.iter().all(|&b| b == 0) {
            secret_bytes[31] = 1;
        }
        let secret_key =
            SecretKey::from_slice(&secret_bytes).map_err(|_| arbitrary::Error::IncorrectFormat)?;
        let keypair = Keypair::from_secret_key(SECP256K1, &secret_key);
        let (x_only, _parity) = keypair.x_only_public_key();
        let descriptor = Descriptor::new_p2tr(&x_only.serialize())
            .expect("x-only pubkey from a valid secp256k1 keypair is always a valid P2TR payload");
        Ok(SafeHarbourAddress(descriptor))
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
        SafeHarbourAddress::try_from(descriptor)
            .map_err(|e| DecodeError::BytesInvalid(e.to_string()))
    }
}

/// A safe harbour address with an activation flag. The address is mutable
/// while deactivated and frozen once activated.
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct SafeHarbour {
    address: SafeHarbourAddress,
    activated: bool,
}

impl SafeHarbour {
    /// Creates a new deactivated safe harbour for the given address.
    pub fn new(address: SafeHarbourAddress) -> Self {
        Self {
            address,
            activated: false,
        }
    }

    /// Returns the configured safe harbour address.
    pub fn address(&self) -> &SafeHarbourAddress {
        &self.address
    }

    /// Returns `Some(&address)` when activated, otherwise `None`.
    pub fn active_address(&self) -> Option<&SafeHarbourAddress> {
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
    pub fn update_address(&mut self, address: SafeHarbourAddress) -> bool {
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

    fn non_p2tr_descriptor() -> Descriptor {
        Descriptor::new_p2wpkh(&[0xAA; 20])
    }

    fn p2tr_descriptor_a() -> Descriptor {
        // x-only public key for the generator point G.
        let payload = [
            0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87,
            0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B,
            0x16, 0xF8, 0x17, 0x98,
        ];
        Descriptor::new_p2tr(&payload).expect("valid x-only public key")
    }

    fn p2tr_descriptor_b() -> Descriptor {
        // `[2u8; 32]` happens to be a valid x-only pubkey on secp256k1; see
        // the bitcoin-bosd `Descriptor::new_p2tr` doctest.
        Descriptor::new_p2tr(&[2u8; 32]).expect("valid x-only public key")
    }

    fn safe_harbour_address_a() -> SafeHarbourAddress {
        SafeHarbourAddress::try_from(p2tr_descriptor_a()).expect("p2tr accepted")
    }

    fn safe_harbour_address_b() -> SafeHarbourAddress {
        SafeHarbourAddress::try_from(p2tr_descriptor_b()).expect("p2tr accepted")
    }

    #[test]
    fn new_is_deactivated() {
        let sh = SafeHarbour::new(safe_harbour_address_a());
        assert!(!sh.is_activated());
        assert_eq!(sh.address(), &safe_harbour_address_a());
        assert_eq!(sh.active_address(), None);
    }

    #[test]
    fn set_activated_toggles_flag_and_active_address() {
        let mut sh = SafeHarbour::new(safe_harbour_address_a());

        sh.set_activated(true);
        assert!(sh.is_activated());
        assert_eq!(sh.active_address(), Some(&safe_harbour_address_a()));

        sh.set_activated(false);
        assert!(!sh.is_activated());
        assert_eq!(sh.active_address(), None);
    }

    #[test]
    fn update_address_when_deactivated_succeeds() {
        let mut sh = SafeHarbour::new(safe_harbour_address_a());
        assert!(sh.update_address(safe_harbour_address_b()));
        assert_eq!(sh.address(), &safe_harbour_address_b());
        assert!(!sh.is_activated());
    }

    #[test]
    fn update_address_when_activated_is_rejected() {
        let mut sh = SafeHarbour::new(safe_harbour_address_a());
        sh.set_activated(true);

        assert!(!sh.update_address(safe_harbour_address_b()));
        // Address must remain unchanged when the update is rejected.
        assert_eq!(sh.address(), &safe_harbour_address_a());
        assert!(sh.is_activated());
        assert_eq!(sh.active_address(), Some(&safe_harbour_address_a()));
    }

    #[test]
    fn ssz_roundtrip() {
        let mut sh = SafeHarbour::new(safe_harbour_address_a());
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
        let mut sh = SafeHarbour::new(safe_harbour_address_a());
        sh.set_activated(true);
        let json = serde_json::to_string(&sh).expect("serialize");
        let decoded: SafeHarbour = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(sh, decoded);
        assert!(json.contains("\"activated\":true"));
        assert!(json.contains("\"address\""));
    }

    #[test]
    fn safe_harbour_address_rejects_non_p2tr() {
        let descriptor = non_p2tr_descriptor();
        let expected_tag = descriptor.type_tag();
        let err = SafeHarbourAddress::try_from(descriptor).expect_err("non-p2tr rejected");
        assert_eq!(err, NotP2trDescriptor(expected_tag));
    }

    #[test]
    fn safe_harbour_address_accepts_p2tr() {
        let addr = SafeHarbourAddress::try_from(p2tr_descriptor_a()).expect("p2tr accepted");
        assert_eq!(addr.as_descriptor(), &p2tr_descriptor_a());
    }

    #[test]
    fn safe_harbour_address_ssz_roundtrip() {
        let addr = SafeHarbourAddress::try_from(p2tr_descriptor_a()).expect("p2tr accepted");
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

        let bytes = NonP2tr(non_p2tr_descriptor()).as_ssz_bytes();
        let err = SafeHarbourAddress::from_ssz_bytes(&bytes)
            .expect_err("non-P2TR descriptor must be rejected");
        assert!(matches!(err, ssz::DecodeError::BytesInvalid(_)));
    }

    #[test]
    fn safe_harbour_address_json_roundtrip() {
        let addr = SafeHarbourAddress::try_from(p2tr_descriptor_a()).expect("p2tr accepted");
        let json = serde_json::to_string(&addr).expect("serialize");
        let decoded: SafeHarbourAddress = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(addr, decoded);
    }

    /// JSON deserialization must reject a descriptor whose type is not P2TR,
    /// preserving the invariant against untrusted wire input.
    #[test]
    fn safe_harbour_address_json_rejects_non_p2tr() {
        let json = serde_json::to_string(&non_p2tr_descriptor()).expect("serialize");
        let err = serde_json::from_str::<SafeHarbourAddress>(&json)
            .expect_err("non-P2TR descriptor must be rejected");
        assert!(err.to_string().contains("P2TR"));
    }

    /// The custom `Arbitrary` impl must only ever yield P2TR descriptors,
    /// since constructing a non-P2TR `SafeHarbourAddress` would violate the
    /// type invariant that `new`, `Deserialize`, and `SszDecode` enforce.
    #[cfg(feature = "arbitrary")]
    #[test]
    fn safe_harbour_address_arbitrary_is_always_p2tr() {
        let seed: Vec<u8> = (0..=u8::MAX).collect();
        let mut u = arbitrary::Unstructured::new(&seed);
        let addr = SafeHarbourAddress::arbitrary(&mut u).expect("arbitrary safe harbour address");
        assert_eq!(addr.as_descriptor().type_tag(), DescriptorType::P2tr);
    }
}
