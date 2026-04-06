use arbitrary::{Arbitrary, Unstructured};
use secp256k1::{PublicKey, SECP256K1, SecretKey};

use crate::EvenPublicKey;

impl<'a> Arbitrary<'a> for EvenPublicKey {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let mut sk_bytes: [u8; 32] = u.arbitrary()?;
        // Clamp the first byte to 0xFE so the value is always below the
        // secp256k1 curve order (which starts with 0xFF), and set the last bit
        // to ensure the scalar is non-zero.
        sk_bytes[0] &= 0xFE;
        sk_bytes[31] |= 1;
        let sk =
            SecretKey::from_slice(&sk_bytes).expect("clamped bytes are always a valid secret key");
        let pk = PublicKey::from_secret_key(SECP256K1, &sk);
        Ok(EvenPublicKey::from(pk))
    }
}

#[cfg(test)]
mod tests {
    use proptest::{collection::vec, num::u8, proptest};

    use super::*;
    use crate::EvenPublicKey;

    proptest! {
        #[test]
        fn test_arbitrary_never_fails(seed in vec(u8::ANY, 64)) {
            let mut u = Unstructured::new(&seed);
            let result = EvenPublicKey::arbitrary(&mut u);
            proptest::prop_assert!(result.is_ok(), "arbitrary should never return IncorrectFormat");
        }
    }
}
