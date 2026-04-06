use musig2::{KeyAggContext, errors::KeyAggError};
use secp256k1::{PublicKey, XOnlyPublicKey};

use crate::EvenPublicKey;

#[derive(Debug, thiserror::Error)]
pub enum Musig2Error {
    #[error("no keys provided for aggregation")]
    EmptyKeys,

    #[error("too many keys: {0} exceeds u32::MAX")]
    TooManyKeys(usize),

    #[error("aggregation context creation failed: {0}")]
    AggregationContextFailed(#[from] KeyAggError),
}

/// Aggregates a collection of Schnorr public keys using MuSig2 key aggregation.
///
/// Unlike [`KeyAggContext::new`] which panics when given an empty or oversized key set,
/// this function validates inputs upfront and returns errors instead, making it suitable
/// for use in no-panic contexts.
pub fn aggregate_schnorr_keys<'k>(
    keys: impl Iterator<Item = &'k EvenPublicKey>,
) -> Result<XOnlyPublicKey, Musig2Error> {
    let public_keys: Vec<PublicKey> = keys.map(|k| PublicKey::from(*k)).collect();

    if public_keys.is_empty() {
        return Err(Musig2Error::EmptyKeys);
    }
    if public_keys.len() > u32::MAX as usize {
        return Err(Musig2Error::TooManyKeys(public_keys.len()));
    }

    let agg_pubkey = KeyAggContext::new(public_keys)?
        .aggregated_pubkey::<PublicKey>()
        .x_only_public_key()
        .0;

    Ok(agg_pubkey)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use secp256k1::{SECP256K1, SecretKey};

    use super::*;

    fn arb_even_public_key() -> impl Strategy<Value = EvenPublicKey> {
        prop::array::uniform32(any::<u8>()).prop_filter_map("valid secret key", |bytes| {
            SecretKey::from_slice(&bytes)
                .ok()
                .map(|sk| EvenPublicKey::from(sk.public_key(SECP256K1)))
        })
    }

    proptest! {
        #[test]
        fn aggregate_schnorr_keys_never_panics(keys in prop::collection::vec(arb_even_public_key(), 0..=50)) {
            let result = aggregate_schnorr_keys(keys.iter());
            if keys.is_empty() {
                prop_assert!(matches!(result, Err(Musig2Error::EmptyKeys)));
            } else {
                prop_assert!(result.is_ok());
            }
        }
    }
}
