//! Field adapters for `#[ssz(with = "...")]`.
//!
//! `ssz_derive` needs one of these for a field whose type has no `Encode`/`Decode` impl of
//! its own. The attribute takes a bare module name, so the module has to be in scope at the
//! derive site.

/// Encodes a [`NonZero<u8>`](std::num::NonZero) as its plain `u8`.
///
/// Zero is the one bit pattern the niche cannot hold, so decoding rejects it. This is the
/// only invariant of these types that survives decoding; the rest live in the constructors.
pub mod non_zero_u8 {
    /// Encoding half of the adapter.
    pub mod encode {
        use std::num::NonZero;

        use ssz::Encode;

        pub fn is_ssz_fixed_len() -> bool {
            <u8 as Encode>::is_ssz_fixed_len()
        }

        pub fn ssz_fixed_len() -> usize {
            <u8 as Encode>::ssz_fixed_len()
        }

        pub fn ssz_bytes_len(value: &NonZero<u8>) -> usize {
            value.get().ssz_bytes_len()
        }

        pub fn ssz_append(value: &NonZero<u8>, buf: &mut Vec<u8>) {
            value.get().ssz_append(buf);
        }
    }

    /// Decoding half of the adapter.
    pub mod decode {
        use std::num::NonZero;

        use ssz::{Decode, DecodeError};

        pub fn is_ssz_fixed_len() -> bool {
            <u8 as Decode>::is_ssz_fixed_len()
        }

        pub fn ssz_fixed_len() -> usize {
            <u8 as Decode>::ssz_fixed_len()
        }

        pub fn from_ssz_bytes(bytes: &[u8]) -> Result<NonZero<u8>, DecodeError> {
            let value = u8::from_ssz_bytes(bytes)?;
            NonZero::new(value)
                .ok_or_else(|| DecodeError::BytesInvalid("value must be non-zero".into()))
        }
    }
}
