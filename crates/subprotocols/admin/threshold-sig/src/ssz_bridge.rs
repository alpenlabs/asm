//! Bridges a domain type to the container generated from `ssz/threshold.ssz`.
//!
//! The schema owns the wire layout. A type states which container represents it and how to
//! convert in both directions, and [`impl_ssz_via_container`] derives [`Encode`] and
//! [`Decode`] from that, so no byte layout is written out by hand.

use ssz::{Decode, DecodeError, Encode};

/// A type whose SSZ encoding is that of its generated container.
pub(crate) trait SszContainer: Sized {
    /// The generated container that defines this type's wire layout.
    type Container: Encode + Decode;

    /// Builds the container that represents `self`.
    ///
    /// # Panics
    ///
    /// Panics if a collection exceeds the bound its container field declares. Every
    /// construction path enforces that bound, so reaching this is a bug in the invariant
    /// rather than bad input.
    fn to_container(&self) -> Self::Container;

    /// Rebuilds the type from a decoded container, re-applying its invariants.
    fn from_container(container: Self::Container) -> Result<Self, DecodeError>;
}

/// Implements [`ssz::Encode`] and [`ssz::Decode`] in terms of [`SszContainer`].
macro_rules! impl_ssz_via_container {
    ($ty:ty) => {
        impl ssz::Encode for $ty {
            fn is_ssz_fixed_len() -> bool {
                <<$ty as $crate::ssz_bridge::SszContainer>::Container as ssz::Encode>::is_ssz_fixed_len()
            }

            fn ssz_fixed_len() -> usize {
                <<$ty as $crate::ssz_bridge::SszContainer>::Container as ssz::Encode>::ssz_fixed_len()
            }

            fn ssz_bytes_len(&self) -> usize {
                ssz::Encode::ssz_bytes_len(
                    &$crate::ssz_bridge::SszContainer::to_container(self),
                )
            }

            fn ssz_append(&self, buf: &mut Vec<u8>) {
                ssz::Encode::ssz_append(
                    &$crate::ssz_bridge::SszContainer::to_container(self),
                    buf,
                )
            }
        }

        impl ssz::Decode for $ty {
            fn is_ssz_fixed_len() -> bool {
                <<$ty as $crate::ssz_bridge::SszContainer>::Container as ssz::Decode>::is_ssz_fixed_len()
            }

            fn ssz_fixed_len() -> usize {
                <<$ty as $crate::ssz_bridge::SszContainer>::Container as ssz::Decode>::ssz_fixed_len()
            }

            fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
                let container = <<$ty as $crate::ssz_bridge::SszContainer>::Container
                    as ssz::Decode>::from_ssz_bytes(bytes)?;
                $crate::ssz_bridge::SszContainer::from_container(container)
            }
        }
    };
}

pub(crate) use impl_ssz_via_container;
