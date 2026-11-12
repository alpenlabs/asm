//! The Strata ASM specs, one module per spec.

mod v0;
mod v1;
mod v2;

pub use v0::StrataAsmSpec;
pub use v1::StrataAsmSpecV1;
pub use v2::StrataAsmSpecV2;
