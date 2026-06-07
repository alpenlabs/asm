//! [Sled](https://docs.rs/sled)-backed implementations of the ASM storage
//! traits.
//!
//! Each implementation keeps synchronous inherent methods for the worker, which
//! runs on a sync thread, and delegates to them from the async trait.

mod manifest_mmr;

pub use self::manifest_mmr::SledAsmManifestMmrDb;
