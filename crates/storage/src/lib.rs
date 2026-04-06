//! Lightweight sled-backed storage for the ASM runner.
//!
//! Replaces alpen's `strata-state`, `strata-storage`, and `strata-db-store-sled`
//! with a self-contained implementation that has zero alpen dependencies.
//!
//! Three storage backends:
//! - [`AsmStateDb`] — anchor states + aux data, keyed by L1 block commitment
//! - [`MmrDb`] — manifest hash MMR (append, prove, query)

mod mmr;
mod state;

pub use mmr::MmrDb;
pub use state::AsmStateDb;
