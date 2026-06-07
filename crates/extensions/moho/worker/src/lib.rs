//! # strata-asm-moho-worker
//!
//! A subscription-driven worker that materializes per-block
//! [`MohoState`](moho_types::MohoState) from the Strata ASM.
//!
//! The worker subscribes to the ASM worker's per-block commit stream
//! ([`Subscription<L1BlockCommitment>`](strata_asm_worker::Subscription)) and,
//! for each committed block, derives the Moho state from the ASM anchor state
//! the ASM worker already persisted, then stores it. It runs no chain view of
//! its own: it is a deterministic forward-only fold over whatever block sequence
//! the ASM worker commits.
//!
//! Storage is supplied by the caller through [`MohoWorkerContext`] — read access
//! to ASM anchor states ([`AsmStateProvider`]) plus persistence for the derived
//! Moho states ([`MohoStateStore`]) — mirroring how `strata-asm-worker` takes a
//! [`WorkerContext`](strata_asm_worker::WorkerContext).

mod builder;
mod compute;
mod constants;
mod errors;
mod handle;
mod service;
mod state;
mod traits;

pub use builder::MohoWorkerBuilder;
pub use errors::{MohoWorkerError, MohoWorkerResult};
pub use handle::MohoWorkerHandle;
pub use service::{MohoWorkerService, MohoWorkerStatus};
pub use state::MohoWorkerServiceState;
pub use traits::{AsmStateProvider, MohoStateStore, MohoWorkerContext};
