//! # strata-asm-moho-worker
//!
//! A subscription-driven worker that materializes per-block
//! [`MohoState`](moho_types::MohoState) from the Strata ASM.
//!
//! The worker subscribes to the ASM worker's per-block commit stream
//! ([`Subscription<L1BlockCommitment>`](strata_asm_worker::Subscription)) and,
//! for each committed block, derives the Moho state from the ASM anchor state
//! the ASM worker already persisted, chained onto the Moho state of the block's
//! parent, then stores it — together with the per-container export-entry leaves
//! the state's `ExportState` MMR commits to. It runs no chain view of its own:
//! it folds each commit onto its resolved parent, so it follows L1 reorgs rather
//! than assuming the commits arrive in unbroken height order.
//!
//! Storage is supplied by the caller through [`MohoWorkerContext`] — read access
//! to ASM anchor states ([`AsmStateProvider`]), L1 block ancestry
//! ([`L1ProviderContext`]), persistence for the derived Moho states
//! ([`MohoStateStore`]), and persistence for the export-entry leaves
//! ([`ExportEntryStore`]) — mirroring how `strata-asm-worker` takes a
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
pub use service::{MohoWorkerService, MohoWorkerStatus, sync_to_tip};
pub use state::MohoWorkerServiceState;
pub use traits::{
    AsmStateProvider, ExportEntryStore, L1ProviderContext, MohoStateStore, MohoWorkerContext,
};
