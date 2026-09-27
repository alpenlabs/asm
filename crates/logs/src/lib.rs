//! # ASM Log Types
//!
//! This crate provides structured log types for the Anchor State Machine (ASM) in the Strata
//! protocol. It defines various log entry types that capture important events within the system.

pub mod asm_stf;
pub mod checkpoint;
mod checkpoint_predicate_enacted;
pub mod constants;
pub mod deposit;
mod ee_predicate_update;
pub mod export;

pub use asm_stf::{extract_next_predicate_from_logs, AsmStfUpdate};
pub use checkpoint::CheckpointTipUpdate;
pub use checkpoint_predicate_enacted::CheckpointPredicateEnacted;
pub use deposit::DepositLog;
pub use ee_predicate_update::EePredicateKeyUpdate;
pub use export::{ExportExtraDataUpdate, NewExportEntry};
