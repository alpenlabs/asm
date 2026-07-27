//! Core type definitions for the Strata administration subprotocol.
//!
//! Holds the governance vocabulary shared by the admin transaction parsing
//! crate, the subprotocol state machine, and ASM instance configuration:
//! authority [`Role`]s, the SPS-50 wire identifiers ([`AdminTxType`],
//! [`UpdateTxType`]), per-update [`ConfirmationDepths`], and the
//! [`AdministrationInitConfig`] genesis configuration.

mod admin_tx;
mod config;
mod confirmation_depth;
mod roles;
mod updates;

pub use admin_tx::AdminTxType;
pub use config::AdministrationInitConfig;
pub use confirmation_depth::ConfirmationDepths;
pub use roles::Role;
pub use updates::UpdateTxType;
