//! Configuration for the proof orchestrator.

use std::{fmt, path::PathBuf, time::Duration};

use k256::schnorr::SigningKey;
use serde::{Deserialize, Serialize};
use strata_asm_common::StfParams;

/// Configuration for the proof orchestrator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrchestratorConfig {
    /// Interval between orchestrator ticks.
    pub tick_interval: Duration,

    /// Maximum number of concurrent proof jobs in flight.
    pub max_concurrent_proofs: usize,

    /// Path to the proof database (SledProofDb).
    pub proof_db_path: PathBuf,

    /// Which proof backend to construct at startup, plus its configuration.
    pub backend: BackendConfig,
}

/// Backend-specific orchestrator configuration.
///
/// Tagged with `kind` so the same config schema is valid regardless of
/// which features the binary was built with. If the selected variant does
/// not match the build (e.g. `sp1` requested in a binary built without the
/// `sp1` feature), [`ProofBackend::new`](crate::ProofBackend::new) surfaces a
/// startup error.
///
/// Both variants take a *list* of ASM proving artifacts so the prover can span
/// an ASM VK upgrade: each block's step proof is produced by the host whose
/// predicate matches the parent `MohoState`'s `next_predicate`. **Entry 0 is
/// the genesis-time artifact** — its predicate seeds the genesis Moho state.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BackendConfig {
    /// SP1 backend. Loads the ASM and Moho guest ELFs from explicit paths at
    /// startup. Each ASM ELF bakes its own STF params, so a path is all an
    /// entry needs.
    Sp1 {
        asm_elf_paths: Vec<PathBuf>,
        moho_elf_path: PathBuf,
    },

    /// Native (in-process) backend. Each signing key fixes the predicate
    /// identity of its host: a native host's verifying key (derived from the
    /// configured signing key) is what `resolve_predicate` packs into the
    /// `PredicateKey`. Keys are parsed and validated as BIP-340 Schnorr
    /// signing keys at config load, so an invalid key fails startup rather
    /// than later in the proving path.
    Native {
        asm_entries: Vec<NativeAsmEntry>,
        #[serde(with = "hex_signing_key")]
        moho_schnorr_signing_key: SigningKey,
    },
}

/// One ASM proving artifact of the native backend.
///
/// Carries the STF params next to the signing key because a native host is the
/// stand-in for a guest ELF: where an ELF hardcodes its params (committing to
/// them through its VK), the native host bakes this entry's params into its
/// execution closure. Pre-/post-fork entries therefore differ in both key and
/// schedule, faithfully simulating two separately built guests.
#[derive(Clone, Serialize, Deserialize)]
pub struct NativeAsmEntry {
    #[serde(with = "hex_signing_key")]
    pub schnorr_signing_key: SigningKey,
    pub stf_params: StfParams,
}

impl fmt::Debug for BackendConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sp1 {
                asm_elf_paths,
                moho_elf_path,
            } => f
                .debug_struct("Sp1")
                .field("asm_elf_paths", asm_elf_paths)
                .field("moho_elf_path", moho_elf_path)
                .finish(),
            Self::Native { asm_entries, .. } => f
                .debug_struct("Native")
                .field("asm_entries", asm_entries)
                .field("moho_schnorr_signing_key", &"<redacted>")
                .finish(),
        }
    }
}

impl fmt::Debug for NativeAsmEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeAsmEntry")
            .field("schnorr_signing_key", &"<redacted>")
            .field("stf_params", &self.stf_params)
            .finish()
    }
}

mod hex_signing_key {
    use k256::schnorr::SigningKey;
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    pub(super) fn serialize<S: Serializer>(key: &SigningKey, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(key.to_bytes()))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<SigningKey, D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(D::Error::custom)?;
        SigningKey::from_bytes(&bytes).map_err(D::Error::custom)
    }
}
