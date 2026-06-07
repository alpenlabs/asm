//! Configuration for the proof orchestrator.

use std::{fmt, path::PathBuf, time::Duration};

use k256::schnorr::SigningKey;
use serde::{Deserialize, Serialize};

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
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[expect(
    clippy::large_enum_variant,
    reason = "BackendConfig is parsed once at startup; boxing a SigningKey to save a few bytes on a singleton value is not worth the indirection"
)]
pub enum BackendConfig {
    /// SP1 backend. Loads the ASM and Moho guest ELFs from explicit paths at startup.
    Sp1 {
        asm_elf_path: PathBuf,
        moho_elf_path: PathBuf,
    },

    /// Native (in-process) backend. Each signing key fixes the predicate
    /// identity of its host: a native host's verifying key (derived from the
    /// configured signing key) is what `resolve_predicate` packs into the
    /// `PredicateKey`. Keys are parsed and validated as BIP-340 Schnorr
    /// signing keys at config load, so an invalid key fails startup rather
    /// than later in the proving path.
    Native {
        #[serde(with = "hex_signing_key")]
        asm_schnorr_signing_key: SigningKey,
        #[serde(with = "hex_signing_key")]
        moho_schnorr_signing_key: SigningKey,
    },
}

impl fmt::Debug for BackendConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sp1 {
                asm_elf_path,
                moho_elf_path,
            } => f
                .debug_struct("Sp1")
                .field("asm_elf_path", asm_elf_path)
                .field("moho_elf_path", moho_elf_path)
                .finish(),
            Self::Native { .. } => f
                .debug_struct("Native")
                .field("asm_schnorr_signing_key", &"<redacted>")
                .field("moho_schnorr_signing_key", &"<redacted>")
                .finish(),
        }
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
