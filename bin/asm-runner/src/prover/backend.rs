//! ZK proof backend setup for the runner.
//!
//! Bundles the feature-gated selection of the ZK proof backend in one place:
//! host construction (SP1 or native), and derivation of the [`PredicateKey`]
//! that authorizes proofs from each host. The result is exposed as a single
//! [`ProofBackend`] value that the runner builds once at startup and threads
//! into the proof orchestrator and the input builder.

use anyhow::{Result, bail};
use strata_predicate::{PredicateKey, PredicateTypeId};
use zkaleido::{ZkVm, ZkVmHost};
#[cfg(feature = "sp1")]
use {
    anyhow::Context,
    sp1_sdk::{HashableKey, SP1VerifyingKey},
    sp1_verifier::GROTH16_VK_BYTES,
    zkaleido_sp1_groth16_verifier::SP1Groth16Verifier,
    zkaleido_sp1_host::SP1Host,
};

/// Concrete host type used by the proof orchestrator.
///
/// Resolves to [`SP1Host`] when the `sp1` feature is enabled, otherwise to
/// the in-process [`zkaleido_native_adapter::NativeHost`].
#[cfg(feature = "sp1")]
pub(crate) type ProofHost = SP1Host;

#[cfg(not(feature = "sp1"))]
pub(crate) type ProofHost = zkaleido_native_adapter::NativeHost;

/// ZK proof backend used by the runner.
///
/// Bundles the `(asm, moho)` host pair together with the [`PredicateKey`] that
/// each one's proofs verify against. Constructed once at startup via
/// [`ProofBackend::new`] and consumed by the proof orchestrator (hosts) and
/// the input builder (predicates).
#[derive(Debug)]
pub(crate) struct ProofBackend {
    pub(crate) asm_host: ProofHost,
    pub(crate) moho_host: ProofHost,
    pub(crate) asm_predicate: PredicateKey,
    pub(crate) moho_predicate: PredicateKey,
}

impl ProofBackend {
    /// Builds the ZK proof backend.
    ///
    /// Constructs both proof hosts and resolves the [`PredicateKey`] each
    /// host's proofs verify against.
    ///
    /// # Errors
    ///
    /// Returns an error if either host cannot be constructed (e.g. a guest
    /// ELF cannot be read in `sp1` builds) or if either host's verifying key
    /// cannot be turned into a [`PredicateKey`].
    pub(crate) fn new() -> Result<Self> {
        let (asm_host, moho_host) = build_proof_hosts()?;
        let asm_predicate = resolve_predicate(&asm_host)?;
        let moho_predicate = resolve_predicate(&moho_host)?;
        Ok(Self {
            asm_host,
            moho_host,
            asm_predicate,
            moho_predicate,
        })
    }
}

/// Builds the `(asm, moho)` host pair used by the proof orchestrator.
///
/// With the `sp1` feature, both hosts are SP1 hosts initialized from the
/// embedded guest ELFs and capable of dispatching proofs to a remote SP1
/// prover. Without the `sp1` feature, both hosts are native (in-process)
/// hosts that simply execute the proof programs and do not produce real
/// cryptographic proofs.
///
/// # Errors
///
/// With the `sp1` feature, returns an error if either guest ELF cannot be
/// read from the path baked into the guest builder.
#[cfg(feature = "sp1")]
fn build_proof_hosts() -> Result<(ProofHost, ProofHost)> {
    use std::fs;

    use strata_asm_sp1_guest_builder::{ASM_ELF_PATH, MOHO_ELF_PATH};

    let asm_elf = fs::read(ASM_ELF_PATH)
        .with_context(|| format!("failed to read ASM guest ELF at {ASM_ELF_PATH}"))?;
    let moho_elf = fs::read(MOHO_ELF_PATH)
        .with_context(|| format!("failed to read Moho guest ELF at {MOHO_ELF_PATH}"))?;

    Ok((SP1Host::init(&asm_elf), SP1Host::init(&moho_elf)))
}

#[cfg(not(feature = "sp1"))]
fn build_proof_hosts() -> Result<(ProofHost, ProofHost)> {
    use moho_recursive_proof::MohoRecursiveProgram;
    use strata_asm_proof_impl::program::AsmStfProofProgram;

    Ok((
        AsmStfProofProgram::native_host(),
        MohoRecursiveProgram::native_host(),
    ))
}

/// Resolves the [`PredicateKey`] for proofs produced by `host`.
///
/// The returned key carries both the predicate type (matching the host's
/// [`ZkVm`] backend) and the encoded verifying-key material required to
/// validate proofs from that host.
///
/// # Errors
///
/// - For SP1 hosts, returns an error if the host's verifying key cannot be deserialized into an
///   `SP1VerifyingKey` or if the SP1 Groth16 verifier cannot be loaded for the resulting program
///   hash.
/// - For Risc0 hosts, returns an error because predicate resolution is not yet implemented for that
///   backend.
/// - When built without the `sp1` feature, an SP1 host returns an error because the SP1
///   verifying-key handling is gated behind that feature.
fn resolve_predicate(host: &impl ZkVmHost) -> Result<PredicateKey> {
    match host.zkvm() {
        // Native execution does not produce a real cryptographic proof; the
        // predicate simply carries the verifying-key bytes verbatim under the
        // BIP-340 Schnorr type as a placeholder identifier.
        ZkVm::Native => Ok(PredicateKey::new(
            PredicateTypeId::Bip340Schnorr,
            host.vk().as_bytes().to_vec(),
        )),

        // SP1 proofs are wrapped in a Groth16 proof, so the on-chain
        // predicate must identify the SP1 Groth16 verifying key (not the SP1
        // program vk itself). The conversion is:
        //   1. Decode the SP1 verifying key from the host's raw bytes.
        //   2. Hash it to obtain the program commitment expected by the Groth16 verifier.
        //   3. Load the matching Groth16 verifier and serialize its vk into the predicate key.
        #[cfg(feature = "sp1")]
        ZkVm::SP1 => {
            let vk = host.vk();
            let sp1_vk: SP1VerifyingKey = bincode::deserialize(vk.as_bytes())
                .context("failed to deserialize SP1 verifying key")?;

            let verifier = SP1Groth16Verifier::load(&GROTH16_VK_BYTES, sp1_vk.hash_bytes())
                .context("failed to load SP1 Groth16 verifier")?;

            Ok(PredicateKey::new(
                PredicateTypeId::Sp1Groth16,
                verifier.vk.to_uncompressed_bytes(),
            ))
        }
        #[cfg(not(feature = "sp1"))]
        ZkVm::SP1 => bail!("SP1 predicate key resolution requires the `sp1` feature"),

        // Risc0 support is not yet wired up; surface a clear error rather
        // than panicking so callers can fail gracefully.
        ZkVm::Risc0 => bail!("predicate key resolution is not implemented for Risc0"),
    }
}
