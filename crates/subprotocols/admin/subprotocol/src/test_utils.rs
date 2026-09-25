//! Helpers shared by the test modules in this crate.

use std::num::NonZero;

use bitcoin::{
    Network,
    secp256k1::{PublicKey, Secp256k1, SecretKey},
};
use rand::rngs::OsRng;
use strata_asm_admin_threshold_sig::P2wpkhAddress;
use strata_asm_admin_types::{ConfirmationDepths, UncheckedThresholdConfig};

/// Network the test parameters name signer addresses on.
pub(crate) const TEST_NETWORK: Network = Network::Regtest;

/// Generates `count` fresh signing keys.
pub(crate) fn new_keys(count: usize) -> Vec<SecretKey> {
    (0..count).map(|_| SecretKey::new(&mut OsRng)).collect()
}

/// Builds a parameter-file signer set holding the addresses of `secret_keys`.
pub(crate) fn signer_config(secret_keys: &[SecretKey], threshold: u8) -> UncheckedThresholdConfig {
    let secp = Secp256k1::new();
    let signers = secret_keys
        .iter()
        .map(|sk| {
            P2wpkhAddress::from_pubkey(&PublicKey::from_secret_key(&secp, sk))
                .to_address(TEST_NETWORK)
                .into_unchecked()
        })
        .collect();

    UncheckedThresholdConfig::try_new(signers, NonZero::new(threshold).expect("non-zero"))
        .expect("test signer set is valid")
}

/// Builds confirmation depths that use `depth` for every update variant.
pub(crate) fn uniform_confirmation_depths(depth: u16) -> ConfirmationDepths {
    ConfirmationDepths {
        strata_admin_multisig_update: depth,
        strata_seq_manager_multisig_update: depth,
        alpen_admin_multisig_update: depth,
        strata_security_council_multisig_update: depth,
        operator_update: depth,
        sequencer_update: depth,
        ol_stf_vk_update: depth,
        asm_stf_vk_update: depth,
        ee_stf_vk_update: depth,
        defcon3: depth,
        safe_harbour_address_update: depth,
    }
}
