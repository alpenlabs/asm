//! Checks over a whole [`AsmGenesisParams`] that no single configuration can make on its own.
//!
//! Every subprotocol configuration validates itself as it deserializes. What is left are the
//! questions that need the anchor, or another subprotocol's configuration, to answer.
//! [`AsmGenesisParams`] runs those as part of its own deserialization, so a parameter file that
//! parses has already been checked.

use strata_asm_admin_types::SignerNetworkMismatch;
use strata_asm_bridge_types::SafeHarborNetworkMismatch;
use strata_asm_checkpoint_types::CheckpointGenesisHeightMismatch;
use thiserror::Error;

use crate::genesis::AsmGenesisParams;

impl AsmGenesisParams {
    /// Checks the invariants that span the whole genesis parameter set.
    ///
    /// Run as part of deserialization, which is where these values come from.
    ///
    /// # Errors
    ///
    /// Returns the first invariant that does not hold.
    pub(crate) fn check_invariants(&self) -> Result<(), InvalidAsmGenesisParams> {
        if let Some(config) = self.admin_config() {
            config.check_signer_networks(self.anchor.network)?;
        }

        if let Some(config) = self.bridge_config() {
            config.check_safe_harbor_network(self.anchor.network)?;
        }

        if let Some(config) = self.checkpoint_config() {
            config.check_genesis_l1_height(self.anchor.block.height())?;
        }

        Ok(())
    }
}

/// An invariant spanning the whole genesis parameter set that does not hold.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum InvalidAsmGenesisParams {
    /// An administration signer was written as an address on another network.
    #[error(transparent)]
    AdminSignerNetwork(#[from] SignerNetworkMismatch),

    /// The bridge safe harbor was written as an address on another network.
    #[error(transparent)]
    BridgeSafeHarborNetwork(#[from] SafeHarborNetworkMismatch),

    /// The checkpoint genesis L1 height is not the height of the L1 anchor.
    #[error(transparent)]
    CheckpointGenesisHeight(#[from] CheckpointGenesisHeightMismatch),
}

#[cfg(test)]
mod tests {
    use bitcoin::Network;

    use super::*;
    use crate::test_fixtures::regtest_params_json;

    /// A signer written for another network is what this check exists to catch: the program
    /// would authorize the same key, but the file and the chain disagree about which
    /// network the operator was looking at.
    #[test]
    fn check_invariants_rejects_a_signer_on_another_network() {
        let mut params: AsmGenesisParams =
            serde_json::from_str(regtest_params_json()).expect("fixture deserializes");
        params.anchor.network = Network::Bitcoin;

        assert_eq!(
            params.check_invariants().unwrap_err().to_string(),
            "Strata Administrator signer at index 0 is not an address on bitcoin"
        );
    }

    /// The check runs as the file is read, so a mismatched file never becomes an
    /// [`AsmGenesisParams`] in the first place.
    #[test]
    fn deserialize_rejects_a_signer_on_another_network() {
        let json =
            regtest_params_json().replace(r#""network": "regtest""#, r#""network": "bitcoin""#);

        let error = serde_json::from_str::<AsmGenesisParams>(&json)
            .expect_err("regtest signers do not belong on a mainnet anchor");

        assert!(
            error
                .to_string()
                .contains("signer at index 0 is not an address on bitcoin"),
            "unexpected error: {error}"
        );
    }

    /// The checkpoint genesis tip and the manifest accumulator must start from the same L1
    /// block, or the first checkpoint's coverage lands outside what the accumulator holds.
    #[test]
    fn deserialize_rejects_a_checkpoint_genesis_height_off_the_anchor() {
        let fixture = regtest_params_json();
        let json = fixture.replace(
            r#""genesis_l1_height": 50462976"#,
            r#""genesis_l1_height": 4294967295"#,
        );
        assert_ne!(json, fixture, "fixture carries the anchor's genesis height");

        let error = serde_json::from_str::<AsmGenesisParams>(&json)
            .expect_err("a checkpoint genesis height off the anchor is rejected");

        assert!(
            error.to_string().contains(
                "checkpoint genesis L1 height 4294967295 does not match the L1 anchor height \
                 50462976"
            ),
            "unexpected error: {error}"
        );
    }

    /// The safe harbor is checked against the anchor in the same way as the signers, so a
    /// mainnet sweep destination cannot slip into a regtest file.
    #[test]
    fn deserialize_rejects_a_safe_harbor_on_another_network() {
        let fixture = regtest_params_json();
        let json = fixture.replace(
            "bcrt1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqc8gma6",
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
        );
        assert_ne!(json, fixture, "fixture carries the regtest safe harbor");

        let error = serde_json::from_str::<AsmGenesisParams>(&json)
            .expect_err("a mainnet safe harbor does not belong on a regtest anchor");

        assert!(
            error
                .to_string()
                .contains("safe harbor address is not an address on regtest"),
            "unexpected error: {error}"
        );
    }
}
