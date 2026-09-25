//! Checks over a whole [`AsmParams`] that no single configuration can make on its own.
//!
//! Every subprotocol configuration validates itself as it deserializes. What is left are the
//! questions that need the anchor, or another subprotocol's configuration, to answer.
//! [`AsmParams`] runs those as part of its own deserialization, so a parameter file that
//! parses has already been checked.

use strata_asm_admin_types::SignerNetworkMismatch;
use thiserror::Error;

use crate::params::AsmParams;

impl AsmParams {
    /// Checks the invariants that span the whole parameter set.
    ///
    /// Run as part of deserialization, which is where these values come from.
    ///
    /// # Errors
    ///
    /// Returns the first invariant that does not hold.
    pub(crate) fn check_invariants(&self) -> Result<(), InvalidAsmParams> {
        if let Some(config) = self.admin_config() {
            config.check_signer_networks(self.anchor.network)?;
        }

        Ok(())
    }
}

/// An invariant spanning the whole parameter set that does not hold.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum InvalidAsmParams {
    /// An administration signer was written as an address on another network.
    #[error(transparent)]
    AdminSignerNetwork(#[from] SignerNetworkMismatch),
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
        let mut params: AsmParams =
            serde_json::from_str(regtest_params_json()).expect("fixture deserializes");
        params.anchor.network = Network::Bitcoin;

        assert_eq!(
            params.check_invariants().unwrap_err().to_string(),
            "Strata Administrator signer at index 0 is not an address on bitcoin"
        );
    }

    /// The check runs as the file is read, so a mismatched file never becomes an
    /// [`AsmParams`] in the first place.
    #[test]
    fn deserialize_rejects_a_signer_on_another_network() {
        let json =
            regtest_params_json().replace(r#""network": "regtest""#, r#""network": "bitcoin""#);

        let error = serde_json::from_str::<AsmParams>(&json)
            .expect_err("regtest signers do not belong on a mainnet anchor");

        assert!(
            error
                .to_string()
                .contains("signer at index 0 is not an address on bitcoin"),
            "unexpected error: {error}"
        );
    }
}
