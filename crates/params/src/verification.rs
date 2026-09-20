//! Checks over a whole [`AsmParams`] that no single configuration can make on its own.
//!
//! Every subprotocol configuration validates itself as it deserializes. What is left are the
//! questions that need the anchor, or another subprotocol's configuration, to answer.

use strata_asm_admin_types::SignerNetworkMismatch;
use thiserror::Error;

use crate::params::AsmParams;

impl AsmParams {
    /// Checks the invariants that span the whole parameter set.
    ///
    /// Call this once, where the parameter file is loaded.
    ///
    /// # Errors
    ///
    /// Returns the first invariant that does not hold.
    pub fn verify(&self) -> Result<(), InvalidAsmParams> {
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

    /// A signer written for another network is what `verify` exists to catch: the program
    /// would authorize the same key, but the file and the chain disagree about which
    /// network the operator was looking at.
    #[test]
    fn verify_rejects_a_signer_on_another_network() {
        let mut params: AsmParams =
            serde_json::from_str(regtest_params_json()).expect("fixture deserializes");
        params.anchor.network = Network::Bitcoin;

        assert_eq!(
            params.verify().unwrap_err().to_string(),
            "Strata Administrator signer at index 0 is not an address on bitcoin"
        );
    }
}
