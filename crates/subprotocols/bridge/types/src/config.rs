#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use bitcoin::{Address, Network, address::NetworkUnchecked};
use serde::{Deserialize, Deserializer, Serialize, de::Error as DeError};
use strata_btc_types::BitcoinAmount;
use strata_crypto::EvenPublicKey;
use thiserror::Error;

use crate::{InvalidSafeHarborAddress, SafeHarborAddress};

/// Initialization configuration for the bridge subprotocol.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeInitConfig {
    /// Initial operator MuSig2 public keys for the bridge
    pub operators: Vec<EvenPublicKey>,
    /// The amount of bitcoin expected to be locked in the N/N multisig.
    pub denomination: BitcoinAmount,
    /// Number of Bitcoin blocks an operator has to fulfill a withdrawal before it is reassigned to
    /// a different operator.
    pub assignment_duration: u16,
    /// Amount the operator can take as fees for processing withdrawal.
    pub operator_fee: BitcoinAmount,
    /// Number of Bitcoin blocks after Deposit Request Transaction that the depositor can reclaim
    /// funds if operators fail to process the deposit.
    pub recovery_delay: u16,
    /// Predefined safe harbor address, as written in the parameter file. Deactivated at init;
    /// the strata security council toggles activation (via Defcon signals), and the strata
    /// administrator rotates the destination address — keeping the sweep trigger and the sweep
    /// destination under separate authorities.
    pub safe_harbor_address: UncheckedSafeHarborAddress,
}

impl BridgeInitConfig {
    /// Checks that the safe harbor address was written for `network`.
    ///
    /// The prefix plays no part in where a sweep pays, which is why it is not stored, but a
    /// prefix that disagrees with the chain means the file and the chain were prepared against
    /// different networks and the operator should look again.
    ///
    /// # Errors
    ///
    /// Returns [`SafeHarborNetworkMismatch`] if the address belongs to another network.
    pub fn check_safe_harbor_network(
        &self,
        network: Network,
    ) -> Result<(), SafeHarborNetworkMismatch> {
        if self
            .safe_harbor_address
            .as_address()
            .is_valid_for_network(network)
        {
            Ok(())
        } else {
            Err(SafeHarborNetworkMismatch { network })
        }
    }
}

/// A safe harbor address written for a different network than the chain is anchored to.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("safe harbor address is not an address on {network}")]
pub struct SafeHarborNetworkMismatch {
    /// Network the chain is anchored to.
    network: Network,
}

/// The parameter-file form of a [`SafeHarborAddress`].
///
/// The safe harbor is written as a bech32m address so an operator can paste back exactly what
/// their wallet displays. It is checked to be P2TR on the way in, so converting one into a
/// [`SafeHarborAddress`] cannot fail.
///
/// The address is kept as written, prefix and all, so the file round-trips. Whether that prefix
/// matches the network the chain runs on needs the anchor to answer, so
/// [`BridgeInitConfig::check_safe_harbor_network`] asks it when the parameter file is loaded.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct UncheckedSafeHarborAddress(Address<NetworkUnchecked>);

impl UncheckedSafeHarborAddress {
    /// Creates a parameter-file safe harbor from an address.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSafeHarborAddress`] if `address` cannot be a safe harbor.
    pub fn try_new(address: Address<NetworkUnchecked>) -> Result<Self, InvalidSafeHarborAddress> {
        SafeHarborAddress::try_from_address(&address)?;
        Ok(Self(address))
    }

    /// Returns the address, as written.
    pub fn as_address(&self) -> &Address<NetworkUnchecked> {
        &self.0
    }
}

/// Resolves a parameter-file safe harbor into the descriptor the chain stores.
impl From<&UncheckedSafeHarborAddress> for SafeHarborAddress {
    fn from(address: &UncheckedSafeHarborAddress) -> Self {
        SafeHarborAddress::try_from_address(&address.0)
            .expect("UncheckedSafeHarborAddress::try_new checked that this is a safe harbor")
    }
}

/// [`Deserialize`] is implemented by hand so that decoded values go through
/// [`UncheckedSafeHarborAddress::try_new`] and satisfy the same invariant as constructed ones.
impl<'de> Deserialize<'de> for UncheckedSafeHarborAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let address = Address::<NetworkUnchecked>::deserialize(deserializer)?;
        Self::try_new(address).map_err(DeError::custom)
    }
}

/// Picks the network an arbitrary configuration writes its safe harbor address for.
///
/// The stored safe harbor does not include a network, but the address it is written as does,
/// so a generated configuration has to settle on one.
#[cfg(feature = "arbitrary")]
fn arbitrary_network(u: &mut Unstructured<'_>) -> arbitrary::Result<Network> {
    let networks = [
        Network::Bitcoin,
        Network::Testnet,
        Network::Signet,
        Network::Regtest,
    ];
    u.choose(&networks).copied()
}

#[cfg(feature = "arbitrary")]
impl BridgeInitConfig {
    /// Generates a configuration whose safe harbor is an address on `network`.
    ///
    /// [`Arbitrary`] picks the network itself. Callers that already have a network need this
    /// instead.
    pub fn arbitrary_for_network(
        u: &mut Unstructured<'_>,
        network: Network,
    ) -> arbitrary::Result<Self> {
        // Generate at least one operator.
        let len = u.int_in_range(1..=5)?;
        let operators = (0..len)
            .map(|_| u.arbitrary())
            .collect::<arbitrary::Result<Vec<EvenPublicKey>>>()?;

        Ok(Self {
            operators,
            denomination: u.arbitrary()?,
            assignment_duration: u.arbitrary()?,
            operator_fee: u.arbitrary()?,
            recovery_delay: u.arbitrary()?,
            safe_harbor_address: UncheckedSafeHarborAddress::arbitrary_for_network(u, network)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for BridgeInitConfig {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let network = arbitrary_network(u)?;
        Self::arbitrary_for_network(u, network)
    }
}

#[cfg(feature = "arbitrary")]
impl UncheckedSafeHarborAddress {
    /// Generates a safe harbor written as an address on `network`.
    pub fn arbitrary_for_network(
        u: &mut Unstructured<'_>,
        network: Network,
    ) -> arbitrary::Result<Self> {
        let address = SafeHarborAddress::arbitrary(u)?;
        Ok(Self(address.to_address(network).into_unchecked()))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for UncheckedSafeHarborAddress {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let network = arbitrary_network(u)?;
        Self::arbitrary_for_network(u, network)
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::Amount;

    use super::*;

    /// P2TR address over the x-only generator point, written for regtest.
    const REGTEST_P2TR: &str = "bcrt1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqc8gma6";

    fn parse_safe_harbor(json: &str) -> serde_json::Result<UncheckedSafeHarborAddress> {
        serde_json::from_str(json)
    }

    fn config_with_safe_harbor(address: &str) -> BridgeInitConfig {
        BridgeInitConfig {
            operators: Vec::new(),
            denomination: Amount::ZERO.into(),
            assignment_duration: 0,
            operator_fee: Amount::ZERO.into(),
            recovery_delay: 0,
            safe_harbor_address: UncheckedSafeHarborAddress::try_new(
                address.parse().expect("valid address"),
            )
            .expect("p2tr address accepted"),
        }
    }

    #[test]
    fn safe_harbor_deserializes_from_p2tr_address_and_round_trips() {
        let json = format!("\"{REGTEST_P2TR}\"");
        let address = parse_safe_harbor(&json).expect("p2tr address accepted");

        assert_eq!(
            SafeHarborAddress::from(&address)
                .to_address(Network::Regtest)
                .to_string(),
            REGTEST_P2TR
        );
        assert_eq!(serde_json::to_string(&address).expect("serialize"), json);
    }

    #[test]
    fn safe_harbor_deserialize_rejects_non_p2tr_address() {
        // BIP-173 P2WPKH test vector.
        let error = parse_safe_harbor("\"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4\"")
            .expect_err("p2wpkh address rejected");

        assert_eq!(
            error.to_string(),
            InvalidSafeHarborAddress::NotP2tr.to_string()
        );
    }

    /// The hex descriptor the field used to take is not an address, so an old parameter file
    /// fails to load rather than being read some other way.
    #[test]
    fn safe_harbor_deserialize_rejects_bosd_descriptor() {
        parse_safe_harbor("\"0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\"")
            .expect_err("descriptor hex rejected");
    }

    #[test]
    fn check_safe_harbor_network_accepts_matching_network() {
        let config = config_with_safe_harbor(REGTEST_P2TR);

        assert_eq!(config.check_safe_harbor_network(Network::Regtest), Ok(()));
    }

    #[test]
    fn check_safe_harbor_network_rejects_other_network() {
        let config = config_with_safe_harbor(REGTEST_P2TR);

        assert_eq!(
            config
                .check_safe_harbor_network(Network::Bitcoin)
                .unwrap_err()
                .to_string(),
            "safe harbor address is not an address on bitcoin"
        );
    }
}
