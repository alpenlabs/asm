use arbitrary::Arbitrary;
use bitcoin::{
    XOnlyPublicKey,
    secp256k1::{Keypair, SECP256K1, SecretKey},
};
use strata_btc_types::BitcoinOutPoint;

use crate::unstake::UnstakeTxHeaderAux;

/// Information extracted from an unstake transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnstakeInfo {
    /// SPS-50 auxiliary data from the transaction tag.
    header_aux: UnstakeTxHeaderAux,
    /// Outpoint of the stake-connector input (`input[0]`) the transaction spends.
    stake_inpoint: BitcoinOutPoint,
    /// Pubkey extracted from the stake-connector script (witness element 2).
    witness_pushed_pubkey: XOnlyPublicKey,
    /// Stake hash extracted from the stake-connector script (witness element 2).
    stake_hash: [u8; 32],
}

impl UnstakeInfo {
    pub fn new(
        header_aux: UnstakeTxHeaderAux,
        stake_inpoint: BitcoinOutPoint,
        witness_pushed_pubkey: XOnlyPublicKey,
        stake_hash: [u8; 32],
    ) -> Self {
        Self {
            header_aux,
            stake_inpoint,
            witness_pushed_pubkey,
            stake_hash,
        }
    }

    pub fn header_aux(&self) -> &UnstakeTxHeaderAux {
        &self.header_aux
    }

    pub fn stake_inpoint(&self) -> &BitcoinOutPoint {
        &self.stake_inpoint
    }

    pub fn witness_pushed_pubkey(&self) -> &XOnlyPublicKey {
        &self.witness_pushed_pubkey
    }

    pub fn stake_hash(&self) -> &[u8; 32] {
        &self.stake_hash
    }
}

impl<'a> Arbitrary<'a> for UnstakeInfo {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let header_aux = UnstakeTxHeaderAux::arbitrary(u)?;
        let stake_inpoint = BitcoinOutPoint::arbitrary(u)?;

        let mut secret_key_bytes = [0u8; 32];
        u.fill_buffer(&mut secret_key_bytes)?;

        let secret_key = SecretKey::from_slice(&secret_key_bytes)
            .map_err(|_| arbitrary::Error::IncorrectFormat)?;
        let keypair = Keypair::from_secret_key(SECP256K1, &secret_key);
        let (witness_pushed_pubkey, _parity) = keypair.x_only_public_key();

        let mut stake_hash = [0u8; 32];
        u.fill_buffer(&mut stake_hash)?;

        Ok(Self {
            header_aux,
            stake_inpoint,
            witness_pushed_pubkey,
            stake_hash,
        })
    }
}
