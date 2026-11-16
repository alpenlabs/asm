//! SPS-50 envelope transactions: the commit address and the reveal that spends it.
//!
//! This is the one place in the repo that builds them. The admin CLI and the
//! integration-test harness both use it, so the transactions operators send and the ones
//! the tests feed the ASM come from the same code. It moves to strata-common with the rest
//! of btcio.

use bitcoin::{
    Address, Amount, FeeRate, Network, OutPoint, ScriptBuf, Sequence, TapLeafHash, TapSighashType,
    Transaction, TxIn, TxOut, Witness,
    absolute::LockTime,
    blockdata::script,
    hashes::Hash as _,
    key::{Keypair, UntweakedKeypair},
    secp256k1::{Message, SECP256K1},
    sighash::{Prevouts, SighashCache, TaprootError},
    taproot::{ControlBlock, LeafVersion, TaprootBuilder},
    transaction::Version,
};
use rand::{RngCore, rngs::OsRng};
use strata_l1_envelope_fmt::{
    EnvelopeBuildError, build_envelope_script, build_signed_envelope_leaf,
};
use strata_l1_txfmt::{MagicBytes, ParseConfig, TagData, TxFmtError};
use thiserror::Error;

/// Length of a BIP-340 signature with the default sighash type.
const SCHNORR_SIG_LEN: usize = 64;

/// Failure to build an envelope transaction.
#[derive(Debug, Error)]
pub enum EnvelopeTxError {
    /// The SPS-50 tag could not be encoded.
    #[error("failed to encode the SPS-50 tag: {0}")]
    Tag(#[from] TxFmtError),
    /// The payload does not fit an envelope.
    #[error("failed to build the envelope: {0}")]
    Envelope(#[from] EnvelopeBuildError),
    /// The reveal's script-path sighash could not be computed.
    #[error("failed to compute the reveal sighash: {0}")]
    Sighash(#[from] TaprootError),
}

/// An SPS-50 payload ready to be committed to and revealed.
///
/// The commit pays to [`Self::address`]. The reveal spends that output through the envelope
/// leaf and carries the SPS-50 tag in its first output.
#[derive(Debug)]
pub struct EnvelopeTx {
    tag_script: ScriptBuf,
    leaf: ScriptBuf,
    leaf_version: LeafVersion,
    control_block: ControlBlock,
    address: Address,
    signer: Option<Keypair>,
}

impl EnvelopeTx {
    /// Prepares `payload` under `tag`, with the commit address on `network`.
    ///
    /// With `signer`, the leaf is an SPS-51 envelope for its key (`<key> OP_CHECKSIG` and the
    /// envelope). Without one, the leaf is the envelope followed by `OP_TRUE`, for
    /// subprotocols that don't read SPS-51, and the taproot internal key is random.
    ///
    /// The leaf is committed under `leaf_version`. Bitcoin runs only a
    /// [`LeafVersion::TapScript`] leaf, so only that spend is signed. Any other version
    /// gives a valid but non-standard reveal.
    pub fn new(
        magic: MagicBytes,
        tag: &TagData,
        payload: &[u8],
        signer: Option<Keypair>,
        leaf_version: LeafVersion,
        network: Network,
    ) -> Result<Self, EnvelopeTxError> {
        let tag_script = ParseConfig::new(magic).encode_script_buf(&tag.as_ref())?;
        let (internal_key, leaf) = match &signer {
            Some(keypair) => {
                let (key, _) = keypair.x_only_public_key();
                (key, build_signed_envelope_leaf(&key.serialize(), payload)?)
            }
            None => {
                let (key, _) = random_keypair().x_only_public_key();
                let leaf = script::Builder::from(build_envelope_script(payload)?.into_bytes())
                    .push_int(1)
                    .into_script();
                (key, leaf)
            }
        };
        let spend_info = TaprootBuilder::new()
            .add_leaf_with_ver(0, leaf.clone(), leaf_version)
            .expect("a single leaf at depth 0 is a valid tree")
            .finalize(SECP256K1, internal_key)
            .expect("a single-leaf tree is complete");
        let control_block = spend_info
            .control_block(&(leaf.clone(), leaf_version))
            .expect("the leaf is in the tree");
        let address = Address::p2tr_tweaked(spend_info.output_key(), network);

        Ok(Self {
            tag_script,
            leaf,
            leaf_version,
            control_block,
            address,
            signer,
        })
    }

    /// Address the commit pays to.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Fee that makes the reveal pay `fee_rate`, when it sends its change to `change`.
    ///
    /// Returns `None` if the fee overflows.
    pub fn reveal_fee(&self, fee_rate: FeeRate, change: &ScriptBuf) -> Option<Amount> {
        // The signature's size is fixed, so a placeholder gives the exact weight.
        let change = TxOut {
            value: Amount::ZERO,
            script_pubkey: change.clone(),
        };
        let mut template = self.unsigned_reveal(OutPoint::null(), change);
        template.input[0].witness = self.witness(self.signs().then_some(&[0; SCHNORR_SIG_LEN]));
        fee_rate.fee_vb(template.vsize() as u64)
    }

    /// Builds the reveal spending `prevout` at `outpoint`, the output the commit paid to
    /// [`Self::address`], with `change` as its second output.
    pub fn build_reveal(
        &self,
        outpoint: OutPoint,
        prevout: &TxOut,
        change: TxOut,
    ) -> Result<Transaction, EnvelopeTxError> {
        let mut reveal = self.unsigned_reveal(outpoint, change);
        let signature = match &self.signer {
            Some(keypair) if self.signs() => {
                let leaf_hash = TapLeafHash::from_script(&self.leaf, self.leaf_version);
                let sighash = SighashCache::new(&reveal).taproot_script_spend_signature_hash(
                    0,
                    &Prevouts::All(&[prevout]),
                    leaf_hash,
                    TapSighashType::Default,
                )?;
                let message = Message::from_digest(sighash.to_byte_array());
                Some(SECP256K1.sign_schnorr(&message, keypair).serialize())
            }
            _ => None,
        };
        reveal.input[0].witness = self.witness(signature.as_ref());
        Ok(reveal)
    }

    /// Builds the reveal with the leaf and control block but no signature.
    ///
    /// For spending an output whose witness Bitcoin never checks, such as a segwit v2+
    /// program. Such a spend is non-standard.
    pub fn build_unsigned_reveal(&self, outpoint: OutPoint, change: TxOut) -> Transaction {
        let mut reveal = self.unsigned_reveal(outpoint, change);
        reveal.input[0].witness = self.witness(None);
        reveal
    }

    fn signs(&self) -> bool {
        self.signer.is_some() && self.leaf_version == LeafVersion::TapScript
    }

    fn unsigned_reveal(&self, outpoint: OutPoint, change: TxOut) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![
                TxOut {
                    value: Amount::ZERO,
                    script_pubkey: self.tag_script.clone(),
                },
                change,
            ],
        }
    }

    fn witness(&self, signature: Option<&[u8; SCHNORR_SIG_LEN]>) -> Witness {
        let mut witness = Witness::new();
        if let Some(signature) = signature {
            witness.push(signature);
        }
        witness.push(self.leaf.as_bytes());
        witness.push(self.control_block.serialize());
        witness
    }
}

/// A fresh random keypair.
pub fn random_keypair() -> Keypair {
    let mut secret = [0; 32];
    OsRng.fill_bytes(&mut secret);
    UntweakedKeypair::from_seckey_slice(SECP256K1, &secret)
        .expect("32 random bytes are a valid key")
}
