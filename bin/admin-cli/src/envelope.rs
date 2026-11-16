//! Sizes and checks the commit and reveal transactions that carry a signed admin payload.

use anyhow::{Context, anyhow, ensure};
use bitcoin::{
    Address, Amount, FeeRate, Network, OutPoint, ScriptBuf, Transaction, TxOut,
    taproot::LeafVersion,
};
use strata_asm_common::TxInputRef;
use strata_asm_proto_admin_txs::parser::{EnvelopePayload, SignedPayload, parse_tx};
use strata_l1_txfmt::{MagicBytes, ParseConfig};
use strata_test_utils_btcio::{EnvelopeTx, random_keypair};

/// A signed admin payload, ready to be committed to and revealed.
#[derive(Debug)]
pub(crate) struct Envelope {
    magic: MagicBytes,
    expected: EnvelopePayload,
    tx: EnvelopeTx,
}

impl Envelope {
    pub(crate) fn new(
        payload: SignedPayload,
        magic: MagicBytes,
        network: Network,
    ) -> anyhow::Result<Self> {
        let tag = payload.action.tag();
        let expected = EnvelopePayload::from(payload);
        // This key only guards the commit output until the reveal spends it, and the ASM
        // ignores it. A throwaway key keeps the admin signers out of transaction building.
        let tx = EnvelopeTx::new(
            magic,
            &tag,
            &expected.clone().into_envelope_bytes(),
            Some(random_keypair()),
            LeafVersion::TapScript,
            network,
        )?;
        Ok(Self {
            magic,
            expected,
            tx,
        })
    }

    /// Address the commit transaction pays to.
    pub(crate) fn address(&self) -> &Address {
        self.tx.address()
    }

    /// Value the commit output needs so the reveal pays `fee_rate` and leaves `change` a
    /// non-dust output.
    pub(crate) fn commit_value(
        &self,
        fee_rate: FeeRate,
        change: &ScriptBuf,
    ) -> anyhow::Result<Amount> {
        Ok(self.reveal_fee(fee_rate, change)? + change.minimal_non_dust())
    }

    /// Builds and signs the reveal spending `commit`'s output to [`Self::address`], with what
    /// the fee leaves paid to `change`.
    ///
    /// Fails unless the reveal decodes, through the ASM's own parser, to the signed payload.
    pub(crate) fn build_reveal(
        &self,
        commit: &Transaction,
        change: ScriptBuf,
        fee_rate: FeeRate,
    ) -> anyhow::Result<Transaction> {
        let script_pubkey = self.address().script_pubkey();
        let vout = commit
            .output
            .iter()
            .position(|output| output.script_pubkey == script_pubkey)
            .context("commit transaction does not pay the envelope address")?;
        let prevout = &commit.output[vout];
        let fee = self.reveal_fee(fee_rate, &change)?;
        let value = prevout
            .value
            .checked_sub(fee)
            .filter(|value| *value >= change.minimal_non_dust())
            .ok_or_else(|| {
                anyhow!(
                    "commit output of {} does not cover the reveal",
                    prevout.value
                )
            })?;

        let outpoint = OutPoint::new(commit.compute_txid(), vout as u32);
        let change = TxOut {
            value,
            script_pubkey: change,
        };
        let reveal = self.tx.build_reveal(outpoint, prevout, change)?;

        let decoded = decode_reveal(&reveal, self.magic)?;
        ensure!(
            decoded == self.expected,
            "reveal decodes to a different payload than the one signed"
        );
        Ok(reveal)
    }

    fn reveal_fee(&self, fee_rate: FeeRate, change: &ScriptBuf) -> anyhow::Result<Amount> {
        self.tx
            .reveal_fee(fee_rate, change)
            .context("reveal fee overflows")
    }
}

/// Decodes `reveal` as the ASM does: SPS-50 tag first, then the admin envelope.
fn decode_reveal(reveal: &Transaction, magic: MagicBytes) -> anyhow::Result<EnvelopePayload> {
    let tag = ParseConfig::new(magic)
        .try_parse_tx(reveal)
        .map_err(|e| anyhow!("reveal carries no SPS-50 tag: {e}"))?;
    parse_tx(&TxInputRef::new(reveal, tag)).context("the admin parser rejected the reveal")
}
