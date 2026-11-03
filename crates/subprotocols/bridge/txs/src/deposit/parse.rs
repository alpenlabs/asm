use bitcoin::{Witness, taproot::TAPROOT_ANNEX_PREFIX};
use strata_asm_common::TxInputRef;
use strata_codec::decode_buf_exact;

use crate::{
    constants::BridgeTxType,
    deposit::{DEPOSIT_OUTPUT_INDEX, DepositInfo, aux_input::DepositTxHeaderAux},
    deposit_request::DRT_OUTPUT_INDEX,
    errors::{TxStructureError, WitnessError},
};

/// Index of the deposit transaction input that spends the DRT (Deposit Request Transaction)
/// output.
const DRT_INPUT_INDEX: usize = 0;

/// Length of a BIP340 Schnorr signature committing to `SIGHASH_DEFAULT`.
const SCHNORR_SIG_LEN: usize = 64;

/// Length of a BIP340 Schnorr signature followed by an explicit sighash type byte.
const SCHNORR_SIG_WITH_SIGHASH_LEN: usize = 65;

/// Parses deposit transaction to extract [`DepositInfo`].
///
/// Parses a deposit transaction following the SPS-50 specification and extracts the decoded
/// auxiliary data ([`DepositTxHeaderAux`]) along with the deposit output and DRT inpoint. The
/// auxiliary data is encoded with [`strata_codec::Codec`] and includes the deposit index.
///
/// # Errors
///
/// Returns [`TxStructureError`] if the auxiliary data cannot be decoded, if the expected
/// deposit output is missing, if the first input does not spend the DRT's output, or if it does
/// not spend it through the taproot key path.
pub fn parse_deposit_tx<'a>(tx_input: &TxInputRef<'a>) -> Result<DepositInfo, TxStructureError> {
    // Parse auxiliary data
    let header_aux: DepositTxHeaderAux = decode_buf_exact(tx_input.tag().aux_data())
        .map_err(|e| TxStructureError::invalid_auxiliary_data(BridgeTxType::Deposit, e))?;

    // Extract the deposit output
    let deposit_output = tx_input
        .tx()
        .output
        .get(DEPOSIT_OUTPUT_INDEX)
        .ok_or_else(|| {
            TxStructureError::missing_output(
                BridgeTxType::Deposit,
                DEPOSIT_OUTPUT_INDEX,
                "deposit output",
            )
        })?
        .clone()
        .try_into()
        .map_err(|e| {
            TxStructureError::invalid_output(
                BridgeTxType::Deposit,
                DEPOSIT_OUTPUT_INDEX,
                e,
                "deposit output",
            )
        })?;

    // Extract the DRT input
    let drt_input = tx_input.tx().input.get(DRT_INPUT_INDEX).ok_or_else(|| {
        TxStructureError::missing_input(BridgeTxType::Deposit, DRT_INPUT_INDEX, "drt input")
    })?;
    let drt_inpoint = drt_input.previous_output;

    // The DRT is later fetched as auxiliary data by txid alone, and `parse_drt` always reads the
    // output at `DRT_OUTPUT_INDEX`. Without this check the deposit could spend some other output
    // of that transaction while validation approves an output that is never consumed.
    if drt_inpoint.vout != DRT_OUTPUT_INDEX as u32 {
        return Err(TxStructureError::wrong_spent_output(
            BridgeTxType::Deposit,
            DRT_OUTPUT_INDEX as u32,
            drt_inpoint.vout,
            "drt input",
        ));
    }

    // The DRT output's internal key is the N/N aggregate, but its takeback leaf lets the
    // depositor alone spend it once the recovery delay has passed. Only the key path proves the
    // operators authorized this deposit; see `ensure_key_path_spend`.
    ensure_key_path_spend(&drt_input.witness)
        .map_err(|e| TxStructureError::invalid_witness(BridgeTxType::Deposit, e, "drt input"))?;

    // Construct the validated deposit information
    Ok(DepositInfo::new(
        header_aux,
        deposit_output,
        drt_inpoint.into(),
    ))
}

/// Requires `witness` to be that of a taproot key-path spend, following BIP341.
///
/// With two or more elements, a last element starting with [`TAPROOT_ANNEX_PREFIX`] is the annex
/// and is set aside. What remains is a key-path spend when it is a single element, the signature,
/// and a script-path spend when it has two or more, ending with the leaf script and its control
/// block.
///
/// Telling the two apart from the witness is sound only because the spent output is a taproot
/// output: validation checks the DRT output against the expected deposit request script before
/// accepting the deposit. Under that script, a key-path spend is signed by the output key, the
/// N/N aggregate tweaked by the takeback leaf's merkle root, which only the full operator set
/// can produce.
///
/// The signature itself is not verified. Bitcoin consensus already verified it for any
/// transaction in a valid block, and the ASM's validity rests on that assumption for every
/// transaction it reads. The length check therefore rejects nothing a valid block can contain.
///
/// A key-path signature authorizes only what its sighash type commits to. Under `SIGHASH_NONE`
/// it commits to no outputs, so a third party could rewrite output 0, and with it the deposit
/// index, without invalidating the operators' signature. `SIGHASH_SINGLE` on input 0 still
/// commits to output 0, and validation pins output 1. The operators sign with `SIGHASH_DEFAULT`,
/// which commits to every output, so this check accepts any sighash type and relies on that.
fn ensure_key_path_spend(witness: &Witness) -> Result<(), WitnessError> {
    let has_annex = witness.len() >= 2
        && witness
            .last()
            .is_some_and(|last| last.first() == Some(&TAPROOT_ANNEX_PREFIX));
    let elements = witness.len() - usize::from(has_annex);
    if elements != 1 {
        return Err(WitnessError::NotKeyPathSpend { elements });
    }

    let signature = witness
        .nth(0)
        .expect("witness has exactly one element besides any annex");
    if !matches!(
        signature.len(),
        SCHNORR_SIG_LEN | SCHNORR_SIG_WITH_SIGHASH_LEN
    ) {
        return Err(WitnessError::InvalidKeyPathSignatureLength(signature.len()));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::mem;

    use bitcoin::{
        OutPoint, ScriptBuf, Transaction, TxOut, Witness, secp256k1::SECP256K1,
        taproot::TAPROOT_ANNEX_PREFIX,
    };
    use strata_btc_types::BitcoinAmount;
    use strata_crypto::test_utils::schnorr::create_agg_pubkey_from_privkeys;
    use strata_test_utils_arb::ArbitraryGenerator;

    use crate::{
        BRIDGE_SUBPROTOCOL_ID,
        constants::BridgeTxType,
        deposit::{
            DEPOSIT_OUTPUT_INDEX, DepositInfo, DepositTxHeaderAux, parse::DRT_INPUT_INDEX,
            parse_deposit_tx,
        },
        deposit_request::{DRT_OUTPUT_INDEX, DrtHeaderAux},
        errors::{TxStructureError, TxStructureErrorKind, WitnessError},
        test_utils::{
            create_connected_drt_and_dt, create_drt_takeback_witness, create_test_operators,
            overwrite_aux_data, parse_sps50_tx,
        },
    };

    const AUX_LEN: usize = mem::size_of::<DepositTxHeaderAux>();

    fn create_deposit_tx_with_info() -> (DepositInfo, Transaction) {
        let (info, tx, _) = create_deposit_fixture();
        (info, tx)
    }

    /// Returns a deposit, the honest deposit transaction for it, and the witness with which the
    /// depositor could instead sweep the same DRT output through its takeback leaf.
    fn create_deposit_fixture() -> (DepositInfo, Transaction, Witness) {
        let mut arb = ArbitraryGenerator::new();
        let drt_header_aux: DrtHeaderAux = arb.generate();
        let deposit_idx: u32 = arb.generate();
        let amount = BitcoinAmount::try_from(100_000)
            .expect("test amount must be within the Bitcoin money supply");
        let recovery_delay = 5;

        let (sks, _) = create_test_operators(3);
        let dt_aux = DepositTxHeaderAux::new(deposit_idx);
        let (drt, dt) = create_connected_drt_and_dt(
            &drt_header_aux,
            dt_aux.clone(),
            amount.into(),
            recovery_delay,
            &sks,
        );
        let nn_key = create_agg_pubkey_from_privkeys(&sks);

        let drt_inpoint = OutPoint::new(drt.compute_txid(), DRT_OUTPUT_INDEX as u32);
        let deposit_output = TxOut {
            value: amount.into(),
            script_pubkey: ScriptBuf::new_p2tr(SECP256K1, nn_key, None),
        };
        let info = DepositInfo::new(
            dt_aux,
            deposit_output
                .try_into()
                .expect("deposit script within size bound"),
            drt_inpoint.into(),
        );
        let takeback_witness = create_drt_takeback_witness(&drt_header_aux, nn_key, recovery_delay);
        (info, dt, takeback_witness)
    }

    /// An annex: a final witness element starting with [`TAPROOT_ANNEX_PREFIX`].
    fn annex() -> Vec<u8> {
        vec![TAPROOT_ANNEX_PREFIX, 0xAA, 0xBB]
    }

    fn witness_from(elements: &[&[u8]]) -> Witness {
        Witness::from_slice(elements)
    }

    fn parse_with_drt_witness(
        tx: &Transaction,
        witness: Witness,
    ) -> Result<DepositInfo, TxStructureError> {
        let mut tx = tx.clone();
        tx.input[DRT_INPUT_INDEX].witness = witness;
        parse_deposit_tx(&parse_sps50_tx(&tx))
    }

    #[test]
    fn test_parse_dt_success() {
        let (info, tx) = create_deposit_tx_with_info();
        let tx_input = parse_sps50_tx(&tx);

        let parsed = parse_deposit_tx(&tx_input).expect("should parse deposit tx");

        assert_eq!(info, parsed);
    }

    /// The fixture's deposit is signed the way operators sign one: a MuSig2 key-path spend of the
    /// DRT output, leaving a lone 64-byte signature as the witness.
    #[test]
    fn test_parse_dt_fixture_is_key_path_spend() {
        let (_, tx, _) = create_deposit_fixture();
        let witness = &tx.input[DRT_INPUT_INDEX].witness;
        assert_eq!(witness.len(), 1);
        assert_eq!(witness.nth(0).map(<[u8]>::len), Some(64));
    }

    /// Every key-path witness shape BIP341 allows is accepted: a 64-byte signature, a 65-byte one
    /// with an explicit sighash type, either with an annex, and a lone signature that happens to
    /// start with the annex prefix (an annex needs at least two elements).
    #[test]
    fn test_parse_accepts_key_path_spends() {
        let (info, tx, _) = create_deposit_fixture();
        let sig = tx.input[DRT_INPUT_INDEX]
            .witness
            .nth(0)
            .expect("fixture has a key-path signature")
            .to_vec();
        let mut sig_with_sighash = sig.clone();
        sig_with_sighash.push(0x01);
        let mut sig_with_annex_prefix = sig.clone();
        sig_with_annex_prefix[0] = TAPROOT_ANNEX_PREFIX;
        let annex = annex();

        let cases: [(&str, Witness); 5] = [
            ("64-byte signature", witness_from(&[&sig])),
            ("65-byte signature", witness_from(&[&sig_with_sighash])),
            (
                "64-byte signature with annex",
                witness_from(&[&sig, &annex]),
            ),
            (
                "65-byte signature with annex",
                witness_from(&[&sig_with_sighash, &annex]),
            ),
            (
                "lone signature starting with the annex prefix",
                witness_from(&[&sig_with_annex_prefix]),
            ),
        ];
        for (case, witness) in cases {
            let parsed = parse_with_drt_witness(&tx, witness)
                .unwrap_or_else(|e| panic!("{case}: key-path spend should parse: {e}"));
            assert_eq!(parsed, info, "{case}");
        }
    }

    /// Anything other than a key-path spend of the DRT output is rejected. The takeback sweep is
    /// the case that matters: after the recovery delay it lets the depositor alone produce a
    /// transaction that otherwise passes every deposit check.
    #[test]
    fn test_parse_rejects_non_key_path_spends() {
        let (_, tx, takeback) = create_deposit_fixture();
        let mut takeback_with_annex = takeback.clone();
        takeback_with_annex.push(annex());
        let leaf_script = takeback
            .nth(1)
            .expect("takeback witness has its leaf script")
            .to_vec();

        let cases: [(&str, Witness, WitnessError); 6] = [
            (
                "takeback script-path spend",
                takeback,
                WitnessError::NotKeyPathSpend { elements: 3 },
            ),
            (
                "takeback script-path spend with annex",
                takeback_with_annex,
                WitnessError::NotKeyPathSpend { elements: 3 },
            ),
            (
                "two elements without an annex",
                witness_from(&[&[0x01; 64], &leaf_script]),
                WitnessError::NotKeyPathSpend { elements: 2 },
            ),
            (
                "empty witness",
                Witness::new(),
                WitnessError::NotKeyPathSpend { elements: 0 },
            ),
            (
                "lone annex-prefixed element too short for a signature",
                witness_from(&[&[TAPROOT_ANNEX_PREFIX]]),
                WitnessError::InvalidKeyPathSignatureLength(1),
            ),
            (
                "63-byte signature",
                witness_from(&[&[0x01; 63]]),
                WitnessError::InvalidKeyPathSignatureLength(63),
            ),
        ];
        for (case, witness, expected) in cases {
            let err = parse_with_drt_witness(&tx, witness)
                .expect_err(&format!("{case}: should be rejected"));
            assert_eq!(err.tx_type(), BridgeTxType::Deposit, "{case}");
            let TxStructureErrorKind::InvalidWitness(got) = err.kind() else {
                panic!("{case}: expected InvalidWitness, got {:?}", err.kind());
            };
            assert_eq!(got, &expected, "{case}");
        }
    }

    #[test]
    fn test_parse_missing_output() {
        let (_, mut tx) = create_deposit_tx_with_info();

        // Remove the deposit output
        tx.output.pop();

        let tx_input = parse_sps50_tx(&tx);
        let err = parse_deposit_tx(&tx_input).unwrap_err();
        assert_eq!(err.tx_type(), BridgeTxType::Deposit);
        assert!(matches!(
            err.kind(),
            TxStructureErrorKind::MissingOutput {
                index: DEPOSIT_OUTPUT_INDEX
            }
        ))
    }

    #[test]
    fn test_parse_missing_input() {
        let (_, mut tx) = create_deposit_tx_with_info();

        // Remove all the inputs
        tx.input.clear();

        let tx_input = parse_sps50_tx(&tx);
        let err = parse_deposit_tx(&tx_input).unwrap_err();
        assert_eq!(err.tx_type(), BridgeTxType::Deposit);
        assert!(matches!(
            err.kind(),
            TxStructureErrorKind::MissingInput {
                index: DRT_INPUT_INDEX
            }
        ))
    }

    /// A deposit spending some output of the DRT other than the deposit request output must be
    /// rejected. Otherwise validation would approve the output at `DRT_OUTPUT_INDEX` while the
    /// deposit consumes a different one, leaving the real DRT output unspent.
    #[test]
    fn test_parse_wrong_spent_drt_output() {
        let (_, mut tx) = create_deposit_tx_with_info();

        // Keep the same DRT txid, but point the input at a different output of it.
        let wrong_vout = DRT_OUTPUT_INDEX as u32 + 1;
        tx.input[DRT_INPUT_INDEX].previous_output.vout = wrong_vout;

        let tx_input = parse_sps50_tx(&tx);
        let err = parse_deposit_tx(&tx_input).unwrap_err();
        assert_eq!(err.tx_type(), BridgeTxType::Deposit);
        assert!(matches!(
            err.kind(),
            TxStructureErrorKind::WrongSpentOutput { expected, got }
                if *expected == DRT_OUTPUT_INDEX as u32 && *got == wrong_vout
        ))
    }

    #[test]
    fn test_parse_invalid_aux() {
        let (_, mut tx) = create_deposit_tx_with_info();

        let larger_aux = [0u8; AUX_LEN + 1].to_vec();
        overwrite_aux_data(
            &mut tx,
            BRIDGE_SUBPROTOCOL_ID,
            BridgeTxType::Deposit as u8,
            larger_aux,
        );

        let tx_input = parse_sps50_tx(&tx);
        let err = parse_deposit_tx(&tx_input).unwrap_err();
        assert_eq!(err.tx_type(), BridgeTxType::Deposit);
        assert!(matches!(
            err.kind(),
            TxStructureErrorKind::InvalidAuxiliaryData(_)
        ));

        let smaller_aux = [0u8; AUX_LEN - 1].to_vec();
        overwrite_aux_data(
            &mut tx,
            BRIDGE_SUBPROTOCOL_ID,
            BridgeTxType::Deposit as u8,
            smaller_aux,
        );

        let tx_input = parse_sps50_tx(&tx);
        let err = parse_deposit_tx(&tx_input).unwrap_err();
        assert_eq!(err.tx_type(), BridgeTxType::Deposit);
        assert!(matches!(
            err.kind(),
            TxStructureErrorKind::InvalidAuxiliaryData(_)
        ));
    }
}
