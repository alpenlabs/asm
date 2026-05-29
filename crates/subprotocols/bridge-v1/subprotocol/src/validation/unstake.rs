use bitcoin::ScriptBuf;
use strata_asm_proto_bridge_v1_txs::unstake::{
    UnstakeInfo, expected_stake_connector_script_pubkey,
};

use crate::errors::UnstakeValidationError;

/// Validates a parsed unstake transaction against the prevout it claims to spend.
///
/// The check binds the witness-derived `(stake_hash, witness_pushed_pubkey)` to a
/// real stake-connector UTXO: a P2TR output with the NUMS unspendable internal
/// key whose only leaf is `stake_connector_script(stake_hash, NN_pk)`. The
/// resulting `scriptPubKey` is a deterministic function of `(stake_hash, NN_pk)`,
/// so reconstructing it locally and comparing against the actually-spent output
/// is equivalent to asking Bitcoin "did the canonical stake-connector script
/// authorize this spend?" — which Bitcoin can only answer yes for after running
/// `OP_CHECKSIGVERIFY` against the N/N aggregated key.
pub(crate) fn validate_unstake_info(
    info: &UnstakeInfo,
    stake_connector_script_pubkey: &ScriptBuf,
) -> Result<(), UnstakeValidationError> {
    let expected =
        expected_stake_connector_script_pubkey(*info.stake_hash(), *info.witness_pushed_pubkey());
    if stake_connector_script_pubkey != &expected {
        return Err(UnstakeValidationError::InvalidStakeConnectorScript);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use bitcoin::ScriptBuf;
    use strata_asm_common::VerifiedAuxData;
    use strata_asm_proto_bridge_v1_txs::unstake::UnstakeInfo;

    use crate::{
        UnstakeValidationError, test_utils::setup_unstake_test, validation::validate_unstake_info,
    };

    fn stake_connector_script_from_aux(info: &UnstakeInfo, aux: &VerifiedAuxData) -> ScriptBuf {
        let txout = aux
            .get_bitcoin_txout(info.stake_inpoint().outpoint())
            .expect("stake connector txout should exist in aux data");
        txout.script_pubkey.clone()
    }

    #[test]
    fn test_unstake_tx_validation_success() {
        let (info, aux) = setup_unstake_test_with_operators();
        let spk = stake_connector_script_from_aux(&info, &aux);
        validate_unstake_info(&info, &spk).expect("valid unstake info should pass validation");
    }

    #[test]
    fn test_unstake_tx_wrong_script_pubkey() {
        let (info, _aux) = setup_unstake_test_with_operators();
        let bogus = ScriptBuf::from_bytes(vec![0x00; 34]);
        let err = validate_unstake_info(&info, &bogus).unwrap_err();
        assert!(matches!(
            err,
            UnstakeValidationError::InvalidStakeConnectorScript
        ));
    }

    fn setup_unstake_test_with_operators() -> (UnstakeInfo, VerifiedAuxData) {
        use crate::test_utils::create_test_state;
        let (_, operators) = create_test_state();
        setup_unstake_test(1, &operators)
    }
}
