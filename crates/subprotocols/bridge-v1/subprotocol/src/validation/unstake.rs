use bitcoin::ScriptBuf;
use strata_asm_proto_bridge_v1_txs::unstake::{
    UnstakeInfo, expected_stake_connector_script_pubkey,
};
use strata_btc_types::BitcoinXOnlyPublicKey;

use crate::{
    errors::UnstakeValidationError,
    state::{BridgeV1State, operator::build_nn_script},
};

/// Validates a parsed unstake transaction against the prevout it claims to spend.
///
/// Two independent bindings are required; only their conjunction is safe:
///
/// 1. **Key legitimacy.** The witness-pushed pubkey must be an aggregated N/N key the operator set
///    actually used at some point in its history. Without this, an attacker could mint their *own*
///    stake connector under a key they control, spend it (Bitcoin will happily run
///    `OP_CHECKSIGVERIFY` against the attacker key), and have ASM remove any operator named in the
///    SPS-50 tag.
///
/// 2. **Spend authenticity.** The actually-spent prevout must equal the canonical stake-connector
///    `scriptPubKey` reconstructed from `(stake_hash, NN_pk)` — a P2TR output with the NUMS
///    unspendable internal key whose only leaf is `stake_connector_script(stake_hash, NN_pk)`.
///    Because the internal key is unspendable, a match is only possible if Bitcoin authorized the
///    spend by running `OP_CHECKSIGVERIFY` against `NN_pk`. Without this, the original
///    witness-layout bypass lets an attacker present a real N/N key at `witness[2]` while actually
///    spending a trivially-spendable UTXO.
pub(crate) fn validate_unstake_info(
    state: &BridgeV1State,
    info: &UnstakeInfo,
    stake_connector_script_pubkey: &ScriptBuf,
) -> Result<(), UnstakeValidationError> {
    // The witness-pushed pubkey must be a historical N/N aggregated key. We don't store
    // historical pubkeys directly, only their key-path P2TR representation, so reconstruct
    // that and check membership.
    let witness_pubkey = BitcoinXOnlyPublicKey::from(*info.witness_pushed_pubkey());
    let nn_keypath_script = build_nn_script(&witness_pubkey);
    let config = state
        .operators()
        .historical_nn_scripts()
        .find(|config| config.script() == nn_keypath_script.inner())
        .ok_or(UnstakeValidationError::UnknownNnKey)?;

    // The operator being unstaked must have been a member of that historical N/N multisig.
    let operator_idx = info.header_aux().operator_idx();
    if !config.operators().is_active(operator_idx) {
        return Err(UnstakeValidationError::OperatorNotInMultisig {
            operator: operator_idx,
            script: config.script().clone(),
        });
    }

    // The spent prevout must be the canonical stake connector committing to that key.
    let expected =
        expected_stake_connector_script_pubkey(*info.stake_hash(), *info.witness_pushed_pubkey());
    if stake_connector_script_pubkey != &expected {
        return Err(UnstakeValidationError::StakeConnectorMismatch);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use bitcoin::ScriptBuf;
    use strata_asm_common::VerifiedAuxData;
    use strata_asm_proto_bridge_v1_txs::{test_utils::create_test_operators, unstake::UnstakeInfo};

    use crate::{
        UnstakeValidationError,
        test_utils::{create_test_state, setup_unstake_test},
        validation::validate_unstake_info,
    };

    fn stake_connector_script_from_aux(info: &UnstakeInfo, aux: &VerifiedAuxData) -> ScriptBuf {
        let txout = aux
            .get_bitcoin_txout(info.stake_inpoint().outpoint())
            .expect("stake connector txout should exist in aux data");
        txout.script_pubkey.clone()
    }

    #[test]
    fn test_unstake_tx_validation_success() {
        let (state, operators) = create_test_state();
        let (info, aux) = setup_unstake_test(1, &operators);
        let spk = stake_connector_script_from_aux(&info, &aux);
        validate_unstake_info(&state, &info, &spk)
            .expect("valid unstake info should pass validation");
    }

    #[test]
    fn test_unstake_tx_rejects_non_canonical_stake_connector() {
        let (state, operators) = create_test_state();
        let (info, _aux) = setup_unstake_test(1, &operators);
        let bogus = ScriptBuf::from_bytes(vec![0x00; 34]);
        let err = validate_unstake_info(&state, &info, &bogus).unwrap_err();
        assert!(matches!(
            err,
            UnstakeValidationError::StakeConnectorMismatch
        ));
    }

    #[test]
    fn test_unstake_tx_rejects_attacker_owned_stake_connector() {
        let (state, _operators) = create_test_state();
        // Keys the attacker controls — generated independently of `state`'s operators.
        let (attacker_keys, _) = create_test_operators(3);
        let (info, aux) = setup_unstake_test(1, &attacker_keys);
        let spk = stake_connector_script_from_aux(&info, &aux);
        let err = validate_unstake_info(&state, &info, &spk).unwrap_err();
        assert!(matches!(err, UnstakeValidationError::UnknownNnKey));
    }

    #[test]
    fn test_unstake_tx_rejects_operator_outside_multisig() {
        // Genesis operators back the N/N key the stake connector commits to.
        let (mut state, operators) = create_test_state();
        let genesis_count = operators.len() as u32;

        // Add a fresh operator after genesis: it joins the new N/N config but was never part of
        // the genesis one the witness pubkey identifies.
        let (_, new_pubkeys) = create_test_operators(1);
        state.apply_operator_set_update(&new_pubkeys, &[]);

        // The unstake commits to the genesis N/N key but names the newly added operator.
        let (info, aux) = setup_unstake_test(genesis_count, &operators);
        let spk = stake_connector_script_from_aux(&info, &aux);
        let err = validate_unstake_info(&state, &info, &spk).unwrap_err();
        assert!(matches!(
            err,
            UnstakeValidationError::OperatorNotInMultisig { operator, .. } if operator == genesis_count
        ));
    }
}
