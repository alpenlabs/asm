use bitcoin::ScriptBuf;
use strata_asm_proto_bridge_v1_types::OperatorIdx;

use crate::{errors::SlashValidationError, state::BridgeV1State};

/// Validates the stake connector script for a slash transaction locked to one of the historical N/N
/// multisig configurations, and that the operator being slashed belonged to that configuration.
pub(crate) fn validate_slash_stake_connector(
    state: &BridgeV1State,
    operator_idx: OperatorIdx,
    stake_connector_script: &ScriptBuf,
) -> Result<(), SlashValidationError> {
    let config = state
        .operators()
        .historical_nn_scripts()
        .find(|config| config.script() == stake_connector_script)
        .ok_or(SlashValidationError::InvalidStakeConnectorScript)?;

    if !config.operators().is_active(operator_idx) {
        return Err(SlashValidationError::OperatorNotInMultisig {
            operator: operator_idx,
            script: config.script().clone(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use bitcoin::ScriptBuf;
    use strata_asm_common::VerifiedAuxData;
    use strata_asm_proto_bridge_v1_txs::{slash::SlashInfo, test_utils::create_test_operators};

    use crate::{
        SlashValidationError,
        test_utils::{create_test_state, setup_slash_test},
        validation::validate_slash_stake_connector,
    };

    fn stake_connector_script_from_aux(info: &SlashInfo, aux: &VerifiedAuxData) -> ScriptBuf {
        let txout = aux
            .get_bitcoin_txout(info.stake_inpoint().outpoint())
            .expect("stake connector txout should exist in aux data");
        txout.script_pubkey.clone()
    }

    #[test]
    fn test_slash_tx_validation_success() {
        let (state, operators) = create_test_state();
        let (info, aux) = setup_slash_test(1, &operators);
        let operator_idx = info.header_aux().operator_idx();
        let stake_connector_script = stake_connector_script_from_aux(&info, &aux);
        validate_slash_stake_connector(&state, operator_idx, &stake_connector_script)
            .expect("handling valid slash info should succeed");
    }

    #[test]
    fn test_slash_tx_invalid_signers() {
        let (state, mut operators) = create_test_state();
        operators.pop();
        let (info, aux) = setup_slash_test(1, &operators);
        let operator_idx = info.header_aux().operator_idx();
        let stake_connector_script = stake_connector_script_from_aux(&info, &aux);
        let err = validate_slash_stake_connector(&state, operator_idx, &stake_connector_script)
            .unwrap_err();
        assert!(matches!(
            err,
            SlashValidationError::InvalidStakeConnectorScript
        ));
    }

    #[test]
    fn test_slash_tx_rejects_operator_outside_multisig() {
        // Genesis operators back the only N/N script the stake connector is locked to.
        let (mut state, operators) = create_test_state();
        let genesis_count = operators.len() as u32;

        // Add a fresh operator after genesis: it joins the *new* N/N config but was never part of
        // the genesis one that the stake connector commits to.
        let (_, new_pubkeys) = create_test_operators(1);
        state.apply_operator_set_update(&new_pubkeys, &[]);

        // Stake connector built from the genesis operators matches the genesis historical script.
        let (info, aux) = setup_slash_test(genesis_count, &operators);
        let stake_connector_script = stake_connector_script_from_aux(&info, &aux);

        // Slashing the newly added operator against the genesis script must be rejected.
        let err = validate_slash_stake_connector(&state, genesis_count, &stake_connector_script)
            .unwrap_err();
        assert!(matches!(
            err,
            SlashValidationError::OperatorNotInMultisig { operator, .. } if operator == genesis_count
        ));
    }
}
