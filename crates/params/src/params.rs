use serde::{Deserialize, Serialize};

use crate::{AsmGenesisParams, AsmRuntimeParams};

/// Top-level ASM parameter file.
///
/// Separates the inputs that build the genesis state from the per-spec values that specs after
/// genesis read while they execute. The genesis part defines the chain, so it stays the same for
/// the life of a network. Configuring a later spec only adds that spec's section to the runtime
/// part.
///
/// # File layout
///
/// The file is `{"genesis": {..}, "runtime": {..}}`, and unknown top-level fields are
/// rejected. Earlier releases wrote the genesis fields (`magic`, `anchor`, `subprotocols`) at
/// the top level, so such a file fails to parse. Converting it moves those fields under
/// `genesis` unchanged and adds `"runtime": {}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsmParams {
    /// Parameters used to build the genesis state.
    pub genesis: AsmGenesisParams,

    /// Per-spec values that specs after genesis read while they execute.
    pub runtime: AsmRuntimeParams,
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;
    use crate::test_fixtures::regtest_params_json;

    fn fixture() -> Value {
        serde_json::from_str(regtest_params_json()).expect("fixture is JSON")
    }

    fn parse(file: &Value) -> Result<AsmParams, serde_json::Error> {
        serde_json::from_value(file.clone())
    }

    #[test]
    fn deserializes_the_genesis_and_runtime_parts() {
        let params = parse(&fixture()).expect("params file deserializes");

        let spec_v2 = params
            .runtime
            .spec_v2
            .expect("fixture has a spec 2 section");
        assert_eq!(spec_v2.confirmation_depths.sequencer_update, 288);
    }

    #[test]
    fn accepts_an_empty_runtime_part_and_writes_it_back_empty() {
        let mut file = fixture();
        file["runtime"] = json!({});

        let params = parse(&file).expect("a network with no spec sections is valid");

        assert_eq!(params.runtime.spec_v2, None);
        assert_eq!(serde_json::to_value(&params).unwrap()["runtime"], json!({}));
    }

    /// A binary that predates a spec must still read a file that configures it.
    #[test]
    fn ignores_runtime_sections_it_does_not_know() {
        let mut file = fixture();
        file["runtime"]["spec_v9"] = json!({ "anything": 1 });

        let params = parse(&file).expect("unknown spec sections are ignored");

        assert_eq!(params, parse(&fixture()).unwrap());
    }

    #[test]
    fn rejects_the_flat_layout_of_earlier_releases() {
        let error = parse(&fixture()["genesis"])
            .expect_err("genesis fields at the top level are not a params file");

        assert!(
            error
                .to_string()
                .contains("expected `genesis` or `runtime`"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn rejects_a_file_without_a_runtime_part() {
        let mut file = fixture();
        file.as_object_mut().unwrap().remove("runtime");

        let error = parse(&file).expect_err("the runtime part is required, even if empty");

        assert!(
            error.to_string().contains("missing field `runtime`"),
            "unexpected error: {error}"
        );
    }
}
