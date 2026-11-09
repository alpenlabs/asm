//! Parameter fixtures shared by the crate's tests.

/// Mainnet's params file. Its genesis part never changes, so tests can pin its values.
pub(crate) fn mainnet_params_json() -> &'static str {
    include_str!("../envs/mainnet.json")
}
