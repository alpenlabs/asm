use crate::{AnchorState, Subprotocol};

/// Specification for a concrete ASM instantiation describing the subprotocols we
/// want to invoke and in what order.
///
/// This way, we only have to declare the subprotocols a single time and they
/// will always be processed in a consistent order as defined by an `AsmSpec`.
pub trait AsmSpec {
    /// The parameters type used to construct the genesis state.
    type Params;

    /// Function that calls the stage with each subprotocol we intend to
    /// process, in the order we intend to process them.
    ///
    /// This MUST NOT change its behavior depending on the stage we're
    /// processing.
    fn call_subprotocols(&self, stage: &mut impl Stage);

    /// Builds the genesis [`AnchorState`] from the given parameters.
    fn construct_genesis_state(&self, params: &Self::Params) -> AnchorState;
}

/// Impl of a subprotocol execution stage.
pub trait Stage {
    /// Invoked by the ASM spec to perform a the stage's logic with respect to
    /// the subprotocol.
    fn invoke_subprotocol<S: Subprotocol>(&mut self);
}
