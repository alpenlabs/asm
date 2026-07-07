use std::fmt::Debug;

use crate::{AnchorState, StfParams, Subprotocol};

/// Specification for a concrete ASM instantiation: the subprotocols we intend
/// to invoke and the order to invoke them in, plus the parameter set an
/// instance is configured with.
///
/// The pipeline is declared as a type-level list rather than a method so the
/// invocation order is a compile-time constant of the spec type: it cannot
/// vary per stage, per execution, or with any runtime configuration — the
/// determinism the STF requires. Everything that must traverse the
/// subprotocols (loading, processing, finishing, genesis construction) drives
/// off this single declaration.
pub trait AsmSpec {
    /// The subprotocols processed by this ASM, in invocation order.
    type Subprotocols: SubprotoList;

    /// The full parameter set an instance of this ASM is configured with.
    ///
    /// Owning the params type ties everything derived from configuration —
    /// the genesis layout, the STF params — to the same spec that declares
    /// the pipeline, so a worker instantiated with this spec cannot be handed
    /// a genesis state built for a different one.
    type Params: Debug;

    /// Builds the genesis anchor state from the params.
    fn construct_genesis_state(params: &Self::Params) -> AnchorState;

    /// Extracts the base STF params every transition executes under.
    fn stf_params(params: &Self::Params) -> StfParams;

    /// Invokes the stage with each subprotocol, in the declared order.
    fn call_subprotocols(stage: &mut impl Stage) {
        Self::Subprotocols::for_each(stage);
    }
}

/// A type-level list of [`Subprotocol`]s, traversed left to right.
///
/// Implemented for tuples of subprotocols up to 8 elements (e.g.
/// `(AdminSubproto, BridgeSubproto)`); the unit type is the empty list.
pub trait SubprotoList {
    /// Invokes the stage with each subprotocol in the list, in order.
    fn for_each(stage: &mut impl Stage);
}

impl SubprotoList for () {
    fn for_each(_stage: &mut impl Stage) {}
}

/// Generates the [`SubprotoList`] impl for one tuple arity.
///
/// Rust has no variadic generics, so tuples of arbitrary length cannot be
/// covered by a single impl. Like the standard library's tuple impls of
/// `Hash`/`Debug`, we stamp out one impl per arity up to a cap. Growing an
/// ASM past the cap fails to compile ("SubprotoList is not implemented");
/// the fix is one more invocation below.
macro_rules! impl_subproto_list {
    ($($s:ident),+) => {
        impl<$($s: Subprotocol),+> SubprotoList for ($($s,)+) {
            fn for_each(stage: &mut impl Stage) {
                $(stage.invoke_subprotocol::<$s>();)+
            }
        }
    };
}

impl_subproto_list!(A);
impl_subproto_list!(A, B);
impl_subproto_list!(A, B, C);
impl_subproto_list!(A, B, C, D);
impl_subproto_list!(A, B, C, D, E);
impl_subproto_list!(A, B, C, D, E, F);
impl_subproto_list!(A, B, C, D, E, F, G);
impl_subproto_list!(A, B, C, D, E, F, G, H);

/// Impl of a subprotocol execution stage.
pub trait Stage {
    /// Invoked by the ASM spec to perform the stage's logic with respect to
    /// the subprotocol.
    fn invoke_subprotocol<S: Subprotocol>(&mut self);
}
