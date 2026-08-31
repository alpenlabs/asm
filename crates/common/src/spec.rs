use crate::{AnchorState, AsmResult, SpecId, Subprotocol};

/// Specification for a concrete ASM instantiation describing the subprotocols we
/// want to invoke and in what order.
///
/// This way, we only have to declare the subprotocols a single time and they
/// will always be processed in a consistent order as defined by an `AsmSpec`.
pub trait AsmSpec {
    /// Ruleset identity written to genesis and successful transition outputs.
    const ID: SpecId;

    /// The parameters type used to construct the genesis state.
    type GenesisParams;

    /// Prepares working state for this ruleset before either STF entrypoint loads sections.
    ///
    /// Use only source state and spec constants; preserve magic and chain view.
    /// Set `spec_id` to [`Self::ID`] after migration and leave compatible state unchanged.
    /// Returns an owned working state while preserving the borrowed parent.
    ///
    /// # Example
    ///
    /// A future spec can migrate only checkpoint from schema 0 to 1. Here
    /// `CheckpointV0`, `CheckpointV1`, and `migrate_checkpoint` are illustrative
    /// subprotocol implementations and a deterministic conversion, not existing types.
    /// Admin and bridge sections remain untouched. Inside `impl AsmSpec for SpecN`:
    ///
    /// ```ignore
    /// fn prepare(&self, source: &AnchorState) -> AsmResult<AnchorState> {
    ///     let mut state = source.clone();
    ///     assert!(matches!(state.spec_id, 0 | 1), "unsupported source spec");
    ///     let checkpoint = state.sections.iter_mut()
    ///         .find(|section| section.id == CheckpointV1::ID)
    ///         .expect("supported source has a checkpoint section");
    ///
    ///     if state.spec_id == Self::ID {
    ///         assert_eq!(checkpoint.version, CheckpointV1::STATE_VERSION);
    ///         return Ok(state);
    ///     }
    ///
    ///     let old = checkpoint.try_to_state::<CheckpointV0>()?;
    ///     let migrated = migrate_checkpoint(old);
    ///     *checkpoint = SectionState::from_state::<CheckpointV1>(&migrated)?;
    ///     state.spec_id = Self::ID;
    ///     Ok(state)
    /// }
    /// ```
    ///
    /// The example uses [`crate::SectionStateExt`] for checked decoding and versioned encoding.
    ///
    /// # Errors
    ///
    /// Returns an error if a migration cannot represent the source state, for example because a
    /// migrated section no longer fits its capacity. The block then fails to process.
    ///
    /// # Panics
    ///
    /// Panics if the source spec is unsupported.
    fn prepare(&self, state: &AnchorState) -> AsmResult<AnchorState>;

    /// Function that calls the stage with each subprotocol we intend to
    /// process, in the order we intend to process them.
    ///
    /// This MUST NOT change its behavior depending on the stage we're
    /// processing.
    fn call_subprotocols(&self, stage: &mut impl Stage);

    /// Builds the genesis [`AnchorState`] from the given parameters.
    fn construct_genesis_state(&self, params: &Self::GenesisParams) -> AnchorState;

    /// Returns the L1 block height of the chain genesis (anchor) block.
    ///
    /// Used by the worker to align the height-indexed manifest MMR with L1
    /// block heights (positions `0..=genesis_l1_height` are sentinel-prefilled).
    fn genesis_l1_height(&self, params: &Self::GenesisParams) -> u64;
}

/// Impl of a subprotocol execution stage.
pub trait Stage {
    /// Invoked by the ASM spec to perform a the stage's logic with respect to
    /// the subprotocol.
    fn invoke_subprotocol<S: Subprotocol>(&mut self);
}
