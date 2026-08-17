//! Loader infrastructure for setting up the context.

use std::collections::BTreeMap;

use strata_asm_common::{
    AnchorState, AuxRequestCollector, AuxRequests, HeaderVerificationState, SectionStateExt, Stage,
    Subprotocol, SubprotocolId, TxInputRef, VerifiedAuxData,
};
use strata_identifiers::L1BlockCommitment;

use crate::manager::SubprotoManager;

/// Stage to load each subprotocol.
pub(crate) struct LoaderStage<'c> {
    manager: &'c mut SubprotoManager,
    anchor_state: &'c AnchorState,
}

impl<'c> LoaderStage<'c> {
    pub(crate) fn new(manager: &'c mut SubprotoManager, anchor_state: &'c AnchorState) -> Self {
        Self {
            manager,
            anchor_state,
        }
    }
}

impl Stage for LoaderStage<'_> {
    fn invoke_subprotocol<S: Subprotocol>(&mut self) {
        let state = self
            .anchor_state
            .find_section(S::ID)
            .unwrap_or_else(|| panic!("asm: missing section for subprotocol {}", S::ID))
            .try_to_state::<S>()
            .unwrap_or_else(|e| panic!("asm: failed to deserialize section for {}: {e}", S::ID));
        self.manager.insert_subproto::<S>(state);
    }
}

/// Stage to process txs pre-extracted from the block for each subprotocol.
pub(crate) struct PreProcessStage<'c> {
    manager: &'c mut SubprotoManager,
    tx_bufs: &'c BTreeMap<SubprotocolId, Vec<TxInputRef<'c>>>,
    aux_collector: AuxRequestCollector,
}

impl<'c> PreProcessStage<'c> {
    pub(crate) fn new(
        manager: &'c mut SubprotoManager,
        anchor_state: &'c AnchorState,
        tx_bufs: &'c BTreeMap<SubprotocolId, Vec<TxInputRef<'c>>>,
    ) -> Self {
        let accumulator = &anchor_state.chain_view.history_accumulator;

        // Manifests only exist for heights below the block being processed — this
        // block's own manifest is appended at the end of the transition — so the
        // accumulator's last inserted height is the highest one that can be served.
        let aux_collector = AuxRequestCollector::new(accumulator.last_inserted_height());
        Self {
            manager,
            tx_bufs,
            aux_collector,
        }
    }

    pub(crate) fn into_aux_requests(self) -> AuxRequests {
        self.aux_collector.into_requests()
    }
}

impl Stage for PreProcessStage<'_> {
    fn invoke_subprotocol<S: Subprotocol>(&mut self) {
        let txs = self
            .tx_bufs
            .get(&S::ID)
            .map(|v| v.as_slice())
            .unwrap_or(&[]);

        self.manager
            .invoke_pre_process_txs::<S>(&mut self.aux_collector, txs);
    }
}

/// Stage to process txs pre-extracted from the block for each subprotocol.
pub(crate) struct ProcessStage<'c> {
    manager: &'c mut SubprotoManager,
    header_vs: &'c HeaderVerificationState,
    tx_bufs: BTreeMap<SubprotocolId, Vec<TxInputRef<'c>>>,
    verified_aux_data: VerifiedAuxData,
}

impl<'c> ProcessStage<'c> {
    pub(crate) fn new(
        manager: &'c mut SubprotoManager,
        header_vs: &'c HeaderVerificationState,
        tx_bufs: BTreeMap<SubprotocolId, Vec<TxInputRef<'c>>>,
        verified_aux_data: VerifiedAuxData,
    ) -> Self {
        Self {
            manager,
            header_vs,
            tx_bufs,
            verified_aux_data,
        }
    }
}

impl Stage for ProcessStage<'_> {
    fn invoke_subprotocol<S: Subprotocol>(&mut self) {
        let txs = self
            .tx_bufs
            .get(&S::ID)
            .map(|v| v.as_slice())
            .unwrap_or(&[]);

        self.manager
            .invoke_process_txs::<S>(txs, self.header_vs, &self.verified_aux_data);
    }
}

/// Stage to handle messages exchanged between subprotocols in execution.
pub(crate) struct FinishStage<'m> {
    manager: &'m mut SubprotoManager,
    l1ref: &'m L1BlockCommitment,
}

impl<'m> FinishStage<'m> {
    pub(crate) fn new(manager: &'m mut SubprotoManager, l1ref: &'m L1BlockCommitment) -> Self {
        Self { manager, l1ref }
    }
}

impl Stage for FinishStage<'_> {
    fn invoke_subprotocol<S: Subprotocol>(&mut self) {
        self.manager.invoke_process_msgs::<S>(self.l1ref);
    }
}
