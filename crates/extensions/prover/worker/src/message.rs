//! Input messages driving the prover worker.
//!
//! Unlike the ASM worker, the prover has no external command surface: it is
//! driven entirely by the ASM worker's commit subscription plus a periodic
//! wakeup tick. The framework's [`TickingInput`](strata_service::TickingInput)
//! merges those two sources into a single stream of [`TickMsg`]:
//!
//! - [`TickMsg::Msg`] carries a newly committed [`L1BlockCommitment`], which the service expands
//!   into the ASM step proof and Moho recursive proof it requires.
//! - [`TickMsg::Tick`] is the periodic wakeup that drives the reconcile + schedule cycle.

use strata_identifiers::L1BlockCommitment;
use strata_service::TickMsg;

/// Input message processed by the prover service.
pub type ProverMessage = TickMsg<L1BlockCommitment>;
