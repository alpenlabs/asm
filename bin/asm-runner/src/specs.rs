//! Assembly of compiled specs for genesis, native execution, and proof hosts.

use strata_asm_common::{AnchorState, AsmSpec, SpecId};
use strata_asm_params::AsmParams;
use strata_asm_prover_worker::{
    AsmArtifactConfig, AsmHostLoader, AsmProofHost, ProofHost, ProverError, ProverResult,
    load_spec_host,
};
use strata_asm_spec::StrataAsmSpec;
use strata_asm_worker::{ExecutionRegistry, WorkerResult};
use strata_predicate::PredicateKey;

/// Node-side selection only; each guest still compiles a single concrete spec.
pub(crate) enum CompiledSpec {
    V0,
}

impl CompiledSpec {
    pub(crate) fn resolve(id: SpecId) -> ProverResult<Self> {
        match id {
            StrataAsmSpec::ID => Ok(Self::V0),
            _ => Err(ProverError::BackendUnavailable(
                "ASM spec is not compiled into this binary",
            )),
        }
    }

    pub(crate) fn genesis(&self, params: &AsmParams) -> AnchorState {
        match self {
            Self::V0 => StrataAsmSpec.construct_genesis_state(params),
        }
    }

    pub(crate) fn register_execution(
        &self,
        registry: &mut ExecutionRegistry,
        predicate: PredicateKey,
    ) -> WorkerResult<()> {
        match self {
            Self::V0 => registry.register(predicate, StrataAsmSpec),
        }
    }
}

/// Constructs hosts for the node's compiled specs; each guest remains version-specific.
#[derive(Debug)]
pub(crate) struct CompiledSpecLoader;

impl AsmHostLoader for CompiledSpecLoader {
    type Host = ProofHost;

    fn validate_spec(&self, spec_id: SpecId) -> ProverResult<()> {
        CompiledSpec::resolve(spec_id).map(|_| ())
    }

    async fn load(&self, artifact: &AsmArtifactConfig) -> ProverResult<AsmProofHost<ProofHost>> {
        match CompiledSpec::resolve(artifact.spec_id)? {
            CompiledSpec::V0 => load_spec_host(&artifact.source, StrataAsmSpec).await,
        }
    }
}
