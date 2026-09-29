//! Native ASM assembly shared by the standalone runner and embedded callers such as OL.
//!
//! This module owns the compiled-spec catalog, genesis construction, and execution registry
//! assembly. It has no proving-backend dependency. Callers supply the chain's public genesis
//! predicate and a trusted predicate-to-spec mapping; registration does not authenticate that
//! mapping. Keep it immutable across restarts, as required by [`ExecutionRegistry`].
//!
//! The worker owns per-block selection, upgrade activation, and reorg recovery. An embedded
//! caller configures it with the same native assembly as the runner:
//!
//! ```no_run
//! use strata_asm_spec::host::{CompiledSpec, NativeAssemblyError, build_execution_registry};
//! use strata_asm_worker::AsmWorkerBuilder;
//! # use strata_asm_common::SpecId;
//! # use strata_asm_params::AsmParams;
//! # use strata_predicate::PredicateKey;
//! # fn configure_worker<W>(context: W, params: &AsmParams,
//! #     genesis_predicate: PredicateKey, targets: Vec<(PredicateKey, SpecId)>)
//! #     -> Result<AsmWorkerBuilder<W>, NativeAssemblyError> {
//! let registry = build_execution_registry(targets)?;
//! let spec = CompiledSpec::resolve(registry.resolve(&genesis_predicate)?.spec_id())?;
//! let genesis = spec.construct_genesis_state(params);
//! let builder = AsmWorkerBuilder::new()
//!     .with_context(context)
//!     .with_genesis(genesis, genesis_predicate)
//!     .with_registry(registry);
//! // Launch with the caller's task executor after supplying its WorkerContext.
//! # Ok(builder)
//! # }
//! ```

use strata_asm_common::{AnchorState, AsmSpec, SpecId};
use strata_asm_params::AsmParams;
use strata_asm_worker::{ExecutionRegistry, WorkerError};
use strata_predicate::PredicateKey;
use thiserror::Error;

use crate::{StrataAsmSpec, StrataAsmSpecV1};

/// A failure to assemble the configured native execution targets.
#[derive(Debug, Error)]
pub enum NativeAssemblyError {
    /// The library does not contain the requested implementation.
    #[error("ASM spec {0} is not compiled into this library")]
    UnsupportedSpec(SpecId),
    /// The target mapping violates an execution-registry invariant.
    #[error(transparent)]
    Registry(#[from] WorkerError),
}

/// The native implementations compiled into this release.
///
/// Proof-host assembly can match this catalog separately without adding a prover dependency
/// to native callers. Each guest continues to compile a single concrete spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompiledSpec {
    /// The initial Strata ASM ruleset.
    V0,
    /// Its successor, which commits `OperatorClaimUnlockV1` bridge export leaves.
    V1,
}

impl CompiledSpec {
    /// Selects a compiled implementation by its protocol spec ID.
    pub fn resolve(id: SpecId) -> Result<Self, NativeAssemblyError> {
        match id {
            StrataAsmSpec::ID => Ok(Self::V0),
            StrataAsmSpecV1::ID => Ok(Self::V1),
            _ => Err(NativeAssemblyError::UnsupportedSpec(id)),
        }
    }

    /// Constructs the genesis anchor under this implementation's rules.
    pub fn construct_genesis_state(&self, params: &AsmParams) -> AnchorState {
        match self {
            Self::V0 => StrataAsmSpec.construct_genesis_state(params),
            Self::V1 => StrataAsmSpecV1.construct_genesis_state(params),
        }
    }

    fn register_execution(
        self,
        registry: &mut ExecutionRegistry,
        predicate: PredicateKey,
    ) -> Result<(), WorkerError> {
        match self {
            Self::V0 => registry.register(predicate, StrataAsmSpec),
            Self::V1 => registry.register(predicate, StrataAsmSpecV1),
        }
    }
}

/// Builds the native registry from trusted `(predicate, spec_id)` associations.
///
/// Rejects unsupported implementations and duplicate predicates or spec IDs. Entries describe
/// local capabilities; the worker follows genesis and committed upgrade logs for activation.
/// Callers must also resolve their genesis predicate before launching the worker.
pub fn build_execution_registry(
    targets: impl IntoIterator<Item = (PredicateKey, SpecId)>,
) -> Result<ExecutionRegistry, NativeAssemblyError> {
    let mut registry = ExecutionRegistry::default();
    for (predicate, spec_id) in targets {
        CompiledSpec::resolve(spec_id)?.register_execution(&mut registry, predicate)?;
    }
    Ok(registry)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_catalog_resolves_the_configured_program_and_rejects_unknown_authority() {
        let predicate = PredicateKey::always_accept();
        let registry = build_execution_registry([(predicate.clone(), StrataAsmSpec::ID)]).unwrap();
        assert_eq!(
            registry.resolve(&predicate).unwrap().spec_id(),
            StrataAsmSpec::ID
        );
        assert!(matches!(
            registry.resolve(&PredicateKey::never_accept()),
            Err(WorkerError::UnsupportedExecutionPredicate(_))
        ));
    }

    /// Both rulesets are compiled in, and a registry may carry them at once so that historical
    /// work keeps resolving its own parent's predicate across an activation.
    #[test]
    fn native_catalog_carries_both_rulesets_at_once() {
        let genesis = PredicateKey::always_accept();
        let successor = PredicateKey::never_accept();
        let registry = build_execution_registry([
            (genesis.clone(), StrataAsmSpec::ID),
            (successor.clone(), StrataAsmSpecV1::ID),
        ])
        .unwrap();

        assert_eq!(
            registry.resolve(&genesis).unwrap().spec_id(),
            StrataAsmSpec::ID
        );
        assert_eq!(
            registry.resolve(&successor).unwrap().spec_id(),
            StrataAsmSpecV1::ID
        );
    }

    #[test]
    fn assembly_rejects_unsupported_specs_and_ambiguous_mappings() {
        assert!(matches!(
            build_execution_registry([(PredicateKey::always_accept(), SpecId::MAX)]),
            Err(NativeAssemblyError::UnsupportedSpec(SpecId::MAX))
        ));
        assert!(matches!(
            build_execution_registry([
                (PredicateKey::always_accept(), StrataAsmSpec::ID),
                (PredicateKey::always_accept(), StrataAsmSpec::ID),
            ]),
            Err(NativeAssemblyError::Registry(
                WorkerError::DuplicateExecutionPredicate
            ))
        ));
        assert!(matches!(
            build_execution_registry([
                (PredicateKey::always_accept(), StrataAsmSpec::ID),
                (PredicateKey::never_accept(), StrataAsmSpec::ID),
            ]),
            Err(NativeAssemblyError::Registry(
                WorkerError::DuplicateExecutionSpec(_)
            ))
        ));
    }
}
