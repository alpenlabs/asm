//! Native ASM assembly shared by the standalone runner and embedded callers such as OL.
//!
//! This module owns the compiled-spec catalog, genesis construction, and execution registry
//! assembly. It has no proving-backend dependency. Callers supply the chain's public genesis
//! predicate and a trusted predicate-to-spec mapping; registration does not authenticate that
//! mapping. Keep it immutable across restarts, as required by [`ExecutionRegistry`].
//!
//! Callers also supply the chain's [`AsmRuntimeParams`]. A spec that reads a section of them,
//! such as [`StrataAsmSpecV2`], must see the same section, or the same absence of one, as its
//! proof guest baked in, or native execution and proofs disagree.
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
//! let registry = build_execution_registry(targets, &params.runtime)?;
//! let spec = CompiledSpec::resolve(registry.resolve(&genesis_predicate)?.spec_id())?;
//! let genesis = spec.construct_genesis_state(params)?;
//! let builder = AsmWorkerBuilder::new()
//!     .with_context(context)
//!     .with_genesis(genesis, genesis_predicate)
//!     .with_registry(registry);
//! // Launch with the caller's task executor after supplying its WorkerContext.
//! # Ok(builder)
//! # }
//! ```

use strata_asm_common::{AnchorState, AsmSpec, SpecId};
use strata_asm_params::{AsmParams, AsmRuntimeParams};
use strata_asm_worker::{ExecutionRegistry, WorkerError};
use strata_predicate::PredicateKey;
use thiserror::Error;

use crate::{StrataAsmSpec, StrataAsmSpecV1, StrataAsmSpecV2};

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
    /// The successor to both, which installs the admin confirmation depths from the
    /// `spec_v2` section of [`AsmRuntimeParams`], if there is one.
    V2,
}

impl CompiledSpec {
    /// Selects a compiled implementation by its protocol spec ID.
    pub fn resolve(id: SpecId) -> Result<Self, NativeAssemblyError> {
        match id {
            StrataAsmSpec::ID => Ok(Self::V0),
            StrataAsmSpecV1::ID => Ok(Self::V1),
            StrataAsmSpecV2::ID => Ok(Self::V2),
            _ => Err(NativeAssemblyError::UnsupportedSpec(id)),
        }
    }

    /// Constructs the genesis anchor under this implementation's rules.
    pub fn construct_genesis_state(
        &self,
        params: &AsmParams,
    ) -> Result<AnchorState, NativeAssemblyError> {
        Ok(match self {
            Self::V0 => StrataAsmSpec.construct_genesis_state(&params.genesis),
            Self::V1 => StrataAsmSpecV1.construct_genesis_state(&params.genesis),
            Self::V2 => spec_v2(&params.runtime).construct_genesis_state(&params.genesis),
        })
    }

    fn register_execution(
        self,
        registry: &mut ExecutionRegistry,
        predicate: PredicateKey,
        runtime: &AsmRuntimeParams,
    ) -> Result<(), NativeAssemblyError> {
        match self {
            Self::V0 => registry.register(predicate, StrataAsmSpec)?,
            Self::V1 => registry.register(predicate, StrataAsmSpecV1)?,
            Self::V2 => registry.register(predicate, spec_v2(runtime))?,
        }
        Ok(())
    }
}

/// Builds spec 2 from the `spec_v2` section of the runtime params, if there is one.
pub fn spec_v2(runtime: &AsmRuntimeParams) -> StrataAsmSpecV2 {
    StrataAsmSpecV2::new(
        runtime
            .spec_v2
            .as_ref()
            .map(|section| section.confirmation_depths.clone()),
    )
}

/// Builds the native registry from trusted `(predicate, spec_id)` associations.
///
/// Rejects unsupported implementations and duplicate predicates or spec IDs. Entries describe
/// local capabilities; the worker follows genesis and committed upgrade logs for activation.
/// Callers must also resolve their genesis predicate before launching the worker.
pub fn build_execution_registry(
    targets: impl IntoIterator<Item = (PredicateKey, SpecId)>,
    runtime: &AsmRuntimeParams,
) -> Result<ExecutionRegistry, NativeAssemblyError> {
    let mut registry = ExecutionRegistry::default();
    for (predicate, spec_id) in targets {
        CompiledSpec::resolve(spec_id)?.register_execution(&mut registry, predicate, runtime)?;
    }
    Ok(registry)
}

#[cfg(test)]
mod tests {
    use strata_asm_params::{ConfirmationDepths, SpecV2Params};
    use strata_predicate::PredicateTypeId;

    use super::*;

    fn runtime_params() -> AsmRuntimeParams {
        AsmRuntimeParams {
            spec_v2: Some(SpecV2Params {
                confirmation_depths: ConfirmationDepths {
                    strata_admin_multisig_update: 6,
                    strata_seq_manager_multisig_update: 6,
                    alpen_admin_multisig_update: 6,
                    strata_security_council_multisig_update: 6,
                    operator_update: 6,
                    sequencer_update: 6,
                    ol_stf_vk_update: 6,
                    asm_stf_vk_update: 6,
                    ee_stf_vk_update: 6,
                    defcon3: 6,
                    safe_harbor_address_update: 6,
                },
            }),
        }
    }

    #[test]
    fn native_catalog_resolves_the_configured_program_and_rejects_unknown_authority() {
        let predicate = PredicateKey::always_accept();
        let registry =
            build_execution_registry([(predicate.clone(), StrataAsmSpec::ID)], &runtime_params())
                .unwrap();
        assert_eq!(
            registry.resolve(&predicate).unwrap().spec_id(),
            StrataAsmSpec::ID
        );
        assert!(matches!(
            registry.resolve(&PredicateKey::never_accept()),
            Err(WorkerError::UnsupportedExecutionPredicate(_))
        ));
    }

    /// Every ruleset is compiled in, and a registry may carry them at once so that historical
    /// work keeps resolving its own parent's predicate across an activation.
    #[test]
    fn native_catalog_carries_every_ruleset_at_once() {
        let targets = [
            (PredicateKey::always_accept(), StrataAsmSpec::ID),
            (PredicateKey::never_accept(), StrataAsmSpecV1::ID),
            (
                PredicateKey::try_new(PredicateTypeId::AlwaysAccept, vec![2]).unwrap(),
                StrataAsmSpecV2::ID,
            ),
        ];
        let registry = build_execution_registry(targets.clone(), &runtime_params()).unwrap();

        for (predicate, spec_id) in targets {
            assert_eq!(registry.resolve(&predicate).unwrap().spec_id(), spec_id);
        }
    }

    #[test]
    fn spec_v2_registers_without_its_runtime_section() {
        let predicate = PredicateKey::always_accept();
        let empty = AsmRuntimeParams { spec_v2: None };

        let registry = build_execution_registry([(predicate.clone(), StrataAsmSpecV2::ID)], &empty)
            .expect("spec 2 keeps the chain's depths without a section");

        assert_eq!(
            registry.resolve(&predicate).unwrap().spec_id(),
            StrataAsmSpecV2::ID
        );
    }

    #[test]
    fn assembly_rejects_unsupported_specs_and_ambiguous_mappings() {
        assert!(matches!(
            build_execution_registry(
                [(PredicateKey::always_accept(), SpecId::MAX)],
                &runtime_params()
            ),
            Err(NativeAssemblyError::UnsupportedSpec(SpecId::MAX))
        ));
        assert!(matches!(
            build_execution_registry(
                [
                    (PredicateKey::always_accept(), StrataAsmSpec::ID),
                    (PredicateKey::always_accept(), StrataAsmSpec::ID),
                ],
                &runtime_params()
            ),
            Err(NativeAssemblyError::Registry(
                WorkerError::DuplicateExecutionPredicate
            ))
        ));
        assert!(matches!(
            build_execution_registry(
                [
                    (PredicateKey::always_accept(), StrataAsmSpec::ID),
                    (PredicateKey::never_accept(), StrataAsmSpec::ID),
                ],
                &runtime_params()
            ),
            Err(NativeAssemblyError::Registry(
                WorkerError::DuplicateExecutionSpec(_)
            ))
        ));
    }
}
