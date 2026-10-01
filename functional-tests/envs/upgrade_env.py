import os

import flexitest

from factory.asm_rpc.config_cfg import (
    AsmArtifact,
    ExecutionTargetConfig,
    NativeArtifact,
    OrchestratorConfig,
)

from .prover_env import ProverEnv

# Signing key of the native spec 1 host. Distinct from the spec 0 key so the
# two programs have different predicates, as an upgrade requires.
NATIVE_TEST_ASM_V1_SIGNING_KEY = "03" * 32
# Predicate the native ASM host derives from `NATIVE_TEST_ASM_V1_SIGNING_KEY`.
NATIVE_TEST_ASM_V1_PREDICATE = (
    "Bip340Schnorr:531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337"
)
ASM_V1_SPEC_ID = 1

# Short enough to activate an upgrade within a few blocks, but non-zero so the
# update goes through the admin queue as it would on a deployed chain.
UPGRADE_ADMIN_CONFIRMATION_DEPTH = 2


class UpgradeEnv(ProverEnv):
    """Prover environment that starts under spec 0 and can prove spec 1 once an admin
    update activates it."""

    def _orchestrator_config(
        self, ectx: flexitest.EnvContext, service_name: str = "asm_rpc"
    ) -> OrchestratorConfig:
        # TODO(STR-4106): build an SP1 guest for spec 1 so this env can run against SP1.
        # Each guest compiles one concrete spec, and only spec 0 has one today.
        backend = os.environ.get("ASM_PROVER_BACKEND", "native")
        if backend != "native":
            raise ValueError(f"spec {ASM_V1_SPEC_ID} has no {backend} guest; use native")

        config = super()._orchestrator_config(ectx, service_name)
        config.asm_artifacts.append(
            AsmArtifact(
                spec_id=ASM_V1_SPEC_ID,
                source=NativeArtifact(signing_key=NATIVE_TEST_ASM_V1_SIGNING_KEY),
            )
        )
        return config

    def _execution_targets(self) -> list[ExecutionTargetConfig]:
        return [
            *super()._execution_targets(),
            ExecutionTargetConfig(predicate=NATIVE_TEST_ASM_V1_PREDICATE, spec_id=ASM_V1_SPEC_ID),
        ]

    def _admin_confirmation_depth(self) -> int:
        return UPGRADE_ADMIN_CONFIRMATION_DEPTH
