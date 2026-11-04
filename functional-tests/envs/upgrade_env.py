import os

import flexitest

from factory.asm_rpc.config_cfg import (
    ArtifactSource,
    AsmArtifact,
    ExecutionTargetConfig,
    NativeArtifact,
    OrchestratorConfig,
)

from .prover_env import ProverEnv, sp1_asm_artifact

# Signing keys of the native spec 1 and spec 2 hosts. Distinct from each other and from the
# spec 0 key so every program has its own predicate, as an upgrade requires.
NATIVE_TEST_ASM_V1_SIGNING_KEY = "03" * 32
NATIVE_TEST_ASM_V2_SIGNING_KEY = "04" * 32
# Predicates the native ASM hosts derive from the signing keys above.
NATIVE_TEST_ASM_V1_PREDICATE = (
    "Bip340Schnorr:531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337"
)
NATIVE_TEST_ASM_V2_PREDICATE = (
    "Bip340Schnorr:462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b"
)
ASM_V1_SPEC_ID = 1
ASM_V2_SPEC_ID = 2

# The specs this env can upgrade to, in activation order.
UPGRADE_SPEC_IDS = (ASM_V1_SPEC_ID, ASM_V2_SPEC_ID)

_NATIVE_TEST_ASM_HOSTS = {
    ASM_V1_SPEC_ID: (NATIVE_TEST_ASM_V1_SIGNING_KEY, NATIVE_TEST_ASM_V1_PREDICATE),
    ASM_V2_SPEC_ID: (NATIVE_TEST_ASM_V2_SIGNING_KEY, NATIVE_TEST_ASM_V2_PREDICATE),
}

# Short enough to activate an upgrade within a few blocks, but non-zero so the
# update goes through the admin queue as it would on a deployed chain.
UPGRADE_ADMIN_CONFIRMATION_DEPTH = 2


class UpgradeEnv(ProverEnv):
    """Prover environment that starts under spec 0 and can prove specs 1 and 2 once admin
    updates activate them."""

    def _orchestrator_config(
        self, ectx: flexitest.EnvContext, service_name: str = "asm_rpc"
    ) -> OrchestratorConfig:
        config = super()._orchestrator_config(ectx, service_name)
        for spec_id in UPGRADE_SPEC_IDS:
            source, _ = _asm_upgrade_artifact(spec_id)
            config.asm_artifacts.append(AsmArtifact(spec_id=spec_id, source=source))
        return config

    def _execution_targets(self) -> list[ExecutionTargetConfig]:
        return [
            *super()._execution_targets(),
            *(
                ExecutionTargetConfig(predicate=asm_upgrade_predicate(spec_id), spec_id=spec_id)
                for spec_id in UPGRADE_SPEC_IDS
            ),
        ]

    def _admin_confirmation_depth(self) -> int:
        return UPGRADE_ADMIN_CONFIRMATION_DEPTH


def asm_upgrade_predicate(spec_id: int) -> str:
    """Return the predicate the ASM host for upgrade spec `spec_id` must resolve to."""
    _, predicate = _asm_upgrade_artifact(spec_id)
    return predicate


def _asm_upgrade_artifact(spec_id: int) -> tuple[ArtifactSource, str]:
    """Pick the ASM source for upgrade spec `spec_id` matching the binary built by
    run_test.sh, together with the predicate it must resolve to."""
    backend = os.environ.get("ASM_PROVER_BACKEND", "native")
    if backend == "sp1":
        return sp1_asm_artifact(spec_id)
    if backend == "native":
        signing_key, predicate = _NATIVE_TEST_ASM_HOSTS[spec_id]
        return NativeArtifact(signing_key=signing_key), predicate
    raise ValueError(f"Unknown ASM_PROVER_BACKEND: {backend!r} (expected: native|sp1)")
