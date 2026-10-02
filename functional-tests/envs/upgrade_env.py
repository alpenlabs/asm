import os

import flexitest

from factory.asm_rpc.config_cfg import (
    ArtifactSource,
    AsmArtifact,
    ExecutionTargetConfig,
    NativeArtifact,
    OrchestratorConfig,
    Sp1Artifact,
)

from .prover_env import SP1_GENERATED_DIR, ProverEnv

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
        config = super()._orchestrator_config(ectx, service_name)
        source, _ = _asm_v1_artifact()
        config.asm_artifacts.append(AsmArtifact(spec_id=ASM_V1_SPEC_ID, source=source))
        return config

    def _execution_targets(self) -> list[ExecutionTargetConfig]:
        return [
            *super()._execution_targets(),
            ExecutionTargetConfig(predicate=asm_v1_predicate(), spec_id=ASM_V1_SPEC_ID),
        ]

    def _admin_confirmation_depth(self) -> int:
        return UPGRADE_ADMIN_CONFIRMATION_DEPTH


def asm_v1_predicate() -> str:
    """Return the predicate the spec 1 ASM host must resolve to."""
    _, predicate = _asm_v1_artifact()
    return predicate


def _asm_v1_artifact() -> tuple[ArtifactSource, str]:
    """Pick the spec 1 ASM source matching the binary built by run_test.sh, together with the
    predicate it must resolve to."""
    backend = os.environ.get("ASM_PROVER_BACKEND", "native")
    if backend == "sp1":
        # The local guest build compiles the newest spec, which is spec 1. run_test.sh derives
        # its predicate from that same build, so the startup predicate check only catches a
        # mix-up between files, not a wrong guest.
        return (
            Sp1Artifact(elf_path=str(SP1_GENERATED_DIR / "asm.elf")),
            (SP1_GENERATED_DIR / "asm-predicate.txt").read_text().strip(),
        )
    if backend == "native":
        return (
            NativeArtifact(signing_key=NATIVE_TEST_ASM_V1_SIGNING_KEY),
            NATIVE_TEST_ASM_V1_PREDICATE,
        )
    raise ValueError(f"Unknown ASM_PROVER_BACKEND: {backend!r} (expected: native|sp1)")
