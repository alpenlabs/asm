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
from .upgrade_env import (
    ASM_V1_SPEC_ID,
    UPGRADE_ADMIN_CONFIRMATION_DEPTH,
    asm_v1_artifact,
    asm_v1_predicate,
)

# Signing key of the native spec 2 host. Distinct from the spec 1 key so the
# two programs have different predicates, as an upgrade requires.
NATIVE_TEST_ASM_V2_SIGNING_KEY = "05" * 32
# Predicate the native ASM host derives from `NATIVE_TEST_ASM_V2_SIGNING_KEY`.
NATIVE_TEST_ASM_V2_PREDICATE = (
    "Bip340Schnorr:62c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f7"
)
ASM_V2_SPEC_ID = 2


class UpgradeV2Env(ProverEnv):
    """Prover environment that starts under spec 1 and can prove spec 2 once an admin
    update activates it."""

    def _orchestrator_config(
        self, ectx: flexitest.EnvContext, service_name: str = "asm_rpc"
    ) -> OrchestratorConfig:
        config = super()._orchestrator_config(ectx, service_name)
        v1_source, _ = asm_v1_artifact()
        v2_source, _ = _asm_v2_artifact()
        config.asm_artifacts = [
            AsmArtifact(spec_id=ASM_V1_SPEC_ID, source=v1_source),
            AsmArtifact(spec_id=ASM_V2_SPEC_ID, source=v2_source),
        ]
        return config

    def _execution_targets(self) -> list[ExecutionTargetConfig]:
        # The first target is the genesis program, so the chain starts under spec 1.
        return [
            ExecutionTargetConfig(predicate=asm_v1_predicate(), spec_id=ASM_V1_SPEC_ID),
            ExecutionTargetConfig(predicate=asm_v2_predicate(), spec_id=ASM_V2_SPEC_ID),
        ]

    def _admin_confirmation_depth(self) -> int:
        return UPGRADE_ADMIN_CONFIRMATION_DEPTH


def asm_v2_predicate() -> str:
    """Return the predicate the spec 2 ASM host must resolve to."""
    _, predicate = _asm_v2_artifact()
    return predicate


def _asm_v2_artifact() -> tuple[ArtifactSource, str]:
    """Pick the spec 2 ASM source matching the binary built by run_test.sh, together with the
    predicate it must resolve to."""
    backend = os.environ.get("ASM_PROVER_BACKEND", "native")
    if backend == "sp1":
        # The local guest build compiles the newest spec, which is spec 2. run_test.sh derives
        # its predicate from that same build, so the startup predicate check only catches a
        # mix-up between files, not a wrong guest.
        return (
            Sp1Artifact(elf_path=str(SP1_GENERATED_DIR / "asm.elf")),
            (SP1_GENERATED_DIR / "asm-predicate.txt").read_text().strip(),
        )
    if backend == "native":
        return (
            NativeArtifact(signing_key=NATIVE_TEST_ASM_V2_SIGNING_KEY),
            NATIVE_TEST_ASM_V2_PREDICATE,
        )
    raise ValueError(f"Unknown ASM_PROVER_BACKEND: {backend!r} (expected: native|sp1)")
