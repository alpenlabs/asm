import os
from pathlib import Path

import flexitest

from factory.asm_rpc.config_cfg import (
    ArtifactSource,
    AsmArtifact,
    Duration,
    NativeArtifact,
    OrchestratorConfig,
    Sp1Artifact,
)

from .basic_env import BasicEnv

# Hardcoded deterministic 32-byte test keys for the native backend.
# Each host gets its own key so the native predicate key is stable across
# runs. Distinct, non-zero values (the zero scalar is rejected by
# `k256::schnorr::SigningKey::from_bytes`).
NATIVE_TEST_ASM_SIGNING_KEY = "01" * 32
NATIVE_TEST_MOHO_SIGNING_KEY = "02" * 32
# Predicate the native ASM host derives from `NATIVE_TEST_ASM_SIGNING_KEY`.
NATIVE_TEST_ASM_PREDICATE = (
    "Bip340Schnorr:1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
)


class ProverEnv(BasicEnv):
    """Functional-test environment with proof orchestrator enabled."""

    def _orchestrator_config(
        self, ectx: flexitest.EnvContext, service_name: str = "asm_rpc"
    ) -> OrchestratorConfig:
        envdd_path = Path(ectx.envdd_path)
        proof_db_path = str((envdd_path / service_name / "proof_db").resolve())
        moho, asm_source, _ = _artifact_sources()
        return OrchestratorConfig(
            tick_interval=Duration(secs=1, nanos=0),
            max_concurrent_proofs=4,
            proof_db_path=proof_db_path,
            moho=moho,
            asm_artifacts=[AsmArtifact(spec_id=0, source=asm_source)],
        )

    def _asm_predicate(self) -> str:
        _, _, asm_predicate = _artifact_sources()
        return asm_predicate


def _artifact_sources() -> tuple[ArtifactSource, ArtifactSource, str]:
    """Pick the Moho and ASM sources matching the binary built by run_test.sh.

    Returns the Moho source, the ASM source, and the predicate the ASM host must
    resolve to.
    """
    backend = os.environ.get("ASM_PROVER_BACKEND", "native")
    if backend == "sp1":
        repo_root = Path(__file__).resolve().parents[2]
        generated_dir = (repo_root / "guest-builder" / "sp1" / "generated").resolve()
        return (
            Sp1Artifact(elf_path=str(generated_dir / "moho.elf")),
            Sp1Artifact(elf_path=str(generated_dir / "asm.elf")),
            os.environ["ASM_EXPECTED_PREDICATE"],
        )
    if backend == "native":
        return (
            NativeArtifact(signing_key=NATIVE_TEST_MOHO_SIGNING_KEY),
            NativeArtifact(signing_key=NATIVE_TEST_ASM_SIGNING_KEY),
            NATIVE_TEST_ASM_PREDICATE,
        )
    raise ValueError(f"Unknown ASM_PROVER_BACKEND: {backend!r} (expected: native|sp1)")
