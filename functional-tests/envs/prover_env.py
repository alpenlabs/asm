import os
from pathlib import Path

import flexitest

from factory.asm_rpc.config_cfg import (
    BackendConfig,
    Duration,
    NativeAsmEntry,
    NativeBackend,
    OrchestratorConfig,
    Sp1Backend,
)

from .basic_env import BasicEnv

# Hardcoded deterministic 32-byte test keys for the native backend.
# Each host gets its own key so the native predicate key is stable across
# runs. Distinct, non-zero values (the zero scalar is rejected by
# `k256::schnorr::SigningKey::from_bytes`).
NATIVE_TEST_ASM_SIGNING_KEY = "01" * 32
NATIVE_TEST_MOHO_SIGNING_KEY = "02" * 32


class ProverEnv(BasicEnv):
    """Functional-test environment with proof orchestrator enabled."""

    def _orchestrator_config(self, ectx: flexitest.EnvContext) -> OrchestratorConfig | None:
        envdd_path = Path(ectx.envdd_path)
        proof_db_path = str((envdd_path / "asm_rpc" / "proof_db").resolve())
        return OrchestratorConfig(
            tick_interval=Duration(secs=1, nanos=0),
            max_concurrent_proofs=4,
            proof_db_path=proof_db_path,
            backend=self._backend_config_override(),
        )

    def _backend_config_override(self) -> BackendConfig:
        """Backend selection hook; override to configure other artifacts."""
        return _backend_config()


def elfs_dir() -> Path:
    repo_root = Path(__file__).resolve().parents[2]
    return (repo_root / "guest-builder" / "sp1" / "elfs").resolve()


def _backend_config() -> BackendConfig:
    """Pick the backend variant matching the binary built by run_test.sh."""
    backend = os.environ.get("ASM_PROVER_BACKEND", "native")
    if backend == "sp1":
        return Sp1Backend(
            asm_elf_paths=[str(elfs_dir() / "asm.elf")],
            moho_elf_path=str(elfs_dir() / "moho.elf"),
        )
    if backend == "native":
        return NativeBackend(
            asm_entries=[
                NativeAsmEntry(
                    schnorr_signing_key=NATIVE_TEST_ASM_SIGNING_KEY,
                    # Matches the schedule baked into the production ASM guest.
                    stf_params={"forks": {"fork1": 0}},
                )
            ],
            moho_schnorr_signing_key=NATIVE_TEST_MOHO_SIGNING_KEY,
        )
    raise ValueError(f"Unknown ASM_PROVER_BACKEND: {backend!r} (expected: native|sp1)")
