import os
from pathlib import Path

import flexitest

from factory.asm_rpc.config_cfg import (
    BackendConfig,
    Duration,
    NativeBackend,
    OrchestratorConfig,
    Sp1Backend,
)

from .basic_env import BasicEnv

# Hardcoded 32-byte test key for the native backend. Deterministic across
# runs so test fixtures stay reproducible; not used to authenticate anything
# real today.
NATIVE_TEST_SIGNING_KEY = "00" * 32


class ProverEnv(BasicEnv):
    """Functional-test environment with proof orchestrator enabled."""

    def _orchestrator_config(self, ectx: flexitest.EnvContext) -> OrchestratorConfig | None:
        envdd_path = Path(ectx.envdd_path)
        proof_db_path = str((envdd_path / "asm_rpc" / "proof_db").resolve())
        return OrchestratorConfig(
            tick_interval=Duration(secs=1, nanos=0),
            max_concurrent_proofs=4,
            proof_db_path=proof_db_path,
            backend=_backend_config(),
        )


def _backend_config() -> BackendConfig:
    """Pick the backend variant matching the binary built by run_test.sh."""
    backend = os.environ.get("ASM_PROVER_BACKEND", "native")
    if backend == "sp1":
        repo_root = Path(__file__).resolve().parents[2]
        elfs_dir = str((repo_root / "guest-builder" / "sp1" / "elfs").resolve())
        return Sp1Backend(elfs_dir=elfs_dir)
    if backend == "native":
        return NativeBackend(schnorr_signing_key=NATIVE_TEST_SIGNING_KEY)
    raise ValueError(f"Unknown ASM_PROVER_BACKEND: {backend!r} (expected: native|sp1)")
