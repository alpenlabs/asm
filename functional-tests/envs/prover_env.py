from pathlib import Path

import flexitest

from factory.asm_rpc.config_cfg import Duration, OrchestratorConfig

from .basic_env import BasicEnv


class ProverEnv(BasicEnv):
    """Functional-test environment with proof orchestrator enabled."""

    def _orchestrator_config(self, ectx: flexitest.EnvContext) -> OrchestratorConfig | None:
        envdd_path = Path(ectx.envdd_path)
        proof_db_path = str((envdd_path / "asm_rpc" / "proof_db").resolve())
        return OrchestratorConfig(
            tick_interval=Duration(secs=1, nanos=0),
            max_concurrent_asm_proofs=4,
            proof_db_path=proof_db_path,
        )
