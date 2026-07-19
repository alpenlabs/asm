import flexitest

from factory.asm_rpc.config_cfg import FollowerMode

from .prover_env import ProverEnv

FOLLOWER_SERVICE_NAME = "asm_rpc_follower"

# The sync test asserts the follower only fetches while its peer is alive, so
# the lag fallback must never trigger; the unavailability fallback
# (max_peer_failures ticks without a reachable peer) stays at the Rust-side
# default so stopping the generator flips the follower to local proving within
# a few ticks.
FOLLOWER_MAX_LAG = 10_000


class FollowerEnv(ProverEnv):
    """Two asm-runners on one bitcoind: a generator proving locally and a
    follower fetching proofs from the generator's RPC."""

    def init(self, ectx: flexitest.EnvContext) -> flexitest.LiveEnv:
        svcs: dict[str, flexitest.Service] = {}

        bitcoind, params_file_path = self._setup_bitcoind_and_params(ectx)
        svcs["bitcoin"] = bitcoind

        asm_factory = ectx.get_factory("asm_rpc")
        generator = asm_factory.create_asm_rpc_service(
            bitcoind.props, params_file_path, orchestrator=self._orchestrator_config(ectx)
        )
        svcs["asm_rpc"] = generator

        follower_orch = self._orchestrator_config(ectx, service_name=FOLLOWER_SERVICE_NAME)
        follower_orch.mode = FollowerMode(
            peer_url=generator.get_prop("rpc_url"),
            max_lag=FOLLOWER_MAX_LAG,
        )
        svcs[FOLLOWER_SERVICE_NAME] = asm_factory.create_asm_rpc_service(
            bitcoind.props,
            params_file_path,
            orchestrator=follower_orch,
            service_name=FOLLOWER_SERVICE_NAME,
        )

        return flexitest.LiveEnv(svcs)
