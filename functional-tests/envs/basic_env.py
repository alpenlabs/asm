from pathlib import Path

import flexitest

from constants import ASM_MAGIC_BYTES, INITIAL_BLOCKS
from factory.asm_rpc.config_cfg import OrchestratorConfig
from factory.common.asm_params import build_asm_params, write_asm_params_json
from utils.utils import wait_until_bitcoind_ready

# x-only MuSig2 test key material; compressed form is prefixed with 0x02 in params builder.
DEFAULT_MUSIG2_KEYS = [
    "becdf7aab195ab0a42ba2f2eca5b7fa5a246267d802c627010e1672f08657f70",
]

# HACK(STR-2572): querying ASM exactly at its genesis block can panic in downstream setups.
# Keep ASM genesis one block behind the pre-mined chain height.
ASM_GENESIS_OFFSET = 1


class BasicEnv(flexitest.EnvConfig):
    """Minimal functional-test environment: bitcoind + strata-asm-runner."""

    def init(self, ectx: flexitest.EnvContext) -> flexitest.LiveEnv:
        svcs: dict[str, flexitest.Service] = {}

        bitcoind, params_file_path = self._setup_bitcoind_and_params(ectx)
        svcs["bitcoin"] = bitcoind

        asm_factory = ectx.get_factory("asm_rpc")
        svcs["asm_rpc"] = asm_factory.create_asm_rpc_service(
            bitcoind.props, params_file_path, orchestrator=self._orchestrator_config(ectx)
        )

        return flexitest.LiveEnv(svcs)

    def _orchestrator_config(self, ectx: flexitest.EnvContext) -> OrchestratorConfig | None:
        """Return orchestrator config. Override in subclasses to enable proving."""
        return None

    def _setup_bitcoind_and_params(
        self, ectx: flexitest.EnvContext
    ) -> tuple[flexitest.Service, str]:
        """Set up bitcoind and generate ASM params. Shared by all env variants."""
        btc_factory = ectx.get_factory("bitcoin")
        bitcoind = btc_factory.create_regtest_bitcoin()
        bitcoin_rpc = bitcoind.create_rpc()
        wait_until_bitcoind_ready(bitcoin_rpc, timeout=30)

        bitcoin_rpc.proxy.createwallet(bitcoind.get_prop("walletname"))
        wallet_addr = bitcoin_rpc.proxy.getnewaddress()
        bitcoin_rpc.proxy.generatetoaddress(INITIAL_BLOCKS, wallet_addr)

        genesis_height = max(0, INITIAL_BLOCKS - ASM_GENESIS_OFFSET)
        genesis_hash = bitcoin_rpc.proxy.getblockhash(genesis_height)
        genesis_header = bitcoin_rpc.proxy.getblockheader(genesis_hash)
        asm_params = build_asm_params(
            musig2_keys=DEFAULT_MUSIG2_KEYS,
            genesis_height=genesis_height,
            block_hash=genesis_hash,
            header=genesis_header,
            magic=ASM_MAGIC_BYTES,
        )

        params_path = Path(ectx.envdd_path) / "generated" / "asm-params.json"
        params_file_path = write_asm_params_json(params_path, asm_params)

        return bitcoind, params_file_path
