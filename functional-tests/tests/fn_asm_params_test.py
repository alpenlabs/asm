import logging

import flexitest

from constants import ASM_MAGIC_BYTES
from factory.common.asm_params import DEFAULT_SAFE_HARBOR_ADDRESS
from utils.utils import wait_until_asm_ready, wait_until_bitcoind_ready

# Externally-tagged subprotocol variants, in the order `basic_env` writes them
# into asm-params.json. getParams must echo that order back.
EXPECTED_SUBPROTOCOLS = ["Admin", "Checkpoint", "Bridge"]


@flexitest.register
class AsmGetParamsTest(flexitest.Test):
    """Smoke test for `strata_asm_getParams`.

    getParams just re-serializes the static params the runner was launched with,
    so — unlike the state/manifest tests — no blocks need to be mined to exercise
    it; the RPC being up is enough.
    """

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env("basic")

    def main(self, ctx: flexitest.RunContext):
        bitcoind_service = ctx.get_service("bitcoin")
        asm_service = ctx.get_service("asm_rpc")

        bitcoin_rpc = bitcoind_service.create_rpc()
        asm_rpc = asm_service.create_rpc()

        wait_until_bitcoind_ready(bitcoin_rpc, timeout=30)
        wait_until_asm_ready(asm_rpc)
        logging.info("ASM RPC service is ready")

        params = asm_rpc.strata_asm_getParams()
        assert params is not None, "strata_asm_getParams returned None"
        assert set(params) == {"genesis", "runtime"}, f"unexpected sections: {list(params)!r}"
        # The env configures no spec that reads runtime values.
        assert params["runtime"] == {}, f"unexpected runtime params: {params['runtime']!r}"
        genesis = params["genesis"]

        # SPS-50 magic bytes serialize as their ASCII string over JSON-RPC.
        assert genesis["magic"] == ASM_MAGIC_BYTES, f"unexpected magic: {genesis['magic']!r}"

        # Anchor pins the runner to the regtest chain the env pre-mined.
        assert genesis["anchor"]["network"] == "regtest", (
            f"unexpected anchor network: {genesis['anchor']!r}"
        )

        subprotocols = genesis["subprotocols"]
        tags = [next(iter(sp)) for sp in subprotocols]
        assert tags == EXPECTED_SUBPROTOCOLS, f"unexpected subprotocols: {tags!r}"

        # Nested config must round-trip, not just the variant tags: the bridge
        # carries the operator set the env configured.
        bridge = subprotocols[tags.index("Bridge")]["Bridge"]
        assert bridge["operators"], f"bridge params missing operators: {bridge!r}"

        # The safe harbor comes back as the address the file was written with, not as the
        # descriptor the chain stores.
        assert bridge["safe_harbor_address"] == DEFAULT_SAFE_HARBOR_ADDRESS, (
            f"unexpected safe harbor in bridge params: {bridge['safe_harbor_address']!r}"
        )

        logging.info("getParams returned magic=%s, subprotocols=%s", genesis["magic"], tags)
        return True
