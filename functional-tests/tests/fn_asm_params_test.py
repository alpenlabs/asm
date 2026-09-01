import logging

import flexitest

from constants import ASM_MAGIC_BYTES
from utils.utils import wait_until_asm_ready, wait_until_bitcoind_ready

# The subprotocol configs the genesis config carries, each as its own named
# field. getParams must echo all three back.
EXPECTED_SUBPROTOCOL_FIELDS = ["admin", "checkpoint", "bridge"]


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

        # SPS-50 magic bytes serialize as their ASCII string over JSON-RPC.
        assert params["magic"] == ASM_MAGIC_BYTES, f"unexpected magic: {params['magic']!r}"

        # Anchor pins the runner to the regtest chain the env pre-mined.
        assert params["anchor"]["network"] == "regtest", (
            f"unexpected anchor network: {params['anchor']!r}"
        )

        # Every subprotocol config is a required named field, so a missing one is
        # a missing key rather than a short list.
        for field in EXPECTED_SUBPROTOCOL_FIELDS:
            assert field in params, f"genesis config missing {field!r}: {sorted(params)!r}"

        # Nested config must round-trip, not just the field names: the bridge
        # carries the operator set the env configured.
        bridge = params["bridge"]
        assert bridge["operators"], f"bridge config missing operators: {bridge!r}"

        logging.info(
            "getParams returned magic=%s, subprotocol configs=%s",
            params["magic"],
            EXPECTED_SUBPROTOCOL_FIELDS,
        )
        return True
