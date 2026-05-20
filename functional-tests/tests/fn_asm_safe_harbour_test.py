import logging

import flexitest

from factory.common.asm_params import DEFAULT_SAFE_HARBOUR_ADDRESS
from utils.utils import (
    wait_until_asm_reaches_height,
    wait_until_asm_ready,
    wait_until_bitcoind_ready,
)


@flexitest.register
class AsmSafeHarbourTest(flexitest.Test):
    """Verify `strata_asm_getSafeHarbour` returns the configured address
    in its initial deactivated state.

    The bridge subprotocol is initialised from `asm_params.json` with
    `DEFAULT_SAFE_HARBOUR_ADDRESS` and `activated=false`. Without any
    admin defcon signal, every processed block must surface that exact
    pair via the RPC.
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

        initial_btc_height = bitcoin_rpc.proxy.getblockcount()
        wallet_addr = bitcoin_rpc.proxy.getnewaddress()
        num_blocks = 3
        bitcoin_rpc.proxy.generatetoaddress(num_blocks, wallet_addr)

        target_height = initial_btc_height + num_blocks
        asm_height = wait_until_asm_reaches_height(asm_rpc, min_height=target_height)
        logging.info("ASM progressed to height %s", asm_height)

        # Tip and an earlier processed block must both return the same payload —
        # the safe harbour is consensus state, so it must be consistent across history
        # while no admin message has touched it.
        heights = (initial_btc_height + 1, target_height)
        previous = None
        for height in heights:
            block_hash = bitcoin_rpc.proxy.getblockhash(height)
            result = asm_rpc.strata_asm_getSafeHarbour(block_hash)
            assert result is not None, (
                f"strata_asm_getSafeHarbour returned None for processed block at height {height}"
            )
            assert set(result.keys()) >= {"address", "activated"}, (
                f"unexpected safe harbour payload at height {height}: {result!r}"
            )
            normalized = result["address"].lower().removeprefix("0x")
            assert normalized == DEFAULT_SAFE_HARBOUR_ADDRESS, (
                f"expected configured safe harbour address {DEFAULT_SAFE_HARBOUR_ADDRESS}, "
                f"got {result['address']}"
            )
            assert result["activated"] is False, (
                f"safe harbour should start deactivated, got activated={result['activated']!r}"
            )
            if previous is not None:
                assert result == previous, (
                    "safe harbour should be identical across processed blocks: "
                    f"{previous} vs {result}"
                )
            previous = result

        return True
