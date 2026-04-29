import logging

import flexitest

from utils.utils import (
    wait_until_asm_reaches_height,
    wait_until_asm_ready,
    wait_until_bitcoind_ready,
)


@flexitest.register
class AsmGetMohoStateTest(flexitest.Test):
    """Smoke test for `strata_asm_getMohoState`.

    Every processed L1 block produces a `MohoState`, so we can drive the
    happy path directly: generate blocks, wait for ASM, then assert the
    handler returns SSZ-encoded bytes for processed blocks.
    """

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env("prover")

    def main(self, ctx: flexitest.RunContext):
        bitcoind_service = ctx.get_service("bitcoin")
        asm_service = ctx.get_service("asm_rpc")

        bitcoin_rpc = bitcoind_service.create_rpc()
        asm_rpc = asm_service.create_rpc()

        wait_until_bitcoind_ready(bitcoin_rpc, timeout=30)
        logging.info("Bitcoin node is ready")

        wait_until_asm_ready(asm_rpc)
        logging.info("ASM RPC service is ready")

        initial_btc_height = bitcoin_rpc.proxy.getblockcount()
        wallet_addr = bitcoin_rpc.proxy.getnewaddress()
        num_blocks = 3
        logging.info("Generating %s blocks", num_blocks)
        bitcoin_rpc.proxy.generatetoaddress(num_blocks, wallet_addr)

        target_height = initial_btc_height + num_blocks
        asm_height = wait_until_asm_reaches_height(asm_rpc, min_height=target_height)
        logging.info("ASM progressed to height %s", asm_height)

        # Tip and an earlier processed block must both return a non-empty payload —
        # the handler should be consistent across history, not just the latest snapshot.
        for height in (initial_btc_height + 1, target_height):
            block_hash = bitcoin_rpc.proxy.getblockhash(height)
            result = asm_rpc.strata_asm_getMohoState(block_hash)
            assert result is not None, (
                f"strata_asm_getMohoState returned None for processed block at height {height}"
            )
            assert len(result) > 0, (
                f"strata_asm_getMohoState returned an empty payload at height {height}: {result!r}"
            )
            logging.info("  height=%s: got %d byte(s) of SSZ payload", height, len(result))

        return True
