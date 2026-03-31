import logging

import flexitest

from utils.utils import (
    wait_until_asm_reaches_height,
    wait_until_asm_ready,
    wait_until_bitcoind_ready,
)


@flexitest.register
class AsmBlockProcessingTest(flexitest.Test):
    """Smoke test for asm-runner block processing over regtest."""

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env("basic")

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
        logging.info("Initial Bitcoin height: %s", initial_btc_height)

        wallet_addr = bitcoin_rpc.proxy.getnewaddress()
        num_blocks_to_generate = 10
        logging.info("Generating %s blocks", num_blocks_to_generate)
        bitcoin_rpc.proxy.generatetoaddress(num_blocks_to_generate, wallet_addr)

        latest_asm_height = wait_until_asm_reaches_height(
            asm_rpc,
            min_height=initial_btc_height + 1,
        )
        logging.info("ASM progressed to height %s", latest_asm_height)

        latest_btc_block_hash = bitcoin_rpc.proxy.getblockhash(latest_asm_height)
        assignments = asm_rpc.strata_asm_getAssignments(latest_btc_block_hash)
        if assignments is None:
            raise AssertionError("ASM getAssignments should return a list")
        logging.info("Assignments at latest ASM block: %s entries", len(assignments))

        return True
