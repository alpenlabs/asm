import logging

import flexitest

from utils.utils import (
    wait_until_asm_reaches_height,
    wait_until_asm_ready,
    wait_until_bitcoind_ready,
)


@flexitest.register
class AsmGetStateTest(flexitest.Test):
    """Smoke test for `strata_asm_getAnchorState` and `strata_asm_getManifest`.

    Every processed L1 block produces an anchor state (in the state store) and a
    manifest carrying its logs (in the manifest store), so we can drive the happy
    path directly: generate blocks, wait for ASM, then assert both handlers
    return a payload for processed blocks.
    """

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
        wallet_addr = bitcoin_rpc.proxy.getnewaddress()
        num_blocks = 3
        logging.info("Generating %s blocks", num_blocks)
        bitcoin_rpc.proxy.generatetoaddress(num_blocks, wallet_addr)

        target_height = initial_btc_height + num_blocks
        asm_height = wait_until_asm_reaches_height(asm_rpc, min_height=target_height)
        logging.info("ASM progressed to height %s", asm_height)

        # Tip and an earlier processed block must both return a payload —
        # the handlers should be consistent across history, not just the latest snapshot.
        for height in (initial_btc_height + 1, target_height):
            block_hash = bitcoin_rpc.proxy.getblockhash(height)

            # Anchor state: serialized as opaque SSZ bytes (a JSON byte array).
            anchor = asm_rpc.strata_asm_getAnchorState(block_hash)
            assert anchor is not None, (
                f"strata_asm_getAnchorState returned None for processed block at height {height}"
            )

            # Manifest: a struct carrying the block's emitted logs.
            manifest = asm_rpc.strata_asm_getManifest(block_hash)
            assert manifest is not None, (
                f"strata_asm_getManifest returned None for processed block at height {height}"
            )
            assert "logs" in manifest, (
                f"strata_asm_getManifest payload missing `logs` at height {height}: {manifest!r}"
            )
            logging.info("  height=%s: got %d log entries", height, len(manifest["logs"]))

        return True
