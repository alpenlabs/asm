import logging

import flexitest

from utils.utils import (
    wait_until_asm_reaches_height,
    wait_until_asm_ready,
    wait_until_bitcoind_ready,
)

# Bridge V1 container ID. Matches `BRIDGE_V1_SUBPROTOCOL_ID` in the Rust codebase
# (crates/txs/bridge-v1/src/constants.rs)
BRIDGE_V1_CONTAINER_ID = 2

# Sentinel 32-byte leaf unlikely to collide with any real export entry.
UNKNOWN_LEAF_HASH = [0xAB] * 32


@flexitest.register
class AsmExportEntryMmrProofTest(flexitest.Test):
    """Smoke test for `strata_asm_getExportEntryMMRProof`.

    ASM lacks tooling to simulate an assignment fulfillment for now, so we
    can't drive a real export entry from here — only negative paths covered.
    Revisit once that tooling exists.
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

        block_hash = bitcoin_rpc.proxy.getblockhash(target_height)

        # Each case must produce `None`.
        cases: list[tuple[str, tuple[object, int, list[int]]]] = [
            (
                "unknown leaf on bridge container (chain never fulfilled a withdrawal)",
                (block_hash, BRIDGE_V1_CONTAINER_ID, UNKNOWN_LEAF_HASH),
            ),
            (
                "unknown container_id",
                (block_hash, 0x99, UNKNOWN_LEAF_HASH),
            ),
            (
                "wrong-sized leaf (31 bytes)",
                (block_hash, BRIDGE_V1_CONTAINER_ID, [0xAB] * 31),
            ),
            (
                "wrong-sized leaf (33 bytes)",
                (block_hash, BRIDGE_V1_CONTAINER_ID, [0xAB] * 33),
            ),
            (
                "empty leaf",
                (block_hash, BRIDGE_V1_CONTAINER_ID, []),
            ),
        ]

        for description, args in cases:
            result = asm_rpc.strata_asm_getExportEntryMMRProof(*args)
            assert result is None, (
                f"strata_asm_getExportEntryMMRProof should return None for "
                f"case '{description}', got {result!r}"
            )
            logging.info("  %s: returned None as expected", description)

        # Also call against an earlier processed block — ensures the handler
        # is consistent across the block history, not just the tip.
        earlier_height = initial_btc_height + 1
        earlier_block_hash = bitcoin_rpc.proxy.getblockhash(earlier_height)
        result = asm_rpc.strata_asm_getExportEntryMMRProof(
            earlier_block_hash, BRIDGE_V1_CONTAINER_ID, UNKNOWN_LEAF_HASH
        )
        assert result is None, (
            f"handler should return None for an earlier block too, got {result!r}"
        )
        logging.info(
            "earlier block at height %s also returned None as expected",
            earlier_height,
        )

        return True
