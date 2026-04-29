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

        # An unobserved leaf is legitimate absence — the handler returns None
        # rather than erroring, since the chain may simply not have produced
        # that entry yet.
        result = asm_rpc.strata_asm_getExportEntryMMRProof(
            block_hash, BRIDGE_V1_CONTAINER_ID, UNKNOWN_LEAF_HASH
        )
        assert result is None, f"unknown leaf at tip should return None, got {result!r}"
        logging.info("unknown leaf at tip returned None as expected")

        # Same query against an earlier processed block — the handler stays
        # consistent across history, not just the tip.
        earlier_height = initial_btc_height + 1
        earlier_block_hash = bitcoin_rpc.proxy.getblockhash(earlier_height)
        result = asm_rpc.strata_asm_getExportEntryMMRProof(
            earlier_block_hash, BRIDGE_V1_CONTAINER_ID, UNKNOWN_LEAF_HASH
        )
        assert result is None, (
            f"unknown leaf at height {earlier_height} should return None, got {result!r}"
        )
        logging.info(
            "unknown leaf at earlier height %s returned None as expected",
            earlier_height,
        )

        return True
