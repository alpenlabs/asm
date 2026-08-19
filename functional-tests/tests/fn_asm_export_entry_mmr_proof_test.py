import logging

import flexitest

from constants import BRIDGE_SUBPROTOCOL_ID
from rpc.client import RpcError
from utils.utils import (
    wait_until_asm_reaches_height,
    wait_until_asm_ready,
    wait_until_bitcoind_ready,
)

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

        # An unobserved leaf has no proof, and the error says so rather than
        # leaving the caller to guess why nothing came back.
        self.expect_no_proof(asm_rpc, block_hash, "tip")

        # Same query against an earlier processed block — the handler stays
        # consistent across history, not just the tip.
        earlier_height = initial_btc_height + 1
        earlier_block_hash = bitcoin_rpc.proxy.getblockhash(earlier_height)
        self.expect_no_proof(asm_rpc, earlier_block_hash, f"height {earlier_height}")

        return True

    def expect_no_proof(self, asm_rpc, block_hash, where):
        """Asserts the leaf has no proof at `block_hash`, and that the error says why."""
        try:
            result = asm_rpc.strata_asm_getExportEntryMMRProof(
                block_hash, BRIDGE_SUBPROTOCOL_ID, UNKNOWN_LEAF_HASH
            )
        except RpcError as e:
            assert "leaf not found" in e.msg, (
                f"unknown leaf at {where} should report the leaf as missing, got {e.msg!r}"
            )
            logging.info("unknown leaf at %s reported as missing: %s", where, e.msg)
        else:
            raise AssertionError(f"unknown leaf at {where} should have errored, got {result!r}")
