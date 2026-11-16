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
# `getExportEntryIndex` takes the leaf as a hex `Buf32`.
UNKNOWN_LEAF_HEX = bytes(UNKNOWN_LEAF_HASH).hex()


@flexitest.register
class AsmExportEntryMmrProofTest(flexitest.Test):
    """Smoke test for the export-entry RPCs: `getExportEntryIndex`,
    `getExportEntryProof`, and the deprecated `getExportEntryMMRProof`.

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

        # Check the tip and an earlier processed block, so the handlers stay
        # consistent across history, not just at the tip.
        earlier_height = initial_btc_height + 1
        earlier_block_hash = bitcoin_rpc.proxy.getblockhash(earlier_height)
        for at, where in [(block_hash, "tip"), (earlier_block_hash, f"height {earlier_height}")]:
            self.expect_no_index(asm_rpc, at, where)
            self.expect_no_proof_at_index(asm_rpc, at, where)
            self.expect_no_proof(asm_rpc, at, where)

        # Reorg the tip out. Its Moho state stays stored, but the entry index
        # follows the new chain, so the handlers must refuse the old hash. Mine
        # to a fresh address so the replacement can't rebuild the same block.
        bitcoin_rpc.proxy.invalidateblock(block_hash)
        bitcoin_rpc.proxy.generatetoaddress(2, bitcoin_rpc.proxy.getnewaddress())
        self.expect_not_canonical(
            "index",
            lambda: asm_rpc.strata_asm_getExportEntryIndex(
                block_hash, BRIDGE_SUBPROTOCOL_ID, UNKNOWN_LEAF_HEX
            ),
        )
        self.expect_not_canonical(
            "proof",
            lambda: asm_rpc.strata_asm_getExportEntryProof(block_hash, BRIDGE_SUBPROTOCOL_ID, 0),
        )
        self.expect_not_canonical(
            "deprecated proof",
            lambda: asm_rpc.strata_asm_getExportEntryMMRProof(
                block_hash, BRIDGE_SUBPROTOCOL_ID, UNKNOWN_LEAF_HASH
            ),
        )

        return True

    def expect_not_canonical(self, what, call):
        """Asserts `call` refuses a reorged-out block hash."""
        try:
            result = call()
        except RpcError as e:
            assert "not on the canonical chain" in e.msg, (
                f"{what} at a reorged-out block should be refused, got {e.msg!r}"
            )
            logging.info("%s at reorged-out block refused: %s", what, e.msg)
        else:
            raise AssertionError(
                f"{what} at a reorged-out block should have errored, got {result!r}"
            )

    def expect_no_index(self, asm_rpc, block_hash, where):
        """Asserts an unknown leaf resolves to no index, rather than an error."""
        result = asm_rpc.strata_asm_getExportEntryIndex(
            block_hash, BRIDGE_SUBPROTOCOL_ID, UNKNOWN_LEAF_HEX
        )
        assert result is None, f"unknown leaf at {where} should have no index, got {result!r}"

    def expect_no_proof_at_index(self, asm_rpc, block_hash, where):
        """Asserts there is no proof at index 0 while the container holds no entries."""
        try:
            result = asm_rpc.strata_asm_getExportEntryProof(block_hash, BRIDGE_SUBPROTOCOL_ID, 0)
        except RpcError as e:
            # The bridge container exists from genesis, but holds no entries.
            assert "out of range" in e.msg, (
                f"index 0 at {where} should report no such entry, got {e.msg!r}"
            )
            logging.info("index 0 at %s reported as absent: %s", where, e.msg)
        else:
            raise AssertionError(f"index 0 at {where} should have errored, got {result!r}")

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
