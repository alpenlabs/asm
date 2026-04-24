import logging

import flexitest

from constants import INITIAL_BLOCKS
from envs.basic_env import ASM_GENESIS_OFFSET
from rpc.asm_types import CheckpointTip
from utils.utils import (
    wait_until_asm_reaches_height,
    wait_until_asm_ready,
    wait_until_bitcoind_ready,
)

GENESIS_OL_BLKID = "0" * 64
GENESIS_L1_HEIGHT = max(0, INITIAL_BLOCKS - ASM_GENESIS_OFFSET)


@flexitest.register
class AsmCheckpointTipTest(flexitest.Test):
    """Verify strata_asm_getCheckpointTip returns the genesis tip before any checkpoint."""

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
        num_blocks_to_generate = 5
        bitcoin_rpc.proxy.generatetoaddress(num_blocks_to_generate, wallet_addr)

        target_height = initial_btc_height + num_blocks_to_generate
        latest_asm_height = wait_until_asm_reaches_height(asm_rpc, min_height=target_height)
        logging.info("ASM progressed to height %s", latest_asm_height)

        latest_block_hash = bitcoin_rpc.proxy.getblockhash(latest_asm_height)
        raw = asm_rpc.strata_asm_getCheckpointTip(latest_block_hash)
        assert raw is not None, "getCheckpointTip should return the genesis tip"

        tip = CheckpointTip.from_dict(raw)
        logging.info("Got checkpoint tip: %s", tip)

        assert tip.epoch == 0, f"expected genesis epoch 0, got {tip.epoch}"
        assert tip.l1_height == GENESIS_L1_HEIGHT, (
            f"expected genesis l1_height {GENESIS_L1_HEIGHT}, got {tip.l1_height}"
        )
        assert tip.l2_commitment.slot == 0, (
            f"expected genesis l2 slot 0, got {tip.l2_commitment.slot}"
        )
        normalized_blkid = tip.l2_commitment.blkid.lower().removeprefix("0x")
        assert normalized_blkid == GENESIS_OL_BLKID, (
            f"expected zero genesis ol blkid, got {tip.l2_commitment.blkid}"
        )

        # Tip should be stable across every processed block while no checkpoint is posted.
        earlier_height = initial_btc_height + 1
        earlier_block_hash = bitcoin_rpc.proxy.getblockhash(earlier_height)
        earlier_tip = CheckpointTip.from_dict(
            asm_rpc.strata_asm_getCheckpointTip(earlier_block_hash)
        )
        assert earlier_tip == tip, (
            f"checkpoint tip should be identical across processed blocks: {earlier_tip} vs {tip}"
        )

        return True
