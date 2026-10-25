import logging

import flexitest

from envs import BasicEnv
from envs.basic_env import ADMIN_SECRET_KEY, DEFAULT_ADMIN_CONFIRMATION_DEPTH
from factory.common.asm_params import DEFAULT_SAFE_HARBOR_DESCRIPTOR
from utils.test_cli import submit_safe_harbor_update
from utils.utils import (
    wait_until_asm_reaches_height,
    wait_until_asm_ready,
    wait_until_bitcoind_ready,
)

# P2TR address the test rotates the safe harbor to, written as a regtest wallet shows it.
NEW_SAFE_HARBOR_ADDRESS = "bcrt1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqc8gma6"

# BOSD descriptor of `NEW_SAFE_HARBOR_ADDRESS`, the form the RPC reports.
NEW_SAFE_HARBOR_DESCRIPTOR = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"


def safe_harbor_descriptor(asm_rpc, bitcoin_rpc, height: int) -> str:
    """Return the safe harbor descriptor the ASM reports at `height`, checking that a
    rotation left it deactivated."""
    block_hash = bitcoin_rpc.proxy.getblockhash(height)
    safe_harbor = asm_rpc.strata_asm_getSafeHarbor(block_hash)
    assert safe_harbor is not None, f"no safe harbor at height {height}"
    assert safe_harbor["activated"] is False, (
        f"safe harbor should stay deactivated, got {safe_harbor!r} at height {height}"
    )
    return safe_harbor["address"].lower().removeprefix("0x")


@flexitest.register
class AsmSafeHarborUpdateTest(flexitest.Test):
    """Rotate the safe harbor to a P2TR address through an admin update.

    The administrator names the new destination by address, as their wallet shows it, and
    signs a message that shows the same address. The bridge adopts it in the block that
    enacts the update, and the RPC reports it as the descriptor the chain stores.

    Runs in its own env: the rotation would leak into the tests that read the initial
    safe harbor, and mining through the confirmation depth would enact admin updates
    other tests leave queued.
    """

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env(BasicEnv())

    def main(self, ctx: flexitest.RunContext):
        bitcoind_service = ctx.get_service("bitcoin")
        asm_service = ctx.get_service("asm_rpc")

        bitcoin_rpc = bitcoind_service.create_rpc()
        asm_rpc = asm_service.create_rpc()

        wait_until_bitcoind_ready(bitcoin_rpc, timeout=30)
        wait_until_asm_ready(asm_rpc)

        wallet_addr = bitcoin_rpc.proxy.getnewaddress()
        initial_height = bitcoin_rpc.proxy.getblockcount()

        txid = submit_safe_harbor_update(
            bitcoind_service,
            admin_secret_key=ADMIN_SECRET_KEY,
            seqno=1,
            address=NEW_SAFE_HARBOR_ADDRESS,
        )
        [submit_hash] = bitcoin_rpc.proxy.generatetoaddress(1, wallet_addr)
        assert txid in bitcoin_rpc.proxy.getblock(submit_hash)["tx"], (
            f"update tx {txid} was not mined in {submit_hash}"
        )
        submit_height = initial_height + 1

        # The queued update is enacted `depth` blocks after the one that carried it.
        enact_height = submit_height + DEFAULT_ADMIN_CONFIRMATION_DEPTH
        bitcoin_rpc.proxy.generatetoaddress(enact_height - submit_height, wallet_addr)
        wait_until_asm_reaches_height(asm_rpc, min_height=enact_height)

        before = safe_harbor_descriptor(asm_rpc, bitcoin_rpc, enact_height - 1)
        assert before == DEFAULT_SAFE_HARBOR_DESCRIPTOR, (
            f"safe harbor changed before the update was enacted: {before}"
        )
        after = safe_harbor_descriptor(asm_rpc, bitcoin_rpc, enact_height)
        assert after == NEW_SAFE_HARBOR_DESCRIPTOR, (
            f"expected safe harbor {NEW_SAFE_HARBOR_DESCRIPTOR} once enacted, got {after}"
        )
        logging.info(
            "Safe harbor rotated to %s at height %s", NEW_SAFE_HARBOR_ADDRESS, enact_height
        )

        return True
