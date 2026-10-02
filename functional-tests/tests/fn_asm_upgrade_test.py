import logging

import flexitest

from envs.basic_env import ADMIN_SECRET_KEY
from envs.upgrade_env import (
    ASM_V1_SPEC_ID,
    UPGRADE_ADMIN_CONFIRMATION_DEPTH,
    asm_v1_predicate,
)
from utils.test_cli import submit_asm_stf_update
from utils.utils import (
    wait_until_asm_proof_exists,
    wait_until_asm_reaches_height,
    wait_until_asm_ready,
    wait_until_bitcoind_ready,
    wait_until_moho_proof_exists,
)

GENESIS_SPEC_ID = 0


def anchor_spec_id(asm_rpc, block_hash: str) -> int:
    """Read the producing spec ID from a block's SSZ-encoded anchor state.

    `spec_id` is the container's first field, a fixed-size little-endian u16, so it
    always occupies the first two bytes.
    """
    anchor = asm_rpc.strata_asm_getAnchorState(block_hash)
    assert anchor is not None, f"no anchor state for {block_hash}"
    return int.from_bytes(bytes(anchor[:2]), "little")


@flexitest.register
class AsmUpgradeTest(flexitest.Test):
    """Activate spec 1 through an admin update and check that execution and the
    recursive proof chain continue across the switch.

    The block that enacts the update still runs under spec 0; every block after it
    runs under spec 1 and is proven by the spec 1 host. A Moho proof past the switch
    can only exist if the recursion accepted step proofs from both programs.
    """

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env("upgrade")

    def main(self, ctx: flexitest.RunContext):
        bitcoind_service = ctx.get_service("bitcoin")
        asm_service = ctx.get_service("asm_rpc")

        bitcoin_rpc = bitcoind_service.create_rpc()
        asm_rpc = asm_service.create_rpc()

        wait_until_bitcoind_ready(bitcoin_rpc, timeout=30)
        wait_until_asm_ready(asm_rpc)

        wallet_addr = bitcoin_rpc.proxy.getnewaddress()
        initial_height = bitcoin_rpc.proxy.getblockcount()

        # Prove a block under spec 0 before anything changes.
        bitcoin_rpc.proxy.generatetoaddress(2, wallet_addr)
        pre_upgrade_hash = bitcoin_rpc.proxy.getblockhash(initial_height + 2)
        wait_until_asm_reaches_height(asm_rpc, min_height=initial_height + 2)
        wait_until_moho_proof_exists(asm_rpc, pre_upgrade_hash)
        logging.info("Moho proof exists under spec 0 at height %s", initial_height + 2)

        txid = submit_asm_stf_update(
            bitcoind_service,
            admin_secret_key=ADMIN_SECRET_KEY,
            seqno=1,
            predicate=asm_v1_predicate(),
        )
        [submit_hash] = bitcoin_rpc.proxy.generatetoaddress(1, wallet_addr)
        assert txid in bitcoin_rpc.proxy.getblock(submit_hash)["tx"], (
            f"update tx {txid} was not mined in {submit_hash}"
        )
        submit_height = initial_height + 3

        # The queued update is enacted `depth` blocks after the one that carried it.
        enact_height = submit_height + UPGRADE_ADMIN_CONFIRMATION_DEPTH
        tip_height = enact_height + 2
        bitcoin_rpc.proxy.generatetoaddress(tip_height - submit_height, wallet_addr)
        wait_until_asm_reaches_height(asm_rpc, min_height=tip_height)

        for height in range(initial_height + 1, tip_height + 1):
            expected = GENESIS_SPEC_ID if height <= enact_height else ASM_V1_SPEC_ID
            spec_id = anchor_spec_id(asm_rpc, bitcoin_rpc.proxy.getblockhash(height))
            assert spec_id == expected, (
                f"block {height} ran under spec {spec_id}, expected {expected} "
                f"(update enacted at {enact_height})"
            )
        logging.info("Spec switched from 0 to 1 after enacting block %s", enact_height)

        # The first spec 1 block is proven by the new host, and the recursion chains
        # through it to the tip.
        first_v1_hash = bitcoin_rpc.proxy.getblockhash(enact_height + 1)
        wait_until_asm_proof_exists(asm_rpc, first_v1_hash)
        tip_hash = bitcoin_rpc.proxy.getblockhash(tip_height)
        wait_until_moho_proof_exists(asm_rpc, tip_hash)
        logging.info("Moho proof exists under spec 1 at height %s", tip_height)

        return True
