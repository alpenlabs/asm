import logging

import flexitest

from envs.basic_env import ADMIN_SECRET_KEY
from envs.upgrade_env import ASM_V1_SPEC_ID, UPGRADE_ADMIN_CONFIRMATION_DEPTH
from envs.upgrade_v2_env import ASM_V2_SPEC_ID, asm_v2_predicate
from factory.common.asm_params import (
    DEFAULT_SAFE_HARBOR_DESCRIPTOR,
    NEW_SAFE_HARBOR_ADDRESS,
    NEW_SAFE_HARBOR_DESCRIPTOR,
    load_runtime_params,
)
from utils.test_cli import submit_asm_stf_update, submit_safe_harbor_update
from utils.utils import (
    safe_harbor_descriptor,
    wait_until_asm_proof_exists,
    wait_until_asm_reaches_height,
    wait_until_asm_ready,
    wait_until_bitcoind_ready,
    wait_until_moho_proof_exists,
)


def anchor_spec_id(asm_rpc, block_hash: str) -> int:
    """Read the producing spec ID from a block's SSZ-encoded anchor state.

    `spec_id` is the container's first field, a fixed-size little-endian u16, so it
    always occupies the first two bytes.
    """
    anchor = asm_rpc.strata_asm_getAnchorState(block_hash)
    assert anchor is not None, f"no anchor state for {block_hash}"
    return int.from_bytes(bytes(anchor[:2]), "little")


@flexitest.register
class AsmUpgradeV1V2Test(flexitest.Test):
    """Activate spec 2 on a chain that started under spec 1, and check that execution and
    the recursive proof chain continue across the switch.

    The block that enacts the update still runs under spec 1; every block after it
    runs under spec 2 and is proven by the spec 2 host. A Moho proof past the switch
    can only exist if the recursion accepted step proofs from both programs.

    Spec 2 queues admin updates with the confirmation depths from the runtime params,
    so an update submitted after the switch waits for those instead of the genesis ones.
    """

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env("upgrade_v2")

    def main(self, ctx: flexitest.RunContext):
        bitcoind_service = ctx.get_service("bitcoin")
        asm_service = ctx.get_service("asm_rpc")

        bitcoin_rpc = bitcoind_service.create_rpc()
        asm_rpc = asm_service.create_rpc()

        wait_until_bitcoind_ready(bitcoin_rpc, timeout=30)
        wait_until_asm_ready(asm_rpc)

        wallet_addr = bitcoin_rpc.proxy.getnewaddress()
        initial_height = bitcoin_rpc.proxy.getblockcount()

        # Prove a block under spec 1 before anything changes.
        bitcoin_rpc.proxy.generatetoaddress(2, wallet_addr)
        pre_upgrade_hash = bitcoin_rpc.proxy.getblockhash(initial_height + 2)
        wait_until_asm_reaches_height(asm_rpc, min_height=initial_height + 2)
        wait_until_moho_proof_exists(asm_rpc, pre_upgrade_hash)
        logging.info("Moho proof exists under spec 1 at height %s", initial_height + 2)

        txid = submit_asm_stf_update(
            bitcoind_service,
            admin_secret_key=ADMIN_SECRET_KEY,
            seqno=1,
            predicate=asm_v2_predicate(),
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
            expected = ASM_V1_SPEC_ID if height <= enact_height else ASM_V2_SPEC_ID
            spec_id = anchor_spec_id(asm_rpc, bitcoin_rpc.proxy.getblockhash(height))
            assert spec_id == expected, (
                f"block {height} ran under spec {spec_id}, expected {expected} "
                f"(update enacted at {enact_height})"
            )
        logging.info("Spec switched from 1 to 2 after enacting block %s", enact_height)

        # The first spec 2 block is proven by the new host, and the recursion chains
        # through it to the tip.
        first_v2_hash = bitcoin_rpc.proxy.getblockhash(enact_height + 1)
        wait_until_asm_proof_exists(asm_rpc, first_v2_hash)
        tip_hash = bitcoin_rpc.proxy.getblockhash(tip_height)
        wait_until_moho_proof_exists(asm_rpc, tip_hash)
        logging.info("Moho proof exists under spec 2 at height %s", tip_height)

        # A rotation submitted under spec 2 waits for the runtime depth. It has to be
        # longer than the genesis one, or enacting on time would not tell them apart.
        spec_v2 = load_runtime_params()["spec_v2"]
        v2_depth = spec_v2["confirmation_depths"]["safe_harbor_address_update"]
        assert v2_depth > UPGRADE_ADMIN_CONFIRMATION_DEPTH, (
            f"runtime depth {v2_depth} must exceed the genesis depth "
            f"{UPGRADE_ADMIN_CONFIRMATION_DEPTH}"
        )
        txid = submit_safe_harbor_update(
            bitcoind_service,
            admin_secret_key=ADMIN_SECRET_KEY,
            seqno=2,
            address=NEW_SAFE_HARBOR_ADDRESS,
        )
        [rotate_hash] = bitcoin_rpc.proxy.generatetoaddress(1, wallet_addr)
        assert txid in bitcoin_rpc.proxy.getblock(rotate_hash)["tx"], (
            f"update tx {txid} was not mined in {rotate_hash}"
        )
        rotate_enact_height = tip_height + 1 + v2_depth
        bitcoin_rpc.proxy.generatetoaddress(v2_depth, wallet_addr)
        wait_until_asm_reaches_height(asm_rpc, min_height=rotate_enact_height)

        before = safe_harbor_descriptor(asm_rpc, bitcoin_rpc, rotate_enact_height - 1)
        assert before == DEFAULT_SAFE_HARBOR_DESCRIPTOR, (
            f"safe harbor changed before the runtime depth elapsed: {before}"
        )
        after = safe_harbor_descriptor(asm_rpc, bitcoin_rpc, rotate_enact_height)
        assert after == NEW_SAFE_HARBOR_DESCRIPTOR, (
            f"expected safe harbor {NEW_SAFE_HARBOR_DESCRIPTOR} once enacted, got {after}"
        )
        logging.info(
            "Safe harbor rotated after the runtime depth of %s blocks, at height %s",
            v2_depth,
            rotate_enact_height,
        )

        return True
