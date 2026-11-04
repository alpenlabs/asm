import logging

import flexitest

from envs.basic_env import ADMIN_SECRET_KEY
from envs.upgrade_env import (
    UPGRADE_ADMIN_CONFIRMATION_DEPTH,
    UPGRADE_SPEC_IDS,
    asm_upgrade_predicate,
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
    """Activate spec 1 and then spec 2 through admin updates and check that execution and
    the recursive proof chain continue across each switch.

    The block that enacts an update still runs under the old spec; every block after it
    runs under the new spec and is proven by its host. A Moho proof past a switch can only
    exist if the recursion accepted step proofs from both programs. Going through spec 1
    also exercises spec 2 migrating the bridge section of a spec 1 parent.
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
        tip_height = initial_height + 2
        pre_upgrade_hash = bitcoin_rpc.proxy.getblockhash(tip_height)
        wait_until_asm_reaches_height(asm_rpc, min_height=tip_height)
        wait_until_moho_proof_exists(asm_rpc, pre_upgrade_hash)
        logging.info("Moho proof exists under spec 0 at height %s", tip_height)

        # Each entry is (first height, spec ID) for a run of blocks under one spec.
        spec_runs = [(initial_height + 1, GENESIS_SPEC_ID)]
        for seqno, spec_id in enumerate(UPGRADE_SPEC_IDS, start=1):
            enact_height = self._enact_update(
                bitcoin_rpc, bitcoind_service, wallet_addr, seqno, spec_id, tip_height
            )
            # Mine two blocks under the new spec so the Moho recursion has to chain past it.
            tip_height = enact_height + 2
            bitcoin_rpc.proxy.generatetoaddress(tip_height - enact_height, wallet_addr)
            wait_until_asm_reaches_height(asm_rpc, min_height=tip_height)
            spec_runs.append((enact_height + 1, spec_id))

            for height in range(initial_height + 1, tip_height + 1):
                expected = next(
                    run_spec for start, run_spec in reversed(spec_runs) if height >= start
                )
                actual = anchor_spec_id(asm_rpc, bitcoin_rpc.proxy.getblockhash(height))
                assert actual == expected, (
                    f"block {height} ran under spec {actual}, expected {expected} "
                    f"(spec runs {spec_runs})"
                )
            previous = spec_runs[-2][1]
            logging.info(
                "Spec switched from %s to %s after enacting block %s",
                previous,
                spec_id,
                enact_height,
            )

            # The first block under the new spec is proven by its host, and the recursion
            # chains through it to the tip.
            first_hash = bitcoin_rpc.proxy.getblockhash(enact_height + 1)
            wait_until_asm_proof_exists(asm_rpc, first_hash)
            tip_hash = bitcoin_rpc.proxy.getblockhash(tip_height)
            wait_until_moho_proof_exists(asm_rpc, tip_hash)
            logging.info("Moho proof exists under spec %s at height %s", spec_id, tip_height)

        return True

    def _enact_update(
        self,
        bitcoin_rpc,
        bitcoind_service,
        wallet_addr: str,
        seqno: int,
        spec_id: int,
        tip_height: int,
    ) -> int:
        """Submit an update to `spec_id` on top of `tip_height` and mine until it is enacted.

        Returns the height of the enacting block, which still runs under the old spec.
        """
        txid = submit_asm_stf_update(
            bitcoind_service,
            admin_secret_key=ADMIN_SECRET_KEY,
            seqno=seqno,
            predicate=asm_upgrade_predicate(spec_id),
        )
        [submit_hash] = bitcoin_rpc.proxy.generatetoaddress(1, wallet_addr)
        assert txid in bitcoin_rpc.proxy.getblock(submit_hash)["tx"], (
            f"update tx {txid} was not mined in {submit_hash}"
        )
        submit_height = tip_height + 1

        # The queued update is enacted `depth` blocks after the one that carried it.
        enact_height = submit_height + UPGRADE_ADMIN_CONFIRMATION_DEPTH
        bitcoin_rpc.proxy.generatetoaddress(enact_height - submit_height, wallet_addr)
        return enact_height
