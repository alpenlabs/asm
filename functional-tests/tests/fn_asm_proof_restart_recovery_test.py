import logging

import flexitest

from utils.utils import (
    wait_until_asm_reaches_height,
    wait_until_asm_ready,
    wait_until_bitcoind_ready,
    wait_until_moho_proof_exists,
)

# Mine enough blocks in one burst that the rate-limited recursive Moho chain
# cannot catch up before we stop. The chain advances at most one proof per
# orchestrator tick (1s in tests), because Moho(H) can only be submitted once
# Moho(H-1) is stored. The worker, by contrast, processes these tiny regtest
# blocks in well under a tick each. So by the time the worker has processed the
# whole burst, only a handful of Moho proofs exist and the upper blocks' proofs
# are still queued — not yet submitted. A large burst keeps a comfortable margin
# between "worker done" and "chain caught up".
BURST = 20


@flexitest.register
class AsmProofRestartRecoveryTest(flexitest.Test):
    """Pending proofs must survive a restart (regression for STR-3858).

    The in-memory pending proof queue is fed only by blocks the worker
    (re)processes, and an already-processed block is a no-op on restart. So a
    Moho proof that was pending — enqueued but not yet submitted — when the
    runner stopped used to be lost on restart: the channel never re-delivered it
    (the block was already processed) and startup only recovered proofs already
    submitted to the remote prover. Because the Moho chain is recursive, that
    gap never healed — every later block's proof deferred forever on the missing
    predecessor.

    This test forces the gap, then asserts the runner heals it after a restart
    with no new blocks mined — only possible if it rebuilds the pending set from
    durable state (latest completed Moho proof → worker tip) on startup.
    """

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env("prover")

    def main(self, ctx: flexitest.RunContext):
        bitcoind_service = ctx.get_service("bitcoin")
        asm_service = ctx.get_service("asm_rpc")

        bitcoin_rpc = bitcoind_service.create_rpc()
        asm_rpc = asm_service.create_rpc()

        wait_until_bitcoind_ready(bitcoin_rpc, timeout=30)
        wait_until_asm_ready(asm_rpc)

        initial_btc_height = bitcoin_rpc.proxy.getblockcount()
        wallet_addr = bitcoin_rpc.proxy.getnewaddress()

        bitcoin_rpc.proxy.generatetoaddress(BURST, wallet_addr)
        tip_height = initial_btc_height + BURST
        tip_hash = bitcoin_rpc.proxy.getblockhash(tip_height)

        # Wait only for the *worker* to process the burst — NOT for proofs to
        # catch up. Processing persists the anchor states that startup recovery
        # reads, while the recursive Moho chain is left lagging far behind.
        wait_until_asm_reaches_height(asm_rpc, min_height=tip_height)

        # The bug only bites if the tip's Moho proof is still pending here. If
        # it already exists, the burst was too small to outrun the chain and the
        # test would pass vacuously — fail loudly instead of silently.
        assert asm_rpc.strata_asm_getMohoProof(tip_hash) is None, (
            f"tip Moho proof at height {tip_height} already completed before restart; "
            f"increase BURST (currently {BURST}) so the recursive chain cannot catch up"
        )

        logging.info("stopping ASM runner with pending Moho proofs up to tip %s", tip_height)
        asm_service.stop()

        # Restart WITHOUT mining anything new. The startup tip-submit is a no-op
        # (the tip is already processed), so nothing re-enters the proof queue
        # via the channel — recovery must come from durable state alone.
        logging.info("restarting ASM runner")
        asm_service.start()
        asm_rpc = asm_service.create_rpc()
        wait_until_asm_ready(asm_rpc)

        # The recursive chain must heal all the way up to the pre-restart tip.
        # Proving the tip requires every Moho proof below it, so this single
        # assertion covers the whole recovered gap. Without the fix the chain
        # stays stuck where it stopped and this times out.
        wait_until_moho_proof_exists(asm_rpc, tip_hash)
        logging.info("Moho proof for pre-restart tip %s recovered after restart", tip_height)

        return True
