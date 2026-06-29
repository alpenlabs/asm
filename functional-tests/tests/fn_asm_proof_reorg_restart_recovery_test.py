import logging

import flexitest

from utils.utils import (
    wait_until_asm_reaches_height,
    wait_until_asm_ready,
    wait_until_bitcoind_ready,
    wait_until_moho_proof_exists,
)

# Orphan branch A: mined *and* fully proven before the reorg, so its Moho proofs
# linger afterwards (orphaned states and proofs are never pruned). Its tip height
# becomes the misleading global-maximum Moho proof.
BURST_A = 20

# Replacement branch B: longer than A so it is adopted as canonical, and large
# enough that the rate-limited recursive chain (one Moho proof per 1s tick)
# cannot re-prove past A's orphan height before we restart.
BURST_B = 30


@flexitest.register
class AsmProofReorgRestartRecoveryTest(flexitest.Test):
    """Pending proofs must survive a restart that follows an L1 reorg (STR-3858).

    Recovery rebuilds the pending proof set from durable state on startup. If it
    derives its watermark from the global-maximum Moho proof, an orphaned proof
    from an abandoned reorg branch — which is never pruned — can outrank the
    canonical proof frontier. Recovery then skips the genuinely-pending canonical
    blocks below that orphan, and the recursive Moho chain stalls on the gap
    forever.

    Concretely: branch A is mined and fully proven (orphan proofs up to A's tip),
    then a reorg replaces it with a longer branch B whose proofs still lag near
    the fork. A global-max watermark reads A's tip and never re-enqueues B's
    lower blocks. This test asserts the chain heals up to B's tip after restart,
    which is only possible if recovery walks the *canonical* chain instead.
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

        fork_height = bitcoin_rpc.proxy.getblockcount()
        wallet_addr = bitcoin_rpc.proxy.getnewaddress()

        # Branch A: mine, then wait for the recursive chain to fully prove up to
        # its tip. These proofs become orphans after the reorg but persist.
        bitcoin_rpc.proxy.generatetoaddress(BURST_A, wallet_addr)
        a_tip_height = fork_height + BURST_A
        a_tip_hash = bitcoin_rpc.proxy.getblockhash(a_tip_height)
        wait_until_asm_reaches_height(asm_rpc, min_height=a_tip_height)
        wait_until_moho_proof_exists(asm_rpc, a_tip_hash)
        logging.info("branch A proven up to orphan tip %s", a_tip_height)

        # Reorg: invalidate A from the fork's first child and mine a longer B.
        # bitcoind abandons A, so blocks mined now build on the fork point.
        fork_child = bitcoin_rpc.proxy.getblockhash(fork_height + 1)
        bitcoin_rpc.proxy.invalidateblock(fork_child)
        bitcoin_rpc.proxy.generatetoaddress(BURST_B, wallet_addr)
        b_tip_height = fork_height + BURST_B
        b_tip_hash = bitcoin_rpc.proxy.getblockhash(b_tip_height)

        # Let the worker reprocess B (fast) — this persists the anchor states that
        # recovery reads. Its recursive proof chain restarts near the fork and
        # lags far behind, while A's orphan proof at a_tip_height still lingers.
        wait_until_asm_reaches_height(asm_rpc, min_height=b_tip_height)
        logging.info("branch B (canonical) processed up to tip %s", b_tip_height)

        # The orphaned proof must still be readable (proofs are keyed by block
        # commitment and never pruned), and the canonical block at the orphan's
        # height must NOT yet be proven. Together these guarantee the global-max
        # watermark points at the orphan — without that, the buggy code would
        # behave correctly and the test would pass vacuously.
        assert asm_rpc.strata_asm_getMohoProof(a_tip_hash) is not None, (
            "orphaned branch-A Moho proof unexpectedly absent; the reorg scenario is not set up"
        )
        canonical_at_orphan_height = bitcoin_rpc.proxy.getblockhash(a_tip_height)
        assert asm_rpc.strata_asm_getMohoProof(canonical_at_orphan_height) is None, (
            f"canonical Moho proof at height {a_tip_height} already completed before "
            f"restart; the recursive chain outran the orphan. Increase BURST_A "
            f"(currently {BURST_A}) so the orphan stays above the canonical frontier"
        )

        logging.info("stopping ASM runner with orphan proof above the canonical frontier")
        asm_service.stop()

        # Restart WITHOUT mining anything new: the startup tip-submit is a no-op
        # (B's tip is already processed), so nothing re-enters the queue via the
        # channel — recovery must come from durable state alone.
        logging.info("restarting ASM runner")
        asm_service.start()
        asm_rpc = asm_service.create_rpc()
        wait_until_asm_ready(asm_rpc)

        # The canonical chain must heal all the way to B's tip. Proving the tip
        # requires every Moho proof below it, so this single assertion covers the
        # whole skipped gap. With a global-max watermark the chain stays stuck
        # behind the orphan and this times out.
        wait_until_moho_proof_exists(asm_rpc, b_tip_hash)
        logging.info("Moho proof for canonical tip %s recovered after reorg+restart", b_tip_height)

        return True
