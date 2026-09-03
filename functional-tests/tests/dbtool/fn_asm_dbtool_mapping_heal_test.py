import logging
import time

import flexitest

from envs import ProverEnv
from utils.dbtool import proof_db_path, run_dbtool_json
from utils.utils import (
    wait_until_asm_proof_exists,
    wait_until_asm_reaches_height,
    wait_until_asm_ready,
    wait_until_bitcoind_ready,
    wait_until_moho_proof_exists,
)

# Ticks the prover gets to prove the deleted block before we conclude it never
# will. The env runs a 1s tick interval, and the liveness check below already
# waits for fresh work to complete, so this only has to cover scheduling jitter.
WEDGE_OBSERVATION_TICKS = 10


def _moho_proof(asm_rpc, block_hash):
    """The Moho proof for a block, or None. Mirrors the wait helpers, which
    treat an RPC error as "not there yet"."""
    try:
        return asm_rpc.strata_asm_getMohoProof(block_hash)
    except Exception as exc:
        logging.debug("Moho proof lookup failed for %s: %s", block_hash, exc)
        return None


@flexitest.register
class AsmDbtoolMappingHealTest(flexitest.Test):
    """Deleting a proof wedges its block; deleting the mapping frees it.

    A mapping row records that a proof was submitted to the remote prover, and
    the scheduler skips any proof that has one. Nothing in the worker ever
    clears that row, so deleting a proof without its mapping leaves a block
    that can never be proven again — a restart re-reads the same row and
    reaches the same conclusion. `proof mapping delete` is the way out.

    The wedge halts Moho recursion only. ASM step proofs have no proof
    prerequisites, so they keep being produced throughout, which is what this
    test uses to show the prover is alive rather than merely idle.
    """

    def __init__(self, ctx: flexitest.InitContext):
        # A dedicated prover env, not the shared `prover` one: the test stops
        # and restarts the runner repeatedly to take sled's lock for offline
        # dbtool surgery, which must not disturb other tests.
        ctx.set_env(ProverEnv())

    def main(self, ctx: flexitest.RunContext):
        bitcoin_rpc = ctx.get_service("bitcoin").create_rpc()
        asm_service = ctx.get_service("asm_rpc")
        asm_rpc = asm_service.create_rpc()

        wait_until_bitcoind_ready(bitcoin_rpc, timeout=30)
        wait_until_asm_ready(asm_rpc)

        # Build a few blocks of proven history, so the victim below has a
        # parent Moho proof to recurse from.
        wallet_addr = bitcoin_rpc.proxy.getnewaddress()
        target_height = bitcoin_rpc.proxy.getblockcount() + 3
        bitcoin_rpc.proxy.generatetoaddress(3, wallet_addr)
        wait_until_asm_reaches_height(asm_rpc, min_height=target_height)
        target_hash = bitcoin_rpc.proxy.getblockhash(target_height)
        wait_until_asm_proof_exists(asm_rpc, target_hash)
        wait_until_moho_proof_exists(asm_rpc, target_hash)

        proof_db = proof_db_path(asm_service.props["db_path"])

        # ---- Wedge the tip: delete its Moho proof, leave the mapping ----
        #
        # The highest proof specifically, so the restart has work to rediscover:
        # the queue is seeded from the latest committed block and skips when it
        # is already proven, so removing a lower proof would leave nothing to do.
        asm_service.stop()
        latest = run_dbtool_json(proof_db, "proof", "moho", "latest")
        assert latest["found"] is True, latest
        victim = latest["commitment"]
        victim_height = latest["block"]["height"]
        victim_hash = bitcoin_rpc.proxy.getblockhash(victim_height)
        proof_id = f"moho:{victim}"

        # The mapping outlives the proof — the whole premise of this test.
        # Native proving still goes through the remote-host interface, so it
        # writes these rows exactly as a real remote prover would.
        mapping = run_dbtool_json(proof_db, "proof", "mapping", "get-remote", proof_id)
        assert mapping["found"] is True, mapping

        deleted = run_dbtool_json(proof_db, "--write", "proof", "moho", "delete", victim)
        assert deleted["deleted"] is True, deleted

        asm_service.start()
        asm_rpc = asm_service.create_rpc()
        wait_until_asm_ready(asm_rpc)

        # ---- The wedge holds across the restart ----
        #
        # Mine a block and wait for its ASM proof. That proves the prover is
        # running and completing work, so the Moho proofs still missing below
        # are missing because they are blocked, not because nothing has run yet.
        next_height = bitcoin_rpc.proxy.getblockcount() + 1
        bitcoin_rpc.proxy.generatetoaddress(1, wallet_addr)
        wait_until_asm_reaches_height(asm_rpc, min_height=next_height)
        next_hash = bitcoin_rpc.proxy.getblockhash(next_height)
        wait_until_asm_proof_exists(asm_rpc, next_hash)

        for _ in range(WEDGE_OBSERVATION_TICKS):
            time.sleep(1)
            assert _moho_proof(asm_rpc, victim_hash) is None, (
                f"Moho proof for {victim_hash} came back while its mapping still stood"
            )
        # Recursion is blocked above the victim too: the new block's Moho proof
        # needs the one we deleted.
        assert _moho_proof(asm_rpc, next_hash) is None, next_hash

        # ---- Delete the mapping and it heals ----
        asm_service.stop()
        freed = run_dbtool_json(proof_db, "--write", "proof", "mapping", "delete", proof_id)
        assert freed["deleted"] is True, freed
        gone = run_dbtool_json(proof_db, "proof", "mapping", "get-remote", proof_id)
        assert gone["found"] is False, gone

        asm_service.start()
        asm_rpc = asm_service.create_rpc()
        wait_until_asm_ready(asm_rpc)

        # The deleted proof is regenerated, and the backlog above it drains:
        # the prerequisite cascade walks the newer block back to the victim.
        wait_until_moho_proof_exists(asm_rpc, victim_hash, timeout=120)
        wait_until_moho_proof_exists(asm_rpc, next_hash, timeout=120)

        return True
