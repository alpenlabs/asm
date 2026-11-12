import logging

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


@flexitest.register
class AsmDbtoolProofHealTest(flexitest.Test):
    """A deleted proof is proven again, even though its submission record stays.

    A submission record outlives its remote job, so deleting a stored proof
    leaves a record with no job behind it. The scheduler must read that record
    as stale, not as a job in flight, or the deleted proof and every Moho proof
    that recurses from it would stay missing for good.
    """

    def __init__(self, ctx: flexitest.InitContext):
        # A dedicated prover env, not the shared `prover` one: the test stops
        # and restarts the runner to take sled's lock for offline dbtool
        # surgery, which must not disturb other tests.
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

        # Delete the highest Moho proof and leave its submission record. The
        # highest one specifically, so the restart has work to rediscover: the
        # queue is seeded from the latest committed block and skips it when it
        # is already proven, so removing a lower proof would leave nothing to do.
        asm_service.stop()
        latest = run_dbtool_json(proof_db, "proof", "moho", "latest")
        assert latest["found"] is True, latest
        victim = latest["commitment"]
        victim_hash = bitcoin_rpc.proxy.getblockhash(latest["block"]["height"])
        proof_id = f"moho:{victim}"

        # Native proving still goes through the remote-host interface, so it
        # writes these records exactly as a real remote prover would.
        record = run_dbtool_json(proof_db, "proof", "mapping", "get-remote", proof_id)
        assert record["found"] is True, record

        deleted = run_dbtool_json(proof_db, "--write", "proof", "moho", "delete", victim)
        assert deleted["deleted"] is True, deleted
        logging.info("deleted Moho proof %s, kept its submission record", victim)

        asm_service.start()
        asm_rpc = asm_service.create_rpc()
        wait_until_asm_ready(asm_rpc)

        # Mine a block on top. Its Moho proof needs the deleted one as its
        # parent, so both coming back shows the prerequisite cascade reached
        # the victim and resubmitted it.
        next_height = bitcoin_rpc.proxy.getblockcount() + 1
        bitcoin_rpc.proxy.generatetoaddress(1, wallet_addr)
        wait_until_asm_reaches_height(asm_rpc, min_height=next_height)
        next_hash = bitcoin_rpc.proxy.getblockhash(next_height)

        wait_until_moho_proof_exists(asm_rpc, victim_hash, timeout=120)
        wait_until_moho_proof_exists(asm_rpc, next_hash, timeout=120)

        return True
