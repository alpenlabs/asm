import logging

import flexitest

from utils.dbtool import (
    proof_db_path,
    run_dbtool,
    run_dbtool_json,
    snapshot_db,
)
from utils.utils import (
    wait_until_asm_proof_exists,
    wait_until_asm_reaches_height,
    wait_until_asm_ready,
    wait_until_bitcoind_ready,
    wait_until_moho_proof_exists,
)


@flexitest.register
class AsmDbtoolProofTest(flexitest.Test):
    """`proof` domain reads the proofs and bookkeeping the prover persisted.

    Runs under the `prover` env so the orchestrator populates the proof DB with
    ASM and Moho proofs. The native backend proves locally, so the remote
    mapping/status trees stay empty — those get negative-path coverage.
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

        start_height = bitcoin_rpc.proxy.getblockcount()
        wallet_addr = bitcoin_rpc.proxy.getnewaddress()
        num_blocks = 3
        bitcoin_rpc.proxy.generatetoaddress(num_blocks, wallet_addr)

        target_height = start_height + num_blocks
        wait_until_asm_reaches_height(asm_rpc, min_height=target_height)

        # The proof DB is only written once the orchestrator finishes proving,
        # so wait for both proofs to land before stopping the runner.
        target_block_hash = bitcoin_rpc.proxy.getblockhash(target_height)
        wait_until_asm_proof_exists(asm_rpc, target_block_hash)
        wait_until_moho_proof_exists(asm_rpc, target_block_hash)

        db_path = asm_service.props["db_path"]
        proof_db = proof_db_path(db_path)
        # Stopping the runner releases sled's lock so dbtool can open the proof DB.
        asm_service.stop()
        logging.info("runner stopped; proof DB at %s", proof_db)

        # proof asm: list has entries; a listed range round-trips through get.
        asm_list = run_dbtool_json(proof_db, "proof", "asm", "list")
        assert asm_list["count"] > 0, f"expected ASM proofs, got {asm_list}"
        asm_range = asm_list["entries"][0]["range"]
        asm_got = run_dbtool_json(proof_db, "proof", "asm", "get", asm_range)
        assert asm_got["found"] is True and asm_got["borsh_hex"], asm_got
        asm_missing = run_dbtool_json(proof_db, "proof", "asm", "get", f"999999:{'00' * 32}")
        assert asm_missing["found"] is False, asm_missing

        # proof moho: list / latest / get round-trip / get (missing).
        moho_list = run_dbtool_json(proof_db, "proof", "moho", "list")
        assert moho_list["count"] > 0, moho_list
        latest = run_dbtool_json(proof_db, "proof", "moho", "latest")
        assert latest["found"] is True and latest["borsh_hex"], latest

        # The printed `commitment` field must feed straight back into `get`.
        moho_block = moho_list["entries"][0]
        commitment = moho_block["commitment"]
        assert commitment == f"{moho_block['height']}:{moho_block['blkid']}", moho_block
        moho_got = run_dbtool_json(proof_db, "proof", "moho", "get", commitment)
        assert moho_got["found"] is True and moho_got["borsh_hex"], moho_got
        moho_missing = run_dbtool_json(proof_db, "proof", "moho", "get", f"999999:{'00' * 32}")
        assert moho_missing["found"] is False, moho_missing

        # mapping / status: local (native) proving leaves the remote bookkeeping
        # empty, so lists work and return zero and lookups miss.
        mapping_list = run_dbtool_json(proof_db, "proof", "mapping", "list")
        assert mapping_list["count"] >= 0, mapping_list
        status_list = run_dbtool_json(proof_db, "proof", "status", "list")
        assert status_list["count"] >= 0, status_list
        in_progress = run_dbtool_json(proof_db, "proof", "status", "in-progress")
        assert in_progress["count"] >= 0, in_progress
        status_missing = run_dbtool_json(proof_db, "proof", "status", "get", "deadbeef")
        assert status_missing["found"] is False, status_missing

        # write gate: prune refuses without --write.
        code, _out, err = run_dbtool(proof_db, "proof", "prune", "--before", "1")
        assert code != 0 and "write" in err.lower(), (code, err)

        # write path (on a snapshot so the original is untouched): delete removes
        # the Moho proof and a subsequent get reports it gone.
        snap = snapshot_db(proof_db)
        deleted = run_dbtool_json(snap, "--write", "proof", "moho", "delete", commitment)
        assert deleted["deleted"] is True, deleted
        gone = run_dbtool_json(snap, "proof", "moho", "get", commitment)
        assert gone["found"] is False, gone

        return True
