import logging

import flexitest

from utils.dbtool import (
    run_dbtool,
    run_dbtool_json,
    snapshot_db,
    write_ssz_file,
)
from utils.utils import (
    wait_until_asm_reaches_height,
    wait_until_asm_ready,
    wait_until_bitcoind_ready,
    wait_until_moho_proof_exists,
)

# Bridge V1 container ID. Matches `BRIDGE_V1_SUBPROTOCOL_ID` in the Rust codebase
# (crates/txs/bridge-v1/src/constants.rs).
BRIDGE_V1_CONTAINER_ID = 2


@flexitest.register
class AsmDbtoolMohoTest(flexitest.Test):
    """`moho` domain reads the Moho data the runner persisted.

    Runs under the `prover` env: the Moho worker (which writes the Moho DB)
    only runs when the orchestrator is configured. ASM has no tooling to
    simulate an assignment fulfillment, so no export entry can be driven from
    here — those get negative-path coverage, matching the RPC test.
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

        # A Moho proof for the tip implies the Moho worker has persisted its
        # state for that block, so the Moho DB is ready to read once stopped.
        target_block_hash = bitcoin_rpc.proxy.getblockhash(target_height)
        wait_until_moho_proof_exists(asm_rpc, target_block_hash)

        moho_db = asm_service.props["moho_db_path"]
        # Stopping the runner releases sled's lock on the directory.
        asm_service.stop()
        logging.info("runner stopped; Moho DB at %s", moho_db)

        # moho state: list / latest / get round-trip / get (missing).
        states = run_dbtool_json(moho_db, "moho", "state", "list")
        assert states["count"] > 0, f"expected Moho states, got {states}"
        logging.info("moho state list reports %d entries", states["count"])

        latest = run_dbtool_json(moho_db, "moho", "state", "latest")
        assert latest["found"] is True and latest["ssz_hex"], latest

        # The printed `commitment` field must feed straight back into `get`.
        block = states["entries"][0]
        commitment = block["commitment"]
        assert commitment == f"{block['height']}:{block['blkid']}", block
        got = run_dbtool_json(moho_db, "moho", "state", "get", commitment)
        assert got["found"] is True and got["ssz_hex"], got

        missing = run_dbtool_json(moho_db, "moho", "state", "get", f"999999:{'00' * 32}")
        assert missing["found"] is False, missing

        # write gate: prune refuses without --write.
        code, _out, err = run_dbtool(moho_db, "moho", "state", "prune", "--before", "1")
        assert code != 0 and "write" in err.lower(), (code, err)

        # write path (on a snapshot so the original is untouched): delete removes
        # the state and a subsequent get reports it gone.
        snap = snapshot_db(moho_db)
        deleted = run_dbtool_json(snap, "--write", "moho", "state", "delete", commitment)
        assert deleted["deleted"] is True, deleted
        gone = run_dbtool_json(snap, "moho", "state", "get", commitment)
        assert gone["found"] is False, gone

        # moho export-entries: no entry can be driven from here, so
        # cover the empty/negative paths — count works, and unknown leaves and
        # heights resolve to `found: false` rather than erroring.
        container = str(BRIDGE_V1_CONTAINER_ID)
        count = run_dbtool_json(moho_db, "moho", "export-entries", "count", container)
        assert count["count"] >= 0, count
        logging.info(
            "export-entries container %d holds %d leaves",
            BRIDGE_V1_CONTAINER_ID,
            count["count"],
        )

        entry_missing = run_dbtool_json(
            moho_db, "moho", "export-entries", "get", container, "999999"
        )
        assert entry_missing["found"] is False, entry_missing

        find_missing = run_dbtool_json(
            moho_db, "moho", "export-entries", "find", container, "ab" * 32
        )
        assert find_missing["found"] is False, find_missing

        range_missing = run_dbtool_json(
            moho_db, "moho", "export-entries", "range", container, "999999"
        )
        assert range_missing["found"] is False, range_missing

        # export-entries writes (on a snapshot): append extends the container
        # and reads back, and the CLI enforces the worker's invariants — runs
        # must arrive in ascending height order, and the all-zero hash (the
        # compact MMR's empty-peak sentinel) is not a representable leaf.
        snap = snapshot_db(moho_db)
        base = run_dbtool_json(snap, "moho", "export-entries", "count", container)["count"]
        entries_file = write_ssz_file("ab" * 32 + "cd" * 32)
        appended = run_dbtool_json(
            snap,
            "--write",
            "moho",
            "export-entries",
            "append",
            container,
            "999999",
            "--file",
            entries_file,
        )
        assert appended["appended"] == 2, appended
        leaf = run_dbtool_json(snap, "moho", "export-entries", "get", container, str(base))
        assert leaf["found"] is True and leaf["hash"] == "ab" * 32, leaf
        height = run_dbtool_json(snap, "moho", "export-entries", "height", container, str(base + 1))
        assert height["height"] == 999999, height

        # A second append at (or below) the latest populated height must be
        # refused — it would corrupt the height index.
        code, _out, err = run_dbtool(
            snap,
            "--write",
            "moho",
            "export-entries",
            "append",
            container,
            "999999",
            "--file",
            entries_file,
        )
        assert code != 0 and "prune" in err, (code, err)

        zero_file = write_ssz_file("00" * 32)
        code, _out, err = run_dbtool(
            snap,
            "--write",
            "moho",
            "export-entries",
            "append",
            container,
            "1000000",
            "--file",
            zero_file,
        )
        assert code != 0 and "all-zero" in err, (code, err)

        return True
