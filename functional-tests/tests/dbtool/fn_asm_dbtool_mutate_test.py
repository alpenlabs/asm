import flexitest

from envs import BasicEnv
from utils.dbtool import (
    prepare_populated_db,
    run_dbtool_json,
    snapshot_db,
    write_ssz_file,
)


@flexitest.register
class AsmDbtoolMutateTest(flexitest.Test):
    """With --write: delete removes, put restores, and put-leaf appends to the MMR.

    Each scenario runs on its own snapshot of the stopped DB so the mutations
    stay isolated.
    """

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env(BasicEnv())

    def main(self, ctx: flexitest.RunContext):
        source = prepare_populated_db(ctx)

        # delete → put round-trip, byte-for-byte, through the real binary.
        db = snapshot_db(source)
        manifests = run_dbtool_json(db, "asm", "manifest", "list")
        block = manifests["entries"][0]
        commitment = f"{block['height']}:{block['blkid']}"
        original = run_dbtool_json(db, "asm", "manifest", "get", commitment)
        ssz_file = write_ssz_file(original["ssz_hex"])

        deleted = run_dbtool_json(db, "--write", "asm", "manifest", "delete", commitment)
        assert deleted["deleted"] is True, deleted
        gone = run_dbtool_json(db, "asm", "manifest", "get", commitment)
        assert gone["found"] is False, gone

        stored = run_dbtool_json(db, "--write", "asm", "manifest", "put", "--file", ssz_file)
        assert stored["stored"] is True, stored
        restored = run_dbtool_json(db, "asm", "manifest", "get", commitment)
        assert restored["found"] is True, restored
        assert restored["ssz_hex"] == original["ssz_hex"], "round-trip changed the SSZ bytes"

        # put-leaf appends a new MMR leaf at the current end and reads it back.
        db = snapshot_db(source)
        count = run_dbtool_json(db, "asm", "manifest-mmr", "count")["leaf_count"]
        new_hash = "ab" * 32
        appended = run_dbtool_json(
            db, "--write", "asm", "manifest-mmr", "put-leaf", str(count), new_hash
        )
        assert appended["stored"] is True, appended
        assert run_dbtool_json(db, "asm", "manifest-mmr", "count")["leaf_count"] == count + 1
        leaf = run_dbtool_json(db, "asm", "manifest-mmr", "leaf", str(count))
        assert leaf["found"] is True and leaf["hash"] == new_hash, leaf

        return True
