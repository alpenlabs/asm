import flexitest

from envs import BasicEnv
from utils.dbtool import (
    prepare_populated_db,
    run_dbtool,
    run_dbtool_json,
    write_ssz_file,
)


@flexitest.register
class AsmDbtoolWriteGateTest(flexitest.Test):
    """Every mutating verb refuses without --write and leaves the DB untouched."""

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env(BasicEnv())

    def main(self, ctx: flexitest.RunContext):
        db = prepare_populated_db(ctx)

        # A real commitment + a valid SSZ payload, so the refusal is about the
        # missing --write, not bad arguments.
        manifests = run_dbtool_json(db, "asm", "manifest", "list")
        before_count = manifests["count"]
        block = manifests["entries"][0]
        commitment = f"{block['height']}:{block['blkid']}"
        ssz_file = write_ssz_file(
            run_dbtool_json(db, "asm", "manifest", "get", commitment)["ssz_hex"]
        )

        refused = [
            ("manifest", "delete", commitment),
            ("manifest", "put", "--file", ssz_file),
            ("manifest", "prune", "--after", str(block["height"])),
            ("state", "delete", commitment),
            ("manifest-mmr", "put-leaf", "0", "11" * 32),
        ]
        for args in refused:
            code, _out, err = run_dbtool(db, "asm", *args)
            assert code != 0, f"{args} was not refused without --write"
            assert "--write" in err, f"{args} refusal lacked --write hint: {err!r}"

        # The DB must be unchanged: the manifest is still there and the count holds.
        still = run_dbtool_json(db, "asm", "manifest", "get", commitment)
        assert still["found"] is True, still
        after = run_dbtool_json(db, "asm", "manifest", "list")
        assert after["count"] == before_count, (before_count, after["count"])

        return True
