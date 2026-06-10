import flexitest

from envs import BasicEnv
from utils.dbtool import prepare_populated_db, run_dbtool, run_dbtool_raw


@flexitest.register
class AsmDbtoolInvalidInputTest(flexitest.Test):
    """The binary fails loudly on a bad --db path, a missing --db, and bad args."""

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env(BasicEnv())

    def main(self, ctx: flexitest.RunContext):
        db = prepare_populated_db(ctx)

        # A mistyped --db must not silently open an empty DB.
        code, _out, err = run_dbtool(db + "-typo", "asm", "state", "list")
        assert code != 0 and "existing directory" in err, err

        # --db is required for asm commands.
        code, _out, err = run_dbtool_raw("asm", "state", "list")
        assert code != 0 and "required" in err, err

        # Malformed commitments are rejected (DB opens, parsing then fails).
        for bad in ("nocolon", "notanumber:" + "00" * 32, "100:" + "zz" * 32, "100:00"):
            code, _out, err = run_dbtool(db, "asm", "manifest", "get", bad)
            assert code != 0, f"commitment {bad!r} was accepted"

        # A malformed leaf hash is rejected even with --write (parse precedes write).
        for bad in ("zz", "11" * 5):
            code, _out, err = run_dbtool(db, "--write", "asm", "manifest-mmr", "put-leaf", "0", bad)
            assert code != 0, f"hash {bad!r} was accepted"

        # The all-zero hash is the MMR's empty-peak sentinel, not a storable leaf.
        zero = "00" * 32
        code, _out, err = run_dbtool(db, "--write", "asm", "manifest-mmr", "put-leaf", "0", zero)
        assert code != 0 and "sentinel" in err, err

        return True
