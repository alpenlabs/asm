import flexitest

from envs import BasicEnv
from utils.dbtool import (
    prepare_populated_db,
    run_dbtool,
    run_dbtool_json,
    snapshot_db,
)


def _heights(db: str) -> list[int]:
    entries = run_dbtool_json(db, "asm", "state", "list")["entries"]
    return sorted(e["height"] for e in entries)


@flexitest.register
class AsmDbtoolPruneTest(flexitest.Test):
    """prune --before / --after trim by height; both/neither are rejected."""

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env(BasicEnv())

    def main(self, ctx: flexitest.RunContext):
        source = prepare_populated_db(ctx)
        heights = _heights(source)
        assert len(heights) >= 3, f"need a few states to prune, got {heights}"
        pivot = heights[len(heights) // 2]

        # --before: entries strictly below the pivot are removed.
        db = snapshot_db(source)
        result = run_dbtool_json(db, "--write", "asm", "state", "prune", "--before", str(pivot))
        assert result["pruned"] == "before" and result["height"] == pivot, result
        remaining = _heights(db)
        assert remaining and min(remaining) >= pivot, (pivot, remaining)

        # --after: entries strictly above the pivot are removed (the pivot stays).
        db = snapshot_db(source)
        result = run_dbtool_json(db, "--write", "asm", "state", "prune", "--after", str(pivot))
        assert result["pruned"] == "after" and result["height"] == pivot, result
        remaining = _heights(db)
        assert remaining and max(remaining) <= pivot, (pivot, remaining)
        assert pivot in remaining, (pivot, remaining)

        # Exactly one bound is required: both or neither must fail.
        db = snapshot_db(source)
        for args in (
            ("--before", "1", "--after", "2"),
            (),
        ):
            code, _out, err = run_dbtool(db, "--write", "asm", "state", "prune", *args)
            assert code != 0, f"prune {args} should have been rejected"
            assert "exactly one" in err, f"prune {args} error lacked the hint: {err!r}"

        return True
