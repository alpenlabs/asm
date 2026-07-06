import flexitest

from envs import BasicEnv
from utils.dbtool import prepare_populated_db, run_dbtool_json


@flexitest.register
class AsmDbtoolForkActivationTest(flexitest.Test):
    """fork-activation put derives the activation height; prune --after rolls back."""

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env(BasicEnv())

    def main(self, ctx: flexitest.RunContext):
        db = prepare_populated_db(ctx)

        # BasicEnv never enacts an upgrade, so the tree starts empty.
        listed = run_dbtool_json(db, "asm", "fork-activation", "list")
        assert listed == {"count": 0, "entries": []}, listed

        predicate = "Bip340Schnorr:" + "07" * 32
        result = run_dbtool_json(
            db, "--write", "asm", "fork-activation", "put", "42", "fork1", predicate
        )
        expected = {
            "enacting_height": 42,
            "fork": "fork1",
            "new_predicate": predicate,
            "activation_height": 43,
        }
        assert result == {"stored": True, "activation": expected}, result

        listed = run_dbtool_json(db, "asm", "fork-activation", "list")
        assert listed == {"count": 1, "entries": [expected]}, listed

        # Pruning after the enacting height keeps the activation ...
        run_dbtool_json(db, "--write", "asm", "fork-activation", "prune", "--after", "42")
        listed = run_dbtool_json(db, "asm", "fork-activation", "list")
        assert listed["count"] == 1, listed

        # ... and pruning below it rolls the activation back out.
        result = run_dbtool_json(db, "--write", "asm", "fork-activation", "prune", "--after", "41")
        assert result == {"pruned": "after", "height": 41}, result
        listed = run_dbtool_json(db, "asm", "fork-activation", "list")
        assert listed == {"count": 0, "entries": []}, listed

        return True
