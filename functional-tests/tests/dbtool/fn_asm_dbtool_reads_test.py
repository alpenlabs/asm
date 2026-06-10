import logging

import flexitest

from envs import BasicEnv
from utils.dbtool import prepare_populated_db, run_dbtool_json


@flexitest.register
class AsmDbtoolReadsTest(flexitest.Test):
    """Read verbs return the history the runner persisted, across every resource."""

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env(BasicEnv())

    def main(self, ctx: flexitest.RunContext):
        db = prepare_populated_db(ctx)

        # state: list / latest / get (found) / get (missing).
        states = run_dbtool_json(db, "asm", "state", "list")
        assert states["count"] > 0, f"expected anchor states, got {states}"
        logging.info("state list reports %d entries", states["count"])

        latest = run_dbtool_json(db, "asm", "state", "latest")
        assert latest["found"] is True and latest["ssz_hex"], latest

        # The printed `commitment` field must feed straight back into `get`.
        block = states["entries"][0]
        commitment = block["commitment"]
        assert commitment == f"{block['height']}:{block['blkid']}", block
        got = run_dbtool_json(db, "asm", "state", "get", commitment)
        assert got["found"] is True and got["ssz_hex"], got

        missing = run_dbtool_json(db, "asm", "state", "get", f"999999:{'00' * 32}")
        assert missing["found"] is False, missing

        # aux: list always works; the runner may or may not have written entries.
        aux = run_dbtool_json(db, "asm", "aux", "list")
        assert aux["count"] >= 0, aux
        aux_missing = run_dbtool_json(db, "asm", "aux", "get", f"999999:{'00' * 32}")
        assert aux_missing["found"] is False, aux_missing

        # manifest: list / get (found) / get (missing).
        manifests = run_dbtool_json(db, "asm", "manifest", "list")
        assert manifests["count"] > 0, manifests
        m_block = manifests["entries"][0]
        m_commitment = f"{m_block['height']}:{m_block['blkid']}"
        m_got = run_dbtool_json(db, "asm", "manifest", "get", m_commitment)
        assert m_got["found"] is True and m_got["ssz_hex"], m_got
        assert "logs" in m_got, m_got
        m_missing = run_dbtool_json(db, "asm", "manifest", "get", f"999999:{'00' * 32}")
        assert m_missing["found"] is False, m_missing

        # manifest-mmr: count / leaf (found + missing) / proof (default + explicit --at).
        count = run_dbtool_json(db, "asm", "manifest-mmr", "count")
        leaf_count = count["leaf_count"]
        assert leaf_count > 0, count
        logging.info("manifest-mmr reports %d leaves", leaf_count)

        leaf = run_dbtool_json(db, "asm", "manifest-mmr", "leaf", "0")
        assert leaf["found"] is True and leaf["hash"], leaf
        leaf_missing = run_dbtool_json(db, "asm", "manifest-mmr", "leaf", str(leaf_count + 1000))
        assert leaf_missing["found"] is False, leaf_missing

        proof = run_dbtool_json(db, "asm", "manifest-mmr", "proof", "0")
        assert proof["proof_ssz_hex"], proof
        proof_at = run_dbtool_json(db, "asm", "manifest-mmr", "proof", "0", "--at", str(leaf_count))
        assert proof_at["at_leaf_count"] == leaf_count, proof_at

        return True
