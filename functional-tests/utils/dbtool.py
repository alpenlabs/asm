"""Helpers for the `dbtool` functional tests.

`dbtool` inspects the runner's storage sled DB; sled takes an exclusive lock on
the directory, so the runner must be stopped before the binary can open it.
"""

import json
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from utils.utils import (
    wait_until_asm_reaches_height,
    wait_until_asm_ready,
    wait_until_bitcoind_ready,
)

logger = logging.getLogger(__name__)

EXPECTED_TARGET_PATHS = (
    "target/debug/dbtool",
    "target/release/dbtool",
)


def resolve_dbtool_bin() -> str:
    """Resolve the `dbtool` binary path, mirroring `resolve_asm_runner_bin`."""
    env_override = os.environ.get("ASM_DBTOOL_BIN")
    if env_override:
        return env_override

    path = shutil.which("dbtool")
    if path:
        return path

    repo_root = Path(__file__).resolve().parents[2]
    for rel in EXPECTED_TARGET_PATHS:
        candidate = (repo_root / rel).as_posix()
        if os.path.exists(candidate):
            return candidate

    return "dbtool"


def run_dbtool_raw(*args: str, timeout: int = 30) -> tuple[int, str, str]:
    """Run `dbtool <args...>` verbatim (no --db injected) and return (code, out, err)."""
    cmd = [resolve_dbtool_bin(), *args]
    logger.info("Running command: %s", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if result.returncode != 0 and result.stderr:
        logger.info("Stderr: %s", result.stderr.strip())
    return result.returncode, result.stdout, result.stderr


def run_dbtool(db_path: str, *args: str, timeout: int = 30) -> tuple[int, str, str]:
    """Run `dbtool --db <db_path> <args...>` and return (code, stdout, stderr)."""
    return run_dbtool_raw("--db", db_path, *args, timeout=timeout)


def run_dbtool_json(db_path: str, *args: str, timeout: int = 30) -> dict:
    """Run `dbtool`, assert it succeeded, and decode its JSON stdout."""
    code, stdout, stderr = run_dbtool(db_path, *args, timeout=timeout)
    assert code == 0, f"dbtool {args} failed ({code}): {stderr.strip()}"
    return json.loads(stdout)


def prepare_populated_db(ctx, num_blocks: int = 6) -> str:
    """Drive the runner over `num_blocks` L1 blocks, stop it, and return its DB path.

    Stopping the runner releases sled's exclusive lock so `dbtool` can open the
    directory the runner just wrote.
    """
    bitcoind_service = ctx.get_service("bitcoin")
    asm_service = ctx.get_service("asm_rpc")

    bitcoin_rpc = bitcoind_service.create_rpc()
    asm_rpc = asm_service.create_rpc()

    wait_until_bitcoind_ready(bitcoin_rpc, timeout=30)
    wait_until_asm_ready(asm_rpc)

    start_height = bitcoin_rpc.proxy.getblockcount()
    wallet_addr = bitcoin_rpc.proxy.getnewaddress()
    bitcoin_rpc.proxy.generatetoaddress(num_blocks, wallet_addr)
    wait_until_asm_reaches_height(asm_rpc, min_height=start_height + num_blocks)

    db_path = asm_service.props["db_path"]
    asm_service.stop()
    logging.info("runner stopped; storage DB at %s", db_path)
    return db_path


def snapshot_db(db_path: str) -> str:
    """Copy a stopped sled DB to a fresh temp dir so destructive verbs are isolated."""
    dst = os.path.join(tempfile.mkdtemp(prefix="dbtool-snap-"), "db")
    shutil.copytree(db_path, dst)
    return dst


def proof_db_path(db_path: str) -> str:
    """The proof DB path beside a storage `db_path`.

    The runner opens the storage DB at `<envdd>/asm_rpc/db` and the proof DB at
    `<envdd>/asm_rpc/proof_db` (see `ProverEnv._orchestrator_config`), so the
    proof DB is the storage DB's sibling. Only populated under the `prover` env.
    """
    return os.path.join(os.path.dirname(db_path), "proof_db")


def write_ssz_file(ssz_hex: str) -> str:
    """Decode an `ssz_hex` field to raw bytes in a temp file `put --file` can read."""
    fd, path = tempfile.mkstemp(suffix=".ssz")
    with os.fdopen(fd, "wb") as f:
        f.write(bytes.fromhex(ssz_hex))
    return path
