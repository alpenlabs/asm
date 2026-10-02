"""Wrapper for `asm-test-cli`, which signs and broadcasts ASM transactions for the tests."""

import logging
import os
import shutil
import subprocess
from pathlib import Path

from constants import ASM_MAGIC_BYTES

logger = logging.getLogger(__name__)

EXPECTED_TARGET_PATHS = (
    "target/debug/asm-test-cli",
    "target/release/asm-test-cli",
)


def resolve_test_cli_bin() -> str:
    """Resolve the `asm-test-cli` binary path, mirroring `resolve_asm_runner_bin`."""
    env_override = os.environ.get("ASM_TEST_CLI_BIN")
    if env_override:
        return env_override

    path = shutil.which("asm-test-cli")
    if path:
        return path

    repo_root = Path(__file__).resolve().parents[2]
    for rel in EXPECTED_TARGET_PATHS:
        candidate = (repo_root / rel).as_posix()
        if os.path.exists(candidate):
            return candidate

    return "asm-test-cli"


def submit_asm_stf_update(
    bitcoind_service, admin_secret_key: str, seqno: int, predicate: str
) -> str:
    """Sign an ASM STF predicate update, broadcast it from the bitcoind wallet, and
    return the reveal txid. The caller mines it."""
    props = bitcoind_service.props
    cmd = [
        resolve_test_cli_bin(),
        "submit-asm-stf-update",
        "--btc-url",
        f"http://127.0.0.1:{props['rpc_port']}/wallet/{props['walletname']}",
        "--btc-user",
        props["rpc_user"],
        "--btc-password",
        props["rpc_password"],
        "--magic",
        ASM_MAGIC_BYTES,
        "--admin-sk",
        admin_secret_key,
        "--seqno",
        str(seqno),
        "--predicate",
        predicate,
    ]
    logger.info("Running command: %s", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, (
        f"asm-test-cli failed ({result.returncode}): {result.stderr.strip()}"
    )
    return result.stdout.strip()
