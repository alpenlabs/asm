"""Wrapper for `asm-admin`, which signs ASM admin actions and submits them to bitcoind."""

import json
import logging
import os
import shutil
import subprocess
from pathlib import Path

from constants import ASM_MAGIC_BYTES
from factory.common.asm_params import p2wpkh_address

logger = logging.getLogger(__name__)

EXPECTED_TARGET_PATHS = (
    "target/debug/asm-admin",
    "target/release/asm-admin",
)

# Admin signatures bind the network, and the test chain runs on regtest.
NETWORK = "regtest"


def resolve_admin_cli_bin() -> str:
    """Resolve the `asm-admin` binary path, mirroring `resolve_asm_runner_bin`."""
    env_override = os.environ.get("ASM_ADMIN_BIN")
    if env_override:
        return env_override

    path = shutil.which("asm-admin")
    if path:
        return path

    repo_root = Path(__file__).resolve().parents[2]
    for rel in EXPECTED_TARGET_PATHS:
        candidate = (repo_root / rel).as_posix()
        if os.path.exists(candidate):
            return candidate

    return "asm-admin"


def submit_asm_stf_update(
    bitcoind_service, admin_secret_key: str, seqno: int, predicate: str
) -> str:
    """Sign an ASM STF predicate update, broadcast it from the bitcoind wallet, and
    return the reveal txid. The caller mines it."""
    return _submit_admin_action(
        bitcoind_service,
        admin_secret_key,
        seqno,
        ["asm-stf-vk", "--predicate", predicate],
    )


def submit_safe_harbor_update(
    bitcoind_service, admin_secret_key: str, seqno: int, address: str
) -> str:
    """Sign a safe harbor rotation to the P2TR `address`, broadcast it from the bitcoind
    wallet, and return the reveal txid. The caller mines it."""
    return _submit_admin_action(
        bitcoind_service,
        admin_secret_key,
        seqno,
        ["safe-harbor", "--address", address],
    )


def _submit_admin_action(
    bitcoind_service,
    admin_secret_key: str,
    seqno: int,
    action: list[str],
) -> str:
    """Sign as the role's only signer, then submit as the coordinator would."""
    binary = resolve_admin_cli_bin()
    signature = _run(
        [binary, "sign", "--network", NETWORK, "--seq-no", str(seqno), *action],
        {"STRATA_ADMIN_KEY": admin_secret_key},
    )

    props = bitcoind_service.props
    submit = [
        binary,
        "submit",
        "--network",
        NETWORK,
        "--magic",
        ASM_MAGIC_BYTES,
        "--threshold",
        "1",
        "--signer",
        p2wpkh_address(admin_secret_key, NETWORK),
        "--seq-no",
        str(seqno),
        "--signature",
        f"0:{signature}",
        "--btc-url",
        f"http://127.0.0.1:{props['rpc_port']}/wallet/{props['walletname']}",
        "--fee-rate",
        "2",
        *action,
    ]
    output = _run(
        submit,
        {"BTC_RPC_USER": props["rpc_user"], "BTC_RPC_PASSWORD": props["rpc_password"]},
    )
    return json.loads(output)["reveal_txid"]


def _run(cmd: list[str], env: dict[str, str]) -> str:
    logger.info("Running command: %s", " ".join(cmd))
    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=60, env={**os.environ, **env}
    )
    assert result.returncode == 0, (
        f"asm-admin failed ({result.returncode}): {result.stderr.strip()}"
    )
    return result.stdout.strip()
