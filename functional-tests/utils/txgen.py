"""Helpers for shelling out to the `asm-txgen` test-support CLI.

The binary is built by `run_test.sh` and resolved via `PATH`. It crafts and
submits the protocol transactions (multisig-signed admin actions, musig2-signed
unstakes) that can only be built with the workspace's Rust crates; tests mine
the results themselves.
"""

import logging
import subprocess


def run_txgen(
    *args: str, rpc_url: str | None = None, rpc_auth: tuple[str, str] | None = None
) -> str:
    """Run `asm-txgen` with the given subcommand args and return its stdout."""
    cmd = ["asm-txgen"]
    if rpc_url is not None:
        cmd += ["--rpc-url", rpc_url]
    if rpc_auth is not None:
        cmd += ["--rpc-user", rpc_auth[0], "--rpc-password", rpc_auth[1]]
    cmd += list(args)
    logging.debug("running %s", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"asm-txgen failed ({result.returncode}): {result.stderr.strip()}")
    return result.stdout.strip()


def derive_predicate(schnorr_key: str) -> str:
    """Predicate string of a native proving host with this signing key."""
    return run_txgen("derive-predicate", "--schnorr-key", schnorr_key)


def derive_pubkey(secret_key: str) -> str:
    """Compressed secp256k1 public key (hex) of a secret key."""
    return run_txgen("derive-pubkey", "--secret-key", secret_key)
