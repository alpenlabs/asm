"""Environment for the ASM fork-upgrade functional test.

The chain starts under *pre-fork* rules: the worker's base schedule never
activates fork1 (which gates unstake), and the genesis ASM predicate belongs
to the pre-fork proving artifact. The prover is configured with both the pre-
and post-fork artifacts. The admin ASM VK upgrade carries the raw id of the
fork the new artifact implements, so enacting the upgrade to the post-fork
predicate activates the fork one block later — no per-worker trigger config.
"""

import json
import os
from pathlib import Path

from factory.asm_rpc.config_cfg import (
    BackendConfig,
    NativeAsmEntry,
    NativeBackend,
    Sp1Backend,
)
from factory.common.asm_params import FORK_NEVER
from utils.txgen import derive_predicate, derive_pubkey

from .prover_env import NATIVE_TEST_MOHO_SIGNING_KEY, ProverEnv, elfs_dir

# Signing key of the pre-fork (genesis) native ASM artifact.
NATIVE_OLD_ASM_SIGNING_KEY = "01" * 32

# Signing key of the post-fork native ASM artifact.
NATIVE_NEW_ASM_SIGNING_KEY = "03" * 32

# Secrets behind the admin roles and the bridge operator set. Tests sign the
# VK-update action with the first (threshold-1 multisig) and unstakes with the
# full set (N/N musig2) via asm-txgen. Both are chosen so their public keys
# have even parity: the params key types (`EvenPublicKey`) reject odd-parity
# keys, and BIP-137 signature recovery must reproduce the configured key
# exactly. Two operators so an unstake leaves the multisig non-empty (the
# bridge treats an emptied operator set as a fatal invariant violation).
TEST_SECRET_KEYS = ["07" * 32, "09" * 32]

# Short activation delay so the upgrade enacts within a few mined blocks.
CONFIRMATION_DEPTH = 3

# Raw id of the fork the upgrade activates (`ForkId::Fork1`), carried in the
# VK-update action asm-txgen signs.
FORK1_ID = 0


def new_asm_predicate() -> str:
    """Predicate string of the post-fork ASM artifact for the active backend.

    Native: derived from the post-fork signing key. SP1: read from the vk
    JSON the guest build emits next to `asm.elf` (build-derived, cannot be
    hardcoded).
    """
    backend = os.environ.get("ASM_PROVER_BACKEND", "native")
    if backend == "sp1":
        vk_json = Path(elfs_dir()) / "asm-vk.json"
        return json.loads(vk_json.read_text())
    return derive_predicate(NATIVE_NEW_ASM_SIGNING_KEY)


class ForkUpgradeEnv(ProverEnv):
    """Prover environment starting under pre-fork rules with both artifacts."""

    def _backend_config_override(self) -> BackendConfig:
        backend = os.environ.get("ASM_PROVER_BACKEND", "native")
        if backend == "sp1":
            return Sp1Backend(
                asm_elf_paths=[
                    str(elfs_dir() / "asm-pre-unstake.elf"),
                    str(elfs_dir() / "asm.elf"),
                ],
                moho_elf_path=str(elfs_dir() / "moho.elf"),
            )
        return NativeBackend(
            asm_entries=[
                NativeAsmEntry(
                    schnorr_signing_key=NATIVE_OLD_ASM_SIGNING_KEY,
                    stf_params={"forks": {"fork1": FORK_NEVER}},
                ),
                NativeAsmEntry(
                    schnorr_signing_key=NATIVE_NEW_ASM_SIGNING_KEY,
                    stf_params={"forks": {"fork1": 0}},
                ),
            ],
            moho_schnorr_signing_key=NATIVE_TEST_MOHO_SIGNING_KEY,
        )

    def _asm_params_overrides(self) -> dict:
        return {
            # Every multisig role and the bridge operator set use the test
            # secrets' real compressed pubkeys, so asm-txgen's signatures match.
            "musig2_keys": [derive_pubkey(key) for key in TEST_SECRET_KEYS],
            "confirmation_depth": CONFIRMATION_DEPTH,
            # Pre-fork chain: fork1 never activates until an upgrade enacts it.
            "fork1_height": FORK_NEVER,
        }
