"""End-to-end ASM fork upgrade: worker rule switch + prover artifact switch.

The chain starts under pre-fork rules with the pre-fork artifact's predicate
as the genesis ASM VK (see `ForkUpgradeEnv`). The test drives the full upgrade
choreography:

1. Pre-fork, proofs flow (the pre-fork artifact proves) and a genuine unstake
   is ignored — the operator stays.
2. An admin ASM VK upgrade to the post-fork artifact's predicate is submitted
   and mined to enactment.
3. Proofs continue past the boundary. This is the rigorous assertion of the
   switch: the Moho recursion Merkle-checks the step predicate against the
   parent state's `next_predicate` and verifies the step proof under it, so a
   post-boundary Moho proof exists only if the prover switched artifacts.
4. The same kind of unstake now removes the operator — the worker's rules
   flipped at the same height the proving side did.

Runs under both backends via `ASM_PROVER_BACKEND` (native by default; sp1
mirrors the manual `fn_asm_proof_test` workflow).
"""

import logging

import flexitest

from envs.fork_upgrade_env import (
    CONFIRMATION_DEPTH,
    FORK1_ID,
    TEST_SECRET_KEYS,
    new_asm_predicate,
)
from utils.txgen import run_txgen
from utils.utils import (
    wait_until_asm_proof_exists,
    wait_until_asm_reaches_height,
    wait_until_asm_ready,
    wait_until_bitcoind_ready,
    wait_until_moho_proof_exists,
)


@flexitest.register
class AsmForkUpgradeTest(flexitest.Test):
    """Fork-gated unstake across an admin-driven ASM VK upgrade."""

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env("fork_upgrade")

    def main(self, ctx: flexitest.RunContext):
        bitcoind_service = ctx.get_service("bitcoin")
        asm_service = ctx.get_service("asm_rpc")

        bitcoin_rpc = bitcoind_service.create_rpc()
        asm_rpc = asm_service.create_rpc()

        rpc_port = bitcoind_service.get_prop("rpc_port")
        txgen_rpc = {
            "rpc_url": f"http://127.0.0.1:{rpc_port}",
            "rpc_auth": (
                bitcoind_service.get_prop("rpc_user"),
                bitcoind_service.get_prop("rpc_password"),
            ),
        }

        wait_until_bitcoind_ready(bitcoin_rpc, timeout=30)
        wait_until_asm_ready(asm_rpc)
        wallet_addr = bitcoin_rpc.proxy.getnewaddress()

        def mine(n: int) -> int:
            bitcoin_rpc.proxy.generatetoaddress(n, wallet_addr)
            height = bitcoin_rpc.proxy.getblockcount()
            wait_until_asm_reaches_height(asm_rpc, min_height=height)
            return height

        def operators_at_tip() -> list[int]:
            tip_hash = bitcoin_rpc.proxy.getbestblockhash()
            return asm_rpc.strata_asm_getOperators(tip_hash)

        def wait_proofs_at(height: int):
            block_hash = bitcoin_rpc.proxy.getblockhash(height)
            wait_until_asm_proof_exists(asm_rpc, block_hash)
            wait_until_moho_proof_exists(asm_rpc, block_hash)

        unstake_args = ["submit-unstake", "--operator-idx", "0"]
        for key in TEST_SECRET_KEYS:
            unstake_args += ["--operator-key", key]

        # 1. Pre-fork: proofs flow under the pre-fork artifact.
        height = mine(2)
        wait_proofs_at(height)
        logging.info("pre-fork proofs verified at height %s", height)

        assert operators_at_tip() == [0, 1], "both operators must start active"

        # 2. Pre-fork: a genuine unstake is ignored.
        run_txgen(*unstake_args, **txgen_rpc)
        height = mine(1)
        assert operators_at_tip() == [0, 1], "unstake must be ignored before the fork"
        logging.info("pre-fork unstake correctly ignored at height %s", height)

        # 3. Submit the ASM VK upgrade and mine it to enactment.
        new_predicate = new_asm_predicate()
        run_txgen(
            "submit-vk-update",
            "--new-predicate",
            new_predicate,
            "--fork-id",
            str(FORK1_ID),
            "--signer-key",
            TEST_SECRET_KEYS[0],
            "--seqno",
            "1",
            **txgen_rpc,
        )
        submission_height = mine(1)
        enactment_height = mine(CONFIRMATION_DEPTH)
        assert enactment_height == submission_height + CONFIRMATION_DEPTH
        logging.info(
            "VK upgrade submitted at %s, enacted at %s",
            submission_height,
            enactment_height,
        )

        # 4. Proofs continue past the boundary: possible only if the prover
        # switched to the post-fork artifact and the recursion accepted the
        # predicate handover.
        post_boundary = mine(1)
        wait_proofs_at(post_boundary)
        logging.info("post-boundary proofs verified at height %s", post_boundary)

        # 5. Post-fork: the same kind of unstake removes the operator.
        run_txgen(*unstake_args, **txgen_rpc)
        height = mine(1)
        assert operators_at_tip() == [1], "unstake must be processed after the fork"
        logging.info("post-fork unstake removed operator 0 at height %s", height)

        # 6. And the chain keeps proving under post-fork rules.
        final_height = mine(1)
        wait_proofs_at(final_height)
        logging.info("proofs verified at final height %s", final_height)

        return True
