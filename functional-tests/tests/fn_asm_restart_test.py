import logging
import os

import flexitest

from utils.utils import (
    wait_until_asm_reaches_height,
    wait_until_asm_ready,
    wait_until_bitcoind_ready,
)

# Emitted by the worker only on first-bootstrap, gated on
# `!ctx.has_l1_manifest(pivot_block.blkid())` — so its absence in a post-restart
# log slice is direct evidence that the runner resumed from persisted state
# rather than replaying from genesis. See crates/worker/src/service.rs.
GENESIS_BOOTSTRAP_MARKER = "Created genesis manifest"


@flexitest.register
class AsmRestartTest(flexitest.Test):
    """End-to-end coverage of the runner's restart path.

    Persistence belongs at the binary level — the worker reloads from sled,
    resumes from the last persisted block, and reconnects to bitcoind. Unit
    tests in `asm-storage` only exercise sled's own durability, which sled
    already covers.

    A naive "state at height H matches" assertion would also hold for a fresh
    runner that just replayed the same chain from genesis. To distinguish
    resume from replay, we read the worker log: the genesis-bootstrap line
    must not appear after the restart.
    """

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env("basic")

    def main(self, ctx: flexitest.RunContext):
        bitcoind_service = ctx.get_service("bitcoin")
        asm_service = ctx.get_service("asm_rpc")
        log_path = asm_service.props["log_path"]

        bitcoin_rpc = bitcoind_service.create_rpc()
        asm_rpc = asm_service.create_rpc()

        wait_until_bitcoind_ready(bitcoin_rpc, timeout=30)
        wait_until_asm_ready(asm_rpc)

        # Drive ASM to a known height before restarting.
        initial_btc_height = bitcoin_rpc.proxy.getblockcount()
        wallet_addr = bitcoin_rpc.proxy.getnewaddress()
        pre_blocks = 3
        bitcoin_rpc.proxy.generatetoaddress(pre_blocks, wallet_addr)
        pre_restart_height = initial_btc_height + pre_blocks
        wait_until_asm_reaches_height(asm_rpc, min_height=pre_restart_height)

        # Snapshot a processed block we expect to survive the restart.
        snapshot_height = initial_btc_height + 1
        snapshot_hash = bitcoin_rpc.proxy.getblockhash(snapshot_height)
        pre_state = asm_rpc.strata_asm_getAsmState(snapshot_hash)
        assert pre_state is not None, (
            f"strata_asm_getAsmState returned None at height {snapshot_height} pre-restart"
        )

        # Mark where the post-restart slice of the log file begins. The runner
        # appends to this file across stop/start, so a byte offset captured now
        # cleanly partitions pre- vs post-restart output.
        log_offset = os.path.getsize(log_path)

        logging.info("stopping ASM runner at height %s", pre_restart_height)
        asm_service.stop()

        # Mine while the runner is down so it has to catch up on restart —
        # exercises the watcher's gap-fill path, not just steady state.
        catchup_blocks = 2
        bitcoin_rpc.proxy.generatetoaddress(catchup_blocks, wallet_addr)
        post_restart_target = pre_restart_height + catchup_blocks

        logging.info("restarting ASM runner")
        asm_service.start()
        asm_rpc = asm_service.create_rpc()
        wait_until_asm_ready(asm_rpc)
        wait_until_asm_reaches_height(asm_rpc, min_height=post_restart_target)
        logging.info("ASM caught up past restart to height %s", post_restart_target)

        # Resume vs replay: the genesis-bootstrap line only fires when the
        # worker can't find an existing genesis manifest. If the post-restart
        # log slice contains it, the runner threw away persisted state and
        # rebuilt from scratch — exactly the failure mode the test is for.
        with open(log_path, "rb") as f:
            f.seek(log_offset)
            post_log = f.read().decode("utf-8", errors="replace")
        assert GENESIS_BOOTSTRAP_MARKER not in post_log, (
            f"runner re-emitted {GENESIS_BOOTSTRAP_MARKER!r} after restart — "
            "it restarted from genesis instead of resuming from persisted state"
        )

        # Sanity: state for a pre-restart block is still queryable and
        # identical post-restart. Weaker than the log check on its own (a
        # fresh replay would produce the same payload on the same chain), but
        # catches durability regressions where the data is gone entirely.
        post_state = asm_rpc.strata_asm_getAsmState(snapshot_hash)
        assert post_state == pre_state, (
            f"AsmState at height {snapshot_height} changed across restart: "
            f"pre={pre_state!r} post={post_state!r}"
        )

        return True
