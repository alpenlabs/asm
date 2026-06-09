import logging

import flexitest

from utils.utils import (
    read_logs_since,
    snapshot_log_offsets,
    wait_until_asm_reaches_height,
    wait_until_asm_ready,
    wait_until_bitcoind_ready,
    wait_until_logs_match,
)

# Emitted once by the worker on fresh bootstrap, when it finds no persisted
# anchor state and has to construct genesis. Its absence in a post-restart log
# slice is direct evidence the runner resumed from persisted state rather than
# replaying from genesis. See `AsmWorkerServiceState::new` in
# crates/worker/src/state.rs.
GENESIS_BOOTSTRAP_MARKER = "no stored ASM state; initializing genesis anchor"

# The complementary line, logged when the worker does load a persisted anchor.
RESUME_MARKER = "ASM worker resuming from stored anchor state"


@flexitest.register
class AsmRestartTest(flexitest.Test):
    """End-to-end coverage of the runner's restart path.

    Persistence belongs at the binary level — the worker reloads from sled,
    resumes from the last persisted block, and reconnects to bitcoind.

    Two things must hold across a restart:

    1. Resume, not replay. A naive "state at height H matches" assertion would
       also hold for a fresh runner that replayed the same chain from genesis.
       To distinguish the two we read the worker log: the genesis-bootstrap
       line must not appear after the restart (and the resume line must).

    2. Catch up past the gap on startup. ZMQ only forwards blocks mined after
       the watcher subscribes, so blocks mined while the runner was down are
       never replayed. To avoid sitting idle until the next block, the watcher
       submits the current tip once on startup and the worker walks back from it
       to the persisted anchor. So we mine blocks while the runner is down and
       assert it catches up over the whole gap without any new block.
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
        pre_state = asm_rpc.strata_asm_getAnchorState(snapshot_hash)
        assert pre_state is not None, (
            f"strata_asm_getAnchorState returned None at height {snapshot_height} pre-restart"
        )

        # Mark where the post-restart slice of the log file begins. The runner
        # appends to this file across stop/start, so offsets captured now cleanly
        # partition pre- vs post-restart output.
        log_offsets = snapshot_log_offsets([log_path])

        logging.info("stopping ASM runner at height %s", pre_restart_height)
        asm_service.stop()

        # Mine while the runner is down. ZMQ won't replay these on restart (it
        # only forwards blocks mined after subscription), so catching up to them
        # exercises the startup tip-submit and the worker's walk-back, not the
        # steady-state path.
        gap_blocks = 2
        bitcoin_rpc.proxy.generatetoaddress(gap_blocks, wallet_addr)
        post_restart_target = pre_restart_height + gap_blocks

        logging.info("restarting ASM runner")
        asm_service.start()
        asm_rpc = asm_service.create_rpc()
        wait_until_asm_ready(asm_rpc)

        # The runner must reach the gap mined while it was down *without* any new
        # block being mined: on startup the watcher submits the current tip once
        # and the worker walks back from it to the persisted anchor. Before this,
        # the runner sat idle until the next live block arrived — the regression
        # this guards against.
        caught_up_height = wait_until_asm_reaches_height(asm_rpc, min_height=post_restart_target)
        logging.info("ASM caught up past restart to height %s", caught_up_height)

        # Resume vs replay. The worker logs exactly one of two mutually
        # exclusive lines at startup: the resume line when it loads a persisted
        # anchor, or the genesis-bootstrap line when it can't. Both are emitted
        # before the RPC comes up, so they're already in the post-restart slice
        # by now; wait_until_logs_match just reuses the shared offset-scanning
        # matcher rather than re-rolling the file read.
        wait_until_logs_match(
            log_offsets,
            lambda line: RESUME_MARKER in line,
            error_msg=f"runner did not emit {RESUME_MARKER!r} after restart",
        )

        # And assert the genesis-bootstrap line is absent from the same slice —
        # its presence would mean the runner threw away persisted state and
        # rebuilt from scratch, exactly the failure mode the test guards against.
        # Absence can't be expressed as a wait, so read the slice and check.
        post_log = read_logs_since(log_offsets)
        assert GENESIS_BOOTSTRAP_MARKER not in post_log, (
            f"runner re-emitted {GENESIS_BOOTSTRAP_MARKER!r} after restart — "
            "it restarted from genesis instead of resuming from persisted state"
        )

        # Sanity: state for a pre-restart block is still queryable and identical
        # post-restart. Weaker than the log check on its own (a fresh replay
        # would produce the same payload on the same chain), but catches
        # durability regressions where the data is gone entirely.
        post_state = asm_rpc.strata_asm_getAnchorState(snapshot_hash)
        assert post_state == pre_state, (
            f"AnchorState at height {snapshot_height} changed across restart: "
            f"pre={pre_state!r} post={post_state!r}"
        )

        return True
