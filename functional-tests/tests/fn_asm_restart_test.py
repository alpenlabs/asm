import logging
import os

import flexitest

from utils.utils import (
    wait_until_asm_reaches_height,
    wait_until_asm_ready,
    wait_until_bitcoind_ready,
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

    2. Catch up past the gap. The block watcher does no backfilling of its own —
       it only submits blocks it sees live over ZMQ, and ZMQ does not replay
       blocks mined while the runner was down. The worker fills that gap by
       walking back from the next live block to the persisted anchor. So we mine
       blocks while the runner is down, then mine one more once it is back up to
       trigger the walk-back, and assert it catches up over the whole gap.
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
        # appends to this file across stop/start, so a byte offset captured now
        # cleanly partitions pre- vs post-restart output.
        log_offset = os.path.getsize(log_path)

        logging.info("stopping ASM runner at height %s", pre_restart_height)
        asm_service.stop()

        # Mine while the runner is down so it must catch up over a gap on
        # restart. These blocks are never delivered over ZMQ (which only
        # forwards blocks mined after subscription), so they exercise the
        # worker's walk-back, not the steady-state path.
        gap_blocks = 2
        bitcoin_rpc.proxy.generatetoaddress(gap_blocks, wallet_addr)

        logging.info("restarting ASM runner")
        asm_service.start()
        asm_rpc = asm_service.create_rpc()
        wait_until_asm_ready(asm_rpc)

        # Mine one live block to trigger the worker's walk-back to the persisted
        # anchor, which fills the gap mined while down. Retry to absorb the brief
        # window between RPC readiness and ZMQ (re)subscription, during which a
        # lone trigger block could be missed; each retry mines a fresh block.
        caught_up_height = None
        for attempt in range(5):
            bitcoin_rpc.proxy.generatetoaddress(1, wallet_addr)
            tip = bitcoin_rpc.proxy.getblockcount()
            try:
                caught_up_height = wait_until_asm_reaches_height(
                    asm_rpc, min_height=tip, timeout=15
                )
                break
            except TimeoutError:
                logging.info("trigger block not yet observed (attempt %s); retrying", attempt + 1)
        assert caught_up_height is not None, (
            "runner did not catch up to the chain tip after restart"
        )
        assert caught_up_height > pre_restart_height + gap_blocks, (
            f"runner caught up to {caught_up_height}, expected past the "
            f"{gap_blocks}-block gap above {pre_restart_height}"
        )
        logging.info("ASM caught up past restart to height %s", caught_up_height)

        # Resume vs replay: the genesis-bootstrap line only fires when the worker
        # can't load a persisted anchor. If the post-restart log slice contains
        # it, the runner threw away persisted state and rebuilt from scratch —
        # exactly the failure mode the test is for. The resume line must appear
        # in its place.
        with open(log_path, "rb") as f:
            f.seek(log_offset)
            post_log = f.read().decode("utf-8", errors="replace")
        assert GENESIS_BOOTSTRAP_MARKER not in post_log, (
            f"runner re-emitted {GENESIS_BOOTSTRAP_MARKER!r} after restart — "
            "it restarted from genesis instead of resuming from persisted state"
        )
        assert RESUME_MARKER in post_log, (
            f"runner did not emit {RESUME_MARKER!r} after restart — "
            "expected it to resume from persisted state"
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
