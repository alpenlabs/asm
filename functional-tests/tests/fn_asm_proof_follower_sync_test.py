import logging

import flexitest

from envs.follower_env import FOLLOWER_SERVICE_NAME
from utils.utils import (
    read_logs_since,
    snapshot_log_offsets,
    wait_until_asm_reaches_height,
    wait_until_asm_ready,
    wait_until_bitcoind_ready,
    wait_until_logs_match,
    wait_until_moho_proof_exists,
)

# Logged by the scheduler when it submits a proving job to the backend — the
# local-generation path. Its absence from the follower's log while proofs
# appear is the evidence the proofs were fetched, not generated.
SUBMIT_MARKER = "proof submitted to remote prover"

# Logged by the follower for every proof persisted from the peer.
FETCH_MARKER = "proof fetched from peer"

# Logged when the follower gives up on the peer and schedules local proving.
FALLBACK_MARKER = "falling back to local proof generation"


@flexitest.register
class AsmProofFollowerSyncTest(flexitest.Test):
    """A follower asm-runner syncs proofs from its peer instead of proving.

    Phase 1 (sync): both runners track the same bitcoind, but only the
    generator proves. The follower must end up serving the same ASM and Moho
    proofs without ever submitting a local proving job.

    Phase 2 (fallback): stop the generator and mine more blocks. After the
    configured number of failed status probes the follower must switch to
    local proving and keep its last proven block advancing on its own.
    """

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env("follower")

    def main(self, ctx: flexitest.RunContext):
        bitcoind_service = ctx.get_service("bitcoin")
        generator_service = ctx.get_service("asm_rpc")
        follower_service = ctx.get_service(FOLLOWER_SERVICE_NAME)

        bitcoin_rpc = bitcoind_service.create_rpc()
        generator_rpc = generator_service.create_rpc()
        follower_rpc = follower_service.create_rpc()
        follower_log = follower_service.props["log_path"]

        wait_until_bitcoind_ready(bitcoin_rpc, timeout=30)
        wait_until_asm_ready(generator_rpc)
        wait_until_asm_ready(follower_rpc)

        # Snapshot only after the generator's RPC is confirmed up: from this
        # point on, follower status probes succeed, so the unavailability
        # fallback cannot fire and any local submission in the slice below is
        # a genuine bug. (During startup the follower may race the generator's
        # RPC coming up; that window is deliberately excluded.)
        log_offsets = snapshot_log_offsets([follower_log])

        # Phase 1: mine, then wait for the proofs to appear on the *follower*.
        initial_btc_height = bitcoin_rpc.proxy.getblockcount()
        wallet_addr = bitcoin_rpc.proxy.getnewaddress()
        num_blocks = 3
        logging.info("generating %s blocks", num_blocks)
        bitcoin_rpc.proxy.generatetoaddress(num_blocks, wallet_addr)

        target_height = initial_btc_height + num_blocks
        wait_until_asm_reaches_height(follower_rpc, min_height=target_height)
        target_hash = bitcoin_rpc.proxy.getblockhash(target_height)

        logging.info("waiting for follower to sync Moho proof at height %s", target_height)
        wait_until_moho_proof_exists(follower_rpc, target_hash)
        assert follower_rpc.strata_asm_getAsmProof(target_hash) is not None, (
            "follower should serve the ASM proof it synced from the generator"
        )

        # The proofs must have been fetched from the peer, never proven here.
        wait_until_logs_match(
            log_offsets,
            lambda line: FETCH_MARKER in line,
            error_msg=f"follower never logged {FETCH_MARKER!r}",
        )
        sync_log = read_logs_since(log_offsets)
        assert SUBMIT_MARKER not in sync_log, (
            "follower submitted a local proving job while its peer was healthy"
        )
        logging.info("follower synced proofs without local proving")

        # Phase 2: kill the generator; the follower must notice and fall back
        # to proving locally.
        fallback_offsets = snapshot_log_offsets([follower_log])
        logging.info("stopping generator to force follower fallback")
        generator_service.stop()

        gap_blocks = 2
        bitcoin_rpc.proxy.generatetoaddress(gap_blocks, wallet_addr)
        fallback_height = target_height + gap_blocks
        wait_until_asm_reaches_height(follower_rpc, min_height=fallback_height)
        fallback_hash = bitcoin_rpc.proxy.getblockhash(fallback_height)

        logging.info("waiting for follower to prove height %s on its own", fallback_height)
        wait_until_moho_proof_exists(follower_rpc, fallback_hash)

        fallback_log = read_logs_since(fallback_offsets)
        assert FALLBACK_MARKER in fallback_log, (
            "follower never logged the fallback to local proving"
        )
        assert SUBMIT_MARKER in fallback_log, (
            "follower proofs appeared without a local proving submission"
        )
        logging.info("follower fell back to local proving after losing its peer")

        return True
