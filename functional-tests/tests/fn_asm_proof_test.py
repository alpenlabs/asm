import flexitest

from envs.base_test import StrataTestBase
from utils.utils import wait_until, wait_until_bitcoind_ready


@flexitest.register
class AsmProofGenerationTest(StrataTestBase):
    """Verify that ASM proofs are generated and stored for processed blocks."""

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env("basic")

    def main(self, ctx: flexitest.RunContext):
        bitcoind_service = ctx.get_service("bitcoin")
        asm_service = ctx.get_service("asm_rpc")

        bitcoin_rpc = bitcoind_service.create_rpc()
        asm_rpc = asm_service.create_rpc()

        wait_until_bitcoind_ready(bitcoin_rpc, timeout=30)
        self.logger.info("Bitcoin node is ready")

        self.wait_until_asm_ready(asm_rpc)
        self.logger.info("ASM RPC service is ready")

        initial_btc_height = bitcoin_rpc.proxy.getblockcount()
        self.logger.info("Initial Bitcoin height: %s", initial_btc_height)

        # Generate a few blocks for proof generation
        wallet_addr = bitcoin_rpc.proxy.getnewaddress()
        num_blocks = 3
        self.logger.info("Generating %s blocks", num_blocks)
        bitcoin_rpc.proxy.generatetoaddress(num_blocks, wallet_addr)

        # Wait for ASM to process the blocks
        target_height = initial_btc_height + num_blocks
        latest_asm_height = self.wait_until_asm_reaches_height(
            asm_rpc,
            min_height=target_height,
        )
        self.logger.info("ASM progressed to height %s", latest_asm_height)

        # Wait for proof to be generated and stored.
        # The orchestrator runs on a tick interval (1s in tests), so the proof
        # should appear shortly after the block is processed.
        target_block_hash = bitcoin_rpc.proxy.getblockhash(target_height)
        self.logger.info(
            "Waiting for ASM proof at height %s (hash=%s)",
            target_height,
            target_block_hash,
        )

        def asm_proof_exists():
            try:
                result = asm_rpc.strata_asm_getAsmProof(target_block_hash)
                return result is not None
            except Exception as exc:
                self.logger.debug("Error checking proof: %s", exc)
                return False

        wait_until(
            asm_proof_exists,
            timeout=60,
            step=2,
            error_msg=f"ASM proof was not generated for block {target_block_hash} within timeout",
        )

        proof = asm_rpc.strata_asm_getAsmProof(target_block_hash)
        assert proof is not None, "ASM proof should exist after wait"
        self.logger.info("ASM proof found for block at height %s", target_height)

        # Verify that an earlier processed block also has a proof
        earlier_height = initial_btc_height + 1
        earlier_block_hash = bitcoin_rpc.proxy.getblockhash(earlier_height)
        earlier_proof = asm_rpc.strata_asm_getAsmProof(earlier_block_hash)
        assert earlier_proof is not None, (
            f"ASM proof should exist for earlier block at height {earlier_height}"
        )
        self.logger.info("ASM proof also found for earlier block at height %s", earlier_height)

        return True
