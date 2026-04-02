import logging

import flexitest

from utils.utils import (
    wait_until_asm_proof_exists,
    wait_until_asm_reaches_height,
    wait_until_asm_ready,
    wait_until_bitcoind_ready,
    wait_until_moho_proof_exists,
)


@flexitest.register
class AsmProofGenerationTest(flexitest.Test):
    """Verify that ASM proofs are generated and stored for processed blocks."""

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env("basic")

    def main(self, ctx: flexitest.RunContext):
        bitcoind_service = ctx.get_service("bitcoin")
        asm_service = ctx.get_service("asm_rpc")

        bitcoin_rpc = bitcoind_service.create_rpc()
        asm_rpc = asm_service.create_rpc()

        wait_until_bitcoind_ready(bitcoin_rpc, timeout=30)
        logging.info("Bitcoin node is ready")

        wait_until_asm_ready(asm_rpc)
        logging.info("ASM RPC service is ready")

        initial_btc_height = bitcoin_rpc.proxy.getblockcount()
        logging.info("Initial Bitcoin height: %s", initial_btc_height)

        # Generate a few blocks for proof generation
        wallet_addr = bitcoin_rpc.proxy.getnewaddress()
        num_blocks = 3
        logging.info("Generating %s blocks", num_blocks)
        bitcoin_rpc.proxy.generatetoaddress(num_blocks, wallet_addr)

        # Wait for ASM to process the blocks
        target_height = initial_btc_height + num_blocks
        latest_asm_height = wait_until_asm_reaches_height(
            asm_rpc,
            min_height=target_height,
        )
        logging.info("ASM progressed to height %s", latest_asm_height)

        # Wait for proof to be generated and stored.
        # The orchestrator runs on a tick interval (1s in tests), so the proof
        # should appear shortly after the block is processed.
        target_block_hash = bitcoin_rpc.proxy.getblockhash(target_height)
        logging.info(
            "Waiting for ASM proof at height %s (hash=%s)",
            target_height,
            target_block_hash,
        )

        wait_until_asm_proof_exists(asm_rpc, target_block_hash)

        proof = asm_rpc.strata_asm_getAsmProof(target_block_hash)
        assert proof is not None, "ASM proof should exist after wait"
        logging.info("ASM proof found for block at height %s", target_height)

        # Verify that an earlier processed block also has a proof
        earlier_height = initial_btc_height + 1
        earlier_block_hash = bitcoin_rpc.proxy.getblockhash(earlier_height)
        earlier_proof = asm_rpc.strata_asm_getAsmProof(earlier_block_hash)
        assert earlier_proof is not None, (
            f"ASM proof should exist for earlier block at height {earlier_height}"
        )
        logging.info("ASM proof also found for earlier block at height %s", earlier_height)

        # Wait for Moho recursive proof to be generated.
        # Moho proofs depend on the ASM proof existing first, so they appear
        # after the ASM proof for the same block.
        logging.info(
            "Waiting for Moho proof at height %s (hash=%s)",
            target_height,
            target_block_hash,
        )
        wait_until_moho_proof_exists(asm_rpc, target_block_hash)

        moho_proof = asm_rpc.strata_asm_getMohoProof(target_block_hash)
        assert moho_proof is not None, "Moho proof should exist after wait"
        logging.info("Moho proof found for block at height %s", target_height)

        # Verify that an earlier processed block also has a Moho proof
        earlier_moho_proof = asm_rpc.strata_asm_getMohoProof(earlier_block_hash)
        assert earlier_moho_proof is not None, (
            f"Moho proof should exist for earlier block at height {earlier_height}"
        )
        logging.info("Moho proof also found for earlier block at height %s", earlier_height)

        return True
