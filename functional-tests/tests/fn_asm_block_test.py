import flexitest

from envs.base_test import StrataTestBase
from rpc.asm_types import AsmWorkerStatus
from utils.utils import wait_until, wait_until_bitcoind_ready


@flexitest.register
class AsmBlockProcessingTest(StrataTestBase):
    """Smoke test for asm-runner block processing over regtest."""

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

        wallet_addr = bitcoin_rpc.proxy.getnewaddress()
        num_blocks_to_generate = 10
        self.logger.info("Generating %s blocks", num_blocks_to_generate)
        bitcoin_rpc.proxy.generatetoaddress(num_blocks_to_generate, wallet_addr)

        latest_asm_height = self.wait_until_asm_reaches_height(
            asm_rpc,
            min_height=initial_btc_height + 1,
        )
        self.logger.info("ASM progressed to height %s", latest_asm_height)

        latest_btc_block_hash = bitcoin_rpc.proxy.getblockhash(latest_asm_height)
        assignments = asm_rpc.strata_asm_getAssignments(latest_btc_block_hash)
        if assignments is None:
            raise AssertionError("ASM getAssignments should return a list")
        self.logger.info("Assignments at latest ASM block: %s entries", len(assignments))

        return True

    def wait_until_asm_ready(self, asm_rpc, timeout=60):
        def check_asm_ready():
            try:
                _ = asm_rpc.strata_asm_getStatus()
                return True
            except Exception as exc:
                self.logger.debug("ASM not ready yet: %s", exc)
                return False

        wait_until(
            check_asm_ready,
            timeout=timeout,
            step=2,
            error_msg=f"ASM RPC did not become ready within {timeout} seconds",
        )

    def wait_until_asm_reaches_height(self, asm_rpc, min_height: int, timeout=180) -> int:
        height_holder: dict[str, int] = {}

        def check_asm_progressed():
            try:
                status = AsmWorkerStatus.from_dict(asm_rpc.strata_asm_getStatus())
                if status.cur_block is None:
                    return False

                cur_height = status.cur_block.height
                self.logger.debug(
                    "ASM height check: current=%s, target>=%s",
                    cur_height,
                    min_height,
                )

                if cur_height >= min_height:
                    height_holder["height"] = cur_height
                    return True
                return False
            except Exception as exc:
                self.logger.debug("Error checking ASM progression: %s", exc)
                return False

        wait_until(
            check_asm_progressed,
            timeout=timeout,
            step=5,
            error_msg=f"ASM did not reach target height within {timeout} seconds",
        )
        return height_holder["height"]
