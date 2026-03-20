import flexitest

from rpc.asm_types import AsmWorkerStatus
from utils.logging import setup_test_logger
from utils.utils import wait_until


class StrataTestBase(flexitest.Test):
    """Base test class that injects per-test logging."""

    def premain(self, ctx: flexitest.RunContext):
        self.logger = setup_test_logger(ctx.datadir_root, ctx.name)

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
