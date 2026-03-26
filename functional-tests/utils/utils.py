import logging
import time
from collections.abc import Callable

from rpc.asm_types import AsmWorkerStatus


def wait_until(
    condition: Callable[[], bool],
    timeout: int = 120,
    step: int = 1,
    error_msg: str = "Condition not met within timeout",
):
    """Poll condition until it returns True or timeout elapses."""
    end_time = time.time() + timeout
    while time.time() < end_time:
        time.sleep(step)
        try:
            if condition():
                return
        except Exception as exc:  # pragma: no cover - diagnostic path
            logging.debug("while waiting, caught exception: %s", exc)

    raise TimeoutError(f"{error_msg} (timeout: {timeout}s)")


def wait_until_bitcoind_ready(rpc_client, timeout: int = 120, step: int = 1):
    """Wait until bitcoind responds to getblockcount."""
    wait_until(
        lambda: rpc_client.proxy.getblockcount() is not None,
        timeout=timeout,
        step=step,
        error_msg="Bitcoind did not start within timeout",
    )


def wait_until_asm_ready(asm_rpc, timeout: int = 60):
    """Wait until the ASM RPC service responds to getStatus."""

    def check():
        try:
            asm_rpc.strata_asm_getStatus()
            return True
        except Exception as exc:
            logging.debug("ASM not ready yet: %s", exc)
            return False

    wait_until(
        check,
        timeout=timeout,
        step=2,
        error_msg=f"ASM RPC did not become ready within {timeout} seconds",
    )


def wait_until_asm_reaches_height(asm_rpc, min_height: int, timeout: int = 180) -> int:
    """Wait until the ASM has processed at least *min_height* and return the actual height."""
    height_holder: dict[str, int] = {}

    def check():
        try:
            status = AsmWorkerStatus.from_dict(asm_rpc.strata_asm_getStatus())
            if status.cur_block is None:
                return False
            cur_height = status.cur_block.height
            logging.debug("ASM height check: current=%s, target>=%s", cur_height, min_height)
            if cur_height >= min_height:
                height_holder["height"] = cur_height
                return True
            return False
        except Exception as exc:
            logging.debug("Error checking ASM progression: %s", exc)
            return False

    wait_until(
        check,
        timeout=timeout,
        step=5,
        error_msg=f"ASM did not reach target height within {timeout} seconds",
    )
    return height_holder["height"]


def wait_until_asm_proof_exists(asm_rpc, block_hash: str, timeout: int = 60, step: int = 2):
    """Wait until an ASM proof exists for the given block hash."""

    def check():
        try:
            result = asm_rpc.strata_asm_getAsmProof(block_hash)
            return result is not None
        except Exception as exc:
            logging.debug("Error checking proof: %s", exc)
            return False

    wait_until(
        check,
        timeout=timeout,
        step=step,
        error_msg=f"ASM proof was not generated for block {block_hash} within timeout",
    )
