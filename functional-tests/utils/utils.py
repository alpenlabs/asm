import logging
import time
from collections.abc import Callable
from pathlib import Path

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


# The log helpers below are ported from strata-bridge's
# `functional-tests/utils/utils.py` to share its convention for asserting on
# log output emitted after a specific point in time.
def snapshot_log_offsets(log_paths: list[str]) -> dict[str, int]:
    """Capture the current size of each log file, keyed by path.

    Used as a starting offset so later reads only see lines appended after this
    point — the basis for "did this happen after X?" assertions on a log file
    the process appends to across restarts.
    """
    return {
        log_path: Path(log_path).stat().st_size if Path(log_path).exists() else 0
        for log_path in log_paths
    }


def read_logs_since(log_offsets: dict[str, int]) -> str:
    """Read and concatenate everything appended to each log past its offset.

    The companion to `snapshot_log_offsets` for *absence* checks, which a
    poll-until-match helper can't express (you can't wait for a non-event).
    """
    chunks = []
    for log_path, start_offset in log_offsets.items():
        path = Path(log_path)
        if not path.exists():
            continue
        with path.open(encoding="utf-8", errors="ignore") as f:
            f.seek(start_offset)
            chunks.append(f.read())
    return "".join(chunks)


def wait_until_logs_match(
    log_offsets: dict[str, int],
    matcher: Callable[[str], bool],
    timeout: int = 120,
    step: int = 1,
    error_msg: str = "Condition not met within timeout",
):
    """Wait until any line appended past the captured offsets satisfies *matcher*.

    Reading only from each captured offset onward preserves "did this happen
    after X?" semantics: tests that scan whole log files can otherwise match
    stale lines emitted before the action under test.
    """

    def has_matching_line():
        for log_path, start_offset in log_offsets.items():
            path = Path(log_path)
            if not path.exists():
                continue
            with path.open(encoding="utf-8", errors="ignore") as f:
                f.seek(start_offset)
                for line in f:
                    if matcher(line):
                        return True
        return False

    wait_until(has_matching_line, timeout=timeout, step=step, error_msg=error_msg)


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


def wait_until_asm_proof_exists(asm_rpc, block_hash: str, timeout: int = 600, step: int = 2):
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


def wait_until_moho_proof_exists(asm_rpc, block_hash: str, timeout: int = 600, step: int = 2):
    """Wait until a Moho recursive proof exists for the given block hash."""

    def check():
        try:
            result = asm_rpc.strata_asm_getMohoProof(block_hash)
            return result is not None
        except Exception as exc:
            logging.debug("Error checking Moho proof: %s", exc)
            return False

    wait_until(
        check,
        timeout=timeout,
        step=step,
        error_msg=f"Moho proof was not generated for block {block_hash} within timeout",
    )
