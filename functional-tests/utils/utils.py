import logging
import time
from collections.abc import Callable


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
