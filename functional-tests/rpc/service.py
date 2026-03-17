import flexitest

from rpc.client import JsonrpcClient
from utils.utils import wait_until


def inject_service_create_rpc(svc: flexitest.service.ProcService, rpc_url: str, name: str):
    """Inject a JSON-RPC client creator into a ProcService."""

    def _status_check(_method: str):
        wait_until(svc.check_status, timeout=30, step=1, error_msg=f"service '{name}' has stopped")

    def _create_rpc() -> JsonrpcClient:
        rpc = JsonrpcClient(rpc_url)
        rpc._pre_call_hook = _status_check
        return rpc

    svc.create_rpc = _create_rpc
