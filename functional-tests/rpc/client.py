import json

import requests
from websockets.sync.client import connect as wsconnect


class RpcError(Exception):
    def __init__(self, code: int, msg: str, data=None):
        self.code = code
        self.msg = msg
        self.data = data

    def __str__(self) -> str:
        return f"RpcError: code {self.code} ({self.msg})"


def _make_request(method: str, req_id: int, params) -> str:
    req = {"jsonrpc": "2.0", "method": method, "id": req_id, "params": params}
    return json.dumps(req)


def _handle_response(resp_str: str):
    resp = json.loads(resp_str)
    if "error" in resp:
        err = resp["error"]
        data = err.get("data")
        raise RpcError(err["code"], err["message"], data=data)
    return resp["result"]


def _send_single_ws_request(url: str, request: str, max_size: int | None = None) -> str | bytes:
    with wsconnect(url, max_size=max_size) as ws:
        ws.send(request)
        return ws.recv()


def _send_http_request(url: str, request: str) -> str:
    headers = {"Content-Type": "application/json"}
    res = requests.post(url, headers=headers, data=request)
    return res.text


def _dispatch_request(url: str, request: str, max_size: int | None = None) -> str | bytes:
    if url.startswith("http"):
        return _send_http_request(url, request)
    if url.startswith("ws"):
        return _send_single_ws_request(url, request, max_size=max_size)
    raise ValueError(f"unsupported protocol in url '{url}'")


class JsonrpcClient:
    def __init__(self, url: str):
        self.url = url
        self.req_idx = 0
        self._pre_call_hook = None

    def _do_pre_call_check(self, method: str):
        if self._pre_call_hook is not None:
            check_res = self._pre_call_hook(method)
            if isinstance(check_res, bool) and not check_res:
                raise RuntimeError(f"failed precheck on call to '{method}'")

    def _call(self, method: str, args, **kwargs):
        max_size = kwargs.get("max_size")
        self._do_pre_call_check(method)
        req = _make_request(method, self.req_idx, args)
        self.req_idx += 1
        resp = _dispatch_request(self.url, req, max_size=max_size)
        return _handle_response(str(resp))

    def __getattr__(self, name: str):
        def __call(*args, **kwargs):
            return self._call(name, args, **kwargs)

        return __call
