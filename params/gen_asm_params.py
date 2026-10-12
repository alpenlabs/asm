#!/usr/bin/env python3

import argparse
import base64
import json
import logging
import time
import urllib.request
from pathlib import Path

# Bitcoin's difficulty adjustment interval, in blocks. Identical across all networks
# (mainnet, testnet, signet, regtest) per Bitcoin Core's consensus params.
DIFFICULTY_ADJUSTMENT_INTERVAL = 2016

GEN_DIR = Path(__file__).resolve().parent / "gen"
DEFAULT_PARAMS_PATH = GEN_DIR / "asm-params-sample.json"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--api-url",
        help="Esplora REST base URL (e.g. https://mempool.space/signet/api). "
        "Mutually exclusive with the --bitcoin-rpc-* arguments.",
    )
    parser.add_argument("--bitcoin-rpc-url")
    parser.add_argument("--bitcoin-rpc-user")
    parser.add_argument("--bitcoin-rpc-password")
    parser.add_argument("--params", default=str(DEFAULT_PARAMS_PATH))
    parser.add_argument(
        "--genesis-height",
        type=int,
        help="L1 height to anchor the ASM at. Defaults to anchor.block.height "
        "from the --params template.",
    )
    args = parser.parse_args()

    rpc_args = (args.bitcoin_rpc_url, args.bitcoin_rpc_user, args.bitcoin_rpc_password)
    if args.api_url:
        if any(rpc_args):
            parser.error("--api-url cannot be combined with --bitcoin-rpc-* arguments")
    elif not all(rpc_args):
        parser.error(
            "provide either --api-url or all of "
            "--bitcoin-rpc-url/--bitcoin-rpc-user/--bitcoin-rpc-password"
        )
    return args


def rpc_call(rpc_url: str, rpc_user: str, rpc_password: str, method: str, params: list):
    payload = json.dumps(
        {"jsonrpc": "1.0", "id": "asm-runner", "method": method, "params": params}
    ).encode()
    request = urllib.request.Request(
        rpc_url,
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    auth = base64.b64encode(f"{rpc_user}:{rpc_password}".encode()).decode()
    request.add_header("Authorization", f"Basic {auth}")

    with urllib.request.urlopen(request, timeout=5) as response:
        body = json.loads(response.read().decode())

    if body.get("error") is not None:
        raise RuntimeError(body["error"])

    return body["result"]


def http_get(url: str) -> str:
    request = urllib.request.Request(url)
    with urllib.request.urlopen(request, timeout=5) as response:
        return response.read().decode()


def fetch_block_header_rpc(bitcoin_cfg: dict, height: int) -> dict:
    """Fetches the header at ``height`` from a Bitcoin Core JSON-RPC endpoint.

    Returns a normalized header: ``hash`` (block id), ``time`` (unix seconds),
    ``next_target`` (compact difficulty target as an int).
    """
    block_hash = rpc_call(
        bitcoin_cfg["rpc_url"],
        bitcoin_cfg["rpc_user"],
        bitcoin_cfg["rpc_password"],
        "getblockhash",
        [height],
    )
    header = rpc_call(
        bitcoin_cfg["rpc_url"],
        bitcoin_cfg["rpc_user"],
        bitcoin_cfg["rpc_password"],
        "getblockheader",
        [block_hash],
    )
    # Core returns `bits` as a hex string and the timestamp under `time`.
    return {
        "hash": header["hash"],
        "time": int(header["time"]),
        "next_target": int(header["bits"], 16),
    }


def fetch_block_header_esplora(api_url: str, height: int) -> dict:
    """Fetches the header at ``height`` from an Esplora REST API (e.g. mempool.space).

    Returns the same normalized header shape as :func:`fetch_block_header_rpc`.
    """
    block_hash = http_get(f"{api_url}/block-height/{height}").strip()
    block = json.loads(http_get(f"{api_url}/block/{block_hash}"))
    # Esplora returns `bits` as a decimal int and the timestamp under `timestamp`.
    return {
        "hash": block["id"],
        "time": int(block["timestamp"]),
        "next_target": int(block["bits"]),
    }


def build_l1_anchor(genesis_height: int, network: str, fetch_header) -> dict:
    """Builds the L1 anchor dict for the ASM params from on-chain context at ``genesis_height``.

    Records ``genesis_height``'s hash and ``next_target`` on the anchor, plus the timestamp of
    the block at the start of the containing difficulty epoch — matching how the ASM recomputes
    the next difficulty target. ``fetch_header`` is a callable taking a height and returning a
    normalized header (see :func:`fetch_block_header_rpc`).
    """
    epoch_start_height = (
        genesis_height // DIFFICULTY_ADJUSTMENT_INTERVAL
    ) * DIFFICULTY_ADJUSTMENT_INTERVAL
    epoch_start_header = fetch_header(epoch_start_height)
    genesis_header = fetch_header(genesis_height)

    return {
        "block": {"height": genesis_height, "blkid": genesis_header["hash"]},
        "next_target": genesis_header["next_target"],
        "epoch_start_timestamp": epoch_start_header["time"],
        "network": network,
    }


def main() -> None:
    args = parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    logging.info("Starting ASM params generation")

    if args.api_url:
        api_url = args.api_url.rstrip("/")
        fetch_header = lambda height: fetch_block_header_esplora(api_url, height)
        logging.info(f"Fetching chain context from Esplora API at {api_url}")
    else:
        bitcoin_cfg = {
            "rpc_url": args.bitcoin_rpc_url,
            "rpc_user": args.bitcoin_rpc_user,
            "rpc_password": args.bitcoin_rpc_password,
        }
        fetch_header = lambda height: fetch_block_header_rpc(bitcoin_cfg, height)
        logging.info(f"Fetching chain context from Bitcoin RPC at {args.bitcoin_rpc_url}")

    params = json.loads(Path(args.params).read_text())

    genesis_height = args.genesis_height
    if genesis_height is None:
        genesis_height = params["anchor"]["block"]["height"]
        if not isinstance(genesis_height, int):
            raise SystemExit(
                f"anchor.block.height in {args.params} is {genesis_height!r}, not an "
                "integer; set it to the L1 height to anchor at, or pass --genesis-height"
            )
    network = params["anchor"]["network"]
    logging.info(f"Updating ASM params with chain context for {network} network")
    params["anchor"] = build_l1_anchor(genesis_height, network, fetch_header)

    GEN_DIR.mkdir(parents=True, exist_ok=True)
    output_path = GEN_DIR / f"{int(time.time())}.json"

    logging.info(f"Writing updated ASM params to {output_path}")
    output_path.write_text(json.dumps(params, indent=4) + "\n")


if __name__ == "__main__":
    main()
