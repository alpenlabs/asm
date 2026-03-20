"""ASM RPC factory for functional testing."""

import os
import shutil
from dataclasses import asdict
from pathlib import Path

import flexitest
import toml

from rpc import inject_service_create_rpc

from .config_cfg import (
    AsmRpcConfig,
    BitcoinConfig,
    DatabaseConfig,
    Duration,
    OrchestratorConfig,
    RpcConfig,
)

EXPECTED_TARGET_PATHS = (
    "target/debug/strata-asm-runner",
    "target/release/strata-asm-runner",
)


class AsmRpcFactory(flexitest.Factory):
    """Factory for creating ASM RPC service instances."""

    def __init__(self, port_range: list[int]):
        super().__init__(port_range)

    @flexitest.with_ectx("ctx")
    def create_asm_rpc_service(
        self,
        bitcoind_props: dict,
        params_file_path: str,
        ctx: flexitest.EnvContext,
    ) -> flexitest.Service:
        service_name = "asm_rpc"
        datadir = ctx.make_service_dir(service_name)
        envdd_path = Path(ctx.envdd_path)

        rpc_port = self.next_port()
        db_path = str((envdd_path / service_name / "db").resolve())
        proof_db_path = str((envdd_path / service_name / "proof_db").resolve())

        config_toml_path = str((envdd_path / service_name / "config.toml").resolve())
        generate_asm_rpc_config(
            bitcoind_props=bitcoind_props,
            rpc_port=rpc_port,
            db_path=db_path,
            proof_db_path=proof_db_path,
            output_path=config_toml_path,
        )

        logfile = os.path.join(datadir, "service.log")
        cmd = [
            resolve_asm_runner_bin(),
            "--config",
            config_toml_path,
            "--params",
            params_file_path,
        ]

        props = {
            "rpc_port": rpc_port,
            "rpc_url": f"http://127.0.0.1:{rpc_port}",
            "db_path": db_path,
        }

        rpc_url = f"http://127.0.0.1:{rpc_port}"
        svc = flexitest.service.ProcService(props, cmd, stdout=logfile)
        svc.start()
        inject_service_create_rpc(svc, rpc_url, service_name)
        return svc


def resolve_asm_runner_bin() -> str:
    """Resolve the strata-asm-runner binary path."""
    env_override = os.environ.get("STRATA_ASM_RUNNER_BIN")
    if env_override:
        return env_override

    path = shutil.which("strata-asm-runner")
    if path:
        return path

    repo_root = Path(__file__).resolve().parents[3]
    for rel in EXPECTED_TARGET_PATHS:
        candidate = (repo_root / rel).as_posix()
        if os.path.exists(candidate):
            return candidate

    return "strata-asm-runner"


def zmq_connection_string(port: int) -> str:
    return f"tcp://127.0.0.1:{port}"


def generate_asm_rpc_config(
    bitcoind_props: dict,
    rpc_port: int,
    db_path: str,
    proof_db_path: str,
    output_path: str,
):
    """Generate ASM RPC configuration TOML file."""
    config = AsmRpcConfig(
        rpc=RpcConfig(host="127.0.0.1", port=rpc_port),
        database=DatabaseConfig(
            path=db_path,
            num_threads=4,
            retry_count=4,
            delay=Duration(secs=0, nanos=150_000_000),
        ),
        bitcoin=BitcoinConfig(
            rpc_url=f"http://127.0.0.1:{bitcoind_props['rpc_port']}",
            rpc_user="user",
            rpc_password="password",
            rawblock_connection_string=zmq_connection_string(bitcoind_props["zmq_rawblock"]),
            retry_count=3,
            retry_interval=Duration(secs=1, nanos=0),
        ),
        orchestrator=OrchestratorConfig(
            tick_interval=Duration(secs=1, nanos=0),
            max_concurrent_asm_proofs=4,
            proof_db_path=proof_db_path,
        ),
    )

    config_dict = asdict(config)
    # Remove None values — Rust expects the key to be absent for Option::None
    config_dict = _strip_none(config_dict)

    with open(output_path, "w") as f:
        toml.dump(config_dict, f)


def _strip_none(d: dict) -> dict:
    """Recursively remove keys with None values from a dict."""
    cleaned = {}
    for k, v in d.items():
        if v is None:
            continue
        if isinstance(v, dict):
            cleaned[k] = _strip_none(v)
        else:
            cleaned[k] = v
    return cleaned
