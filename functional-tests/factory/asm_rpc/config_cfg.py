"""Configuration dataclasses for ASM RPC service.

These dataclasses mirror the Rust configuration structures in bin/asm-runner/src/config.rs
"""

from dataclasses import dataclass

from factory.common_cfg import Duration


@dataclass
class RpcConfig:
    """RPC server configuration."""

    host: str
    port: int


@dataclass
class DatabaseConfig:
    """Database configuration."""

    path: str
    num_threads: int | None = None
    retry_count: int | None = None
    delay: Duration | None = None


@dataclass
class BitcoinConfig:
    """Bitcoin node configuration."""

    rpc_url: str
    rpc_user: str
    rpc_password: str
    rawblock_connection_string: str
    retry_count: int | None = None
    retry_interval: Duration | None = None


@dataclass
class Sp1Backend:
    """SP1 proof backend configuration.

    Mirrors `BackendConfig::Sp1` in bin/asm-runner/src/prover/config.rs.
    """

    elfs_dir: str
    kind: str = "sp1"


@dataclass
class NativeBackend:
    """Native (in-process) proof backend configuration.

    Mirrors `BackendConfig::Native` in bin/asm-runner/src/prover/config.rs.
    `schnorr_signing_key` is a 32-byte value rendered as a lowercase hex
    string with no `0x` prefix.
    """

    schnorr_signing_key: str
    kind: str = "native"


BackendConfig = Sp1Backend | NativeBackend


@dataclass
class OrchestratorConfig:
    """Proof orchestrator configuration."""

    tick_interval: Duration
    max_concurrent_proofs: int
    proof_db_path: str
    backend: BackendConfig


@dataclass
class AsmRpcConfig:
    """Main ASM RPC configuration structure."""

    rpc: RpcConfig
    database: DatabaseConfig
    bitcoin: BitcoinConfig
    orchestrator: OrchestratorConfig | None = None
