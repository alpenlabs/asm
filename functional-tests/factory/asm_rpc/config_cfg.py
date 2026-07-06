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
    hashblock_connection_string: str
    retry_count: int | None = None
    retry_interval: Duration | None = None


@dataclass
class Sp1Backend:
    """SP1 proof backend configuration.

    Mirrors `BackendConfig::Sp1` in the prover worker's config. `asm_elf_paths`
    lists one guest ELF per ASM proving artifact — several entries let the
    prover span an ASM VK upgrade. Entry 0 is the genesis-time artifact.
    """

    asm_elf_paths: list[str]
    moho_elf_path: str
    kind: str = "sp1"


@dataclass
class NativeAsmEntry:
    """One ASM proving artifact of the native backend.

    The signing key fixes the artifact's predicate identity; `stf_params`
    (e.g. `{"forks": {"fork1": 0}}`) is the schedule baked into its
    execution, mirroring how a guest ELF hardcodes its own params.
    """

    schnorr_signing_key: str
    stf_params: dict


@dataclass
class NativeBackend:
    """Native (in-process) proof backend configuration.

    Mirrors `BackendConfig::Native` in the prover worker's config. Each
    signing key is a 32-byte value rendered as a lowercase hex string with no
    `0x` prefix; the Rust side validates that the bytes form a valid BIP-340
    Schnorr signing key (rejects the zero scalar). Entry 0 of `asm_entries` is
    the genesis-time artifact.
    """

    asm_entries: list[NativeAsmEntry]
    moho_schnorr_signing_key: str
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
