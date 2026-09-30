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
    """Database configuration.

    The runner opens separate sled DBs for the ASM and Moho stores; the proof
    DB path lives in `OrchestratorConfig`.
    """

    asm_path: str
    moho_path: str
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
class Sp1Artifact:
    """SP1 guest ELF loaded from an explicit path.

    Mirrors `ArtifactSource::Sp1` in crates/extensions/prover/worker/src/config.rs.
    """

    elf_path: str
    kind: str = "sp1"


@dataclass
class NativeArtifact:
    """Native (in-process) proof host identity.

    Mirrors `ArtifactSource::Native` in crates/extensions/prover/worker/src/config.rs.
    The signing key is a 32-byte value rendered as a lowercase hex string with
    no `0x` prefix; the Rust side validates that the bytes form a valid BIP-340
    Schnorr signing key (rejects the zero scalar).
    """

    signing_key: str
    kind: str = "native"


ArtifactSource = Sp1Artifact | NativeArtifact


@dataclass
class AsmArtifact:
    """An ASM release the prover can prove, checked against `predicate` at startup.

    Mirrors `AsmArtifactConfig` in crates/extensions/prover/worker/src/config.rs.
    """

    predicate: str
    source: ArtifactSource


@dataclass
class FollowerMode:
    """Follower prover mode: fetch proofs from a peer asm-runner.

    Mirrors `ProverMode::Follower` in crates/extensions/prover/worker/src/config.rs.
    `max_lag` / `max_peer_failures` fall back to the Rust-side defaults when None.
    """

    peer_url: str
    max_lag: int | None = None
    max_peer_failures: int | None = None
    kind: str = "follower"


@dataclass
class GeneratorMode:
    """Generator prover mode: prove locally (the Rust-side default)."""

    kind: str = "generator"


ProverMode = GeneratorMode | FollowerMode


@dataclass
class OrchestratorConfig:
    """Proof orchestrator configuration.

    Mirrors `OrchestratorConfig` in crates/extensions/prover/worker/src/config.rs.
    """

    tick_interval: Duration
    max_concurrent_proofs: int
    proof_db_path: str
    moho: ArtifactSource
    asm_artifacts: list[AsmArtifact]
    # None omits the key, selecting generator mode on the Rust side.
    mode: ProverMode | None = None


@dataclass
class ExecutionTargetConfig:
    """Association between a supported predicate and a compiled spec."""

    predicate: str
    spec_id: int


@dataclass
class ExecutionConfig:
    """Execution identity independent of optional proof generation."""

    genesis_spec_id: int
    targets: list[ExecutionTargetConfig]


@dataclass
class AsmRpcConfig:
    """Main ASM RPC configuration structure."""

    rpc: RpcConfig
    database: DatabaseConfig
    bitcoin: BitcoinConfig
    execution: ExecutionConfig
    orchestrator: OrchestratorConfig | None = None
