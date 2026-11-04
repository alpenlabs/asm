import functools
import hashlib
import logging
import os
from pathlib import Path

import flexitest
import requests

from factory.asm_rpc.config_cfg import (
    ArtifactSource,
    AsmArtifact,
    Duration,
    NativeArtifact,
    OrchestratorConfig,
    Sp1Artifact,
)

from .basic_env import BasicEnv

# Hardcoded deterministic 32-byte test keys for the native backend.
# Each host gets its own key so the native predicate key is stable across
# runs. Distinct, non-zero values (the zero scalar is rejected by
# `k256::schnorr::SigningKey::from_bytes`).
NATIVE_TEST_ASM_SIGNING_KEY = "01" * 32
NATIVE_TEST_MOHO_SIGNING_KEY = "02" * 32
# Predicate the native ASM host derives from `NATIVE_TEST_ASM_SIGNING_KEY`.
NATIVE_TEST_ASM_PREDICATE = (
    "Bip340Schnorr:1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
)

REPO_ROOT = Path(__file__).resolve().parents[2]
SP1_GENERATED_DIR = REPO_ROOT / "guest-builder" / "sp1" / "generated"

# The spec the local guest build (`guest-builder/sp1/guest-asm`) compiles. It is always the
# newest spec; every older spec runs the guest from the release that shipped it.
LOCAL_GUEST_SPEC_ID = 2

ASM_RELEASES_URL = "https://github.com/alpenlabs/asm/releases/download"
# The ASM release whose guest compiles each older spec. v0.5.0-rc.1 is the only release cut
# while the local guest compiled spec 1.
ASM_GUEST_RELEASE_TAGS = {
    0: "v0.4.0",
    1: "v0.5.0-rc.1",
}


class ProverEnv(BasicEnv):
    """Functional-test environment with proof orchestrator enabled."""

    def _orchestrator_config(
        self, ectx: flexitest.EnvContext, service_name: str = "asm_rpc"
    ) -> OrchestratorConfig:
        envdd_path = Path(ectx.envdd_path)
        proof_db_path = str((envdd_path / service_name / "proof_db").resolve())
        moho, asm_source, _ = _artifact_sources()
        return OrchestratorConfig(
            tick_interval=Duration(secs=1, nanos=0),
            max_concurrent_proofs=4,
            proof_db_path=proof_db_path,
            moho=moho,
            asm_artifacts=[AsmArtifact(spec_id=0, source=asm_source)],
        )

    def _asm_predicate(self) -> str:
        _, _, asm_predicate = _artifact_sources()
        return asm_predicate


def _artifact_sources() -> tuple[ArtifactSource, ArtifactSource, str]:
    """Pick the Moho and ASM sources matching the binary built by run_test.sh.

    Returns the Moho source, the ASM source, and the predicate the ASM host must
    resolve to.
    """
    backend = os.environ.get("ASM_PROVER_BACKEND", "native")
    if backend == "sp1":
        asm_source, asm_predicate = sp1_asm_artifact(0)
        return (
            Sp1Artifact(elf_path=str(SP1_GENERATED_DIR / "moho.elf")),
            asm_source,
            asm_predicate,
        )
    if backend == "native":
        return (
            NativeArtifact(signing_key=NATIVE_TEST_MOHO_SIGNING_KEY),
            NativeArtifact(signing_key=NATIVE_TEST_ASM_SIGNING_KEY),
            NATIVE_TEST_ASM_PREDICATE,
        )
    raise ValueError(f"Unknown ASM_PROVER_BACKEND: {backend!r} (expected: native|sp1)")


def sp1_asm_artifact(spec_id: int) -> tuple[Sp1Artifact, str]:
    """Return the SP1 guest for `spec_id`, together with the predicate it must resolve to.

    The newest spec runs the local build. run_test.sh derives its predicate from that same build,
    so the startup predicate check only catches a mix-up between files, not a wrong guest. Older
    specs run the guest their release shipped.
    """
    if spec_id == LOCAL_GUEST_SPEC_ID:
        return (
            Sp1Artifact(elf_path=str(SP1_GENERATED_DIR / "asm.elf")),
            (SP1_GENERATED_DIR / "asm-predicate.txt").read_text().strip(),
        )
    elf_path, predicate = _fetch_release_asm_artifacts(spec_id)
    return Sp1Artifact(elf_path=str(elf_path)), predicate


@functools.cache
def _fetch_release_asm_artifacts(spec_id: int) -> tuple[Path, str]:
    """Download the guest for `spec_id` from the release that shipped it, once per run.

    Checks the ELF and the predicate against the release's `SHA256SUMS`, writes the ELF next to
    the local build, and returns its path together with the predicate.
    """
    release_url = f"{ASM_RELEASES_URL}/{ASM_GUEST_RELEASE_TAGS[spec_id]}"
    logging.info("Fetching the spec %s ASM guest from %s", spec_id, release_url)
    sums = _download_release_file(release_url, "SHA256SUMS").decode()
    digests = {name: digest for digest, name in (line.split() for line in sums.splitlines())}

    def download_checked(name: str) -> bytes:
        data = _download_release_file(release_url, name)
        digest = hashlib.sha256(data).hexdigest()
        if digest != digests[name]:
            raise RuntimeError(f"{name} has sha256 {digest}, release lists {digests[name]}")
        return data

    elf = download_checked("asm.elf")
    predicate = download_checked("asm-predicate.txt").decode().strip()

    elf_path = SP1_GENERATED_DIR / f"asm-v{spec_id}.elf"
    SP1_GENERATED_DIR.mkdir(parents=True, exist_ok=True)
    elf_path.write_bytes(elf)
    return elf_path, predicate


def _download_release_file(release_url: str, name: str) -> bytes:
    response = requests.get(f"{release_url}/{name}", timeout=60)
    response.raise_for_status()
    return response.content
