#!/usr/bin/env python3
"""guest_publish.py — Helpers for the "Publish ASM Guest" workflow.

Bundles the concerns that the workflow chains together so each workflow step
is one line. Pure-stdlib so it runs on every GitHub-hosted runner without an
install step.

Subcommands:
    validate    Verify the env input before any build work.
    bundle      Check the guest files the build produced in $OUTPUT_DIR, then write
                SHA256SUMS and manifest.json next to them.
    upload      Copy the bundle to s3://<bucket>/<prefix>/<env>/<commit>/, each file with
                a `<name>.sha256` sidecar in `sha256sum -c` format, then manifest.json
                last as the completion marker.

Each subcommand reads its inputs from environment variables documented on the
per-command function.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import NoReturn

# ---- shared helpers --------------------------------------------------------


def fail(message: str) -> NoReturn:
    """Print a GHA `::error::` annotation and exit non-zero."""
    print(f"::error::{message}", file=sys.stderr)
    sys.exit(1)


def sha256_hex(path: Path) -> str:
    """Return the SHA-256 of `path` as a lowercase hex digest, read in chunks."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_sha256_sidecar(digest: str, name: str, dest_dir: Path) -> Path:
    """Write `<dest_dir>/<name>.sha256` in `sha256sum -c` format (two spaces)."""
    sidecar = dest_dir / f"{name}.sha256"
    sidecar.write_text(f"{digest}  {name}\n", encoding="utf-8")
    return sidecar


def require_file(path: Path) -> None:
    if not path.is_file() or path.stat().st_size == 0:
        fail(f"expected file missing or empty: {path}")


def aws(*args: str) -> str:
    """Run the AWS CLI, returning stdout. check=True so an AWS error fails the step
    instead of reading as an empty result; stderr stays in the job log."""
    return subprocess.run(
        ["aws", *args], check=True, stdout=subprocess.PIPE, text=True
    ).stdout


def write_summary(lines: list[str]) -> None:
    with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


# ---- validate --------------------------------------------------------------

ENVIRONMENTS = ("dev", "staging", "testnet", "mainnet")


def validate_env(env: str) -> str:
    if env not in ENVIRONMENTS:
        fail(f"env must be one of {', '.join(ENVIRONMENTS)} (got {env!r})")
    return env


def params_path(env: str) -> str:
    """Return the repo path of the params file the guest for `env` is built with."""
    return f"crates/params/envs/{env}.json"


def cmd_validate() -> None:
    """Env: INPUT_ENV."""
    validate_env(os.environ["INPUT_ENV"])


# ---- bundle ----------------------------------------------------------------

# The files the guest build writes to guest-builder/sp1/generated/. Each is
# checksummed by SHA256SUMS and published with a `.sha256` sidecar.
GUEST_FILES = ("asm.elf", "asm-predicate.txt", "asm-vkey-hash.txt")
BUNDLE_FILES = GUEST_FILES + ("SHA256SUMS",)
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
SP1_VERSION_RE = re.compile(r"^v\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$")


def cmd_bundle() -> None:
    """Env: OUTPUT_DIR, DEPLOY_ENV, GUEST_REF, COMMIT, SP1_VERSION, GITHUB_RUN_ID,
    GITHUB_STEP_SUMMARY.

    Runs in the credentialed job, so the digests come from a clean environment rather
    than from the job that ran the untrusted build.
    """
    output_dir = Path(os.environ["OUTPUT_DIR"])
    env = validate_env(os.environ["DEPLOY_ENV"])
    guest_ref = os.environ["GUEST_REF"]
    commit = os.environ["COMMIT"]
    if not SHA1_RE.fullmatch(commit):
        fail(f"built commit is not a sha: {commit!r}")
    sp1_version = os.environ["SP1_VERSION"]
    if not SP1_VERSION_RE.fullmatch(sp1_version):
        fail(f"SP1 version is not a release tag: {sp1_version!r}")

    for name in GUEST_FILES:
        require_file(output_dir / name)

    guest_digests = {name: sha256_hex(output_dir / name) for name in GUEST_FILES}
    (output_dir / "SHA256SUMS").write_text(
        "".join(f"{digest}  {name}\n" for name, digest in guest_digests.items()),
        encoding="utf-8",
    )

    vkey_hash = (output_dir / "asm-vkey-hash.txt").read_text().strip()
    predicate = (output_dir / "asm-predicate.txt").read_text().strip()
    # The params file is in the repo at `commit`, so the manifest names it instead of
    # shipping the section the guest baked in.
    manifest = {
        "schema": 1,
        "env": env,
        "run_id": os.environ.get("GITHUB_RUN_ID", ""),
        "sp1_version": sp1_version,
        "asm_params": params_path(env),
        "ref": guest_ref,
        "commit": commit,
        "predicate": predicate,
        "vkey_hash": vkey_hash,
        "sha256": {name: sha256_hex(output_dir / name) for name in BUNDLE_FILES},
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    write_summary(
        [
            "## ASM guest publish",
            "",
            f"- env: `{env}`",
            f"- ref: `{guest_ref}` @ `{commit}`",
            f"- SP1 toolchain: `{manifest['sp1_version']}`",
            f"- params file: `{params_path(env)}` @ `{commit}`",
            "",
            "### Predicate",
            "",
            f"`{predicate}`",
            "",
            "### Verifying key (vkey hash)",
            "",
            f"`{vkey_hash}`",
            "",
            "### SHA-256",
            "",
            "```",
            *(f"{digest}  {name}" for name, digest in manifest["sha256"].items()),
            "```",
            "",
        ]
    )


# ---- upload ----------------------------------------------------------------

# SHA256SUMS is itself a checksum file, and manifest.json carries every digest.
NO_SIDECAR = frozenset({"SHA256SUMS", "manifest.json"})


def s3_cp(src: Path, dst: str) -> None:
    """Copy a single non-empty file to S3, failing fast if it's missing/empty."""
    require_file(src)
    print(f"uploading {src} -> {dst}")
    aws("s3", "cp", "--no-progress", str(src), dst)


def upload_tree(
    names: tuple[str, ...], src_dir: Path, base: str, digests: dict[str, str]
) -> list[str]:
    """Upload each of `names` from `src_dir` to `<base>/<name>`, following every
    object not in NO_SIDECAR with its `<name>.sha256` sidecar."""
    uris: list[str] = []
    for name in names:
        dst = f"{base}/{name}"
        s3_cp(src_dir / name, dst)
        uris.append(dst)
        if name in NO_SIDECAR:
            continue
        sidecar = write_sha256_sidecar(digests[name], name, src_dir)
        s3_cp(sidecar, f"{dst}.sha256")
        uris.append(f"{dst}.sha256")
    return uris


def first_key(bucket: str, prefix: str) -> str | None:
    key = aws(
        "s3api",
        "list-objects-v2",
        "--bucket",
        bucket,
        "--prefix",
        prefix,
        "--max-items",
        "1",
        "--query",
        "Contents[0].Key",
        "--output",
        "text",
    ).strip()
    return None if key in ("", "None") else key  # an empty listing prints "None"


def published_manifest(bucket: str, key: str) -> dict | None:
    """Return the manifest already at `key`, or None if there is none."""
    # Compare exactly so a longer key sharing the prefix (e.g. manifest.json.bak)
    # doesn't count as published.
    if first_key(bucket, key) != key:
        return None
    try:
        return json.loads(aws("s3", "cp", f"s3://{bucket}/{key}", "-"))
    except json.JSONDecodeError as e:
        fail(f"s3://{bucket}/{key} is not valid JSON ({e})")


def cmd_upload() -> None:
    """Env: OUTPUT_DIR, S3_BUCKET, S3_PREFIX (default elfs/asm-runner), GITHUB_STEP_SUMMARY.

    Uploads to <prefix>/<env>/<commit>/ with manifest.json written last. A present
    manifest means a completed publish: one with matching digests is a no-op, one
    with different digests fails. Objects without a manifest are an interrupted
    publish and are re-uploaded.
    """
    output_dir = Path(os.environ["OUTPUT_DIR"])
    bucket = os.environ["S3_BUCKET"]
    prefix = os.environ.get("S3_PREFIX", "elfs/asm-runner")

    manifest = json.loads((output_dir / "manifest.json").read_text())
    env = validate_env(manifest["env"])
    commit = manifest["commit"]
    if not SHA1_RE.fullmatch(commit):
        fail(f"manifest commit is not a sha: {commit!r}")
    key_base = f"{prefix}/{env}/{commit}"
    base = f"s3://{bucket}/{key_base}"

    existing = published_manifest(bucket, f"{key_base}/manifest.json")
    if existing is not None:
        if existing.get("sha256") != manifest["sha256"]:
            fail(
                f"{base}/ was published with different digests: two {env} builds of "
                f"{commit} differ"
            )
        note = f"`{base}/` already published, digests match, nothing uploaded"
        print(note)
        write_summary(["### S3 upload", "", f"- {note}", ""])
        return

    if first_key(bucket, f"{key_base}/"):
        print(
            f"::warning::{base}/ has objects but no manifest.json (interrupted publish), re-uploading"
        )

    uris = upload_tree(BUNDLE_FILES, output_dir, base, manifest["sha256"])
    manifest_dst = f"{base}/manifest.json"
    s3_cp(output_dir / "manifest.json", manifest_dst)
    uris.append(manifest_dst)

    write_summary(
        [
            "### S3 upload",
            "",
            f"- asm-runner: `{base}/`",
            "",
            *(f"- `{u}`" for u in uris),
            "",
        ]
    )


# ---- entry point -----------------------------------------------------------

COMMANDS = {
    "validate": cmd_validate,
    "bundle": cmd_bundle,
    "upload": cmd_upload,
}


def main() -> None:
    parser = argparse.ArgumentParser(description="Helpers for the Publish ASM Guest workflow.")
    parser.add_argument("command", choices=COMMANDS)
    COMMANDS[parser.parse_args().command]()


if __name__ == "__main__":
    main()
