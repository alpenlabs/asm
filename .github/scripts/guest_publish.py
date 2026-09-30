#!/usr/bin/env python3
"""guest_publish.py — Helpers for the "Publish ASM Guest to S3" workflow.

Bundles the concerns that the workflow chains together so each workflow step
is one line. Pure-stdlib so it runs on every GitHub-hosted runner without an
install step.

Subcommands:
    validate    Verify the tag input before any network work.
    fetch       Download the ASM guest assets from the tag's GitHub Release into
                $OUTPUT_DIR, verify them against SHA256SUMS, resolve the tag's
                commit and write manifest.json.
    upload      Copy the assets to s3://<bucket>/<prefix>/<commit>/, each with a
                `<name>.sha256` sidecar in `sha256sum -c` format, then manifest.json
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

TAG_RE = re.compile(r"^v[A-Za-z0-9._-]{1,200}$")


def cmd_validate() -> None:
    """Env: INPUT_TAG."""
    if not TAG_RE.fullmatch(os.environ["INPUT_TAG"]):
        fail("tag must match v[A-Za-z0-9._-]+")


# ---- fetch -----------------------------------------------------------------

# Checksummed by SHA256SUMS, and published with a `.sha256` sidecar each.
GUEST_FILES = ("asm.elf", "asm-predicate.txt", "asm-vkey-hash.txt")
RELEASE_FILES = GUEST_FILES + ("SHA256SUMS",)
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def fetch_release_assets(repo: str, tag: str, output_dir: Path) -> None:
    """Pull the guest assets from the tag's GitHub Release via `gh`."""
    cmd = ["gh", "release", "download", tag, "--repo", repo, "--dir", str(output_dir)]
    for name in RELEASE_FILES:
        cmd += ["--pattern", name]
    subprocess.run(cmd, check=True)
    for name in RELEASE_FILES:
        p = output_dir / name
        if not p.is_file() or p.stat().st_size == 0:
            fail(f"missing or empty {name} in {repo} release {tag}")


def verify_sha256sums(output_dir: Path) -> None:
    """Check every guest file against the release's SHA256SUMS, which must list
    exactly GUEST_FILES."""
    listed: dict[str, str] = {}
    for line in (output_dir / "SHA256SUMS").read_text().splitlines():
        digest, _, name = line.partition(" ")
        # `sha256sum` marks binary-mode entries with a leading `*`.
        name = name.lstrip(" *")
        if not SHA256_RE.fullmatch(digest) or not name:
            fail(f"malformed SHA256SUMS line: {line!r}")
        listed[name] = digest
    if set(listed) != set(GUEST_FILES):
        fail(f"SHA256SUMS lists {sorted(listed)}, expected {sorted(GUEST_FILES)}")
    for name in GUEST_FILES:
        actual = sha256_hex(output_dir / name)
        if actual != listed[name]:
            fail(f"{name} sha256 {actual} does not match SHA256SUMS {listed[name]}")


def resolve_commit(repo: str, tag: str) -> str:
    """Resolve the tag to its full commit SHA via the GitHub API.

    The commits endpoint dereferences both lightweight and annotated tags.
    """
    sha = subprocess.run(
        ["gh", "api", f"repos/{repo}/commits/{tag}", "--jq", ".sha"],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.strip()
    if not SHA1_RE.fullmatch(sha):
        fail(f"could not resolve {repo} tag {tag} to a commit sha (got {sha!r})")
    return sha


def cmd_fetch() -> None:
    """Env: TAG, OUTPUT_DIR, GH_TOKEN, GITHUB_REPOSITORY, GITHUB_STEP_SUMMARY."""
    tag = os.environ["TAG"]
    repo = os.environ["GITHUB_REPOSITORY"]
    output_dir = Path(os.environ["OUTPUT_DIR"])
    # `gh` reads GH_TOKEN itself; we only verify it's present so a missing token
    # fails fast with a clear error instead of an interactive gh auth prompt.
    if not os.environ.get("GH_TOKEN"):
        fail("GH_TOKEN must be set")

    output_dir.mkdir(parents=True, exist_ok=True)
    fetch_release_assets(repo, tag, output_dir)
    verify_sha256sums(output_dir)
    commit = resolve_commit(repo, tag)

    vkey_hash = (output_dir / "asm-vkey-hash.txt").read_text().strip()
    manifest = {
        "tag": tag,
        "commit": commit,
        "release_url": f"https://github.com/{repo}/releases/tag/{tag}",
        "vkey_hash": vkey_hash,
        "predicate": (output_dir / "asm-predicate.txt").read_text().strip(),
        "sha256": {name: sha256_hex(output_dir / name) for name in RELEASE_FILES},
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    write_summary(
        [
            "## ASM guest publish",
            "",
            f"- release: [`{tag}`]({manifest['release_url']}) @ `{commit}`",
            "",
            "### Predicate",
            "",
            f"`{manifest['predicate']}`",
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
    if not src.is_file() or src.stat().st_size == 0:
        fail(f"expected upload artifact missing or empty: {src}")
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

    Uploads to <prefix>/<commit>/ with manifest.json written last. A present
    manifest means a completed publish: matching digests are a no-op (an rc and
    its final release tagged on one commit), differing digests fail. Objects
    without a manifest are an interrupted publish and are re-uploaded.
    """
    output_dir = Path(os.environ["OUTPUT_DIR"])
    bucket = os.environ["S3_BUCKET"]
    prefix = os.environ.get("S3_PREFIX", "elfs/asm-runner")

    manifest = json.loads((output_dir / "manifest.json").read_text())
    commit = manifest["commit"]
    if not SHA1_RE.fullmatch(commit):
        fail(f"manifest commit is not a sha: {commit!r}")
    key_base = f"{prefix}/{commit}"
    base = f"s3://{bucket}/{key_base}"

    existing = published_manifest(bucket, f"{key_base}/manifest.json")
    if existing is not None:
        if existing.get("sha256") != manifest["sha256"]:
            fail(
                f"{base}/ was published from {existing.get('tag')!r} with different "
                f"digests than {manifest['tag']!r}: two builds of {commit} differ"
            )
        note = (
            f"`{base}/` already published from `{existing.get('tag')}`,"
            " digests match, nothing uploaded"
        )
        print(note)
        write_summary(["### S3 upload", "", f"- {note}", ""])
        return

    if first_key(bucket, f"{key_base}/"):
        print(
            f"::warning::{base}/ has objects but no manifest.json (interrupted publish), re-uploading"
        )

    uris = upload_tree(RELEASE_FILES, output_dir, base, manifest["sha256"])
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
    "fetch": cmd_fetch,
    "upload": cmd_upload,
}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Helpers for the Publish ASM Guest to S3 workflow."
    )
    parser.add_argument("command", choices=COMMANDS)
    COMMANDS[parser.parse_args().command]()


if __name__ == "__main__":
    main()
