#!/usr/bin/env python3
"""guest_publish.py — Helpers for release.yml and the "Publish ASM Guest" workflow.

Bundles the concerns that the workflows chain together so each workflow step
is one line. Pure-stdlib so it runs on every GitHub-hosted runner without an
install step.

Subcommands:
    validate    Verify the inputs before any build work.
    branch      Check a release tag points at a commit on its release line's branch,
                or on main for a vX.Y.0 pre-release cut before that branch.
    draft       Create the tag's draft release, or check an existing one is a draft.
    tagged      Check the release is still a draft and the built commit is the one
                its tag points at, before files are attached to it.
    stage       Copy one network's guest files into $DIST_DIR under network-prefixed
                names, ready to attach to the release.
    notes       Put each network's guest section at the top of the draft release's
                notes.
    publish     Check the draft release holds exactly the files built for $NETWORKS,
                byte for byte, and that the tag still points at $SOURCE_SHA, then
                publish it.
    fetch       Download a published release's guest files, check each against the
                release attestation, and split them into $OUTPUT_DIR/<env>/.
    bundle      Check the guest files in $OUTPUT_DIR, then write SHA256SUMS and
                manifest.json next to them.
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
import shutil
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
    return subprocess.run(["aws", *args], check=True, stdout=subprocess.PIPE, text=True).stdout


def gh(*args: str) -> str:
    """Run the GitHub CLI, returning stdout. `gh` reads GH_TOKEN itself."""
    return subprocess.run(["gh", *args], check=True, stdout=subprocess.PIPE, text=True).stdout


def write_summary(lines: list[str]) -> None:
    with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def repo_url() -> str:
    return f"{os.environ['GITHUB_SERVER_URL']}/{os.environ['GITHUB_REPOSITORY']}"


# ---- validate --------------------------------------------------------------

ENVIRONMENTS = ("dev", "staging", "testnet", "mainnet")
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
SP1_VERSION_RE = re.compile(r"^v\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$")
# vMAJOR.MINOR.PATCH with an optional pre-release suffix, e.g. v0.6.0-rc.1.
RELEASE_TAG_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)(-[0-9A-Za-z.-]+)?$")


def validate_env(env: str) -> str:
    if env not in ENVIRONMENTS:
        fail(f"env must be one of {', '.join(ENVIRONMENTS)} (got {env!r})")
    return env


def validate_sha(sha: str, what: str) -> str:
    if not SHA1_RE.fullmatch(sha):
        fail(f"{what} is not a commit sha: {sha!r}")
    return sha


def parse_release_tag(tag: str) -> tuple[int, int, int, bool]:
    """Return a release tag's major, minor and patch numbers, and whether it has a
    pre-release suffix. The major and minor numbers name its release line."""
    match = RELEASE_TAG_RE.fullmatch(tag)
    if not match:
        fail(f"tag {tag!r} is not vMAJOR.MINOR.PATCH with an optional -suffix")
    major, minor, patch = (int(part) for part in match.groups()[:3])
    return major, minor, patch, match.group(4) is not None


def params_path(env: str) -> str:
    """Return the repo path of the params file the guest for `env` is built with."""
    return f"crates/params/envs/{env}.json"


def cmd_validate() -> None:
    """Env: INPUT_ENV, INPUT_RELEASE_TAG (may be empty)."""
    validate_env(os.environ["INPUT_ENV"])
    release_tag = os.environ.get("INPUT_RELEASE_TAG", "")
    if release_tag:
        parse_release_tag(release_tag)


# ---- release tag checks ----------------------------------------------------

# The branch a line's first rcs are tagged on, before its release branch is cut.
MAIN_BRANCH = "main"


def tag_commit(repo: str, tag: str) -> str:
    """Resolve a tag to its commit. The full ref keeps a branch with the same name
    from matching, and the commits endpoint resolves annotated tags too."""
    commit = gh("api", f"repos/{repo}/commits/refs/tags/{tag}", "--jq", ".sha").strip()
    return validate_sha(commit, f"{repo} tag {tag}")


def release_branch(major: int, minor: int) -> str:
    """Name the branch a release line is tagged from, e.g. releases/v0.5.x."""
    return f"releases/v{major}.{minor}.x"


def branch_exists(repo: str, branch: str) -> bool:
    # matching-refs matches by prefix, so look for the exact ref.
    refs = gh("api", f"repos/{repo}/git/matching-refs/heads/{branch}", "--jq", ".[].ref")
    return f"refs/heads/{branch}" in refs.splitlines()


def on_branch(repo: str, branch: str, commit: str) -> bool:
    """Return whether `commit` is the tip of `branch` or one of its ancestors."""
    status = gh(
        "api", f"repos/{repo}/compare/refs/heads/{branch}...{commit}", "--jq", ".status"
    ).strip()
    return status in ("identical", "behind")


def cmd_branch() -> None:
    """Env: TAG, SOURCE_SHA, GH_TOKEN, GITHUB_REPOSITORY.

    A line's first rcs come from main. Once the line's branch is cut, every tag of
    the line must point at a commit on it, because a tag cut from main would carry
    everything main changed since. vX.Y.0 and the patch releases are maintained on
    the branch, so they always need it.
    """
    tag = os.environ["TAG"]
    repo = os.environ["GITHUB_REPOSITORY"]
    source_sha = validate_sha(os.environ["SOURCE_SHA"], "SOURCE_SHA")

    major, minor, patch, prerelease = parse_release_tag(tag)
    branch = release_branch(major, minor)
    if not branch_exists(repo, branch):
        if patch != 0 or not prerelease:
            fail(f"{branch} does not exist; cut it from main before tagging {tag}")
        branch = MAIN_BRANCH
    if not on_branch(repo, branch, source_sha):
        fail(f"tag {tag} points at {source_sha}, which is not on {branch}")
    print(f"{tag} points at {source_sha}, which is on {branch}")


def release_is_draft(repo: str, tag: str) -> bool | None:
    """Return whether the tag's release is a draft, or None if it has no release.

    Any other `gh` failure fails the step, so an API error isn't read as "no release".
    """
    result = subprocess.run(
        ["gh", "release", "view", tag, "--repo", repo, "--json", "isDraft", "--jq", ".isDraft"],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        return result.stdout.strip() == "true"
    if "release not found" in result.stderr.lower():
        return None
    fail(f"could not read release {tag}: {result.stderr.strip()}")


def cmd_draft() -> None:
    """Env: TAG, GH_TOKEN, GITHUB_REPOSITORY.

    A rerun reuses the draft. A published release is immutable, so it can't take the
    files.
    """
    tag = os.environ["TAG"]
    repo = os.environ["GITHUB_REPOSITORY"]
    prerelease = parse_release_tag(tag)[3]

    is_draft = release_is_draft(repo, tag)
    if is_draft is None:
        args = ["--draft", "--title", tag, "--generate-notes"]
        if prerelease:
            args.append("--prerelease")
        gh("release", "create", tag, "--repo", repo, *args)
        print(f"created draft release {tag}")
    elif not is_draft:
        fail(f"release {tag} is already published; files cannot be attached to it")
    else:
        print(f"reusing draft release {tag}")


def cmd_tagged() -> None:
    """Env: TAG, SOURCE_SHA, GH_TOKEN, GITHUB_REPOSITORY.

    A published release is immutable, so it must still be a draft. A run by hand can
    set release_tag but build another ref, so the built commit must be the tag's.
    """
    tag = os.environ["TAG"]
    repo = os.environ["GITHUB_REPOSITORY"]
    source_sha = validate_sha(os.environ["SOURCE_SHA"], "SOURCE_SHA")

    is_draft = release_is_draft(repo, tag)
    if is_draft is None:
        fail(f"no GitHub release for {tag}; release.yml creates its draft on the tag push")
    if not is_draft:
        fail(f"release {tag} is already published; files cannot be attached to it")
    commit = tag_commit(repo, tag)
    if commit != source_sha:
        fail(f"tag {tag} points at {commit}, but this run checked out {source_sha}")


# ---- release files ---------------------------------------------------------

# The files the guest build writes to guest-builder/sp1/generated/ that are
# published. Each is checksummed by SHA256SUMS and published with a `.sha256`
# sidecar in S3.
GUEST_FILES = ("asm.elf", "asm-predicate.txt")
BUNDLE_FILES = GUEST_FILES + ("SHA256SUMS",)
# Built alongside, and shown in the release notes, but not published.
VKEY_HASH_FILE = "asm-vkey-hash.txt"
# The notes print these as-is, so check their shape first.
PREDICATE_RE = re.compile(r"^Sp1Groth16:[0-9a-f]+$")
VKEY_HASH_RE = re.compile(r"^0x[0-9a-f]{64}$")


def build_dir(artifacts_dir: Path, env: str, commit: str) -> Path:
    """Return where a network's build artifact was downloaded to."""
    return artifacts_dir / f"asm-guest-{env}-{commit}"


def read_checked(path: Path, pattern: re.Pattern[str]) -> str:
    require_file(path)
    value = path.read_text(encoding="utf-8").strip()
    if not pattern.fullmatch(value):
        fail(f"{path} does not look like {pattern.pattern}: {value[:80]!r}")
    return value


def release_name(env: str, name: str) -> str:
    """Return a guest file's name in the GitHub release.

    The network comes first because a release is one flat list of files shared by
    every network built for a tag.
    """
    return f"{env}-{name}"


def release_files(networks: list[str]) -> set[str]:
    return {release_name(env, name) for env in networks for name in GUEST_FILES}


def check_release_files(tag: str, found: list[str], networks: list[str]) -> None:
    """Fail unless a release holds exactly the guest files of `networks`."""
    expected = release_files(networks)
    extra = sorted(set(found) - expected)
    missing = sorted(expected - set(found))
    if extra or missing:
        fail(f"release {tag} has unexpected files {extra} and is missing {missing}")


def sp1_version(lockfile: Path) -> str:
    """Return the SP1 toolchain version a build uses: `sp1-build` in Cargo.lock.

    Matches .github/actions/setup-sp1, which installs that version.
    """
    match = re.search(
        r'^name = "sp1-build"\nversion = "([^"]+)"$', lockfile.read_text(), re.MULTILINE
    )
    if not match:
        fail(f"no sp1-build entry in {lockfile}")
    version = f"v{match.group(1)}"
    if not SP1_VERSION_RE.fullmatch(version):
        fail(f"SP1 version is not a release tag: {version!r}")
    return version


# ---- stage -----------------------------------------------------------------


def cmd_stage() -> None:
    """Env: OUTPUT_DIR, DEPLOY_ENV, DIST_DIR."""
    output_dir = Path(os.environ["OUTPUT_DIR"])
    env = validate_env(os.environ["DEPLOY_ENV"])
    dist_dir = Path(os.environ["DIST_DIR"])
    dist_dir.mkdir(parents=True, exist_ok=True)
    for name in GUEST_FILES:
        require_file(output_dir / name)
        shutil.copyfile(output_dir / name, dist_dir / release_name(env, name))


# ---- notes -----------------------------------------------------------------

# Wrap the guests section so a rerun replaces it instead of adding a second copy.
NOTES_START = "<!-- asm-guests -->"
NOTES_END = "<!-- /asm-guests -->"
REBUILD_DOC = "guest-builder/sp1/README.md#checking-a-published-guest"


def cmd_notes() -> None:
    """Env: TAG, NETWORKS (a JSON list), SOURCE_SHA, ARTIFACTS_DIR, WORK_DIR, LOCKFILE,
    GH_TOKEN, GITHUB_REPOSITORY, GITHUB_SERVER_URL.

    Links name the tag rather than the commit: publishing locks an immutable release's tag
    to the commit `publish` checked, so the two point at the same files.

    The predicate comes from the draft release, so the notes show what is published.
    The vkey hash comes from each network's build artifact, at
    $ARTIFACTS_DIR/asm-guest-<env>-<sha>/, since it is not a release file.
    """
    tag = os.environ["TAG"]
    repo = os.environ["GITHUB_REPOSITORY"]
    networks = [validate_env(n) for n in json.loads(os.environ["NETWORKS"])]
    commit = validate_sha(os.environ["SOURCE_SHA"], "SOURCE_SHA")
    artifacts_dir = Path(os.environ["ARTIFACTS_DIR"])
    work_dir = Path(os.environ["WORK_DIR"])
    work_dir.mkdir(parents=True, exist_ok=True)
    version = sp1_version(Path(os.environ["LOCKFILE"]))
    url = repo_url()

    gh(
        "release",
        "download",
        tag,
        "--repo",
        repo,
        "--dir",
        str(work_dir),
        "--pattern",
        "*-asm-predicate.txt",
    )

    lines = [
        NOTES_START,
        "## ASM guests",
        "",
        (
            f"Built from [`{commit[:8]}`]({url}/commit/{commit}) with SP1 `{version}`."
            " Each network's guest bakes in its params file at this tag. To rebuild one"
            " and compare, see"
            f" [Checking a published guest]({url}/blob/{tag}/{REBUILD_DOC})."
        ),
        "",
        (
            "The vkey hash is SP1's program vkey hash of the ELF, which `cargo prove vkey"
            " --elf <env>-asm.elf` prints. Most of a predicate's bytes are the same for"
            " every build, so compare vkey hashes to tell builds apart."
        ),
        "",
    ]
    for env in networks:
        predicate = read_checked(work_dir / release_name(env, "asm-predicate.txt"), PREDICATE_RE)
        vkey_hash = read_checked(
            build_dir(artifacts_dir, env, commit) / VKEY_HASH_FILE, VKEY_HASH_RE
        )
        lines += [
            f"### `{env}`",
            "",
            f"- Params: [`{params_path(env)}`]({url}/blob/{tag}/{params_path(env)})",
            f"- vkey hash: `{vkey_hash}`",
            "",
            "Predicate:",
            "",
            "```",
            predicate,
            "```",
            "",
        ]
    lines.append(NOTES_END)
    section = "\n".join(lines)

    # Replace only the guests section, so text added by hand around it survives a rerun.
    body = gh("release", "view", tag, "--repo", repo, "--json", "body", "--jq", ".body")
    if NOTES_START in body and NOTES_END in body:
        before, rest = body.split(NOTES_START, 1)
        after = rest.split(NOTES_END, 1)[1]
        new_body = before + section + after
    else:
        new_body = section + "\n\n" + body.lstrip("\n")
    notes = work_dir / "notes.md"
    notes.write_text(new_body, encoding="utf-8")
    gh("release", "edit", tag, "--repo", repo, "--notes-file", str(notes))


# ---- publish ---------------------------------------------------------------


def cmd_publish() -> None:
    """Env: TAG, NETWORKS (a JSON list), SOURCE_SHA, ARTIFACTS_DIR, WORK_DIR, GH_TOKEN,
    GITHUB_REPOSITORY.

    A published release is immutable, so the files are checked while it is still a
    draft. A stray or replaced file can then be fixed on the draft and the job rerun.
    The files must match this run's builds byte for byte, since anyone who can write
    to the draft could replace one under the same name. The tag can still move while
    the release is a draft, which would make the release name a different commit than
    the one the guests were built from.
    """
    tag = os.environ["TAG"]
    repo = os.environ["GITHUB_REPOSITORY"]
    networks = [validate_env(n) for n in json.loads(os.environ["NETWORKS"])]
    source_sha = validate_sha(os.environ["SOURCE_SHA"], "SOURCE_SHA")
    artifacts_dir = Path(os.environ["ARTIFACTS_DIR"])
    download_dir = Path(os.environ["WORK_DIR"]) / "release"

    gh("release", "download", tag, "--repo", repo, "--dir", str(download_dir))
    check_release_files(tag, sorted(p.name for p in download_dir.iterdir()), networks)
    for env in networks:
        for name in GUEST_FILES:
            built = build_dir(artifacts_dir, env, source_sha) / name
            require_file(built)
            if sha256_hex(download_dir / release_name(env, name)) != sha256_hex(built):
                fail(f"release {tag} file {release_name(env, name)} differs from this run's build")
    commit = tag_commit(repo, tag)
    if commit != source_sha:
        fail(f"tag {tag} now points at {commit}, but the guests were built from {source_sha}")
    gh("release", "edit", tag, "--repo", repo, "--draft=false")


# ---- fetch -----------------------------------------------------------------


def cmd_fetch() -> None:
    """Env: TAG, SOURCE_SHA, OUTPUT_DIR, LOCKFILE, GH_TOKEN, GITHUB_REPOSITORY,
    GITHUB_OUTPUT.

    Writes each network's files to $OUTPUT_DIR/<env>/ under their build names, ready
    for `bundle`, and sets the `networks` and `sp1_version` outputs. The S3 key uses
    the commit the guests were built from, so the tag must still point at it.
    """
    tag = os.environ["TAG"]
    parse_release_tag(tag)
    repo = os.environ["GITHUB_REPOSITORY"]
    source_sha = validate_sha(os.environ["SOURCE_SHA"], "SOURCE_SHA")
    commit = tag_commit(repo, tag)
    if commit != source_sha:
        fail(f"tag {tag} now points at {commit}, but the guests were built from {source_sha}")
    output_dir = Path(os.environ["OUTPUT_DIR"])
    download_dir = output_dir / "release"

    gh("release", "download", tag, "--repo", repo, "--dir", str(download_dir))
    found = sorted(path.name for path in download_dir.iterdir())
    networks = [env for env in ENVIRONMENTS if release_name(env, GUEST_FILES[0]) in found]
    if not networks:
        fail(f"release {tag} has no <env>-{GUEST_FILES[0]} files")
    check_release_files(tag, found, networks)
    for name in found:
        # Checks the file's digest against the attestation GitHub signed when the
        # release was published.
        gh("release", "verify-asset", tag, str(download_dir / name), "--repo", repo)

    for env in networks:
        env_dir = output_dir / env
        env_dir.mkdir(parents=True, exist_ok=True)
        for name in GUEST_FILES:
            shutil.move(download_dir / release_name(env, name), env_dir / name)

    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as f:
        f.write(f"networks={' '.join(networks)}\n")
        f.write(f"sp1_version={sp1_version(Path(os.environ['LOCKFILE']))}\n")


# ---- bundle ----------------------------------------------------------------


def bundle_location(env: str, commit: str) -> tuple[str, str]:
    """Return the S3 bucket and key prefix a bundle for `env` at `commit` goes to.

    Env: S3_BUCKET, S3_PREFIX (default elfs/asm-runner).
    """
    prefix = os.environ.get("S3_PREFIX", "elfs/asm-runner")
    return os.environ["S3_BUCKET"], f"{prefix}/{env}/{commit}"


def bundle_uri(env: str, commit: str) -> str:
    bucket, key_base = bundle_location(env, commit)
    return f"s3://{bucket}/{key_base}"


def cmd_bundle() -> None:
    """Env: OUTPUT_DIR, DEPLOY_ENV, GUEST_REF, COMMIT, SP1_VERSION, GITHUB_RUN_ID,
    GITHUB_SERVER_URL, GITHUB_REPOSITORY, GITHUB_STEP_SUMMARY.

    Runs in the credentialed job, so the digests come from a clean environment rather
    than from the job that ran the untrusted build.
    """
    output_dir = Path(os.environ["OUTPUT_DIR"])
    env = validate_env(os.environ["DEPLOY_ENV"])
    guest_ref = os.environ["GUEST_REF"]
    commit = validate_sha(os.environ["COMMIT"], "built commit")
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
        "sha256": {name: sha256_hex(output_dir / name) for name in BUNDLE_FILES},
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    params_url = f"{repo_url()}/blob/{commit}/{params_path(env)}"
    write_summary(
        [
            f"## ASM guest: `{env}`",
            "",
            f"- ref: `{guest_ref}` @ `{commit}`",
            f"- SP1 toolchain: `{sp1_version}`",
            f"- params file: [`{params_path(env)}`]({params_url})",
            "",
            "### Predicate",
            "",
            f"`{predicate}`",
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

    manifest = json.loads((output_dir / "manifest.json").read_text())
    env = validate_env(manifest["env"])
    commit = validate_sha(manifest["commit"], "manifest commit")
    bucket, key_base = bundle_location(env, commit)
    base = bundle_uri(env, commit)

    existing = published_manifest(bucket, f"{key_base}/manifest.json")
    if existing is not None:
        if set(existing.get("sha256", {})) != set(manifest["sha256"]):
            fail(
                f"{base}/ was published with a different set of files: "
                f"{sorted(existing.get('sha256', {}))}"
            )
        if existing.get("sha256") != manifest["sha256"]:
            fail(
                f"{base}/ was published with different digests: two {env} builds of {commit} differ"
            )
        note = f"`{base}/` already published, digests match, nothing uploaded"
        print(note)
        write_summary(["### S3 upload", "", f"- {note}", ""])
        return

    if first_key(bucket, f"{key_base}/"):
        print(
            f"::warning::{base}/ has objects but no manifest.json (interrupted publish), "
            "re-uploading"
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
    "branch": cmd_branch,
    "draft": cmd_draft,
    "tagged": cmd_tagged,
    "stage": cmd_stage,
    "notes": cmd_notes,
    "publish": cmd_publish,
    "fetch": cmd_fetch,
    "bundle": cmd_bundle,
    "upload": cmd_upload,
}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Helpers for release.yml and the Publish ASM Guest workflow."
    )
    parser.add_argument("command", choices=COMMANDS)
    COMMANDS[parser.parse_args().command]()


if __name__ == "__main__":
    main()
