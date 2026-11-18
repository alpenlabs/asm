# strata-asm-sp1-guest-builder

This crate builds the SP1 guest for the ASM step proof. The guest code is in `guest-asm`. The build script writes the guest ELF and the files derived from it to `generated/`.

Use this page to build the guest yourself and check that a published guest matches its source.

The crate is part of the root workspace, so run every command below from the repo root. `guest-asm` is its own workspace with its own `Cargo.lock`.

## Prerequisites

- **Rust.** The toolchain pinned in the root `rust-toolchain.toml`.
- **SP1 toolchain.** Install it with `sp1up`, at the version of `sp1-build` in the root `Cargo.lock`. A published guest records its version in `manifest.json` as `sp1_version`.

  ```bash
  SP1_VERSION="v$(awk -F'"' '/^name = "sp1-build"$/{f=1;next} f&&/^version = /{print $2;exit}' Cargo.lock)"
  curl -fsSL https://sp1.succinct.xyz | bash
  export PATH="$HOME/.sp1/bin:$PATH"  # the installer only updates PATH for new shells
  sp1up -v "$SP1_VERSION"
  cargo prove --version
  ```

- **protoc.** Some guest dependencies compile protobuf files.
- **Docker.** Needed for the `docker-build` feature. Published guests use it, so you need Docker to reproduce one. The Docker daemon must be running.

## One guest per network

The guest compiles the newest spec. It also bakes in that spec's section of the params file at `ASM_PARAMS_PATH` (currently `runtime.spec_v2`), or the fact that the file has none. So the same commit gives a different ELF for each network.

Each network's params file is in the repo at `crates/params/envs/<env>.json`. The commit and the network together pin the values a guest bakes in.

Older specs don't build here. They keep the guest from the release that shipped them.

## Outputs

All files land in `generated/`, which is gitignored.

| File | Contents |
|---|---|
| `asm.elf` | The compiled guest program. |
| `asm-predicate.txt` | The SP1 Groth16 predicate, as `Sp1Groth16:<hex>`. The runner's `[[execution.targets]]` entries use it. |
| `asm-vkey-hash.txt` | SP1's program vkey hash, as `0x<hex>`. It is the same value `cargo prove vkey` prints for the ELF. Release notes show it, but it is not a published file. |
| `asm-spec-v2-params.ssz` | The baked-in section, as SSZ. The guest includes these bytes at compile time. |
| `asm-runtime-params.json` | The same section as a runtime part. Native runs such as `prover-perf` read it so they use the same values as the guest. |

`generated/moho.elf` is not built here. `contrib/fetch_moho_artifacts.sh` downloads it from a moho release.

## Building

Both steps are opt-in, because both are slow. A plain `cargo build` compiles the crate and skips them.

Build the ELF, the predicate, and the vkey hash for a network:

```bash
ASM_PARAMS_PATH="$PWD/crates/params/envs/<env>.json" BUILD_VKEY=1 \
  cargo build --locked -p strata-asm-sp1-guest-builder
```

`BUILD_ELF=1` builds only the ELF. `BUILD_VKEY` implies `BUILD_ELF`, since the vk is derived from the ELF.

Give `ASM_PARAMS_PATH` as an absolute path. Cargo runs the build script from this crate's directory, so a relative path resolves from here and not from the repo root.

### Reproducible builds

By default the guest compiles with your local SP1 toolchain. The result can differ from machine to machine. To get the same ELF as a published guest, compile inside SP1's Docker image:

```bash
ASM_PARAMS_PATH="$PWD/crates/params/envs/<env>.json" BUILD_VKEY=1 \
  cargo build --locked -p strata-asm-sp1-guest-builder --features docker-build
```

This is the command the `Publish ASM Guest` workflow runs. Only the guest compile runs in Docker. The vk is still derived on the host.

### Things to watch out for

- `generated/` survives `cargo clean`. A build without the flags leaves old files in place, and they may not match the current source or network. Rebuild before you use them.
- If you changed a dependency the guest uses, check its lockfile first. SP1 rewrites a stale `guest-asm/Cargo.lock` during the build instead of failing:

  ```bash
  cargo metadata --locked --offline --manifest-path guest-builder/sp1/guest-asm/Cargo.toml --format-version 1 > /dev/null
  ```

- `cargo clippy` never builds the guest, whatever flags are set. With `SP1_SKIP_PROGRAM_BUILD=true`, the build script writes nothing.
- On macOS, the build script points `AR` at the SP1 toolchain's `llvm-ar`. macOS's own `ar` produces archives that fail to link in the guest. You don't need to do anything, but this is why `rustc +succinct` must work.

## Publishing

### Releases

Pushing a `v*` tag runs `.github/workflows/release.yml`. It does a reproducible build of the guest for every network in `crates/params/envs/` except `dev`, with that network's params file at the tag. It then:

1. Attaches `<env>-asm.elf` and `<env>-asm-predicate.txt` for each network to a draft GitHub release.
2. Adds a section to the release notes. It names the commit and the SP1 version, and for each network its params file, vkey hash, and predicate.
3. Publishes the release once it holds exactly the files this run built, byte for byte, and the tag still points at the commit they were built from. Releases are immutable after that.
4. Copies the published files to S3, after checking each one against the release's attestation. This job waits until a reviewer approves the `baremetal-binaries` environment.

`dev` gets no released guest, because it is only for local runs and CI.

### Which branch to tag

Each release line has a branch, `releases/vX.Y.x`. Until it exists, you can tag the line's rcs (`vX.Y.0-rc.N`) on `main`. Every other tag needs the branch: `vX.Y.0` and each patch release must point at a commit on it. Once the branch exists, the rcs must come from it too.

So cut the branch from `main` before you tag `vX.Y.0`:

```bash
git push origin <commit>:refs/heads/releases/vX.Y.x
git tag -a vX.Y.0 <commit> -m vX.Y.0
git push origin refs/tags/vX.Y.0
```

If the tag isn't on the right branch, the run stops at "Check the tag's branch", before it creates the release. Don't publish a release for that tag by hand. A published release is immutable, so it can never get the guest files. Cut the branch, then tag the next patch release from it.

### By hand

Run the `Publish ASM Guest` workflow (`.github/workflows/publish-asm-guest.yml`) from main with the ref to build and the network. Without `release_tag`, it uploads straight to S3. Use it for `dev`, or for a build that isn't a release.

### S3 layout

Both paths upload to the same place:

```
s3://alpen-mosaic-artifacts/elfs/asm-runner/<env>/<commit>/
  asm.elf  asm.elf.sha256
  asm-predicate.txt  asm-predicate.txt.sha256
  SHA256SUMS
  manifest.json
```

`manifest.json` is written last and marks a completed publish. It records the network, the ref and commit, the params file's path, the SP1 version, the predicate, and every file's SHA-256.

## Checking a published guest

For a release, download the files and check them against the release's attestation:

```bash
gh release download <tag> --repo alpenlabs/asm --pattern '<env>-*'
gh release verify-asset <tag> <env>-asm.elf --repo alpenlabs/asm
gh release verify-asset <tag> <env>-asm-predicate.txt --repo alpenlabs/asm
```

For an S3 bundle, put it in one directory and check the hashes:

```bash
sha256sum -c SHA256SUMS
```

Older macOS versions don't ship `sha256sum`. Use `shasum -a 256 -c SHA256SUMS` there instead.

Check that the predicate matches the one in your runner config. The runner also refuses to start when a loaded ELF's predicate differs from its config.

To check that the ELF matches its source:

1. Check out the commit the release notes or `manifest.json` name. Follow that commit's copy of this page, since the build flags may differ. Commits from before this page existed may need other steps.
2. Install the SP1 toolchain at the version the release notes or `manifest.json` name.
3. Clear any earlier build, so cargo can't skip the build script and leave old files in `generated/`:

   ```bash
   cargo clean -p strata-asm-sp1-guest-builder
   ```

4. Do a [reproducible build](#reproducible-builds) with the network's params file, `crates/params/envs/<env>.json`.
5. Compare `generated/asm.elf` and `generated/asm-predicate.txt` with the published ones. `generated/asm-vkey-hash.txt` should match the vkey hash in the release notes.

A match shows the ELF was built from that commit and params file. It does not show that the source implements the spec it claims. That is a code review question.
