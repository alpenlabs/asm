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
| `asm-vkey-hash.txt` | SP1's program vkey hash, as `0x<hex>`. It is the same value `cargo prove vkey` prints for the ELF. It is not published. |
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

Run the `Publish ASM Guest` workflow (`.github/workflows/publish-asm-guest.yml`) from main. It takes the ref to build and the network. It does a reproducible build with that network's params file at that ref, and uploads the result to:

```
s3://alpen-mosaic-artifacts/elfs/asm-runner/<env>/<commit>/
  asm.elf  asm.elf.sha256
  asm-predicate.txt  asm-predicate.txt.sha256
  SHA256SUMS
  manifest.json
```

`manifest.json` is written last and marks a completed publish. It records the network, the ref and commit, the params file's path, the SP1 version, the predicate, and every file's SHA-256.

A release covers several networks, so run the workflow once per network. Each run's summary ends with a release-note section for that network. Paste it into the GitHub release.

## Checking a published guest

Get the bundle for your network and commit into one directory, then check the hashes:

```bash
sha256sum -c SHA256SUMS
```

Older macOS versions don't ship `sha256sum`. Use `shasum -a 256 -c SHA256SUMS` there instead.

Check that `asm-predicate.txt` matches the `predicate` in `manifest.json` and the one in your runner config. The runner also refuses to start when a loaded ELF's predicate differs from its config.

To check that the ELF matches its source:

1. Check out the `commit` from `manifest.json`. Follow that commit's copy of this page, since the build flags may differ. Commits from before this page existed may need other steps.
2. Install the SP1 toolchain at its `sp1_version`.
3. Clear any earlier build, so cargo can't skip the build script and leave old files in `generated/`:

   ```bash
   cargo clean -p strata-asm-sp1-guest-builder
   ```

4. Do a [reproducible build](#reproducible-builds) with the params file at its `asm_params`.
5. Compare `generated/asm.elf` and `generated/asm-predicate.txt` with the published ones.

A match shows the ELF was built from that commit and params file. It does not show that the source implements the spec it claims. That is a code review question.
