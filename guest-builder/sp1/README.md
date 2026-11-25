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

A `v*` tag publishes a reproducible build of the guest for every network except `dev`, in a GitHub release and in S3. [Releasing](../../docs/releasing.md) covers which branch to tag, what a release publishes, and how to publish a guest by hand.

## Checking a published guest

For a release, download the files and check them against the release's attestation:

```bash
gh release download <tag> --repo alpenlabs/asm --pattern '<env>-*'
gh release verify-asset <tag> <env>-asm.elf --repo alpenlabs/asm
gh release verify-asset <tag> <env>-asm-predicate.txt --repo alpenlabs/asm
```

For an S3 bundle ([layout](../../docs/releasing.md#what-a-release-publishes)), put it in one directory and check the hashes:

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

## Differences from the native STF

The STF runs twice: natively in the ASM worker, and in this guest for the step proof. Consumers check only the proof, so for them the ASM is whatever the guest computes. If the guest fails on a block the native STF accepts, that block cannot be proven. If it computes a different state, the proven state is not the one runners report. The [security model](../../docs/security-model.md) treats both as security failures.

The two share almost all their code. They differ here:

| Difference | Native | Guest |
| --- | --- | --- |
| Crypto crates | The crates.io versions, such as libsecp256k1 | SP1 versions, swapped in by `[patch.crates-io]` in [`guest-asm/Cargo.toml`](guest-asm/Cargo.toml). Today these are `secp256k1`, `k256`, `sha2`, and `substrate-bn`. |
| Dependency versions | The root `Cargo.lock` | Its own `Cargo.lock`, which can resolve a shared dependency to another version |
| Spec and params | Picked at runtime, with params read from the params file | The newest spec only, with its params baked in; see [One guest per network](#one-guest-per-network) |
| Input | The block and aux data, passed in memory | The same data, decoded from SSZ |
| Memory | The host's | SP1's limits; see [Memory limits](#memory-limits) |

The crypto crates are the easiest to get wrong. A call to `secp256k1` runs libsecp256k1 natively and a `k256`-based port in the guest. The two can disagree on input that the native library rejects or treats specially, such as zero or out-of-range scalars, high-`s` signatures, and bad encodings. The source does not show this. The call reads like libsecp256k1, and the patch that swaps it is in another workspace.

Tests do not show it either. Unit, integration, and functional tests all run the native STF. In CI the guest runs only in [`prover-perf`](../../bin/prover-perf/README.md), which compares its output with the native run on one honest fixture block.

When STF code passes untrusted input into one of these places:

1. Check what the guest's version does with invalid and edge-case input, not only the native one.
2. If the two can differ, decide the case in our own code before the call, so both builds apply the same rule.
3. Pin that rule with fixed vectors.

Check again when the SP1 patches, the guest lockfile, or the baked-in params change. Don't use `cfg(target_os = "zkvm")` in STF code. Today it only keeps host code out of the guest, and any other use makes the two builds differ.

### Memory limits

A transition that needs more memory than the guest has cannot be proven, even if it runs fine natively. These are the limits in SP1 6.10.0:

| Limit | Value | Where it is set |
| --- | --- | --- |
| Guest address space | 2^37 bytes (128 GiB) | `SP1_ZKVM_MAX_MEMORY` default in `sp1-zkvm`'s `build.rs` |
| Input region, part of that space | 2^34 bytes (16 GiB) | `SP1_ZKVM_INPUT_REGION_SIZE` default in `sp1-zkvm`'s `build.rs` |
| Executor process memory | 24 GiB | `DEFAULT_MEMORY_LIMIT` in `sp1-core-executor`'s `opts.rs` |

The guest panics with `Input region overflowed` or `Memory limit exceeded` when it passes the first two. We set none of the three ourselves, so the defaults apply.

A Bitcoin block is a few megabytes, far below these limits. The aux data can be larger, since it holds whole previous transactions, and it has no size bound of its own. What can bring the limits closer is state that grows without bound, or code that allocates in proportion to something an attacker controls. Treat a change that does either as a change to what can be proven, and check the limits again when the SP1 version changes.
