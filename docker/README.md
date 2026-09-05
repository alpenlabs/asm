# ASM Docker Setup

A single Dockerfile produces two image variants via `--target`:

- `native` (default): runner built without SP1.
- `sp1`: runner built with `--features sp1`, with the SP1 guest ELFs baked in at `/app/elfs/`.

Both variants are two-stage builds: Ubuntu 24.04 with the project's pinned Rust toolchain (from `rust-toolchain.toml`) compiles `strata-asm-runner`, and the binary ships on a slim Ubuntu 24.04 runtime.

## Prover modes

The runner has three prover modes, selected by the config file at runtime:

| Mode   | Config                                              | `native` image | `sp1` image |
| ------ | --------------------------------------------------- | -------------- | ----------- |
| none   | omit `[orchestrator]`                               | yes            | yes         |
| native | `orchestrator.backend.kind = "native"`              | yes            | yes         |
| sp1    | `orchestrator.backend.kind = "sp1"`                 | no             | yes         |

## Building the native image

From the repository root:

```sh
docker build -f docker/asm-runner/Dockerfile -t strata-asm-runner:native .
```

## Building the SP1 image

The SP1 guest ELFs are compiled **outside** the docker build (host or CI runner with the SP1 toolchain installed via `sp1up`) and staged into the build context. The image build itself does not install the SP1 toolchain — this matches the pattern alpen uses for its strata image.

```sh
# 1. Build the guest ELFs locally (requires the SP1 toolchain).
cargo b -r -p strata-asm-sp1-guest-builder

# 2. Stage them into the build context.
mkdir -p docker/asm-runner/artifacts/elfs
cp guest-builder/sp1/elfs/asm.elf  docker/asm-runner/artifacts/elfs/
cp guest-builder/sp1/elfs/moho.elf docker/asm-runner/artifacts/elfs/

# 3. Build the image targeting the sp1 stage.
docker build -f docker/asm-runner/Dockerfile \
  --target sp1 --build-arg CARGO_FEATURES=sp1 \
  -t strata-asm-runner:sp1 .
```

In `config.toml`, point the SP1 backend at the baked-in ELFs:

```toml
[orchestrator.backend]
kind = "sp1"
asm_elf_path  = "/app/elfs/asm.elf"
moho_elf_path = "/app/elfs/moho.elf"
```

## Running

The default `CMD` points at `/app/config.toml` and `/app/asm-params.json`. The runner doesn't validate the params up front — any misconfiguration surfaces as a runtime failure from the binary itself.

Mount the config and params from the host:

```sh
docker run --rm \
  -v "$PWD/config.toml:/app/config.toml:ro" \
  -v "$PWD/asm-params.json:/app/asm-params.json:ro" \
  -v "$PWD/data:/app/data" \
  -p 9010:9010 \
  strata-asm-runner:native
```

Override the paths by passing flags directly:

```sh
docker run --rm \
  -v "$PWD/conf:/conf:ro" \
  strata-asm-runner:native --config /conf/my.toml --params /conf/my.json
```
