# warning: run from repo root, NOT inside this dir
#
# Builds strata-asm-runner. The runner supports three prover modes selected by
# config (see docker/README.md):
#   - none:   `[orchestrator]` omitted entirely
#   - native: `orchestrator.backend.kind = "native"`
#   - sp1:    `orchestrator.backend.kind = "sp1"`
#
# Two image variants are produced from a single Dockerfile via `--target`:
#   - `native` (default): runner built without SP1; only the `none` and
#     `native` prover modes work.
#   - `sp1`: runner built with `--features sp1`; the SP1 guest ELFs
#     (`asm.elf`, `moho.elf`) must be staged at
#     `docker/asm-runner/artifacts/elfs/` in the build context — they are
#     compiled outside docker (host or CI runner with `sp1up`), matching the
#     pattern alpen uses for its strata image. The image build itself does
#     NOT install the SP1 toolchain.
#
# Examples:
#   docker build -f docker/asm-runner/Dockerfile -t strata-asm-runner:native .
#
#   cargo b -r -p strata-asm-sp1-guest-builder
#   mkdir -p docker/asm-runner/artifacts/elfs
#   cp guest-builder/sp1/elfs/{asm,moho}.elf docker/asm-runner/artifacts/elfs/
#   docker build -f docker/asm-runner/Dockerfile \
#     --target sp1 --build-arg CARGO_FEATURES=sp1 \
#     -t strata-asm-runner:sp1 .
FROM --platform=linux/amd64 ubuntu:24.04 AS builder

WORKDIR /app

# Optional comma-separated cargo features (e.g. "sp1"). Applied to the runner
# build below.
ARG CARGO_FEATURES=""

ENV CARGO_INCREMENTAL=0
ENV CARGO_TERM_COLOR=always
ENV DEBIAN_FRONTEND=noninteractive
ENV PATH=/root/.cargo/bin:$PATH
# The guest-builder crate's build.rs gets compiled as part of the workspace
# metadata pass even when building `-p strata-asm-runner`. Guest ELFs are
# always supplied externally (see sp1 target below), so skip the in-build
# guest compilation — otherwise the build would need the SP1 toolchain.
ENV SP1_SKIP_PROGRAM_BUILD=true

RUN apt-get update && \
    apt-get -y upgrade && \
    apt-get install -y --no-install-recommends \
        pkg-config \
        build-essential \
        protobuf-compiler \
        git \
        curl \
        ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install rustup with no default toolchain; `rust-toolchain.toml` pins the
# exact version and `rustup show` materializes it.
RUN curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain none --profile minimal

COPY rust-toolchain.toml rust-toolchain.toml
RUN rustup show && cargo --version

COPY . .

# Build the binary and lift it out of the cache-mounted target dir so it
# persists into the layer.
RUN --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/root/.cargo/git \
    --mount=type=cache,target=/app/target \
    cargo b -r -p strata-asm-runner \
      ${CARGO_FEATURES:+--features "$CARGO_FEATURES"} && \
    cp /app/target/release/strata-asm-runner /usr/local/bin/strata-asm-runner

FROM --platform=linux/amd64 ubuntu:24.04 AS runtime-base

WORKDIR /app

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
        ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/strata-asm-runner /usr/local/bin/strata-asm-runner

ENTRYPOINT ["/usr/local/bin/strata-asm-runner"]
CMD ["--config", "/app/config.toml", "--params", "/app/asm-params.json"]

# SP1 variant: adds the pre-built guest ELFs. Point
# `orchestrator.backend.sp1.{asm,moho}_elf_path` at /app/elfs/{asm,moho}.elf
# from config.toml.
FROM runtime-base AS sp1
COPY docker/asm-runner/artifacts/elfs/asm.elf /app/elfs/asm.elf
COPY docker/asm-runner/artifacts/elfs/moho.elf /app/elfs/moho.elf

# Default target: native-only runtime. Listed last so plain `docker build`
# (without `--target`) produces the non-SP1 image.
FROM runtime-base AS native
