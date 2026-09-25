# syntax=docker/dockerfile:1

# ------------------------------------------------------------------------------
# Stage 1: Build the strata-asm-runner binary
# ------------------------------------------------------------------------------
FROM --platform=linux/amd64 ubuntu:24.04 AS builder

# Build dependencies and rustup with no default toolchain; rust-toolchain.toml
# pins the exact nightly and `rustup show` below materializes it.
# cmake and a C++ compiler are needed because zmq-sys builds libzmq from
# source (zeromq-src). protoc plus the well-known .proto includes from
# libprotobuf-dev are needed by sp1-prover-types' build script, which imports
# google/protobuf/empty.proto.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    build-essential ca-certificates cmake curl git libprotobuf-dev pkg-config protobuf-compiler \
    && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain none --profile minimal \
    && rm -rf /var/lib/apt/lists/*
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /build

# Toolchain first so the pinned nightly install is its own cached layer. Only
# the minimal profile is installed, and RUSTUP_TOOLCHAIN pins it below so the
# components listed in rust-toolchain.toml (docs, miri, analyzer) are never
# pulled in; the build needs none of them.
COPY rust-toolchain.toml ./
RUN awk -F'"' '/^channel = /{print $2}' rust-toolchain.toml > /rust-channel \
    && rustup toolchain install "$(cat /rust-channel)" --profile minimal

COPY Cargo.toml Cargo.lock ./
COPY .cargo .cargo
COPY bin bin
COPY crates crates
COPY guest-builder guest-builder
COPY tests tests

# --features sp1 matches the deployed image and the bare-metal binary: testnet
# uses Sp1Groth16 predicates, and without the feature an SP1 operator config
# cannot start. The binary also runs with no [orchestrator] section, but the
# sp1 feature compiles the native backend out, so `kind = "native"` configs
# are rejected at startup, as with the image strata-bridge builds. BUILD_ELF and
# BUILD_VKEY stay unset, so no guest program is compiled and no SP1 toolchain
# is needed; the guest ELFs are runtime inputs referenced from config.toml.
# Cache mounts keep the multi-GB target directory and the cargo registry out
# of the image layers; on an ephemeral CI runner they start empty, locally they
# make rebuilds incremental.
RUN --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/root/.cargo/git \
    --mount=type=cache,target=/build/target \
    RUSTUP_TOOLCHAIN="$(cat /rust-channel)" \
    cargo build --release --locked -p strata-asm-runner --features sp1 \
    && strip --strip-debug -o /strata-asm-runner target/release/strata-asm-runner

# ------------------------------------------------------------------------------
# Stage 2: Minimal runtime image
# ------------------------------------------------------------------------------
FROM --platform=linux/amd64 ubuntu:24.04 AS runtime

# Runtime inputs, all supplied by the deployment (see docker/README.md):
#   /app/config.toml       - runner configuration (required)
#   /app/asm-params.json   - ASM params (required)
#   database directories   - database.asm_path / database.moho_path in config.toml
#   proof database         - orchestrator.proof_db_path in config.toml
#   SP1 guest ELFs         - orchestrator.backend.{asm,moho}_elf_path when kind = "sp1"
# The process runs as root, like the image strata-bridge builds, so existing
# deployments (root-owned volumes, commands that write into /app) keep working.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app

COPY --from=builder /strata-asm-runner /usr/local/bin/strata-asm-runner
COPY --chmod=755 docker/entrypoint.sh /usr/local/bin/entrypoint.sh

ENTRYPOINT ["sh", "/usr/local/bin/entrypoint.sh"]
