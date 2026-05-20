#!/bin/bash
set -euo pipefail

cd "$(dirname "$(realpath "$0")")"
source env.bash

# Set finite fd limit so subprocesses inherit a sane value.
ulimit -n 10240

# Which proof backend the runner is built against.
#   native (default): debug build, no extra features. Fast iteration.
#   sp1:              release build with --features sp1. SP1 proving is
#                     unusably slow in debug.
ASM_PROVER_BACKEND="${ASM_PROVER_BACKEND:-native}"
export ASM_PROVER_BACKEND

case "$ASM_PROVER_BACKEND" in
  native)
    CARGO_ARGS=()
    TARGET_DIR="debug"
    ;;
  sp1)
    CARGO_ARGS=(--release --features sp1)
    TARGET_DIR="release"
    ;;
  *)
    echo "Unknown ASM_PROVER_BACKEND: $ASM_PROVER_BACKEND (expected: native|sp1)" >&2
    exit 1
    ;;
esac

pushd .. > /dev/null
cargo build --bin strata-asm-runner ${CARGO_ARGS[@]+"${CARGO_ARGS[@]}"}
if [[ "$ASM_PROVER_BACKEND" == "sp1" ]]; then
  # Produces guest-builder/sp1/elfs/{asm,moho}.elf, which the runner reads at startup.
  cargo build -p strata-asm-sp1-guest-builder --release
fi
TARGET_ROOT="${CARGO_TARGET_DIR:-target}"
if [[ "$TARGET_ROOT" != /* ]]; then
  TARGET_ROOT="$PWD/$TARGET_ROOT"
fi

BIN_PATH="$TARGET_ROOT/$TARGET_DIR"
RUNNER_BIN="$BIN_PATH/strata-asm-runner"
if [ ! -x "$RUNNER_BIN" ]; then
  echo "Expected runner binary not found: $RUNNER_BIN" >&2
  exit 1
fi

export STRATA_ASM_RUNNER_BIN="$RUNNER_BIN"
export PATH="$BIN_PATH:$PATH"
popd > /dev/null

uv run python entry.py "$@"
