#!/bin/bash
set -euo pipefail

cd "$(dirname "$(realpath "$0")")"
source env.bash

# Set finite fd limit so subprocesses inherit a sane value.
ulimit -n 10240

pushd .. > /dev/null
if [ "${CARGO_DEBUG:-1}" = "0" ]; then
  CARGO_ARGS=(--release)
  TARGET_DIR="release"
else
  CARGO_ARGS=()
  TARGET_DIR="debug"
fi

cargo build --bin strata-asm-runner ${CARGO_ARGS[@]+"${CARGO_ARGS[@]}"}
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
