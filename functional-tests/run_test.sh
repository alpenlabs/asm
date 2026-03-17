#!/bin/bash
set -euo pipefail

cd "$(dirname "$(realpath "$0")")"
source env.bash

# Set finite fd limit so subprocesses inherit a sane value.
ulimit -n 10240

pushd .. > /dev/null
if [ "${CARGO_DEBUG:-1}" = "0" ]; then
  CARGO_ARGS="--release"
  BIN_PATH="$(realpath target/release/)"
else
  CARGO_ARGS=""
  BIN_PATH="$(realpath target/debug/)"
fi

cargo build --bin strata-asm-runner $CARGO_ARGS
export PATH="$BIN_PATH:$PATH"
popd > /dev/null

uv run python entry.py "$@"
