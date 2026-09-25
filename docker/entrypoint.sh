#!/bin/sh
# Entrypoint for the strata-asm-runner Docker container.
#
# Expected volume mounts:
#   /app/config.toml      - runner configuration (TOML)
#   /app/asm-params.json  - ASM params (JSON)
#
# Override the paths with CONFIG_FILE / PARAMS_FILE; --config and --params are
# already passed, so they cannot be given as extra arguments. Any other
# arguments are forwarded to the strata-asm-runner binary. Kept POSIX sh
# because deployments invoke it as `sh /usr/local/bin/entrypoint.sh`.

set -eu

CONFIG_FILE="${CONFIG_FILE:-/app/config.toml}"
PARAMS_FILE="${PARAMS_FILE:-/app/asm-params.json}"

for required in "$CONFIG_FILE" "$PARAMS_FILE"; do
    [ -f "$required" ] || { echo "ERROR: $required not found; mount it, e.g. -v /path/on/host:$required:ro" >&2; exit 1; }
done

exec /usr/local/bin/strata-asm-runner --config "$CONFIG_FILE" --params "$PARAMS_FILE" "$@"
