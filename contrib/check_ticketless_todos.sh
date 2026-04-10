#!/usr/bin/env bash

# Check that all TODO/FIXME/HACK comments include a ticket reference.
#
# Valid:   TODO(STR-2105), FIXME(#123), HACK(PROJ-42)
# Invalid: TODO, TODO:, FIXME without a ticket
#
# Usage:
#   ./contrib/check_ticketless_todos.sh

set -euo pipefail

# Scan all source files for TODO/FIXME/HACK without ticket references.
violations=$(grep -rn \
    --include='*.rs' --include='*.py' --include='*.sh' \
    --include='*.toml' --include='*.yml' --include='*.yaml' \
    --exclude-dir='target' --exclude-dir='.venv' \
    -E '\b(TODO|FIXME|HACK)\b' . \
    | grep -vE '(TODO|FIXME|HACK)\([A-Za-z]+-[0-9]+\)' \
    | grep -vE '(TODO|FIXME|HACK)\(#[0-9]+\)' \
    | grep -vE 'check_ticketless_todos\.sh' \
    | grep -vE 'TODO_TICKETS\.md' \
    || true)

if [ -n "$violations" ]; then
    echo "ERROR: Found TODO/FIXME/HACK comments without ticket references."
    echo "       Use the format TODO(PROJ-123) or FIXME(#456) instead."
    echo ""
    echo "$violations"
    exit 1
fi

echo "OK: All TODO/FIXME/HACK comments have ticket references."
exit 0
