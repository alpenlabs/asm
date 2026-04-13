#!/usr/bin/env bash

# Check that all TODO/FIXME comments include a ticket reference.
#
# Valid:   TODO(STR-2105), FIXME(#123)
# Invalid: TODO, TODO:, FIXME without a ticket
#
# Usage:
#   ./contrib/check_ticketless_todos.sh

set -euo pipefail

# Scan all source files for TODO/FIXME without ticket references.
violations=$(grep -rn \
    --include='*.rs' --include='*.py' --include='*.sh' \
    --include='*.toml' --include='*.yml' --include='*.yaml' \
    --exclude-dir='target' --exclude-dir='.venv' \
    -E '\b(TODO|FIXME)\b' . \
    | grep -vE '(TODO|FIXME)\([A-Za-z]+-[0-9]+\)' \
    | grep -vE '(TODO|FIXME)\(#[0-9]+\)' \
    | grep -vE 'check_ticketless_todos\.sh' \
    | grep -vE 'TODO_TICKETS\.md' \
    || true)

if [ -n "$violations" ]; then
    echo "ERROR: Found TODO/FIXME comments without ticket references."
    echo "       Use the format TODO(PROJ-123) or FIXME(#456) instead."
    echo ""
    echo "$violations"
    exit 1
fi

echo "OK: All TODO/FIXME comments have ticket references."
exit 0
