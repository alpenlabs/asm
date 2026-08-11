#!/usr/bin/env bash

# Check that every tracked path can be checked out on Windows.
#
# Windows rejects some paths that Unix accepts. Git on Windows refuses to write
# them, so `git clone` and `cargo` git dependencies fail with
# "error: invalid path ...". That breaks Windows users even though the code
# itself is fine, and the failure only shows up downstream, long after merge.
#
# The rules checked here:
#
#   1. Reserved device names (CON, PRN, AUX, NUL, COM1-9, LPT1-9) as any path
#      component. The extension does not help: `aux.rs` is just as reserved as
#      `aux`. The superscript forms (COM¹, LPT²) are reserved too.
#   2. Reserved characters: < > : " \ | ? * and control characters 0-31.
#   3. A path component ending in a space or a period.
#   4. Paths that differ only by case. Windows and macOS filesystems are
#      case-insensitive, so one file silently overwrites the other.
#
# Usage:
#   ./contrib/check_windows_paths.sh

set -euo pipefail

# Reserved device names, uppercased. Matched against a component with its
# extension stripped.
reserved='CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³]'

files=$(git ls-files)

# 1. Reserved device names in any path component.
bad_names=$(printf '%s\n' "$files" | awk -F/ -v re="^($reserved)\$" '
    {
        for (i = 1; i <= NF; i++) {
            name = $i
            sub(/\..*$/, "", name)   # Windows reserves the name before the first dot
            if (toupper(name) ~ re) {
                print "  " $0 "  (component: " $i ")"
                break
            }
        }
    }')

# 2. Reserved characters. Forward slash is the separator, so it is not checked.
bad_chars=$(printf '%s\n' "$files" | grep '[<>:"\\|?*[:cntrl:]]' | sed 's/^/  /' || true)

# 3. Trailing space or period in a path component.
bad_trailing=$(printf '%s\n' "$files" | grep -E '[ .](/|$)' | sed 's/^/  /' || true)

# 4. Paths differing only by case.
bad_case=$(printf '%s\n' "$files" | tr 'A-Z' 'a-z' | sort | uniq -d | sed 's/^/  /' || true)

status=0

if [ -n "$bad_names" ]; then
    echo "ERROR: Paths using a Windows reserved device name."
    echo "       These cannot be checked out on Windows. Rename them, for"
    echo "       example 'aux.rs' -> 'aux_input.rs'."
    echo ""
    echo "$bad_names"
    echo ""
    status=1
fi

if [ -n "$bad_chars" ]; then
    echo 'ERROR: Paths containing a character Windows reserves (< > : " \ | ? * or a control character).'
    echo ""
    echo "$bad_chars"
    echo ""
    status=1
fi

if [ -n "$bad_trailing" ]; then
    echo "ERROR: Paths with a component ending in a space or a period."
    echo "       Windows strips these, so the file lands under a different name."
    echo ""
    echo "$bad_trailing"
    echo ""
    status=1
fi

if [ -n "$bad_case" ]; then
    echo "ERROR: Paths that differ only by case."
    echo "       On Windows and macOS one silently overwrites the other."
    echo ""
    echo "$bad_case"
    echo ""
    status=1
fi

if [ "$status" -ne 0 ]; then
    exit 1
fi

echo "OK: All tracked paths are valid on Windows."
exit 0
