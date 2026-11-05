#!/usr/bin/env bash

# Download the Moho recursive proof guest ELF from a moho GitHub release.
#
# The ELF lands in guest-builder/sp1/generated/, next to the ASM guest ELF. The release tag
# defaults to MOHO_GUEST_TAG below, the deployed Moho guest, which is pinned separately from the
# moho crates in Cargo.toml: the crates can move (for example a dependency bump) while the guest
# stays put, as long as the encodings the host produces for it don't change. Set MOHO_TAG to use
# another release.
#
# Usage:
#   ./contrib/fetch_moho_artifacts.sh
#   MOHO_TAG=v0.5.0 ./contrib/fetch_moho_artifacts.sh

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out_dir="$repo_root/guest-builder/sp1/generated"

# The Moho guest this ASM release proves with. Change it only when deciding to upgrade the
# deployed Moho guest, not when bumping the moho crates.
MOHO_GUEST_TAG="v0.4.0"

tag="${MOHO_TAG:-$MOHO_GUEST_TAG}"

base_url="https://github.com/alpenlabs/moho/releases/download/$tag"
echo "Fetching the Moho guest ELF from $base_url"

# Download into a scratch dir first so a failed download never leaves a partial ELF behind.
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

for file in moho.elf SHA256SUMS; do
    if ! curl -fsSL --proto '=https' --tlsv1.2 -o "$tmp_dir/$file" "$base_url/$file"; then
        echo "ERROR: could not download $file. Does the moho $tag release have guest artifacts?" >&2
        exit 1
    fi
done

(cd "$tmp_dir" && grep ' moho\.elf$' SHA256SUMS | shasum -a 256 -c)

mkdir -p "$out_dir"
mv "$tmp_dir/moho.elf" "$out_dir/"
echo "Wrote $out_dir/moho.elf"
