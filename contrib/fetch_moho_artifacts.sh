#!/usr/bin/env bash

# Download the Moho recursive proof guest ELF and its predicate from a moho GitHub release.
#
# The files land in guest-builder/sp1/elfs/, next to the ASM guest ELF. The release tag defaults
# to the moho tag this workspace depends on in Cargo.toml, so the ELF matches the moho crates the
# host links against. Set MOHO_TAG to use another release.
#
# moho publishes the predicate as plain text in moho-predicate.txt. This script writes it out as
# moho-vk.json, a JSON string, which is the form asm-vk.json uses and the bridge reads.
#
# Usage:
#   ./contrib/fetch_moho_artifacts.sh
#   MOHO_TAG=v0.4.0 ./contrib/fetch_moho_artifacts.sh

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out_dir="$repo_root/guest-builder/sp1/elfs"

tag="${MOHO_TAG:-$(sed -n 's/^moho-types = .*tag = "\([^"]*\)".*/\1/p' "$repo_root/Cargo.toml")}"
if [ -z "$tag" ]; then
    echo "ERROR: could not read the moho tag from Cargo.toml; set MOHO_TAG." >&2
    exit 1
fi

base_url="https://github.com/alpenlabs/moho/releases/download/$tag"
echo "Fetching Moho guest artifacts from $base_url"

# Download into a scratch dir first so a failed download never leaves a mismatched ELF and vk.
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

for file in moho.elf moho-predicate.txt moho-vkey-hash.txt SHA256SUMS; do
    if ! curl -fsSL --proto '=https' --tlsv1.2 -o "$tmp_dir/$file" "$base_url/$file"; then
        echo "ERROR: could not download $file. Does the moho $tag release have guest artifacts?" >&2
        exit 1
    fi
done

(cd "$tmp_dir" && shasum -a 256 -c SHA256SUMS)

predicate="$(cat "$tmp_dir/moho-predicate.txt")"
if ! [[ "$predicate" =~ ^Sp1Groth16:[0-9a-f]+$ ]]; then
    echo "ERROR: moho-predicate.txt is not an Sp1Groth16 predicate." >&2
    exit 1
fi
printf '"%s"' "$predicate" > "$tmp_dir/moho-vk.json"

mkdir -p "$out_dir"
mv "$tmp_dir/moho.elf" "$tmp_dir/moho-vk.json" "$out_dir/"
echo "Wrote $out_dir/moho.elf and $out_dir/moho-vk.json"
