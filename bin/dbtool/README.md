# dbtool

Offline inspection and maintenance for ASM storage — the ASM counterpart to
alpen's `strata-dbtool`, but built in a layered `<domain> <resource> <verb>`
grammar instead of a flat verb-prefixed surface.

The binary is `dbtool` (crate `asm-dbtool`).

## Storage model

The runner persists into two independent sled databases:

- **Storage DB** — anchor state, aux data, full manifests, and the
  manifest-hash MMR. Backed by the `asm-storage` crate. Targeted by `asm`
  commands.
- **Proof DB** — ASM/Moho proofs, Moho state, and the remote-prover bookkeeping.
  Backed by `strata-asm-proof-db`. Targeted by the planned `moho`/`proof`
  commands.

Each invocation opens exactly the one database its command needs, so both are
selected with a single `--db <path>` flag — point it at whichever directory the
command operates on. **sled takes an exclusive lock on the directory, so the
runner must be stopped** while `dbtool` runs.

## Usage

```
dbtool [--db <path>] [--pretty] [--write] <domain> <resource> <verb> [args]
```

- Output is JSON on stdout (compact; `--pretty` for indented). Errors go to
  stderr.
- **Read-only by default.** Mutating verbs (`put`, `delete`, `prune`,
  `put-leaf`) refuse to run without `--write`.
- A commitment argument is written `<height>:<blkid_hex>`. Each record prints
  that exact string in its `block.commitment` field, so a printed commitment
  copies straight into `get`/`delete` (alongside the structured `height` and
  `blkid`).
- Records are SSZ-encoded; each `get` prints the fields we can cheaply decode
  plus an `ssz_hex` blob carrying the canonical bytes losslessly. `put` consumes
  those same bytes from `--file` (raw SSZ, not the hex text), so get → put
  round-trips once you hex-decode `ssz_hex` back to bytes — see the round-trip
  example below.

### Examples

```sh
# Highest anchor state, pretty-printed
dbtool --db ./data/asm --pretty asm state latest

# A manifest and its logs
dbtool --db ./data/asm asm manifest get 1234:6f1a...ee

# List every stored manifest commitment
dbtool --db ./data/asm asm manifest list

# Manifest-hash MMR: count, a leaf, and an inclusion proof
dbtool --db ./data/asm asm manifest-mmr count
dbtool --db ./data/asm asm manifest-mmr leaf 1234
dbtool --db ./data/asm asm manifest-mmr proof 1234 --at 2000

# Roll storage back to a known-good height (mutating → needs --write)
dbtool --db ./data/asm --write asm state prune --after 1234

# Round-trip a record: get → hex-decode its ssz_hex to raw bytes → put it back
dbtool --db ./data/asm asm manifest get 1234:6f1a...ee \
  | jq -r .ssz_hex | xxd -r -p > manifest.ssz
dbtool --db ./data/asm --write asm manifest put --file manifest.ssz
```

## Command surface

### `asm` (storage DB) — implemented

| Resource | Verbs |
|---|---|
| `asm state` | `get <commitment>` · `latest` · `list` · `put --file F` (w) · `delete <commitment>` (w) · `prune (--before\|--after) <h>` (w) |
| `asm aux` | `get <commitment>` · `list` · `put <commitment> --file F` (w) · `delete <commitment>` (w) · `prune (--before\|--after) <h>` (w) |
| `asm manifest` | `get <commitment>` · `list` · `put --file F` (w) · `delete <commitment>` (w) · `prune (--before\|--after) <h>` (w) |
| `asm manifest-mmr` | `count` · `leaf <index>` · `proof <index> [--at <leaf_count>]` · `put-leaf <height> <hash_hex>` (w) |

`(w)` = mutation, gated behind `--write`. The manifest-hash MMR is
height-indexed, so the `<index>` read by `leaf`/`proof` and the `<height>`
written by `put-leaf` are the same value — the leaf for the block at height `h`
is leaf index `h`.

### Planned (proof DB) — not yet implemented

These share the proof DB and the `strata-asm-proof-db` crate and land in a
follow-up:

- `asm proof get/list/delete` (ASM step proofs)
- `moho state` · `moho export-entries[-mmr]` · `moho proof`
- `proof mapping` · `proof status` · `proof prune` (remote-prover bookkeeping)
