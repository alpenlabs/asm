# dbtool

Offline inspection and maintenance for ASM storage — the ASM counterpart to
alpen's `strata-dbtool`, but built in a layered `<domain> <resource> <verb>`
grammar instead of a flat verb-prefixed surface.

The binary is `dbtool` (crate `asm-dbtool`).

## Storage model

The runner persists into two independent sled databases:

- **Storage DB** — anchor state, aux data, full manifests, and the
  manifest-hash MMR. Backed by the `asm-storage` crate. Selected with
  `--storage-db <path>`.
- **Proof DB** — ASM/Moho proofs, Moho state, and the remote-prover bookkeeping.
  Backed by `strata-asm-proof-db`. Will be selected with `--proof-db <path>`.

Each invocation opens exactly the one database its command needs. **sled takes
an exclusive lock on the directory, so the runner must be stopped** while
`dbtool` runs.

## Usage

```
dbtool [--storage-db <path>] [--pretty] [--write] <domain> <resource> <verb> [args]
```

- Output is JSON on stdout (compact; `--pretty` for indented). Errors and write
  confirmations go to stderr.
- **Read-only by default.** Mutating verbs (`put`, `delete`, `prune`,
  `put-leaf`) refuse to run without `--write`.
- A commitment argument is written `<height>:<blkid_hex>` — exactly the shape
  the tool prints in each record's `block` field.
- Records are SSZ-encoded; each `get` prints the fields we can cheaply decode
  plus an `ssz_hex` blob carrying the canonical bytes losslessly. `put` consumes
  that same encoding from `--file` (raw SSZ bytes), so get → put round-trips.

### Examples

```sh
# Highest anchor state, pretty-printed
dbtool --storage-db ./data/asm --pretty asm state latest

# A manifest and its logs
dbtool --storage-db ./data/asm asm manifest get 1234:6f1a...ee

# List every stored manifest commitment
dbtool --storage-db ./data/asm asm manifest list

# Manifest-hash MMR: count, a leaf, and an inclusion proof
dbtool --storage-db ./data/asm asm manifest-mmr count
dbtool --storage-db ./data/asm asm manifest-mmr leaf 1234
dbtool --storage-db ./data/asm asm manifest-mmr proof 1234 --at 2000

# Roll storage back to a known-good height (mutating → needs --write)
dbtool --storage-db ./data/asm --write asm state prune --after 1234
```

## Command surface

### `asm` (storage DB) — implemented

| Resource | Verbs |
|---|---|
| `asm state` | `get <commitment>` · `latest` · `list` · `put --file F` (w) · `delete <commitment>` (w) · `prune (--before\|--after) <h>` (w) |
| `asm aux` | `get <commitment>` · `list` · `put <commitment> --file F` (w) · `delete <commitment>` (w) · `prune (--before\|--after) <h>` (w) |
| `asm manifest` | `get <commitment>` · `list` · `put --file F` (w) · `delete <commitment>` (w) · `prune (--before\|--after) <h>` (w) |
| `asm manifest-mmr` | `count` · `leaf <index>` · `proof <index> [--at <leaf_count>]` · `put-leaf <height> <hash_hex>` (w) |

`(w)` = mutation, gated behind `--write`.

### Planned (proof DB) — not yet implemented

These share the proof DB and the `strata-asm-proof-db` crate and land in a
follow-up:

- `asm proof get/list/delete` (ASM step proofs)
- `moho state` · `moho export-entries[-mmr]` · `moho proof`
- `proof mapping` · `proof status` · `proof prune` (remote-prover bookkeeping)
