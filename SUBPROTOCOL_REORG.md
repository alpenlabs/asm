# Proposal: Reorganize Subprotocol Crates by Subprotocol

## Context

ASM currently spreads each subprotocol's code across multiple top-level directories:

- [crates/subprotocols/](crates/subprotocols/) — subprotocol implementations
- [crates/txs/](crates/txs/) — tx parsers/encoders
- [crates/msgs/](crates/msgs/) — inter-subprotocol message types
- [crates/bridge-types/](crates/bridge-types/) and [crates/checkpoint-types/](crates/checkpoint-types/) — primitive types per subprotocol

To touch one subprotocol end-to-end (e.g., bridge-v1), a contributor must navigate four sibling directory trees. This obscures the conceptual unit ("a subprotocol = its types + its txs + its messages + its STF logic") and makes ownership / API boundaries hard to see.

**Goal:** colocate every crate that belongs to a subprotocol under a single directory, and adopt a uniform package-naming scheme so that the role of each crate is obvious from its name.

---

## Current Layout

```
crates/
├── bridge-types/                 # strata-bridge-types
├── checkpoint-types/             # strata-checkpoint-types-ssz
├── manifest-types/               # strata-asm-manifest-types  (ASM-wide)
├── msgs/
│   ├── bridge/                   # strata-asm-bridge-msgs
│   └── checkpoint/               # strata-asm-checkpoint-msgs
├── subprotocols/
│   ├── admin/                    # strata-asm-proto-administration
│   ├── bridge/                   # (empty placeholder dir)
│   ├── bridge-v1/                # strata-asm-proto-bridge-v1
│   ├── checkpoint/               # strata-asm-proto-checkpoint
│   ├── debug/                    # (empty placeholder dir)
│   └── debug-v1/                 # strata-asm-proto-debug-v1
└── txs/
    ├── admin/                    # strata-asm-txs-admin
    ├── bridge-v1/                # strata-asm-txs-bridge-v1
    ├── checkpoint/               # strata-asm-txs-checkpoint
    └── test-utils/               # strata-asm-txs-test-utils
```

## Proposed Layout

```
crates/
├── manifest-types/                # stays — ASM-wide, not subprotocol-specific
└── subprotocols/
    ├── txs-test-utils/            # strata-asm-proto-txs-test-utils  (shared)
    ├── admin/
    │   ├── subprotocol/           # strata-asm-proto-admin
    │   └── txs/                   # strata-asm-proto-admin-txs
    ├── bridge-v1/
    │   ├── subprotocol/           # strata-asm-proto-bridge-v1
    │   ├── txs/                   # strata-asm-proto-bridge-v1-txs
    │   ├── msgs/                  # strata-asm-proto-bridge-v1-msgs
    │   └── types/                 # strata-asm-proto-bridge-v1-types
    ├── checkpoint/
    │   ├── subprotocol/           # strata-asm-proto-checkpoint
    │   ├── txs/                   # strata-asm-proto-checkpoint-txs
    │   ├── msgs/                  # strata-asm-proto-checkpoint-msgs
    │   └── types/                 # strata-asm-proto-checkpoint-types
    └── debug-v1/
        └── subprotocol/           # strata-asm-proto-debug-v1
```

### Naming convention

Every crate that belongs to a subprotocol uses the prefix **`strata-asm-proto-<name>`** with an optional role suffix:

| Role | Suffix | Example |
|---|---|---|
| Subprotocol implementation (STF, state, handler) | *(none)* | `strata-asm-proto-bridge-v1` |
| Transaction parsing / encoding | `-txs` | `strata-asm-proto-bridge-v1-txs` |
| Inter-subprotocol messages | `-msgs` | `strata-asm-proto-bridge-v1-msgs` |
| Primitive types | `-types` | `strata-asm-proto-bridge-v1-types` |

This eliminates four naming inconsistencies in the current workspace: `strata-asm-proto-administration` (full word vs. dir name `admin`); `strata-asm-bridge-msgs` and `strata-asm-checkpoint-msgs` (missing `-proto-` infix); `strata-bridge-types` (missing `-asm-` and `-proto-`); and `strata-checkpoint-types-ssz` (trailing `-ssz` is an implementation detail leaked into the package name).

### Mapping

| Current path | New path | Old crate name | New crate name |
|---|---|---|---|
| `crates/subprotocols/admin` | `crates/subprotocols/admin/subprotocol` | `strata-asm-proto-administration` | `strata-asm-proto-admin` |
| `crates/txs/admin` | `crates/subprotocols/admin/txs` | `strata-asm-txs-admin` | `strata-asm-proto-admin-txs` |
| `crates/subprotocols/bridge-v1` | `crates/subprotocols/bridge-v1/subprotocol` | `strata-asm-proto-bridge-v1` | `strata-asm-proto-bridge-v1` *(unchanged)* |
| `crates/txs/bridge-v1` | `crates/subprotocols/bridge-v1/txs` | `strata-asm-txs-bridge-v1` | `strata-asm-proto-bridge-v1-txs` |
| `crates/msgs/bridge` | `crates/subprotocols/bridge-v1/msgs` | `strata-asm-bridge-msgs` | `strata-asm-proto-bridge-v1-msgs` |
| `crates/bridge-types` | `crates/subprotocols/bridge-v1/types` | `strata-bridge-types` | `strata-asm-proto-bridge-v1-types` |
| `crates/subprotocols/checkpoint` | `crates/subprotocols/checkpoint/subprotocol` | `strata-asm-proto-checkpoint` | `strata-asm-proto-checkpoint` *(unchanged)* |
| `crates/txs/checkpoint` | `crates/subprotocols/checkpoint/txs` | `strata-asm-txs-checkpoint` | `strata-asm-proto-checkpoint-txs` |
| `crates/msgs/checkpoint` | `crates/subprotocols/checkpoint/msgs` | `strata-asm-checkpoint-msgs` | `strata-asm-proto-checkpoint-msgs` |
| `crates/checkpoint-types` | `crates/subprotocols/checkpoint/types` | `strata-checkpoint-types-ssz` | `strata-asm-proto-checkpoint-types` |
| `crates/subprotocols/debug-v1` | `crates/subprotocols/debug-v1/subprotocol` | `strata-asm-proto-debug-v1` | `strata-asm-proto-debug-v1` *(unchanged)* |
| `crates/txs/test-utils` | `crates/subprotocols/txs-test-utils` | `strata-asm-txs-test-utils` | `strata-asm-proto-txs-test-utils` |

**Crates that stay put:**
- [crates/manifest-types/](crates/manifest-types/) — ASM-wide (depended on by `common`, `worker`, `checkpoint-types`); not owned by any one subprotocol. Keep current path and name `strata-asm-manifest-types`.
- All non-subprotocol crates (`common`, `params`, `logs`, `proof/`, `spec`, `stf`, `worker`, `rpc`, `test-utils/`, etc.) untouched.

**Deleted directories** (after move): `crates/bridge-types/`, `crates/checkpoint-types/`, `crates/msgs/`, `crates/txs/`, `crates/subprotocols/bridge/` (empty placeholder), `crates/subprotocols/debug/` (empty placeholder).

### Cross-subprotocol coupling — explicit acknowledgement

Several "owned" crates are consumed by sibling subprotocols. After the move:
- `strata-asm-proto-bridge-v1-types` — consumed by `bridge-v1`, `checkpoint`, `debug-v1` subprotocols.
- `strata-asm-proto-bridge-v1-msgs` — consumed by `admin`, `bridge-v1`, `checkpoint`, `debug-v1`.
- `strata-asm-proto-checkpoint-msgs` — consumed by `admin`, `bridge-v1`, `checkpoint`.

This coupling is real and pre-exists the refactor. Co-locating these crates with their *originating* subprotocol makes the dependency arrows visible in the directory tree rather than hidden under a flat `msgs/`. Note: if a `bridge-v2` ever ships, the v1-versioned `types`/`msgs` paths will still be the canonical home for the cross-subprotocol primitives until they're explicitly forked.

---

## Files to Modify

### Workspace root
- [Cargo.toml](Cargo.toml):
  - `[workspace] members` (lines 4-42) — replace each old path with its new path.
  - `[workspace.dependencies]` (lines 55-86) — rename keys and update `path = "..."` for every moved crate.
  - `[patch."https://github.com/alpenlabs/alpen.git"]` (lines 175-195) — same renames + path updates. **Important:** because this patch overrides crates that `alpen.git` publishes under their *current* names (`strata-asm-bridge-msgs`, `strata-checkpoint-types-ssz`, etc.), renaming our local crates means the patch entries no longer match anything in the upstream registry. Need to confirm with the team how alpen.git transitively pulls these — the rename may break the patch and require either (a) keeping alias entries, (b) coordinating an upstream rename, or (c) deferring the rename portion until upstream catches up. **This is the single highest-risk item in the proposal.**

### Per moved crate
For each moved crate:
1. Move the directory (`git mv`).
2. Update `package.name` in its own `Cargo.toml`.
3. Update its `[dependencies]` entries that reference *other renamed* sibling crates (these go through `[workspace.dependencies]` keys, so the key name changes).
4. `build.rs` files in `checkpoint-types` and `manifest-types` reference the local `ssz/` directory by relative path — preserved by moving the directory together; no edits needed.

### Every dependent crate
Each crate that imports a renamed package needs:
1. `Cargo.toml` `[dependencies]` and `[dev-dependencies]` keys updated.
2. Rust source: `use strata_bridge_types::...` → `use strata_asm_proto_bridge_v1_types::...` etc. across `crates/`, `tests/`, `bin/`, `guest-builder/`.

Approximate scope of source-import sweep (from earlier exploration):
- `strata-bridge-types` → 6 dependents
- `strata-checkpoint-types-ssz` → 2 dependents
- `strata-asm-bridge-msgs` → 4 dependents
- `strata-asm-checkpoint-msgs` → 3 dependents
- `strata-asm-txs-*` → primarily their matching subprotocol + tests/binaries

`cargo fix` cannot rewrite these — they're cross-crate path renames. Use a scripted `sd`/`sed` sweep or rust-analyzer rename in IDE, then `cargo check` to verify.

### CI / scripts
Search outside Cargo.toml for hardcoded paths:
```
rg -F 'crates/bridge-types|crates/checkpoint-types|crates/msgs/|crates/txs/|crates/subprotocols/'
```
Likely hits in `.github/workflows/*.yml`, `Justfile`/`Makefile` if present, codecov config. Update those.

---

## Execution Order (when approved)

Single PR — partial states leave the workspace unbuildable. Suggested commit sequence within the PR for review legibility:

1. **Move-only commit:** `git mv` every directory; update workspace `members` + `path`s; do NOT rename packages yet. Workspace must build.
2. **Rename commit per subprotocol** (bridge-v1, then checkpoint, then admin, then misc):
   - Update `package.name` in moved crates.
   - Update `[workspace.dependencies]` keys.
   - Update `[patch.alpen.git]` keys.
   - Sweep source: `Cargo.toml` deps + `use` paths in dependents.
   - `cargo check --workspace` after each subprotocol to localize breakage.
3. **Cleanup commit:** delete now-empty placeholder dirs, sweep CI/scripts.

---

## Verification

- `cargo check --workspace --all-targets` — no errors, no new warnings.
- `cargo test --workspace` — all existing tests pass.
- `cargo build -p asm-runner` and `cargo build -p prover-perf` — both binaries link.
- SP1 guest build still works (run whatever the existing `guest-builder/sp1` build command is).
- `git grep -nE 'strata[-_](bridge|checkpoint)[-_]types|strata[-_]asm[-_](bridge|checkpoint)[-_]msgs|strata[-_]asm[-_]txs[-_]'` — should return zero hits across the repo (stale identifier sweep).
- `rg -F 'crates/bridge-types|crates/checkpoint-types|crates/msgs/|crates/txs/'` — zero hits outside the renamed `[patch]` section.
- Diff against `main`: confirm `manifest-types` and all non-subprotocol crates are untouched.

---

## Out of Scope

- Moving/renaming `manifest-types` or any non-subprotocol crate.
- Restructuring `lib.rs` / module layout *inside* any moved crate.
- Splitting `strata-asm-proto-bridge-v1-types` into a non-versioned bridge primitives crate (could revisit when `bridge-v2` is on the horizon).
- Coordinating the upstream rename with `alpenlabs/alpen.git` — surfaced as a risk above; handle separately if needed.
