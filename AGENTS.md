# AGENTS.md

Guidance for AI coding agents working in this repository.

## Project Overview

Strata ASM (Anchor State Machine) folds Bitcoin blocks into an `AnchorState`. Each block runs
through a deterministic state transition function (STF) that routes SPS-50 tagged
transactions to subprotocols (admin, checkpoint, bridge) and emits a manifest of logs.
The STF runs natively in a worker and inside an SP1 guest for proofs.

Downstream repos depend on this one. [alpen](https://github.com/alpenlabs/alpen) embeds the
ASM worker and reads manifests and logs. [strata-bridge](https://github.com/alpenlabs/strata-bridge)
runs `strata-asm-runner` and calls its RPC. Changes to public types, logs, RPC, config, or the
params file are breaking for them.

Contributor docs are in [`docs/`](docs/README.md). Read
[`docs/architecture.md`](docs/architecture.md) before changing the STF or the workers.

## Commands

```bash
just fmt                  # format Rust
just lints                # every lint and format check CI runs
just unit-test            # cargo nextest over the workspace
just doctest
cargo nextest run --locked --all-features -p <crate>       # one crate
cargo test --locked -p integration-tests --test asm_admin  # one integration test target
cd functional-tests && ./run_test.sh fn_asm_block_test     # one functional test
```

`just lints` needs `taplo` and `uv`. Unit and integration tests need `bitcoind` on `PATH`.
CI uses Bitcoin Core 30.2. Functional tests need `bitcoind` and `uv`; see
[`functional-tests/README.md`](functional-tests/README.md).

## Architecture

See [`docs/layout.md`](docs/layout.md) for every crate.

- `crates/common`, `crates/state`, `crates/stf`, `crates/spec`: STF traits, state, and
  transition. These build into the guest.
- `crates/subprotocols/`: one directory per subprotocol, split into `types`, `txs`, `msgs`,
  and `subprotocol` crates.
- `crates/worker`, `crates/storage`: the ASM worker and its sled stores.
- `crates/extensions/moho/`, `crates/extensions/prover/`: Moho state and proof workers.
- `crates/proof/statements`, `guest-builder/sp1`: the ASM step proof and its SP1 guest.
- `bin/asm-runner`: wires bitcoind, workers, storage, and RPC.
- `tests/`: Rust integration tests. `functional-tests/`: Python tests against the runner.

## Testing

- Add tests for behavior changes and regressions. Test public behavior and protocol
  invariants, not private details.
- Keep unit tests free of external processes. Use `tests/` for anything that needs
  `bitcoind` or running workers, and `functional-tests/` for the runner binary.
- Reuse shared fixtures and wait helpers. Add missing ones to `tests/harness` (the
  `AdminExt`, `BridgeExt`, and `CheckpointExt` traits) instead of copying them into a test.
- Don't re-test what an upstream library already guarantees.
- Pin consensus encodings with fixed vectors. SSZ byte-layout tests and the
  `test-data/baseline` vectors fail on purpose when an encoding moves. Never regenerate a
  vector just to make a test pass.
- Exercise the real assembly or encoding path together with its verification or decoding
  path.
- Make tests deterministic. Wait on conditions, not sleeps. Prefer `assert_eq!` over
  `assert!` when comparing values.
- Run the affected crate first, then widen.

## Commit and PR Style

- Use Conventional Commits with a scope, for example `fix(checkpoint): ...`. Add `!` for a
  breaking change, for example `feat(admin)!: ...`.
- Keep each commit to one logical change that builds on its own.
- Follow [`.github/PULL_REQUEST_TEMPLATE.md`](.github/PULL_REQUEST_TEMPLATE.md).
- Keep PRs focused. Put unrelated refactors, migrations, and cleanup in their own PR.
- Run `just fmt`, `just lints`, and the tests for what you changed. Don't add new warnings.
  Say in the PR what you could not run.

## Notes

- **Determinism**: STF and subprotocol code must not depend on wall-clock time, environment
  variables, I/O, unseeded randomness, or `HashMap` iteration order. Data from outside the
  block comes in as aux data, requested in `pre_process_txs` and verified by the STF.
- **Panics in the STF**: subprotocols skip invalid transactions; they don't fail the block. A
  panic marks a broken invariant, such as a missing or wrong-version section, and halts the
  chain on purpose. Don't turn it into an error without a reason.
- **SSZ schemas**: types in `crates/state`, `crates/manifest-types`,
  `crates/btc-verification`, and `crates/subprotocols/checkpoint/*` are generated from `.ssz`
  files by `build.rs`. Edit the schema, not the generated code. Other crates derive SSZ
  directly.
- **Consensus changes**: changing an encoded field, its order, a tag, a hash input, or a
  section's `State` is a consensus change. Mark it breaking with `!`. Once a chain runs the
  old rules, the change has to ship as a new spec; see
  [`docs/asm-upgrade-development.md`](docs/asm-upgrade-development.md).
- **Guest**: `guest-builder/sp1/guest-asm` is its own workspace with its own `Cargo.lock`.
  Update that lockfile when you change a dependency the guest uses. Set `BUILD_ELF=1` to
  build the guest. Output in `guest-builder/sp1/generated/` is not tracked and survives
  `cargo clean`.
- **TODOs**: every `TODO` or `FIXME` needs a ticket, for example `TODO(STR-1234): ...`.
  `just check-todos` runs the same check as CI.
- **Dependencies**: declare versions in the root `Cargo.toml` and use `workspace = true`.
  `.cargo/config.toml` refuses crates.io versions less than 14 days old.

## Code Style

### Design and API Boundaries

- Give each crate one focused job. Keep protocol and STF logic independent of RPC,
  persistence, orchestration, and runtime policy.
- Take dependencies through narrow context traits. Keep concrete databases, services, and
  clients in the integration layer.
- Keep binaries to loading config, opening resources, setting up observability, and
  launching library services.
- Encode invariants in types. Use typed IDs and domain values inside, and convert to strings
  only at boundaries.
- Don't expose public fields on nontrivial domain structs. Provide constructors, accessors,
  and operations that keep invariants. Plain data carriers with no invariants may have public
  fields.
- Keep constructors to field assembly and basic checks. Give substantial setup or I/O its
  own named function.
- Reuse the owning implementation of protocol algorithms, validation, codecs, and test
  helpers. Don't duplicate them at call sites.

### Serialization

- Use the codec the boundary already uses. Don't add a wire or storage format without a
  compatibility and migration plan.
- Keep domain types separate from wire or storage types when their fields or invariants
  differ. Validate at the conversion.

### Ownership and Allocation

- Borrow to inspect, take ownership when you need it, and use `&mut` for in-place updates.
- Avoid needless clones, temporary collections, repeated encoding buffers, and `Arc` with no
  sharing need.
- Prefer plain ownership over shared mutable state. If you must share, keep the lock scope
  small.

### Naming and Documentation

- `snake_case` for files, modules, functions, variables, and serialized fields.
  `UpperCamelCase` for types and traits. `SCREAMING_SNAKE_CASE` for constants.
- Use precise verbs for functions that do work. Use bare nouns for cheap accessors, `as_` for
  cheap borrowed views, `to_` for allocating conversions, and `with_` for builders.
- Import with `use` at the top of the file. CI denies absolute paths through
  `clippy::absolute_paths`.
- Give public items a one-sentence summary. Use intra-doc links such as ``[`SomeType`]``.
  Document invariants, ordering, preconditions, panics, and design reasons.
- Comments explain why, not what.
- Implement `Default` only when the type has a real domain default. Add `const` only when
  compile-time use is part of the API.

### Error Handling

| Context | Approach |
| --- | --- |
| Invalid input or recoverable failure | `Result` with structured variants |
| Expected absence | `Option`, not a sentinel or default |
| Broken internal invariant | `assert!`, `unwrap()`, or `expect("the invariant")` |
| Library errors | an error `enum` or `struct` with `thiserror` |
| Application boundary errors | `anyhow` with context |

- Panics mean bugs or broken invariants, never normal runtime errors. Document them in a
  `# Panics` section on public APIs.
- Keep error variants and source chains distinct across layers. Don't collapse failures into
  strings or catch-all variants.
- Error messages describe the failure without an `error` prefix.

### Async and Concurrency

- Never block an async executor thread. Use an async API or the runtime's blocking-task
  facility.
- Don't hold a lock guard across `.await`.
- Workers own their state. Expose commands and status through a handle.
- Make shutdown and cancellation explicit. Partial work must not leave persisted state
  inconsistent.

### Observability

- Use structured `tracing` fields, not interpolated strings. Don't repeat context the module
  or span already gives.
- `error!` for unrecoverable failures, `warn!` for unexpected conditions someone should act
  on, `info!` for lifecycle events, `debug!` and `trace!` for detail.
- Expected lag, graceful shutdown, irrelevant traffic, and rejected untrusted input should
  not warn.
- Keep pure STF code free of operational logs when the caller can report with better
  context.
