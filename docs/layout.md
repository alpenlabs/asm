# Repository layout

This page lists each crate and what it does. Package names are in parentheses where they differ from the
directory name. Each crate's `lib.rs` doc comment has more.

## State transition

These crates make up the STF. They build for the zkVM guest, so they do no I/O.

- [`crates/common`](../crates/common) (`strata-asm-common`): the `Subprotocol`, `AsmSpec`,
  and `Stage` traits, the aux data framework, and section helpers. Re-exports the state
  types.
- [`crates/state`](../crates/state) (`strata-asm-state`): the `AnchorState` SSZ schema.
- [`crates/stf`](../crates/stf) (`strata-asm-stf`): `compute_asm_transition` and
  `pre_process_asm`.
- [`crates/spec`](../crates/spec) (`strata-asm-spec`): the concrete specs and genesis
  construction. The `host` feature adds the compiled spec catalog for native callers.
- [`crates/params`](../crates/params) (`strata-asm-params`): `AsmParams`, the genesis input.
- [`crates/btc-verification`](../crates/btc-verification) (`strata-btc-verification`): PoW
  header checks and block integrity checks.
- [`crates/manifest-types`](../crates/manifest-types) (`strata-asm-manifest-types`):
  `AsmManifest` and log entry types.
- [`crates/logs`](../crates/logs) (`strata-asm-logs`): typed log payloads.

## Subprotocols

Under [`crates/subprotocols`](../crates/subprotocols). See
[subprotocols.md](subprotocols.md) for how each one is split into crates.

- `admin/` (ID 0): multisig governance. `threshold-sig` holds the M-of-N signature scheme.
- `checkpoint/` (ID 1): OL checkpoint verification. `verification` holds the logic that does
  not depend on the subprotocol trait.
- `bridge/` (ID 2): deposits, operators, and withdrawals. `state` holds the bridge state.
- `txs-test-utils/`: helpers for building tagged transactions in tests.

## Services

- [`crates/worker`](../crates/worker) (`strata-asm-worker`): the ASM worker. Runs the STF
  per block, handles sync and reorgs, and resolves aux data.
- [`crates/storage`](../crates/storage) (`asm-storage`): sled stores for the ASM worker.
- [`crates/extensions/moho/worker`](../crates/extensions/moho/worker) and
  [`storage`](../crates/extensions/moho/storage): derives and stores `MohoState` per block.
- [`crates/extensions/prover/worker`](../crates/extensions/prover/worker),
  [`storage`](../crates/extensions/prover/storage), and
  [`types`](../crates/extensions/prover/types): runs ASM and Moho proofs and stores them.
- [`crates/rpc`](../crates/rpc) (`strata-asm-rpc`): the `strata_asm` JSON-RPC traits and
  types.

## Proofs

- [`crates/proof/statements`](../crates/proof/statements) (`strata-asm-proof-impl`): the ASM
  step proof, as a Moho program.
- [`guest-builder/sp1`](../guest-builder/sp1) (`strata-asm-sp1-guest-builder`): builds the
  SP1 guest into `generated/`. The guest itself, `guest-asm/`, is a separate workspace with
  its own `Cargo.lock`.

## Binaries

- [`bin/asm-runner`](../bin/asm-runner) (`strata-asm-runner`): the node. Wires bitcoind, the
  workers, storage, and RPC.
- [`bin/dbtool`](../bin/dbtool) (`asm-dbtool`, binary `dbtool`): offline database tool.
- [`bin/prover-perf`](../bin/prover-perf) (`strata-asm-prover-perf`): SP1 guest performance
  reports, and a check that the guest and native STF agree.

## Tests

- [`tests`](../tests) (`integration-tests`): Rust tests that drive the workers against a
  regtest `bitcoind`. Also builds `asm-test-cli`, which the functional tests use.
- [`crates/test-utils`](../crates/test-utils): shared fixtures and generators.
- [`functional-tests`](../functional-tests): Python tests that run `strata-asm-runner`
  against `bitcoind`.

## Other

- [`contrib`](../contrib): CI check scripts and the Moho artifact fetcher.
- [`docker`](../docker): the runner image.

Shared protocol types come from
[strata-common](https://github.com/alpenlabs/strata-common) and the proof framework from
[moho](https://github.com/alpenlabs/moho). Both are pinned by tag in the root `Cargo.toml`.
