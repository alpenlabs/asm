# ASM upgrade development

Use this guide to add an ASM spec, register its execution and proof artifacts, and run the
repository validation checks.

## Authority model

- The parent Moho state's `next_predicate` authorizes the program for the next block. Local
  configuration only declares which authorized programs this node supports.
- The block that enacts an upgrade still runs under its parent's predicate, so the old spec
  executes it. Its manifest carries the `AsmStfUpdate` log, and the next block runs under the new
  predicate.
- An unknown predicate stops native execution with `UnsupportedExecutionPredicate` before the
  child block is processed. An authorized predicate with no loaded proof artifact stops proving
  without dropping queued work.
- Historical proof jobs resolve their own parent's predicate, not the current tip's.
- The Moho recursive program is fixed per node. Only the ASM step program changes across upgrades.

## Adding a concrete spec and release

1. **Implement the spec.** Implement `AsmSpec` with a unique `SpecId`, a deterministic `prepare`,
   ordered `call_subprotocols`, and spec-owned genesis construction.
   - `prepare` receives the committed parent and must not mutate it.
   - Check the source `spec_id` and each section's schema version explicitly. Don't infer
     migration from a numeric configuration value.
   - `prepare` currently panics on an unsupported source. Keep the set of supported predecessors
     explicit, and don't skip versions without a tested edge.
2. **Register it in the native catalog.** Add a `CompiledSpec` variant in
   `crates/spec/src/host.rs`, and extend `CompiledSpec::resolve`, `construct_genesis_state`, and
   `register_execution`. Native callers (the runner and OL) get it through
   `build_execution_registry`.
3. **Register the proof host.** Add the matching arm to `load_asm_host` in
   `bin/asm-runner/src/bootstrap.rs`. It is kept out of `strata-asm-spec::host` so native callers
   take no prover dependency.
4. **Build its guest.** Each guest compiles one concrete spec
   (`guest-builder/sp1/guest-asm/src/main.rs`); the witness cannot select rules. Retain old
   guests while delayed jobs or reorgs may still need them. Record the source commit,
   `Cargo.lock`, toolchain, ELF digest, derived predicate, and spec ID together.

   ```sh
   cargo metadata --locked --offline --manifest-path guest-builder/sp1/guest-asm/Cargo.toml --format-version 1 > /dev/null
   cargo clean -p strata-asm-sp1-guest-builder
   BUILD_ELF=1 BUILD_VKEY=1 cargo build --locked --release -p strata-asm-sp1-guest-builder
   ```

   The metadata preflight catches stale guest lockfiles before SP1's own metadata discovery
   rewrites them. Existing files in `guest-builder/sp1/generated` survive `cargo clean`, so a
   successful host build does not prove that a new guest was built. Compare the actual ELF and
   verifying key with the release record. Deriving a key from arbitrary bytes does not show that
   the ELF implements the declared spec.
5. **Configure execution.** Add an `[[execution.targets]]` entry `{ predicate, spec_id }`.
   `execution.genesis_spec_id` names the spec the chain starts under, and the runner takes the
   genesis predicate from its target entry. It stays fixed across upgrades. Each predicate and
   each spec ID appears at most once, so a new predicate for unchanged rules still needs a new
   spec ID.
6. **Configure proving, if enabled.** Add `[[orchestrator.asm_artifacts]]` entries
   `{ spec_id, source }`, where `source` is `{ kind = "sp1", elf_path }` or
   `{ kind = "native", signing_key }`. Each spec ID must also appear in `[execution].targets`,
   which supplies its predicate. Every artifact is loaded at startup, and `bind_expected` checks
   the predicate derived from it against that one, so a wrong ELF or key fails boot.
   `orchestrator.moho` names the fixed Moho program.

An ASM-only runner omits `[orchestrator]` but still needs a complete `[execution]` section.

## Configuration and artifact contracts

- **Keep spec-to-predicate mappings immutable across restarts.** When a stored manifest has
  no upgrade log, `ExecutionRegistry::recover_predicate` resolves the anchor's `spec_id` through
  the configured registry. Registration rejects duplicate bindings within one registry, but
  recovery does not compare the configuration with a persisted binding from the previous run.
  Changing that mapping can resume native execution under a different predicate. Assign a new
  spec ID when changing an artifact's predicate, and retain the old binding for historical work.
- **Native hosts attest a signing key.** The predicate identifies the key; it does not establish
  which code the signer executed.
- **Release owners establish native/guest equivalence.** Artifact loading checks the predicate,
  while the compiled catalog and release record associate that artifact with the native spec.
  Validate that association before distributing the release.

## Repository validation

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-features --all-targets -- -D warnings
cargo nextest run --locked --workspace --all-features
cargo test --locked -p integration-tests --test asm_upgrade_recovery --test asm_coinbase
```

Put `bitcoind` on `PATH` for integration tests. CI pins Bitcoin Core 30.2 in
[the unit-test workflow](../.github/workflows/unit.yml). Match that version when reproducing CI.

- `asm_upgrade_recovery` drives an authenticated admin activation of test spec 17 through real
  ASM and Moho services with Sled stores:
  - the old spec executes the enacting block;
  - workers are recreated at activation and again after an ordinary successor block;
  - a reorg across the activation restores the initial spec and keeps the orphaned states
    queryable.

  This is native service recovery over existing database handles. It is not a process crash,
  and it runs no prover.
- `asm_coinbase` checks that the successor's direct genesis and `prepare` preserve the baseline
  semantics. The successor changes only its spec ID, so this is not a section migration.

After building the ASM ELF, compare real guest execution with native execution for the
deterministic block fixture:

```sh
SP1_PROVER=light cargo run --locked -p strata-asm-prover-perf -- --programs asm-stf
```

The harness requires identical public bytes. `light` executes the guest without generating a
proof. The fixture is one block, with no upgrade or recursion.
