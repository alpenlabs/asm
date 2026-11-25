# ASM upgrade development

Use this guide to add an ASM spec, register its execution and proof artifacts, and test the
upgrade. [Architecture](architecture.md#specs-and-upgrades) explains how an upgrade switches the
predicate and which spec runs which block.

## What a spec ID pins

A spec ID pins a guest, through its predicate. It does not pin native code. Every spec in
`crates/spec/src/specs/` calls the subprotocol code at HEAD and gates only its own change. So
native spec N runs HEAD code plus spec N's change, and it can drift from the guest that shipped
spec N.

The drift is safe while a node that syncs from genesis still reaches the same state. A change
to shared code moves consensus only if some block folds differently under it. Before you change
shared code that a running chain uses:

- Check the chain's history for a block that takes the changed path. If there is none, replay is
  unchanged and the old behavior needs no spec gate. If there is one, keep the old behavior for
  the old spec and put the new behavior behind a new spec.
- The chain's active guest still runs the old rules. Until an upgrade activates a guest with the
  change, native execution and proofs disagree on any new block that takes the changed path.

Hardening fixes reject input that honest software never produces, so they usually pass the
history check. Run the check anyway, because an attacker may already have put such input on
chain.

## Adding a concrete spec and release

1. **Implement the spec.** Implement `AsmSpec` with a unique `SpecId`, a deterministic `prepare`,
   ordered `call_subprotocols`, and spec-owned genesis construction.
   - `prepare` receives the committed parent and must not mutate it.
   - Check the source `spec_id` and each section's schema version explicitly. Don't infer
     migration from a numeric configuration value.
   - `prepare` currently panics on an unsupported source. Keep the set of supported predecessors
     explicit, and don't skip versions without a tested edge.
   - A spec that executes with per-network values gets its own optional section in
     `AsmRuntimeParams`, named after the spec (`spec_v2`), and takes the section as constructor
     arguments. The native catalog, the runner's proof host, and the guest each build it from
     that section. A network whose file has no section keeps the values already in state, so the
     spec takes the section as an `Option`. Install the values into state in `prepare`, so no
     later spec reads an earlier spec's section.
2. **Register it in the native catalog.** Add a `CompiledSpec` variant in
   `crates/spec/src/host.rs`, and extend `CompiledSpec::resolve`, `construct_genesis_state`, and
   `register_execution`. Native callers (the runner and OL) get it through
   `build_execution_registry`.
3. **Register the proof host.** Add the matching arm to `load_asm_host` in
   `bin/asm-runner/src/bootstrap.rs`. It is kept out of `strata-asm-spec::host` so native callers
   take no prover dependency.
4. **Build its guest.** Each guest compiles one concrete spec; the witness cannot select rules.
   The local guest (`guest-builder/sp1/guest-asm/src/main.rs`) always compiles the newest spec,
   so point it at the new one. Older specs keep the guest from the
   [release](releasing.md#what-a-release-publishes) that shipped them, and tests download it with
   its predicate (`functional-tests/envs/prover_env.py` for spec 0). Retain old guests while
   delayed jobs or reorgs may still need them.

   Each network gets [its own guest](../guest-builder/sp1/README.md#one-guest-per-network), with
   its params baked in. The guest builder README covers building one and checking a published
   one, and [Releasing](releasing.md) covers publishing it and recording its spec ID.
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

- **Keep spec-to-predicate mappings fixed across restarts.** Recovery resolves the anchor's
  `spec_id` through the configured `ExecutionRegistry`, and nothing compares it with the
  previous run's mapping. Changing it can resume native execution under a different predicate.
- **Native hosts attest a signing key.** The predicate identifies the key; it does not establish
  which code the signer executed.
- **Runtime params must match the guest.** The runner builds each native spec from that spec's
  section of the `runtime` part of its params file. It executes natively with those values and
  proves with the ones baked into its guest. Nothing checks that the two agree. If they
  differ, proofs of blocks under that spec stop matching native execution.
  The [guest builder README](../guest-builder/sp1/README.md#differences-from-the-native-stf)
  lists the other places where the two can differ.
- **Release owners establish native/guest equivalence.** Artifact loading checks the predicate,
  while the compiled catalog and the [release notes](releasing.md#cutting-a-release) associate
  that artifact with the native spec. Validate that association before distributing the release.

## Testing an upgrade

Add tests for the new spec next to the ones for earlier specs:

- An integration test for what the spec changes, like
  [`tests/asm/spec_v2.rs`](../tests/asm/spec_v2.rs).
- A functional test for the upgrade from the previous spec, like
  [`fn_asm_upgrade_v1_v2_test.py`](../functional-tests/tests/upgrades/fn_asm_upgrade_v1_v2_test.py).
  On the SP1 backend the older spec runs its release guest; see the
  [functional test README](../functional-tests/README.md#proof-backend).
- If the spec keeps the subprotocol schemas, a call to
  `assert_successor_preserves_baseline_semantics` in
  [`tests/asm/coinbase.rs`](../tests/asm/coinbase.rs). It checks that genesis and `prepare`
  keep the baseline rules.

Two checks need no changes for a new spec.
[`tests/asm/upgrade_recovery.rs`](../tests/asm/upgrade_recovery.rs) activates a test spec through
the ASM and Moho services, across worker restarts and a reorg. It reuses the open databases, so
it does not test a process crash, and it runs no prover. [`prover-perf`](../bin/prover-perf)
runs the newest spec natively and in the guest on one fixture block, and requires identical
public bytes. Build the ASM ELF first, then run it without making a proof:

```sh
SP1_PROVER=light cargo run --locked -p strata-asm-prover-perf -- --programs asm-stf
```
