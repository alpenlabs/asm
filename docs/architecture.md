# Architecture

The Anchor State Machine (ASM) reads Bitcoin blocks one at a time. In each block it picks out
the transactions tagged for Strata and hands them to the subprotocols, which update their part
of the state and emit logs. A state transition function (STF) does this work. It takes the
previous `AnchorState` and the Bitcoin block, and returns the next `AnchorState` plus an
`AsmManifest`. The manifest lists the logs the subprotocols emitted for that Bitcoin block.
Each transition is also proven in a zkVM.

ASM consumers, like the Orchestration Layer (OL) in [alpen](https://github.com/alpenlabs/alpen)
and the bridge in [strata-bridge](https://github.com/alpenlabs/strata-bridge), read the logs
in the manifests. The proofs tie each manifest to the Bitcoin block it came from, so a
consumer can check the result without running the STF again. This is how checkpoints,
deposits, withdrawals, and admin actions posted to Bitcoin take effect in Strata.

## Tagged transactions

The ASM only reads transactions in the SPS-50 format, which
[`strata-l1-txfmt`](https://github.com/alpenlabs/strata-common/tree/main/crates/l1proto/txfmt)
in strata-common defines. A tagged transaction's first output is an `OP_RETURN` with this
data:

| Bytes | Field |
| --- | --- |
| 0..4 | Magic. Marks the transaction as Strata's. Set in the genesis params. |
| 4 | Subprotocol ID |
| 5 | Transaction type within that subprotocol |
| 6.. | The rest of the payload, which the subprotocol parses |

The ASM drops every transaction without a valid tag. It also drops the coinbase, even when it
is tagged. A miner writes the coinbase freely, with no UTXO and no signature, so reading it
would let any miner feed the subprotocols unauthenticated input. The ASM groups the remaining
transactions by subprotocol ID and gives each subprotocol only its own.

## Anchor state

`AnchorState` is defined in [`crates/state/ssz/state.ssz`](../crates/state/ssz/state.ssz). It
holds:

- `spec_id`: the ruleset that produced this state.
- `magic`: the 4-byte SPS-50 magic. See [Tagged transactions](#tagged-transactions).
- `chain_view`: the Bitcoin header verification state, and a history accumulator. The
  accumulator is an MMR of manifest hashes indexed by L1 height.
- `sections`: one SSZ-encoded `SectionState` per subprotocol, tagged with the subprotocol ID
  and its schema version.

## The state transition

The entry point is `compute_asm_transition` in
[`crates/stf/src/transition.rs`](../crates/stf/src/transition.rs). For each block it:

1. Calls `AsmSpec::prepare` to get a working copy of the parent state. This is where a new
   spec migrates sections it changed.
2. Checks the block body against the header: merkle root and witness commitment.
3. Checks the header against the header verification state and advances it.
4. Verifies the aux data against the history accumulator.
5. Groups the tagged transactions by subprotocol ID, as described in
   [Tagged transactions](#tagged-transactions).
6. Runs three stages: load each subprotocol's section, process its transactions, then
   deliver the messages the subprotocols sent each other. Each stage calls the subprotocols
   in the order the spec gives. [subprotocols.md](subprotocols.md) covers what a subprotocol
   can do in each stage.
7. Builds the manifest from the logs, adds its hash to the accumulator, and writes the new
   state.

### Aux data

Some subprotocols need data that is not in the block, such as an older manifest hash or a
transaction a deposit spends. The STF cannot fetch it, so the work splits in two:

1. `pre_process_asm` ([`crates/stf/src/preprocess.rs`](../crates/stf/src/preprocess.rs))
   loads the subprotocols and lets each one list what it needs.
2. The worker fetches the data
   ([`crates/worker/src/aux_resolver.rs`](../crates/worker/src/aux_resolver.rs)) and passes
   it to the STF. The STF verifies it before any subprotocol sees it, so the data needs no
   trust.

## Subprotocols

A subprotocol owns one section of the state and the transactions tagged with its ID. See
[subprotocols.md](subprotocols.md) for the trait and the crate layout.

| ID | Subprotocol | Role |
| --- | --- | --- |
| 0 | Admin | Multisig governance with time-delayed updates |
| 1 | Checkpoint | Verifies OL checkpoints and tracks the verified tip |
| 2 | Bridge | Deposits, operators, withdrawal assignments |

## Specs and upgrades

An `AsmSpec` ([`crates/common/src/spec.rs`](../crates/common/src/spec.rs)) lists the
subprotocols and the order they run in. The concrete specs live in
[`crates/spec/src/spec.rs`](../crates/spec/src/spec.rs).

Each spec is bound to a predicate, which is the key that verifies its proofs. The worker
tracks the predicate for the next block. An `AsmStfUpdate` log, emitted by the admin
subprotocol, changes it. The `ExecutionRegistry`
([`crates/worker/src/registry.rs`](../crates/worker/src/registry.rs)) maps a predicate to the
compiled spec that runs the block.

To add a spec, see [asm-upgrade-development.md](asm-upgrade-development.md).

## Moho

[Moho](https://github.com/alpenlabs/moho) is Strata's recursive proof framework. Each Moho
proof checks the previous Moho proof and one ASM step proof, so a single proof covers the
chain from genesis up to a given block. The Moho state also carries the predicate for the
next block, which is how an upgrade switches to a new ASM program. The ASM plugs into Moho by
implementing its `MohoProgram` trait (see [Proofs](#proofs)).

## Runtime

`strata-asm-runner` ([`bin/asm-runner`](../bin/asm-runner)) wires the services together in
[`bootstrap.rs`](../bin/asm-runner/src/bootstrap.rs):

```text
           ZMQ hashblock
bitcoind ─────────────────▶ block watcher ──▶ ASM worker ──▶ Moho worker ──▶ prover worker
                                                  │               │               │
                                               ASM DB          Moho DB        proof DB
                                                  └───────────────┴───────────────┴──▶ RPC
```

- **Block watcher** sends each new block hash to the ASM worker. On startup it also sends
  the current tip.
- **ASM worker** ([`crates/worker`](../crates/worker)) walks back from the new block to the
  last block it has a state for, then runs the STF forward over every block in between. This
  also handles reorgs. For each block it stores the manifest, the aux data, and the anchor
  state, in that order. The anchor state write is the commit point. It then tells its
  subscribers.
- **Moho worker** ([`crates/extensions/moho/worker`](../crates/extensions/moho/worker))
  folds each committed block into a `MohoState`. A `MohoState` commits to the ASM state, the
  next predicate, and an export state that the bridge proves against.
- **Prover worker** ([`crates/extensions/prover/worker`](../crates/extensions/prover/worker))
  follows the Moho worker. It requests an ASM step proof and a Moho recursive proof per
  block from a remote or native prover, and stores the results.
- **RPC** ([`crates/rpc`](../crates/rpc)) serves state, manifests, proofs, and export entry
  proofs under the `strata_asm` namespace.

The Moho and prover workers run only when the config has an `[orchestrator]` section.

Each worker owns its state and takes its dependencies through context traits, such as
`WorkerContext` in [`crates/worker/src/traits.rs`](../crates/worker/src/traits.rs). The
runner supplies the sled and bitcoind implementations. Other hosts, such as the OL node in
alpen, embed the ASM worker with their own context.

## Storage

The runner uses three sled databases:

- **ASM DB** ([`crates/storage`](../crates/storage)): anchor states, aux data, manifests, and
  the manifest hash MMR.
- **Moho DB** ([`crates/extensions/moho/storage`](../crates/extensions/moho/storage)): Moho
  states and export entries.
- **Proof DB** ([`crates/extensions/prover/storage`](../crates/extensions/prover/storage)):
  proofs and remote prover bookkeeping. Only opened with an orchestrator.

[`bin/dbtool`](../bin/dbtool/README.md) reads and repairs these offline.

## Proofs

The ASM step proof runs the same STF as the ASM worker, inside the SP1 zkVM.
[`crates/proof/statements`](../crates/proof/statements) implements Moho's `MohoProgram` trait
for it. [`guest-builder/sp1`](../guest-builder/sp1) compiles the SP1 guest, which always runs
the newest spec. The Moho recursive guest comes from the
[moho](https://github.com/alpenlabs/moho) release, fetched by
[`contrib/fetch_moho_artifacts.sh`](../contrib/fetch_moho_artifacts.sh).
