# Subprotocols

A subprotocol owns one section of the `AnchorState` and the SPS-50 transactions tagged with
its ID. The STF hands each subprotocol only its own transactions, in the order its spec
lists it. See [architecture.md](architecture.md) for where this fits in the transition.

## The trait

`Subprotocol` is defined in
[`crates/common/src/subprotocol.rs`](../crates/common/src/subprotocol.rs). An implementation
sets:

- `ID`: the subprotocol ID. It must match the ID in the SPS-50 tag.
- `STATE_VERSION`: the schema version of its section.
- `State`: the SSZ type stored in its section.
- `Msg`: the message type other subprotocols send to it.

The STF calls these hooks once per block:

| Hook | When | What it can do |
| --- | --- | --- |
| `pre_process_txs` | Before the transition, in the worker | Ask for aux data |
| `process_txs` | Process stage | Update state, emit logs, send messages |
| `process_msgs` | Finish stage, after every subprotocol ran `process_txs` | Update state |

A subprotocol never does I/O. Anything it needs from outside the block it asks for in
`pre_process_txs`, and reads from `VerifiedAuxData` in `process_txs`.

## Messages and logs

A subprotocol sends a message with `MsgRelayer::relay_msg`. The receiver gets it in
`process_msgs`, in the same block. Delivery is one round: `process_msgs` cannot send
messages or emit logs. Subprotocols trust each other, so messages are not re-validated.

Current message flow:

| From | To | Messages |
| --- | --- | --- |
| Admin | Checkpoint | `UpdateSequencerKey`, `UpdateCheckpointPredicate` |
| Admin | Bridge | `UpdateOperatorSet`, `UpdateSafeHarborAddress`, `Defcon` |
| Bridge | Checkpoint | `DepositProcessed` |
| Checkpoint | Bridge | `DispatchWithdrawal` |

Logs go out with `MsgRelayer::emit_log` and end up in the block's manifest. The typed log
payloads live in [`crates/logs`](../crates/logs). Downstream systems decode them, so a log
format is a public interface.

## Crate layout

Each subprotocol under [`crates/subprotocols`](../crates/subprotocols) is split so other
code can depend on the small parts without pulling in the state machine:

| Crate | Holds | Example |
| --- | --- | --- |
| `types` | Shared types and the genesis config | [`bridge/types`](../crates/subprotocols/bridge/types) |
| `txs` | The ID constant, tx type tags, and parsers and builders for its transactions | [`bridge/txs`](../crates/subprotocols/bridge/txs) |
| `msgs` | The incoming message enum | [`bridge/msgs`](../crates/subprotocols/bridge/msgs) |
| `subprotocol` | The `Subprotocol` impl and handlers | [`bridge/subprotocol`](../crates/subprotocols/bridge/subprotocol) |

Some subprotocols add a crate for logic that stands on its own: `bridge/state`,
`checkpoint/verification`, and `admin/threshold-sig`.

## State and schema versions

The loader decodes each section with the subprotocol's `State` type. It panics if the
section is missing or its version does not match `STATE_VERSION`. The panic is deliberate:
a mismatch means the spec and the state disagree, and the chain must stop.

So a change to `State`'s encoding is a consensus change. Once a chain runs the old schema,
the change needs a new `STATE_VERSION`, a new spec, and a migration in that spec's
`prepare`. The steps are in [asm-upgrade-development.md](asm-upgrade-development.md).

## Adding a subprotocol

1. Create the crates above and pick an unused ID.
2. Add its genesis config to `SubprotocolInstance` in
   [`crates/params`](../crates/params/src/params.rs).
3. Build its genesis section in
   [`crates/spec/src/genesis.rs`](../crates/spec/src/genesis.rs).
4. Add it to a spec's `call_subprotocols`. On a live chain this means a new spec that adds
   the section in `prepare`.
5. Cover it with unit tests in its crates and an integration test in [`tests/asm`](../tests/asm).
