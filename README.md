# Strata ASM (Anchor State Machine)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache-blue.svg)](https://opensource.org/licenses/apache-2-0)
[![ci](https://github.com/alpenlabs/asm/actions/workflows/lint.yml/badge.svg?event=push)](https://github.com/alpenlabs/asm/actions)

A provable state machine that anchors Strata to Bitcoin.

## What is ASM?

The Anchor State Machine anchors Strata to Bitcoin, which is where its name comes from. It reads every Bitcoin block and picks out the transactions tagged for Strata. With them it updates the anchor state: the verified Bitcoin header chain plus one section per subprotocol (admin, checkpoint, bridge). Strata's checkpoints, deposits, withdrawals, and admin actions all take effect this way, through Bitcoin transactions the ASM processes. Each block also produces a manifest of logs. The Orchestration Layer and the bridge read those logs, and proofs tie each one to the Bitcoin block it came from.

## Goals

- **Provable.** The same state transition runs natively and inside a zkVM, so anyone can check the state from a proof instead of re-running it.
- **Bitcoin is the only input.** The state depends only on Bitcoin blocks and the genesis params.
- **Modular.** Each concern is a subprotocol with its own state and transactions.
- **Upgradable.** The admin multisig activates a new ruleset on chain, and nodes switch at the next block.
- **Small.** The state and rules stay small so proofs stay cheap.

## Contributing

Contributions are generally welcome. If you intend to make larger changes, please discuss them in an issue before opening a PR to avoid duplicate work and architectural mismatches.

[`CONTRIBUTING.md`](CONTRIBUTING.md) lists the tools you need and the commands to lint and test. For how the code fits together, see [`docs/`](docs/README.md): start with [`docs/architecture.md`](docs/architecture.md), then [`docs/layout.md`](docs/layout.md) for what each crate does.