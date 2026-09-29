# Baseline deposit requests

Produced by baseline `v0.3.0-rc.2`, commit
`45a1fa2f52289b483dd9767b4ec9c80545d5789b`, using its locked dependencies.
Two independent generator invocations produced identical files.

The fixtures use the baseline transaction helper and production SPS-50 encoding
and Taproot deposit-request lock builder. The baseline parser accepted each
transaction and recovered exactly the supplied auxiliary data and output.
Destination lengths are 0, 20, and the maximum 42 bytes, each filled with `0xab`.
Recovery/internal keys derive from secret bytes `[7; 32]`/`[8; 32]`; the amount is
100,000 satoshis and the recovery delay is 1,008 blocks. These are public test keys.

To reproduce, copy `generate.rs` into the baseline checkout as
`crates/subprotocols/bridge-v1/txs/examples/baseline_deposit_request.rs` and run:

```sh
cargo run --locked --offline -p strata-asm-proto-bridge-v1-txs \
  --features test-utils --example baseline_deposit_request -- /tmp/bridge-fixtures
```

The candidate test parses frozen Bitcoin wire bytes, checks the metadata and
amount, and rebuilds the transaction to assert identical header and locking-script
bytes. This protects deposit-request formatting and lock construction. Transactions
have dummy inputs: they are not funded Bitcoin transactions or deployed-history
samples. This does not qualify deposit execution, withdrawal export compatibility,
or a successor's complete L1 behavior.
