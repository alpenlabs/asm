# ASM Functional Tests

Minimal functional tests for `strata-asm-runner`.

This suite only starts:
- `bitcoind` (regtest)
- `strata-asm-runner`

No bridge-node, secret-service, or FoundationDB services are required.

## Prerequisites

1. Install `bitcoind` and ensure it is on your `PATH`.
2. Install `uv` (<https://docs.astral.sh/uv/>).

## Run

```bash
cd functional-tests
./run_test.sh
```

Run a specific test module:

```bash
cd functional-tests
./run_test.sh fn_asm_block_test
```

### SP1 proof generation

To run with SP1 proof generation enabled:

```bash
SP1_PROOF_STRATEGY="" NETWORK_PRIVATE_KEY="" CARGO_DEBUG=0 CARGO_FEATURES=sp1 ./run_test.sh fn_asm_proof_test
```

- `SP1_PROOF_STRATEGY` — the SP1 proof fulfillment strategy. See
  [FulfillmentStrategy](https://docs.rs/sp1-sdk/5.2.1/sp1_sdk/network/enum.FulfillmentStrategy.html)
  for available options.
- `NETWORK_PRIVATE_KEY` — private key for the SP1 network prover (required
  when using a network strategy).

Results are written under `functional-tests/_dd/`.
