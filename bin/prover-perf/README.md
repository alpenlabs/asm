# Prover Performance Evaluation

Evaluate SP1 prover performance for ASM guest programs (`asm-stf`, `moho`).

## Prerequisites

Ensure you have [just](https://github.com/casey/just) installed.

## Usage

### Performance evaluation (mock mode)

Generates reports and profiling data using the mock prover:

```bash
just prover-eval
```

### Proof generation (local)

Generate proofs locally with the mock prover:

```bash
just prover-proof
```

### Proof generation (SP1 network prover)

To generate proofs using the SP1 network prover, set the following environment
variables:

```bash
SP1_PROVER=network NETWORK_PRIVATE_KEY=<your-key> SP1_PROOF_STRATEGY=reserved just prover-proof
```

- `SP1_PROVER` — set to `network` to use the SP1 network prover instead of
  local execution.
- `NETWORK_PRIVATE_KEY` — private key for authenticating with the SP1 network
  prover.
- `SP1_PROOF_STRATEGY` — the SP1 proof fulfillment strategy. See
  [FulfillmentStrategy](https://docs.rs/sp1-sdk/5.2.1/sp1_sdk/network/enum.FulfillmentStrategy.html)
  for available options (e.g. `reserved`).