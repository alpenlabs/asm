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

Results are written under `functional-tests/_dd/`.
