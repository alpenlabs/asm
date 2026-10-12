# gen_asm_params

Generates ASM params by populating the L1 anchor (block hash, `next_target`,
epoch-start timestamp) from on-chain context. The context can be read either
from a running `bitcoind` (JSON-RPC) or from an Esplora REST API such as
mempool.space. Output is written to `gen/<unix-ts>.json` next to the script
(`params/gen/`), independent of the current working directory.

## Usage

From a local `bitcoind` (JSON-RPC):

```sh
python3 gen_asm_params.py \
  --bitcoin-rpc-url http://127.0.0.1:12301 \
  --bitcoin-rpc-user user \
  --bitcoin-rpc-password password
```

From a public Esplora API (e.g. mempool.space on signet, no node required):

```sh
python3 gen_asm_params.py \
  --api-url https://mempool.space/signet/api \
  --genesis-height 319119
```

Pick exactly one source: pass `--api-url`, or the full `--bitcoin-rpc-*` trio.

`--params` defaults to [`gen/asm-params-sample.json`](gen/asm-params-sample.json);
pass `--params <path>` to override.

## Arguments

- `--api-url` — Esplora REST base URL (e.g. `https://mempool.space/signet/api`).
  Mutually exclusive with the `--bitcoin-rpc-*` arguments.
- `--bitcoin-rpc-url` — Bitcoin Core JSON-RPC endpoint.
- `--bitcoin-rpc-user` / `--bitcoin-rpc-password` — RPC credentials.
- `--params` — Input ASM params JSON template. `anchor.network` is read from it,
  as is `anchor.block.height` when `--genesis-height` is not given; the rest of
  `anchor` is overwritten. Defaults to `gen/asm-params-sample.json`.
- `--genesis-height` — L1 height to anchor the ASM at. Overrides
  `anchor.block.height` from the template, which is useful when the template
  carries a `REPLACE_ME` placeholder there.

The chosen source must already be synced past `anchor.block.height` — the
script does not wait. Note that using a public API trusts that provider for the
anchor values that pin your ASM genesis; fine for dev/test signet deployments,
less ideal if you need a trust-minimized anchor.
