# asm-admin

`asm-admin` signs ASM admin actions and puts them on Bitcoin.

An admin action needs signatures from a threshold of its role's signers. Each signer signs on their own machine. One coordinator collects the signatures, checks them, and submits the transaction from a bitcoind wallet. Signing needs no network access.

## Install

```bash
cargo install --locked --git https://github.com/alpenlabs/asm strata-asm-admin-cli
```

## Actions

Every command ends with the action. Signers and the coordinator must give the same action and sequence number, or the signatures won't match.

| Action | Role |
| --- | --- |
| [`asm-stf-vk --predicate <P>`](#predicate-updates) | Strata Administrator |
| [`ol-stf-vk --predicate <P>`](#predicate-updates) | Strata Administrator |
| [`ee-stf-vk --predicate <P>`](#predicate-updates) | Alpen Administrator |
| [`safe-harbor --address <P2TR address>`](#safe-harbor) | Strata Administrator |
| [`operator-set [--add <key>]... [--remove <index>]...`](#operator-set) | Strata Administrator |
| [`cancel --id <ID> <update>`](#cancel) | the role of the cancelled update |

The chain applies an admin action as signed. A valid signature doesn't make an action safe. A wrong or badly timed action can stall the bridge or halt the chain, and some can't be undone. Before you sign, check what the action does to the running chain, not only that the message reads right. Prefer small steps over one large change.

The sequence number is counted per role. It must be above the role's last accepted one, by at most the `max_seqno_gap` in the params file. The tool can't check this offline. A transaction with a bad sequence number is mined, but the ASM skips it.

### Predicate updates

`asm-stf-vk`, `ol-stf-vk` and `ee-stf-vk` set the predicate that verifies the ASM, OL and EE proofs. A predicate is written as `<type>` or `<type>:<hex>`, for example `Sp1Groth16:<hex>`.

Before an `asm-stf-vk` update, every ASM executor must already list the new predicate. An executor that doesn't halts at the first block after the update activates.

### Safe harbor

`safe-harbor` sets the P2TR address the bridge's funds can be swept to. Give the address as a wallet shows it. The tool rejects an address for another network. Once the safe harbor is activated, the bridge ignores the update.

### Operator set

`operator-set` adds and removes bridge operators. Give at least one `--add` or `--remove`, and repeat either one as needed.

An operator is removed by its index. The genesis operators take indices 0, 1, 2, ... in the order the params file lists them. Each operator added later takes the next unused index. Indices are never reused. The tool can't see the chain's operator table, so it can't check the indices. An unknown index is skipped.

An operator key is the operator's MuSig2 key. Give it as compressed hex, as the params file writes it, or as 32-byte x-only hex. The signing message shows the x-only form. The bridge ignores a key it has ever held, so a removed key can't be added back.

To rotate a key, remove the old index and add the new key in one action:

```bash
asm-admin message --network bitcoin --seq-no 7 \
  operator-set --remove 2 --add "$NEW_KEY" > message.txt
```

Rotate a few operator keys at a time, not all of them at once.

### Cancel

A queued update can be cancelled until it activates. Give its ID, and the update exactly as it was queued:

```bash
asm-admin sign --network bitcoin --seq-no 8 \
  cancel --id 3 asm-stf-vk --predicate "$PREDICATE"
```

Only the ID goes on chain. The chain rebuilds the signing message from the update it has queued, so signatures over any other update fail. A cancel needs a new sequence number from the same role.

## Sign

Each signer signs with either a wallet or a key.

With a wallet, print the message and sign the text with the wallet's "sign message" feature, using your signer address. The address is native segwit (P2WPKH), so the wallet must be able to sign a message with one. Bitcoin Core's `signmessage` signs only with legacy addresses, so it can't.

```bash
asm-admin message --network bitcoin --seq-no 7 asm-stf-vk --predicate "$PREDICATE" > message.txt
```

The message goes to stdout exactly as it must be signed, with no trailing newline. Sign the text, not a hash of it.

With a key, put an xpriv or a 32-byte hex key in a file only you can read, and run:

```bash
STRATA_ADMIN_KEY="$(cat "$KEY_FILE")" asm-admin sign \
  --network bitcoin --seq-no 7 asm-stf-vk --predicate "$PREDICATE"
```

An xpriv signs with its own key, with no derivation. The command shows the message and your address on stderr, and prints the base64 signature on stdout.

Either way, send the coordinator your signature and your address.

## Verify and submit

Each signature is given as `<index>:<base64>`. The index is the position of the signer's address in the role's signer list, counting from 0.

Check the signatures against the params file the chain was launched with:

```bash
asm-admin verify --params asm-params.json --seq-no 7 \
  --signature "0:$SIG_A" --signature "2:$SIG_B" \
  asm-stf-vk --predicate "$PREDICATE"
```

If a signature doesn't match, the error names its index and the address it should come from.

Then submit with the same arguments, plus a bitcoind wallet and a fee rate. The tool is built and tested against Bitcoin Core 30. Try `--dry-run` first. It builds both transactions and checks that the node's mempool would take them, but broadcasts nothing:

```bash
export BTC_RPC_USER=... BTC_RPC_PASSWORD=...
asm-admin submit --params asm-params.json --seq-no 7 \
  --signature "0:$SIG_A" --signature "2:$SIG_B" \
  --btc-url "http://127.0.0.1:8332/wallet/$WALLET" --fee-rate 5 --dry-run \
  asm-stf-vk --predicate "$PREDICATE"
```

Without `--dry-run`, the commit and reveal transactions go out together as one package. The command prints both txids. If the broadcast fails, the command prints both signed transactions on stderr. The node may have taken the commit alone, and the reveal can then still be sent with `sendrawtransaction`. Once the reveal is mined, the update is queued. It activates after the confirmation depth the params set for its update type.

### A rotated signer set

The params file holds the signer sets from genesis. If a role's signers were rotated on chain, give the chain and the current signer set by hand instead of `--params`:

```bash
asm-admin verify --network bitcoin --magic STRA --threshold 2 \
  --signer "$ADDR_0" --signer "$ADDR_1" --signer "$ADDR_2" \
  --seq-no 7 --signature "0:$SIG_A" --signature "2:$SIG_B" \
  asm-stf-vk --predicate "$PREDICATE"
```

List the signers in index order.
