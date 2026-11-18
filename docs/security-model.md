# Security model

The ASM has no sequencer and no consensus of its own. Its only inputs are the Bitcoin chain and
the public params file, which holds the genesis params and each spec's runtime params. So anyone
can run it, and every honest runner computes the same state. But a runner convinces only whoever
runs it. Everyone else, such as the bridge, relies on the Moho proof
([architecture.md](architecture.md#moho)).

This page lists what the ASM guarantees, what it assumes, and whom it trusts, and gives the
rules for judging a security finding. To report a vulnerability, follow
[SECURITY.md](../SECURITY.md).

## What a Moho proof shows

A Moho proof shows that some chain of Bitcoin headers, starting at genesis, has total work W
and folds to state S.

It does not show that Bitcoin follows that chain. The STF checks each header, and checks that
the block body belongs to it ([`crates/btc-verification`](../crates/btc-verification)). It does
not validate transactions, because that would need the UTXO set and script execution inside
the proof. So anyone who mines a fork can prove the fork's state, even if the fork breaks
Bitcoin's rules.

Choosing between Moho proofs is the consumer's job. The bridge compares their total work, and
waits for anyone to challenge a proof with a heavier one.

## What the ASM guarantees

1. **No block that Bitcoin accepts halts the ASM.** The ASM cannot reject a block that Bitcoin
   accepted. The native STF processes it and the guest proves it, well inside the time a
   consumer such as the bridge waits. A malformed or invalid transaction is skipped. It never
   fails the block. A halt stops every runner and every prover at the same height, and only an
   upgrade gets them past it. It is a safety failure and not only downtime: with no newer Moho
   proof, a consumer cannot answer a proof made on a fork.
   [Deliberate halts](#deliberate-halts) lists the exceptions.
2. **Every honest run gives the same result, native or proven.** The STF depends only on the
   parent state, the block, and aux data it verifies itself. Local config, clocks, I/O, and
   iteration order do not change the result. The native STF and the guest agree on every
   input. Consumers act on what the guest computed, so a difference between the two is a
   failure even when every runner agrees. The
   [guest builder README](../guest-builder/sp1/README.md#differences-from-the-native-stf) lists
   where they can differ.
3. **A step proof exists only for a transition the STF allows.** A step proof made from a
   made-up pre-state does not link to the previous Moho proof, so it leads to no Moho proof.
   The STF checks aux data by txid or by MMR proof before any subprotocol reads it. If data the
   transition needs is missing, the guest panics and there is no step proof.
4. **The work a Moho proof reports is real.** Every header is checked and its work added to the
   chain's total. Consumers such as the bridge read that total from the export state and do not
   check headers themselves.
5. **Subprotocol state changes only with the right authorization.**
   - A deposit is accepted once, and only if it is locked to the current N/N key and carries
     the right amount.
   - A withdrawal fulfillment is accepted only if it matches its assignment. Only an accepted
     fulfillment adds a bridge export entry, which is the operator's claim record.
   - A withdrawal is dispatched only from a checkpoint that was posted under the sequencer key
     and has a valid checkpoint proof.
   - Slash and unstake remove an operator only if the operator's stake connector was really
     spent.
   - An admin action needs a signature threshold from its role and a fresh sequence number. An
     update takes effect after the confirmation depth the params file sets for its type. A
     depth of zero means at once. `Defcon1` and cancels always apply at once.

### Deliberate halts

In these cases the STF stops on purpose, and guarantee 1 does not apply.

- **Governance halts the ASM**, for example by removing every operator or by switching to a
  guest that cannot run. Governance is trusted; see
  [What the ASM assumes](#what-the-asm-assumes).
- **The bridge cannot serve a withdrawal.** The STF panics when a withdrawal has no unassigned
  deposit or no eligible operator to take it, and when a removal would leave no active operator.
  This is a [known accepted risk](#known-accepted-risks).
- **Aux data is missing.** The block does not cause this. The worker supplies aux data and will
  not run the STF until it has all of it. In the guest the panic means no step proof, which is
  the only sound result when data is withheld.
- **A subprotocol section is missing or has the wrong version.** The state and the spec
  disagree; see [subprotocols.md](subprotocols.md#state-and-schema-versions).

### SSZ bounds

Nothing stops Bitcoin from producing a block that pushes the ASM past one of its own size
bounds. A bound that such a block can reach breaks guarantee 1.

The state, the manifest, and the guest input are SSZ types, and their lists have fixed maximum
sizes. The bounds are set in the `.ssz` schemas, such as `MAX_SECTION_STATE_BYTES` in
[`crates/state/ssz/state.ssz`](../crates/state/ssz/state.ssz) and `MAX_LOGS_PER_MANIFEST` in
[`crates/manifest-types/ssz/manifest.ssz`](../crates/manifest-types/ssz/manifest.ssz). A
transition that would go past a bound fails, in the native STF and in the guest alike.

So every bound must be one of these:

- Out of reach of any chain Bitcoin accepts, given Bitcoin's block size and the protocol's own
  rules.
- Handled before it is hit. The subprotocol skips the transaction that would overflow, and the
  block goes through.

Some bounds fill up over time, not in one block. The bridge section, for example, holds the
deposits and assignments that are still open. Check those against the life of the chain, not
one block.

A list bound also feeds into the SSZ hash, so raising it later is a consensus change that needs
a new spec. It is cheaper to size a bound right the first time.

## What the ASM assumes

- **Bitcoin.** Honest miners hold most of the hash power. So in the long run the chain that
  follows Bitcoin's rules has the most work, and an attacker cannot keep a fork ahead of it.
- **The proof system.** Proofs are made with SP1. SP1 is sound, and the Moho recursive guest
  checks and links step proofs correctly. Both come from outside this repo. A native prover
  only signs its output, so it shows nothing about what code ran. It is for tests.
- **bitcoind.** Each runner trusts its own bitcoind to serve the real chain, with `txindex` on.
  A lying bitcoind misleads only that runner.
- **Governance.** The admin multisigs are trusted. They can change the operator set, the
  sequencer key, the verifying keys, and their own members. Changing the ASM verifying key
  swaps the ASM guest itself. The security council can also sweep the bridge's deposits to the
  safe harbor address (`Defcon1`, `Defcon3`), and governance sets that address. So governance
  can move funds and can halt the ASM.
- **OL sequencer.** Trusted for liveness only. It can stop posting checkpoints, and the ASM
  carries on without them. Every checkpoint still needs a valid checkpoint proof.
- **Bridge operators.** A deposit needs a signature from all N operators, and at least one of
  them is honest. So no deposit is accepted unless an honest operator signed it.
- **Remote prover.** Trusted for liveness only. The prover worker verifies every step proof and
  Moho proof it receives. If a prover withholds them, the runner can use another one.

## Trust boundaries

Each input to the ASM falls into one of five groups:

- **Untrusted**: anyone can supply it.
- **Authenticated**: a known party supplies it, and the ASM checks that it came from them.
- **Verified**: the STF checks the content before using it.
- **Trusted for liveness**: the party can go silent, but what it sends is still checked.
- **Trusted, per runner**: it belongs to whoever runs the runner. A problem here misleads only
  that runner.

| Input | Trust | Notes |
| --- | --- | --- |
| Bitcoin block contents (SPS-50 tagged transactions, envelopes) | Untrusted | Anyone who pays fees can post them. Parsers and handlers must skip bad input. They must never panic, fail the block, or accept something they should reject, natively or in the guest. |
| Reorgs and competing forks | Untrusted | The worker walks back to the last stored ancestor and re-runs forward. A fork costs the work needed to keep it ahead. |
| Admin actions | Authenticated by the role's multisig | The ASM checks the signatures, the role, and the sequence number. Signers read the signing message on a hardware wallet, so it must show what the action does. |
| OL checkpoints | Authenticated by the sequencer key | The ASM checks the key and verifies the checkpoint proof. |
| Deposit, slash, and unstake transactions | Authenticated by the N/N operator set | Bitcoin enforces the signature. The ASM checks that the script is one the operator set really used. |
| Aux data | Verified | Its content is checked. Whether it is present is not; see [Deliberate halts](#deliberate-halts). |
| Remote prover, and the peer runner in follower mode (`peer_url`) | Trusted for liveness | Every step proof and Moho proof is verified on receipt. |
| bitcoind | Trusted, per runner | See [What the ASM assumes](#what-the-asm-assumes). |
| Sled databases, `dbtool`, params file, config, guest ELFs | Trusted, per runner | The worker is the only writer of state. A step proof made from a forged local state does not link to the previous Moho proof, so it leads to no Moho proof. |
| Callers of the `strata_asm` RPC | Trusted, per runner | The RPC is read-only. It serves callers that whoever runs the runner chooses, such as their bridge node or a follower runner. |

## Triaging findings

These rules add to the
[shared Alpen audit rules](https://github.com/alpenlabs/actions/blob/main/ai-security-review/context/general.md).
Where the two conflict, these win.

1. **Name the boundary.** Say which row of the table the attacker's input comes through. If
   there is none, it is not a security finding.
2. **"Trusted, per runner" input gives bugs, not security findings.** A compromised host
   misleads only its own runner.
3. **"Trusted for liveness" does not mean trusted for content.** Accepting a bad step proof, a
   bad Moho proof, or bad aux data from such a party is a finding. So is mishandling its other
   responses.
4. **For authenticated input, the check is in scope.** What the party chooses to do within its
   role is not. A governance action that halts the ASM is out of scope, unless the signing
   message hides what the action does.
5. **The ASM accepts blocks that break Bitcoin's rules, by design**
   ([What a Moho proof shows](#what-a-moho-proof-shows)). So "the ASM accepted a
   double spend" or "an invalid script" is not a finding. Neither is a halt that only such a
   block can cause: the block never reaches a runner, and in the guest it only stops the
   fork's own step proof. A bug in a check the ASM does make is a finding, even though it only
   shows up on a fork. Those checks are the header checks, the work total, and the match
   between body and header.
6. **Breaking a guarantee has Severe impact**, on the shared rules' scale. If an ordinary
   Bitcoin transaction can trigger it, the risk is Critical. This includes halts. The shared
   rules cap availability-only findings at High, but here a halt is a safety failure
   (guarantee 1).
7. **Don't suggest a fix that fails the block.** The ASM cannot reject a block, so such a
   check can only halt it. A check that skips one transaction is fine. For the same reason,
   don't suggest turning a [deliberate halt](#deliberate-halts) into an error.
8. **Secrets are always in scope**, such as bitcoind credentials, `NETWORK_PRIVATE_KEY`, and CI
   tokens.

### Known accepted risks

- The `strata_asm` RPC has no authentication or rate limit. Each consumer runs its own runner.
  Bind the RPC to loopback or a private interface.
- The STF halts when the bridge cannot serve a withdrawal; see
  [Deliberate halts](#deliberate-halts). With no operator the funds are already stuck on
  Bitcoin. Preventing this is an operational task.

## Keeping this page current

Treat a change to this page as a security change, since it decides what gets triaged away.

The automated PR reviewer does not load this page yet. It takes its repository context from
`ai-security-review/context/repos/` in alpenlabs/actions, which has no file for this repo. Until
it does, the triage rules here bind people, not the reviewer.
