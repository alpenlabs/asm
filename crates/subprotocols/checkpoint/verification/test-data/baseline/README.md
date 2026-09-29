# Signed baseline checkpoint fixture

Produced by the production types, codecs, hashing and Schnorr implementation at
ASM `45a1fa2f52289b483dd9767b4ec9c80545d5789b` (`v0.3.0-rc.2`) with that
revision's locked dependencies. Two generation runs produced identical bytes.
`SHA256SUMS` records the five binary fixtures.

The covered range is L1 height 100, using a one-log manifest produced by the same
baseline revision (copied here as `manifest.ssz`). The previous tip has epoch 0,
L1 height 99, OL slot 0 and block ID `[3; 32]`; the new tip has epoch 1, L1
height 100, OL slot 1 and block ID `[4; 32]`. The state diff is `[5, 6, 7]`,
OL logs are empty, and the terminal complement contains timestamp 123, parent
`[3; 32]`, body root `[8; 32]`, and log root `[9; 32]`.

The publicly known test signing key is `[7; 32]`. The producer verifies its own
signature and emits the full predicate, previous tip, claim, payload and manifest.
The candidate test decodes these fixed bytes and models the baseline's 1,024-log
manifest schema with the production SSZ derives. It checks that the baseline and
production schemas encode the manifest identically, reconstructs exactly the
baseline claim from the baseline root, and advances the checkpoint state through
production verification. The production root must match the baseline root, and the signed checkpoint must
advance through production manifest hashing and verification. A changed manifest
must fail signature verification and leave checkpoint state unchanged.

To regenerate, copy `generate.rs` into
`crates/test-utils/checkpoint/examples/baseline_checkpoint.rs` of an isolated
checkout of the baseline revision. Run there:

```sh
cargo run --locked --offline -p strata-test-utils-checkpoint \
  --example baseline_checkpoint -- /tmp/checkpoint-fixtures /absolute/path/to/manifest.ssz
```

The generator uses baseline APIs intentionally; do not compile it against current
candidate types to refresh expectations. Changes require explicit compatibility
review. This is a deterministic synthetic signed checkpoint payload, not a deployed
L1 transaction or an SP1 proof. Envelope authentication, deployed-history coverage
and historical withdrawal export formats need their own qualification evidence.
