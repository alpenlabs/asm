# ASM Development Guide For AI Agents

This guide provides comprehensive instructions for AI agents working on the ASM codebase. It
covers the architecture, development workflows, and critical guidelines for effective
contributions.

## Project Overview
Strata ASM (Anchor State Machine) is the core component of the Strata protocol. The ASM processes
L1 blocks, routes transactions to pluggable subprotocols, applies deterministic state transitions,
emits manifests/logs, and persists state through a worker service.

## Engineering Best Practices

### Design and API Boundaries

- Give each crate and component a focused responsibility. Keep protocol and state-transition
  logic independent of RPC, persistence, orchestration, and runtime policy.
- Express dependencies through narrow capability or context traits. Keep concrete databases,
  services, and external clients in integration layers.
- Keep binaries focused on loading configuration, opening resources, setting up observability,
  and launching reusable library services. Put substantive processing, synchronization, RPC,
  and service implementations in library crates.
- Encode invariants in types so invalid states are difficult to construct. Use typed identifiers
  and domain values internally, and convert to strings or other presentation types only at
  boundaries.
- Do not expose public fields on nontrivial domain structs. Keep representation details private
  and provide constructors, accessors, borrowed views, and domain operations that preserve
  invariants. Public fields are appropriate for deliberately transparent data carriers with no
  invariants.
- Keep constructors to field assembly and basic sanity checks. Use explicitly named functions
  for initialization that performs substantial work or I/O.
- Reuse the authoritative implementation of protocol algorithms, validation, assembly, codecs,
  and test helpers. Factor repeated behavior into the layer that owns it instead of duplicating
  it at call sites.
- Declare shared dependency versions in the workspace root and inherit them with
  `workspace = true`.

### Determinism and Serialization

- State transitions and protocol processing must be deterministic. Do not make their results
  depend on wall-clock time, environment variables, nondeterministic iteration order, external
  I/O, or unseeded randomness.
- Use the codec already designated by a protocol, storage, proof, or RPC boundary. Do not
  introduce a new wire or persistence format without an explicit compatibility and migration
  plan.
- Separate domain or runtime types from wire or storage types when they have different fields or
  invariants. Perform validation at the conversion boundary.
- Treat changes to encoded fields, ordering, tags, defaults, and hash inputs as compatibility
  changes. Add round-trip and known-vector tests where encoded data or commitments change.

### Ownership and Allocation

- Borrow values for inspection, consume them when ownership is required, and use `&mut` for
  in-place updates.
- Avoid unconditional clones, temporary collections, repeated encoding buffers, and `Arc`
  without an actual sharing requirement.
- Prefer straightforward ownership over shared mutable state. When sharing is necessary, keep
  the synchronization boundary small and make ownership clear.

### Naming and Documentation

- Use `snake_case` for files, modules, variables, functions, and serialized field names;
  `UpperCamelCase` for types and traits; and `SCREAMING_SNAKE_CASE` for constants.
- Name work-performing functions with precise verbs. Use bare nouns for cheap accessors, `as_`
  for cheap borrowed views, `to_` for allocating conversions, and `with_` for builder-style
  methods.
- Import symbols with `use` statements rather than scattering long qualified paths through an
  implementation. Avoid absolute paths as enforced by `clippy::absolute_paths`.
- Give public items a brief one-sentence summary. Use intra-doc links such as
  ``[`SomeType`]`` and document non-obvious invariants, ordering requirements, preconditions,
  panics, and design rationale.
- Comments should explain why code exists or why an approach is safe, not restate what the code
  does.
- Implement `Default` only when the type has a meaningful domain default. Use fixtures or
  generators for arbitrary test values.
- Add `const` only when compile-time use is meaningful and intended as an API guarantee.

### Error Handling

| Context | Approach |
| --- | --- |
| Invalid input or recoverable failure | Return `Result` with structured variants |
| Expected absence | Return `Option`; do not invent a sentinel or default value |
| Violated internal invariant or programming bug | Use `assert!`, `unwrap()`, or `expect("specific invariant")` |
| Library errors | Define an error `enum` or `struct`, normally with `thiserror` |
| Application boundary errors | Use `anyhow` to attach and propagate context |

- Panics identify bugs or violated internal assumptions, never normal user or runtime errors.
  Document panicking conditions in a `# Panics` section on public APIs.
- Preserve useful error distinctions and source chains across abstraction boundaries. Do not
  collapse unrelated failures into opaque strings or catch-all variants.
- Make `expect` messages state the invariant that was violated. Error messages should describe
  the failure without a redundant `error` prefix.

### Async and Concurrency

- Never perform blocking I/O or other blocking work on an async executor thread. Use an async API
  or isolate the work with the runtime's blocking-task facility.
- Do not hold a lock guard across an `.await` point.
- Keep worker state owned by the worker. Expose commands and status through a handle rather than
  sharing mutable internals behind locks.
- Make shutdown and cancellation behavior explicit. Ensure partially completed work cannot leave
  persisted state inconsistent.

### Observability

- Use structured `tracing` fields instead of interpolating identifiers into messages. Include the
  context needed to correlate a log, but do not repeat context already supplied by the module or
  surrounding span.
- Reserve `error!` for unrecoverable failures, `warn!` for unexpected actionable conditions where
  processing can continue, `info!` for significant lifecycle events, and `debug!` or `trace!` for
  diagnostic detail.
- Expected lag, graceful shutdown, irrelevant traffic, and rejected untrusted input should not
  produce repetitive warnings.
- Keep pure protocol and state-transition code free of operational logging when the caller can
  report the outcome with better context.

### Testing

- Add tests for behavior changes and regressions. Test public behavior and protocol invariants
  rather than private implementation details.
- Keep unit tests independent of external processes. Use integration or functional tests for
  database, Bitcoin node, RPC, and running-service behavior.
- Exercise production assembly or encoding paths together with their verification or decoding
  paths. Use fixed vectors for consensus-sensitive behavior.
- Reuse shared fixtures, generators, environment-readiness checks, and high-level wait helpers.
  Do not re-test guarantees that belong to upstream libraries.
- Make tests deterministic. Prefer explicit synchronization and bounded waits over arbitrary
  sleeps.
- Use descriptive test names and assertions that preserve useful failure context; prefer
  `assert_eq!` over boolean `assert!` when comparing values.

### Change Scope and Validation

- Keep changes focused and independently reviewable. Split unrelated refactors, migrations, and
  cleanup from the behavior change that motivated them.
- Read and follow [`.github/PULL_REQUEST_TEMPLATE.md`](.github/PULL_REQUEST_TEMPLATE.md) before
  preparing a pull request.
- Run formatting, the relevant tests, and the repository's lint checks. Do not introduce new
  warnings, and document any validation that could not be run.
