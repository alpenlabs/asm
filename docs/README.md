# Contributor docs

These pages explain how the ASM is put together and what it guarantees. They link to the code
for the details. Read them in this order:

- [Architecture](architecture.md): the state transition, the services, and storage.
- [Repository layout](layout.md): what each crate is for.
- [Subprotocols](subprotocols.md): the subprotocol trait, messages, and crate split.
- [Security model](security-model.md): what the ASM guarantees and assumes, and how to triage
  security findings.

Task guides:

- [ASM upgrade development](asm-upgrade-development.md): adding a spec and its proof
  artifacts.

Tool-specific guides live next to the code:

- [Functional tests](../functional-tests/README.md)
- [`dbtool`](../bin/dbtool/README.md)
- [`prover-perf`](../bin/prover-perf/README.md)
- [SP1 guest builder](../guest-builder/sp1/README.md): building and checking the ASM guest
- [Docker image](../docker/README.md)

If you change behavior a page describes, update the page in the same PR.
