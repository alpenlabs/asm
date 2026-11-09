# Contributor docs

These pages explain how the ASM is put together, and link to the code for the details.

- [Architecture](architecture.md): the state transition, the services, and storage.
- [Repository layout](layout.md): what each crate is for.
- [Subprotocols](subprotocols.md): the subprotocol trait, messages, and crate split.
- [ASM upgrade development](asm-upgrade-development.md): adding a spec and its proof
  artifacts.

Tool-specific guides live next to the code:

- [Functional tests](../functional-tests/README.md)
- [dbtool](../bin/dbtool/README.md)
- [Prover perf](../bin/prover-perf/README.md)
- [Docker image](../docker/README.md)

If you change behavior a page describes, update the page in the same PR.
