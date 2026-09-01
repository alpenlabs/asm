# ASM v0.3.0-rc.2 historical artifacts

`asm-vk.json` is the ASM predicate published with release `v0.3.0-rc.2` from commit
`45a1fa2f52289b483dd9767b4ec9c80545d5789b`.

- Release: <https://github.com/alpenlabs/asm/releases/tag/v0.3.0-rc.2>
- Asset: <https://github.com/alpenlabs/asm/releases/download/v0.3.0-rc.2/asm-vk.json>
- Published SHA-256: `d3303f17e741960aa648534ad1ada2d20db396815c7baa1012d881082982e31a`

`guest-artifacts.json` records the published byte identities and the semantic
baseline binding used for historical replay:

- `asm.elf`: `d59d093acf299ecca4a57d67895c33b5ee16b5317b1daca71a0e5d1d6496ab29`
- `asm-vk.json`: `d3303f17e741960aa648534ad1ada2d20db396815c7baa1012d881082982e31a`
- `moho.elf`: `39d563ba9c01c617bb950873eccb8c9720986bdaea17f7ab0b2e8f9e42d17981`
- `moho-vk.json`: `90afb979f5c95bbca73e18fa625471910fdc5129c9c2f5a90b98429abab3c69a`

This release predates the digest-pinned builder policy. Its workflow installed
the current SP1 CLI and permitted an environment override of the builder image,
so the exact CLI, installer revision, installer checksum, and image digest
cannot be reconstructed from source alone. The manifest therefore marks them as unknown and uses
`legacy_published`, rather than claiming modern reproducible-build
qualification retroactively. The published byte checksums remain authoritative
for loading the historical artifacts.

The checked-in source file has the repository's normal trailing line feed. The test hashes the JSON
payload without that line feed and verifies the published asset checksum.
