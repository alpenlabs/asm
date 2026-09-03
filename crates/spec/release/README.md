# Guest artifact release manifests

This directory is an append-only registry of published guest artifacts. Each
manifest binds semantic role, ASM specification (where applicable), predicate,
ELF and VK checksums, exact guest source revision, and build-tool identities.
The runner compiles these statements in and accepts an SP1 artifact only after
startup verifies its local ELF and VK against the selected statement.

The registry currently contains only the `v0.3.0-rc.2` baseline ASM and Moho
artifacts. That historical release is marked `legacy_published`: its exact
published bytes and source revision are known, but its floating SP1 installer
and builder image cannot be reconstructed as digest-pinned provenance.

There is intentionally no successor ASM entry yet. A successor entry must be
added only after its final ELF and VK are built from a frozen source revision by
the pinned release workflow and their predicate and checksums are reviewed.
Until then, production SP1 startup and non-proving predicate routing fail closed
for that artifact. Regtest development remains available through the explicit
`native_development` backend, which cannot be selected on another network.

For a new release:

1. Freeze the guest-affecting source and lockfiles in a commit.
2. Build the final artifacts with the pinned SP1 CLI and digest-pinned builder.
3. Add a `qualified` manifest whose `source.revision` is that frozen commit,
   append it to `EMBEDDED_MANIFESTS`, and review the derived artifact IDs.
4. Tag the manifest commit. The release job rebuilds the exact source revision,
   verifies all resolved SP1 versions and every ELF/VK byte against the embedded
   manifest, then creates a new release. It refuses to reuse any existing draft
   or published release.
