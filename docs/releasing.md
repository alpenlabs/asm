# Releasing

A release is a `v*` tag. Pushing one runs `.github/workflows/release.yml`. It builds the SP1 ASM
guest for every network in `crates/params/envs/` except `dev`, publishes the files in a GitHub
release, and copies them to S3. `dev` gets no released guest, because it is only for local runs and
CI.

The [guest builder README](../guest-builder/sp1/README.md) explains how the guest is built and how
to check a published one against its source.

## Branches and tags

Development happens on `main`. Each release line has its own branch, named `releases/vX.Y.x`, for
example `releases/v0.6.x`.

Until the branch exists, you can tag the line's rcs (`vX.Y.0-rc.N`) on `main`. Every other tag needs
the branch: `vX.Y.0` and each patch release must point at a commit on it. Once the branch exists,
the rcs must come from it too, because a tag cut from `main` would carry everything `main` changed
since.

## Cutting a release

1. Tag `vX.Y.0-rc.1` on `main` and push the tag. Fixes land on `main` and go out in the next rc.
2. When an rc is ready to ship, cut `releases/vX.Y.x` at its commit, then tag `vX.Y.0` on the same
   commit:

   ```bash
   git push origin <commit>:refs/heads/releases/vX.Y.x
   git tag -a vX.Y.0 <commit> -m vX.Y.0
   git push origin refs/tags/vX.Y.0
   ```

   Cut the branch earlier if `main` starts taking work for the next line while this line still
   needs rcs. From then on, land fixes on `main` first, cherry-pick them onto the branch, and tag
   the next rc from the branch.
3. Tag patch releases from the branch.
4. Once the release is published, add the spec ID the guest compiles to its notes by hand.
   Neither the generated notes nor the S3 manifest record it.

If a tag isn't on the right branch, the run stops at "Check the tag's branch", before it creates the
release. Don't publish a release for that tag by hand. A published release is immutable, so it can
never get the guest files. Cut the branch, then tag the next patch release from it.

The tag does not build the `strata-asm-runner` image or the bare-metal binary. Run "Docker Publish
to ECR" (see the [Docker image README](../docker/README.md)) and "Publish Bare-Metal Binaries (S3)"
by hand from `main`, with the tag as `ref`.

## What a release publishes

Each network's guest is built with its params file at the tag, `crates/params/envs/<env>.json`. For
each network, the GitHub release holds:

- `<env>-asm.elf`, the guest program
- `<env>-asm-predicate.txt`, the SP1 Groth16 predicate that the runner's `[[execution.targets]]`
  entries use

The release notes name the commit and the SP1 version. For each network they give the params file,
the vkey hash, and the predicate.

After the release is published, the files are copied to S3:

```
s3://alpen-mosaic-artifacts/elfs/asm-runner/<env>/<commit>/
  asm.elf  asm.elf.sha256
  asm-predicate.txt  asm-predicate.txt.sha256
  SHA256SUMS
  manifest.json
```

The files drop their network prefix there. `manifest.json` is written last and marks a completed
upload. It records the network, the ref and commit, the params file's path, the SP1 version, the
predicate, and every file's SHA-256.

## What `release.yml` does

1. It checks that the tag points at a commit on the right branch, as
   [Branches and tags](#branches-and-tags) describes. If it doesn't, nothing is published.
2. It creates a draft GitHub release. A tag with a suffix, such as `-rc.1`, makes a
   prerelease.
3. It runs `.github/workflows/publish-asm-guest.yml` once per network. Each run does a reproducible
   build of the guest and attaches its files to the draft.
4. It adds the guests' section to the release notes.
5. It publishes the release once the draft holds exactly the files this run built, byte for byte,
   and the tag still points at the commit they were built from.
6. It checks each published file against the release's attestation and copies it to S3. This job
   waits until a reviewer approves the `baremetal-binaries` environment.

The workflow that runs for a tag is the copy at the tagged commit. A change to `release.yml` or its
scripts applies to a tag only if the tagged commit has it. On a release branch, cherry-pick the
change first.

## Building a guest outside a release

Run the "Publish ASM Guest" workflow (`.github/workflows/publish-asm-guest.yml`) from `main` with
the ref to build and the network. Without `release_tag`, it uploads straight to the same S3 layout.
Use it for `dev`, or for a build that isn't a release.
