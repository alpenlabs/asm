# ASM Runner Docker Image

`docker/Dockerfile` builds `strata-asm-runner` into a self-contained image. It is
the same shape as the mosaic image: an Ubuntu 24.04 builder with the repo's pinned
nightly compiles the binary, and a slim Ubuntu 24.04 runtime ships it. It is a
drop-in replacement for the image strata-bridge builds: linux/amd64, runs as root,
same entrypoint path and `CONFIG_FILE` / `PARAMS_FILE` contract.

The binary is built with `--features sp1`, matching the deployed image and the
bare-metal binary. It serves the SP1 backend and the no-orchestrator mode; the
`sp1` feature compiles the native backend out, so a `kind = "native"` config is
rejected at startup, exactly as with the image strata-bridge builds. No SP1 guest program
is compiled during the build; guest ELFs are runtime inputs referenced from
`config.toml`.

## Build

From the repository root:

```sh
docker buildx build --file docker/Dockerfile --tag strata-asm-runner:local --load .
```

## Run

The entrypoint expects the config at `/app/config.toml` and the params at
`/app/asm-params.json`. Override the paths with `CONFIG_FILE` / `PARAMS_FILE`;
the entrypoint already passes `--config` and `--params`, so those two flags cannot
be given as extra arguments. Any other arguments are forwarded to the binary.

```sh
docker run --rm \
  -v "$PWD/config.toml:/app/config.toml:ro" \
  -v "$PWD/asm-params.json:/app/asm-params.json:ro" \
  -v "$PWD/data:/app/data" \
  -p 9010:9010 \
  strata-asm-runner:local
```

## Publish

`.github/workflows/docker-publish-ecr.yml` builds the image, scans it with Trivy,
and pushes it to public ECR (`public.ecr.aws/z5c7y9u9/strata-asm-runner`). The
image tag is the 8-character short SHA of the built ASM commit, so a consumer that
pins ASM by commit (for example strata-bridge's `Cargo.toml`) can pull the matching
image directly. Only `main`'s head or a commit behind a git tag gets that bare tag;
any other branch is published as `dev-<short SHA>`. ECR Public cannot make tags
immutable, so the workflow refuses to re-push a bare short-SHA tag that already
exists; publish a rebuild under a `dev-`, `manual-` or `test-` tag instead.

The workflow runs on manual dispatch only, with an optional `ref` (branch, tag,
or commit; defaults to the branch selected in the UI) and an optional `image_tag`
override, which must start with `dev-`, `manual-` or `test-` so an override can
never overwrite a production short-SHA tag.

Repository setup, mirroring mosaic and strata-bridge:

- a GitHub Environment named `AWS`
- one variable on that environment: `PUBLIC_AWS_ROLE_TO_ASSUME`, the shared public
  ECR push role, whose trust policy must include this repository
- the tag ruleset that restricts tag creation: the workflow treats any commit
  behind a git tag as reviewed and publishes it under the bare short-SHA tag

The workflow fails early with a clear error if the role variable is missing.

### Trivy gate

The image is built to the local daemon and scanned before anything is pushed:

| Scan | Format | Severity | Behaviour |
|---|---|---|---|
| Hard gate | JSON | HIGH, CRITICAL | Fails the run; the image is never pushed if a vulnerability with an available fix is found (CVEs with no fix yet are not gated) |
| Security tab | SARIF | HIGH, CRITICAL, MEDIUM, LOW | Advisory; uploaded to GitHub Code Scanning |
| SBOM | CycloneDX | all | Advisory; attached as a workflow artifact |

The run summary shows a table of any HIGH/CRITICAL findings, and the
`trivy-strata-asm-runner-<tag>` artifact holds the raw JSON, SARIF, and SBOM.
Justified CVE suppressions go in `.trivyignore` at the repo root via a reviewed PR.
