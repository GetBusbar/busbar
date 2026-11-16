# What CI checks

Core's CI runs on GitLab (`github.com`, GetBusbar/busbar). The pipeline definition is not in
this repository: core has no `.gitlab-ci.yml` of its own and includes the shared definition from
GetBusbar/busbar-release, file `ci/core.yml` (with `ci/common.yml`, `ci/conformance.yml`,
`ci/qa.yml`, `ci/drop.yml` and `ci/ghmirror.yml`). GitHub Actions is retired; the GitHub repository is
the public mirror, pushed by CI (`ci/ghmirror.yml`). This page lists what that definition runs, so a
reader of this repository can see it.

## On every change to `dev`

A change lands on `dev` and the `dev` pipeline judges it. `quick-check` runs first; every other check
job waits for it, then they run in parallel.

| Job | What it runs | Blocking |
|---|---|---|
| `quick-check` | `cargo fmt --all --check`, then `cargo check --locked --workspace --all-targets --all-features` for every manifest of the workspace | yes |
| `lint` (`main`, `bans`, `nodefault`) | `cargo fmt --check`, the lockfile check, the bad-patterns scanner, `cargo clippy --workspace --all-targets --all-features`, the crate-wide clippy bans with `-D`, and a `--no-default-features` clippy pass with `-D warnings` | not yet: it reports in full, and its remaining findings are the Stage 2 worklist; it becomes blocking at the end of Stage 2 |
| `supply-chain` | `cargo deny check advisories bans licenses sources` on the workspace, `cargo deny check bans` on the shipped binary's graph, `osv-scanner` over every lockfile CI builds, and `cargo vet` | yes |
| `test-build`, `test` | the workspace test graph built once and run with `cargo nextest` in three hash partitions (every test in exactly one); then doctests (`cargo test --doc`), the plugin packer's tests, the system hammer and the `dist/default` lock check | yes |
| `root-tests` | the `busbar` crate's own tests and `dist/default/tests`, built in the default distribution's workspace | not yet, until `dist/default`'s plugin pins compile again |
| `repo-checks` | `ci/hop` (no entry hops off its thread) and `tools/ci-checks`: the migration text and overlay checks, the fleet manifest, export streams and the LOC report | yes |
| `core-source-checks` | `tools/ci-checks` source scans (C-TRANSPORT, C-NO-LICENCE, the plugin-word scan) | not yet: each turns blocking when the task that owns it lands |
| `ffi` | `cargo clippy -p busbar-ffi -- -D warnings` on its default and full feature sets, then the slot model under loom (`--cfg loom`) | yes |
| `c-header` | the generated static asserts of `busbar_plugin.h` and its C fixture under `-std=c11 -Wall -Werror`, with two compilers | yes |
| `conformance` | core's own conformance suites (`ci/conformance.yml`) | yes |
| `red-proof` | on a commit whose message carries `[red-proof <crate>::<test>]` (not on `dev`): that one test must compile and then fail (nextest exit 100) | yes |

## Scheduled and on demand

| Job | When | What it runs |
|---|---|---|
| `qa` | nightly schedule `qa-nightly`, or a pipeline started by hand | release and debug builds of `busbar`, every conformance suite against them, and the kernel's loom tests in release mode |
| `oracle` | the QA pipeline (`ci/qa.yml`) | the black-box comparison of this build against the published 1.5.5 binary |
| `bench` | `bench/*` branches | the benchmark suites |

## On a release tag

Nothing is published unless every check of the pipeline passed.

- `release-build`, `release-build-arm`: the release binary of `crates/busbar` for each architecture,
  with a CycloneDX SBOM (`cargo cyclonedx`).
- `release`: uploads exactly the bytes the build produced, signed with cosign (`busbar.sigstore.json`).
- `release-assets`, `release-windows`: the shipped assets (PGO, then BOLT on Linux; Authenticode on
  Windows), each with its SBOM.
- `publish-images`: the OCI images for amd64 and arm64, built with build provenance and an SBOM
  attached, and cosign-signed by digest.
- `release-finalize` (manual): sums, signs, attests and publishes the GitHub release.

[docs/verify.md](verify.md) explains how to verify a release's signatures.

## Not yet run

These are known gaps, also listed in the
[security posture](security/1.6.0-security-posture.md) (section 4.2):

- No statement-coverage report is produced or published.
- No fuzz target runs in CI.
- Neither Miri nor a sanitizer runs over the crates that hold `unsafe` code (`busbar-ffi` is held by
  clippy with warnings denied and by its loom model).
