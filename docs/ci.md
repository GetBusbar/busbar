# What CI checks

Core's CI runs in the private delivery system. The pipeline definition is not in
this repository: core has no `.gitlab-ci.yml` of its own and includes the shared definition from
GetBusbar/busbar-release, file `ci/core.yml` (with `ci/common.yml`, `ci/conformance.yml`,
`ci/qa.yml`, `ci/drop.yml` and `ci/ghmirror.yml`). GitHub Actions is retired; the GitHub repository is
the public mirror, pushed by CI (`ci/ghmirror.yml`). This page lists what that definition runs, so a
reader of this repository can see it.

## On every change to `dev`

A change lands on `dev` and the `dev` pipeline judges it. `quick-check` runs first; every other check
job that declares it as a dependency waits for it. Independent report jobs may run alongside it.

Ordinary branch pushes and merge-request events do not start a pipeline under the current
workflow. A successful MR status is not evidence that this revision compiled. The integrated
`dev` pipeline supplies that evidence.

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
| `unsafe-count` | the per-crate `unsafe` count against the forbid baseline; the report is published with each release tag | yes |
| `miri` | the unit tests of `busbar-ffi`, the one crate that holds `unsafe`, under Miri (default features and `host`) | no: it reports and gates nothing yet |
| `fuzz` | every `cargo-fuzz` target for a bounded time, on `dev` and the nightly; it starts when the tree gains a `fuzz/` workspace, which core does not have yet | no: it reports and gates nothing yet |
| `coverage` | line coverage of the workspace tests (`cargo llvm-cov`), on `dev` and the nightly, published as a report | no: a report, never a gate |
| `c-header` | the generated static asserts of `busbar_plugin.h` and its C fixture under `-std=c11 -Wall -Werror`, with two compilers | yes |
| `conformance` | core's own conformance suites (`ci/conformance.yml`) | yes |
| `red-proof` | on a commit whose message carries `[red-proof <crate>::<test>]` (not on `dev`): that one test must compile and then fail (nextest exit 100) | yes |

## Scheduled and on demand

| Job | When | What it runs |
|---|---|---|
| `qa` | nightly schedule `qa-nightly`, or a pipeline started by hand | release and debug builds of `busbar`, every conformance suite against them, and the kernel's loom tests in release mode |
| `oracle` | every `dev` pipeline (`ci/qa.yml`), or by hand with `BUSBAR_ORACLE=1` | the black-box comparison of this build against the published 1.5.5 binary. It reports differences and gates nothing: it is `allow_failure`, and each difference is decided at the upgrade review |
| `bench` | `bench/*` branches | the benchmark suites |

## On a release tag

Nothing is published unless every blocking check of the pipeline passed.

- `release-build`, `release-build-arm`: the release binary of `crates/busbar` for each architecture,
  with a CycloneDX SBOM (`cargo cyclonedx`).
- `release`: uploads exactly the bytes the build produced, signed with cosign (`busbar.sigstore.json`).
- `release-assets`, `release-windows`: the shipped assets (PGO, then BOLT on Linux; Authenticode on
  Windows), each with its SBOM.
- `publish-images`: the OCI images for amd64 and arm64, built with build provenance and an SBOM
  attached, and cosign-signed by digest.
- `release-finalize` (manual): sums, signs, attests and publishes the GitHub release.

[docs/verify.md](verify.md) explains how to verify a release's signatures.

## Coverage and execution evidence

These are known gaps, also listed in the
[security posture](security/1.6.0-security-posture.md) (section 4.2):

- Coverage and Miri are configured as non-blocking jobs; fuzzing is conditional on a `fuzz/Cargo.toml` that this tree does not yet contain. Job definitions do not establish successful execution.
- No sanitizer runs over `busbar-ffi`; it is held by clippy with warnings denied, its loom model and Miri.

The coverage job emits `ci-reports/lcov.info` and `ci-reports/cobertura.xml` with 30-day
artifact retention. Its displayed percentage reads LLVM's `totals.lines.percent`, even though
the CI log labels it “Statement coverage”. This is line coverage, not proof of 80% statement
coverage. There is no threshold gate and no public default-branch coverage report linked here.
Issue #182 remains incomplete until public report publication and the requested execution
evidence exist; a configured job or green pipeline with allowed failures does not satisfy it.

The conformance execution catalog is [conformance/ci-coverage.json](../conformance/ci-coverage.json).
Its scope is execution coverage, not passing verdicts or certification. Core's job selects its
registered `dev` suites; plugins run their own suites against a published core pin. A suite's
presence in the catalog does not establish that the latest core and plugin revisions passed.
