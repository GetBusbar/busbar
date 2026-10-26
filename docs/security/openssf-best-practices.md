# OpenSSF Best Practices Badge — criteria mapping

**Purpose.** A self-certification worksheet for the
[OpenSSF Best Practices Badge](https://www.bestpractices.dev/) (formerly the CII Best
Practices Badge). Each **passing**-level criterion is listed with the concrete evidence in
this repository that satisfies it, so each answer carries a citation rather than resting on
memory. A **silver** on-ramp is noted at the end.

> **Status.** The project is **registered and passing.** Project ID **14739**
> ([`bestpractices.dev/projects/14739`](https://www.bestpractices.dev/projects/14739)),
> repo URL `https://github.com/GetBusbar/busbar`, was at **100% of the passing tier** before the release, CodeQL, fuzz and coverage workflows were deleted on 2026-10-01; the rows below marked **Unmet** no longer hold, and the live badge answers need updating to match. Checks on each change now run in ModernCI from `.ci/default.yaml`.
> The live badge is in [`README.md`](../../README.md). This worksheet is now maintenance
> documentation: keep the rows below true as the repo evolves, and use the silver on-ramp to
> drive the next tier.

> Aligns with [`docs/security/1.6.0-security-posture.md`](1.6.0-security-posture.md),
> [`SECURITY.md`](../../SECURITY.md), and [`THREAT_MODEL.md`](../../THREAT_MODEL.md). Where a
> criterion is honestly *partial* or *roadmap*, this doc says so — the posture doc's rule is
> that a claim you can verify is worth more than one you have to trust.

The badge criteria are grouped as the bestpractices.dev form groups them. Answers are
`Met` unless noted.

## Basics

| Criterion | Status | Evidence |
|---|---|---|
| `description_good` — project describes what it does | Met | [`README.md`](../../README.md) top matter; [GetBusbar.com](https://getbusbar.com). |
| `interact` — a way for users to interact / contribute | Met | [`CONTRIBUTING.md`](../../CONTRIBUTING.md), GitHub Issues, [Discord](https://discord.com/invite/nnK5evXERp). |
| `contribution` — contribution process documented | Met | [`CONTRIBUTING.md`](../../CONTRIBUTING.md); [`CODE_OF_CONDUCT.md`](../../CODE_OF_CONDUCT.md). |
| `contribution_requirements` — requirements stated | Met | `CONTRIBUTING.md` (DCO/PR flow, gate expectations). |
| `floss_license` + `license_location` — OSI license at a known location | Met | [`LICENSE`](../../LICENSE) — Apache-2.0 at repo root; badge in README. |
| `documentation_basics` + `documentation_interface` | Met | [`docs/`](../) (getting-started, operations), `README.md`, `RELEASE.md`. |
| `sites_https` — project sites use HTTPS | Met | github.com/GetBusbar/busbar, getbusbar.com, bestpractices.dev all HTTPS. |
| `discussion` — user discussion channel | Met | GitHub Issues + Discord. |
| `english` — docs in English | Met | All docs are in English. |
| `maintained` — actively maintained | Met | Recent commit history; automated dependency PRs (`.github/dependabot.yml`, cargo + github-actions, weekly, targeting `dev`). |

## Change control

| Criterion | Status | Evidence |
|---|---|---|
| `repo_public` + `repo_track` + `repo_distributed` | Met | Public Git repo on GitHub. |
| `version_unique` + `version_semver` | Met | SemVer version in `Cargo.toml` (`RELEASE.md`). |
| `version_tags` | Met | Past releases carry `vX.Y.Z` tags. In 1.6.0 the tag is an output of the green `qa` → `main` release, which is not written yet (`.ci/qa.yaml`, `RELEASE.md`). |
| `release_notes` + `release_notes_vulns` | Met | [`CHANGELOG.md`](../../CHANGELOG.md) with a `Security` section per the backport policy in `SECURITY.md`. |

## Reporting

| Criterion | Status | Evidence |
|---|---|---|
| `report_process` — bug reporting process | Met | GitHub Issues; `CONTRIBUTING.md`. |
| `report_tracker` — issue tracker | Met | GitHub Issues. |
| `report_responses` — responses to reports | Met | Maintainer-triaged issues; `SECURITY.md` sets a 48h acknowledgement target for security reports. |
| `vulnerability_report_process` — documented private vuln reporting | Met | [`SECURITY.md`](../../SECURITY.md) — private email `security@getbusbar.com` + GitHub private advisories. |
| `vulnerability_report_private` — a private channel exists | Met | `SECURITY.md` — GitHub private vulnerability reporting + `security@`. |
| `vulnerability_report_response` — 14-day response commitment | Met | `SECURITY.md` commits to a **48-hour** acknowledgement (well inside the 14-day floor). |

## Quality

| Criterion | Status | Evidence |
|---|---|---|
| `build` + `build_common_tools` + `build_floss_tools` | Met | `cargo` build; standard Rust toolchain pinned in `rust-toolchain.toml`. |
| `automated_test_suite` + `test` + `test_invocation` | Met | About ten thousand tests across `crates/`, plus the conformance suites under `testing/`; `cargo test`. Every change into `dev` is judged by ModernCI from `.ci/default.yaml` (preflight, clippy, compile, test, doctest, deletion matrix, `cargo deny`, the feature-gated suites). |
| `test_most` — tests cover most of the code | Unmet | The test-effectiveness gate and the workflow that uploaded coverage to Codecov were deleted (2026-10-01); no job here measures coverage or test effectiveness today. |
| `test_policy` + `tests_are_added` + `tests_documented_added` | Met | Repo discipline: a bug becomes a regression test **and**, where the class allows, a CI gate — documented in `docs/security/1.6.0-security-posture.md` §4.2; the security rules live as tests in `crates/busbar-contract/tests/source_rules/`. |
| `warnings` + `warnings_fixed` + `warnings_strict` | Unmet | The `preflight` check in `.ci/default.yaml` enforces `cargo fmt --check` and a current `Cargo.lock`; its C-header step still calls the removed `xtask`. `cargo clippy -- -D warnings` runs on every change, judged no-worse-than-base (`baseline: target`), so a warning already red at the base is not blocking. |

## Security

| Criterion | Status | Evidence |
|---|---|---|
| `know_secure_design` + `know_common_errors` | Met | [`THREAT_MODEL.md`](../../THREAT_MODEL.md) (T1–T12 with in-code mitigations) and the posture doc's six structural defenses. |
| `crypto_published` + `crypto_call` + `crypto_floss` | Met | No home-grown crypto; standard vetted crates. Constant-time secret comparison (`constant_time_eq`, `crates/busbar-contract/src/redacted.rs`), SHA-256 digests, Ed25519 signatures. |
| `crypto_keylength` + `crypto_working` + `crypto_weaknesses` | Met | SHA-256, ed25519 plugin signing key, TLS/mTLS. See posture doc §2.6, §2.3. |
| `crypto_pfs` + `crypto_password_storage` + `crypto_random` | Partial | TLS; in-memory secrets held as `Secret<T>` / `SecretRef` (posture doc §2.2); virtual keys are signed tokens, not stored secrets. **Not met for recoverable credentials:** signed-request secrets Busbar mints are stored in the configured store as plaintext behind a `v1:plain:` tag (`crates/busbar-contract/src/records.rs`); at-rest encryption is designed but not in this tree (THREAT_MODEL T10). |
| `delivery_mitm` — signed/hash-verified delivery | Unmet | The release build, SBOM, build-provenance attestation and cosign signing lived in the deleted release workflows; nothing builds or publishes until ModernCI's `qa` → `main` branch file (`.ci/qa.yaml`) signs and publishes the judged build on landing (`docs/design/BUSBAR-1.6.0.md` Part 6). Verify recipes for past releases: <https://getbusbar.com/security/>. |
| `delivery_unsigned` — no unsigned critical delivery | Unmet | Nothing is published until the engine ports the builds; see `RELEASE.md`. |
| `vulnerabilities_fixed_60_days` | Met | `SECURITY.md` backport policy: fix on `dev` first, severity-driven backport window. |
| `vulnerabilities_critical_fixed` | Met | Critical/High cherry-picked to the latest two minor lines with a GitHub Security Advisory + CVE (`SECURITY.md`). |
| `no_leaked_credentials` | Met | `Secret<T>` (no `Serialize`/`Deserialize`), `SecretRef` (inline literal refused), and the `source_rules/secrets.rs` tests on every change (`crates/busbar-contract/tests/source_rules/`). |
| `static_analysis` + `static_analysis_common_vulnerabilities` | Unmet | The CodeQL workflow was deleted. clippy and the `source_rules` tests run on every change, but they check this project's own rules, not common-vulnerability classes. |
| `static_analysis_fixed` + `static_analysis_often` | Partial | clippy on every change; there is no CodeQL job. |
| `dynamic_analysis` / `dynamic_analysis_unsafe` | Partial | The loom concurrency model runs on every change in the feature-gated suite (`.ci/default.yaml`, `test-gated`). One cargo-fuzz target is in `fuzz/`; nothing in the pipeline runs it. |
| **Dependency advisory scanning** (`static_analysis` supply-chain dimension) | Met | `cargo deny check` (advisories, licenses, sources, bans; `deny.toml`) runs on every change (`.ci/default.yaml`, check `deny`); Dependabot opens advisory-driven update PRs. cargo-audit and OpenSSF Scorecard no longer run; cargo-vet is initialised (`supply-chain/`) but no check runs it. |

## Analysis / other

| Criterion | Status | Evidence |
|---|---|---|
| `hardening` — hardening mechanisms used | Met | Self-hosted static binary, credential boundary, fail-closed governance, the connector's destination guard, a validated plugin ABI and signed plugin loading (posture doc §2.3–§2.6); k8s `securityContext` example in README. |
| `assurance_case` — a documented assurance argument | Met | `docs/security/1.6.0-security-posture.md` is a class→mechanism→check assurance case with its gaps listed. |

## Roadmap items honestly not yet at passing

Called out so the self-certification stays credible (all tracked in the posture doc §5):

- **`vulnerability_report_credit` / bug bounty** — no paid bounty yet; `SECURITY.md` publishes a
  safe harbor and credits reporters (hall-of-fame planned). Passing does *not* require a paid
  bounty, so this does not block the badge.
- **Security owner named** — the maintainer is the named security contact (`SECURITY.md`); the
  project's bus factor is 1 (solo), tracked as a silver growth item below.

## Silver tier — criteria mapping

The project is at 100% of the **passing** tier; this section tracks **silver**. Silver adds
governance, review discipline, and stronger crypto/quality requirements. Each row is `Met` with
evidence, or **`Not met (solo)`** where the criterion needs more than one person and is honestly
unmet for a solo-maintained project — we leave those open rather than overclaim.

### Met now (docs / policy / already in place)

| Silver criterion | Status | Evidence |
|---|---|---|
| `dco` — Developer Certificate of Origin on contributions | Met | `CONTRIBUTING.md` sign-off/DCO flow. |
| `governance` — documented governance | Met | Maintainer-led governance; roles in `SECURITY.md` + `CONTRIBUTING.md`. |
| `code_of_conduct` | Met | [`CODE_OF_CONDUCT.md`](../../CODE_OF_CONDUCT.md). |
| `roles_responsibilities` — roles documented | Met | Maintainer role + **named security contact** (`SECURITY.md`). |
| `documentation_roadmap` | Met | `docs/roadmap.md`; `docs/design/BUSBAR-1.6.0.md`. |
| `documentation_architecture` | Met | `README.md` architecture; `docs/security/1.6.0-security-posture.md`; `THREAT_MODEL.md`. |
| `documentation_security` — how to report + secure use | Met | `SECURITY.md`, posture doc, k8s `securityContext` example in README. |
| `documentation_quick_start` | Met | `README.md` quick start; `docs/` getting-started. |
| `documentation_current` | Met | Docs tracked with releases; `CHANGELOG.md` sections per version (`RELEASE.md`). |
| `coding_standards` + `coding_standards_enforced` | Met | `rustfmt` + `clippy -D warnings` + the `source_rules` tests, enforced on every change by ModernCI. |
| `test_continuous_integration` | Met | ModernCI judges every change into `dev` from `.ci/default.yaml` (required check `ci`). |
| `test_policy_mandated` + `tests_documented_added` | Met | Bug→regression-test(+gate) discipline (posture doc §4.2). |
| `warnings_strict` | Met | `clippy -D warnings` workspace-wide. |
| `vulnerability_report_credit` | Met | `SECURITY.md` credits reporters who wish to be credited. |
| `vulnerability_response_process` | Met | `SECURITY.md` — 48h ack, coordinated disclosure, advisory + CVE. |
| `vulnerabilities_fixed_60_days` | Met | `SECURITY.md` severity-driven backport policy. |
| `signed_releases` | Unmet | See `delivery_mitm`: the signing steps were in the deleted release workflows. |
| `version_tags_signed` | Unmet | Release tags are an output of the green release, never hand-cut (`RELEASE.md`), but the 1.6.0 release step (`.ci/qa.yaml`) that would sign them is not written yet. |
| `installation_common` | Met | `cargo` install + published GHCR / Docker Hub image. |
| `external_dependencies` — deps listed | Met | `Cargo.toml` / `Cargo.lock` (the SBOM emitted at release was produced by the deleted release workflows). |
| `dependency_monitoring` | Met | `.github/dependabot.yml` (cargo, actions, docker); `cargo deny` on every change. cargo-audit and Scorecard no longer run. |
| `updateable_reused_components` | Met | Standard cargo dependency management; dependabot PRs. |
| `input_validation` — documented | Met | The LLM plane's dialect readers and the shared ingress reject (posture doc §2.1). The fuzz target in `fuzz/` is not run by any pipeline job. |
| `crypto_used_network` + `crypto_tls12` + `crypto_certificate_verification` | Met | TLS / mTLS floor; posture doc §2.x. |
| `crypto_weaknesses` + `crypto_algorithm_agility` + `crypto_credential_agility` | Met | Vetted crates, no home-grown crypto; posture doc §2.3 / §2.6. |
| `hardening` | Met | Static binary, credential boundary, fail-closed governance, destination guard, signed plugin loading; k8s `securityContext`. |
| `assurance_case` | Met | `docs/security/1.6.0-security-posture.md` class→mechanism→check case. |
| `security_review` — design **and** code reviewed | Met (internal) | `THREAT_MODEL.md` design review + the posture-doc audit + the repo's documented internal code review process, which silver accepts. |
| `dynamic_analysis` — a dynamic/fuzz tool is applied | Unmet | See `dynamic_analysis` above. |

### Coverage statement (for `test_statement_coverage80`)

Coverage is measured on **product paths only** via Codecov (`codecov.yml` ignores tests, examples,
sample plugins, and docs) and surfaced on the README badge and per-PR context. By design coverage
is **informational, not a hard gate**; no job currently uploads coverage (the workflow that did was deleted), so the Codecov figure is stale. We treat **80% statement coverage on product paths** as
the working floor, but with no job uploading coverage and the test-effectiveness score deleted,
`test_statement_coverage80` cannot be attested today.

### Honestly not met — require more than one person (solo project)

Busbar is currently solo-maintained. These silver criteria are people-gated and we leave them
**open rather than overclaim**:

- `two_person_review` — silver expects ≥50% of new commits reviewed by someone other than the
  author. Not achievable solo. *Mitigation:* every change still passes ModernCI's checks
  (`.ci/default.yaml`), including `clippy -D warnings` and the `source_rules` tests, before merge.
- `contributors_unassociated` — expects contributors from ≥2 organizations. **Not met (solo).**
- `bus_factor` (≥2) — the project's bus factor is 1 today. A named security contact is in place
  (`SECURITY.md`); raising the bus factor is a growth item, not a docs fix.
- `access_continuity` / succession — single maintainer; documented as a known gap, revisited as the
  team grows.

Per-file headers (`copyright_per_file` / `license_per_file`, *suggested* at silver): most Rust
sources carry an `SPDX-License-Identifier: Apache-2.0` and copyright header, but not all, and no
check enforces it; the repository is uniformly Apache-2.0 with `LICENSE` at the root.

## Registration (done — maintenance reference)

Registration is complete: the project is **14739** and the live badge is wired into
`README.md`. To re-verify or update the entry:

1. Sign in at <https://www.bestpractices.dev/> with the GitHub maintainer account.
2. Open [`bestpractices.dev/projects/14739`](https://www.bestpractices.dev/projects/14739)
   (repo URL `https://github.com/GetBusbar/busbar`).
3. Walk each row above and confirm each answer still holds with its cited link; the form
   auto-detects several (repo public, license, HTTPS) from the URL.
4. The badge in `README.md` is
   `https://www.bestpractices.dev/projects/14739/badge`
   linking to `https://www.bestpractices.dev/projects/14739`.
