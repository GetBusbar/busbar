# OpenSSF Best Practices Badge — criteria mapping

**Purpose.** A self-certification worksheet for the
[OpenSSF Best Practices Badge](https://www.bestpractices.dev/) (formerly the CII Best
Practices Badge). Each **passing**-level criterion is listed with the concrete evidence in
this repository that satisfies it, so each answer carries a citation rather than resting on
memory. A **silver** on-ramp is noted at the end.

> **Status.** The project is **registered and passing.** Project ID **14739**
> ([`bestpractices.dev/projects/14739`](https://www.bestpractices.dev/projects/14739)),
> repo URL `https://github.com/GetBusbar/busbar`, currently at **100% of the passing tier**.
> The live badge is in [`README.md`](../../README.md). This worksheet is now maintenance
> documentation: keep the rows below true as the repo evolves, and use the silver on-ramp to
> drive the next tier.

> Aligns with [`docs/design/1.6.0-security-posture.md`](../design/1.6.0-security-posture.md),
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
| `maintained` — actively maintained | Met | Recent commit history; monthly dependency refresh workflow (`sched-monthly-refresh.yml`); automated dependency PRs (`.github/dependabot.yml`, cargo + github-actions, weekly). |

## Change control

| Criterion | Status | Evidence |
|---|---|---|
| `repo_public` + `repo_track` + `repo_distributed` | Met | Public Git repo on GitHub. |
| `version_unique` + `version_semver` | Met | SemVer version in `Cargo.toml`; signed version tags (`RELEASE.md`). |
| `version_tags` | Met | Releases cut from `main` under a signed `vX.Y.Z` tag. |
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
| `automated_test_suite` + `test` + `test_invocation` | Met | 2,000+ unit tests, offline acceptance harness; `cargo test`. Full CI in `ci.yml` (owned separately) and `qa-gate.yml`. |
| `test_most` — tests cover most of the code | Met | Codecov coverage badge in README; a mutation-strength test gate (`scripts/run-mutants-ec2.sh`, `gate-mutants.yml`). |
| `test_policy` + `tests_are_added` + `tests_documented_added` | Met | Repo discipline: a bug becomes a regression test **and**, where the class allows, a CI gate — documented in `docs/design/1.6.0-security-posture.md` §4.2 and enforced by the xtask gate battery (`xtask/src/gates/`). |
| `warnings` + `warnings_fixed` + `warnings_strict` | Met | `cargo clippy --workspace --all-targets -- -D warnings` (warnings are errors) in CI and `sched-monthly-refresh.yml`. |

## Security

| Criterion | Status | Evidence |
|---|---|---|
| `know_secure_design` + `know_common_errors` | Met | [`THREAT_MODEL.md`](../../THREAT_MODEL.md) (T1–T9 with in-code mitigations) and the posture doc's six structural defenses. |
| `crypto_published` + `crypto_call` + `crypto_floss` | Met | No home-grown crypto; standard vetted crates. Constant-time secret comparison (`crates/api/src/auth.rs`), SHA-256 digests. |
| `crypto_keylength` + `crypto_working` + `crypto_weaknesses` | Met | SHA-256, ed25519 plugin signing key, TLS/mTLS. See posture doc §2.6, §2.3. |
| `crypto_pfs` + `crypto_password_storage` + `crypto_random` | Met | TLS; secrets stored via `Redacted<T>` / `SecretRef` (posture doc §2.2), never plaintext at rest by design. |
| `delivery_mitm` — signed/hash-verified delivery | Met | Release binaries carry a GitHub **build-provenance (SLSA) attestation**; the GHCR image is **cosign**-signed (keyless, `docker.yml`); verify recipes at <https://getbusbar.com/security/>. |
| `delivery_unsigned` — no unsigned critical delivery | Met | Release refuses to ship from a non-attested/red commit — `RELEASE.md` (no override); `--signer-workflow` pin in `release.yml`. |
| `vulnerabilities_fixed_60_days` | Met | `SECURITY.md` backport policy: fix on `dev` first, severity-driven backport window. |
| `vulnerabilities_critical_fixed` | Met | Critical/High cherry-picked to the latest two minor lines with a GitHub Security Advisory + CVE (`SECURITY.md`). |
| `no_leaked_credentials` | Met | `Redacted<T>` (no `Serialize`/`Deserialize`), `SecretRef` (inline literal unrepresentable), and the `cargo xtask gate settings-leak` gate. |
| `static_analysis` + `static_analysis_common_vulnerabilities` | Met | CodeQL (`qa-codeql.yml`); clippy at `-D warnings`; the xtask gate battery. |
| `static_analysis_fixed` + `static_analysis_often` | Met | CodeQL on every `qa` promotion; clippy on every push. |
| `dynamic_analysis` / `dynamic_analysis_unsafe` | Met | loom concurrency model (`scripts/loom.sh`) for the config-swap invariant; a mutation-strength test gate. |
| **Dependency advisory scanning** (`static_analysis` supply-chain dimension) | Met | `qa-security.yml` runs **cargo-deny** (advisories · licenses · sources · bans) **and cargo-audit** (RustSec) at the qa boundary and weekly; **OpenSSF Scorecard** (`sched-scorecard.yml`) weekly. |

## Analysis / other

| Criterion | Status | Evidence |
|---|---|---|
| `hardening` — hardening mechanisms used | Met | Self-hosted static binary, credential boundary, fail-closed governance gauntlet, `catch_unwind` FFI confinement (posture doc §2.3–§2.6); k8s `securityContext` example in README. |
| `assurance_case` — a documented assurance argument | Met | `docs/design/1.6.0-security-posture.md` is a full class→mechanism→gate assurance case. |

## Roadmap items honestly not yet at passing

Called out so the self-certification stays credible (all tracked in the posture doc §5):

- **`vulnerability_report_credit` / bug bounty** — no paid bounty yet; `SECURITY.md` publishes a
  safe harbor and credits reporters (hall-of-fame planned). Passing does *not* require a paid
  bounty, so this does not block the badge.
- **Dedicated security owner** — currently the maintainers (`SECURITY.md` roadmap). Not a
  passing blocker.

## Silver on-ramp (after passing)

The credible next steps toward **silver**, most already partly in place:

- `crypto_used_network`, `crypto_tls12` — document the TLS floor explicitly.
- `installation_common`, `external_dependencies` — already strong (SBOM + pinned deps).
- `test_statement_coverage80` — Codecov already reports; state the threshold.
- `signed_releases` (silver) — already met (attestation + cosign); just cite it.
- `hardened_site`, `security_review` — cite `THREAT_MODEL.md` + the posture-doc audit and the
  `security-review` process.
- **Name a security owner** and stand up the safe-harbor/hall-of-fame intake — the two roadmap
  items above — to clear the silver governance questions.

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
