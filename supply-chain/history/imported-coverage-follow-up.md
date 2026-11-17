# Imported coverage follow-up, 2026-11-17

This is evidence for core #390 against core `5edf820275`. It is not an audit,
exemption, publisher-trust decision, or a passing cargo-vet result.
The baseline [coverage inventory](coverage-gaps.tsv) stays unchanged.

## Exact import repair

Both stores now import the following existing `safe-to-deploy` records:

| Provider | Record |
| --- | --- |
| Bytecode Alliance | Full `pkg-config 0.3.25` |
| Mozilla | Delta `0.3.25 -> 0.3.26` |
| Bytecode Alliance | Delta `0.3.26 -> 0.3.29` |
| Bytecode Alliance | Delta `0.3.29 -> 0.3.32` |
| Mozilla | Delta `0.3.32 -> 0.3.34` |

This creates a connected path to the locked registry identity
`pkg-config 0.3.34` in both root and default. Record content is unchanged except
for cargo-vet's import namespace in each TOML table header. No criterion mapping,
publisher trust, exemption, local audit, source URL, dependency or version changes.

[upstream-coverage-sources.tsv](upstream-coverage-sources.tsv) pins the seven
approved providers checked, including Embark (per DEP-5, not currently configured).
Each URL addresses the exact Git revision; the SHA-256 covers the complete fetched
audit file. The five inserted records were compared with these immutable sources.
No other package in the baseline gap inventory has a complete applicable path in
these snapshots. Static remaining counts are **12 root and 13 default identities**;
CI must resolve the complete graphs before any claim of full coverage.

## Remaining disposition

| Identity (see baseline TSV for full Git revision) | Evidence and next permissible action |
| --- | --- |
| `aws-lc-sys 0.47.0@git:3469edb` | Aranya has only a registry `0.28.0 -> 0.39.0` delta. Obtain external coverage of the exact fork, including a covered base, or separately approve a trust disposition. |
| `backon 1.6.0` | Aranya has only `safe-to-run` delta `1.3.0 -> 1.4.0`, with no applicable full base in the checked providers. It neither reaches 1.6.0 nor establishes deployment coverage. External coverage or explicit trust disposition required. |
| `cmake 0.1.58` | Google full 0.1.49 plus Aranya delta to 0.1.54 provides a covered alternative. The locked aws-lc-sys manifest accepts ^0.1.54. See the tradeoff below before a version decision. No audit path reaches 0.1.58. |
| `dunce 1.0.5@git:bb4757b` | Aranya and Zcash each audit registry 1.0.5. Neither covers the fork delta. Returning to registry code would discard the retained Windows path fixes; require external exact-delta coverage or an explicit disposition. |
| `fs_extra 1.3.0@git:70f4786` | No matching audit, wildcard, or publisher entry in the seven snapshots. External exact-fork coverage or explicit disposition required. |
| `granit-parser 2.1.0@git:d31e929` | No matching records. The mandated YAML stack's patch cannot be certified by unrelated registry identity. External exact-fork coverage or explicit disposition required. |
| `h2 0.4.18@git:d6146a5` | Registry deltas and upstream publisher-trust entries exist; none attests the fork. Do not downgrade to the old audited 0.4.x deltas: RustSec now requires >=0.4.16 for RUSTSEC-2026-0258. |
| `jobserver 0.1.35@git:fbe3efc` | Registry deltas reach 0.1.33; upstream publisher-trust entries do not cover the fork. External exact-fork coverage or explicit disposition required. |
| `lexopt 0.3.2` | No matching records. External coverage or explicit trust disposition required; replacing the approved CLI lexer requires dependency design and behavioral/performance qualification. |
| `serde-saphyr 2.1.1@git:a94d2da` | No matching records. Mandated YAML stack; external exact-fork coverage or explicit disposition required. |
| `sseer 0.3.1` | No matching records. External coverage or explicit trust disposition required; a parser replacement needs dependency design and existing SSE behavior/benchmark qualification. |
| `stringprep 0.1.5@git:e81fc4b` (default only) | Embark full registry 0.1.2 does not reach registry 0.1.5 or this fork. No usable exact path; external coverage or explicit disposition required. |
| `tungstenite 0.29.0@git:893a21f` | No matching records. External exact-fork coverage or explicit disposition required. |
| `unicode-properties 0.1.5` (default only) | No matching records. External coverage or explicit trust disposition required; older Unicode table versions are not interchangeable correctness evidence. |

The cmake alternative is a candidate, not an adopted downgrade: upstream's
[0.1.58 changelog](https://github.com/rust-lang/cmake-rs/blob/v0.1.58/CHANGELOG.md)
records Visual Studio 2026, build-directory/path handling, CMake fallback/version
handling and i686 Windows changes after 0.1.54. A version decision needs two fresh
dependency-design reviews and platform CI. Aranya also records trust in cmake
publisher user-id 1 over 2019-03-26 through 2026-05-16. That is an upstream trust
suggestion, not our adopted trust; the exact release's publisher must be verified
before considering it. The crates.io release API was unavailable (HTTP 403) during
this check, so no publisher identity was inferred.

For each remaining row the decision is concrete: obtain approved external
full/delta coverage of the exact identity, adopt a reviewed covered replacement,
or explicitly approve a narrowly stated trust disposition. The current #516
adoption forbids new exemptions and self-audits; this change grants neither.
For a Git fork, trusting a crates.io publisher or qualifying regression tests
cannot replace exact Git coverage. Fork CI source admission authorizes execution,
not an audit.

## Advisory cross-check

Checked the RustSec database at
[`02e2517f457a359fc6d3440ea4560c8ea188fee8`](https://github.com/RustSec/advisory-db/tree/02e2517f457a359fc6d3440ea4560c8ea188fee8).
The baseline package names have records for aws-lc-sys, h2 and tungstenite.
Their registry base versions (0.47.0, 0.4.18 and 0.29.0 respectively) exceed the
listed patched thresholds. This version comparison does not establish that a
fork preserves each fix or that an unaudited package is safe.

The remaining baseline package names have no matching package records in that
database snapshot. In particular pkg-config has no matching advisory there.
Absence of an advisory is not audit coverage and does not replace the full
cargo-deny/OSV checks in CI.

## Qualification still required

Local validation was limited to source/record comparison and `git diff --check`.
No local Rust build, test, cargo-vet, or dependency resolution was run. The
coordinator must run the existing exact-store policy tests and cargo-vet for both
root and default on the integrated source. Expected uncovered identities must
remain visible; this partial repair does not close #390 or #516.
