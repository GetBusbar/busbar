# Releasing Busbar

The branch ladder is **predev → dev → qa → main**. busbar has ONE pipeline workflow,
[`.github/workflows/promote.yml`](.github/workflows/promote.yml): every same-repo pull request is one
hop up the ladder. The release engine lives in the private `GetBusbar/busbar-release` repository
(pinned outside this repo by the org variables `ENGINE_REF` and `ENGINE_SHA256`, set with
`busbar-release engine pin <sha>`; `workflow-rules` R16 holds promote.yml to a 40-hex check and a
sha256 verify of the engine at run time); busbar-release's `crates/busbar-release-train/ladder.json`
says what entering each rung needs.

| Rung entered (the PR's base) | What the hop runs | Consent |
|---|---|---|
| **`predev`** (from a `lane-*` branch) | every registered gate (`cargo xtask gate --list`, each by name) | none |
| **`dev`** | the gates, the oracle against the 1.5.5 golden, conformance | none |
| **`qa`** | the same, plus build + test, then the release binaries and the container | the owner (the org ruleset keeps `qa` locked) |
| **`main`** | the same, then publish | the owner (the org ruleset keeps `main` locked) |

A hop has two jobs, both in `promote.yml`:

* **`preflight`**, on a free runner: `cargo fmt --all -- --check`, `cargo metadata --locked`, and the
  generated C header is current (`cargo xtask gate abi-header --write` leaves no diff).
* **`hop`**, on a Latchkey runner sized by the rung: the engine plans the hop, the turnstile
  admits the candidate sha, and the verdict is uploaded as the `turnstile-report-<sha>` artifact. When
  the rung needs no consent and the repository variable `PROMOTE_BOARD` is `true`, the engine
  fast-forwards the base branch to the exact sha it tested. Both promotions are **fast-forward
  pushes**: linear history is what makes "main's HEAD *is* the qa commit" true.

> The entry builds a plan names (`release-binaries`, `container`, `publish`) are not yet ported into
> the engine: `promote.yml` fails a hop that plans one with that message rather than skipping it.
> Nothing is built or published until they land in busbar-release.

**The tag is an OUTPUT of a green release, never an input.** Nobody tags by hand; no workflow is
triggered by a `v*` tag (`cargo xtask gate workflow-rules`, rule R1). Docker Hub tag immutability
makes a published `X.Y.Z` impossible to overwrite, so a broken one is permanent.

## The one human step

Write your notes under `## [Unreleased]` in [`CHANGELOG.md`](CHANGELOG.md) (Keep-a-Changelog
headings: Added / Changed / Fixed / Security). `cargo xtask gate changelog --require-version=X.Y.Z`
**refuses** a version whose section is missing or is not the newest entry in the file.

## Preparing a version (on `dev`)

```
python3 .github/scripts/bump_cargo.py 1.6.0 crates/busbar/Cargo.toml
cargo update -p busbar --precise 1.6.0
UPDATE_OPENAPI=1 cargo test -p busbar -p busbar-kernel -p busbar-core-admin --features openapi-schema openapi_json_matches_committed_file
python3 .github/scripts/roll_changelog.py 1.6.0 CHANGELOG.md
```

That bumps `crates/busbar/Cargo.toml` + `Cargo.lock`, regenerates the committed OpenAPI schema, and
rolls `[Unreleased]` to `[1.6.0]` with today's date. It does **not** tag. Open the result as a pull
request against `dev` and let the hop run.

## Moving a version up the ladder

Open a pull request whose base is the next rung (`dev` into `qa`, `qa` into `main`; a lane branch into `predev`). `promote.yml`
runs the hop on the PR; the run's check names are `preflight` and `hop`. A red hop is fixed
forward on the lower branch and the pull request re-run: every push re-runs the hop on the new sha.

## Branch protection this assumes

`qa` and `main` require the two contexts `preflight` and `hop` (plus the org ruleset's owner
consent).

`scripts/ci-branch-protection.sh` writes the floor (and strips the contexts of the deleted workflows).
Keep `enforce_admins: true`, `required_linear_history: true`, `allow_force_pushes: false` and
`allow_deletions: false` on `qa` and `main`. No workflow may push a commit to either branch
(`workflow-rules` R11).

The ruling: [`docs/design/BUSBAR-1.6.0.md`](docs/design/BUSBAR-1.6.0.md) Part 6, the release engine.

## Downstream (self-healing, no action needed)

- **Homebrew** — the tap's `bump-formula` workflow runs daily and updates both `busbar` and
  `busbar-admin` formulae (version + checksums) when it sees a newer release. A missed run just
  catches up the next day.
- **Website** — the download page shows the new version automatically (`src/release.json` is
  regenerated from Cargo at build). For the version-**pin** examples (docker/compose/helm/attestation),
  run `node scripts/bump-site-version.mjs X.Y.Z` in the marketing repo and push — or wire a
  Cloudflare Pages deploy hook to rebuild on release. *(This never touches `facts.ts BUSBAR_VERSION`,
  which stamps measured benchmark data and only changes on a re-benchmark.)*
- **SDKs** (`busbar-python` / `-js` / `-go`, `busbar-admin`) — these carry their own semver and
  regenerate from `openapi.json`; tag them (`vX.Y.Z`) only when you want to publish a new SDK cut.
  Publishing is tokenless (OIDC / git tag).

## Honesty invariant

Every performance number the site publishes is stamped with version + hardware + source, enforced
by a build-time self-check in `facts.ts` that fails the build if a stamp is missing. Re-benchmark →
update the measured value **and** its `BUSBAR_VERSION`/hardware stamp together; never bump the stamp
without a real run behind it.
