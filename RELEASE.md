# Releasing Busbar

The branch model is **dev → qa → main**, and the split is the whole design:

| Push to | What runs | Cost |
|---|---|---|
| **`dev`** | `ci.yml` — fmt, clippy, `cargo test`, the full-tier gate | cheap; push often |
| **`qa`** | `ci.yml`, then `qa-gate.yml` (~2 h all-plugins soak) **and `release-stage.yml` — the ONE build** | the expensive stage |
| **`main`** | `release.yml` — **promote only**: it retags, tags and publishes what qa already built | seconds, and irreversible |

> **The qa build is what we release.** Every shipped byte — six binaries, the SBOM, the OpenAPI
> asset, the multi-arch image — is built exactly once, on the push to `qa`, under throwaway names.
> The push to `main` builds nothing. `scripts/release-order-lint.py` rule R10 fails CI if
> `release.yml` ever gains a `cargo build`, a `pgo-build`, a `docker/build-push-action` or a call to
> `build-artifact.yml`, because "just rebuild it on main" ships bytes that are not the ones qa
> verified.

**The tag is an OUTPUT of a green release, never an input.** Nobody tags by hand; nothing is
triggered by a `v*` tag. Docker Hub tag immutability makes a published `X.Y.Z` impossible to
overwrite, so a broken one is permanent — hence build → stage under a throwaway name → verify from
the consumer side → promote.

## The one human step

Write your notes under `## [Unreleased]` in [`CHANGELOG.md`](CHANGELOG.md) (Keep-a-Changelog
headings: Added / Changed / Fixed / Security). This is not optional any more: `release-stage.yml`'s
`plan` job runs `scripts/changelog-lint.py --require-version <version>` and **refuses to stage** a
version whose section is missing or is not the newest entry in the file.

## The runbook

Everything below runs from a clean checkout. Both promotions are **fast-forward pushes** — never a
merge commit. Linear history is what makes "main's HEAD *is* the qa commit" true, and that identity
is the entire trust model of the promote.

### 1. Prepare the version (on `dev`)

```
gh workflow run prepare-release.yml --repo GetBusbar/busbar --ref dev -f version=1.6.0
```

Bumps `crates/busbar/Cargo.toml` + `Cargo.lock`, regenerates the committed OpenAPI schema, rolls
`[Unreleased]` → `[1.6.0]` with today's date, and pushes to `dev`. It does **not** tag.

### 2. Push to qa

```
git fetch origin
git push origin dev:qa            # fast-forward only
```

### 3. Wait for qa green — all three runs, on the exact qa HEAD sha

```
QA=$(git rev-parse origin/qa)
gh run list --repo GetBusbar/busbar --commit "$QA" \
  --json name,status,conclusion,url --jq '.[] | "\(.name)\t\(.status)/\(.conclusion)"'
```

| workflow | what it proves |
|---|---|
| `CI` | fmt, clippy, build, the full-tier gate, the shadow oracle, the proof manifest |
| `qa-gate` | the ~2 h all-plugins end-to-end soak against real backends |
| `Release stage` | the ONE build: 6 binaries + SBOM + OpenAPI onto a draft, the PGO image under `staging-<sha12>`, every verifier, and the `staged-manifest` record |

Watch the expensive one directly:

```
gh run watch --repo GetBusbar/busbar \
  "$(gh run list --repo GetBusbar/busbar -w 'Release stage' -b qa -L1 --json databaseId --jq '.[0].databaseId')"
```

`Release stage` waits only for `CI` on the sha, not for `qa-gate` — `qa-gate` fires off CI's
completion and soaks for hours, so waiting would deadlock. Staging therefore finishes before the
soak concludes, which is safe: everything it produces lives under a throwaway name. The
full-population judgment (`CI`, `qa-gate` and `Release stage` all present and green **on the qa
push**) happens on the main push, before anything is named.

Iterate on `qa` as many times as it takes. Every push re-stages: fresh sha, fresh
`staging-<sha12>`, fresh digest, fresh record, the same draft re-filled and re-anchored. Only the
iteration you fast-forward to `main` can ever ship.

### 4. (Optional) Soak the exact bytes that will ship

```
docker pull getbusbar/busbar:staging-$(git rev-parse --short=12 origin/qa)
```

The promote is a manifest-only retag, so numbers measured here are numbers about the bytes that
ship.

### 5. Push to main — this *is* the release

```
git push origin qa:main           # fast-forward only
```

There is nothing else to do.

### 6. Watch the release

```
gh run watch --repo GetBusbar/busbar \
  "$(gh run list --repo GetBusbar/busbar -w Release -b main -L1 --json databaseId --jq '.[0].databaseId')"
```

## What the qa push runs (`release-stage.yml`)

1. **`plan`** — read the version from `Cargo.toml`; no-op if it is already released; refuse if
   `getbusbar/busbar:X.Y.Z` already exists on Docker Hub (that name could never be corrected);
   refuse if the CHANGELOG has no section for it.
2. **`branch-green`** — refuse to stage from a commit whose `CI` run is red or unknown.
3. **`gate`** — Cargo.lock freshness, fmt, clippy, build, test on the exact sha, with live Postgres
   and Valkey.
4. **`draft`** — create the GitHub Release as a **draft**: real, downloadable assets, but unlisted,
   not `releases/latest`, and no git tag.
5. **build + attach** — every target binary (built `--locked`, PGO where the target declares it),
   SBOM, OpenAPI asset and build-provenance **attestation**, onto the draft.
6. **`stage-image`** — `docker.yml` pushes the multi-arch image under `staging-<sha12>` and the
   armv8.0-compatible arm64 image under `staging-<sha12>-armv8.0`, and nothing else.
7. **`verify-assets` / `verify-artifact` / `verify-set-equality`** — the draft owes every asset
   `.github/release-targets.json` declares, each one downloaded back and put through the full
   `.github/artifact-contract.json` row set on its own native runner.
8. **`verify-staged`** — `verify-deploy.yml` in staging mode against the staged image: pull FRESH,
   boot it, execute the release binary, `--version`, the documented quickstart both ways, the
   attestation, every asset download.
9. **`record-staged`** — only on green, and only from re-derived facts: the image digests
   (re-checked against what the registries actually serve) **and every draft asset's name, size and
   sha256**. This record, the `staged-manifest` artifact, is the promote's only input.

## What the main push runs (`release.yml`) — promote only

1. **`plan`** — the version and the tag name; a safe no-op if that version is already released.
2. **`branch-green`** — gate 0. Every run on the sha must have concluded, and `CI`, `qa-gate` and
   `Release stage` must each have a run **from the qa push** that concluded `success`. Skipped is
   not green for those three. **There is no override, no waiver and no exception list**, and a
   status that cannot be determined counts as RED.
3. **`resolve-staged`** — the seam. Find the successful `Release stage` run whose head sha is
   exactly main's HEAD (a merge commit, a direct push or a cherry-pick has none, and is refused with
   no fallback build), download its record, and re-prove all of it from outside: version, sha and
   staging tag agree; both registries serve the recorded digests for the staging tags right now;
   both staged images' attestations verify; the draft still exists, is still a draft, is anchored to
   this sha, and **every asset on it matches the recorded sha256** with nothing missing and nothing
   added.
4. **`promote-image`** — manifest-only retag of the exact verified digests to `X.Y.Z`, then
   `latest`, plus `X.Y.Z-armv8.0` and the floating `armv8.0` pointer, on Docker Hub and GHCR. No
   rebuild.
5. **`promote-release`** — push the git tag, publish the draft, then re-derive the tag, the draft
   flag, the latest flag and the `/releases/latest` redirect from outside and fail loud if any one
   of them did not move.
6. **`notify-downstream`** then **`consumer-verification`** — the fan-out and the full public sweep
   (Homebrew, helm, the site, install.sh, both registries).

**If anything before `promote-image` fails, nothing is public**: no git tag, no listed release, no
container version tag, no fan-out, and `latest` has not moved. Re-run the workflow — every step is
idempotent. **Never** "just rebuild it on main"; that is the one move the whole split exists to ban.
If the record itself is the problem (expired past its 90-day retention, or contradicted by the
registry), the remedy is a re-run of `Release stage` on the same qa sha, which re-records the same
bytes.

`docker.yml` is not triggered by a tag and emits no version tag from a build. Its `promote` job is
the only thing in the repository that creates `getbusbar/busbar:X.Y.Z`.

## Branch protection this runbook assumes

Both promotions are fast-forward pushes, so a required status check must already be green on the
sha being pushed:

| branch | required contexts |
|---|---|
| `dev` | *(none)* — "dev is fast" |
| `qa` | `ci umbrella` — the only context a `dev` sha can carry |
| `main` | `ci umbrella`, `qa-gate umbrella`, `record the staged digest (the promote's only input)` |

Keep `enforce_admins: true`, `required_linear_history: true`, `allow_force_pushes: false` and
`allow_deletions: false` on `qa` and `main`. No workflow may push a commit to either branch
(release-order-lint R11).

Full reasoning, with file:line evidence: [`docs/design/release-path-i5.md`](docs/design/release-path-i5.md).

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
