# Releasing Busbar

The branch model is **dev → qa → main**, and each arrow means one thing:

| Push to | What runs | Cost |
|---|---|---|
| **`dev`** | `ci.yml` — fmt, clippy, `cargo test` | cheap; push often |
| **`qa`** | `qa-gate.yml` — `release-check.sh`, the real all-plugins end-to-end gate | ~2h; the pre-release soak |
| **`main`** | `release.yml` — the whole release, gated: green-branch check, build, stage, verify, THEN tag | the BOOM |

`dev` is always release-ready because every push is fully CI'd. Promoting to `qa` proves the exact
commit works against every plugin together. Promoting to `main` **is** the release.

## The one human step

Write your notes under `## [Unreleased]` in [`CHANGELOG.md`](CHANGELOG.md) (Keep-a-Changelog
headings: Added / Changed / Fixed / Security). If you leave it empty, the release notes fall back
to "Maintenance and dependency updates."

## Cut the release

1. **Prepare the bump on `dev`.** Run the **Prepare release (on dev)** workflow (Actions →
   *Prepare release (on dev)* → Run workflow from `dev` → enter e.g. `1.5.1`). It bumps
   `crates/busbar/Cargo.toml` + `Cargo.lock`, **regenerates the committed OpenAPI schema**
   (`UPDATE_OPENAPI=1` — the CI drift gate that fails the build if stale), promotes
   `CHANGELOG [Unreleased]` → `[version]` with today's date, and commits + pushes to `dev`. It does
   **not** tag.
2. **Promote `dev` → `qa`.** The ~2h `qa-gate.yml` full-plugin gate runs. A green run means the
   bumped commit is release-ready.
3. **Promote `qa` → `main`.** Landing on `main` runs `release.yml`, which reads `vX.Y.Z` from
   `Cargo.toml` and runs the whole release. It is **idempotent**: if that version is already
   released (e.g. a docs hotfix landing on main without a version bump) it is a safe no-op, so
   only a *new* version cuts a release.

## What landing on `main` runs (automatic)

**The tag is the LAST thing that happens, not the first.** Nothing carries a user-facing name until
a consumer has proved it works, because Docker Hub tag immutability makes a published `X.Y.Z`
impossible to overwrite: a broken one is permanent. `release.yml` runs, in order:

1. **`plan`** — read the version from `Cargo.toml`. No-op if it is already released. Refuse if
   `getbusbar/busbar:X.Y.Z` already exists on Docker Hub, since that name could never be corrected.
2. **`branch-green`** — refuse to release from a red commit. Waits for every check on the commit
   to conclude and requires every one of them green. **There is no override, no waiver and no
   exception list**, and a status that cannot be determined counts as RED.
3. **`gate`** — fmt, clippy, build, test on the exact commit, with live Postgres and Valkey.
4. **`draft`** — create the GitHub Release as a **draft**: real, downloadable assets, but it is
   not listed, does not resolve as `releases/latest`, and creates no git tag.
5. **build + attach** — the target binaries, SBOM, OpenAPI asset and build-provenance
   **attestation** (verify with `--repo GetBusbar/busbar`), all onto the draft.
6. **`stage-image`** — `docker.yml` pushes the multi-arch image under `staging-<sha>` — plus the
   armv8.0-compatible arm64 image under `staging-<sha>-armv8.0` — and nothing else. Really
   pullable, really runnable, and no user is looking at those names.
7. **`verify-staged`** — the gate. `verify-deploy.yml` in staging mode: pull the image FRESH
   (`docker rmi` first), boot it, download and EXECUTE the release binary, check `--version`, run
   the documented quickstart both ways, verify the attestation, verify every asset downloads.
8. **`promote-image`** — only on green. Manifest-only retag of the exact verified digests to
   `X.Y.Z` then `latest`, and the armv8.0 compat names (`X.Y.Z-armv8.0`, then the floating
   `armv8.0` pointer), on Docker Hub and GHCR. No rebuild.
9. **`promote-release`** — push the git tag, publish the draft, then re-derive the git tag, the
   draft flag, the latest flag and the `/releases/latest` redirect from outside and fail loud if
   any one of them did not move.
10. **`notify-downstream`** then **`consumer-verification`** — the fan-out and the full public
    sweep (Homebrew, helm, the site, install.sh, both registries).

**If anything before step 8 fails, nothing is public**: no git tag, no listed release, no container
version tag, no fan-out, and `latest` has not moved. The next attempt is a clean re-run of the
workflow, not a recovery. Re-running is safe: every step is idempotent.

`docker.yml` is no longer triggered by a tag and emits no version tag of its own. Its `promote` job
is the only thing in the repository that creates `getbusbar/busbar:X.Y.Z`.

## Downstream (self-healing, no action needed)

- **Homebrew** — the tap's `bump-formula` workflow runs daily and updates both `busbar` and
  `busbar-admin` formulae (version + checksums) when it sees a newer release. A missed run just
  catches up the next day. *(Optional: add a PAT + fire `repository_dispatch{type: upstream-release}`
  at the end of `release.yml` for an instant bump instead of ≤24 h.)*
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
