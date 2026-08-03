# Releasing Busbar

The branch model is **dev → qa → main**, and each arrow means one thing:

| Push to | What runs | Cost |
|---|---|---|
| **`dev`** | `ci.yml` — fmt, clippy, `cargo test` | cheap; push often |
| **`qa`** | `qa-gate.yml` — `release-check.sh`, the real all-plugins end-to-end gate | ~2h; the pre-release soak |
| **`main`** | `tag-on-main.yml` — auto-tags `crates/busbar/Cargo.toml`'s version → the release | the BOOM |

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
3. **Promote `qa` → `main`.** Landing on `main` runs `tag-on-main.yml`, which tags `vX.Y.Z` (the
   version now in `Cargo.toml`) — and that tag is the sign-off. It is **idempotent**: if the tag
   already exists (e.g. a docs hotfix landing on main without a version bump), it is a safe no-op,
   so only a *new* version cuts a release.

## What the tag triggers (automatic)

- **`release.yml`** — cross-compiles the 5 target binaries, SBOM, the OpenAPI asset, and the
  build-provenance **attestation** (verify with `--repo GetBusbar/busbar`).
- **`docker.yml`** — builds + pushes `getbusbar/busbar:X.Y.Z` + `latest` to Docker Hub and
  `ghcr.io/getbusbar/busbar`, cosign-signed.

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
