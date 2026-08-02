# The release train — one push to `main`, everything ships

The rule, stated once: **`dev` is always release-ready, and a push to `main` releases
the entire fleet automatically.** No per-repo hand-tagging, no "download the binary and
re-sign it," no chasing eight plugin repos. Push a version to `main` → BOOM → busbar core
binaries + Docker Hub + GHCR + all first-party plugins + helm + homebrew + terraform +
SDKs + crossplane + pulumi all cut and publish their own next version.

1.5.0 was cut by hand, repo by repo, over hours. This document is the machinery that makes
1.5.1 a single push.

## Two tiers, two guarantees

**laptop → `dev` — proof it works.** Every push to `dev` runs the full `ci.yml`
(lint/clippy/multi-feature/Windows/loom/timing) and, on its success, `dev-gate.yml`
(~2h e2e: the real release-check against every plugin, both directions of the
bidirectional busbar-admin test). Because this runs on *every* dev push, `dev` never
accumulates the silent drift that made 1.5.0 a multi-hour surprise. **Green `dev` ==
releasable.**

**`dev` → `main` — ship it.** A push to `main` is only ever a fast-forward of an
already-green `dev`, immediately followed by cutting the version. That is the whole
release. Everything after the tag is automatic.

## What one `main` push triggers

```
  push to main (via cut-release.yml: bump Cargo, regen OpenAPI, roll CHANGELOG, tag vX.Y.Z)
        │
        ├─ release.yml   → 5-target binaries (PGO), SBOM, OpenAPI asset, attestations
        ├─ docker.yml    → getbusbar/busbar:X.Y.Z + latest, Hub + GHCR, cosign-signed, pubkey embedded
        └─ notify-downstream → repository_dispatch `upstream-release` {tag, version, sha}
                 │             to EVERY repo in .github/release-notify-targets.txt
                 │
                 ├─ each of the 8 plugin repos → release-on-upstream.yml
                 │      re-pin BUSBAR_REF to the new busbar SHA → bump own version line →
                 │      cargo build + sign (BUSBAR_SIGN_KEY) + tag → release.yml uploads signed tarballs
                 ├─ helm-charts    → appVersion=X.Y.Z, chart patch-bump → Release Charts publishes
                 ├─ homebrew-busbar→ formula version + fresh asset sha256s → push
                 ├─ terraform-provider-busbar → tag its next line → GoReleaser → Terraform Registry
                 ├─ busbar-python/js/go → regen from the new OpenAPI asset → bump → PyPI/npm/tag
                 ├─ provider-busbar (crossplane) → bump refs → tag → xpkg publish
                 ├─ pulumi-busbar  → re-pin TF provider → build SDKs → publish (where creds exist)
                 ├─ busbar-admin   → refresh committed openapi.json → bump → tag
                 └─ marketing      → rebuild (download buttons + changelog resolve the new releases)
```

## The dispatch contract

`notify-downstream` sends, to each target repo:

```
event_type: upstream-release
client_payload:
  tag:     v1.5.1              # the busbar core tag
  version: 1.5.1              # tag without the leading v
  sha:     <full core commit SHA at the tag>   # what downstream repos re-pin BUSBAR_REF to
```

Every downstream repo owns a `release-on-upstream.yml` keyed on
`repository_dispatch: types: [upstream-release]` plus a daily-cron self-heal (a missed or
failed dispatch is picked up within 24h — the instant path is the optimization, the cron is
the guarantee). It also keeps `workflow_dispatch` for a manual re-cut.

## Version lines are independent — do NOT force everything to the busbar version

busbar core is `1.5.x`. The downstream repos version on their **own** lines and must not be
snapped to busbar's number:

| Repo(s) | Line | Bump rule on `upstream-release` |
|---|---|---|
| busbar core | 1.5.x | the push itself (cut-release.yml) |
| store-{mysql,postgres,sqlite,valkey}, hashicorp-vault, auth-oidc, webrequest-hook | 1.0.x | patch-bump (rebuilt + re-signed against the new engine) |
| headroom-hook | 2.0.x | patch-bump (2.x = plugin-era; the 1.x line is pre-1.5.0, never retag) |
| terraform-provider, busbar-python/js/go | 0.x | minor-bump on a breaking spec change, else patch |
| helm-charts | chart 0.2.x | chart patch-bump; **appVersion** = busbar version |
| homebrew-busbar | tracks busbar | formula version = busbar version |
| pulumi-busbar, provider-busbar | 0.x | patch-bump; re-pin the TF provider |
| busbar-admin | 0.x | patch-bump; refresh committed openapi.json |

Each repo computes its own next version from its own latest tag — the dispatch tells it a new
busbar shipped and which SHA to build against, not what number to call itself.

## What makes the push actually reach `main` and the tags actually land

The one thing that turned every 1.5.0 push into a fight: **branch protection rejects a plain
`GITHUB_TOKEN` push.** Every bump-and-push in the train uses `RELEASE_DISPATCH_TOKEN` — an
org-level fine-grained PAT (Resource owner = **GetBusbar**, Contents: read+write on the
targets; a personal-account PAT 403s on org repos, which cost hours on 1.5.0). It is both the
dispatch credential AND the bypass-capable push credential.

## Credentials the train needs (state, not aspiration)

- `RELEASE_DISPATCH_TOKEN` — org secret, present and live-tested (HTTP 204 to all targets).
- `BUSBAR_SIGN_KEY` (private) + `BUSBAR_RELEASE_PUBKEY` (public var) — org-wide, present;
  every plugin re-signs, every busbar build embeds the pubkey.
- Docker Hub: `DOCKERHUB_USERNAME`/`DOCKERHUB_TOKEN`; **tag immutability must stay OFF** on
  `getbusbar/busbar` (a frozen tag cannot be corrected — it blocked the 1.5.0 image).
- Terraform Registry: `GPG_PRIVATE_KEY` + `GPG_FINGERPRINT` — present since 2026-07-20.
- PyPI/npm: OIDC trusted publishing (no stored token) for busbar-python/js — configured.
- **Missing, so honestly secret-gated (loud SKIP, never a fake-green):** pulumi-busbar
  `NPM_TOKEN`/`PYPI_API_TOKEN`; provider-busbar e2e `UPTEST_CLOUD_CREDENTIALS`/`UPTEST_DATASOURCE`.

## The 10-minute claim, honestly

Wall-clock from the `main` push to "everything published" is bounded by the slowest single
build, not the sum — the PGO Docker image (~8–12 min) and the plugin matrix run in parallel.
The dispatch fan-out fires in seconds. Nothing is discovered at release time because `dev`
already proved it. That is the difference between 1.5.0 (hours, serial, manual) and 1.5.1
(one push, parallel, automatic).
