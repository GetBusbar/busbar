# Where the published proof manifests live

The Build Proof Dashboard manifest (`docs/design/1.6.0-proof-dashboard.md`) is produced by the
`proof-manifest` job in `.github/workflows/ci.yml` on a push to `dev`, `qa` or `main`, and published
in two places. Neither of them is the branch it ran on.

1. **The `proof-manifests` branch** (canonical, for readers). One file per SOURCE branch —
   `docs/proof/dev.json`, `docs/proof/qa.json`, `docs/proof/main.json` — plus the `index.json`
   roll-up over all of them. The branch is deliberately unprotected, is never built, never released
   and never fast-forwarded into anything.
2. **The `proof-manifest-<branch>` workflow artifact** of the run that produced it, containing the
   same two files. This is the copy to consume from another workflow: it needs no git write at all.

## Why not commit it back to dev/qa/main

It used to. `git push origin "HEAD:${{ github.ref_name }}"` is rejected on `qa` and `main` because
both are protected (required status checks, linear history, `enforce_admins: true`); the job fails,
the `CI` run concludes failure, and `release-stage.yml`'s gate 0 then refuses to stage — a manifest
refresh took the release out. And if such a push ever did land it would mint a release-branch HEAD
carrying `[skip ci]`, for which no `CI`, `qa-gate` or `Release stage` run exists, so
`release.yml`'s `resolve-staged` would refuse that sha permanently.

`scripts/release-order-lint.py` R11 fails CI if any workflow pushes a commit to a release branch, so
this cannot come back by accident.

## Reading it

Marketing (`GetBusbar/marketing` `deploy.yml`) checks the busbar repo out at `ref: proof-manifests`
and renders `docs/proof/<stage>.json` for the stage it is deploying — `getbusbar.dev` reads
`dev.json`, `getbusbar.qa` reads `qa.json`, `getbusbar.com` reads `main.json`. The stage mirroring is
in the file name, so one checkout serves all three deploys.

## The files in this directory

`dev.json` / `index.json` committed here are the seed the collator and the public-safety guard were
developed against, and are what `node scripts/check-proof-manifest-public.mjs` (no arguments) checks
locally. CI no longer refreshes them; the live manifests are on the `proof-manifests` branch.
