# Where the published proof manifests live

The Build Proof Dashboard manifest is collated by `cargo xtask proof-manifest`. The `proof-manifest`
job that ran it (in the removed `ci.yml`, on a push to `dev`, `qa` or `main`) is deleted with the rest of busbar's
workflows: `promote.yml` does not publish a manifest, so nothing refreshes the published copies until
the collator is wired into the release engine in busbar-release. The last published manifests are on
the `proof-manifests` branch.

Usage:

```
cargo xtask proof-manifest --version dev --out docs/proof/dev.json
cargo xtask proof-manifest --version 1.6.0 --out docs/proof/1.6.0.json \
    --sha <40hex> --run-id 123 --run-url https://github.com/.../runs/123 \
    --staged-json /path/to/staged.json --reports-dir testing --run-cargo --index
cargo xtask proof-manifest --selftest
```

1. **The `proof-manifests` branch** (canonical, for readers). One file per SOURCE branch —
   `docs/proof/dev.json`, `docs/proof/qa.json`, `docs/proof/main.json` — plus the `index.json`
   roll-up over all of them. The branch is deliberately unprotected, is never built, never released
   and never fast-forwarded into anything.

## Why not commit it back to dev/qa/main

It used to. A push of the manifest back to `qa` or `main` is rejected, because both are protected
(required status checks, linear history, `enforce_admins: true`). And if such a push ever did land it
would mint a release-branch HEAD for which no required run exists. `cargo xtask gate workflow-rules`
rule R11 fails if any workflow pushes a commit to a release branch, so this cannot come back by
accident.

## Reading it

Marketing (`GetBusbar/marketing` `deploy.yml`) checks the busbar repo out at `ref: proof-manifests`
and renders `docs/proof/<stage>.json` for the stage it is deploying — `getbusbar.dev` reads
`dev.json`, `getbusbar.qa` reads `qa.json`, `getbusbar.com` reads `main.json`. The stage mirroring is
in the file name, so one checkout serves all three deploys.

## The files in this directory

`dev.json` / `index.json` committed here are the seed the collator and the public-safety guard were
developed against, and are what `node scripts/check-proof-manifest-public.mjs` (no arguments) checks
locally. Nothing refreshes them; the live manifests are on the `proof-manifests` branch.
