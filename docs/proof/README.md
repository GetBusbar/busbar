# Where the published proof manifests live

The Build Proof Dashboard manifest was collated by `cargo xtask proof-manifest`. That collator was
removed from this tree with the rest of the gate tooling (`xtask`), and the GitHub workflows that ran
it (`ci.yml`, `promote.yml`) are retired with GitHub Actions. No CI job produces or refreshes a
manifest today ([what CI checks](../ci.md)). The last published manifests are on the
`proof-manifests` branch.

1. **The `proof-manifests` branch** (canonical, for readers). One file per SOURCE branch —
   `docs/proof/dev.json`, `docs/proof/qa.json`, `docs/proof/main.json` — plus the `index.json`
   roll-up over all of them. The branch is deliberately unprotected, is never built, never released
   and never fast-forwarded into anything.

## Why not commit it back to dev/qa/main

It used to. A push of the manifest back to `qa` or `main` is rejected, because both are protected,
and if such a push ever did land it would mint a release-branch HEAD for which no required run
exists.

## Reading it

Marketing (`GetBusbar/marketing` `deploy.yml`) checks the busbar repo out at `ref: proof-manifests`
and renders `docs/proof/<stage>.json` for the stage it is deploying — the development site reads
`dev.json`, the QA site reads `qa.json`, and the public site `getbusbar.com` reads `main.json`. The stage mirroring is
in the file name, so one checkout serves all three deploys.

## The files in this directory

`dev.json` / `index.json` committed here are the seed the collator and its public-safety guard were
developed against. Nothing checks or refreshes them; the live manifests are on the `proof-manifests`
branch.
