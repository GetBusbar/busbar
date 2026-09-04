# Parity baseline — HEAD vs the published busbar 1.5.5 (2026-09-04, in progress)

Golden: `busbar-aarch64-apple-darwin.tar.gz` from release `v1.5.5`, sha256 `93f8f02a…`, recorded by
`testing/shadow-oracle/record.sh`. Candidate: `integration/config-seam-stage1-rebased` @ `5252992c`
built `--release` on the same host. Differ: `testing/shadow-oracle/replay.sh`.

This file is rewritten by `baseline-report.py` at the end of Phase 0; until then it holds the findings
as they land, so nothing is lost if the run is interrupted.

## Findings so far

### F-001 · every published 1.5.5 store plugin is refused by HEAD — REGRESSION (weight 10)

```
INVALID: manifest abi_version 2 is not supported for kind 'store' by this binary (supported range v4..=v4)
```

- Reproduced with `busbar-store-sqlite` v1.0.6 (also postgres 1.0.6, mysql 1.0.6, valkey 1.0.7):
  1.5.5 `--validate`s, boots, persists a key and its usage across a restart
  (`testing/shadow-oracle/scripts/store-persist.sh`); HEAD refuses at `--validate`.
- Cause: `crates/busbar-plugin/src/cold/mod.rs:147` bumped the store `ABI_VERSION` 2 → 4 and
  `crates/plugin-loader/src/registry.rs:41` keeps a single-point window `[ABI_VERSION, ABI_VERSION]`.
- Rule it breaks: PB-11 / PB-37 / PB-93 (a 1.5.5 plugin loads through an in-tree ABI-2 adapter; the
  refusal literal and the printed range stay 1.5.5's `v2..=v2` for a genuinely out-of-window manifest).
- Phase 1.0 ticket: ABI-2 store adapter in the loader (window `[2, 4]`, `call_with_legacy_default` for the
  four ops, node-local shim for 1.6.0-only ops), then this cell family green on both binaries.

### N-001 · hook / auth / secret plugins "SKIPPED: this build embeds no busbar release key" — MEASUREMENT ARTIFACT, RESOLVED

`BUSBAR_RELEASE_PUBKEY` is an org VARIABLE the release pipeline exports at build time
(`plugin-sign/src/lib.rs:84`, `build-artifact.yml:105`). A local `cargo build` has no key, so every
first-party signature is unverifiable. The candidate is being rebuilt with the variable set; the
plugin family is measured against that build. Rebuilt with `BUSBAR_RELEASE_PUBKEY` set: github, ldap,
oidc (auth), vault (secret), headroom and webrequest (hook) all list as `first-party ready` on HEAD;
the four stores stay `INVALID`. Secret (1), auth (2), hook (1) and export (2) ABI versions are
unchanged between the tag and HEAD; only the store ABI moved (2 → 4). **F-001 is the only plugin
regression.** Rule for every later measurement: the candidate is built with the release key, exactly
as `build-artifact.yml` builds it.

## Harness fixes made while recording the golden (none are busbar behaviour)

mock readiness (GET), percent-decoded egress paths, dialect alias map, priming the `broke` group,
fresh boot per cell (a parked breaker leaked into later cells), settle-to-fixed-point before the
after-snapshot, `/metrics` via the client key, normalizer rules for base62/uuid ids, `Retry-After`,
timing sums/quantiles, `as_of`, key ids inside metric labels, gemini `responseId`.

## Status of the LLM wire family (105 owed cells)

After the harness fixes: zero status, header, body, usage or audit divergences on the 105 cells.
The residual metric-label and timing noise is closed by the normalizer rules above; the next full
run records the number.
