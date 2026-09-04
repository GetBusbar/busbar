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
- History on HEAD (`crates/busbar-plugin/src/cold/mod.rs:120-147`): v2 → v3 removed the fourteen
  protocol-named durable variants (`PutTask`/`GetTask`/…) for the neutral `PlaneRecord` ones and RAISED
  the floor to 3 "so a stale plugin fails loud"; v3 → v4 relocated the record types out of `busbar-api`
  and raised the floor to 4. Both bumps reason about plugins built during the 1.6.0 line. A REAL 1.5.5
  plugin never had any durable variant: it speaks the v2 base wire (keys, usage, metering, credentials,
  audit, denylist), every one of which still exists on v4. Refusing it protects nothing.
- Phase 1.0 ticket (the fix): `supported_abi("store")` → `[2, ABI_VERSION]`; the loader records the
  plugin's manifest `abi_version` on the handle; every 1.6.0-only request variant (`UpsertPlaneRecord`
  … `RedeemPlaneToken`, and the journal/keyset ops when they land) is routed to the node-local shim
  when the handle is `< 3` and never sent over the wire (PB-93); `call_with_legacy_default` keeps its
  four `Unsupported` defaults (PB-37); the refusal literal for a genuinely out-of-window manifest prints
  the 1.5.5 range for its kind (PB-11). Proof: `plugins.load|store-*` and `plugins.store-persist|store-sqlite`
  green on both binaries, and the plane conformance rigs green against the sqlite plugin (the shim
  path), so a 1.5.5 store deployment gains mcp/a2a without touching its store.

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
