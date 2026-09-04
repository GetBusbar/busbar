# Parity baseline — busbar 1.6.0 vs the published busbar 1.5.5

Golden: `/Users/matthew/Developer/GetBusbar/busbar/.claude/worktrees/config-seam-work/target/oracle/recordings/golden` · Candidate: `/Users/matthew/Developer/GetBusbar/busbar/.claude/worktrees/config-seam-work/target/oracle/recordings/candidate-p1` · cells: `/Users/matthew/Developer/GetBusbar/busbar/.claude/worktrees/config-seam-work/testing/shadow-oracle/cells.json`

**Owed 780 · diverging 0 · golden gaps 1419 · weighted D/W = 0.0000**

> **Status 2026-09-04, end of Phase 1.0.** The numbers below are the re-measurement of HEAD AFTER
> the parity fixes: **780 owed · 0 unaccepted divergences · 278 owner-accepted improvements**.
> The findings section is the triage of the FIRST measurement (407 diverging) that produced the
> fix list; every `fix` row there is now landed and re-measured green, every `accept` row is an
> entry in `testing/shadow-oracle/accepted-differences.json`, and the two owner rows were decided
> (migrator: match 1.5.5; unknown-path 404: match 1.5.5). Two further wire shapes found during the
> stream fix (Bedrock text blocks without contentBlockStart, Responses lifecycle frames) are
> accepted as spec-faithful under the owner's maximum-spec-compliance rule.

## Decision

**Base = HEAD** (owner decision, 2026-09-04): the bar is a legitimate 1.6.0 upgrade — 1.5.5's surface, the same or better, plus the mcp / a2a / voice planes — with an accepted-differences register for the deliberate deltas (`improvement` | `breaking`, each `breaking` named in the CHANGELOG). The numeric rule of the plan reads KEEP HEAD on this run (D/W 0.0000 vs ≤ 0.05; every weight-10 family within bound). **Ship gate: zero unaccepted divergences.** Every diverging cell below is triaged in the findings.

## Per family

| family | owed | diverging | D/W |
|---|---|---|---|
| admin.ops | 225 | 0 | 0.000 |
| billing | 11 | 0 | 0.000 |
| boot.refusal | 177 | 0 | 0.000 |
| boot.warning | 25 | 0 | 0.000 |
| cli | 14 | 0 | 0.000 |
| config.migrate | 138 | 0 | 0.000 |
| hooks | 6 | 0 | 0.000 |
| http.crosscut | 20 | 0 | 0.000 |
| llm.wire | 126 | 0 | 0.000 |
| ops.scrape | 13 | 0 | 0.000 |
| plugins | 11 | 0 | 0.000 |
| route.failover | 14 | 0 | 0.000 |

## Per divergence class

| class | cells |
|---|---|

## Divergences (heaviest first, top 40)

- `admin.ops|DeleteOverlaySection|not-found` [headers,body] headers content-length: '139' -> '194'
- `admin.ops|GetHooksName|ok` [headers,body] headers content-length: '249' -> '318'
- `admin.ops|GetHooks|ok` [headers,body] headers content-length: '280' -> '349'
- `admin.ops|GetOpenapiJson|ok` [headers,body] headers added vary
- `boot.refusal|BOOT-001|validate` [effects.stderr] effects.stderr: identical after the accepted rewrite ['D-1 diagnostic codes']
- `boot.refusal|BOOT-002|validate` [effects.stderr] effects.stderr: identical after the accepted rewrite ['D-1 diagnostic codes']
- `boot.refusal|BOOT-003|validate` [effects.stderr] effects.stderr: identical after the accepted rewrite ['D-1 diagnostic codes']
- `boot.refusal|BOOT-004|validate` [effects.stderr] effects.stderr: identical after the accepted rewrite ['D-1 diagnostic codes']
- `boot.refusal|BOOT-005|validate` [effects.stderr] effects.stderr: identical after the accepted rewrite ['D-1 diagnostic codes']
- `boot.refusal|BOOT-010|validate` [effects.stderr] effects.stderr: identical after the accepted rewrite ['D-1 diagnostic codes']
- `boot.refusal|BOOT-011|validate` [effects.stderr] effects.stderr: identical after the accepted rewrite ['D-1 diagnostic codes']
- `boot.refusal|BOOT-012a|validate` [effects.stderr] effects.stderr: identical after the accepted rewrite ['D-1 diagnostic codes']
- `boot.refusal|BOOT-012b|validate` [effects.stderr] effects.stderr: identical after the accepted rewrite ['D-1 diagnostic codes']
- `boot.refusal|BOOT-012c|validate` [effects.stderr] effects.stderr: identical after the accepted rewrite ['D-1 diagnostic codes']
- `boot.refusal|BOOT-012d|validate` [effects.stderr] effects.stderr: identical after the accepted rewrite ['D-1 diagnostic codes']
- `boot.refusal|BOOT-012e|validate` [effects.stderr] effects.stderr: identical after the accepted rewrite ['D-1 diagnostic codes']
- `boot.refusal|BOOT-013|validate` [effects.stderr] effects.stderr: identical after the accepted rewrite ['D-1 diagnostic codes']
- `boot.refusal|BOOT-014|validate` [effects.stderr] effects.stderr: identical after the accepted rewrite ['D-1 diagnostic codes']
- `boot.refusal|BOOT-015|validate` [effects.stderr] effects.stderr: identical after the accepted rewrite ['D-1 diagnostic codes']
- `boot.refusal|BOOT-016|validate` [effects.stderr] effects.stderr: identical after the accepted rewrite ['D-1 diagnostic codes']
- `boot.refusal|BOOT-017|validate` [effects.stderr] effects.stderr: identical after the accepted rewrite ['D-1 diagnostic codes']
- `boot.refusal|BOOT-020|validate` [effects.stderr] stderr line 3: "  - provider 'gemini' has unknown protocol 'bogus': must be one of: anthropic, o" -> "  - provider 'gemini' has unknown protocol 'bogus': must be one of: anthropic, g"
- `boot.refusal|BOOT-021a|validate` [effects.stderr] effects.stderr: identical after the accepted rewrite ['D-1 diagnostic codes']
- `boot.refusal|BOOT-021b|validate` [effects.stderr] effects.stderr: identical after the accepted rewrite ['D-1 diagnostic codes']
- `boot.refusal|BOOT-022|validate` [effects.stderr] effects.stderr: identical after the accepted rewrite ['D-1 diagnostic codes']
- `boot.refusal|BOOT-023|validate` [effects.stderr] effects.stderr: identical after the accepted rewrite ['D-1 diagnostic codes']
- `boot.refusal|BOOT-024|validate` [effects.stderr] effects.stderr: identical after the accepted rewrite ['D-1 diagnostic codes']
- `boot.refusal|BOOT-025|validate` [effects.stderr] effects.stderr: identical after the accepted rewrite ['D-1 diagnostic codes']
- `boot.refusal|BOOT-026|validate` [effects.stderr] effects.stderr: identical after the accepted rewrite ['D-1 diagnostic codes']
- `boot.refusal|BOOT-027|validate` [effects.stderr] effects.stderr: identical after the accepted rewrite ['D-1 diagnostic codes']
- `boot.refusal|BOOT-028|validate` [effects.stderr] effects.stderr: identical after the accepted rewrite ['D-1 diagnostic codes']
- `boot.refusal|BOOT-029|validate` [effects.stderr] effects.stderr: identical after the accepted rewrite ['D-1 diagnostic codes']
- `boot.refusal|BOOT-030|validate` [effects.stderr] effects.stderr: identical after the accepted rewrite ['D-1 diagnostic codes']
- `boot.refusal|BOOT-031|validate` [effects.stderr] effects.stderr: identical after the accepted rewrite ['D-1 diagnostic codes']
- `boot.refusal|BOOT-032|validate` [effects.stderr] effects.stderr: identical after the accepted rewrite ['D-1 diagnostic codes']
- `boot.refusal|BOOT-033|validate` [effects.stderr] effects.stderr: identical after the accepted rewrite ['D-1 diagnostic codes']
- `boot.refusal|BOOT-034|validate` [effects.stderr] effects.stderr: identical after the accepted rewrite ['D-1 diagnostic codes']
- `boot.refusal|BOOT-035|validate` [effects.stderr] effects.stderr: identical after the accepted rewrite ['D-1 diagnostic codes']
- `boot.refusal|BOOT-036|validate` [effects.stderr] effects.stderr: identical after the accepted rewrite ['D-1 diagnostic codes']
- `boot.refusal|BOOT-040|validate` [effects.stderr] effects.stderr: identical after the accepted rewrite ['D-1 diagnostic codes']
- … 238 more in the report's diverging.txt

## Golden gaps (cells the 1.5.5 recording could not produce — named, never owed)

- 1380 × SKIP: named gap on the golden, never owed
- 39 × SKIP: named gap: the fixture this cell needs is not in the tree yet

## Findings

### How to read this

Every diverging cell has been mapped to exactly one root cause below (no cell is untriaged; the
mapping script is the triage in `docs/design/PARITY-BASELINE-2026-09-04.md`'s history). The
run counts are dominated by two line-level causes that touch almost every boot cell: F-002 (a
missing deprecation warning, 281 cells) and D-1 (diagnostic codes appended to every error / warn
line, 259 cells). Once F-002 is fixed and D-1 is accepted, the same recording diffs to **~90
cells across 12 causes**, of which the money / wire / plugin ones are all fixes, not decisions.

Disposition vocabulary: **fix** = regression, restore 1.5.5 behaviour on HEAD (Phase 1.0);
**accept** = additive or strictly better, goes in `accepted-differences.json` as `improvement`
once the owner confirms; **owner** = wording / shape choice that only the owner can make.

| id | cells | disposition | what HEAD does differently from the published 1.5.5 |
|---|---|---|---|
| F-002 | 281 | **fix** | Every deprecated-env-var warning is gone: `[warn] BUSBAR_PROVIDERS is DEPRECATED…` (W30), `BUSBAR_WORKER_THREADS`, `BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE`, `BUSBAR_UPSTREAM_HTTP1_ONLY`. Worse: `BUSBAR_PROVIDERS` is no longer honoured at all — BOOT-121 points it at a nonexistent file and HEAD says `ok: config valid` using the providers.yaml beside the config where 1.5.5 refuses with `cannot read providers file`. Operators on the env var silently get a different providers file. |
| D-1 | 259 | accept (`improvement`) | Every `[error]` / `[warn]` / `warning:` stderr line carries a diagnostic code (`[error] BUSBAR-3015: config validation failed:`) and every boot log line carries `diag=BUSBAR-NNNN`. Text after the code is byte-identical. Recommend accept; changelog-worthy as a feature. |
| F-004 | 69 | **owner** | `--migrate-config` output changed shape: pool members `- model: x` / `- weight: 1 model: x` are rewritten to bare names with a `weights:` map; CHANGES count grows accordingly (9 → 11 on v0.10.0); per-member capabilities are left in place with a new `TODO(migrate)` comment + a `TODO (n) - a human must decide` block. 1.5.5 emitted none of this. Both shapes validate on HEAD. Question for the owner: is the new canonical form the 1.6.0 config shape (then accept as `improvement` and document), or must the migrator keep emitting 1.5.5's shape? |
| D-2 | 29 | accept (`improvement`) | jemalloc line on macOS is `[info] … EXPECTED on macOS …` instead of 1.5.5's `[warn] could not enable jemalloc background purge thread`. Level and wording only. |
| F-005/6/7 | 20 | **fix** (money) | Streaming responses are unmetered: `/usage` spend stays `null` where 1.5.5 records 18 tokens / 250 cents per call; the same-protocol stream also leaks a final `usage` chunk (`"usage":{"completion_tokens":7,…}`) the client never got from 1.5.5; cross-protocol streams come back in the egress dialect instead of the caller's. All 18 llm `ok_stream` cells + `hooks|hooked-pool|ok_stream` + its metrics. |
| F-001 | 11 | **fix** | All four published store plugins (sqlite / postgres / mysql / valkey, ABI 2) are `INVALID: manifest abi_version 2 is not supported for kind 'store' by this binary (supported range v4..=v4)`; the store-persist script cell cannot even start. Design + code sites in the F-001 section below. |
| F-008 | 9 | **fix** (wire) | Cross-protocol non-stream responses put the *busbar model name* (`m-bedrock`, `m-cohere`) in `model` / `modelVersion` where 1.5.5 returned `""`, `null`, or the request's model (`gpt-4o`). Clients that key on the field see a new value. |
| F-011 | 5 | accept (`improvement`) | Admin views grow fields: hook objects gain `fires_at`, `groups`, `phase`; the overlay-section 404 lists `identity-providers`, `export`, `tools`, `agents`; `openapi.json` adds the mcp / a2a endpoints. Additive; 1.5.5 fields unchanged. |
| F-013 | 9 | accept (`improvement`) | Validation wording: `expected one of` key lists include the plane keys (`mcp`, `oauth_as`, `tools`, `agents`, `streams`, …) and the new limit metrics (`tokens_input`, `tokens_output`, `tokens_cache_read`, `tokens_cache_write`); P07/P09 reserved-name and credential-mode sentences rephrased; BOOT-043b unknown pool member is reported by the pool-member validator (`config errors:` + `not defined in any of models:/tools:/agents:`) instead of `references unknown model`; BOOT-020 protocol list reordered; BOOT-141 download error text is reqwest's new wording. Same refusal, same exit code in every case. |
| F-003 | 4 | **owner** | `--help` USAGE is `busbar [-c <path>] [--providers <path>]` (67 lines vs 49); `--version` prints a second `build: profile=release opt-level=3 lto=… target=…` line. Additive; owner to confirm the flags are meant to ship. |
| F-012 | 3 | **fix** (security) | The reserved name `admin` is accepted for a model (BOOT-013), a pool (BOOT-016) and a provider (BOOT-017); 1.5.5 refuses all three because `/admin/*` is routed to the operator surface, so such an entry is unreachable and shadows the admin routes. |
| F-009 | 2 | **fix** | `/stats` lanes lost `limit` (1.5.5: `2305843009213693951` for an unbounded lane; HEAD: `null`). Also visible in `http.crosscut|bearer-and-x-api-key`. |
| F-010 | 2 | **owner** | Unknown path with an Anthropic header: HEAD answers the Anthropic error shape (`type: error`, `request_id`, message `This endpoint does not support that operation.`) and counts the request in `busbar_requests_total`; 1.5.5 answered the generic `the requested resource was not found` and counted nothing. Recommend restoring 1.5.5 (an unknown path is not a request). |
| F-014 | 1 | **fix** | `--validate` now resolves identity-provider secrets: with `ORACLE_UNUSED_TOKEN` unset HEAD exits 1 (`secret env:… cannot resolve`) where 1.5.5 exits 0. CI validate steps without production env break. |
| O-1 | 1 | accept (`improvement`) | One new `/metrics` series on a 1.5.5 config: `busbar_metering_pending_coalesced_total` (write-behind overflow sentinel). No 1.5.5 series changed. |

Projected after Phase 1.0 (all **fix** rows done) with the **accept** rows in the register: the
remaining unaccepted divergences are the three **owner** rows — F-004 (69), F-003 (4), F-010 (2).

### Harness facts established while triaging (not busbar behaviour)

- The 1.5.5 binary itself emits the boot banner's `pool /x = …` lines and `--validate`'s error
  bullets in map order (3 of 6 identical runs each way); `normalize.py` sorts each run in place
  (`boot.pool-order`, `boot.error-order`). Likewise key listings (`keys.order`), ETags, `latency_ms`,
  `started_at`, minted `bbk_…` secrets and the version string are normalized. None of these hid a
  real diff: every rule fires on both sides.
- `replay.sh` needed absolute paths (verdict.sh runs from the repo root; a relative `--out` read an
  empty ledger and called the run vacuous — correctly).
- One candidate cell (`admin.ops|GetHooksNameHealth|ok`) failed its fresh boot once and passed on
  re-record; the harness's fresh-boot readiness wait is the suspect, not busbar.
- Weak family: the 69 `validate-migrated` cells exit 1 on **both** binaries because the migration
  corpus ships no providers.yaml (`provider 'x' … not found in providers.yaml`). They still compare
  the refusal text, but they do not prove the migrated configs are accepted. Corpus needs a
  providers file per config before this family counts as coverage.
- Named gaps still owed by the harness: postgres / mysql / valkey store-persist (need services),
  `PostHooks` / `PostPluginsRollback` fixtures, 34 boot mutations without fixtures, mcp / a2a via
  the conformance rigs, timing / concurrency families.

### F-001 · every published 1.5.5 store plugin is refused by HEAD — REGRESSION (weight 10)

`busbar --list-plugins` on the four published store tarballs (fetched by digest):

```
1.5.5: busbar-store-sqlite-1.0.6-<TRIPLE>.tar.gz busbar-store-sqlite-plugin sqlite store 1.0.6 first-party ready
HEAD:  busbar-store-sqlite-1.0.6-<TRIPLE>.tar.gz - - - - INVALID  INVALID: manifest abi_version 2 is not supported for kind 'store' by this binary (supported range v4..=v4)
```

Where it lives: the window is a single point in `crates/plugin-loader/src/registry.rs` (`supported_abi`)
and it is enforced only in `crates/plugin-sign/src/lib.rs` (`validate_structure`). The eight
1.6.0-only `PlaneRecord` verbs already default to inert, and `DynStore` has no `abi_version`
(the `open_login` precedent shows how a missing verb is treated as absent). Fix design:
accept `[2, 4]` for kind `store`, surface `abi_version` on `DynStore`, and route the eight new
verbs to the inert default for ABI < 4; invert the two registry tests that assert refusal.
Ship gate for the family: `plugins.store-persist|store-sqlite` byte-identical (the same sqlite
tarball persists keys across a restart on both binaries).

