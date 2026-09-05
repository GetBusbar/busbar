# Parity baseline — busbar 1.6.0 vs the published busbar 1.5.5

Golden: `/Users/matthew/Developer/GetBusbar/busbar/.claude/worktrees/config-seam-work/target/oracle/recordings/golden` · Candidate: `/Users/matthew/Developer/GetBusbar/busbar/.claude/worktrees/config-seam-work/target/oracle/recordings/candidate` · cells: `/Users/matthew/Developer/GetBusbar/busbar/.claude/worktrees/config-seam-work/testing/shadow-oracle/cells.json`

**Owed 890 · diverging 0 · golden gaps 1393 · weighted D/W = 0.0000**

## Decision

**Base = HEAD** (owner decision, 2026-09-04): the bar is a legitimate 1.6.0 upgrade — 1.5.5's surface, the same or better, plus the mcp / a2a / voice planes — with an accepted-differences register for the deliberate deltas (`improvement` | `breaking`, each `breaking` named in the CHANGELOG). The numeric rule of the plan reads KEEP HEAD on this run (D/W 0.0000 vs ≤ 0.05; every weight-10 family within bound). **Ship gate: zero unaccepted divergences.** Every diverging cell below is triaged in the findings.

## Per family

| family | owed | diverging | D/W |
|---|---|---|---|
| admin.ops | 234 | 0 | 0.000 |
| auth.lifecycle | 3 | 0 | 0.000 |
| billing | 11 | 0 | 0.000 |
| boot.refusal | 195 | 0 | 0.000 |
| boot.warning | 31 | 0 | 0.000 |
| cli | 14 | 0 | 0.000 |
| concurrency | 3 | 0 | 0.000 |
| config.migrate | 138 | 0 | 0.000 |
| cooldown | 1 | 0 | 0.000 |
| crosscut.traps | 5 | 0 | 0.000 |
| documented | 28 | 0 | 0.000 |
| hazard | 2 | 0 | 0.000 |
| hooks | 10 | 0 | 0.000 |
| http.crosscut | 20 | 0 | 0.000 |
| llm.wire | 127 | 0 | 0.000 |
| neutrality | 18 | 0 | 0.000 |
| ops.scrape | 14 | 0 | 0.000 |
| plugins | 11 | 0 | 0.000 |
| queue | 2 | 0 | 0.000 |
| route.failover | 16 | 0 | 0.000 |
| teller | 7 | 0 | 0.000 |

## Per divergence class

| class | cells |
|---|---|

## Divergences (heaviest first, top 40)

- `admin.ops|DeleteHooksName|ok` [effects.readback] effects.readback /0/body/json/fires_at: null -> ["request", "candidate", "routing", "response"]
- `admin.ops|DeleteOverlaySection|not-found` [headers,body] headers content-length: '139' -> '194'
- `admin.ops|GetHooksName|ok` [headers,body] headers content-length: '249' -> '328'
- `admin.ops|GetHooks|ok` [headers,body] headers content-length: '280' -> '359'
- `admin.ops|GetOpenapiJson|ok` [headers,body] headers added vary
- `admin.ops|PatchHooksNameSettings|ok` [effects.readback] effects.readback /0/body/json/fires_at: null -> ["request", "candidate", "routing", "response"]
- `admin.ops|PostHooks|if-match-stale` [headers,body] headers content-length: '215' -> '294'
- `admin.ops|PostHooks|ok` [headers,body,effects.readback] headers content-length: '215' -> '294'
- `admin.ops|PutHooksName|ok` [effects.readback] effects.readback /0/body/json/fires_at: null -> ["request", "candidate", "routing", "response"]
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
- … 254 more in the report's diverging.txt

## Golden gaps (cells the 1.5.5 recording could not produce — named, never owed)

- 1380 × SKIP: named gap on the golden, never owed
- 13 × SKIP: named gap: the fixture this cell needs is not in the tree yet
