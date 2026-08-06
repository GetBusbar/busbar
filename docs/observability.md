# Health, metrics, and observability

Busbar exposes its liveness, per-lane topology, and Prometheus metrics on three endpoints. This page documents each, plus the signals worth alerting on.

Cross-references: [Circuit breaker](/docs/circuit-breaker/) · [In-flight failover](/docs/failover/) · [Configuration](/docs/configuration/#export).

## /healthz

```
GET /healthz
```

No auth required. Returns `200 OK` (body: `ok`) if any lane is usable: meaning at least one lane across all configured pools has a Closed or HalfOpen breaker in any of its cells, and is not permanently dead. Returns `503 Service Unavailable` (body: `no usable lanes`) if every lane is unusable.

Use as a Kubernetes readiness and liveness probe. The check is side-effect-free: it never steals a HalfOpen recovery probe slot.

A `503` from `/healthz` means all lanes are either tripped/cooling, hard-down, budget-exhausted, or permanently dead. Check `/stats` for details.

## /stats

```
GET /stats
Authorization: Bearer <client-token-or-virtual-key>
```

Requires auth (client token or virtual key). Returns a JSON topology snapshot, scoped to the calling key's `allowed_pools`: a key with a non-empty `allowed_pools` list sees only its permitted pools and the lanes reachable through them.

Per-lane fields in the response:

| Field | Meaning |
|---|---|
| `model` | Model name (as declared in `models:`). |
| `provider` | Provider name. |
| `max_concurrent` | Lane's concurrency cap. |
| `inflight` | Currently executing requests. |
| `free_slots` | `max_concurrent - inflight`. |
| `available` | Free concurrency permits for a bounded lane, or the string `"unbounded"` when `max_concurrent` is omitted. |
| `at_capacity` | `true` when a bounded lane is at its `max_concurrent` limit and is therefore shedding/spilling rather than queueing. |
| `availability` | Unified availability from the shared `classify` taxonomy: `"available"` when the lane would admit a request, or the reason it can't — `"breaker_open"`, `"at_capacity"`, `"dead"`, `"budget_exhausted"`, `"probe_in_flight"`, or `"shedding"`. |
| `recovery_hint_ms` | Honest lower bound (ms) on when an unavailable lane could next serve (`null` when available or the reason has no self-recovery, e.g. dead/budget). |
| `breaker_state` | `"closed"`, `"half_open"`, or `"open"` — the independent breaker axis (can be `"open"` and `at_capacity: true` at the same time). |
| `ok` | Lifetime successful upstream responses. |
| `err` | Lifetime recorded upstream failures. |
| `client_fault` | Lifetime 4xx responses attributed to callers (not counted against breaker). |
| `usable` | `true` if the lane is Closed or HalfOpen in any cell. |
| `dead` | `true` if permanently dead (restart to clear). |
| `dead_reason` | `auth`, `billing`, or other hard-down reason. |
| `cooldown_remaining_s` | Worst-case cooldown remaining across all cells (0 if Closed). |
| `streak` | Current consecutive failure streak (worst across cells). |
| `budget` | Remaining `max_requests` lifetime budget (`-1` = unlimited). |

`/stats` is the first tool to reach for when diagnosing a degraded pool. Check `cooldown_remaining_s` (non-zero means a cell is Open and the value shows when it will try to recover), `streak` (growing streak suggests repeated probe failures), and `dead` + `dead_reason` (a hard problem requiring intervention).

## /metrics

```
GET /metrics
Authorization: Bearer <client-token-or-virtual-key>
```

Prometheus text exposition (`text/plain; version=0.0.4`). Goes through the same auth check as other routes, it is treated as an information-disclosure surface (it reveals pool structure, lane names, and failure rates). With no auth chain (`auth.chain: []`), the check admits unconditionally, so `/metrics` is effectively open. Restrict it at the network layer if that matters for your threat model.

### Metrics are opt-in

Metrics are **off unless you ask for them.** With no `module: prometheus` instance under `export:` busbar installs no recorder, records nothing on the request path, and does not mount `/metrics` or `/metrics/hooks` at all — a scrape of either gets the same 404 as any other unknown path. Opting in is one `export:` instance, and `buffer_seconds` is **required**:

```yaml
export:
  metrics:                      # the INSTANCE NAME — yours to choose
    module: prometheus
    settings:
      buffer_seconds: 60        # REQUIRED — how many seconds of observations to retain
      key_gauge_limit: 2000     # optional (default 2000)
```

(1.5.3 retired the top-level `metrics:` block into this instance; at most ONE `prometheus` instance
is allowed, since it owns the one well-known `/metrics` route.)

`buffer_seconds` is the retention window. Busbar folds buffered observations into their aggregate form on a timer and drops anything older, so:

* **quantile lines** on `/metrics` (`busbar_request_duration_seconds{quantile="…"}`) cover the last `buffer_seconds`;
* **`_sum` and `_count` are cumulative** and unaffected by the window — totals and rates never lose anything;
* **memory is bounded by the window, not by uptime.** Retention is one window's traffic, whether or not anything ever scrapes you.

There is no default because the right value is a memory-for-fidelity trade only you can make: every second of buffer holds that second's raw observations in memory (at very high request rates, a few MB per second). Pick the window your dashboards actually query. `buffer_seconds: 0` is rejected at boot — it would retain nothing while still paying the recording cost; omit the whole instance instead.

`key_gauge_limit` bounds the per-key gauge series (e.g. `busbar_key_spend_cents{key="…"}`) emitted on a single `/metrics` scrape. A fleet with many virtual keys can otherwise produce one time series per key, unbounded — Prometheus cardinality that never shrinks back down. Busbar emits at most `key_gauge_limit` per-key series per scrape (highest-spend keys first) and logs a warning when it truncates; aggregate totals (`_sum`, `_count`) are never affected, only the per-key breakdown. Raise it if your dashboards need finer per-key visibility than the default gives at your key count; the trade is the same one `buffer_seconds` makes — more fidelity for more memory and scrape payload.

Scraping is not required for correctness. A gateway with metrics enabled and nothing scraping it retains one `buffer_seconds` window and no more.

## Metrics to watch

| Metric | Type | Labels | What to watch for |
|---|---|---|---|
| `busbar_requests_total` | counter | `ingress_protocol`, `pool`, `outcome` | `outcome=exhausted` rising → pools running out of healthy members. `outcome=error` → 5xx-class problems reaching the client; `outcome=client_error` → 4xx relayed to callers. |
| `busbar_upstream_attempts_total` | counter | `pool`, `lane` | Real upstream calls, re-counted per failover hop. Ratio to `busbar_requests_total` > 1 indicates failovers are happening. |
| `busbar_upstream_failures_total` | counter | `pool`, `lane`, `disposition` | `disposition` is `transient_upstream`, `attempt_timeout`, `hard_down`, or `context_length`. `hard_down` requires intervention (auth/billing problem). |
| `busbar_breaker_trips_total` | counter | `pool`, `lane` | One per Closed→Open trip (reopens don't count). A spike means a backend just went down. |
| `busbar_failovers_total` | counter | `pool`, `reason` | `reason` is `timeout`, `connect`, `transient_upstream`, `attempt_timeout`, `hard_down`, or `context_length`. A high rate on one pool indicates a flapping member. |
| `busbar_translations_total` | counter | `from`, `to` | Cross-protocol translation hops. Useful for auditing unexpected protocol conversion. |
| `busbar_request_duration_seconds` | histogram | `ingress_protocol`, `pool` | End-to-end latency including failover hops. |
| `busbar_key_spend_cents` | gauge | `key` + mint labels | Per-virtual-key DERIVED spend (abstract minor units, all-time attribution bucket), recomputed at scrape time from the token ledger x the current `rate_card` plus the flat fee (reprice-on-read). |
| `busbar_bucket_spend_cents` | gauge | `bucket`, `group`, `window` | Derived spend per (group, window) enforcement bucket (`bucket` = `group:<name>@<window>`). |
| `busbar_bucket_budget_remaining_cents` | gauge | `bucket`, `group`, `window` | Budget cap minus derived spend, only for buckets with a `budget` limit. Use for burn-rate alerting. |
| `busbar_key_tokens_total` | gauge | `key` + mint labels | Accumulated tokens consumed by each virtual key (all-time attribution bucket). |
| `busbar_bucket_tokens` | gauge | `bucket`, `model`, `tier` (+ mint labels on key buckets) | Per-(bucket, model, tier) token counters for the bucket's current budget window, from the token ledger. `bucket` is a virtual-key id or `group:<name>`; `tier` ∈ `input`\|`output`\|`cache_read`\|`cache_write`. The raw material for any external per-model cost dashboard (multiply by your own catalog). |
| `busbar_bucket_spend_cents` | gauge | `bucket` | Derived spend per BUDGET-GROUP bucket (tokens x current rate card; the flat fee counts against key buckets) for its current window. |
| `busbar_bucket_budget_remaining_cents` | gauge | `bucket` | Budget-group cap minus derived spend. The external-alerting hook: point Alertmanager at 80% burn - Busbar ships the hard 100% stop only, alerts live outside the core. |
| `busbar_lane_state` | gauge | `pool`, `lane` | Per-(pool, lane-index) circuit-breaker health: `0` = Closed (healthy), `1` = HalfOpen (cooling, probe admitted), `2` = Open (tripped). Side-effect-free at scrape time. |
| `busbar_lane_available` | gauge | `pool`, `lane` | Unified availability from the shared `classify` taxonomy (the same one routing dispatches on): `1` = the lane would admit a request right now, `0` = unavailable for ANY reason (breaker Open, at-capacity, dead, budget, probe-in-flight). Pair with `busbar_lane_state` (breaker) and `busbar_lane_available_permits` (capacity) to see which axis is the cause. Replaces the former `busbar_lane_at_capacity`. Side-effect-free. |
| `busbar_lane_recovery_hint_ms` | gauge | `pool`, `lane` | Honest lower bound (ms) on when an unavailable lane could next serve, from the same `recovery_hint_ms` that feeds `Retry-After`: breaker `until` for an Open lane, the at-capacity floor (2000ms) for a saturated one. `0` when available or the reason has no self-recovery (dead/budget). Side-effect-free. |
| `busbar_lane_available_permits` | gauge | `pool`, `lane` | Free concurrency permits for a bounded lane (`0` = saturated) — the independent capacity axis. Unbounded lanes emit no sample. Side-effect-free. |
| `busbar_pool_queued` | gauge | `pool` | Requests currently parked in the `on_exhausted: queue` bounded wait, per pool. Reads `0` until the queue policy is wired. Side-effect-free. |
| `busbar_route_policy_selections_total` | counter | `pool`, `policy` | Requests where a routing policy produced a usable ranked order. Only incremented on a successful `Order` outcome; abstains and on-error fallbacks are not counted. |
| `busbar_route_policy_rejections_total` | counter | `pool`, `policy`, `status` | Requests deliberately rejected by a routing hook's `reject` verb (a 4xx to the caller, no upstream dispatched). A guardrail saying no, not a failure. |
| `busbar_billing_truncated_total` | counter | none | A same-protocol non-stream response whose billing-side buffer hit the translate-body cap before the terminal `usage` block, so tokens could not be parsed and the request billed zero. The client response is unaffected; only the billing side-channel was capped. Alert on a non-zero rate to catch an over-cap billing gap. |
| `busbar_tap_notifications_dropped_total` | counter | none | A fire-and-forget tap notification dropped because the in-flight cap was reached (slow or unreachable tap endpoint). Global backpressure, not per-request. Alert on a non-zero rate. |
| `busbar_webhook_logs_dropped_total` | counter | none | A request-log webhook delivery shed because the bounded delivery pool was saturated (the endpoint is slow or unreachable). Global backpressure. A non-zero rate means logs are being dropped silently. |
| `busbar_file_logs_dropped_total` | counter | none | A request-log FILE append shed because that sink's bounded in-flight append pool was saturated (a slow or stalled filesystem — full disk, hung mount). The file-sink counterpart of the webhook counter above. A non-zero rate means request-log lines are being dropped. |

**Mint labels.** Key labels attached at mint (`labels: {"team": "growth"}`) are echoed verbatim onto that key's gauge series, so Grafana can `sum by (team)` and Alertmanager can fire per team without Busbar knowing what a team is. Label keys are operator-chosen at mint (admin-plane bounded), never request bytes.

**Spend is derived, and the hard cap is per node.** Every spend gauge above is recomputed at scrape time from the token ledger and the current `rate_card`; nothing dollar-shaped is stored, so a rate correction re-prices what you see on the next scrape. When N Busbar nodes share a durable store, each node scrapes its own in-memory window counters and enforces the budget hard cap per node (fleet-wide the effective ceiling is up to ~N times a configured cap between flushes; see [operations.md](operations.md)).

The `pool` label is always a configured pool name or the sentinel `unresolved` (for routes that did not resolve to a pool). It is never a raw client-supplied model string, which would create unbounded label cardinality.

Deeper observability rides the single `export:` surface (1.5.3 — the `observability:` block is gone): a `module: otlp` instance for traces and a `module: request-log-webhook` instance for per-request logs. Both are validated at startup against SSRF blocklists (no RFC-1918, loopback, or cloud-metadata targets, except OTLP allows plaintext `http://` to loopback for a local collector). Because `export:` is a NAMED map, several instances of one module are allowed — e.g. two request-log webhooks, one to your log store and one to a SIEM. See [configuration.md](configuration.md#export).

## Response headers

Every response header Busbar itself injects (as opposed to a header it relays or translates from an upstream) is an **opt-in toggle under `advanced.response_headers`, default OFF**. Each one is, in some form, an in-band tell that the request went through Busbar rather than talking to the backend directly — so none of them ship enabled out of the box, and an operator opts in per-header only when the tradeoff (a useful diagnostic vs. a fingerprintable observable) is one they've chosen to accept. Both toggles are **restart-to-apply**: each is baked into process-wide state at boot (router middleware composition for `server_timing`, a process-wide flag for `route_policy`), so a live `PUT /config/settings` stores the new value durably but it only takes effect after a restart (`POST /restart` or a supervisor restart) — `reload_to_apply` flags `advanced.response_headers` when you change it live.

```yaml
advanced:
  response_headers:
    server_timing: false   # default
    route_policy: false    # default
```

| Header | Toggle | Carries | Fires | Default |
|---|---|---|---|---|
| `Server-Timing: busbar;dur=<ms>` | `advanced.response_headers.server_timing` | Busbar's OWN added latency (total request wall-clock minus the upstream round-trip), at millisecond precision per the W3C `Server-Timing` spec. | On every response, once enabled — including admin/health/early-error responses that never dispatched upstream (in which case the full request time is reported). | `false` |
| `x-busbar-route-policy` / `x-busbar-route-target` | `advanced.response_headers.route_policy` | The name of the routing policy that chose the lane, and the chosen lane's model. Values are bounded, operator-defined strings (a fixed policy enumeration + a configured model name) — never request-derived data. | Only when a non-default routing policy actually produced the order; a default `route: weighted` pool (or a policy that abstained and fell through to weighted round-robin) attaches nothing even when the toggle is on. | `false` |

**Why default off.** Both headers are useful — `Server-Timing` is a standard latency probe DevTools and APM tooling already understand; the route headers are handy when debugging which policy picked a lane — but Busbar is deliberately anti-fingerprinting: an unauthenticated client should not be able to tell it's talking to a gateway rather than the backend directly from response shape alone. `Server-Timing: busbar;dur=…` and `x-busbar-route-*` are both in-band Busbar tells observable on every response, so both stay invisible until an operator explicitly accepts that tradeoff.

**The composition gate (not a runtime check).** Enabling `server_timing` installs an ADDITIONAL middleware layer on the router at boot (mirroring how `limits.max_inbound_concurrent: 0` removes the inbound-concurrency layer entirely rather than checking a flag inside it); when disabled, the layer performing the actual timing (a per-request allocation, a monotonic clock read, and a task-local scope) is never installed at all, so the default-off posture costs nothing per request, not even the allocation the earlier gate used to pay even while suppressing the header. `route_policy` is gated the same way in spirit: a single process-wide decision read at the header's one injection site, not a per-response cost when off.

## Tracing (the hot-path level policy)

Every per-request span/event lives at the SAME level, set in exactly one place, so it is off by
default and an operator can turn the whole request path on with one env var. The rule this section
documents: **every `#[tracing::instrument]` must carry an explicit `level =` — a
"rogue" instrument with no level silently defaults to INFO, which is always-on on the hot path — and
that level is set in one spot, not re-picked ad hoc at each call site.**

**The one spot: `observability::HOTPATH_LEVEL`.** `crates/busbar/src/observability.rs` defines:

```rust
pub(crate) const HOTPATH_LEVEL: tracing::Level = tracing::Level::DEBUG;
```

Every hot, per-request `#[tracing::instrument]` (the `forward` span in `proxy/engine/mod.rs`, the
`forward_once` span in `proxy/engine/walk.rs`, and the ingress entry spans — `gemini_ingress`,
`bedrock_converse`, `bedrock_converse_stream`, `named`, `adhoc` — in `ingress/mod.rs`) references
this constant (or, where the macro's parser requires a bare identifier rather than a `crate::`-
prefixed path, imports it with `use crate::observability::HOTPATH_LEVEL;` and writes
`level = HOTPATH_LEVEL`). Raising or lowering hot-path verbosity for the whole request path is a
one-line change to that constant — never a per-call-site literal.

`HOTPATH_LEVEL` is `DEBUG`, not the `tracing::Level::TRACE` variant, because it pairs with the
OTHER half of the one-spot policy: `observability::log_levels()`, which builds the stderr and OTLP
filters. Stderr takes `RUST_LOG` (default `info` — hot-path spans off). OTLP floors at
`DEBUG` unconditionally, specifically so pointing an `export:` `module: otlp` instance at a collector gets
the request-path spans without ALSO having to set `RUST_LOG=debug` and flood stderr with every debug
line in the process. Both stay off at the default `RUST_LOG=info` filter either way — set
`RUST_LOG=debug` (or `RUST_LOG=busbar=debug`) to see hot-path spans on stderr, or configure OTLP to
get them exported without touching stderr at all.

**Event macros (`info!`/`warn!`/`error!`) are a documented convention, not lint-enforced.** In the
hot modules (proxy/auth/governance/ingress) every `info!`/`warn!` fires only on an error, rejection,
degraded, or boot/config condition, never on the per-request happy path. The convention: a `debug!`/`trace!`
(hot level) event on the per-request happy path is fine and expected; reserve `info!`/`warn!`/
`error!` for exactly the conditions above — a state an operator running at the default level should
see. Whether a NEW event macro belongs at the hot level is a judgment call (does it fire on every
successful request, or only on a rare/error path?) that a mechanical lint cannot make reliably
without false positives, so it is enforced by review, not CI — see `scripts/tracing-lint.sh`'s header
comment for why that script deliberately stops at the `#[instrument]`-level-presence rule.

**Enforcement: `scripts/tracing-lint.sh`.** Runs in CI (the `structure-lint` job, alongside
`structure-lint.sh` / `response-header-lint.sh`). Fails the build on any `#[tracing::instrument]` (or
bare `#[instrument]`) anywhere in `crates/**/*.rs` (excluding `*/tests/*`) whose attribute text —
gathered across however many lines it spans — never mentions `level`. `--selftest` proves the
scanner still catches a level-less instrument (bare, single-line, and multi-line shapes) before its
verdict on the tree is trusted, mirroring `structure-lint.sh --selftest` /
`response-header-lint.sh --selftest`.

---
