# Operations

Running Busbar in production: process configuration, health/readiness, the metrics
to watch, circuit-breaker and health-probe behavior, failover/exhaustion outcomes,
governance/admin usage, and troubleshooting.

## Process configuration

Busbar is a single native binary configured by two YAML files and environment
variables.

| Env var | Default | Purpose |
|---|---|---|
| `BUSBAR_PROVIDERS` | `/etc/busbar/providers.yaml` | Path to the provider catalog. |
| `BUSBAR_CONFIG` | `/etc/busbar/config.yaml` | Path to the deployment config. |
| `BUSBAR_WORKER_THREADS` | one per available core | Size of the async worker pool. See below. |
| Provider key vars | n/a | Named by each provider's `api_key: { env: ... }` reference (e.g. `ANTHROPIC_KEY`). |
| Token/secret vars | n/a | Anything referenced via `${VAR}` in either file (client tokens, admin token, …). |

**Worker threads and scaling.** Busbar's request path is CPU-bound (parse, translate, serialize), so
throughput scales with worker threads. The default is **one worker per available core**
(`available_parallelism`, which respects CPU affinity and the cgroup **cpuset**, but **not** the CFS
`cpu.max` bandwidth quota, which it cannot see), which gives linear scaling: ~9,750 req/s per core,
sub-millisecond, to ~156k on 16 cores in our [benchmark](https://getbusbar.com/performance). Each worker
carries a thread stack and, on glibc, its own malloc arena, so idle memory grows slowly with the count. For
a **footprint-sensitive sidecar** set `BUSBAR_WORKER_THREADS=1` (or `2`). On a **CPU-quota-limited pod** (a
k8s CPU *limit* on a many-core node) the default sizes to the node's full core count and oversubscribes the
quota: **set `BUSBAR_WORKER_THREADS` to your CPU limit**; likewise to cap a shared box, set it to the cores
you want Busbar to use. Scale up by default, tune down deliberately. *(Before 1.4.0 the default was capped at
`min(cores, 4)`, which pinned throughput to ~4 cores regardless of box size, set the variable explicitly
on older binaries.)*

Startup is fail-loud: an unset `${VAR}`, an unknown provider reference, an unknown
protocol or auth mode, or an invalid `on_exhausted` action stops the process with a
diagnostic. A provider whose key env var is empty logs a warning and runs (its lane
will fail auth on first use). `auth.chain: []` prints a loud open-relay warning.

The HTTP client uses a 300s request timeout and pools up to 1024 idle keep-alive connections per upstream host.

### Validating configuration (`busbar --validate`)

`busbar --validate` runs the exact load → resolve → validate pipeline the gateway runs at boot,
then exits, **without** starting the server. It binds no port, writes no state file, spawns no
tasks, opens no TLS material, and makes no network call, so it is safe to run anywhere, including
in CI and against a config edited on a live host before you reload it.

```sh
BUSBAR_CONFIG=./config.yaml BUSBAR_PROVIDERS=./providers.yaml busbar --validate
# ok: config valid — 2 provider(s), 2 model(s), 1 pool(s)
#   note: 1 env var(s) referenced but unset here — required at runtime: BUSBAR_CLIENT_TOKEN
```

- **Exit `0`** = valid; **`1`** = errors (same diagnostics boot prints: invalid YAML, removed keys,
  dangling pool/lane references, malformed auth chains, cert-file and `base_url`/`path` SSRF violations).
  Use it as a CI gate: `busbar --validate && deploy`.
- **Secrets are not required.** It checks *structure*, not upstream reachability, so a `${VAR}` unset
  in your shell is reported in a `note:` ("required at runtime") rather than failing, you can validate
  in CI without production secrets. (At real boot an unset `${VAR}` is still a hard error.)
- Honors `BUSBAR_CONFIG`, `BUSBAR_PROVIDERS`, and `--safe-mode` exactly as boot does. Because it reuses
  the boot path, a clean `--validate` means a clean boot.

## Inbound TLS & mutual-TLS (mTLS)

Busbar terminates TLS natively for the client↔Busbar hop. Add an optional `tls`
block to `config.yaml`; when it is **absent**, Busbar serves plain HTTP exactly as
before (no behavior change). When present, Busbar handles the TLS handshake itself,
no sidecar required.

```yaml
listen: "0.0.0.0:8443"
tls:
  cert: { file: /etc/busbar/tls/fullchain.pem }  # PEM cert chain, leaf first (secret reference)
  key:  { file: /etc/busbar/tls/privkey.pem }    # PEM private key (PKCS#8 / PKCS#1 / SEC1)
  # client_ca: { file: /etc/busbar/tls/ca.pem }  # OPTIONAL: see "Mutual TLS" below
```

Each of `cert`, `key`, and `client_ca` is a **secret reference**, not a bare path: the
`{ file: /path }` form above reads PEM bytes from disk, and `{ env: VAR }` reads them from an
environment variable (or `{ module: <secret-plugin>, settings: {…} }` from a secret backend). The
plaintext `cert_file`/`key_file`/`client_ca_file` path keys of earlier releases are gone in 1.5.0.

**Certificate & key formats.** `cert` resolves to a PEM certificate chain with the leaf
(server) certificate first, followed by any intermediates: exactly what most CAs
ship as `fullchain.pem`. `key` resolves to the matching PEM private key in PKCS#8
(`BEGIN PRIVATE KEY`), PKCS#1 (`BEGIN RSA PRIVATE KEY`), or SEC1
(`BEGIN EC PRIVATE KEY`) encoding. Busbar advertises **http/1.1** over ALPN.

**Fail-fast.** Any missing, unreadable, or unparseable cert/key/CA file stops the
process at startup with a message naming the offending file: a misconfigured
certificate can never silently downgrade or half-start the listener. Key bytes are
never logged.

### Mutual TLS (client-cert auth)

Set `client_ca` (a secret reference resolving to a PEM CA bundle) to require **mutual TLS**: every client must
present a certificate that chains to that CA, or the TLS handshake is rejected before
any request is processed. This is transport-level zero-trust: only holders of a
cert your CA signed can establish a connection at all, with no service mesh or
external proxy. It composes with (and runs before) the normal `auth` token / virtual-key
check. A client with a missing or wrong certificate is dropped at handshake; the
rejection is contained to that one connection and never affects the server or other
clients.

### Certificate rotation

Certs are loaded once at startup, so rotation always needs a restart — but it does not need a
shell. Push the new cert/key/CA through the admin API, then restart in-product:

```bash
curl -X PUT http://localhost:8081/api/v1/admin/config/settings \
  -H "x-admin-token: $ADMIN_TOKEN" -H 'content-type: application/json' \
  --data '{"tls": {"cert": {"file": "..."}, "key": {"file": "..."}, "client_ca": {"file": "..."}}}'
# -> {"reload_to_apply": ["tls"], "note": "... takes effect on the next restart ..."}

curl -X POST http://localhost:8081/api/v1/admin/restart \
  -H "x-admin-token: $ADMIN_TOKEN"
```

The `PUT` stores the new material durably (overlay-persisted) and reports `tls` under
`reload_to_apply` — restart-scoped, per the [`PUT /config/settings`](/docs/admin-api/#the-config-plane)
table. `POST /restart` then applies it: it drains through the same graceful-shutdown path a signal
takes (in-flight requests finish first), which is exactly why a restart on rotation is safe under
live traffic — the same guarantee this section always relied on, now reachable without shelling in.
If no process supervisor is detected, the endpoint refuses with `409 conflict` unless the request
sets `confirm: true` (an unsupervised exit would leave Busbar down).

Without admin API access (or without a config overlay configured), the file-level fallback still
works: replace the PEM files on disk and restart Busbar directly (e.g. `systemctl restart busbar`).

**Reverse proxy alternative.** A TLS-terminating reverse proxy (nginx, Caddy,
Envoy) in front of a plain-HTTP Busbar still works if you prefer to manage certs
there: simply omit the `tls` block.

### Connection-level hardening (slow-loris)

When Busbar terminates TLS itself, the native listener bounds the request **header-read**
phase (30 s) in addition to the TLS handshake, so a client that completes the handshake
and then trickles request headers one byte at a time cannot pin a connection open
indefinitely. This bound applies only to reading the request headers: it never limits a
streaming response, so long model completions are unaffected.

The plain-HTTP listener (no `tls` block) does **not** apply a header-read timeout. For an
**edge-facing** deployment, either enable the `tls` block (recommended) or front Busbar
with a reverse proxy / load balancer (nginx, Caddy, Envoy, an ALB), which terminates
client connections and provides its own slow-client protection. A plain-HTTP Busbar
directly exposed to untrusted networks is not recommended.

## Health & readiness

| Endpoint | Auth | Meaning |
|---|---|---|
| `GET /healthz` | open | `200 ok` if **any** lane is usable; `503` otherwise. Use for liveness/readiness probes. |
| `GET /metrics` | virtual key | Prometheus exposition. OPT-IN: mounted only when a `metrics:` block is configured (with its required `buffer_seconds`); otherwise the path 404s like any other. Requires a valid key with a non-empty `auth.chain`, open under `chain: []`. Restrict at the network layer if unauthenticated scraping is needed. |
| `GET /stats` | virtual key | Per-lane health snapshot + pool membership, JSON. |

`/stats` returns, per lane: `model`, `provider`, `max_concurrent`, `inflight`,
`free_slots`, `available` (free permits for a bounded lane, or `"unbounded"`),
`at_capacity` (`true` when a bounded lane is at its `max_concurrent` limit and is
therefore shedding/spilling rather than queueing), `ok`, `err`, `usable`, `dead`,
`dead_reason`, `cooldown_remaining_s`, `streak`, and `budget`. It is the first place to
look when a pool is degraded; `at_capacity` distinguishes an oversubscribed lane from a
merely slow one.

## Running multiple instances (HA)

Busbar is **stateless** (apart from governance ledgers, see below), so the robust
production shape is **N instances behind a load balancer**, each configured
identically, each health-checked on `GET /healthz`. Any instance serves any request;
lose one and the LB routes around it. On Kubernetes this is `replicaCount` + the
Service/Ingress + a PodDisruptionBudget; on VMs it is N hosts behind an external LB
(nginx, HAProxy, or a cloud L4/L7 balancer) probing `/healthz`.

Three things are worth understanding before you scale out:

- **Circuit-breaker and lane health are per-instance.** Each instance learns upstream
  health independently from its own traffic. This is correct (a lane that's dead for
  one instance is usually dead for all) and a new instance re-learns within seconds.
  Nothing is shared or needs sharing.
- **Session affinity is per-instance.** The `affinity` header pins a session to a lane
  *within one instance*. Across instances, an LB that spreads a client's requests will
  spread its affinity too. If you depend on affinity, enable **sticky sessions** at the
  LB (e.g. by the affinity header / a cookie) so a session lands on the same instance.
- **Governance state defaults to per-instance memory; enforcement is per-node either
  way.** The default `store: memory` is ephemeral RAM per instance. A cluster-shared
  store (postgres/redis) genuinely shares keys and the token ledger across N nodes (but
  NOT the durable audit log - see below), and each node's write-behind flush ships
  ADDITIVE per-(model, tier) token deltas so the store converges on the true fleet
  totals - but the budget hard
  cap is still checked from each node's in-memory counters, so between flushes N nodes
  splitting traffic can admit up to ~N times a configured cap. For a strict single
  ceiling, run a single instance (scale vertically); the proxy path itself scales
  horizontally without this caveat.
- **The durable audit log takes exactly ONE writer.** Audit sequence numbers are
  allocated in-process, so two nodes sharing a store reach for the same numbers and
  overwrite each other's entries, breaking the hash chain the next boot verifies. A
  node that detects another writer logs an error and detaches its durable sink,
  continuing to audit to its in-memory ring and state snapshot rather than corrupting
  the shared log. Point at most one node at a durable audit store; `GET /audit` is
  per-instance either way (it serves that node's in-memory ring, never the store).

So: for a gateway without group limits, scale out freely behind an LB. With limits,
either accept the per-node cap semantics over a shared store, or keep enforcement on
one instance and scale the box, not the count.

## Metrics to watch

All metrics are Prometheus counters/histograms exposed at `/metrics`, which is opt-in: with no `metrics:` block busbar records nothing and does not mount the endpoint. `metrics.buffer_seconds` (required when you opt in) sets how many seconds of observations are retained — quantiles cover that window, `_sum`/`_count` stay cumulative, and memory is bounded by the window rather than by uptime.

| Metric | Type | Labels | Watch for |
|---|---|---|---|
| `busbar_requests_total` | counter | `ingress_protocol`, `pool`, `outcome` | `outcome` is `ok` / `client_error` / `exhausted` (503) / `error`. A rising `exhausted` means pools are running out of healthy members. |
| `busbar_upstream_attempts_total` | counter | `pool`, `lane` | Real upstream calls (re-counted per failover hop). |
| `busbar_upstream_failures_total` | counter | `pool`, `lane`, `disposition` | `disposition` is `transient_upstream` / `attempt_timeout` / `hard_down` / `context_length`. Concentration on one lane points at a sick backend. |
| `busbar_breaker_trips_total` | counter | `pool`, `lane` | Each hard-down/trip. Spikes = a backend going down. |
| `busbar_failovers_total` | counter | `pool`, `reason` | `reason` is `timeout` / `connect` / `transient_upstream` / `attempt_timeout` / `hard_down` / `context_length`. |
| `busbar_translations_total` | counter | `from`, `to` | Cross-protocol translation hops. |
| `busbar_request_duration_seconds` | histogram | `ingress_protocol`, `pool` | End-to-end latency. |
| `busbar_key_spend_cents` | gauge | `key` (+ mint labels) | Per-virtual-key derived spend in cents (all-time attribution bucket; spend derives from the token ledger x the current rate card at scrape time). |
| `busbar_key_tokens_total` | gauge | `key` (+ mint labels) | Tokens consumed by each virtual key (all-time attribution bucket). |
| `busbar_bucket_spend_cents` | gauge | `bucket`, `group`, `window` | Derived spend per (group, window) enforcement bucket (`bucket` = `group:<name>@<window>`). |
| `busbar_bucket_budget_remaining_cents` | gauge | `bucket`, `group`, `window` | Budget cap minus derived spend, only for buckets carrying a `budget` limit. Enables Prometheus burn-rate alerting per group. |
| `busbar_bucket_tokens` | gauge | `bucket`, `group`, `window`, `model`, `tier` | Per-(bucket, model, tier) token counters (the raw material for external cost dashboards). |
| `busbar_lane_state` | gauge | `pool`, `lane` | Circuit-breaker health per lane: `0` = Closed, `1` = HalfOpen, `2` = Open (tripped). Side-effect-free at scrape. |
| `busbar_lane_at_capacity` | gauge | `pool`, `lane` | Saturation signal: `1` when a bounded (`max_concurrent`) lane is at its limit (shedding/spilling), else `0` (has headroom or unbounded). Distinguishes an oversubscribed lane from a slow upstream, which the duration histogram cannot. Side-effect-free. |
| `busbar_lane_available_permits` | gauge | `pool`, `lane` | Free concurrency permits for a bounded lane (`0` = saturated). Unbounded lanes emit no sample. Side-effect-free. |
| `busbar_route_policy_selections_total` | counter | `pool`, `policy` | Requests where a selection strategy (a native strategy or a gate hook) produced a usable ranked order. Only incremented on a successful `Order` outcome; abstains and on-error fallbacks are not counted. |
| `busbar_route_policy_rejections_total` | counter | `pool`, `policy`, `status` | Requests deliberately rejected by a routing hook's `reject` verb (a 4xx to the caller, no upstream dispatched). A guardrail saying no, not a failure. |
| `busbar_webhook_logs_dropped_total` | counter | n/a | Request-log webhook deliveries shed because the in-flight delivery pool was saturated (a slow/unreachable webhook endpoint). A non-zero rate means request logs are being silently dropped, scale the endpoint or alert. |
| `busbar_billing_truncated_total` | counter | n/a | Same-protocol non-stream responses whose body exceeded the translate-body cap, so the terminal `usage` frame was missed and the request billed zero tokens (the client still got a full response). A non-zero rate signals an over-cap billing gap. |

`/metrics` requires a valid key with a non-empty `auth.chain`, it is treated as an
information-disclosure surface and goes through the same auth check as other routes.
Only `chain: []` admits scrapes unconditionally. Restrict it at the network layer (firewall, reverse proxy) if you
need unauthenticated scraping under your threat model.

## Circuit breaker

The breaker decides health from real request outcomes (passive), with optional
active probing layered on top. The disposition pipeline (see
[architecture.md](architecture.md)) decides *whether* an outcome counts as an
upstream fault; this section covers *what happens to the lane* once it does.

Breaker state is **per-(pool, lane)**: a lane that is a member of more than one pool
carries independent Open/Closed/HalfOpen state, streak, cooldown, and error window in
each pool, so one pool's traffic tripping a lane does not bench it for the others.
Direct/ad-hoc routes (`POST /{provider}/{model}`, `POST /{model}`) and `/stats` share a
single lane-default cell. The concurrency limit and the `max_requests` lifetime budget
are **not** per-pool, they cap the shared upstream, so they apply across every pool.
A successful active health probe (it tests the shared upstream) clears the breaker in
*every* cell for the lane.

### States

<svg viewBox="0 0 700 260" role="img" aria-label="Circuit-breaker state machine. Closed serves traffic and trips to Open when the trip condition is met. Open is skipped during selection until the cooldown expires, which moves the lane to HalfOpen. HalfOpen admits exactly one probe: a successful probe returns the lane to Closed, while a failed probe returns it to Open with a longer cooldown." style="width:100%;height:auto;max-width:700px;font-family:ui-sans-serif,system-ui,sans-serif;">
  <defs>
    <marker id="cb-arw" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M0,0 L10,5 L0,10 z" fill="#94a3b8"/>
    </marker>
  </defs>
  <rect x="0" y="0" width="700" height="260" fill="#ffffff"/>

  <!-- Return arc: HalfOpen &#8594; Closed (recovery, over the top) -->
  <path d="M600,110 C600,40 100,40 100,110" fill="none" stroke="#94a3b8" stroke-width="2" marker-end="url(#cb-arw)"/>
  <text x="350" y="34" text-anchor="middle" fill="#64748b" font-size="11">probe succeeds &#8594; back to Closed</text>

  <!-- Return arc: HalfOpen &#8594; Open (below) -->
  <path d="M600,166 C600,232 350,232 350,166" fill="none" stroke="#94a3b8" stroke-width="2" marker-end="url(#cb-arw)"/>
  <text x="480" y="248" text-anchor="middle" fill="#64748b" font-size="11">probe fails (longer cooldown)</text>

  <!-- Forward arrows -->
  <g stroke="#94a3b8" stroke-width="2" marker-end="url(#cb-arw)">
    <line x1="162" y1="138" x2="248" y2="138"/>
    <line x1="422" y1="138" x2="518" y2="138"/>
  </g>
  <text x="205" y="130" text-anchor="middle" fill="#64748b" font-size="11">trip condition</text>
  <text x="470" y="130" text-anchor="middle" fill="#64748b" font-size="11">cooldown expires</text>

  <!-- Closed -->
  <rect x="40" y="116" width="122" height="44" rx="22" fill="#ecfccb" stroke="#d9f99d"/>
  <text x="101" y="143" text-anchor="middle" fill="#35510b" font-size="14" font-weight="700">Closed</text>

  <!-- Open -->
  <rect x="248" y="116" width="122" height="44" rx="22" fill="#fee2e2" stroke="#fecaca"/>
  <text x="309" y="143" text-anchor="middle" fill="#b91c1c" font-size="14" font-weight="700">Open</text>

  <!-- HalfOpen -->
  <rect x="518" y="116" width="122" height="44" rx="22" fill="#fef9c3" stroke="#fde68a"/>
  <text x="579" y="143" text-anchor="middle" fill="#a16207" font-size="14" font-weight="700">HalfOpen</text>

  <!-- Subtle self-note near Closed -->
  <text x="101" y="182" text-anchor="middle" fill="#94a3b8" font-size="10">single sub-threshold failure</text>
  <text x="101" y="195" text-anchor="middle" fill="#94a3b8" font-size="10">&#8594; brief skip, stays Closed</text>
</svg>

- **Closed**: the lane serves traffic. A single upstream failure that does **not**
  meet the trip condition still arms a short cooldown (the lane is briefly skipped),
  but the breaker stays Closed.
- **Open**: the lane is tripped and skipped during selection until its cooldown
  expires.
- **HalfOpen**: on cooldown expiry, the next selection attempt transitions the lane
  to HalfOpen and admits **exactly one** probe request (single-flight via CAS). A
  successful probe completes recovery to Closed (streak/error window cleared); a
  failed probe reopens the lane with an escalated cooldown.

### Trip conditions

Configured per pool via `breaker.trip` (see
[configuration.md](configuration.md#breaker)):

- **`error_rate`** (default): trips when the failure fraction over `window_secs`
  reaches `threshold` (default 0.5), but never before `min_requests` (default 5)
  outcomes have accrued in the window.
- **`consecutive`**: trips on `consecutive_n` consecutive failures (default 3).

### Cooldown & backoff

Cooldown grows exponentially with the consecutive failure streak, doubling from
`base_cooldown_secs` up to `max_cooldown_secs`, with ±10% jitter once the streak is
nonzero. A server `Retry-After` header is always honored as a **floor**: even if it
exceeds `max_cooldown_secs`. Defaults (no `breaker:` block): base 15s, max 120s.

### Hard-down vs transient

- A **transient** fault (5xx/timeout/network/overload/rate-limit) drives the trip
  evaluation and, on trip, opens the breaker: recoverable via the half-open probe.
- A **hard-down** fault (billing/quota or auth) opens the breaker immediately with a
  long *sticky* cooldown (30 min) rather than waiting for a trip threshold, it does
  **not** set a permanent `dead` flag, so it is still recoverable: a successful active
  probe (or organic half-open probe) brings it back. An **auth** hard-down also relays the
  error to the caller; a **billing** hard-down fails the request over to another
  member.

## Active health probing

Passive health alone only learns a lane is sick when real traffic hits it, and only
recovers it on the next organic request. Active probing (per-provider `health:`
config) adds a background prober:

| Mode | Behavior |
|---|---|
| `none` (default) | No probing; pure passive health. |
| `dead` | Periodically re-probe **only tripped** lanes, so a recovered upstream is picked back up promptly. |
| `active` | Periodically probe **every** lane, so a silently-dead upstream trips out before real traffic hits it. Sends a tiny billable one-token request per interval. |

Each probing lane gets one background task. `interval_secs` (default 30) and
`timeout_secs` (default 5) are honored (floored at 1s). The first tick is skipped so
Busbar doesn't probe before any traffic establishes health. A lane with no key is
skipped (a guaranteed 401 would only thrash the breaker). A 2xx probe recovers a
tripped lane to Closed and increments the lane's `ok` counter by one; a failed probe records a
transient (which, on a Closed lane in `active` mode, can trip it out).

## Failover & exhaustion

For a single request, Busbar will retry across pool members up to the failover
`max_hops` (default 3) and within the `timeout_secs` budget (default 120). Failover is
allowed **only before the first upstream byte reaches the client**: once streaming
has started, a failure cannot fail over (the client holds a partial response); the
lane records the breaker fault and the stream terminates with an SSE `error` event,
and the client must retry.

When all members are unusable, the pool's `on_exhausted` action decides:

- `reject` / `status_503` (default): `503` with `Retry-After` — the soonest genuine
  member cooldown, or a small saturation floor when exhaustion is pure at-capacity
  (not the misleading `1`).
- `least_bad`, serve the soonest-cooldown member that still has a free permit
  (skipping a saturated one), degraded and logged loudly.
- `{ fallback_pool: <name> }`, route to another pool (loop-guarded).

If `outcome="exhausted"` (503) is climbing in `busbar_requests_total`, check
`/stats` for dead/tripped lanes and consider a `fallback_pool` or `least_bad` policy
for graceful degradation.

## Governance & the admin API

Data-plane callers authenticate with **signed, expiring virtual keys** (the built-in `keys`
verifier in `auth.chain`). Keys are managed over the admin API on the separate `admin_listen`,
guarded by `auth.admin_auth` (the built-in `admin-tokens` operator credential, sent as
`Authorization: Bearer <admin_token>` or `X-Admin-Token: <admin_token>`, or an IdP role with
`admin_scope`).

Minting, listing, rotating, and revoking keys — the routes, request/response shapes, the mint-body
field reference, and the scope lattice — are owned by the **[Admin API reference](/docs/admin-api/)**.
The limit/group model those keys charge through is owned by
**[Configuration → Virtual keys and enforcement](/docs/configuration/#virtual-keys-and-enforcement)**.
This guide stays on the operational picture. In brief: `POST /api/v1/admin/keys` mints a key and
returns the signed token **once**; a key is pure auth (every limit lives on the bound `group`), it
EXPIRES (default 90 days — re-mint or rotate before then), and `DELETE` puts its subject on the
durable revocation denylist immediately.

### Enforcement model

- **Verification is stateless**: signature + expiry + the revocation denylist; policy (group,
  pools) resolves from the store by the token's subject, so a PATCH takes effect without
  re-issuing the credential.
- **Admission walks the bound group's chain** and ANDs every limit of every group: `requests`
  (precise, `429` + `Retry-After`), `tokens` (best-effort post-paid, `429` + `Retry-After`),
  `budget` (derived spend, the vendor-native quota status with `error.type:
  insufficient_quota`; Bedrock signals over-budget as `400`), `concurrent` (in-flight gauge,
  `429`). The rejection names the exact blocking bucket (group + metric + window). A frozen
  group (`enabled: false`) rejects with `403`.
- **Spend derives from the TOKEN LEDGER**: a flat `per_request_fee` is charged (as +1 request)
  atomically pre-forward, and the response's per-(model, tier) token split is ledgered at
  stream end. Spend = requests x fee + tokens x `rate_card` rates, recomputed on every check;
  with no rate card, tokens price at 0 and only the flat fee counts.
- **Ledgers default to in-memory** (ephemeral); configure a durable store plugin
  (`store: { module: sqlite|postgres|redis, settings: {...} }`) to persist keys, usage, and
  the denylist across restarts.

> Limit windows are per-process, and the caps are enforced per node even over a shared store
> (see the fleet caveat above).

## Troubleshooting

| Symptom | Where to look |
|---|---|
| `503` on every request | `/stats`, are all lanes `dead` or in cooldown? Check `dead_reason`. |
| A lane stuck `dead` with `billing` reason | Upstream wallet/quota; the lane recovers on a successful probe once funded. Consider `health.mode: dead`. |
| A lane stuck `dead` with `auth` reason | Wrong/expired credential behind the provider's `api_key` reference. |
| A few `401`s from a Vertex AI or Azure (Entra ID) lane right after startup | The lane's first OAuth token is still minting. `jwt-bearer` / `oauth-client-credentials` lanes fetch an access token in the background at boot (and on every reload); for up to ~1s before it lands, the earliest calls return `401`. Clears itself within a second, no action needed. Static-key lanes (`bearer` / `api-key` / SigV4) never have this window. |
| `429` from Busbar itself | A group limit blocked. The body's `error.type` distinguishes the cause: `rate_limit_error` = requests/tokens/concurrent limit (the message names group + metric + window); `insufficient_quota` = a budget limit (Bedrock ingress signals over-budget as `400` instead). Check `GET /api/v1/admin/keys/{id}/usage`. |
| `403` from Busbar | The virtual key's `allowed_pools` doesn't include the target. |
| Startup panic: "unset environment variable" | A `${VAR}` (possibly in a comment) isn't exported. |
| Startup panic: "not found in providers.yaml" | A `config.yaml` provider name isn't in the catalog. |
| Cross-protocol responses missing fields | Expected, only the modeled IR subset survives a cross-protocol hop; same-protocol routes are lossless. |
| High `busbar_failovers_total` for one lane | That backend is flapping; inspect its `busbar_upstream_failures_total` `disposition`. |
