# Operations

Running Busbar in production: process configuration, health/readiness, the metrics
to watch, circuit-breaker and health-probe behavior, failover/exhaustion outcomes,
governance/admin usage, and troubleshooting.

## Process configuration

Busbar is a single native binary configured by two YAML files and environment
variables.

| Env var | Default | Purpose |
|---|---|---|
| `BUSBAR_CONFIG` | `/etc/busbar/config.yaml` | Path to the deployment config. **The one bootstrap env var**: it locates config.yaml itself. |
| Provider key vars | n/a | Named by each provider's `api_key: { env: ... }` reference (e.g. `ANTHROPIC_KEY`). |
| Token/secret vars | n/a | Anything referenced via `${VAR}` in either file (client tokens, admin token, …). |

**Operational config moved into `config.yaml` (1.5.3).** Several knobs that used to be env vars now
live in config.yaml, so they are reviewable, `--validate`-checked, and part of the deployment artifact.
The old env vars **still work for one release** (each logs a deprecation warning) but are the migration
path, not the home:

| Deprecated env var | New config.yaml key |
|---|---|
| `BUSBAR_PROVIDERS` | `providers_file:` (top-level; default `providers.yaml` next to config.yaml) |
| `BUSBAR_CONFIG_OVERLAY` | `config.overlay.file` (see [config mutability](#config-mutability-locked--overlay)) |
| `BUSBAR_WORKER_THREADS` | `advanced.worker_threads` |
| `BUSBAR_UPSTREAM_HTTP1_ONLY` | `advanced.upstream_http1_only` |
| `BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE` | `advanced.upstream_h2_prior_knowledge` |

`TOKIO_WORKER_THREADS` is still honored as a fallback for `advanced.worker_threads`.

### Config mutability (`locked` + `overlay`)

The top-level `config:` block governs whether the admin API may change config at runtime and where those
changes persist. **Durable by default:** with nothing specified, config is *mutable* and admin-API
mutations persist to `busbar-overlay.json` next to config.yaml. A group or hook provisioned over the
admin API therefore **survives a restart** out of the box.

```yaml
config:
  locked: false                 # false = mutable (admin API may change config); true = immutable
  overlay:
    file: busbar-overlay.json    # where mutations persist; default = next to config.yaml
```

- **`locked: true`** is an immutable/GitOps deployment: admin-API config mutations are *refused* at
  runtime (edit config.yaml and `POST /config/reload` instead). The overlay is ignored.
- **Boot invariant: `locked` XOR a writable overlay.** A *mutable* config with **no writable overlay**
  (you set `overlay: false`, or the config directory is read-only) **refuses to boot**, with a message
  telling you to either point `config.overlay.file` at a writable path or set `config.locked: true`.
  This makes "applied but silently lost on restart" impossible to reach.
  - **Read-only config dir (e.g. `/etc/busbar` on a read-only mount):** the default overlay path is
    unwritable, so an unconfigured mutable busbar refuses to boot. Fix: set a writable
    `config.overlay.file`, or set `config.locked: true` (a read-only/GitOps deployment never persists
    runtime mutations anyway). See the [upgrade note](migration-1.5.md#153-config-consolidation).

**Worker threads and scaling.** Busbar's request path is CPU-bound (parse, translate, serialize), so
throughput scales with worker threads. The default is **one worker per available core**
(`available_parallelism`, which respects CPU affinity and the cgroup **cpuset**, but **not** the CFS
`cpu.max` bandwidth quota, which it cannot see), which gives linear scaling: ~9,750 req/s per core,
sub-millisecond, to ~156k on 16 cores in our [benchmark](https://getbusbar.com/performance). Each worker
carries a thread stack and, on glibc, its own malloc arena, so idle memory grows slowly with the count. For
a **footprint-sensitive sidecar** set `advanced.worker_threads: 1` (or `2`). On a **CPU-quota-limited pod** (a
k8s CPU *limit* on a many-core node) the default sizes to the node's full core count and oversubscribes the
quota: **set `advanced.worker_threads` to your CPU limit**; likewise to cap a shared box, set it to the cores
you want Busbar to use. Scale up by default, tune down deliberately. *(Before 1.4.0 the default was capped
at `min(cores, 4)`, which pinned throughput to ~4 cores regardless of box size, set the value explicitly on
older binaries.)*

Startup is fail-loud: an unset `${VAR}`, an unknown provider reference, an unknown
protocol or auth mode, or an invalid `on_exhausted` action stops the process with a
diagnostic. A provider whose key env var is empty logs a warning and runs (its lane
will fail auth on first use). `auth.chain: []` prints a loud open-relay warning.

The HTTP client uses a 300s request timeout and pools up to 1024 idle keep-alive connections per upstream host.

### Validating configuration (`busbar --validate`)

`busbar --validate` runs the exact load → resolve → validate pipeline the gateway runs at boot,
then exits, **without** starting the server. It binds no port, writes nothing to disk, spawns no
tasks, and makes no network call, so it is safe to run anywhere, including in CI and against a config
edited on a live host before you reload it. It does read the files your `file:` secret references
name, because since 1.5.3 it resolves those references rather than only checking their shape.

```sh
BUSBAR_CONFIG=./config.yaml BUSBAR_PROVIDERS=./providers.yaml busbar --validate
# ok: config valid [...] 2 provider(s), 2 model(s), 1 pool(s)
#   note: 1 env var(s) referenced but unset here [...] required at runtime: BUSBAR_CLIENT_TOKEN
```

Two different mechanisms read the environment, and `--validate` treats them differently. Read both of
the middle bullets before you wire this into CI.

- **Exit `0`** = valid; **`1`** = errors (same diagnostics boot prints: invalid YAML, removed keys,
  dangling pool/lane references, malformed auth chains, cert-file and `base_url`/`path` SSRF violations).
  Use it as a CI gate: `busbar --validate && deploy`.
- **`${VAR}` interpolation is lenient, and needs no value.** A `${VAR}` token anywhere in
  `config.yaml` that is unset in your shell is reported in a `note:` ("required at runtime") rather
  than failing. (At real boot an unset `${VAR}` is still a hard error.)
- **`env:` and `file:` secret REFERENCES are resolved, and one that cannot resolve fails the run.**
  A secret reference is the `{ env: VAR }` / `{ file: /path }` form on `providers.*.api_key`,
  `tls.cert` / `tls.key` / `tls.client_ca` (and the `admin_tls` equivalents), `auth.signing_key`, and
  the `admin-tokens` token. Since 1.5.3 `--validate` reads each one and exits `1` naming the first
  that fails, where it previously checked only the shape and exited `0`. So a CI job needs the same
  variables and files the deployment has, or a config whose references resolve in that environment.
  A reference served by a secret PLUGIN is not resolved here, since the plugin may not be loadable.
  Boot is unchanged: an unresolvable reference logs a warning and Busbar serves, with every request
  to that provider failing upstream. It checks *structure* and secret resolution, never upstream
  reachability.
- Honors `BUSBAR_CONFIG`, `BUSBAR_PROVIDERS`, and `--safe-mode` exactly as boot does. Because it reuses
  the boot path, a clean `--validate` means a clean boot.

### Inspecting the SSRF denylist (`busbar --print-metadata-blocklist`)

Provider `base_url` values are checked against a cloud-metadata denylist, so a compromised or
mistyped config cannot turn Busbar into a reader of your instance credentials. The list the running
binary actually enforces is the built-in set plus whatever you added under
`security.blocked_metadata_hosts`, which means it is not something you can read off the config file
alone. This flag prints it, one entry per line, and exits `0`:

```sh
BUSBAR_CONFIG=./config.yaml busbar --print-metadata-blocklist
```

- The built-in set always prints, so the flag works before a deployment is wired up.
- Your `security.blocked_metadata_hosts` entries are appended when `BUSBAR_CONFIG` points at a config
  that reads and parses. If it does not, the flag prints the built-in set alone and says so on stderr
  rather than handing you a silently incomplete list. Run Busbar normally to see the parse error.
- It does NOT subtract the allow-overrides. `security.allow_metadata_hosts`, a provider's own
  `allow_metadata_hosts`, and `allow_all_metadata` still win at request time, so a host printed here
  can still be reachable if you unblocked it. See
  [the configuration reference](configuration.md#security) for how the two sides combine.

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

Certs are loaded once at startup, so rotation always needs a restart. It does not, however, need a
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
`reload_to_apply`, which is restart-scoped, per the [`PUT /config/settings`](/docs/admin-api/#the-config-plane)
table. `POST /restart` then applies it: it drains through the same graceful-shutdown path a signal
takes (in-flight requests finish first), which is exactly why a restart on rotation is safe under
live traffic. That is the same guarantee this section always relied on, now reachable without
shelling in.
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
| `GET /metrics` | virtual key | Prometheus exposition. OPT-IN: mounted only when an `export:` instance with `module: prometheus` is configured (with its required `settings.buffer_seconds`); otherwise the path 404s like any other. Requires a valid key with a non-empty `auth.chain`, open under `chain: []`. Restrict at the network layer if unauthenticated scraping is needed. |
| `GET /stats` | virtual key | Per-lane health snapshot + pool membership, JSON. |

`/stats` returns, per lane: `model`, `provider`, `max_concurrent`, `limit` (alias of
`max_concurrent`), `inflight`, `free_slots`, `available` (free permits for a bounded lane,
or `"unbounded"`), `at_capacity` (`true` when a bounded lane is at its `max_concurrent`
limit and is therefore shedding/spilling rather than queueing), `availability`,
`recovery_hint_ms`, `breaker_state`, `ok`, `err`, `usable`, `dead`, `dead_reason`,
`cooldown_remaining_s`, `streak`, and `budget`. It is the first place to look when a pool
is degraded.

`availability` renders the shared `classify` taxonomy, the same one routing dispatches on,
so `/stats` cannot drift from behaviour. It is `"available"` when the lane would admit a
request, or the reason it can't: `"breaker_open"`, `"at_capacity"`, `"dead"`,
`"budget_exhausted"`, `"probe_in_flight"`, or `"shedding"`. `recovery_hint_ms` is the honest
lower bound (ms) on when that lane could next serve (`null` when available or the reason has
no self-recovery, e.g. dead/budget). The breaker (`breaker_state`: `"closed"`/`"open"`/
`"half_open"`) and capacity (`at_capacity`) axes are exposed INDEPENDENTLY: a saturated Open
lane shows `breaker_state: "open"` AND `at_capacity: true`, so you can see why such a lane's
breaker never recovers (its recovery probe needs a dispatch it can never win), rather than the
signal being collapsed into one string.

## Running multiple instances (HA)

Busbar is **stateless** (apart from governance ledgers, see below), so the robust
production shape is **N instances behind a load balancer**, each configured
identically, each health-checked on `GET /healthz`. Any instance serves any request;
lose one and the LB routes around it. On Kubernetes this is `replicaCount` + the
Service/Ingress + a PodDisruptionBudget; on VMs it is N hosts behind an external LB
(nginx, HAProxy, or a cloud L4/L7 balancer) probing `/healthz`.

Three things are worth understanding before you scale out:

- **Circuit-breaker and target health are per-instance.** Each instance learns
  upstream health independently from its own traffic, on every plane: lanes, tool
  servers and agents alike. This is correct (a target that's dead for one instance is
  usually dead for all) and a new instance re-learns within seconds. Nothing is
  shared or needs sharing.
- **Session affinity is per-instance.** The `affinity` header pins a session to a lane
  *within one instance*. Across instances, an LB that spreads a client's requests will
  spread its affinity too. If you depend on affinity, enable **sticky sessions** at the
  LB (e.g. by the affinity header / a cookie) so a session lands on the same instance.
- **Governance state defaults to per-instance memory; enforcement is per-node either
  way.** The default `store: memory` is ephemeral RAM per instance. A cluster-shared
  store (postgres/valkey) genuinely shares keys and the token ledger across N nodes (but
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
  continuing to audit to its in-memory ring (ephemeral) rather than corrupting
  the shared log. Point at most one node at a durable audit store; `GET /audit` is
  per-instance either way (it serves that node's in-memory ring, never the store).
- **The signing key (`auth.signing_key`) must be the SAME secret on every node.**
  It is fleet-shared: every node verifying the same virtual-key tokens must resolve
  the same ed25519 signing key. A token minted on one instance fails verification on
  another if they disagree, so point every node's `auth.signing_key` at the identical
  secret reference (never let each instance generate or resolve its own).

So: for a gateway without group limits, scale out freely behind an LB. With limits,
either accept the per-node cap semantics over a shared store, or keep enforcement on
one instance and scale the box, not the count.

## Metrics to watch

All metrics are Prometheus counters/histograms exposed at `/metrics`, which is opt-in: with no `module: prometheus` instance under `export:` busbar records nothing and does not mount the endpoint. Its `settings.buffer_seconds` (required when you opt in) sets how many seconds of observations are retained. Quantiles cover that window, `_sum`/`_count` stay cumulative, and memory is bounded by the window rather than by uptime.

| Metric | Type | Labels | Watch for |
|---|---|---|---|
| `busbar_requests_total` | counter | `ingress_protocol`, `pool`, `outcome` | Model (LLM) plane only, unchanged from 1.5.4 (no `plane` label). `outcome` is `ok` / `client_error` / `exhausted` (503) / `error`. A rising `exhausted` means pools are running out of healthy members. |
| `busbar_plane_requests_total` | counter | `plane`, `ingress_protocol`, `pool`, `outcome` | Mounted planes: `plane` is `mcp` / `a2a`, so `sum by (plane) (rate(busbar_plane_requests_total[5m]))` splits the mounted-plane traffic. Same `outcome` vocabulary as `busbar_requests_total`. |
| `busbar_upstream_attempts_total` | counter | `pool`, `lane` | Real upstream calls (re-counted per failover hop). |
| `busbar_upstream_failures_total` | counter | `pool`, `lane`, `disposition` | `disposition` is `transient_upstream` / `attempt_timeout` / `hard_down` / `context_length`. Concentration on one lane points at a sick backend. |
| `busbar_breaker_trips_total` | counter | `pool`, `lane` | Each hard-down/trip. Spikes = a backend going down. |
| `busbar_failovers_total` | counter | `pool`, `reason` | `reason` is `timeout` / `connect` / `transient_upstream` / `attempt_timeout` / `hard_down` / `context_length`. |
| `busbar_translations_total` | counter | `from`, `to` | Cross-protocol translation hops. |
| `busbar_request_duration_seconds` | histogram | `ingress_protocol`, `pool` | Model (LLM) plane only, unchanged from 1.5.4. End-to-end latency. |
| `busbar_plane_request_duration_seconds` | histogram | `plane`, `ingress_protocol`, `pool` | Mounted planes (`mcp` / `a2a`). End-to-end latency for tool calls and agent tasks. |
| `busbar_key_spend_cents` | gauge | `key` (+ mint labels) | Per-virtual-key derived spend in cents (all-time attribution bucket; spend derives from the token ledger x the current rate card at scrape time). |
| `busbar_key_tokens_total` | gauge | `key` (+ mint labels) | Tokens consumed by each virtual key (all-time attribution bucket). |
| `busbar_bucket_spend_cents` | gauge | `bucket`, `group`, `window` | Derived spend per (group, window) enforcement bucket (`bucket` = `group:<name>@<window>`). |
| `busbar_bucket_budget_remaining_cents` | gauge | `bucket`, `group`, `window` | Budget cap minus derived spend, only for buckets carrying a `budget` limit. Enables Prometheus burn-rate alerting per group. |
| `busbar_bucket_tokens` | gauge | `bucket`, `group`, `window`, `model`, `tier` | Per-(bucket, model, tier) token counters (the raw material for external cost dashboards). |
| `busbar_lane_state` | gauge | `pool`, `lane` | Circuit-breaker health per lane (the independent breaker axis): `0` = Closed, `1` = HalfOpen, `2` = Open (tripped). Side-effect-free at scrape. |
| `busbar_lane_available` | gauge | `pool`, `lane` | Unified availability from the shared `classify` taxonomy (the same one routing dispatches on): `1` = the lane would admit a request right now, `0` = unavailable for ANY reason (breaker Open, at-capacity, dead, budget, probe-in-flight). Pair with `busbar_lane_state` (breaker) and `busbar_lane_available_permits` (capacity) to see which axis is the cause. Replaces the former `busbar_lane_at_capacity`. Side-effect-free. |
| `busbar_lane_recovery_hint_ms` | gauge | `pool`, `lane` | Honest lower bound (ms) on when an unavailable lane could next serve, from the same `recovery_hint_ms` that feeds `Retry-After`: breaker `until` for an Open lane, the at-capacity floor (2000ms) for a saturated one. `0` when available or the reason has no self-recovery (dead/budget). Side-effect-free. |
| `busbar_lane_inflight` | gauge | `pool`, `lane` | In-flight requests (held concurrency permits) per lane, the depth companion to `busbar_lane_available`. Side-effect-free. |
| `busbar_lane_available_permits` | gauge | `pool`, `lane` | Free concurrency permits for a bounded lane (`0` = saturated), the independent capacity axis. Unbounded lanes emit no sample. Side-effect-free. |
| `busbar_pool_queued` | gauge | `pool` | Requests currently parked in the `on_exhausted: queue` bounded wait, per pool. Reads `0` until the queue policy is wired. Side-effect-free. |
| `busbar_route_policy_selections_total` | counter | `pool`, `policy` | Requests where a selection strategy (a native strategy or a gate hook) produced a usable ranked order. Only incremented on a successful `Order` outcome; abstains and on-error fallbacks are not counted. |
| `busbar_route_policy_rejections_total` | counter | `pool`, `policy`, `status` | Requests deliberately rejected by a routing hook's `reject` verb (a 4xx to the caller, no upstream dispatched). A guardrail saying no, not a failure. |
| `busbar_webhook_logs_dropped_total` | counter | n/a | Request-log webhook deliveries shed because the in-flight delivery pool was saturated (a slow/unreachable webhook endpoint). A non-zero rate means request logs are being silently dropped, scale the endpoint or alert. |
| `busbar_file_logs_dropped_total` | counter | n/a | Request-log file appends shed because that sink's in-flight append pool was saturated (a slow/stalled filesystem: full disk, hung NFS/EBS mount). A non-zero rate means request-log lines are being dropped, check the mount or alert. |
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

The breaker is keyed on the **target** about to be called, and it runs on all three
planes: a pool member (LLM), a registered tool server (MCP), a registered agent
(A2A). The subsections below describe the LLM plane, whose vocabulary is pools and
lanes; [across the planes](#the-breaker-across-the-planes) covers what changes and
what does not on the other two, and [MCP](/docs/mcp/) and [A2A](/docs/a2a/) carry
each plane's full operator reference, including the exact wire shape a tripped
target answers with.

Breaker state is **per-(pool, lane)**: a lane that is a member of more than one pool
carries independent Open/Closed/HalfOpen state, streak, cooldown, and error window in
each pool, so one pool's traffic tripping a lane does not bench it for the others.
Direct/ad-hoc routes (`POST /{provider}/{model}`, `POST /{model}`) and `/stats` share a
single lane-default cell. The concurrency limit and the `max_requests` lifetime budget
are **not** per-pool, they cap the shared upstream, so they apply across every pool.
A successful active health probe (it tests the shared upstream) clears the breaker in
*every* cell for the lane.

### States

The canonical Closed/Open/HalfOpen transition graph (the FSM itself) lives on
[circuit-breaker.md](circuit-breaker.md#states), the source of truth. What an operator watching
`/stats` and `/metrics` sees is not that graph but **two independent axes**: the breaker state and
the lane's spare capacity, each exposed as its own field and never collapsed into one. The matrix
below reads them together, so a saturated Open lane shows up as **both** open **and** at capacity.

<svg viewBox="0 0 720 470" role="img" aria-label="Observability matrix for a lane. Columns are the breaker axis, the busbar_lane_state gauge: 0 Closed, 1 HalfOpen, 2 Open. Rows are the capacity axis, at_capacity and busbar_lane_available_permits: top row at_capacity false with free permits, bottom row at_capacity true with zero permits. The two axes are exposed independently, so each of the six cells reports a breaker value and a capacity value at once. The bottom-right cell, lane_state 2 and at_capacity true, shows a saturated Open lane reading both open and at capacity, whose recovery probe can never win a dispatch. Each cell also emits busbar_lane_recovery_hint_ms: 0 when serving, the breaker cooldown for an Open lane, a 2000ms floor for a saturated one." style="width:100%;height:auto;max-width:720px;font-family:ui-sans-serif,system-ui,sans-serif;">
  <rect x="0" y="0" width="720" height="470" fill="#111a2e"/>

  <!-- Title -->
  <text x="360" y="30" text-anchor="middle" fill="#e6edf7" font-size="16" font-weight="700">What an operator sees: two independent axes</text>
  <text x="360" y="52" text-anchor="middle" fill="#94a3b8" font-size="12">breaker state and lane capacity are exposed separately, never collapsed into one signal</text>

  <!-- Top axis label (breaker) -->
  <text x="425" y="82" text-anchor="middle" fill="#94a3b8" font-size="11" font-weight="600">busbar_lane_state gauge (breaker axis) / stats: breaker_state</text>

  <!-- Column headers: lane_state 0 / 1 / 2 -->
  <rect x="170" y="90" width="160" height="48" rx="8" fill="#16210b" stroke="#a3e635" stroke-opacity="0.5"/>
  <text x="250" y="110" text-anchor="middle" fill="#94a3b8" font-size="11">lane_state 0</text>
  <text x="250" y="128" text-anchor="middle" fill="#bef264" font-size="14" font-weight="700">Closed</text>

  <rect x="350" y="90" width="160" height="48" rx="8" fill="#2a2410" stroke="#fbbf24" stroke-opacity="0.55"/>
  <text x="430" y="110" text-anchor="middle" fill="#94a3b8" font-size="11">lane_state 1</text>
  <text x="430" y="128" text-anchor="middle" fill="#fcd34d" font-size="14" font-weight="700">HalfOpen</text>

  <rect x="530" y="90" width="160" height="48" rx="8" fill="#2a1416" stroke="#f87171" stroke-opacity="0.55"/>
  <text x="610" y="110" text-anchor="middle" fill="#94a3b8" font-size="11">lane_state 2</text>
  <text x="610" y="128" text-anchor="middle" fill="#fca5a5" font-size="14" font-weight="700">Open</text>

  <!-- Left axis label (capacity), rotated -->
  <text x="16" y="312" text-anchor="middle" fill="#94a3b8" font-size="11" font-weight="600" transform="rotate(-90 16 312)">at_capacity / busbar_lane_available_permits (capacity axis)</text>

  <!-- Row header: at_capacity false -->
  <rect x="34" y="152" width="130" height="120" rx="8" fill="#16210b" stroke="#a3e635" stroke-opacity="0.5"/>
  <text x="99" y="200" text-anchor="middle" fill="#94a3b8" font-size="11">at_capacity</text>
  <text x="99" y="218" text-anchor="middle" fill="#bef264" font-size="14" font-weight="700">false</text>
  <text x="99" y="240" text-anchor="middle" fill="#94a3b8" font-size="10">permits available</text>

  <!-- Row header: at_capacity true -->
  <rect x="34" y="282" width="130" height="120" rx="8" fill="#2a1416" stroke="#f87171" stroke-opacity="0.55"/>
  <text x="99" y="330" text-anchor="middle" fill="#94a3b8" font-size="11">at_capacity</text>
  <text x="99" y="348" text-anchor="middle" fill="#fca5a5" font-size="14" font-weight="700">true</text>
  <text x="99" y="370" text-anchor="middle" fill="#94a3b8" font-size="10">0 permits, shedding</text>

  <!-- Row 1 cells: at_capacity false -->
  <rect x="170" y="152" width="160" height="120" rx="8" fill="#1a2740" stroke="#2c3a52"/>
  <text x="250" y="196" text-anchor="middle" fill="#e6edf7" font-size="12" font-weight="600">Serving</text>
  <text x="250" y="216" text-anchor="middle" fill="#94a3b8" font-size="10">would admit a request</text>
  <text x="250" y="252" text-anchor="middle" fill="#94a3b8" font-size="10">recovery_hint_ms: 0</text>

  <rect x="350" y="152" width="160" height="120" rx="8" fill="#1a2740" stroke="#2c3a52"/>
  <text x="430" y="196" text-anchor="middle" fill="#e6edf7" font-size="12" font-weight="600">Probe in flight</text>
  <text x="430" y="216" text-anchor="middle" fill="#94a3b8" font-size="10">single-flight recovery</text>
  <text x="430" y="252" text-anchor="middle" fill="#94a3b8" font-size="10">recovery_hint_ms: probe wait</text>

  <rect x="530" y="152" width="160" height="120" rx="8" fill="#1a2740" stroke="#2c3a52"/>
  <text x="610" y="196" text-anchor="middle" fill="#e6edf7" font-size="12" font-weight="600">Tripped, cooling</text>
  <text x="610" y="216" text-anchor="middle" fill="#94a3b8" font-size="10">skipped in selection</text>
  <text x="610" y="252" text-anchor="middle" fill="#94a3b8" font-size="10">recovery_hint_ms: breaker until</text>

  <!-- Row 2 cells: at_capacity true -->
  <rect x="170" y="282" width="160" height="120" rx="8" fill="#1a2740" stroke="#2c3a52"/>
  <text x="250" y="326" text-anchor="middle" fill="#e6edf7" font-size="12" font-weight="600">Healthy but full</text>
  <text x="250" y="346" text-anchor="middle" fill="#94a3b8" font-size="10">breaker fine, sheds now</text>
  <text x="250" y="382" text-anchor="middle" fill="#94a3b8" font-size="10">recovery_hint_ms: 2000 floor</text>

  <rect x="350" y="282" width="160" height="120" rx="8" fill="#1a2740" stroke="#2c3a52"/>
  <text x="430" y="326" text-anchor="middle" fill="#e6edf7" font-size="12" font-weight="600">Recovering, full</text>
  <text x="430" y="346" text-anchor="middle" fill="#94a3b8" font-size="10">probe or spill</text>
  <text x="430" y="382" text-anchor="middle" fill="#94a3b8" font-size="10">recovery_hint_ms: 2000 floor</text>

  <rect x="530" y="282" width="160" height="120" rx="8" fill="#20090c" stroke="#f87171" stroke-opacity="0.7" stroke-width="2"/>
  <text x="610" y="322" text-anchor="middle" fill="#fca5a5" font-size="12" font-weight="700">Open AND at_capacity</text>
  <text x="610" y="342" text-anchor="middle" fill="#94a3b8" font-size="10">both axes fire at once</text>
  <text x="610" y="360" text-anchor="middle" fill="#94a3b8" font-size="10">probe cannot win a slot</text>
  <text x="610" y="384" text-anchor="middle" fill="#94a3b8" font-size="10">recovery_hint_ms: breaker until</text>

  <!-- Footer legend -->
  <text x="360" y="440" text-anchor="middle" fill="#94a3b8" font-size="11">Read the column and the row together: each lane reports its breaker value and its capacity value independently.</text>
  <text x="360" y="458" text-anchor="middle" fill="#94a3b8" font-size="10">/metrics: busbar_lane_state, busbar_lane_available_permits, busbar_lane_recovery_hint_ms   /   /stats: breaker_state, at_capacity, available, recovery_hint_ms</text>
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

### The breaker across the planes

There is one place to configure it: `pools.<pool>.breaker:`. There is no `breaker:`
key under `tools:` or `agents:` (an earlier version of this page said there was, and a
config written against it fails at boot, because both sections reject unknown keys).
Omit the block and you get the defaults. On the MCP and A2A planes the breaker runs on
those defaults through the shared selection seam, and **that seam is wired into the
tool-dispatch, the agent-submission and the agent-relay call sites**, so it fires on
live calls: a tripped target fast-fails, and a target an operator put in a
`tool_pools:`/`agent_pools:` set is rerouted to a verified twin before the first byte.
Full detail, with worked YAML, is in
[circuit-breaker.md](circuit-breaker.md#the-breaker-on-the-mcp-and-a2a-planes).

**Why an operator cares.** With no breaker on a plane, an upstream that is hard down
(revoked auth, lapsed billing) does not fail fast: every call pays the full request
timeout, holds a concurrency slot while it does, and retries pile onto a server that
is already in trouble. Worse, nothing says so. The first report comes from a user.
With the breaker, the target trips, subsequent calls are refused immediately, and the
trip is a signal that names the server or the agent and the cause.

**Failover on MCP and A2A is opt-in and operator-declared, and it is declared as a pool
rather than a per-registration key.** A tool is namespaced to the server that exports it
and an A2A task is addressed to a specific agent, so busbar will never guess at a
substitute: you name the twins yourself, in a top-level `tool_pools:` or `agent_pools:`
map, and busbar then verifies that claim against the fingerprints it already computed —
the approved tool schema digest on MCP, the approved canonical card fingerprint on A2A —
before it moves anything. Members whose pins disagree are refused with both fingerprints
named, not defaulted. `failover:` is still not accepted under `tools:` or `agents:`; the
two pool sections are the whole vocabulary, and an absent section is exactly the old
behaviour. Given a pool, a `tools/call` to a server whose primary is tripped, or that
cannot be connected to at all, is rerouted to its verified twin **before the first
byte**, and a fresh A2A submission to a pooled agent is walked the same way at
admission.

**What stays deliberately narrower than the LLM plane** is everything after a dispatch
has gone out. Once a call has left Busbar, moving it repeats work the upstream may
already have done, so only operations the operator has written into `repeatable:` are
repeated — there is no `repeatable: all` and no switch that disables the rule. And an
**accepted A2A task is pinned to the member that accepted it**: if that member's
breaker is Open, the task-scoped verb is refused (`503` with `Retry-After`, and the
task row is *not* ended) rather than silently re-dispatched to a twin. Failover on
these planes is an admission-time choice, never a mid-flight migration. For a single
registration with no pool, unchanged: what the breaker gives is failing *fast* instead
of *slowly*, plus the signal.

**What a caller sees when a target is Open:**

- **MCP**: `503` with `Retry-After` set from the breaker's cooldown expiry, and a
  JSON-RPC error carrying `reason`, `server` and `retry_after_ms`. It is an error,
  **not** a tool result with `isError: true`: the call never happened, and telling a
  model otherwise makes it reason from a false premise.
- **A2A**: the task is **`rejected`** (not `failed`) and comes back with a task id,
  so the calling agent, not Busbar, decides whether to retry.

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

- `reject` / `status_503` (default): `503` with a `Retry-After` set to the soonest genuine
  member cooldown, or to a small saturation floor when exhaustion is pure at-capacity
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

Minting, listing, rotating, and revoking keys (the routes, request/response shapes, the mint-body
field reference, and the scope lattice) are owned by the **[Admin API reference](/docs/admin-api/)**.
The limit/group model those keys charge through is owned by
**[Configuration → Virtual keys and enforcement](/docs/configuration/#virtual-keys-and-enforcement)**.
This guide stays on the operational picture. In brief: `POST /api/v1/admin/keys` mints a key and
returns the signed token **once**; a key is pure auth (every limit lives on the bound `group`), it
EXPIRES (default 90 days, so re-mint or rotate before then), and `DELETE` puts its subject on the
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
  (`store: { module: sqlite|postgres|valkey, settings: {...} }`) to persist keys, usage, and
  the denylist across restarts.

> Limit windows are per-process, and the caps are enforced per node even over a shared store
> (see the fleet caveat above).

## Running on Windows

`x86_64-pc-windows-msvc` is a published release target (`busbar-x86_64-pc-windows-msvc.zip`), and
CI builds, lints and tests the workspace on `windows-latest`. Busbar runs there. Four behaviours
nevertheless **differ from unix**, and each one is a property an operator may have read as
cross-platform. They are listed here rather than left to be discovered, because in every case the
unix documentation states a guarantee that Windows does not carry.

| Area | On unix | On Windows |
|---|---|---|
| **Secret files** (config overlay, signing key) | Created `0600` at open — never briefly world-readable | **No mode bits.** The file inherits the ACL of the directory holding it. The overlay can carry credentials verbatim (e.g. a `postgres://user:pass@host/db` in `store.settings.url`), so its confidentiality is exactly the ACL you set on the config directory. **Set that ACL yourself; nothing in busbar narrows it.** |
| **Plugin staging** (`docs/plugins.md`) | Per-process staging dir `0700`, file `0600`; boot sweep removes staging left by a crashed prior process | Directory and file inherit the `%TEMP%` ACL — per-user in a default setup, but not the `0700` guarantee. The **boot sweep is a no-op**: it decides "is the prior pid dead" with `kill(pid, 0)`, which has no Windows implementation, so an abandoned staging directory accumulates per crash under `%TEMP%`. This costs disk, not integrity — a staged file is regenerated from the verified in-memory bytes on every load and is never trusted input. |
| **Durable write** (`fsync` of the holding directory after a rename) | The directory entry is fsynced, so a publish survives power loss | **Not performed** — a directory cannot be opened for `fsync` on Windows and `FlushFileBuffers` on a directory handle is not the same barrier. File CONTENTS are still fsynced before the rename on every platform, so a power loss can lose the *rename* (old file, or no file) but never yields a torn one. |
| **Orderly shutdown** | `SIGINT` and `SIGTERM` both drain in-flight requests | `SIGTERM` does not exist. Busbar handles `CTRL_C`, `CTRL_CLOSE` and `CTRL_SHUTDOWN`, which covers an interactive Ctrl+C, a closing console, `docker stop` on a Windows container, and machine shutdown. A `TerminateProcess` (Task Manager "End task", `taskkill /F`) is not interceptable by any process and does **not** drain. |

**`BUSBAR_CONFIG` is required on Windows.** The default config path is `/etc/busbar/config.yaml`,
which on Windows is *drive-relative* and not a usable location. There is deliberately no second
Windows default: a platform-dependent answer to "which file is my config" is the one silent
divergence you never want, so the miss is a loud startup error naming the path it looked for. Set
`BUSBAR_CONFIG=C:\ProgramData\busbar\config.yaml` (or wherever you keep it) and set that
directory's ACL — see the secret-files row above.

**`transport: stdio` MCP servers on Windows.** Two differences, both consequences of the platform:

- **`command:` must be absolute in the Windows spelling** — `C:\path\to\server.exe` or a UNC
  `\\host\share\server.exe`. A bare name (resolved via `PATH`), a relative path, and a
  drive-relative `\foo` (resolved against the *current* drive) are all refused at boot, because each
  lets the environment rather than the config decide which binary runs.
- **The child's environment is cleared**, and on Windows that is a bigger deal than on unix. Busbar
  never hands its own environment to an operator-configured child (it holds provider keys, store
  credentials and admin tokens), so the child gets **only** what `env:` names. On unix an empty
  environment is a working one. On Windows the OS itself reads `SystemRoot`/`windir` during DLL
  resolution and Winsock startup, and interpreter-based servers (Node, Python — most of the
  installed stdio ecosystem) also want `PATH`, `TEMP`/`TMP` and often `APPDATA`. **Name them
  explicitly in `env:`** or the child may fail to start, or start and fail on its first socket.

**Not verified on a Windows host.** The stdio transport's spawn/pipe/teardown tests use `/bin/sh`
fixture children and are `#[cfg(unix)]`, so they compile to nothing on the Windows CI job: that job
is green while the spawn half is *unexecuted*. The same is true of the plugin-staging lifecycle
tests. Treat the stdio and plugin-loading behaviour above as reasoned from the platform's
documented semantics, not as observed. If you run either on Windows, report what you see.

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
| Cross-protocol responses missing fields | Expected: only the modeled IR subset survives a cross-protocol hop. Everything the IR does not model is dropped with a `warn!` naming the field, so `grep` the logs for `dropping` on the request id; the constructs with no target-protocol representation at all are listed in [Fields the target protocol cannot express](https://getbusbar.com/docs/protocols/#fields-the-target-protocol-cannot-express). Same-protocol routes are byte-for-byte and lose nothing. |
| High `busbar_failovers_total` for one lane | That backend is flapping; inspect its `busbar_upstream_failures_total` `disposition`. |
