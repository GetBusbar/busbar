# Operations

Running Busbar in production: process configuration, health/readiness, the metrics
to watch, circuit-breaker and health-probe behavior, failover/exhaustion outcomes,
governance/admin usage, and troubleshooting.

## Process configuration

Busbar is a single native binary configured by two YAML files and environment
variables.

**Pointing Busbar at its files (flag-first, 1.6.0).** Two optional CLI flags name the input files;
each takes precedence over the env/config layer below it:

- `-c <path>` / `--config <path>` (also `--config=<path>`) — path to config.yaml.
  Precedence: **`-c`/`--config` flag > `BUSBAR_CONFIG` env > `/etc/busbar/config.yaml`** (default).
- `--providers <path>` (also `--providers=<path>`) — path to the provider catalog.
  Precedence: **`--providers` flag > `providers_file:` in config.yaml > `providers.yaml` next to the
  resolved config.yaml** (default).

When a flag actually overrides a lower layer the operator also set — a different `BUSBAR_CONFIG`, or a
`providers_file:` in config.yaml — Busbar logs a terse boot notice naming both, so an ignored value is
never silent.

| Env var | Default | Purpose |
|---|---|---|
| `BUSBAR_CONFIG` | `/etc/busbar/config.yaml` | Path to the deployment config. The bootstrap env var that locates config.yaml itself. Overridden by `-c`/`--config`. |
| Provider key vars | n/a | Named by each provider's `api_key: { env: ... }` reference (e.g. `ANTHROPIC_KEY`). |
| Token/secret vars | n/a | Anything referenced via `${VAR}` in either file (client tokens, admin token, …). |

`TOKIO_WORKER_THREADS` is a supported fallback for `advanced.worker_threads`. Provider selection, worker count and upstream HTTP behaviour are configured in config.yaml (`providers_file:` or `--providers`, `advanced.worker_threads`, `advanced.upstream_http1_only`, `advanced.upstream_h2_prior_knowledge`), not by environment variables; see [the upgrade guide](migration-1.6.md#retired-environment-variables) for the variables an older deployment may still set.
`BUSBAR_CONFIG`, `RUST_LOG`, and explicit secret environment references are read. A few further
variables are read for specific purposes and are not configuration inputs: `BUSBAR_DATA_DIR` (the
data directory the plugin registry uses when plugins are enabled), `BUSBAR_RECORD_BOOTSTRAP_RECEIPT`
(see [cold record bootstrap](operations/cold-record-bootstrap.md)) and `BUSBAR_INCREMENTAL_SCAN`
(opts the admission gate into its incremental-scan tenant). `BUSBAR_TIMING` only has an effect in a
binary built with the timing feature.

### Config mutability (`locked` + `overlay`)

The top-level `config:` block governs whether the admin API may change config at runtime. Changes
persist exclusively in the configured Store. A durable Store preserves hooks, groups, settings,
plugin version pins and named definitions across restart; an ephemeral Store loses them on restart.

```yaml
config:
  locked: false                 # false = mutable (admin API may change config); true = immutable
```

- **`locked: true`** is an immutable/GitOps deployment: admin-API config mutations are *refused* at
  runtime (edit config.yaml and `POST /config/reload` instead). The overlay is ignored.
- Mutable management requires the Store's atomic conditional-record capability. Every mutation
  persists before its config generation is published. Failed persistence refuses the mutation.
- A read-only config directory has no effect on Store persistence. `config.overlay` file/boolean
  selectors are refused by current configuration parsing. The one-time migrator removes the old
  selector and preserves `config.locked`; old file state is imported by the migration procedure.
  Serving does not read `BUSBAR_CONFIG_OVERLAY` or use files as fallback overlay state.
- The operator's base `store:` is the overlay anchor for the deployment. Boot validates the base
  inputs, initializes its connector with base transport settings, opens that Store and recovers the
  complete overlay before opening effective hooks, planes or exporters. The recovered destination
  and security policy, framer settings, pool settings and listener self-dial protection are finalized
  before those effective plugins open. Existing anchor connections retain custody throughout.
  An unavailable, incomplete,
  corrupt or newer Store overlay refuses recovery; `--ignore-overlay` explicitly ignores it (left
  untouched) and starts from base inputs without deleting Store records. It affects boot only: an
  admin reload, apply or config write afterwards re-merges the Store overlay and persists to it. `--validate` reads operator inputs only
  and never opens or probes a Store.
- Live reload retains the same anchor. A runtime `store` setting edit remains restart-to-apply for
  governance; at restart the effective governance Store may differ, but runtime config still lives
  in the base-config anchor. Changing the operator's base `store:` selects a different anchor at
  the next boot; move its state deliberately. There is no fallback when the old anchor is unavailable.
- Overlay generations use bounded immutable Store records and one atomic head change. That change
  retires the superseded generation; readers retry if their prior snapshot was retired. An unknown
  transaction retains its exact candidate and replay identity. After receipt retention expires,
  further mutation refuses until restart recovers the authoritative Store head. Crash-abandoned,
  never-published staging records are retained because their ownership cannot be inferred from an
  unreferenced key while another node may still be publishing it.
- A running generation pins the overlay head it recovered. Another node's update requires an
  explicit successful reload before this process can mutate config again; ordinary diagnostic reads
  cannot refresh that authority. A failed rebuild leaves the old generation serving and quarantined
  from further mutations when its Store head has changed.
- The anchor Store and secret modules needed to open it must satisfy the operator's base trust
  policy before their Store-owned version pins can be read. A plugin rollback that would make one
  of those bootstrap dependencies unavailable is refused before persisting its pin. Keep an
  admitted bootstrap version or deliberately change the base Store/trust/floor configuration first.
  Other plugin pins are recovered before the complete application's plugin validation.

**Worker threads and scaling.** Busbar's request path is CPU-bound (parse, translate, serialize), so
throughput scales with data-plane workers. `advanced.worker_threads` is the **data-plane
worker count**, not a tokio pool size: on unix, each worker is a **pinned single-threaded runtime with
its own `SO_REUSEPORT` listener** on the data port, and the kernel spreads accepted connections across
them; the admin plane and background tasks run on a separate small control-runtime thread. `N: 1` on a
one-core box is the same design, just one worker. The default is **one worker per available core**
(`available_parallelism`, which respects CPU affinity and the cgroup **cpuset**, but **not** the CFS
`cpu.max` bandwidth quota, which it cannot see), capped at **128**, which gives linear scaling: ~9,750
req/s per core, sub-millisecond, to ~156k on 16 cores in our
[benchmark](https://getbusbar.com/performance). Each worker carries a thread stack and, on glibc, its
own malloc arena, so idle memory grows slowly with the count. For a **footprint-sensitive sidecar** set
`advanced.worker_threads: 1` (or `2`). On a **CPU-quota-limited pod** (a k8s CPU *limit* on a many-core
node) the default sizes to the node's full core count and oversubscribes the quota: **set
`advanced.worker_threads` to your CPU limit**; likewise to cap a shared box, set it to the cores you
want Busbar to use. Scale up by default, tune down deliberately. The topology is directly observable:
the workers show up as threads named `busbar-core-0` … `busbar-core-N-1`, and `ss -tlnp` / `netstat`
shows N listen sockets on the one data port.

Startup is fail-loud: an unset `${VAR}`, an unknown provider reference, an unknown
protocol or auth mode, or an invalid `on_exhausted` action stops the process with a
diagnostic. A provider whose `api_key` reference does not resolve refuses boot
(`BUSBAR-8020`), and refuses an admin apply/reload the same way; declare `api_key: none`
for an upstream that takes no credential. `auth.chain: []` prints a loud open-relay warning.

The HTTP client uses a 300s request timeout and pools up to 8192 idle keep-alive connections per upstream host (`limits.pool_max_idle_per_host`).

### Validating configuration (`busbar --validate`)

`busbar --validate` runs the exact load → resolve → validate pipeline the gateway runs at boot,
then exits, **without** starting the server. It binds no port, writes nothing to disk, starts no
server tasks, and makes no network call to an upstream, so it is safe to run anywhere, including in CI and against a config
edited on a live host before you reload it. It does read the files your `file:` secret references
name, because it resolves those references rather than only checking their shape. It also runs plugin preflight: every plugin manifest is checked (signature and trust, conflicts, ABI and version floors), and authorized native grammar and check callbacks may run.

```sh
busbar --validate -c ./config.yaml --providers ./providers.yaml
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
  the operator-credential token. `--validate` reads each one and exits `1` naming the first
  that fails. So a CI job needs the same
  variables and files the deployment has, or a config whose references resolve in that environment.
  A reference served by a secret PLUGIN is not resolved here, since the plugin may not be loadable.
  Boot agrees: an unresolvable provider `api_key` reference refuses boot
  (`BUSBAR-8020`), including on admin apply. It checks *structure* and secret resolution, never upstream
  reachability.
- Honors `-c`/`--config`, `--providers`, `BUSBAR_CONFIG`, and `--ignore-overlay` exactly as boot does.
  Because it reuses the boot path, a passing `--validate` catches configuration and plugin-preflight problems before boot. It does not guarantee boot, plugin readiness or backend reachability.

### Inspecting the SSRF denylist (`busbar --print-metadata-blocklist`)

Provider `base_url` values are checked against a cloud-metadata denylist, so a compromised or
mistyped config cannot turn Busbar into a reader of your instance credentials. The list the running
binary actually enforces is the built-in set plus whatever you added under
`security.blocked_metadata_hosts`, which means it is not something you can read off the config file
alone. This flag prints it, one entry per line, and exits `0`, or exits `1` when boot would be refused for a reason that is not the config file itself:

```sh
busbar -c ./config.yaml --print-metadata-blocklist
```

- The built-in set always prints, so the flag works before a deployment is wired up.
- Your `security.blocked_metadata_hosts` entries are appended when the config path (`-c`/`--config`, else `BUSBAR_CONFIG`) reads and parses. If it parses but is invalid, the flag prints the built-in set alone and says so on stderr. A file that cannot be read is skipped silently, so check the path first.
- Every host printed here is refused for every outbound connection: there are no allow-overrides
  (BUSBAR-3136). See
  [the configuration reference](configuration.md#security).

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
environment variable (or `{ module: <secret-plugin>, settings: {…} }` from a secret backend). Bare
path keys (`cert_file`, `key_file`, `client_ca_file`) are not accepted.

**Certificate & key formats.** `cert` resolves to a PEM certificate chain with the leaf
(server) certificate first, followed by any intermediates: exactly what most CAs
ship as `fullchain.pem`. `key` resolves to the matching PEM private key in PKCS#8
(`BEGIN PRIVATE KEY`), PKCS#1 (`BEGIN RSA PRIVATE KEY`), or SEC1
(`BEGIN EC PRIVATE KEY`) encoding. Busbar offers **h2, http/1.1** over ALPN: an h2-capable client speaks HTTP/2, an http/1.1-only client is served as before.

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

### Readiness propagation before shutdown

The first operator signal or an admin restart released by its asking unit immediately makes
`/readyz` return 503. `/livez` remains independent of this shutdown state. Existing listeners,
ordinary request handling and credential refresh continue for the boot-captured
`advanced.shutdown.deregister_delay` (default `5s`, configurable `0s..300s`). At that fixed
deadline listeners begin draining and the full 20-second engine drain starts. Repeated operator
requests do not restart the allowance. Native writer renewal continues until retirement.

A persistence safety failure or natural end of serving skips propagation and starts draining.
A second OS signal skips propagation and permanently expires the drain clock. These safety
paths intentionally give up the ordinary propagation allowance.

Set supervisor grace to at least `deregister_delay + 20s + 6s + operator margin`. The default
therefore requires 31 seconds before margin; the Kubernetes example uses 40 seconds. Increase
both the allowance and grace if your endpoint/load-balancer propagation needs more time. The
allowance does not guarantee delivery through an arbitrarily slow external load balancer.

### Exit statuses

Busbar's exit status tells a supervisor whether a restart is safe:

| Status | Meaning | Operator action |
|---|---|---|
| 0 | Clean: the writer retired | none |
| 75 | Spend saved; open streams were cut; the writer was not retired | safe to restart |
| 70 | Spend not persisted (`unpersisted` or `in_doubt` non-empty at the cut) | investigate the stderr evidence before restarting; money-loss signal |
| 143 | Signalled before the listener came up | restart |

- **systemd:** set `SuccessExitStatus=75`, never 70, so a 70 exit stays a failure that alerts.
- **Kubernetes:** a 75 exit shows as `Error`, but the restart is safe. Alert on 70.
- **Grace period:** size it as described in
  [Readiness propagation before shutdown](#readiness-propagation-before-shutdown).

### Certificate rotation

Certs are loaded once at startup, so rotation always needs a restart. It does not, however, need a
shell. Push the new cert/key/CA through the admin API, then restart in-product:

```bash
curl -X PUT http://localhost:8081/api/v1/admin/config/settings \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'content-type: application/json' \
  --data '{"tls": {"cert": {"file": "..."}, "key": {"file": "..."}, "client_ca": {"file": "..."}}}'
# -> {"reload_to_apply": ["tls"], "note": "... takes effect on the next restart ..."}

curl -X POST http://localhost:8081/api/v1/admin/restart \
  -H "Authorization: Bearer $ADMIN_TOKEN"
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

The native listeners, with or without a `tls` block, bound the request **header-read**
phase (30 s) (and, with a `tls` block, the TLS handshake), so a client that completes the handshake
and then trickles request headers one byte at a time cannot pin a connection open
indefinitely. This applies to each of the N data-plane listeners alike. The bound applies
only to reading the request headers: it never limits a streaming response, so long model
completions are unaffected.

The same 30 s header-read bound applies to the plain-HTTP listeners (no `tls` block). For an
**edge-facing** deployment, still prefer the `tls` block, or front Busbar with a reverse proxy /
load balancer (nginx, Caddy, Envoy, an ALB), which terminates client connections and provides its
own slow-client protection. A plain-HTTP Busbar directly exposed to untrusted networks is not
recommended.

## Health & readiness

| Endpoint | Auth | Meaning |
|---|---|---|
| `GET /livez` | open | Process liveness; upstream/store readiness never triggers a restart. |
| `GET /readyz` | open | Serving readiness, including configured planes, lanes and durability admission. |
| `GET /healthz` | open | Existing observational response; use the separate probes above. |
| `GET /metrics` | virtual key | Prometheus exposition. Data listener: OPT-IN, mounted only when an `export:` instance of the Prometheus-exposition kind is configured (with its required `settings.buffer_seconds`; see that export plugin's own documentation); otherwise the path 404s like any other. The admin listener serves its own `/metrics` regardless (see below). Requires a valid key with a non-empty `auth.chain`, open under `chain: []`. Restrict at the network layer if unauthenticated scraping is needed. |
| `GET /stats` | virtual key | Per-lane health snapshot + pool membership, JSON. |

`/stats` returns, per lane: `model`, `provider`, `max_concurrent`, `inflight`, `free_slots`, `available` (free permits for a bounded lane,
or `"unbounded"`), `at_capacity` (`true` when a bounded lane is at its `max_concurrent`
limit and is therefore shedding/spilling rather than queueing), `availability`,
`recovery_hint_ms`, `breaker_state`, `ok`, `err`, `usable`, `dead`, `dead_reason`,
`client_fault`, `cooldown_remaining_s`, `streak`, and `budget`. It is the first place to look when a pool
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
identically, each health-checked on `GET /readyz`. Any instance serves any request;
lose one and the LB routes around it. On Kubernetes this is `replicaCount` + the
Service/Ingress + a PodDisruptionBudget; on VMs it is N hosts behind an external LB
(nginx, HAProxy, or a cloud L4/L7 balancer) probing `/readyz`.

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
- **Governance state in `store: memory` is per-instance; enforcement is per-node either
  way.** The `store:` block is required in 1.6.0 (the first 1.6.0 boot of a 1.5.5 config inserts `store: {module: memory}`); `memory` is ephemeral RAM per instance. A cluster-shared
  store plugin genuinely shares keys and the token ledger across N nodes (but
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

### First start with several replicas

On an empty shared store, one replica performs the dataset's
first start while the others wait. A waiting process binds **no listener**, so `/healthz`
does not answer until it is admitted. It logs, on its first wait and every 10 s after:

```text
waiting on first start of this dataset by writer <id>: last change <n> s ago, takeover in <m> s if it stays unchanged. ...
```

It is admitted as soon as the owner publishes. If the owner's progress (its birth record,
writer row and, during a 1.5.5 import, core's import progress row) stays unchanged for the
stall window, 90 s plus 35 s per plane the owner already completed, one waiter takes the
first start over (logged as `BUSBAR-9014`) and finishes it.

The window lives in memory, so **killing a waiter early resets its wait**; if every replica
is killed early, a crashed first-start owner is never replaced. Give each replica a startup
budget of at least **200 + 105 x P seconds**, where P is the number of conditional-records
planes configured: on Kubernetes a `startupProbe` whose `failureThreshold x periodSeconds`
covers it (the README example ships 10 s x 100 = 1000 s, enough for P <= 7), or a
systemd/VM supervisor start timeout. Liveness and readiness probes start only after the
startup probe succeeds.

Only crashes, SIGKILL and hangs need this budget. A replica that refuses boot cleanly, or
receives SIGTERM/SIGINT (a probe kill or pod deletion, inside
`terminationGracePeriodSeconds`) while it owns the first start, retires its own writer on the
way out (`BUSBAR-9017`), and the next start takes over at once.

**The 1.5.5 upgrade boot.** The first boot of 1.6.0 over a 1.5.5 dataset adds M, all
migration time before the listener binds: each store's data step, any pre-admission check,
and the import of 1.5.5 records. M grows with the 1.5.5 audit and usage history; raise the
startup budget by M for that boot (measure it on a copy). A store's data step (and a
pre-admission check) is one transaction that a kill rolls back, so it restarts from zero:
the budget must cover each of them whole, or the upgrade never completes. Only the record
import resumes: a probe that fires during it sends SIGTERM, the owner hands over on exit, and
the next process resumes from the records left, so during the import a short budget slows the
upgrade and loses nothing.

## Metrics to watch

All metrics are Prometheus counters/histograms exposed at `/metrics`, which is opt-in: the data-listener `/metrics` is mounted only when a metrics export instance (an `export:` entry of the Prometheus-exposition kind) is configured. The in-process registry itself is governed by `telemetry.enabled` (default `true`) whatever `export:` holds, and the admin listener always serves its own `GET /metrics` and `GET /metrics/hooks` (admin credential; Prometheus text, OpenMetrics or JSON by `Accept`; `503 telemetry_disabled` when `telemetry.enabled` is `false`). Observations are retained for `telemetry.retention_seconds` (default 300); an export instance's `settings.buffer_seconds` (required for that instance) can only raise that retention. Quantiles cover that window, `_sum`/`_count` stay cumulative, and memory is bounded by the window rather than by uptime.

| Metric | Type | Labels | Watch for |
|---|---|---|---|
| `busbar_requests_total` | counter | `ingress_protocol`, `pool`, `outcome` | Model (LLM) plane only (no `plane` label). `outcome` is `ok` / `client_error` / `exhausted` (503) / `error`. A rising `exhausted` means pools are running out of healthy members. |
| `busbar_plane_requests_total` | counter | `plane`, `ingress_protocol`, `pool`, `outcome` | Mounted planes: `plane` is `mcp` / `a2a`, so `sum by (plane) (rate(busbar_plane_requests_total[5m]))` splits the mounted-plane traffic. Same `outcome` vocabulary as `busbar_requests_total`. |
| `busbar_upstream_attempts_total` | counter | `pool`, `lane` | Real upstream calls (re-counted per failover hop). |
| `busbar_upstream_failures_total` | counter | `pool`, `lane`, `disposition` | `disposition` is `transient_upstream` / `attempt_timeout` / `hard_down` / `context_length`. Concentration on one lane points at a sick backend. |
| `busbar_breaker_trips_total` | counter | `pool`, `lane` | Each hard-down/trip. Spikes = a backend going down. |
| `busbar_failovers_total` | counter | `pool`, `reason` | `reason` is `timeout` / `connect` / `transient_upstream` / `attempt_timeout` / `hard_down` / `context_length`. |
| `busbar_translations_total` | counter | `from`, `to` | Cross-protocol translation hops. |
| `busbar_insecure_transport_admitted_total` | counter | `kind`, `instance`, `accept` | Needs (OPEN, STARTTLS, FETCH) admitted under the instance's `insecure_transport.accept` (`plaintext` or `unverified_tls`). It counts admitted Needs, pooled reuse included, not TCP dials. The acceptance itself is audited once at boot (`config.insecure_transport_accepted`). |
| `busbar_request_duration_seconds` | histogram | `ingress_protocol`, `pool` | Model (LLM) plane only. End-to-end latency. |
| `busbar_plane_request_duration_seconds` | histogram | `plane`, `ingress_protocol`, `pool` | Mounted planes (`mcp` / `a2a`). End-to-end latency for tool calls and agent tasks. |
| `busbar_key_spend_cents` | gauge | `key` (+ mint labels) | Per-virtual-key derived spend (all-time attribution bucket), calculated from exact ledger quantities and dated rate history. The legacy metric name does not select a currency; cost units are operator-defined. |
| `busbar_key_tokens_total` | gauge | `key` (+ mint labels) | Tokens consumed by each virtual key (all-time attribution bucket). |
| `busbar_bucket_spend_cents` | gauge | `bucket`, `group`, `window` | Derived spend per (group, window) enforcement bucket (`bucket` = `group:<name>@<window>`). |
| `busbar_bucket_budget_remaining_cents` | gauge | `bucket`, `group`, `window` | Budget cap minus derived spend, only for buckets carrying a `budget` limit. Enables Prometheus burn-rate alerting per group. |
| `busbar_bucket_tokens` | gauge | `bucket`, `group`, `window`, `model`, `tier` | Per-(bucket, model, tier) token counters (the raw material for external cost dashboards). |
| `busbar_lane_state` | gauge | `pool`, `lane` | Circuit-breaker health of THIS pool's own breaker cell for the lane (the independent breaker axis), never folded with another pool sharing the lane: `0` = Closed (or Open with its cooldown elapsed, so the next request probes), `1` = HalfOpen (a recovery probe is in flight on this pool's cell), `2` = tripped (this pool's cell Open or cooling down, or the lane hard-down). Emitted for every plane; MCP/A2A destinations use their plane-qualified target or pool key as `pool` and the member position as `lane`. Side-effect-free at scrape. |
| `busbar_lane_available` | gauge | `pool`, `lane` | Unified availability from the shared `classify` taxonomy (the same one routing dispatches on): `1` = the lane would admit a request right now, `0` = unavailable for ANY reason (breaker Open, at-capacity, dead, budget, probe-in-flight). Pair with `busbar_lane_state` (breaker) and `busbar_lane_available_permits` (capacity) to see which axis is the cause. Replaces the former `busbar_lane_at_capacity`. Side-effect-free. |
| `busbar_lane_recovery_hint_ms` | gauge | `pool`, `lane` | Honest lower bound (ms) on when an unavailable lane could next serve, from the same `recovery_hint_ms` that feeds `Retry-After`: breaker `until` for an Open lane, the at-capacity floor (2000ms) for a saturated one. `0` when available or the reason has no self-recovery (dead/budget). Side-effect-free. |
| `busbar_lane_inflight` | gauge | `pool`, `lane` | In-flight requests (held concurrency permits) per lane, the depth companion to `busbar_lane_available`. Side-effect-free. |
| `busbar_lane_available_permits` | gauge | `pool`, `lane` | Free concurrency permits for a bounded lane (`0` = saturated), the independent capacity axis. Unbounded lanes emit no sample. Side-effect-free. |
| `busbar_pool_queued` | gauge | `pool` | Requests currently parked in the `on_exhausted: queue` bounded wait, per pool. Reads `0` until the queue policy is wired. Side-effect-free. |
| `busbar_unit_checkpoints_terminal` | gauge | none | Finished governed requests whose spend still awaits settlement in the store (the admission gate's terminal backlog). New governed admission is refused with `503 durability_unavailable` while it is at its fixed cap of 20,000. A value that keeps rising means the store is not keeping up. Side-effect-free. |
| `busbar_governed_admissions_live` | gauge | none | Governed admissions alive: each is released only after its unit's terminal checkpoint is staged, so a shutdown drain waits for this to reach `0`. Side-effect-free. |
| `busbar_route_policy_selections_total` | counter | `pool`, `policy` | Requests where a selection strategy (a native strategy or a gate hook) produced a usable ranked order. Only incremented on a successful `Order` outcome; abstains and on-error fallbacks are not counted. |
| `busbar_route_policy_rejections_total` | counter | `pool`, `policy`, `status` | Requests deliberately rejected by a routing hook's `reject` verb (a 4xx to the caller, no upstream dispatched). A guardrail saying no, not a failure. |
| `busbar_webhook_logs_dropped_total` | counter | n/a | Request-log webhook deliveries shed because the in-flight delivery pool was saturated (a slow/unreachable webhook endpoint). A non-zero rate means request logs are being silently dropped, scale the endpoint or alert. |
| `busbar_file_logs_dropped_total` | counter | n/a | Request-log file appends shed because that sink's in-flight append pool was saturated (a slow/stalled filesystem: full disk, hung NFS/EBS mount). A non-zero rate means request-log lines are being dropped, check the mount or alert. |
| `busbar_billing_truncated_total` | counter | n/a | Same-protocol non-stream responses whose body exceeded the translate-body cap, so the terminal `usage` frame was missed and the request billed zero tokens (the client still got a full response). A non-zero rate signals an over-cap billing gap. |
| `busbar_lane_request_duration_seconds` | histogram | `pool`, `target`, `model`, `instance` | Per-lane request latency. Only lanes within `telemetry.max_lane_series` get their own series. |
| `busbar_unit_refusals_total` | counter | `reason`, `instance` | Units that did not complete, by closed unit reason and plane instance. |
| `busbar_admission_denied_total` | counter | `gate` | Requests refused by an admission gate (for example `gate="inbound"` when the inbound concurrency cap is hit). |
| `busbar_billing_tap_decode_fail_total` | counter | `protocol`, `reason` | A same-protocol 2xx body whose usage could not be read; billing follows the plane's usage policy. |
| `busbar_tap_notifications_dropped_total` | counter | n/a | Hook tap notifications shed under load. |
| `busbar_build_info` | gauge | `version` | Fixed at `1`; carries the running version. |

`/metrics` requires a valid key with a non-empty `auth.chain`, it is treated as an
information-disclosure surface and goes through the same auth check as other routes.
Only `chain: []` admits scrapes unconditionally. Restrict it at the network layer (firewall, reverse proxy) if you
need unauthenticated scraping under your threat model.

## Circuit breaker

The breaker decides health from real request outcomes (passive), with optional
active probing layered on top. The disposition pipeline in
[`busbar-kernel-breaker`](../crates/busbar-kernel-breaker/src/classify.rs) decides *whether* an outcome counts as an
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
[circuit-breaker.md](circuit-breaker.md#breaker-state-machine), the source of truth. What an operator watching
`/stats` and `/metrics` sees is not that graph but **two independent axes**: the breaker state and
the lane's spare capacity, each exposed as its own field and never collapsed into one. The matrix
below reads them together, so a saturated Open lane shows up as **both** open **and** at capacity.

<svg viewBox="0 0 720 500" role="img" aria-label="Observability matrix for a lane. Columns are the breaker axis, the busbar_lane_state gauge: 0 Closed, 1 HalfOpen, 2 Open. Rows are the capacity axis, at_capacity and busbar_lane_available_permits: top row at_capacity false with free permits, bottom row at_capacity true with zero permits. The two axes are exposed independently, so each of the six cells reports a breaker value and a capacity value at once. The bottom-right cell, lane_state 2 and at_capacity true, shows a saturated Open lane reading both open and at capacity, whose recovery probe can never win a dispatch. Each cell also emits busbar_lane_recovery_hint_ms: 0 when serving, the breaker cooldown for an Open lane, a 2000ms floor for a saturated one." style="width:100%;height:auto;max-width:720px;font-family:ui-sans-serif,system-ui,sans-serif;">
  <rect x="0" y="0" width="720" height="500" fill="#111a2e"/>

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
  <text x="16" y="312" text-anchor="middle" fill="#94a3b8" font-size="11" font-weight="600" transform="rotate(-90 16 312)">Capacity axis</text>

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
  <text x="360" y="458" text-anchor="middle" fill="#94a3b8" font-size="10">/metrics: busbar_lane_state · busbar_lane_available_permits · busbar_lane_recovery_hint_ms</text>
  <text x="360" y="480" text-anchor="middle" fill="#94a3b8" font-size="10">/stats: breaker_state · at_capacity · available · recovery_hint_ms</text>
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
`base_cooldown_secs` up to `max_cooldown_secs`, with ±10% jitter on every
cooldown. A server `Retry-After` header is honored as a **floor**, even if it exceeds
`max_cooldown_secs`, but is itself capped at `limits.max_honored_retry_after_secs` (default 86400). Defaults (no `breaker:` block): base 15s, max 120s.

### Hard-down vs transient

- A **transient** fault (5xx/timeout/network/overload/rate-limit) drives the trip
  evaluation and, on trip, opens the breaker: recoverable via the half-open probe.
- A **hard-down** fault (billing/quota or auth) opens the breaker immediately with a
  long *sticky* cooldown (default 30 min, `limits.hard_down_cooldown_secs`) rather than waiting for a trip threshold, it does
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
`pools:` failover pool is rerouted to a verified twin before the first byte.
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
substitute: you name the twins yourself, as a pool in the one neutral top-level `pools:`
map (its kind inferred from its `tools:` or `agents:` members), and busbar then verifies
that claim against the fingerprints it already computed —
the approved tool schema digest on MCP, the approved canonical card fingerprint on A2A —
before it moves anything. Members whose pins disagree are refused with both fingerprints
named, not defaulted. `failover:` is still not accepted under `tools:` or `agents:`; the
`pools:` map is the whole vocabulary, and declaring no such pool is exactly the old
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

- `reject` (default): `503` with a `Retry-After` set to the soonest genuine
  member cooldown, or to a small saturation floor when exhaustion is pure at-capacity
  (not the misleading `1`).
- `least_bad`, serve the soonest-cooldown member that still has a free permit
  (skipping a saturated one), degraded and logged loudly.
- `{ fallback_pool: <name> }`, route to another pool (loop-guarded).
- `{ queue: { max_ms: <ms> } }`, wait up to `max_ms` for a freed permit, then reject.

If `outcome="exhausted"` (503) is climbing in `busbar_requests_total`, check
`/stats` for dead/tripped lanes and consider a `fallback_pool` or `least_bad` policy
for graceful degradation.

## Governance & the admin API

Data-plane callers authenticate with **signed, expiring virtual keys** (the built-in `keys`
verifier in `auth.chain`). Keys are managed over the admin API on the separate `admin_listen`,
guarded by `auth.admin_auth` (the operator credential of the configured auth module, sent as
`Authorization: Bearer <admin_token>` or `X-Admin-Token: <admin_token>`, or an IdP role with
`admin_scope`).

Minting, listing, rotating, and revoking keys (the routes, request/response shapes, the mint-body
field reference, and the scope lattice) are owned by the **[Admin API reference](/docs/admin-api/)**.
The limit/group model those keys charge through is owned by
**[Configuration → Virtual keys and enforcement](/docs/configuration/#virtual-keys-and-enforcement)**.
This guide stays on the operational picture. In brief: `POST /api/v1/admin/keys` mints a key and
returns the signed token **once**; a key is pure auth (every limit lives on the bound `group`), it
EXPIRES (default 90 days, so mint a replacement before then; rotation does not renew its lifetime), and `DELETE` puts its subject on the
durable revocation denylist immediately.

### Containing a self-serve key

An admin action on a self-serve key (one a user minted at `/auth/token`) holds across the user's
next sign-in and Refresh. To contain a leaked key or offboard a user:

- **Disable** (`PATCH /keys/{id} {"enabled": false}`) for a reversible pause. The user's sign-in is
  refused (403 `BUSBAR-4043`) until you `PATCH {"enabled": true}`, which brings back the same key
  and its earlier tokens.
- **Revoke** (`POST /keys/{id}/revoke`) for a permanent stop. Nothing re-enables a revoked key: not a
  sign-in, not a Refresh, not `PATCH {"enabled": true}` (409 `BUSBAR-4044`).
- **Delete** (`DELETE /keys/{id}`) to start the user over: their next sign-in mints a new key with a
  new id, and every old token stays dead. Delete is also how you clear a revoked key or a key held
  by a different sign-in provider.

Each refused sign-in is in the admin audit log as `self_serve.mint` / `rejected` on
`key:<id>#<reason>`, and logs `BUSBAR-4043` at debug.

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
- **Spend derives from exact class quantities and dated rate history.** The plane reports
  billable units, including fee units; the kernel retains quantities and provenance, never money.
  Each read/check uses the applicable dated rates. A forward card change does not reprice earlier
  arrivals; an attributed backdated amendment affects only its declared window. `as_of` reads
  reproduce an earlier history point. Card history lives in the configured Store: a new card
  activates only after the Store confirms it was saved, and boot refuses if it cannot confirm its card.
- **Ledgers are in-memory under `store: memory`** (ephemeral; the `store:` block itself is required in 1.6.0); configure a durable store plugin
  (`store: { module: <store-plugin>, settings: {...} }`) to persist keys, usage, and
  the denylist across restarts.

> Limit windows are per-process, and the caps are enforced per node even over a shared store
> (see the fleet caveat above).

## Running on 64-bit ARM — two builds, one release

From 1.6.0, every release ships **two** 64-bit ARM Linux artifacts (1.5.x shipped the default build only). They are the same code and the same
release pipeline; the only difference is the CPU generation they target:

| Build | ISA floor | Use it on | Binary asset | Container image |
| --- | --- | --- | --- | --- |
| Default | ARMv8.1+ | AWS Graviton, Ampere, Google Axion, NVIDIA Grace, Raspberry Pi 5, Apple Silicon under Linux — anything 2016+ | `busbar-aarch64-unknown-linux-gnu.tar.gz` | `getbusbar/busbar` (the multi-arch manifest's `linux/arm64` entry) |
| ARMv8.0 compat | ARMv8.0 | Raspberry Pi 4 / Pi 400 / CM4 and other Cortex-A72/A53-class boards | `busbar-aarch64-unknown-linux-gnu-armv8.0.tar.gz` | none: run the native archive |

**Why two:** ARMv8.1 added native atomic read-modify-write instructions (LSE). Built for the
ARMv8.0 baseline, every atomic operation compiles to a helper-function call instead — measured at
about 12% of self-time under concurrent load on an ARM server — so the default build raises its
floor to ARMv8.1 and gets the native instructions. A Docker multi-arch manifest cannot carry two
`linux/arm64` variants under one tag, so the image carries the default build only and no ARMv8.0
image is published (`release/release-targets.json` packages only the default `aarch64` binary into
`image-linux-arm64`). On an ARMv8.0 board, run the compat archive natively.

**Symptoms of the wrong choice:** the default build on an ARMv8.0 board dies immediately with
`SIGILL` / "illegal instruction" — switch to the `-armv8.0` artifact. The compat build on modern
hardware runs correctly but leaves atomic-heavy throughput on the table — switch to the default.
A running binary identifies itself: `busbar --build-info` prints `target-features=+lse` (default)
or `target-features=default` (compat).

Both artifacts are built by the same pipeline (PGO included), verified by the same per-artifact
contract, listed in the same release-key-signed `SHA256SUMS` (see [Verifying a busbar release](verify.md)),
and promoted in the same release step.

## Running on Windows

`x86_64-pc-windows-msvc` is a release target (`busbar-x86_64-pc-windows-msvc.zip`). The retained
1.6.0 development evidence below comes from an actual Windows host; it is not final release or
whole-workspace qualification. Account for these platform differences:

| Area | On unix | On Windows |
|---|---|---|
| **Operator-supplied config and secret files** (`config.yaml`, `file:` references) | Restrict access with file and directory permissions | Restrict access with filesystem ACLs; Unix mode bits do not apply. Runtime config overlays remain Store-owned, not a separate file in the config directory. |
| **Plugin staging** (`docs/plugins.md`) | Per-process staging dir `0700`, file `0600`; boot sweep removes staging left by a crashed prior process | Directory and file inherit the `%TEMP%` ACL — per-user in a default setup, but not the `0700` guarantee. The **boot sweep is a no-op**: it decides "is the prior pid dead" with `kill(pid, 0)`, which has no Windows implementation, so an abandoned staging directory accumulates per crash under `%TEMP%`. This costs disk, not integrity — a staged file is regenerated from the verified in-memory bytes on every load and is never trusted input. |
| **Durable write** (`fsync` of the holding directory after a rename) | The directory entry is fsynced, so a publish survives power loss | **Not performed** — a directory cannot be opened for `fsync` on Windows and `FlushFileBuffers` on a directory handle is not the same barrier. File CONTENTS are still fsynced before the rename on every platform, so a power loss can lose the *rename* (old file, or no file) but never yields a torn one. |
| **Orderly shutdown** | `SIGINT` and `SIGTERM` both drain in-flight requests | `SIGTERM` does not exist. Busbar handles `CTRL_C`, `CTRL_CLOSE` and `CTRL_SHUTDOWN`, which covers an interactive Ctrl+C, a closing console, `docker stop` on a Windows container, and machine shutdown. A `TerminateProcess` (Task Manager "End task", `taskkill /F`) is not interceptable by any process and does **not** drain. |
| **Data-plane topology** (1.6.0) | Thread-per-core: `worker_threads` pinned single-threaded runtimes, each with its own `SO_REUSEPORT` listener on the data port (threads `busbar-core-N`); admin + background on a control thread | **Classic single work-stealing tokio runtime** with one listener — `SO_REUSEPORT` load distribution has no Windows equivalent. This is a compile-time platform shape, not a knob; `worker_threads` sizes that one runtime's pool. Same behaviour as pre-1.6.0, so nothing to migrate. |

**Select an explicit config path on Windows.** The default `/etc/busbar/config.yaml` is not an
absolute Windows path. Use `-c C:\ProgramData\busbar\config.yaml` or set `BUSBAR_CONFIG` to that
location; the flag takes precedence. Restrict the file and directory ACLs — see the row above.

**`transport: stdio` MCP servers on Windows.** Configure the child explicitly:

- **`command:` must be absolute for the host platform.** The connector uses the platform's
  `Path::is_absolute` check, so a drive-qualified `C:\path\to\server.exe` or absolute UNC path
  is not refused merely for lacking a leading `/`. Bare names and relative paths remain refused;
  Busbar does not select the executable through a shell or `PATH`. A configured working directory
  must also be absolute.
- **The child's environment is cleared**, and on Windows that is a bigger deal than on unix. Busbar
  never hands its own environment to an operator-configured child (it holds provider keys, store
  credentials and admin tokens), so the child gets **only explicitly admitted environment values**,
  including resolved configured references. Windows applications may need `SystemRoot`/`windir`,
  `PATH`, `TEMP`/`TMP` or `APPDATA` for DLL loading, networking or interpreter support. **Name the
  values your child requires explicitly in `env:`**; Busbar does not inherit them wholesale.

**Scoped native Windows development proof, 2026-11-05.** On Windows Server 2022 with Rust 1.98
MSVC, six host-I/O cases passed: child binary-byte half-close and exit status, admitted environment
and working directory, child reap/handle invalidation, listener accept/rearm/live bytes, refused
connect wakeup, and explicit Unix-target refusal. The selected connector set passed 20 unique
cases (21 executions), with scoped connector clippy clean; the assembled default-schema compile
also passed on the earlier production overlay. These are retained interim source-bound results:
final combined-source qualification remains pending. They do not certify every stdio server,
interpreter, plugin-staging lifecycle or the final release. Windows Unix-domain socket targets
remain explicitly refused.

## Troubleshooting

| Symptom | Where to look |
|---|---|
| `503` on every request | `/stats`, are all lanes in cooldown or carrying a `dead_reason`? |
| A lane tripped with a `billing` reason and a sticky cooldown | Upstream wallet/quota; the lane recovers on a successful probe once funded. Consider `health.mode: dead`. |
| A lane tripped with an `auth` reason and a sticky cooldown | Wrong/expired credential behind the provider's `api_key` reference. |
| A few `401`s from a lane with an OAuth-minted credential right after startup | The lane's first OAuth token is still minting. Lanes whose credential is minted by an OAuth flow fetch an access token in the background at boot (and on every reload); for up to ~1s before it lands, the earliest calls return `401`. Clears itself within a second, no action needed. Static-key lanes (`bearer` / `api-key` / SigV4) never have this window. |
| `429` from Busbar itself | A group limit blocked. The body's `error.type` distinguishes the cause: `rate_limit_error` = requests/tokens/concurrent limit (the message names group + metric + window); `insufficient_quota` = a budget limit (Bedrock ingress signals over-budget as `400` instead). Check `GET /api/v1/admin/keys/{id}/usage`. |
| `403` from Busbar | The virtual key's `allowed_pools` doesn't include the target. |
| Startup panic: "unset environment variable" | A `${VAR}` (possibly in a comment) isn't exported. |
| Startup panic: "not found in providers.yaml" | A `config.yaml` provider name isn't in the catalog. |
| Cross-protocol responses missing fields | Check whether the target protocol represents the missing field. Cross-protocol responses are re-encoded, and fields without a target representation may be omitted or normalized. In the 1.6.0 development LLM plane, inspect the request diagnostics for dropped field paths. See [translation behavior and limits](https://getbusbar.com/docs/protocols/#what-lossless-means-here); use a compatible same-protocol backend when you need a provider-specific field. |
| High `busbar_failovers_total` for one lane | That backend is flapping; inspect its `busbar_upstream_failures_total` `disposition`. |


## Listeners and health checks

| Route | Listener | Access and purpose |
| --- | --- | --- |
| `/api/v1/admin/*` | Separate administration listener, default `127.0.0.1:8081` | Configured admin authentication; exposed binds require mTLS unless explicitly waived |
| `/livez` | Root data and administration listeners | HTTP authentication exempt; listener TLS/mTLS still applies. Process dispatch only; independent of downstreams |
| `/readyz` | Root data and administration listeners | HTTP authentication exempt; listener TLS/mTLS still applies. Configured planes, usable lanes, governance custody and native journal admission must be ready |
| `/healthz` | Root data and administration listeners | Existing observational response, retained for compatibility |
| `/metrics`, `/metrics/hooks` | Administration listener (always); `/metrics` also on the data listener when a metrics export instance is configured | Admin listener: admin credential, `503 telemetry_disabled` when `telemetry.enabled` is false. Data listener: virtual key, see above |

An upstream outage can make `/readyz` or `/healthz` return 503 while the process is healthy. Use `/livez` for restart-triggering liveness and startup checks, and `/readyz` for readiness. Readiness is a side-effect-free snapshot of observed admission eligibility; it does not perform a remote-store probe. `/readyz` returns `200 ok` or `503 not ready`. A TCP probe of the data listener is independent of upstream health but proves only that the socket accepts a connection; it does not detect every application deadlock. `busbar --validate` checks configuration and plugin preflight, not the running process.

## Configuration recovery boundaries

Admin mutations persist through the configured Store. A read-only config directory does not prevent Store writes. Keep the base configuration, Store backup, signing material and required plugin packages together when planning recovery (see [backup set and order](#backup-set-and-order)). A failed persistence operation must not be treated as a successful configuration update; retain ETag/concurrency checks and inspect the effective configuration after recovery. Memory Store state is lost on restart. `config.locked: true` selects configuration managed outside runtime mutation; retired file-overlay settings are migration inputs only.

Durable MCP task records can be queried through a shared persistent Store. Legacy MCP transport sessions remain process-local: preserve session affinity and expect clients to reconnect after a node restart. Shared task storage does not make every live session portable.

### Backup set and order

A deployment is recoverable only from a complete, consistent set. Back up these items, in this
order:

1. **Configuration.** `config.yaml`, the stamped `config.yaml.1.5.5` if migration left one,
   and the providers catalog.
2. **The Store dataset.** Use the backend's own consistent point-in-time backup, for example a
   PostgreSQL base backup with its WAL archive, a MySQL consistent snapshot, the SQLite online
   backup API, or a Valkey RDB snapshot. A copy of live database files taken while a node
   writes is not a backup. The Memory Store holds nothing across a restart and cannot be
   backed up.
3. **Signing material and at-rest keys.** Back these up by reference: each secret source
   keeps its keys under its own backup, so record which secret source and key versions the
   configuration names.
4. **The exported audit stream.** Keep the audit export's own retention covering the Store
   backup point. It is the only record of what changed in the Store after the backup.
5. **Plugin packages and the release keys document** that the deployment runs.

Take items 2 and 4 from the same point in time. To restore, stop **every** node that can
reach the Store, restore in the reverse order (packages and keys document, signing material,
Store dataset, configuration), then start the nodes again.
`POST /api/v1/admin/store-restore` does not perform a restore; it always refuses. Restore
off-node with the backend's own tooling.

A restore returns every Store-held fact to the backup point. Key revocations, trust
demotions, principal transitions, plugin and keys-document floors, consumed replay claims and
redeemed single-use tickets recorded after the backup are lost, so a credential consumed after
the backup point can be presented again until it expires. Before admitting traffic
again, use the exported audit stream to re-apply every revocation, demotion and principal
transition made after the backup point, and load packages and a keys document no older than
the ones the deployment ran before the restore.
