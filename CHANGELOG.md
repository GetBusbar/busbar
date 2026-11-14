# Changelog

All notable changes to Busbar are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.6.0], unreleased

Busbar 1.6.0 is 1.5.5 plus three new planes: MCP, A2A and streaming (realtime voice). A request on any plane gets the caller's key, grants, budget, hooks and audit chain. A configuration that declares none of the new sections gains no endpoint and no route. Run `busbar --migrate-config` first; it converts a working 1.5.5 configuration and reports every change. Details: [the 1.6.0 migration guide](docs/migration-1.6.md).

### Upgrade notes

- Run `busbar --validate` and `busbar --migrate-config` with the old deployment's environment and working directory before starting 1.6.0.
- A `store:` block is now required; boot and `--validate` refuse a config without one. Migration inserts `store: {module: memory}`, what 1.5.5 used when the block was absent.
- A `rate_card` must price every billable class: each entry needs a `units:` map covering `search_units`, `classifications`, `web_fetch_requests`, `unitemized_tokens`, `images`, `audio_ms` and the nine Bedrock `guardrail_*` units (0 keeps a class free, as 1.5.5 billed it). Without it boot refuses, and `PUT /api/v1/admin/config/settings` answers 400.
- Plugins must be rebuilt against the 1.6.0 SDK. A 1.5.5 plugin, including the four published store plugins, no longer loads; boot refuses it and names the rebuild. Install the rebuilt releases before upgrading.
- A Store-only bootstrap plugin (a Store, secret plugin, transport or plane grammar probe needed before Store recovery) must be pinned by its archive SHA-256 in the base `plugins.fetch` entry. Busbar no longer reads or writes `plugin-highwater.json`; later loads use the Store's per-host downgrade floor.
- First-party plugins are named `busbar-<kind>-<name>` (repos, manifest names and release assets). Aliases and old manifest names still select them, and migration rewrites 1.5.5-era `plugins.fetch` pins.
- The Headroom hook is no longer a first-party plugin; remove it from your configuration and plugin directory, or install a release ported to the 1.6.0 SDK.
- Point log collection at `plugins.logs.dir` (default `logs/plugins`) as well as the Busbar log: plugin log lines, including the LLM plane's, now go to per-plugin files. `plugins.logs` accepts `dir`, `level`, `levels`, `rotate_mb` and `keep`; an unknown level or `rotate_mb: 0` refuses boot.
- The environment variables `BUSBAR_PROVIDERS`, `BUSBAR_WORKER_THREADS`, `BUSBAR_UPSTREAM_HTTP1_ONLY`, `BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE` and `BUSBAR_CONFIG_OVERLAY` are no longer read when serving. Migration captures their values into `providers_file:` and the `advanced` keys; remove them from your launcher afterwards. `--providers`, `BUSBAR_CONFIG`, `RUST_LOG`, `TOKIO_WORKER_THREADS` and explicit `{ env: NAME }` secret references still work.
- The `config.overlay` selector is refused; migration removes it, keeps `config.locked` and imports old file-overlay state. Runtime configuration is persisted through the Store.
- Hooks use `module:` and `phase:` (for a single stage, `phase: [response]`) instead of `plugin:` and `at:`; migration converts them. Hook admin views drop `at` and expose `fires_at`, `phase` and `groups`.
- Alerts that treat `busbar_lane_state == 1` as a tripped lane must use `2`.
- Third-party audit verifiers must read recipe numbers from decimal strings and add the `busbar.audit.digest.v4` field order (see `docs/audit-chain-digest-v4.md`); no stored record is rewritten.
- The Postgres store answers only SCRAM-SHA-256 unless the URL sets `require_auth`: move the role to SCRAM or add `require_auth=md5` (or `password`) to the URL.
- The MySQL store sends a `caching_sha2_password` full-authentication password over TCP only to a pinned RSA key: add `server_public_key_sha256=<64 hex digits>` to the URL, or connect over the unix socket.
- To mint keys with `issue_aws_credential: true`, configure `credentials.at_rest.key` (32 random bytes, for example `openssl rand -hex 32` in a file) on every node sharing the store.
- Rate-card history is now dated. To correct what a past window was charged, post `POST /api/v1/admin/ledger/amend-rate-history` instead of editing the live card.

### Breaking changes

- A provider whose `api_key` reference does not resolve refuses boot (`BUSBAR-8020`) and refuses an admin apply or reload. A keyless local upstream must declare `api_key: none` (not with `jwt-bearer` or `oauth-client-credentials`); migration does not insert it.
- Provider and identity-provider addresses that resolve to a private network are refused unless allowlisted (`advanced.block_private_addresses` defaults to `true`). The destination guard also covers A2A peers, streaming upstreams and WebSocket dials; allow them in `advanced.allow_destinations` (an A2A registration may set `allow_private: true`).
- An identified principal that earns no governance key (no roles, or unbound roles) is refused with `401`; 1.5.5 admitted it ungoverned and booked its spend to `anonymous`. Bind its roles in `role_bindings`.
- A request whose key row has a passed `expires_at` is refused with `401`, and the refusal is audited.
- When an auth plugin's `max_inflight` is full, or an inbound auth plugin's `verify` gives no verdict (for example an OIDC key set that is unavailable), a request is answered `503` with `Retry-After: 1` instead of `401`. A rejected credential is still `401`.
- A sign-in whose identity provider answers 5xx or 429, or times out, answers `503` with the provider's `Retry-After` (clamped 1 to 3600 s, 5 when absent).
- A hook with `on_error: reject` whose transform fails answers `503`; 1.5.5 passed the request through.
- `allow_unsigned` no longer admits a plugin signed by a retired busbar release key (`retired_key`); name the key under `plugins.trust.publishers` to opt in.
- `GET /auth/token?method=<m>&refresh=1` rotates the key only on a same-origin navigation from Busbar's own page; otherwise it re-shows the current key.
- `POST /api/v1/admin/keys` with `issue_aws_credential: true` and no at-rest key answers `409 conflict` and writes nothing. The secret access key is now stored sealed (AES-256-GCM); keys minted by 1.5.5 are re-sealed once a key is configured.
- `POST /api/v1/admin/ledger/amend-rate-history` needs only a `full` admin grant. `auth.operator_pub` is gone; drop it, and stop signing corrections.
- `POST /api/v1/admin/keys/{id}/rotate` answers `400 invalid_request` for an id over 64 characters, not `404`.
- `POST /api/v1/admin/adjust` requires `pool` (a configured pool, else `400`).
- A fallback, least-bad or queue hop refused upstream with 401/403 is answered in Busbar's ingress-native auth-failure envelope (not the upstream's body) and trips the lane's breaker, as the primary hop already did.
- A same-dialect Anthropic stream cut mid-flight ends on an `error` event with `error.type: api_error`; a Bedrock ConverseStream ends on `internalServerException`.
- A request translated between dialects no longer has an unrepresentable value substituted (an unsupported Bedrock image format relabelled `png`, Gemini `thinkingBudget: -1` sent as `medium`): the field is dropped with a warning and audit row, and a wrong-typed one is refused with the caller's own 400.
- A chat request whose `stream_options` is not a JSON object is refused with `400`; 1.5.5 forwarded it.
- A reserved-name configuration refusal is one generic sentence linking https://getbusbar.com/docs/configuration#reserved-names.
- A store refuses a different record at an already-used task-event sequence as a fork. A store plugin refuses an `op_id` replayed with different fields (`STORE_OPID_CONFLICT`).
- The LDAP auth plugin fails closed on a malformed reply or hostless URL, fails fast on an overrunning length, and caps inbound replies at 16 MiB.
- A configuration apply that first writes a plane section (`mcp:`, `agents:`, `streams:`, `decisions:`) the process did not load at start is refused whole with `400` naming the section; write it in the config file and restart. A plane loaded but not opened accepts the change and lists it under `reload_to_apply`.
- An `mcp:` block with an empty `auth.chain` refuses to start.
- `RUST_LOG` is read strictly: per-target directives such as `busbar=debug,hyper=warn` now work, `off` is honoured, and an invalid value stops boot with `BUSBAR-9007` (1.5.5 silently logged at `info`).

### Billing and metering changes

- Rate cards are a dated history: a new card applies from its effective date, and spend already booked keeps the price in force when the request arrived. `GET /api/v1/admin/usage` reports `rate_card_version` and accepts `?as_of=`. Applying a config no longer reprices spend in the `/metrics` series. After a rate-card edit and a restart, key and group budget reads can differ from `/admin/usage` for the same consumption.
- Fallback, least-bad and queue hops to an OpenAI Chat lane now bill streamed usage; expect spend to rise for traffic that fails over.
- Gemini turns that use server-side tools bill the tool-use tokens in the input tier; every itemized Gemini count is ledgered, and an unexplained total gap is ledgered as `unitemized_tokens`.
- Every provider-reported count is ledgered under its own class: `classifications`, `web_fetch_requests`, `images`, `audio_ms` and Bedrock `guardrail_*`. An OpenAI transcription answered in its own dialect, billed nothing in 1.5.5, is now metered.
- A stream that fails or is cancelled after its first byte keeps its charge for the tokens that streamed, and the request-budget unit is not returned.
- A stream that dies mid-flight (an OpenAI-compatible inline error chunk, a Cohere `ERROR` finish) is no longer served and billed as a completed one; the breaker records the fault.
- A failed request's flat fee is refunded from the window bucket it was charged to, even after the window rolled.
- A request that asks for a stream gets a stream in the caller's dialect, even when the upstream answers with one whole body (audited as `egress.stream_synthesized`).
- An upstream that is down is counted and billed nothing, as in 1.5.5.

### New

- MCP: Busbar is an MCP server (`mcp:`) with OAuth 2.1 discovery, and a governed gateway in front of your MCP tool estate (`tools:`) over HTTP and stdio (`transport: stdio`, `busbar --mcp-stdio`). Tool calls are metered, hook-able, written to a per-caller tamper-evident record, and relay upstream sampling, roots, elicitation and resource-update requests to the caller.
- A2A: JSON-RPC, HTTP+JSON and gRPC bindings in front of registered agents (`agents:`), with push notifications relayed when the agent finishes, and `agent_push: { ca: <PEM> }` for a private push CA.
- Streaming: a `streams:` block serves full-duplex realtime sessions (OpenAI Realtime and Gemini Live dialects) metered by the same ledger.
- Decisions: a `decisions:` block serves the `jev` (`POST /v1/systemone`) and `nanojev` (`POST /api/evaluate`) dialects as a passthrough, priced by `decisions.rate_card` and `decisions.fees.per_request`.
- Failover pools for MCP servers and A2A agents; MCP and A2A traffic on `/metrics` as `busbar_plane_requests_total` and `busbar_plane_request_duration_seconds`.
- Documents, audio and video cross between LLM dialects instead of becoming an empty text block; usage sub-buckets (reasoning tokens, cache tiers, search units) survive a hop; streamed Cohere and Responses citations reach the client.
- Provider entries take their own request headers and query parameters; model entries take `protocol`, including `bedrock-invoke` for Anthropic models over Bedrock `InvokeModel`.
- Admin: verb-by-verb authority (`verbs:` on a role binding), signed audit records and checkpoints with `GET /api/v1/admin/audit/keys` and `GET /api/v1/admin/ledger/{totals,checkpoints,reconciliation,migration}`, and one OpenAPI document for every admin operation. `identity-providers` and `export` overlay sections can be reset with `DELETE /api/v1/admin/overlay/{section}`.
- `limits.hook_content_max_bytes` bounds content shown to a content-granted hook; hooks now fire on MCP tool calls and A2A submissions, and on the normalized request the upstream receives.
- OpenAI Responses background-turn webhooks at `POST /v1/llm/webhooks/openai` (`webhooks: { openai_responses: true }`); Client ID Metadata Documents for the OAuth server.
- Error and warning lines carry `BUSBAR-NNNN` diagnostic codes; at `DEBUG` each request ends with one `request finished` summary on target `busbar::request`.
- OTLP trace export now works (one OTLP/HTTP span per request-path span) and ships as the `busbar-export-otlp` plugin linked into the default build.
- The TLS listener offers h2 via ALPN. The data plane is thread-per-core on unix (`advanced.worker_threads`). Default arm64 builds target ARMv8.1+, with an ARMv8.0 build (`busbar-aarch64-unknown-linux-gnu-armv8.0.tar.gz`, `getbusbar/busbar:armv8.0`) alongside.
- A quarantined or wedged hook is retried (1 s backing off to 30 s) and returns to service on a successful trial.

### Changed

- Same-dialect routes pass the caller's bytes, headers and `?alt=sse` through unchanged apart from governed fields; the caller receives every upstream response header except hop-by-hop and credential-derived ones.
- Cross-dialect answers are closer to each provider's published schema: Anthropic, Responses and Gemini objects carry their required members, Responses streams carry the lifecycle frames, errors use native types, and `finish_reason` is always a real token. Citations an Anthropic or Bedrock caller cannot represent are omitted with a warning and audit record.
- A Gemini speech response with no audio is no longer served as an MP3; a Bedrock `cachePoint` before a document no longer sends it twice; a non-image attachment no longer reaches Anthropic as an `image`.
- Fields dropped at the cross-protocol seam are named in the log and audited.
- A postgres store that cannot open names the server's SQLSTATE and message; a mis-encoded `env:` secret is reported as an encoding problem, not unset.
- `/metrics` families are emitted in a stable sorted order; `busbar_lane_state` reads each pool's own breaker.
- `--help` documents `-c`/`--config` and `--providers`, and `--version` prints a second line. `openapi.json` reports the running build version.
- MCP servers and A2A agents are refused only on a breaker trip, not on a single timeout's cooldown.

### Fixed

- `oauth_as:` could not mint an authorization code (consent cookie scoped to the wrong path).
- Two concurrent admin key rotations could share an idempotency key, and an in-flight idempotency sentinel was swept after ten minutes, admitting a second mint. A rotation retried across the upgrade runs again.
- An admin-auth provider is judged by its module, so `ops: { module: admin-tokens }` now authenticates.
- `GET /admin/plugins` hid an installed plugin on Windows when its filename's case differed; Windows now drains in-flight requests on `docker stop` and console shutdown.
- An idle Busbar could abort after serving a body over 8 MiB on macOS and static-musl builds (present in 1.5.5).
- Cohere `tool_plan` is no longer shown as answer text, and a Cohere tool-result `document` keeps its structure; grounding citations survive out of Cohere and streaming.
- Anthropic stream error events carry `request_id`; a Bedrock text block no longer opens with an empty `contentBlockStart`; a streamed chat `usage` trailer arrives even without a stop reason.
- A webrequest hook's status no longer reports false drift.

### Security

- The A2A push-callback token is now a per-task capability that is revoked when the task ends and fails closed on a store that cannot check it; it was previously replayable.
- A2A hop refusals no longer name the backend URL, resolved address or response text to the caller; they carry a stable `a2a.hop.*` code and the detail goes to the operator journal.
- A first-party plugin cannot be downgraded: a per-plugin high-water mark refuses an older genuinely-signed release, and `plugins.rollback` is the audited way past it.
- An inline secret literal in a secret-reference slot is refused without echoing the value; an unreadable service-account key file no longer echoes the key into the error.
- Metadata host lists match Unicode-written hosts against the ASCII host they map to, a metadata entry that names no usable host refuses startup, and `--print-metadata-blocklist` also lists `fd00:ec2::23` and `fe80::/10`.
- The OIDC auth plugin refuses a discovery or JWKS redirect to a cloud metadata host from any host, and to a private or loopback host unless the redirecting hop is itself private or loopback.
- Two A2A verbs, `GetExtendedAgentCard` and `ListTasks`, are now admitted and metered (the card verb against the `agents` plane pool); an MCP tool call that never left is not charged.
- An `ask_caller` confirm-once approval is redeemed once per deployment, not once per node.
- `busbar-plugin-pack` refuses a plugin settings schema with a deeply nested `$ref` chain instead of hanging.

## [1.5.4], 2026-08-14

A hotfix. 1.5.3's Docker image does not start, so if you run Busbar in a container, upgrade. There is
no config change and no behaviour change beyond the two fixes below.

### Fixed

- **The Docker image starts again.** `docker run getbusbar/busbar:1.5.3` exited 1 before binding a
  port, with "the overlay backend '/etc/busbar/busbar-overlay.json' is not writable". The image runs as
  an unprivileged user on a read-only `/etc/busbar`, and the documented quickstart mounts your
  `config.yaml` read-only on top of that, so the config overlay 1.5.3 introduced had nowhere to
  write — and 1.5.3 treated that as a reason to refuse to start. It no longer does. Busbar boots,
  serves traffic, warns clearly at startup that it has no durable config overlay, and refuses
  admin-API config changes outright rather than applying them in memory and losing them on restart. If
  you want those changes to persist, point `config.overlay.file` at a writable volume; if you never
  wanted them, `config.locked: true` says so explicitly and silences the warning. A config that
  explicitly sets `config.overlay: false` while remaining mutable still refuses to start, because that
  one is a contradiction you can only reach by writing it down. ([#50])

- **First-party plugins verify on ARM Linux.** `busbar-aarch64-unknown-linux-gnu` shipped without the
  embedded Busbar release public key in 1.5.1, 1.5.2 and 1.5.3, so every correctly signed first-party
  plugin was refused on ARM Linux — and only there — as unsigned. That target was the one platform
  built by cross-compiling inside a container the key never reached; it now builds on a native ARM
  runner. The release build additionally refuses to compile at all without a well-formed key, and
  asserts the key is present in the finished artifact before it is uploaded, so this cannot recur
  silently on any platform. ([#52])

### Changed

- The release pipeline boots the container image and checks `/healthz` before any tag, `latest`
  included, is allowed to point at it. Nothing had ever started the image before publishing it.
- The post-release verifier runs all of its checks and reports every failure, instead of stopping at
  the first. A check that could not reach getbusbar.com from CI was aborting the run before the check
  that boots the published image, which is why the defect above stayed invisible for six days.

[#50]: https://github.com/GetBusbar/busbar/issues/50
[#52]: https://github.com/GetBusbar/busbar/issues/52

## [1.5.3], 2026-08-08

This release reshapes the config file, so give yourself a few minutes for the upgrade.
`busbar --migrate-config <config.yaml>` does most of it for you and tells you what it changed. Busbar
will not start on the old spellings, which is deliberate. Every breaking change below is a config
change; [config at a glance](docs/config-at-a-glance.md) shows the finished shape on one page, and
[the 1.5 migration guide](docs/migration-1.5.md) walks the path from 1.4.

### Breaking changes

- **`busbar --validate` now resolves `env:` and `file:` secret references and exits 1 when one
  cannot be resolved.** It previously checked only that the reference was well formed, so a config
  naming an unset variable reported "ok: config valid". A CI job that runs `--validate` without
  production secrets will now go red: give it the variables and files your config names. Boot is
  unchanged. See [the operations guide](docs/operations.md#validating-configuration-busbar---validate).
- **The Redis-protocol store plugin is now Valkey.** Change `store.module: redis` to `valkey` and
  install the `busbar-store-valkey` artifact. Your connection URL does not change; re-pin any version
  pin under the new name and delete the old plugin file.
- **Hooks are defined once by name and attached by name.** Inline definitions and `global_hooks:` no
  longer load: define each hook under the top-level `hooks:` block and list its name under
  `pools.hooks:`. Stage names are now `request`, `candidate`, `routing` and `response`; a pool may not
  be named `hooks`; a hook with no stage list fires at all four stages, so set `phase: [request]` for
  the old behaviour. See [the hooks guide](docs/hooks.md).
- **Identity providers are defined once by name and referenced by name.** Define each under the
  top-level `identity-providers:` block; `auth.chain:` and `auth.admin_auth:` are lists of those
  names. `auth.methods:` is gone, `auth.role_bindings:` is keyed by provider name, and an unstated
  admin trust ceiling is now the most restrictive one — raisable only in the config file, never
  through the admin API.
- **Export sinks are named, and `observability:` is gone.** Write `export:` as
  `<your-name>: {module, settings}` rather than keyed by type, so you can run two sinks of one kind.
  `generic-webhook` is now part of `request-log-webhook`, and `observability.otlp_url` becomes an
  export sink using the `otlp` module. See [the observability guide](docs/observability.md).
- **Response headers are off by default.** Everything Busbar used to add to a response, timing and
  route headers included, must be enabled under `advanced.response_headers`.
  `observability.emit_server_timing` no longer exists.
- **`admin_insecure` is now `admin_require_mtls`, with the meaning reversed** and safe by default.
  A network-exposed admin listener with no client CA still refuses to start; the waiver is
  `admin_require_mtls: false`.
- **Upstream credentials are configured per pool.** `auth.upstream_credentials` moves to
  `pools.upstream_credentials`, and any pool can override it.

### Added

- Identity providers and export sinks can be managed through the admin API, as hooks already were.
  See [the admin API reference](docs/admin-api.md).
- Config changes made through the admin API survive a restart out of the box. Set
  `config.locked: true` to make the file the only way to change configuration.
- Plugins can serve their own HTTP endpoints, and a plugin's own log lines now reach your log sink
  with their level and structured fields intact, filtered by `RUST_LOG` like everything else.
- A guide to pointing Busbar at a local inference server — Ollama, LM Studio, llama.cpp, vLLM. See
  [the providers guide](docs/providers.md).

### Changed

- Operational settings that were environment variables are now config keys under `config:` and
  `advanced:` (`config.overlay.file`, `advanced.worker_threads`, `advanced.upstream_http1_only`,
  `advanced.upstream_h2_prior_knowledge`), and the provider catalog moves to `providers_file:` / the
  `--providers` flag. The old env vars are deprecated and still honored: for `BUSBAR_PROVIDERS`,
  `BUSBAR_WORKER_THREADS`, `BUSBAR_UPSTREAM_HTTP1_ONLY` and `BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE` the
  env var wins when both are set; only `BUSBAR_CONFIG_OVERLAY` is honored the other way, only when
  `config.overlay` is left unset. `BUSBAR_CONFIG` is unchanged.
- The `persist` field on admin config calls is ignored; durability is a property of the deployment.
- The admin hooks API calls the field `module` rather than `plugin`, matching the config file.
  `plugin` is still accepted.
- Every durable store now answers the same way for the same request, where the answer used to depend
  on which store you deployed. Deleting a key that never existed is an error, deleting one already
  deleted is a success, revoking an unknown credential is an error, and an audit write onto an
  occupied position succeeds only if the record is identical. Tooling that read a lenient backend's
  silent success as confirmation should be checked.

### Fixed

- Admin reads returned the raw values of a module's settings, including client secrets and store
  passwords. They now return only the setting names.
- An admin deletion of a user's self-serve key survived only until that user's next login, which
  silently recreated the credential and put every token minted before the deletion back into service.
- Rotating a user's self-serve key and then changing their group's pools left the user holding two
  valid keys, each metering separately, so spend was counted against two buckets and neither
  reflected the real total.
- Deleting or rotating a key could return an error while the key went on working, and flushing the
  authentication cache could return success without revoking anything.
- A hook that could not reach its own dependency read as "no opinion", so a gate configured with
  `on_error: reject` admitted the request instead of refusing it. See [the hooks guide](docs/hooks.md).
- Busbar sent an empty `client_secret` when exchanging a code for a public identity-provider client,
  so a provider could answer `invalid_client` and browser login could fail outright.
- The SSRF guard on an OTLP export sink checked only the literal text of the endpoint, so a hostname
  resolving to a cloud metadata address was allowed through. The endpoint is now resolved and every
  resulting address checked. See [the observability guide](docs/observability.md).
- Budget accounting could allow spend it should have blocked: an exhausted lifetime budget on a group
  with an email-shaped name reset to zero on restart, deleting one principal could reclaim another's
  budget, and deleted groups left invisible budget entries behind.
- Admin config writes could report success without taking effect: an unknown field was accepted then
  dropped at reload, `config.locked` was not enforced on two endpoints, and a write with nowhere to
  persist returned success.
- An identity provider's `max_admin_scope` was ignored, leaving it read-only even when you granted
  more.
- `busbar --migrate-config` could change or drop what you wrote: a hook attached with a single value
  migrated to a pool with no hooks and still passed `--validate`, an unrecognized budget period became
  a lifetime cap, a yearly budget carried onto a monthly window unrescaled, and a provider used on
  both planes could lose one plane's settings.
- Busbar could refuse to start in a writable directory when the config file was named with no
  directory path.
- The request-log file export could grow without bound if the destination stalled, and every webhook
  export shared one queue limit.
- A hook whose settings referenced a secret reported a settings mismatch on every check, forever.
- `advanced.worker_threads: 0` was silently ignored instead of reported.

## [1.5.2], 2026-08-02

### Breaking changes

- **`auth.chain: [keys]` with no way to mint an admin token now refuses to start.** It previously
  booted as a silent open relay admitting anonymous requests. Give `auth.admin_auth` an `admin-tokens`
  entry with a `token:`, or an admin module granting `mint` or `full`, or set an explicit `admin_auth: []`
  for development. See [the 1.5 migration guide](docs/migration-1.5.md).

### Changed

- Setting an admin token no longer forces data-plane requests to carry a virtual key, so `chain: []` plus
  an admin token is now an open relay with a protected admin API.

## [1.5.1], 2026-08-02

### Breaking changes

- **Busbar no longer generates a signing key at boot.** If `auth.chain` names the built-in `keys`
  verifier, `auth.signing_key` is required and startup fails without it. Generate one with
  `busbar --generate-signing-key` and point `auth.signing_key` at a file or environment variable. It is
  fleet-shared, so generate once and distribute to every node; rotating it revokes every outstanding key.
  1.5.0 wrote this file itself beside your config, which boot-looped on a read-only mount.

### Added

- `/stats` and `/metrics` report why a lane cannot take a request (at capacity, breaker open, dead, budget
  exhausted), when it might recover, and how many requests are parked. See
  [the observability guide](docs/observability.md).
- `on_exhausted: { queue: { max_ms } }` holds a request for a bounded wait when every pool member is at
  capacity, then dispatches it or falls through to `reject`.

### Changed

- A pool whose members are all at `max_concurrent` now spills or sheds per `on_exhausted` instead of
  queueing to the failover deadline, so a burst against a small pool with a cloud overflow pool spills
  immediately rather than serializing.
- `busbar_lane_at_capacity` is replaced by `busbar_lane_available`. Update dashboards that use it.

### Fixed

- `on_exhausted: least_bad` returned a 503 when the best member was at capacity even though a sibling had a
  free slot.
- `Retry-After` on an exhaustion 503 always said one second under saturation, rather than the real cooldown.
- `limits.max_inbound_concurrent` queued excess requests behind the cap instead of shedding them, so
  clients got no backpressure.

## [1.5.0], 2026-08-01

The config, identity and cost release. The config file changed shape and every 1.4.x virtual key stops
working, so plan the migration and the key rotation together. The data-plane HTTP surface is
unaffected: an application posting to `/v1/chat/completions` gets a byte-identical response after the
upgrade.

### Breaking changes

- **The config file changed shape and a 1.4.x config refuses to start.** Run
  `busbar --migrate-config <old.yaml> > config.yaml`, review every WARNING and TODO it prints, then run
  `busbar --validate`. Read every `allowed_pools: []` carefully: its meaning flipped from all pools to
  no pools.
- **Every 1.4.x virtual key stops working and must be re-minted** through `POST /api/v1/admin/keys`,
  with the new tokens rolled out to callers. Keys are now signed tokens that expire (90 days by
  default) and can be revoked fleet-wide.
- **A durable store is dropped and recreated on first open.** Usage history resets with it.
- **Limits moved off keys and onto groups.** `rpm_limit`, `tpm_limit`, `max_budget_cents` and
  `budget_period` are gone from minting, from `PATCH /keys/{id}` and from key metadata; a key resolves
  to a group and the group carries the limits. The per-key `busbar_key_budget_remaining_cents` gauge
  is gone with them, so use the bucket gauges.
- **The `governance:` block is gone.** `store`, `rate_card`, `per_request_fee`, `groups` and
  `advanced` are top-level, and the admin token is a secret reference on the `admin-tokens` module.
  Handled by `--migrate-config`.
- **Static token auth is gone.** The `tokens` module and `auth.client_tokens` are removed; data-plane
  auth is the built-in `keys` verifier or an identity provider.
- **The top-level `hooks:` registry is gone,** with the hook `global:` and `default:` flags. A hook
  instance is referenced inline in a pool's `hooks:` list or in `global_hooks:`. (Reversed in 1.5.3,
  which restores a named `hooks:` definition map.)
- **`cost_per_mtok` on pool members and `governance.price_per_1k_tokens_cents` are gone.** `rate_card:`
  is the only cost source; `--migrate-config` synthesizes entries and flags them for review.
- **Config aliases are gone, one canonical name each.** `window_s` becomes `window_secs`, `n` becomes
  `consecutive_n`, `deadline_secs` becomes `timeout_secs`, `cap` becomes `max_hops`, `otlp_endpoint`
  becomes `otlp_url`, a member's `target` becomes `model`, `api_key_env` becomes `api_key: { env: ... }`,
  and `auth.mode` becomes `auth.chain` plus `auth.upstream_credentials`.

### Added

- **`groups:` is the one place limits live:** a named tree where requests, tokens, budget and
  concurrency all use one shape. Admission checks every group up the chain and a rejection names the
  bucket that blocked it. A limit can carry `pool: <name>` so a team's spend splits across model tiers,
  and a pool-scoped budget can declare `on_exhaust: downgrade` to route to a cheaper pool instead of
  refusing. See [the configuration guide](docs/configuration.md).
- Groups are editable live over the admin API with no restart, past accrual survives the edit, and
  per-group usage is readable at `GET /api/v1/admin/groups/{name}/usage`.
- `POST /api/v1/admin/keys` can auto-provision a personal group under a parent, and the new `mint`
  admin scope lets a portal issue keys without full admin rights.
  `limits.max_keys_per_principal` caps how many keys one principal may hold.
- `rate_card:` is the only source of cost, priced per model and tier. Omit it and everything prices at
  zero; include it and it must be complete, with a missing model failing startup with a paste-ready
  stub.
- Every secret in the config is a reference: `{ env: VAR }`, `{ file: /path }`, or a secret plugin for
  a vault or cloud secret manager.
- **Durable stores are plugins.** SQLite, Postgres and Valkey ship as signed tarballs you install and
  name in `store.module`; the compiled-in `memory` store is still the zero-setup default. Store,
  secret, identity and hook plugins share one signed artifact format and trust model — unsigned,
  tampered or unknown-publisher plugins are skipped and never loaded, and `trust.allow_unsigned` and
  `trust.allow_third_party` default to off. See [the plugins guide](docs/plugins.md).
- Identity providers are plugins: name one in `auth.chain` and it loads at boot, and one that cannot
  load is a hard startup failure rather than a silently open front door. The bundled `oidc` module is
  the first.
- Hooks are signed plugins loaded in process. `busbar-headroom-hook` compresses prompts before
  dispatch and `busbar-webrequest-hook` forwards to an HTTPS sidecar you run yourself.
- Plugins can be listed, installed, removed, hot-reloaded and rolled back over the admin API with the
  same trust checks boot applies. Changing the store module still needs a restart.
- `GET`/`PUT /api/v1/admin/config/settings` covers every config section, and
  `POST /api/v1/admin/restart` applies the settings that need one — listeners, TLS, store backend —
  without shell access. Admin config changes persist to a Busbar-owned overlay file and your
  `config.yaml` is never written.
- `busbar --validate` covers the whole new surface with paste-ready fixes, and `busbar --list-plugins`
  prints the plugin inventory without loading plugin code.
- Spend, budget-remaining and token metrics are labelled by group and window, and key labels set at
  mint time echo onto per-key series, so a dashboard can sum by team.

### Changed

- The SemVer contract is stated explicitly: the frozen surface is the data-plane HTTP surface and the
  wire protocols. `config.yaml` is an operator artifact outside that freeze and may change between
  releases, always with a migration path and a loud failure on an outdated config.
- Spend is derived, not stored. The store keeps a token ledger and money is computed at read time from
  the current rate card, so correcting a rate is a config edit and a reload with no re-billing.
- `PATCH /keys/{id}` takes `enabled` and `group` only; the 1.4.x cap fields are rejected.
- A hook granted `prompt: ro` or `prompt: rw` now also sees reasoning and thinking text, which reached
  the provider in full but not the hook. Review any path where your hook forwards or logs that
  projection. Opaque redacted reasoning is still never plaintext.

### Fixed

- An exhausted budget could be spent again: a request straddling a window boundary could rewind a live
  budget cell and zero its totals, a store error while loading budgets at boot started with empty
  counters, and a large enough ledger overflowed the derived total to a negative number that read as
  free.
- A caller could escape the `requests` limit by hammering failing requests, because the refund on a
  non-2xx outcome also refunded the admission slot.
- An identity provider could hand a caller a principal id shaped like a real key or group and take
  over that budget bucket.
- A typo in a security-relevant config key was silently ignored, so `client_c:` for `client_ca:`
  disabled mTLS without complaint. Unknown fields now fail startup.
- Concurrent budget flushes could double-count spend against a shared store, the Valkey store wrote
  duplicate audit entries, and store errors could include the connection password.
- An environment variable interpolated into the config could splice extra structure into it, for
  example widening an allowlist.

## [1.4.1], 2026-07-20

### Changed

- The repository moved to [`github.com/GetBusbar/busbar`](https://github.com/GetBusbar/busbar); older links
  redirect. Verify release artifacts with `--repo GetBusbar/busbar`. The Docker Hub image is unchanged.

### Added

- Every tagged release attaches the admin API's OpenAPI document, so you can generate a client or diff the
  API surface without running the gateway.

## [1.4.0], 2026-07-19

### Added

- **Google Vertex AI, Azure OpenAI and Oracle OCI Generative AI, all as configuration rather than code.**
  See [the providers guide](docs/providers.md).
- Two new ways to authenticate outward to a provider: `auth: jwt-bearer` (a signed assertion, which a
  Google service-account JSON satisfies directly) and `auth: oauth-client-credentials`. Both refresh in the
  background before expiry.
- `path_base`, `token_url` and `scope` provider fields, which is what lets the above reach non-standard
  provider URLs without new code.

### Changed

- **The default worker-thread count is one per available core** rather than a cap of four, so throughput
  scales with the machine. It reads the node's core count and cannot see a CPU bandwidth quota, so on a
  Kubernetes pod with a CPU limit it oversubscribes: **pin `BUSBAR_WORKER_THREADS` to your CPU limit
  there**, or to `1` or `2` in a footprint-sensitive sidecar.
- **Memory now falls back toward idle after a burst instead of staying at the peak:** a soak that plateaus
  around 1.2 GB drops to roughly 250 MB within 30 seconds of the load stopping. Windows builds keep the
  system allocator and do not get this.
- A cross-protocol stream whose backend reports usage in a trailing chunk now folds it into the terminal
  frame, so a non-OpenAI client receives real token counts instead of zeros. A Gemini JSON-array client on
  such a stream now receives one extra trailing element carrying that usage.

### Fixed

- **Budgets shared across several nodes no longer clobber each other:** the usage flush writes the delta
  since the last flush rather than an absolute value, so nodes sharing one store sum to the true total.
- The Valkey store's key deletion and credential writes are now atomic, so a partial failure cannot orphan
  an upstream credential behind a deleted key. It also gains reconnect and `rediss://` TLS.
- The token endpoint an OAuth provider posts its client secret to was checked less strictly than the
  provider base URL, so a typo could send the secret to a cloud metadata address. Both self-minting clients
  now also refuse redirects and carry timeouts.
- Health probes were not re-spawned on config reload, so reloaded lanes went unprobed and each reload
  leaked probe tasks.
- A `scope:` configured on a `jwt-bearer` provider was ignored, and a mid-stream transport error billed the
  tokens accumulated before the cut.
- A Cohere backend's pre-tool-call reasoning was dropped on any hop to another protocol, a raw-string tool
  argument was JSON-encoded twice by two writers, and an aborted Gemini JSON-array stream emitted two
  trailing error elements.
- `busbar --validate` reported false errors on a config templating its URLs from environment variables, and
  missed a model whose `context_max` conflicted across pools, so a clean validate could still fail at
  startup.
- A config still carrying the removed `auth.mode:` key now fails with a hint naming its replacement.

## [1.3.3], 2026-07-16

### Added

- `busbar --validate` checks a config file without booting or binding a socket, the `nginx -t` workflow,
  and runs in CI without the runtime environment present.

### Changed

- `BUSBAR_WORKER_THREADS` caps the worker pool, which lowers memory on many-core hosts.

### Fixed

- A slow fire-and-forget hook could grow in-flight work without bound; those spawns are now capped and
  over-cap notifications dropped and counted.
- An unreadable config overlay file was overwritten rather than refused, which could silently discard
  persisted admin state.
- A queued request rewrite that could not be re-applied on failover forwarded the original un-rewritten
  body; the request is now rejected.
- The outbound guard now also blocks the Azure and Oracle Cloud metadata addresses, and the host Busbar
  signs for can no longer differ from the host it dials.

## [1.3.2], 2026-07-14

Maintenance release: CI fixes and dependency bumps only, no change in behaviour.

## [1.3.1], 2026-07-14

Maintenance release: no change in behaviour.

## [1.3.0], 2026-07-13

The API release: anything you could previously do only by editing YAML and restarting, you can now do over
an authenticated, audited API. Hooks and policies are configured differently, so **existing configs need a
one-time update**: see the [1.2.x to 1.3 migration guide](docs/migration-1.3.md). An old-form key reports a
startup error naming exactly what to write instead.

### Breaking changes

- **The management API moved under `/api/v1/admin/`.** The key endpoints at `/admin/keys*` are
  now `/api/v1/admin/keys*`; scripts calling the old paths need a one-line URL update.
- **A network-exposed admin listener refuses to start without client-certificate mTLS.** Set
  `admin_tls.client_ca_file`, keep admin on loopback, or waive it with `admin_insecure: true` if a mesh
  terminates mTLS for you.
- **The inline `policy:` block and transport-named `route:` values.** A pool's `route:` now takes
  a hook name or a built-in policy name (`weighted`, `cheapest`, `fastest`, `least_busy`, `usage`). Each
  removed key reports a startup error with its exact replacement.
- **The embedded Rhai script routing policy (`route: script`),** deprecated in 1.2.1, is gone.
  A compiled hook over a socket or an HTTP webhook does the same job with real process isolation.

### Added

- **The admin API is a full config plane:** read the running config, apply a validated change atomically,
  roll back to a previous version, register hooks, adjust pools, budgets and rate limits. Drive Busbar from
  Terraform, Ansible or CI with no SSH and no restarts. See [the admin API reference](docs/admin-api.md).
- **The admin API is on its own listener, always,** with its own TLS and optional client-certificate mTLS,
  so the control plane binds and is firewalled independently of public traffic. It defaults to loopback.
- Admin credentials are scoped (read-only, hooks-register, full) rather than one shared token, every
  mutation is audited against whoever made it, and the admin auth chain is live-mutable with a guard
  refusing a change that would lock the caller out.
- **Gates, taps and the restrict verb.** A gate can reject a request or restrict which pool members may
  serve it, which is how data residency or a BAA-only lane is expressed without teaching the router about
  compliance. A tap observes and can never delay or fail a request. A request's hooks fire at once, so
  added latency is the slowest hook, not the sum. See [the hooks guide](docs/hooks.md).
- **The rewrite verb:** a trusted gate can replace the request body before dispatch, for context
  compression or redaction, across every protocol at once. A malformed or slow rewrite proceeds with the
  original body, so a broken compressor cannot corrupt a request.
- Hooks are defined once under `hooks:` and referenced by name in a pool's `hooks:` list or in
  `global_hooks:`. One list carries both the ranking strategy and any gates.
- Hook settings can be pushed to a running hook over the admin API, committing only when the hook
  acknowledges, and a restarted hook gets its current settings before any traffic. Its observed settings
  and metrics are readable at `GET /api/v1/admin/hooks/{name}/status`.
- **Per-model and per-key metering at `GET /api/v1/admin/usage`,** reporting the raw token split in daily
  buckets with spend derived at read time, so a consumer with negotiated pricing can reconstruct cost.
- **Authentication is a chain of modules,** each identifying the caller, rejecting, or passing to the next.
  Token auth is the first module and is removable. `group_map:` maps identity-provider groups to admin
  scope and data-plane access in one place, with per-module caps bounding what any module may assert.
- API-applied changes persist to a Busbar-owned overlay file; your hand-written `config.yaml` is never
  touched, so "who set this" is always answerable.
- `POST /api/v1/admin/config/reload` applies your config files atomically. Lane health is carried across by
  model identity rather than list position, so reordering or adding a model never resets what Busbar has
  learned, and that state now survives a restart. `--safe-mode` boots from your base config alone when an
  API-applied change is the problem.

### Changed

### Removed

## [1.2.1], 2026-07-11

### Added

- **A routing hook can run as a compiled binary on a local Unix socket** rather than over HTTP, deciding in
  roughly 8 microseconds. Same wire contract as the webhook. You run the hook process; Busbar connects
  lazily and reconnects across restarts, and requests keep flowing on the pool's fallback if you kill it.
- **A hook can reject a request outright,** and the caller gets an error in its own dialect. With the
  prompt payload below, this is the content-screening primitive: a hook that sees content can stop a
  request before it leaves your network.
- Two per-pool opt-ins extend the hook payload, both off by default: `policy.send_prompt` adds the prompt
  content so a trusted hook can screen for PII, and `policy.send_user` adds caller identity so a hook can
  route by who is asking. The caller's own credential is never in the payload. Each candidate also carries
  the `tags` you declared on it.

### Changed

- **The default hook deadline is 1 ms,** down from 150, because a co-located socket hook decides in about 8
  microseconds. Raise `policy.timeout_ms` if your hook does I/O; on timeout the decision falls back per
  `on_error` and the request proceeds either way.

### Deprecated

- `route: script` (the embedded Rhai interpreter) works behind a build flag but warns at startup. Migrate
  to a compiled socket hook or an HTTP webhook. Removed in 1.3.0.

## [1.2.0], 2026-07-10

Busbar now carries more than chat. Embeddings, moderations, image generation, audio and rerank all
translate across protocols the way chat already did, so a client in one dialect can reach a backend in
another and get its answer back in its own dialect, errors included. Chat itself is byte-for-byte
unchanged.

### Added

- **Embeddings**, routable to OpenAI, Amazon Bedrock, Cohere or Google Gemini from any dialect, with
  vectors, usage accounting and errors surviving the hop.
- **Moderations**, **image generation** (OpenAI, Gemini, Bedrock), **audio** transcription and speech
  (OpenAI, Gemini), and **rerank** (Cohere and Bedrock), all cross-protocol. A backend that lacks an
  operation answers with a clean 404 in the caller's dialect rather than a crash or malformed body.
- **`attempt_timeout_ms` catches a provider that fails by hanging,** where the connection opens and headers
  never arrive, silently eating the whole failover budget on one member. Set it on a model and override per
  pool member. It covers connect and headers only, so it never cuts off a stream that has started.
- Per-token log probabilities cross the OpenAI and Gemini seam both ways, buffered and streaming.
- The reasoning and thinking budget translates between the protocols that model it, **gated by an operator
  flag:** set `reasoning: true` on a model to declare the backend accepts thinking parameters. Without it
  the ask is dropped with a warning, so a non-reasoning model can never fail because of translation.
- An end-user identifier and the parallel-tool-calls switch now translate between OpenAI and Anthropic.

### Changed

- **Busbar is licensed under the Apache License 2.0** from this release onward: permissive,
  commercial-friendly, with an explicit patent grant.
- Error envelopes come back in the caller's own dialect, and usage accounting survives a cross-protocol
  round trip on every operation, not just chat.

### Fixed

- A Gemini backend's streamed reasoning was concatenated into the visible reply for every client in another
  dialect.

## [1.1.1], 2026-07-09

### Added

- **`GET /v1/models` and `GET /v1beta/models`** list every routable name in the caller's dialect. This is
  the first call SDKs and self-hosted UIs make to build a model picker, and it previously returned 404. A
  key restricted by `allowed_pools` sees only what it may reach.

### Fixed

- `/metrics` was empty until the first request arrived, so a freshly booted gateway exposed nothing to
  Prometheus, and direct model lanes with no pool were missing their health gauge.
- `/stats` output and lane ordering are now stable across restarts, so scrapes and dashboards are
  reproducible.

## [1.1.0], 2026-06-30

### Added

- **`upstream_model` separates a model's config key from the id sent on the wire,** which lets the same
  model sit behind two providers in one failover pool, for example Claude via both Anthropic and Bedrock.
  Contributed by [@lguzzon](https://github.com/lguzzon).

## [1.0.1], 2026-06-30

A hardened maintenance release, functionally identical to 1.0.0.

### Added

- Releases ship a CycloneDX SBOM and a build-provenance attestation, so an artifact can be verified with
  `gh attestation verify <file> --repo GetBusbar/busbar`. Dependencies are checked against the RustSec
  advisory database on every change and weekly.

## [1.0.0], 2026-06-21

First stable release. The HTTP API, configuration schema and wire-protocol contracts are stable under
Semantic Versioning from here: no breaking change without a major version bump.

### Changed

- **Migration from rc.7:** `governance.rate_sweep_interval` must now be at least `1`; rc.7 silently
  disabled the sweep on `0`. No other change for a default deployment.
- Structured output, stop reasons, image sources and redacted reasoning survive a cross-protocol hop intact
  rather than passing through as opaque blobs.

### Fixed

- Two Bedrock request shapes returned a 400 on a valid request, Anthropic cache markers were dropped on
  thinking and image blocks, and a streaming refusal could lose content.
- Billing corrections: sub-cent attribution, cancelled mid-stream requests, and no token billing for a
  stream aborted during translation.
- A client could hold a connection open indefinitely by trickling request headers on either listener.

## [1.0.0-rc.7], 2026-06-20

Every request now takes one code path with billing metered from it, and the config surface is cleaned up to
freeze a 1.0 contract. Same-protocol traffic stays byte-exact and just as fast.

### Breaking changes

- **`auth.token` is removed,** and `auth:`, `governance:` and `security:` reject unknown keys, so
  a stale or typo'd security key is a loud startup error rather than a silent default.

### Added

- **A `limits:` block puts every operational limit under operator control** rather than hardcoding it:
  upstream timeout, request body maximum, idle connections per host, hard-down cooldown, upstream error
  body cap, TLS handshake timeout, honored `Retry-After` ceiling, default `max_tokens`, and a new
  `max_inbound_concurrent`. Each defaults to its previous value, so nothing changes unless you set it.
- Grounding and web-search citations survive a cross-protocol hop, streaming and buffered.
- `observability.emit_server_timing` (default off) emits the `Server-Timing: busbar` response header.

### Changed

- **Migration from rc.6.** If `auth.token:` was your only credential, move its value into
  `auth.client_tokens: [...]` or the gateway refuses to start. Fix any typo'd or stale key under `auth:`,
  `governance:` or `security:`, now hard startup errors. Update any script parsing the admin API error
  shape, now the same `{"error":{"message","type"}}` envelope as the proxy endpoints. Prefer the renamed
  keys: `window_s` to `window_secs`, breaker `trip.n` to `consecutive_n`, `failover.cap` to `max_hops`,
  `failover.deadline_secs` to `timeout_secs`; the old names still work, but do not set both spellings.
- **Cache-hit requests on Anthropic and Bedrock backends now bill more than in rc.6,** because their cache
  tokens were previously not counted at all.
- Same-protocol traffic takes the same path as cross-protocol, with a short-circuit that re-emits the
  original bytes when nothing changed. Net effect is a fidelity improvement: most protocols now forward a
  same-protocol request byte for byte, where the old path re-serialized and reordered JSON keys.

### Removed

### Fixed

- Streamed Responses requests reported zero tokens, so they were never billed.
- A Bedrock image sourced from S3 leaked its location as a corrupt payload when translated, and an internal
  redacted-reasoning marker could reach a client wire or be injected by one.
- A Gemini chunk carrying several citations produced one array event that crashed native Anthropic SDKs,
  and a corrupt Bedrock event prelude spliced raw bytes into the client stream.
- Admin key endpoints echoed a fragment of the request body, which carries the key secret, in a parse
  error.
- `observability.max_inflight_webhook_deliveries: 0` silently dropped every delivery; it is floored at 1.

## [1.0.0-rc.6], 2026-06-19

### Added

- **`Server-Timing: busbar;dur=<ms>` reports Busbar's own added latency on every response,** readable in
  browser developer tools or any APM tool against your real traffic.
- Provider-native features survive a cross-protocol hop instead of being silently dropped: sampling
  controls, structured output, reasoning and thinking blocks both ways, Anthropic cache markers against
  their Bedrock equivalent, cache-read token accounting, and Cohere image input. Where a target genuinely
  has no equivalent, the parameter is dropped with a warning rather than in silence.

### Changed

- **Cross-protocol translation of a large payload is roughly twice as fast** (about 186 to 84 microseconds
  on a 32 KB body); small requests are unchanged at the per-request floor of about 33 microseconds. Full
  methodology at [getbusbar.com/benchmark](https://getbusbar.com/benchmark).
- The JSON serializer formats some floats differently, for example `1e26` rather than `1e+26`. This is
  numerically lossless; only an exact string comparison on an exotic numeric passthrough field would notice.

### Fixed

- **A small deeply-nested request body could crash the whole process,** killing every in-flight request for
  every tenant. Bodies nested past 128 levels are now rejected before any value is constructed.
- Temperature clamped to a provider's native range is now reported with a warning rather than silently,
  `top_k` spelling is preserved to Bedrock, `max_completion_tokens` is preserved for OpenAI reasoning
  models, and `max_tokens: 0` is filtered uniformly.
- `busbar_breaker_trips_total` counted some trips twice and others not at all.
- A JSON error is logged as a sanitized breadcrumb rather than the raw library message, which can embed
  fragments of the request body.

## [1.0.0-rc.5], 2026-06-17

### Added

- **Pluggable routing policies.** A pool can declare `route:` to order its members, feeding the existing
  failover loop so a policy can never strand a request. Built in: `weighted` (the default, unchanged),
  `cheapest`, `fastest`, `least_busy`, and `usage`, which steers away from members approaching a provider
  rate limit. Operator-defined logic runs over a `webhook` transport in any language, honoring a per-pool
  `timeout_ms` and falling back per `on_error`, so it can never fail the client request. A pool that omits
  `route:` pays nothing for any of this.
- **Native inbound TLS and optional mutual TLS,** without a reverse proxy. Add a `tls:` block with
  `cert_file` and `key_file`, plus `client_ca_file` to require a client certificate, enforced at the
  handshake before any HTTP or token processing. Omitting `tls:` leaves the plain HTTP path unchanged.
- Four Prometheus gauges refreshed at scrape time, not on the request path: per-key spend, per-key budget
  remaining, per-key tokens, and per-lane circuit-breaker state. Every label comes from your configuration.

### Fixed

- **A pool member set to `weight: 0` still received traffic** carrying an existing session-affinity
  stickiness, so an operator draining a lane could not actually drain it.
- Each incoming TLS handshake has a ten-second cap, so a client cannot park a connection before
  authenticating, and a routing webhook's response is capped at 64 KiB.
- A TLS certificate, key or CA that fails to load aborts startup naming the file; key material is never
  logged.
- The outbound guard now also blocks the Oracle Cloud metadata address.

## [1.0.0-rc.4], 2026-06-16

### Fixed

- **A lane that tripped could be benched permanently or have its recovery probe stolen.** A clean stream
  end no longer records a spurious breaker failure, mid-stream error paths no longer double-record, and a
  failed recovery probe releases its permit instead of benching the lane for good.
- An upstream `Retry-After` is honored as the breaker cooldown floor.
- A large same-protocol response undercounted tokens, because usage past a scan cap was dropped.
- Outbound request guards closed a backslash-based bypass and a redirect vector on the telemetry exporter.

## [1.0.0-rc.3], 2026-06-10

### Breaking changes

- **`/metrics` is no longer unconditionally open.** It goes through the same authentication check
  as `/stats`, because the exposition discloses your lane and pool topology and error rates. Only
  `/healthz` stays open. Update any Prometheus scrape config that assumed otherwise.

### Added

- **Every wire protocol is now first-class ingress.** Previously clients could speak only Anthropic or
  OpenAI; now Responses, Cohere, Gemini and Bedrock clients can point their SDK's base URL at Busbar
  unmodified, with errors in the caller's native shape. See [the protocols guide](docs/protocols.md).

### Changed

### Fixed

- Streamed assistant text from a Cohere backend was silently dropped on the read path.
- A Gemini response filtered for safety returned a spurious 500 instead of decoding normally, and an
  OpenAI stream with a usage-only trailing chunk produced a spurious extra event.
- A model named `admin` was reachable at the operator admin surface, making it unreachable to clients and
  bypassing per-model governance. That name is now rejected at config validation.
- A host with a trailing dot, such as `127.0.0.1.`, slipped past the outbound metadata and IP checks and
  resolved to an internal target.
- An Anthropic upstream request could carry two credential headers at once, a shape no native client
  produces.

## [1.0.0-rc.2], 2026-06-04

### Changed

- **Cold start is roughly 30 times faster, about 206 ms down to 6 ms,** so Busbar serves `/healthz` in
  single-digit milliseconds, which is what a container readiness probe needs. In exchange, `/metrics`
  renders empty for a moment after start and the few requests in that window are not counted.

## [1.0.0-rc.1], 2026-06-03

First release candidate for 1.0: feature-complete and API-stable, with the remaining work being operational
validation rather than features. The release binary shrank from about 12 MB to 7.4 MB with a faster hot
path.

## [0.17.4], 2026-06-03

### Fixed

- **An OpenAI-format request omitting `max_tokens` failed on every call against an Anthropic-backed lane,**
  because Anthropic requires the field and OpenAI does not. Busbar now injects one at the translation
  boundary when the target protocol requires it, and a caller-supplied value is always preserved. The new
  per-model `default_max_tokens` sets what gets injected, defaulting to 4096.

## [0.17.3], 2026-05-31

### Fixed

- **Request bodies are now capped at 32 MiB.** They were effectively unbounded, so a multi-gigabyte body
  could exhaust memory, most easily with authentication disabled.
- Token comparison is now proof against a compiler optimization that could reintroduce a timing signal.

## [0.17.2], 2026-05-31

### Fixed

- **A `health:` block written under a provider in `config.yaml` was silently ignored,** exactly as the
  shipped example documents it, so health probing never started for it.

## [0.17.1], 2026-05-31

### Fixed

- **A single upstream 5xx could bench a single-member route for the full cooldown with no active
  recovery,** because probing fired only for fully tripped lanes.
- Reasoning content from an OpenAI-dialect backend was dropped when translated to Anthropic.
- `--help`, `--version` and every startup misconfiguration print a clean error rather than a panic.

## [0.17.0], 2026-05-31

### Changed

- **Logs are now always emitted to stderr,** with the level from `RUST_LOG`. Previously every span and
  warning was dropped unless telemetry export was configured.

### Fixed

- **Three hostile inputs could panic a worker:** a malformed `Authorization` header, an unbalanced brace in
  an upstream body, and an API key containing a control character.
- **A long-running lane spuriously tripped its breaker** on clean recent traffic once old errors aged out.
- Concurrent selections could corrupt the weighted round-robin state and bias distribution across members.
- Session affinity used a randomly seeded hash, so sticky routing did not survive a restart, and cooldown
  jitter only ever lengthened cooldowns.
- Passthrough auth dropped the caller's own token and silently fell back to the lane's static key.
- Degraded routing skipped cross-protocol translation, so it was wrong whenever the chosen lane spoke a
  different protocol.
- The per-key rate-limit map never evicted stale windows, an unbounded memory leak. `/stats` reported
  in-flight requests as always zero, and admin usage double-counted some responses.

## [0.16.2], 2026-05-31

### Fixed

- **The admin token was compared with a non-constant-time comparison,** a timing side channel that could
  let an attacker recover it byte by byte.
- Virtual-key generation now refuses to mint rather than falling back to a predictable, time-derived secret
  if the operating system random source is unavailable.

## [0.16.1], 2026-05-31

### Added

- `error_map` can match a provider's structured error type, not just its numeric code, which is what some
  providers surface. `/stats` reports each lane's client-fault counter alongside its success and error
  counts.

## [0.16.0], 2026-05-31

### Added

- **A lane shared by several pools now carries independent circuit-breaker state per pool,** so one pool's
  traffic tripping a lane no longer benches it for every other pool. A successful health probe recovers the
  lane everywhere, since it tests the one shared upstream. This supersedes the 0.15.0 note deferring it.

## [0.15.0], 2026-05-31

### Added

- **Active health checks.** A provider's `health.mode` can be `none` (passive only, the default), `dead`
  (re-probe only tripped lanes so a recovered upstream is picked up promptly), or `active` (probe every
  lane so a silently dead upstream trips before real traffic hits it).
- **A pool's `breaker:` block now takes effect.** It was parsed then ignored, with the breaker using a
  hardcoded rule. `failover.exclusions` are likewise now enforced, and `affinity.header_name` is honored.

### Fixed

- **A tripped lane never came back.** Its recovery probe could succeed without ever closing the breaker, so
  any lane that tripped once became permanently dead.

## [0.14.0], 2026-05-31

This changelog begins at 0.14.0; earlier history is not recorded here.

### Added

- **Cohere is now a supported wire protocol** at `/v2/chat`, including streaming, with system prompts
  preserved across a cross-protocol hop.
- **Azure OpenAI** is reachable through a per-provider `auth: api-key` style, shipped as a template in
  `providers.yaml`.

### Fixed

- A pool landing on a member in another protocol returned a response with no `model` field.
- Token accounting was not charged on the buffered cross-protocol path, so per-key token limits never
  enforced there.
- The `max_requests` lifetime cap was never enforced and per-lane success counts always read zero.

## [Early development]

Project scaffolding for the open-source release. The project is licensed under the Apache License 2.0 as of
1.2.0.
