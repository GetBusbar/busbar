# Migrating from 1.5.x to 1.6.0

There is nothing to migrate. 1.5.3 was the last config-breaking release, the config grammar is
frozen and grows only by optional keys, and 1.6.0 holds to that: a config written for 1.5.5 boots,
validates and serves on 1.6.0 with no edits, every minted key and every durable store carries
over, and the published 1.5.5 store plugins load unchanged. This was measured rather than
promised — the same configs, requests and plugins were run through the published 1.5.5 binary
and through 1.6.0, and the differences are the ones named in [the changelog](../CHANGELOG.md)
under "Improvements", every one additive.

The recommended path is the same as for any point release: install the binary, `busbar
--validate`, start. If Busbar boots, you're done. What follows is what you may notice afterwards,
and what is new to write if you want it.

---

## 1. No config changes required

- **Every 1.5.5 key means what it meant.** Pool members stay as you wrote them — `- model: x`
  with an optional `weight:` and per-member capabilities is the canonical form (a bare-name list
  plus a pool-level `weights:` map is accepted as an equivalent shorthand; see
  [Pools](pools.md#config-reference)). `busbar --migrate-config` on a 1.5.5 config prints the
  same output the 1.5.5 migrator printed, byte for byte; it does not rewrite members, add
  `TODO` comments, or touch anything a 1.5.5 config can contain.
- **Keys carry over.** `auth.signing_key` is read as before, so every outstanding minted key
  keeps verifying; nothing is re-minted.
- **Stores carry over.** A `sqlite`, `postgres`, `mysql` or `valkey` store opens on its 1.5.5
  contents: keys, groups, audit rows and usage history are all read as they were written. The
  usage ledger's on-disk shape is re-folded into 1.6.0's representation on first read through a
  versioned, idempotent migration (a partial run followed by a rerun yields the same totals as a
  clean one); nothing is dropped and recreated.
- **Store plugins carry over.** The four published 1.5.5 store plugins (`abi_version: 2`) load on
  1.6.0: the durable wire is additive, and the new plane-record verbs (MCP call records, A2A
  tasks) are simply inert on an old plugin, kept in process as under `store: memory`. See
  [Plugins](plugins.md#the-artifact).
- **An `export` plugin must be rebuilt.** The export payload schema moves `2` -> `3`: the reply to
  `deliver` now carries the sink's acknowledgement (`durable` / `received` / `retry`) where it used
  to carry nothing, so a host can tell a sink that took a record from one that dropped it. A
  changed reply shape is a breaking wire change, so a v2 sink is refused at LOAD with a clear
  message rather than mis-called per delivery. Rebuild against the 1.6.0 SDK, re-sign, and bump the
  manifest's `abi_version` to `3`; no other edit is needed, since `export_export_plugin!` and the
  `Export` face's `receive` signature are unchanged at the call site. This affects `kind: export`
  only — store, auth, secret and hook plugins are untouched. See
  [Plugins](plugins.md#the-artifact).
- **Validation is the same gate.** `--validate` resolves the same `env:` / `file:` references
  boot reads, and no others, exactly as 1.5.5 did. A CI job that passed on 1.5.5 passes on 1.6.0.
- **The reserved name `admin`** is still refused for a model, pool or provider, with the 1.5.5
  message.

One exception, and `--validate` already tells you whether it applies to you: a provider whose
`api_key` reference does not resolve no longer starts with an empty credential. If you were
relying on that — most often to run a keyless local ollama or vLLM — you need one edit. See
[§6](#6-a-provider-credential-that-cannot-resolve-refuses-boot).

## 2. Deprecated env vars keep working, with a warning

`BUSBAR_PROVIDERS`, `BUSBAR_CONFIG_OVERLAY`, `BUSBAR_WORKER_THREADS`, `BUSBAR_UPSTREAM_HTTP1_ONLY`
and `BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE` were deprecated in 1.5.3 in favour of config.yaml keys.
1.6.0 reads each of them at the same point of the boot sequence as 1.5.5 and honours it exactly as
before; the only difference is that the 1.5.5 deprecation warning now carries a diagnostic code,
BUSBAR-3021, whose entry in [the diagnostics reference](diagnostics.md) names the replacement key:

| Deprecated env var (still honoured) | config.yaml key |
|---|---|
| `BUSBAR_PROVIDERS` | `providers_file:` (or the `--providers <path>` flag) |
| `BUSBAR_CONFIG_OVERLAY` | `config.overlay.file` |
| `BUSBAR_WORKER_THREADS` | `advanced.worker_threads` |
| `BUSBAR_UPSTREAM_HTTP1_ONLY` | `advanced.upstream_http1_only` |
| `BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE` | `advanced.upstream_h2_prior_knowledge` |

`BUSBAR_PROVIDERS` pointing at a file that does not exist refuses to boot, as it did in 1.5.5,
rather than silently using the `providers.yaml` beside the config. `BUSBAR_CONFIG`, secret
`{ env: NAME }` references, `RUST_LOG` and `TOKIO_WORKER_THREADS` are not deprecated. Move each
variable into config.yaml when convenient; the warning is the only consequence of not doing so.

## 3. What you will notice after the upgrade

None of these need action; they are listed so what you see is expected.

- **Diagnostic codes on every error and warning line.** `[error]`, `[warn]` and `warning:`
  lines are prefixed `BUSBAR-NNNN:` and every boot log line carries `diag=BUSBAR-NNNN`; the text
  after the code is unchanged. If a log pipeline matches on the leading text of those lines,
  allow for the code. See [the diagnostics reference](diagnostics.md).
- **The jemalloc background-purge line is `[info]` on macOS**, not `[warn]`.
- **One new `/metrics` series** on an unchanged config, `busbar_metering_pending_coalesced_total`.
  No 1.5.5 series changed shape or labels; in particular `busbar_requests_total` and
  `busbar_request_duration_seconds` are byte-identical (MCP and A2A traffic is on the separate
  `busbar_plane_*` families). See [Observability](observability.md).
- **Admin views gained fields.** Hook objects carry `fires_at`, `groups` and `phase`; the
  overlay-section 404 lists the sections that now exist; `openapi.json` describes the new planes.
  Every 1.5.5 field, including the lane `limit` alias on `/stats`, is still there.
- **`--help` is longer and `--version` prints two lines** (the second is a `build:` provenance
  stamp). `-c`/`--config` and `--providers` are new, additive flags.
- **Streams through a fallback or least-bad hop to an OpenAI Chat Completions lane are now
  billed** their real tokens (1.5.5 billed them zero). If a key's traffic routinely fails over,
  its spend rises to what it actually used.
- **Two cross-protocol stream shapes match the provider's spec** where 1.5.5 did not: Bedrock text
  blocks no longer open with an empty `contentBlockStart`, and Responses streams carry the
  `content_part` / `output_text.done` lifecycle frames. See
  [Protocols → Spec fidelity](protocols.md#spec-fidelity).
- **Thread-per-core data plane (unix).** N threads named `busbar-core-0` … `busbar-core-N-1`, N
  listen sockets on the data port via `SO_REUSEPORT`, and one `busbar listening` log line per
  listener. `advanced.worker_threads` now sizes that worker count (default one per core;
  `TOKIO_WORKER_THREADS` still works as a fallback). Non-unix builds are unchanged.

## 4. New optional sections for the planes

Each plane is declared by writing its section and is absent otherwise: a config with none of them
gains no endpoint and no route, and the migrator adds none of them.

| Section | What it declares | Guide |
|---|---|---|
| `mcp:` | Busbar as an MCP server: canonical URI, identity provider, OAuth 2.1 discovery | [MCP](mcp.md) |
| `tools:` | Registered upstream MCP servers Busbar governs (`transport: stdio` for local ones) | [MCP](mcp.md), [Tool and agent trust](tool-and-agent-trust.md) |
| `agents:` | Registered A2A agents, served over JSON-RPC, HTTP+JSON and gRPC | [A2A](a2a.md) |
| `streams:` | The live-voice plane: full-duplex realtime sessions over one IR | the grammar at the head of `crates/busbar-voice/src/config.rs` until the operator guide lands |
| `oauth_as:` | The embedded OAuth 2.1 authorization server the MCP door can use | [MCP](mcp.md) |

Two things about them are worth knowing before you write one. An `mcp:` block with an empty
`auth.chain` refuses to start, because an anonymous MCP request is never narrowed by a key and
would run with wildcard grants over every registered server. And an MCP or A2A failover pool is
written in the top-level `pools:` map with `tools:` / `agents:` entries as bare-name members, so
the same breaker and failover you already run for models applies to them; see
[Circuit breaker](circuit-breaker.md).

Validation messages know the new keys: an `expected one of` list now includes `mcp`, `oauth_as`,
`tools`, `agents` and `streams`, and the group-limit `metric` list includes the four token
sub-metrics `tokens_input`, `tokens_output`, `tokens_cache_read` and `tokens_cache_write` (see
[Configuration → `groups`](configuration.md#groups)).

## 5. Retired 1.5.x spellings, rewritten for you

Four spellings that 1.5.x accepted as read-only back-compat, and that were never the documented
form, are gone in 1.6.0. Each has a migration path, so no config and no persisted state is bricked.

- **Hook `plugin:` → `module:`.** The `plugin:` key on a hook definition was a read-only alias of
  `module:` (the documented spelling since 1.5.3). `busbar --migrate-config` rewrites it, and a
  persisted config overlay that still spells it `plugin:` is auto-migrated at boot. Admin API
  `POST`/`PUT /api/v1/admin/hooks` bodies must name `module:`.
- **Hook `at: <stage>` → `phase: [<stage>]`.** The single-stage tap key is replaced by the
  `phase:` list documented since 1.5.3. `busbar --migrate-config` rewrites it (behaviour-preserving)
  and a persisted overlay is auto-migrated at boot. An omitted `phase:` still means the four core
  stages.
- **`persist:` on `PUT /api/v1/admin/config/settings`** was accepted and ignored since 1.5.3
  (config mutation is durable by default). A client that still sends it receives `400
  invalid_request` naming `persist` as an unknown field. Drop the field; it never changed the
  outcome.
- **The `at` field on `GET /api/v1/admin/hooks[/{name}]`**, which was `null` for essentially every
  hook, is replaced by `fires_at` (the resolved stage set, in pipeline order) and `phase` (the
  literal config echo).

---

## 6. A provider credential that cannot resolve refuses boot

**What changed.** 1.5.5 resolved each provider's `api_key` reference at boot and, when that failed,
logged `[warn] provider <name> api_key (<reference>) empty` and started the lane with an EMPTY
credential. 1.6.0 refuses: an `api_key` reference that does not resolve — unset variable, missing or
empty file, unknown module, secret-plugin error — stops boot under `BUSBAR-8020`, and stops an admin
apply/reload the same way. The diagnostic names the provider and the reference (`env:VAR`,
`file:/path`) and never the value.

**Why.** The degraded lane could not work. It booted "healthy", the health prober skipped it (no
key, no probe), and every request routed to it came back as a 401 from the upstream — with one
warning line at boot as the only signal. Every other secret in busbar is fail-closed; the provider
credential was the exception, and the exception bought nothing but a slower, more confusing failure.
`busbar --validate` has refused exactly this since 1.5.3, so boot and validate now agree.

**Keyless upstreams are DECLARED.** A local ollama or vLLM genuinely takes no credential. Say so:

```yaml
providers:
  ollama:
    api_key: none          # this upstream takes NO credential
```

`none` is a plain scalar (there is no `{ none: … }` form) and is accepted only on a provider
`api_key`. A TLS cert, `auth.signing_key`, the authorization server's signing key, an admin token or
an OIDC client secret has no credential-free mode, and `auth: jwt-bearer` / `auth:
oauth-client-credentials` mint their token FROM the credential, so `none` is refused in all of those
places. A lane declaring `none` starts, sends NO auth header upstream, and is skipped by the health
prober — exactly what the empty-credential lane did, now on purpose.

**What to do.** Run `busbar --validate` before upgrading; it names any provider that would now
refuse.

- If the reference should resolve, fix it: set the variable, mount the file, install and trust the
  secret plugin.
- If the upstream takes no credential, change the reference to `api_key: none`.

`busbar --migrate-config` does NOT insert `none` for you. Whether an upstream needs a credential is
a fact about your deployment, not something a migration can read off the config file — guessing
wrong would silently disarm a provider that does need one.

---

## Quick checklist

- [ ] Install 1.6.0, `busbar --validate`, start. That is the whole upgrade.
- [ ] If `--validate` names a provider `api_key` that does not resolve: fix the reference, or — for
      an upstream that takes no credential (local ollama / vLLM) — declare `api_key: none`. It is
      a boot refusal now, not a warning ([§6](#6-a-provider-credential-that-cannot-resolve-refuses-boot)).
- [ ] If a log pipeline matches on the leading text of `[error]` / `[warn]` lines, allow for the
      `BUSBAR-NNNN:` prefix.
- [ ] If any key's traffic routinely fails over to an OpenAI Chat Completions lane while streaming,
      expect its spend to rise to what it actually used.
- [ ] Deprecated env vars: none need moving today; each warns with BUSBAR-3021 until you do.
- [ ] Hooks spelled `plugin:` or `at:` in config.yaml: run `busbar --migrate-config` once
      (overlays migrate themselves at boot).
- [ ] Want MCP, A2A or voice? Add the section; see the guide in the table above.
