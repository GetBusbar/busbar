# Migrating from 1.5.x to 1.6.0

There are two things to do, and both are owner-signed changes from 1.5.5: **a config must now
carry a `store:` block** (`busbar --migrate-config` inserts it), and **a plugin built for 1.5.5
must be replaced by one built for 1.6.0**. Everything else is identical to 1.5.5. 1.5.3 was the last
config-breaking release, the config grammar is frozen and grows only by optional keys, and 1.6.0
holds to that: a config written for 1.5.5 that has a `store:` block boots, validates and serves on
1.6.0 with no other edits, and every minted key and every durable store carries over. This was
measured rather than promised — the same configs, requests and plugins were run through the published 1.5.5 binary
and through 1.6.0, and the differences are the ones named in [the changelog](../CHANGELOG.md)
under "Improvements", every one additive.

The recommended path is the same as for any point release: install the binary, `busbar
--validate`, start. If Busbar boots, you're done. What follows is what you may notice afterwards,
and what is new to write if you want it.

---

## The `store:` block is required

A 1.6.0 config must carry a `store:` block, even for the in-memory store. `busbar --validate`
refuses a config without one, and boot refuses it too, telling you to add one. This is an
owner-signed, customer-visible change from 1.5.5 (1.5.5 defaulted to `memory` when the block was
absent); the reason is that config now says what loads.

```sh
busbar --migrate-config config.yaml > config-1.6.yaml   # inserts `store: {module: memory}`
busbar --validate
```

`--migrate-config` inserts exactly `store: {module: memory}`, which is what an absent block meant in
1.5.5, so behaviour does not change. A config that already names a store is left as written.

## A plugin built for 1.5.5 does not load

The published 1.5.5 plugins spoke a JSON contract. 1.6.0 plugins speak the memory ABI only, so boot
refuses a 1.5.5 plugin with a message naming the rebuild against the 1.6.0 SDK. That includes the
four published store plugins (sqlite, postgres, mysql, valkey). Install the 1.6.0 releases of the
first-party plugins before upgrading; rebuild a third-party plugin with
[the SDK migration note](plugin-sdk-migration-1.6.md). Your data carries over: a rebuilt store
plugin opens its own database and upgrades it with its own `migrate()`. See
[Plugins](plugins.md#plugins-and-160).

## 1. No other config changes required

- **Every 1.5.5 key means what it meant.** Pool members stay as you wrote them — `- model: x`
  with an optional `weight:` and per-member capabilities is the canonical form (a bare-name list
  plus a pool-level `weights:` map is accepted as an equivalent shorthand; see
  [Pools](pools.md#config-reference)). `busbar --migrate-config` on a 1.5.5 config prints the
  same output the 1.5.5 migrator printed, plus the `store:` block when the config has none, and
  with hook `plugin:` / `at:` keys rewritten to `module:` / `phase:` (see [§5](#5-retired-15x-spellings-rewritten-for-you));
  it does not rewrite members or add `TODO` comments.
- **Keys carry over.** `auth.signing_key` is read as before, so every outstanding minted key
  keeps verifying; nothing is re-minted.
- **Stores carry over.** A `sqlite`, `postgres`, `mysql` or `valkey` store opens on its 1.5.5
  contents: keys, groups, audit rows and usage history are all read as they were written. The
  usage ledger's on-disk shape is re-folded into 1.6.0's representation on first read through a
  versioned, idempotent migration (a partial run followed by a rerun yields the same totals as a
  clean one); nothing is dropped and recreated.
- **Store plugins are replaced, not carried.** The four published 1.5.5 store plugins
  (`abi_version: 2`) are refused at boot; install their 1.6.0 releases, which open the same
  database. See [Plugins](plugins.md#plugins-and-160).
- **Validation is the same gate.** `--validate` resolves the same `env:` / `file:` references
  boot reads, and no others, exactly as 1.5.5 did. A CI job that passed on 1.5.5 passes on 1.6.0.
- **The reserved name `admin`** is still refused for a model, pool or provider, with the 1.5.5
  message.

Three exceptions. `--validate` tells you whether either of the first two applies to you; it does not
catch the third:

- a provider whose `api_key` reference does not resolve no longer starts with an empty credential.
  If you were relying on that — most often to run a keyless local ollama or vLLM — you need one
  edit. See [§6](#6-a-provider-credential-that-cannot-resolve-refuses-boot).
- a config with a `rate_card:` must price every billable unit the plane counts, and a 1.5.5 card
  never priced the units a provider reports beside its tokens (`search_units`, `classifications`,
  `web_fetch_requests`, `unitemized_tokens`, `images`, `audio_ms`, the Bedrock `guardrail_*`
  units). If you have a `rate_card:`, you need one edit. See
  [§7](#a-card-must-configure-every-billable-unit-its-plane-counts).
- `advanced.block_private_addresses` now defaults to `true`. A provider whose `base_url` or
  `token_url` is on a private or loopback address (a local ollama or vLLM, an in-cluster gateway)
  is refused when dialled unless `advanced.allow_destinations` names it. Add the host, IP or CIDR
  to `advanced.allow_destinations`, or set `advanced.block_private_addresses: false` to restore
  1.5.5's behaviour. Cloud metadata addresses are refused either way.

## 2. Deprecated env vars keep working, with a warning

`BUSBAR_PROVIDERS`, `BUSBAR_CONFIG_OVERLAY`, `BUSBAR_WORKER_THREADS`, `BUSBAR_UPSTREAM_HTTP1_ONLY`
and `BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE` were deprecated in 1.5.3 in favour of config.yaml keys.
1.6.0 reads each of them at the same point of the boot sequence as 1.5.5 and honours it exactly as
before. The only difference is that the deprecation warning for `BUSBAR_CONFIG_OVERLAY`,
`BUSBAR_UPSTREAM_HTTP1_ONLY` and `BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE` now carries a diagnostic code,
BUSBAR-3021, whose entry in [the diagnostics reference](diagnostics.md) names the replacement key.
The `BUSBAR_PROVIDERS` and `BUSBAR_WORKER_THREADS` warnings are still printed without a code:

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

- **Diagnostic codes on error and warning lines.** `[error]`, `[warn]` and `warning:` lines are
  prefixed `BUSBAR-NNNN:` and boot log lines carry `diag=BUSBAR-NNNN`; the text after the code is
  unchanged. A few `[warn]` lines are still uncoded (two deprecated env vars, jemalloc, memfd). If a log pipeline matches on the leading text of those lines,
  allow for the code. See [the diagnostics reference](diagnostics.md).
- **The jemalloc background-purge line is `[info]` on macOS**, not `[warn]`.
- **One new `/metrics` series** on an unchanged config, `busbar_metering_pending_coalesced_total`.
  No 1.5.5 series changed shape or labels; in particular `busbar_requests_total` and
  `busbar_request_duration_seconds` are byte-identical (MCP and A2A traffic is on the separate
  `busbar_plane_*` families). See [Observability](observability.md).
- **`busbar_lane_state` reads each pool's own breaker.** When one lane is shared by several
  pools, the gauge for a pool now reflects that pool's own breaker only. On 1.5.5 a pool whose
  breaker had tripped read `1` as long as another pool could still reach the same lane; it now
  reads `2`, matching `busbar_lane_available` = `0` on the same labels. `1` now means only that a
  recovery probe is in flight on that pool's breaker. Some series that read `1` on 1.5.5 therefore
  read `2`; an alert on `busbar_lane_state == 2` fires for a pool that cannot send, whatever its
  neighbours do. The gauge also gains series for MCP and A2A destinations (`pool` is the
  plane-qualified target or pool key such as `tool:<server>`, `lane` the member position), which
  appear once a request has been sent to them.
- **Admin views gained fields.** Hook objects carry `fires_at`, `groups` and `phase`; the
  unknown-overlay-section 400 lists the sections that now exist; `openapi.json` describes the new planes.
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
- **A configured voice/streams `session_fee` now draws.** It never drew in 1.5.x (a defect, not a
  tariff); on 1.6.0 it charges once per session, exactly as configured, the first time a leg
  genuinely opens. See [1.6.0 advisories](advisories/1.6.0/voice-session-fee-draws-once-per-session.md).
- **The published MySQL store plugin's request-count durability is fixed.** A rare split-flush
  (about 1 run in 40 at the default cadence) could silently drop a key's requests counter across
  a restart on 1.5.x; token/spend accounting was never affected. See
  [1.6.0 advisories](advisories/1.6.0/mysql-store-split-flush-request-count-loss.md).

See [the full 1.6.0 advisories index](advisories/1.6.0/README.md) for these and two further
disclosures (an upstream-429-as-503 status-code clarification, and a fee defect on a refund that
crosses a billing window) that require no operator action but are recorded for completeness.

## 4. New optional sections for the planes

Each plane is declared by writing its section and is absent otherwise: a config with none of them
gains no endpoint and no route, and the migrator adds none of them.

| Section | What it declares | Guide |
|---|---|---|
| `mcp:` | Busbar as an MCP server: canonical URI, identity provider, OAuth 2.1 discovery | [MCP](mcp.md) |
| `tools:` | Registered upstream MCP servers Busbar governs (`transport: stdio` for local ones) | [MCP](mcp.md), [Tool and agent trust](tool-and-agent-trust.md) |
| `agents:` | Registered A2A agents, served over JSON-RPC, HTTP+JSON and gRPC | [A2A](a2a.md) |
| `streams:` | The live-voice plane: full-duplex realtime sessions over one IR | [Voice](voice.md) |
| `oauth_as:` | The embedded OAuth 2.1 authorization server the MCP door can use | [MCP](mcp.md) |
| `decisions:` | The decisions plane: `jev` and `nanojev` served as passthrough | [Changelog](../CHANGELOG.md#additive-planes) |

Two things about them are worth knowing before you write one. An `mcp:` block with an empty
`auth.chain` refuses to start, because an anonymous MCP request is never narrowed by a key and
would run with wildcard grants over every registered server. And an MCP or A2A failover pool is
written in the top-level `pools:` map with `tools:` / `agents:` entries as bare-name members, so
the same breaker and failover you already run for models applies to them; see
[Circuit breaker](circuit-breaker.md).

Validation messages are frozen at 1.5.5's wording: an `expected one of` list still names only the
keys 1.5.5 knew. The new sections, and the group-limit token sub-metrics `tokens_input`,
`tokens_output`, `tokens_cache_read` and `tokens_cache_write`, parse and validate but are not named
in those lists (see [Configuration → `groups`](configuration.md#groups)).

## 5. Retired 1.5.x spellings, rewritten for you

Four spellings that 1.5.x accepted as read-only back-compat, and that were never the documented
form, are still accepted in 1.6.0, so no config, client or persisted state breaks. Prefer the
documented form in anything new.

- **Hook `plugin:` → `module:`.** The `plugin:` key on a hook definition is a read-only alias of
  `module:` (the documented spelling since 1.5.3). It is still accepted in config and in admin API
  `POST`/`PUT /api/v1/admin/hooks` bodies. `busbar --migrate-config` rewrites it, and a persisted
  config overlay that still spells it `plugin:` is rewritten at boot.
- **Hook `at: <stage>` → `phase: [<stage>]`.** The single-stage tap key is still accepted, in config
  and in admin bodies, and behaves as it did in 1.5.5. The documented form is the `phase:` list.
  `busbar --migrate-config` rewrites it (behaviour-preserving) and a persisted overlay is rewritten
  at boot. An omitted `phase:` still means the four core stages.
- **`persist:` on `PUT /api/v1/admin/config/settings`** is accepted and ignored, as it was since
  1.5.3 (config mutation is durable by default). It must still be a boolean; any other value gets a
  400. Drop the field when convenient; it never changed the outcome.
- **The `at` field on `GET /api/v1/admin/hooks[/{name}]`** is still served. Beside it are
  `fires_at` (the resolved stage set, in pipeline order) and `phase` (the literal config echo),
  which are what to read in new tooling.

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

## 7. Rate cards became a dated history, and `GET /admin/usage` prices by it

**What shipped.** A rate card is no longer a single mutable price. Cards are an append-only DATED
HISTORY: each entry carries an `effective_from`, publishing one never touches the window before that
date, and a back-dated correction reprices exactly the window it names —
`[effective_from, effective_until)` — as an attributed append rather than an edit to a booked row.
The back-dated correction is served at `POST /api/v1/admin/ledger/amend-rate-history`.

**`GET /admin/usage` prices each row at the card in force when it was earned.** The endpoint still
stores raw token quantities and derives spend at read time, but it no longer derives it off the
newest card. Each row resolves through the dated history at the instant it was earned, so publishing
a card leaves every figure before its `effective_from` where it was, and a back-dated
correction moves exactly the window it names. A card edit in the middle of a day splits that day
at the edit rather than repricing all of it. If you relied on 1.5.5's behaviour — a
`PUT /api/v1/admin/config/settings` rate-card edit repricing every past row on the next read — that
no longer happens: past rows keep the price they were earned at.

`GET /admin/usage` also accepts an optional `as_of` query parameter naming a snapshot of the dated
history (an entry number). A read at the same snapshot answers the same figures every time, which is
how an invoice is re-derived; a snapshot above the history's newest entry is refused, never answered
at the newest. The `as_of` field in the response is unchanged: it is still the instant the read was
taken.

**Every plane has its own card and its own fees.** The top-level `rate_card:` and
`per_request_fee:` price the LLM plane exactly as they did in 1.5.5. Any other plane can carry its
own `rate_card:` and a `fees:` block (`per_request`, `per_session`) inside its own section; a plane
with no card of its own prices its usage at zero and bills only the fees it configured, whatever
another plane's card says. A card that is present and does not price a class the traffic hit refuses
it rather than answering zero. `/usage` prices each row with the card and fees of the plane that
served it, and every plane's card and fees are dated in the same history.

### A card must configure every billable unit its plane counts

A plane's card that is present must give a rate — `0` is a rate — for every billable unit the plane
counts, or boot and `--validate` refuse, naming the section and each missing unit:

```
pools.rate_card does not configure billable unit(s) search_units, classifications, ... declared by this plane; add them (0 to make them free)
```

**This is the one edit a 1.5.5 config with a `rate_card:` needs.** Every count a provider reports
is a ledger line under its own unit (owner ruling LEDGER-100). The LLM plane counts `input`,
`output`, `cache_read`, `cache_write` (the `*_utok` tiers; a tier the entry leaves out is `0`, as in
1.5.5) and these open units, which have no tier:

| unit | what the provider reported |
|---|---|
| `search_units` | a rerank's billed search units; an Anthropic turn's web searches |
| `classifications` | Cohere `billed_units.classifications` |
| `web_fetch_requests` | Anthropic `usage.server_tool_use.web_fetch_requests` |
| `unitemized_tokens` | the tokens a provider's stated total (`total_tokens`, `totalTokenCount`, `totalTokens`) counts above the buckets it itemizes |
| `images` | the images a per-image provider returned (dall-e, Imagen, Titan, SDXL) |
| `audio_ms` | a transcription's reported duration, in whole milliseconds |
| `guardrail_*` (nine) | the Bedrock guardrail policy units, one unit per policy type |

1.5.5 billed every one of them at `0`, so the upgrade that keeps every figure 1.5.5 billed is to
price each at `0`:

```yaml
rate_card:
  claude-sonnet: { input_utok: 3, output_utok: 15,
                   units: { search_units: 0, classifications: 0, web_fetch_requests: 0,
                            unitemized_tokens: 0, images: 0, audio_ms: 0,
                            guardrail_automated_reasoning_policies: 0,
                            guardrail_automated_reasoning_policy_units: 0,
                            guardrail_content_policy_image_units: 0, guardrail_content_policy_units: 0,
                            guardrail_contextual_grounding_policy_units: 0,
                            guardrail_sensitive_information_policy_free_units: 0,
                            guardrail_sensitive_information_policy_units: 0,
                            guardrail_topic_policy_units: 0, guardrail_word_policy_units: 0 } }
```

None of the open units counts toward a `tokens:` cap, so caps count what they counted in 1.5.5.

The same holds for a card written at run time: `PUT /api/v1/admin/config/settings` with a
`rate_card` that leaves an open unit out is refused (400) with the same message, where 1.5.5
applied it. A script or dashboard that writes cards through the admin API needs the same `"units"`
map on each entry.

Put it on every entry, not just one: boot is satisfied by any entry, but a lane whose own entry is
silent about a unit it serves refuses that traffic rather than pricing it at zero. Write a real rate
instead of `0` to start billing reranks (`units:` rates are micro-units per unit). The other planes
are new in 1.6.0, so their cards are new config; the same rule holds for each (`tools.rate_card`:
`tool_calls`, `bytes`; `agents.rate_card`: `bytes`; `streams.rate_card`: the seven voice units;
`decisions.rate_card`: `decision`, `input_tokens`, `output_tokens`), and `--validate` names whatever your build counts.

Likewise, a nonzero `<section>.fees` key for a unit the plane does not count (for example
`streams.fees.per_request`: a voice session pays `per_session`) refuses boot, naming the key and the
units the plane counts. `fees:` is 1.6.0 config, so no 1.5.5 config is affected.

**Cards survive a restart.** On a node with a data directory, every applied rate card is journalled
and a restart rebuilds the dated history; a journal written before this upgrade starts its history
at the boot card from instant zero. A node with no data directory keeps no journal: after a restart
its history is the boot card from instant zero, as in 1.5.5.

**No currencies.** Rate-card figures are abstract cost units with no currency and no conversion. A
correction body that names a `currency` is refused.

**New, additive ledger surface.** No 1.5.5 path or field is changed. The one administrative OpenAPI
document (`GET /api/v1/admin/openapi.json`; the unfiltered copy at
`GET /api/v1/admin/ledger/openapi.json`) now describes these operations beside every 1.5.5 one, each
marked `x-busbar-since: 1.6.0`; a 1.5.5 operation's entry is unchanged. What is served today is
exactly these:

- `GET /api/v1/admin/ledger/totals`, `/checkpoints`, `/reconciliation`, `/migration` and
  `/openapi.json` — the five additive reads.
- `POST /api/v1/admin/ledger/amend-rate-history` — the correction write.

**Back-dating is available, and it is attributable.** The `amend-rate-history` verb appends a dated
entry and journals one record per correction, naming the window, the corrected cells, the card it
corrects, the principal that posted it and the SHA-256 of its reason. The body carries no signer and
no signature. The original line and the correction are both visible forever, and no booked line is
rewritten.

**What to do if a rate was wrong.** Post a correction through
`POST /api/v1/admin/ledger/amend-rate-history` naming the window it repairs, rather than editing the
live card. The correction is an append and it leaves an attributed record. Editing the live card
prices only what happens after the edit; it cannot repair a window that is already past.

---

## Quick checklist

- [ ] Add a `store:` block: `busbar --migrate-config config.yaml` inserts `store: {module: memory}`. `busbar --validate` refuses a config without one ([the `store:` block is required](#the-store-block-is-required)).
- [ ] Replace every plugin built for 1.5.5 (including the sqlite, postgres, mysql and valkey stores) with its 1.6.0 release; boot refuses the old ones ([a plugin built for 1.5.5 does not load](#a-plugin-built-for-155-does-not-load)).
- [ ] Install 1.6.0, `busbar --validate`, start.
- [ ] If you have a `rate_card:`: add the `units:` map (every open unit at `0`) to every entry (or
      a real rate for the units you bill). `--validate` names each unit a card leaves out
      ([§7](#a-card-must-configure-every-billable-unit-its-plane-counts)).
- [ ] If `--validate` names a provider `api_key` that does not resolve: fix the reference, or — for
      an upstream that takes no credential (local ollama / vLLM) — declare `api_key: none`. It is
      a boot refusal now, not a warning ([§6](#6-a-provider-credential-that-cannot-resolve-refuses-boot)).
- [ ] If a provider `base_url` / `token_url` is on a private or loopback address: name it in
      `advanced.allow_destinations` (or set `advanced.block_private_addresses: false`). `--validate`
      does not catch this; the dial is refused at run time ([§1](#1-no-other-config-changes-required)).
- [ ] If a log pipeline matches on the leading text of `[error]` / `[warn]` lines, allow for the
      `BUSBAR-NNNN:` prefix.
- [ ] If any key's traffic routinely fails over to an OpenAI Chat Completions lane while streaming,
      expect its spend to rise to what it actually used.
- [ ] Deprecated env vars: none need moving today; each warns (three with BUSBAR-3021) until you do.
- [ ] Hooks spelled `plugin:` or `at:` in config.yaml: run `busbar --migrate-config` once
      (overlays migrate themselves at boot).
- [ ] If a dashboard or reconciliation relied on `GET /admin/usage` totals recalculating after a
      rate-card edit: they no longer do (a card prices only what follows it). Post an
      `amend-rate-history` correction for booked usage, and pass `?as_of=<history_seq>` to read money
      as of a past history point ([§7](#7-rate-cards-became-a-dated-history-and-get-adminusage-prices-by-it)).
- [ ] Want MCP, A2A or voice? Add the section; see the guide in the table above.
