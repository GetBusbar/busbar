# Hooks: your logic on the request path

Busbar owns the request path. Hooks are the sanctioned attachment points on it: the places where your own code sees what Busbar sees and steers what Busbar does. Every hook follows one design rule, enforced structurally rather than by convention: **a hook can steer, observe, or rewrite, but a hook can never break the request path.** A slow, crashed, or wrong hook degrades to a safe default; it never blocks, hangs, or fails a request on its own.

In 1.5.0, a hook is a **`kind: hook` dlopen plugin**: the same signed-tarball, hybrid-ABI, in-process model that store, secret, and auth plugins use. The 1.5.0 release **retired the built-in out-of-process `socket` and `webhook` transports**: a hook is now always a signed plugin. Out-of-process isolation is still available through the first-party **`busbar-webrequest-hook`** plugin, which forwards the decision to an HTTPS sidecar. Write a hook once and it runs against all six protocols and every provider, with failover and circuit breaking underneath it, in one hop.

## How a hook attaches

A hook instance is a **module ref** whose `module:` names a loaded `kind: hook` plugin (by its signed-manifest name/alias); `settings:` is the plugin's opaque config. Loading any hook plugin requires `plugins.enabled: true` and the signed tarball in the plugins directory. A `module:` that does not resolve to an installed plugin is a fail-closed boot error.

| Posture | How it runs | Trust anchor |
|---|---|---|
| In-process `kind: hook` plugin | Loaded from a signed tarball at boot or on hot-reload. The hook is a `cdylib` exporting the frozen **hybrid ABI**: `busbar_abi`, `busbar_plugin_kind`, `busbar_open`, `busbar_call`, `busbar_free`, `busbar_close`. Operations ride `busbar_call` as op-discriminated JSON. | ed25519 signature over the signed manifest; kind cross-checked at load |
| Out-of-process via `busbar-webrequest-hook` | The first-party forwarder plugin POSTs the projection to your HTTPS sidecar (any language) and returns its reply. The sidecar URL is `settings.url`, SSRF-guarded (loopback allowed; RFC-1918 / link-local / CGNAT / cloud-metadata rejected; remote must be `https://`). | The plugin is signed + auto-trusted; the sidecar runs in its own process |

**In-process trust is signature-based, not process-based.** A `kind: hook` plugin loads inside Busbar's address space, verified by ed25519 against the signed manifest. For fault isolation of untrusted logic, forward it out-of-process with `busbar-webrequest-hook` (see [Webrequest](#first-party-hook-plugins-150) below); the choice is performance and integration in-process vs. process isolation via the forwarder.

**Admin opt-in required.** A `kind: hook` plugin cannot self-wire into a security-critical path. Wiring a hook with `prompt` above `no`, or attaching one at the all-pools `pools.hooks:` key, requires `full` admin scope.

**Grants are core-enforced, never plugin-driven.** A plugin cannot self-grant access. The signed manifest `needs` field (set at pack time with `plugin-pack --needs-prompt rw`) declares intent; the core enforces the actual projection. The plugin only sees what the operator AND the declared need allow.

## Two kinds: tap and gate

Every hook is one of two kinds. That is the only structural distinction: the rest is the same contract for both.

| Kind | Mechanic | Reply |
|---|---|---|
| `tap` | fire-and-forget (watch) | none: it observes, it never answers |
| `gate` | fire-and-wait (decide) | one reply arm: nothing / reject / restrict / order / rewrite |

A **tap** watches: logging, audit, metering, shipping records to a SIEM. It can never delay or change a request. A **gate** decides: it can reject the request, restrict which pool members may serve it, re-order the failover walk, or rewrite the request body. The PII guard, the smart router, and the Headroom compressor are all gates: same wire, same timing, same fail-safe, different reply arm.

## Named definitions, referenced by name (1.5.3)

A hook is **DEFINED once** in the top-level `hooks:` map (`<instance-name>: { module, settings, … }`)
and **REFERENCED by bare name** wherever it should fire. There are no inline hook instances
anywhere in 1.5.3, and the old top-level `global_hooks:` list is gone: its job is now the reserved
all-pools `pools.hooks:` attach key. The same `module:` may back **several named hooks**. A
different scope or different settings is simply a new name, and *the name is the instance*.

```yaml
plugins:
  enabled: true
  dir: /etc/busbar/plugins                 # the signed kind:hook tarballs live here

hooks:                                     # THE definition map
  audit:
    module: busbar-audit-hook              # your signed audit tap
    kind: tap
    phase: [response]                      # a LIST of stages; omit = all four
    prompt: ro
  pii-eng:
    module: busbar-pii-hook
    groups: [engineering]                  # SCOPE: omit or [] = every caller
    kind: gate
    prompt: ro
    on_error: reject
  rtr:
    module: webrequest                     # out-of-process forwarder to a sidecar
    settings: { url: "https://hooks.internal/rtr" }
  headroom:
    module: headroom                       # first-party kind: hook plugin (in-process)
    prompt: rw

pools:
  hooks: [audit]                           # RESERVED all-pools attach: fires for EVERY pool
  my-pool:
    hooks: [cheapest, pii-eng, rtr, headroom]   # bare NAMES only
    members:
      - model: claude-opus
      - model: claude-opus-bedrock
        tags: ["baa"]
```

The `module` names a loaded `kind: hook` plugin by its signed-manifest name/alias (e.g. the
first-party `headroom` and `webrequest` aliases, or your own). Resolution is exact: name first,
then alias, with no fuzzy matching. `settings:` is the plugin's opaque config. For `webrequest`
that includes the SSRF-guarded sidecar `url`. Loading any of these requires
`plugins.enabled: true` and the tarball installed in `plugins.dir`; an unresolved `module:`, or an attach-point name that no `hooks:` entry defines,
refuses to boot.

**Attach a hook** two ways, both bare-name lists: the reserved `pools.hooks:` key (fires for every
pool) or a pool's own `hooks:` list (fires for that pool). The two **combine additively**, deduped by
name. A hook named in both fires exactly ONCE, at its first position. A pool's `hooks:` list also
carries its ordering strategy (`weighted`/`cheapest`/`fastest`/`least_busy`/`usage`, a bare name, at
most one) alongside any number of gates. A definition with no `kind:` defaults to `kind: gate`.

**Two scope dimensions on the definition.** `groups:` limits WHICH CALLERS a hook fires for (omit or
`[]` = all; a user is a leaf group, e.g. `user:bob`, and membership walks the `groups:` tree through
ancestors). `phase:` limits WHICH STAGES it fires at. Because both live on the definition, running
one module with two different scopes means two named entries (`pii-eng`, `pii-all`), not one entry
with a magic flag.

**Gates fire concurrently.** All of a request's decision gates (the pool's own and every all-pools attach) fire at once against the same candidate set, then reconcile deterministically: any **reject** wins (the lowest-`priority` gate's status/message surfaces), **restrict**s intersect, and with several **order**s the last in the priority chain wins, re-validated against the post-restrict set. Added latency is the slowest gate, not the sum.

**A hook picks its observation stages** with `phase:`, a **LIST** (1.5.3 generalized the old
single-valued tap `at:` into it). Omitting `phase:` means exactly these four core stages:

| `phase:` member | Observes | Extra payload |
|---|---|---|
| `request` | the effective (post-rewrite) request | prompt text per the `prompt: ro` grant |
| `candidate` | the routing decision (was `route`) | surviving candidate count |
| `routing` | every dispatch attempt (was `attempt`) | `attempt_number`, `model` (the dispatched member), `remaining_candidates`, `previous_failure` |
| `response` | the outcome (was `completion`) | `outcome` + `status`, including the **synthetic rejected completion**, so an audit tap sees denials, not just served traffic |

The three renamed stage words are a HARD rename: an old `route`/`attempt`/`completion` value is
rejected at boot with the new spelling named in the error (`busbar --migrate-config` rewrites it).

Stage payloads ride a top-level `stage` object on the (shape-only) per-request projection, with
only the stage's own fields present:

```jsonc
{"op": "notify", "request": {...}, "candidates": [], "context": {},
 "stage": {"at": "routing",                 // "candidate" | "routing" | "response"
           "model": "claude-opus",          // the dispatched member (routing)
           "attempt_number": 2,             // (routing)
           "remaining_candidates": 3,       // (candidate, routing)
           "previous_failure": "...",       // (routing, attempt ≥ 2)
           "outcome": "ok", "status": 200}} // (response)
```

The completion `outcome` vocabulary is `ok | failed | rejected_by_gate | rejected_by_auth` and is
**append-only**: treat unknown outcomes as "not ok", never crash on one. In 1.3 the `user:` grant
projects identity on **gate decision payloads only**; tap and transform payloads omit identity
(adding it later is an append-only change; key your parser on field presence).

## The other two planes: MCP tool calls and A2A submissions (1.6.0)

The full operator reference for each of those planes is its own page: [MCP](/docs/mcp/) and
[A2A](/docs/a2a/). This section is the hook-shaped slice of both.

**A hook is a decision about one request, and it does not matter which protocol carried it.** The
same `hooks:` definitions attach to a registered MCP server and to a registered A2A agent, by the
same bare-name lists, with the same additive combine:

```yaml
tools:
  hooks: [pii-screen]                      # RESERVED all-MCP attach: fires for EVERY server
  filesystem:
    url: https://mcp.internal/fs
    pin: { mechanism: cert_spki, key: "sha256/PIN==" }
    hooks: [fs-policy]                     # this server only; ADDS to the section list

agents:
  hooks: [pii-screen]                      # RESERVED all-agent attach
  planner:
    url: https://planner.agent.internal/a2a
    pin: { mechanism: unpinned }
    hooks: [plan-policy]
```

**Where they fire.** On the DISPATCH path, never the catalogue: what a caller may SEE is decided by
its key grants and nothing else, and a hook decides what a caller may DO. On MCP that is inside
`tools/call`, after the tool has been resolved and re-validated and **after any `ask_caller` answers
have been merged** — so the gate screens the arguments that would actually go upstream — and before
the outbound credential is leased. On A2A it is after the submission has been admitted to an agent
and before the meter, the egress gate and the task row. A rejection therefore costs no token
exchange, no durable state and no hop.

**What the hook receives** is the ordinary hook wire, built from the request's IR:

```jsonc
{"op": "decide",
 "request": {"request_id": 7,
             "pool": "filesystem",          // the CONTAINER: pool | MCP server | A2A agent
             "ingress_protocol": "mcp",     // or "a2a"
             "message_count": 1, "has_tools": true, "total_chars": 21, "stream": false,
             // behind the `prompt: ro|rw` grant — the tool call's arguments (MCP) or the
             // submission's params, including a message's `parts` (A2A):
             "messages": [{"role": "user", "text": "{\"path\":\"/etc/hosts\"}"}],
             "user": {"key_id": "k-1", "key_name": "reporting"}},   // behind `user: ro`
 "candidates": [], "context": {}}
```

**`candidates` is empty on these planes, and that is a fact rather than a gap:** the request routes
to the one registered upstream the caller's grant selected, so there is nothing to rank. Only
**reject** applies. An `order` or `restrict` reply is ignored (logged at `debug`), and a gate that
fails applies its own `on_error` exactly as on the pool plane — `on_error: reject` means a control
an operator declared load-bearing cannot be skipped by being broken.

A refusal is answered in the plane's own error vocabulary — MCP `-32000` with the hook's status and
message, A2A a `-32004` ProtoJSON error body — and is recorded: the MCP per-call log carries the
reason token `hook_rejected`, distinct from `not_granted`, because "your key does not reach this
tool" and "a policy your operator attached said no" send an operator to different places.

## Access grants: what a hook is trusted to see

By default a hook sees **shapes, not content**: sizes, counts, flags, live lane signals, never prompt text, never caller identity. Two per-hook grants, both default off, opt a trusted hook into more:

| Grant | Levels | Adds |
|---|---|---|
| `prompt:` | `no` (default) · `ro` · `rw` | `ro` sends the flattened system + messages text (for PII screening, guardrails, audit). This **includes reasoning/thinking text** (Anthropic `thinking`, Bedrock `reasoningText`, Responses `reasoning`) when a client replays it into a multi-turn body, since a screening hook must see everything the provider receives (see "What a gate receives" below for the redacted-reasoning exception). `rw` additionally lets a **gate** return the `rewrite` arm. |
| `user:` | `no` (default) · `ro` | `ro` sends caller identity: the governance key's `id`/`name` and the body's end-user field. Never the secret/token, under any configuration. |

Grants are a monotonic trust ladder (`no ⊂ ro ⊂ rw`) and are **immutable after registration**: you cannot register a hook with `prompt: no`, wire it in, then quietly raise it to `rw`. `rw` on a `tap` is a boot error (a tap never replies, so it can never rewrite).

For `kind: hook` plugins, the manifest `needs` field (set with `--needs-prompt rw` at pack time) declares the maximum grant the plugin may receive. The core enforces the actual projection: the plugin only sees what both its declared needs and the operator's instance grant allow.

### What a gate receives

> **The projection is built from the normalized IR** — the same representation the request that
> goes upstream is built from. There is exactly one answer to "what is the text in this request",
> and your hook and the provider are given the same one. That is what makes a hook behave
> identically whichever dialect the client speaks, and it is why the list below is short.
>
> - **The system prompt is always in `system`.** Whichever dialect the client speaks, and whether
>   they sent it as a body field or as an in-band `{role: "system"}` turn, it reaches your hook in
>   one place. A hook that compresses or rewrites "the messages" no longer risks shredding the
>   operator's own instructions on some dialects and not others. (That shipped as a real bug in
>   Headroom, fixed there on 2026-08-05; it cannot recur here.)
> - **`messages` is aligned with the NORMALIZED turns, not with the wire body.** For a body that
>   carries its system prompt in-band, `message_count` is one lower than the client's array length.
>   Media-only turns still keep their entry, with empty text, so you never see fewer turns than the
>   provider does.
> - **An OpenAI `refusal` content part is projected** and counts toward `total_chars`.
> - **Tool-call arguments are projected**, attributed to the turn that made the call, alongside tool
>   results.
> - **A body busbar cannot read is rejected with a 400**, not forwarded with a best-effort
>   projection. A turn with a role no protocol recognises is a client error, and screening it as
>   `role: ""` while it went upstream anyway was a fail-open shape.
> - **Content is bounded** by `limits.hook_content_max_bytes` (default `0` = unlimited; the
>   projection is sent uncapped unless an operator opts in to a ceiling). When a ceiling is set,
>   over-cap content is
>   omitted WHOLE — never truncated mid-value — and your hook receives a present-but-empty content
>   projection while the size fields still report the real totals, so an omission is visible in the
>   payload rather than silent. `busbar_hook_content_truncated_total` counts it.
>
> None of these are grant questions. They apply at `prompt: ro` and `prompt: rw` alike.

- **The request projection**: `pool`, `ingress_protocol`, `message_count`, `has_tools`, `total_chars` (a size signal; token counts do not exist pre-dispatch), `max_tokens`, `stream`. With `prompt: ro`/`rw`, also the flattened `system` + `messages` text. With `user: ro`, also caller identity.
  - **Reasoning/thinking text is included.** No content block that reaches the provider is silently omitted: Anthropic `thinking`, Bedrock `reasoningContent.reasoningText`, and Responses `reasoning` text project like any other text block. This is a widened scope for the `prompt` grant as of this release. An operator who wired `prompt: ro` for PII screening before now also sees replayed chain-of-thought, which is the correct behavior for a screening gate (content the provider sees that the gate does not is a bypass, not a feature) but is worth knowing if your hook logs or forwards the projection verbatim.
  - **Redacted reasoning (Anthropic `redacted_thinking`, Bedrock `redactedContent`, a Responses `reasoning` item carrying only an opaque `encrypted_content` blob with no `content[]`/`summary[]` text) projects as a fixed marker, `[busbar:redacted_reasoning]`, never the ciphertext.** Busbar cannot decrypt it, so there is nothing to screen and handing a hook the raw bytes would be a new disclosure (they would reach your `prompt`-forwarder sidecar, which never received provider ciphertext before). Treat the marker as a **presence signal only, not a trust signal**: a client can also send ordinary text that happens to equal this string, so do not gate a decision on the marker's presence/absence alone. Also note `rewrite` (`prompt: rw`) is not index-aligned (see the `rewrite` arm below). A hook that echoes the marker back writes it into a real, visible content block on the outgoing request.
- **The candidate projection**: one entry per healthy member: `cost_per_mtok` (derived from the model's `rate_card` entry), `latency_ms` (rolling EWMA), `available_concurrency` (free slots now), `budget_remaining`, `rate_headroom` (fraction: the tightest requests/tokens limit headroom across the key's group chain), and your `tier`/`tags` labels. The full task/latency/cost/quality picture, every signal a built-in strategy ranks on is on the wire, so an external hook can implement any of them identically.
- **The budget-chain state** (when the request carries a virtual key): the whole enforcement chain the request must clear, one entry per bucket from the key's own attribution bucket out through every ancestor group's budget-window buckets (`bucket_id` = `group:<name>@<window>`), each `{bucket_id, budget_group?, spend_micros_at_current_rate, remaining_micros, window_start, budget_period}`. `spend_micros_at_current_rate` is derived at hook-call time from the token ledger times the current top-level `rate_card` (micro-units, 10,000 per cent). This is the read surface for budget-aware routing: a gate can see how close the key or its team is to a cap and downshift to a cheaper `tier`. Busbar exposes the state only; the routing policy lives entirely in your hook.

## The gate reply arms

A gate answers with exactly one of:

- **nothing / abstain**: no opinion; Busbar proceeds as it normally would.
- **reject** (`{"reject": {"status": 451, "message": "..."}}`): no upstream is dispatched; the caller gets a dialect-native error. Status clamped to 400 to 499 (default 403) so the caller's SDK catches the right typed class (429 → rate-limit, 401 → auth, …); message sanitized. Fail-closed: a malformed reject degrades to the defaults, never to silently routing the request. With `prompt: ro`, this is the PII-screen primitive: see content, say no, before it leaves your network.
- **restrict** (`{"restrict": {"tags_any": ["baa"]}}`): only members carrying one of those `tags` may serve. The restriction **persists across failover** (every hop stays inside the surviving set); an empty intersection follows the gate's `on_empty` (default `reject`, fail-closed).
- **order** (`{"order": [idx, ...]}`): rank the surviving candidates, most-preferred first (omitted members are demoted, not excluded). That order becomes the failover walk: Busbar tries your first choice, and on a pre-first-byte failure walks to your second. You choose the order; the breaker, concurrency caps, and failover budget still apply.
- **rewrite** (`{"rewrite": {"messages": [...], "tools": [...]}}`): replace the request body (compression, redaction). Requires `prompt: rw`. Note the asymmetry: a hook *receives* messages as `{role, text}` (the flattened projection) but *replies* in body form (`{role, content}`); the system prompt is not rewritable; and a socket reply is capped at 64 KiB, which bounds very large rewrites. Body-only: a rewrite never changes routing, the principal, or the target dialect. It fires **before dispatch and before the routing decision**, so both the decision and every upstream see the rewritten body, and it persists across failover. Token accounting (budgets, metrics) is on the provider-reported usage of the rewritten body: the savings are real and measured. A malformed/oversized rewrite follows `on_error` (default: proceed with the body **unmodified**; a broken compressor never corrupts a request). Pre-existing hazard, not introduced by reasoning-text projection but now more visible because of it: the write-back is **not index-aligned**. A hook that echoes what it was projected as literal `{role, content}` text loses every image/`tool_use`/`tool_result`/`signature`/cache-control block in that turn (only its text survives), and now also promotes any projected reasoning text (or the redacted-reasoning marker) into a real, visible content block shipped upstream. If your `rw` hook only inspects and passes through, prefer returning no `rewrite` (abstain) over echoing the projection verbatim.

## Ordering

- **`priority: <n>`** is the one ordering knob: it orders the rewrite transform chain (each rewrite sees the prior's output) and tie-breaks the concurrent decision reconcile: which reject's message surfaces, and which `order` counts as "last". Ties keep the all-pools `pools.hooks:` attaches first, then config order.
- A pool that names no strategy gets the zero-cost inline `weighted` backstop. (The 1.4.x `default: true` registry flag is gone: name the base strategy per pool.)

## What Busbar guarantees when a hook misbehaves

| Failure | What happens |
|---|---|
| Hook is slow | Cut off at `timeout_ms` (default 1 ms; raise it when your hook hits a DB or the network), decision coerced to `on_error` |
| Hook errors, returns garbage, or is saturated | Same: `on_error` |
| `on_error: nothing` (default) | **Does not participate**: the failing gate drops out of the decision entirely and can never displace another gate's verdict. The right posture for gates whose job is orthogonal to routing (a compressor, a logger-gate): their failure should never reshape traffic. |
| `on_error: weighted` | Falls back to the weighted floor: a broken hook is indistinguishable from no hook. Behaviorally identical to `nothing` (in the concurrent reconcile both mean "didn't participate"); the two names exist so a config reads correctly: `weighted` for ordering gates, `nothing` for everything else. |
| `on_error: first` | Config order, deterministic |
| `on_error: reject` | Fail closed with a 503, for security gates, where an unscreened request is worse than none. Docs mandate this for security gates. |
| `on_error: { hook: <name> }` | **A named fallback** (structured ref): when this gate fails, that hook fires in its place (its decision is honored exactly as a primary's, projected per **its own** grants). Its own `on_error` chains further; Busbar proves at boot that every chain terminates: an unknown name, a tap, or a cycle is a startup error. `weighted`/`reject`/`first` are the reserved chain terminals; a ranking strategy name (`cheapest`, …) is also a valid, infallible fallback. |

A `tap`, being fire-and-forget, has no `on_error` to speak of: its reply is discarded, its errors swallowed, its delivery bounded and dropped-under-pressure. It can never delay, reorder, or fail a request.

## The wire, precisely

### The sidecar wire contract (`busbar-webrequest-hook`)

When a hook forwards out-of-process through `busbar-webrequest-hook`, Busbar exchanges the same
op-discriminated JSON with your HTTPS sidecar: one POST body per message. (The in-process
`kind: hook` plugin ABI carries the identical payload over `busbar_call`. See [`kind: hook`
plugin ABI](#kind-hook-plugin-abi) below.) The projection is **byte-identical** whichever path
carries it, so sidecar logic and plugin logic are the same. The rules a sidecar author must know:

- **Message discrimination.** A message with a top-level `configure`, `describe`, or `status` key
  is a **management** message. Everything else is a **per-request** message and its `op` field says
  which kind: `decide` (a gate's blocking decision, answer it), `transform` (a rewrite pass,
  answer it), `notify` (a tap observation, **never answer it**; on a socket, Busbar does not read
  a reply and an answered notify queues bytes forever).
- **Evolvability.** The wire is **append-only**: Busbar may add fields and message kinds at any
  time. A hook MUST ignore unknown fields, MUST treat unknown `op` values and unknown management
  keys as "not for me" (reply `{}` on a socket; `200 {}` on a webhook), and may attach extra fields
  to its own replies (Busbar ignores unknowns symmetrically).
- **Optional fields are absent, not `null`.** Key your parser on field **presence** (e.g.
  `"tier" in candidate`), never on null-ness, and never on key order.
- **Abstain is an explicit reply.** `{}` (or `{"abstain": true}`) is the abstain. An **empty body,
  a non-2xx webhook status, a closed socket, or a missing newline is a transport ERROR**, not an
  abstain. It routes to the gate's `on_error`. Under the default `on_error: nothing` the two look
  identical; under `on_error: reject` an "abstain via 204" fails every request. A webhook's reject
  must ride a **200** response body; a 4xx/5xx status is the hook *erroring*, not rejecting.
- **Transform precedence.** A `transform` reply is read as **reject > rewrite > abstain**: a
  rewrite gate that also screens (a compressor with a PII check) returns `{"reject": ...}` and the
  request stops, exactly as on the decide path. `restrict`/`order` are decide-path verbs and are
  ignored on a transform reply.

### `kind: hook` plugin ABI

For in-process plugins, the transport is `busbar_call` over the frozen **hybrid ABI**, six
kind-neutral C symbols: `busbar_abi`, `busbar_plugin_kind`, `busbar_open`, `busbar_call`,
`busbar_free`, `busbar_close`. (`TRANSPORT_VERSION = 1` is the low-level C signature contract,
frozen; `abi_version` in the manifest is the per-kind payload version: `HOOK_ABI_VERSION = 1` for
the hook kind.) Operations are the same op-discriminated JSON payload as socket/webhook: `decide`,
`transform`, `notify`, `configure`, `describe`, `status`. The serialization is JSON over the C ABI
rather than NDJSON over a socket, but the payload contract is identical. A hook's decision logic
is transport-agnostic.

## Management messages: `configure`, `describe`, `status`

Management messages apply across all transports. On socket and webhook they are NDJSON lines or
HTTP POSTs; on `kind: hook` plugins they ride `busbar_call` with the same JSON payload.

- **`configure`**: Busbar pushes the hook's opaque `settings` map, stamped with the hook's
  **instance name**, a `settings_version`, and Busbar's version. It is the **first message on every
  socket connection, always**, including a hook with no settings (an empty `settings: {}` is valid
  desired-state), so a (re)started hook always hears its identity, current settings, and Busbar's
  version before any traffic. It is also pushed live by
  `PATCH /api/v1/admin/hooks/{name}/settings`. **One ack rule for both deliveries**: reply
  `{"ack": {"settings_version": <the exact version sent>}}` (5s deadline). On the PATCH, no exact
  ack = nothing commits (the operator gets a 400); on the connection preamble, no exact ack =
  the connection is not used.
- **`describe`** (`{"describe": true}`): reply with your self-description ENVELOPE:
  `{"schema": <settings JSON Schema>}`. Busbar extracts `schema` and serves it at
  `GET /api/v1/admin/hooks/{name}/schema`. The member is optional; don't answer (or `{}`) and the
  API reports `schema: null`.
- **`status`** (`{"status": true}`): the control-plane read: reply your **observed** state,
  `{"status": {"settings_version": N, "settings": {...}, "metrics": [ ... ]}}`, and Busbar surfaces
  it at `GET /api/v1/admin/hooks/{name}/status` with a desired-vs-reported **drift** verdict. Busbar
  serves only the settings **key names** there (`settings_keys`), never the values, on either side:
  the bag you echo is the SECRET-RESOLVED one Busbar pushed you, and that read is reachable at
  read-only admin scope. The drifting key names are reported in `drift_keys`. The
  `metrics` ARRAY is how your hook feeds its own operational data to the control plane (a Headroom
  compressor reports `chars_saved_total`; a dashboard built on Busbar sees what each plug is doing)
  instead of running its own dashboard. Each entry is Prometheus/OpenMetrics-shaped:
  ```jsonc
  {"name": "chars_saved_total",       // ^[a-z][a-z0-9_]{0,63}$ ; counters SHOULD end _total
   "type": "counter"|"gauge"|"histogram",
   "value": 812000,                   // counter/gauge scalar; a histogram's is its sample count
   "labels":    {"pool": "chat"},     // Prometheus DIMENSIONS: several entries may share a name
   "quantiles": {"0.5": 12, "0.95": 34, "0.99": 51},   // a histogram's distribution (p50/p95/p99)
   "estimated": true, "ci_low": 27.7, "ci_high": 35.7, // mark + bound an ESTIMATE vs a measured fact
   "label": "Characters saved", "unit": "%", "viz": "counter"|"gauge"|"sparkline"|"histogram",
   "max": 100, "help": "..."}
  ```
  Beyond `name`+`type` everything is optional; the simplest hook sends `{name, type, value}`.
  **`labels` is how you break a metric down by dimension** (per-pool, per-model, per-strategy): a
  hook that runs on several pools reports one entry per pool (it receives `request.pool` on every
  message), so `GET /hooks/{name}/status` returns the whole picture and a dashboard drills down by
  label. A hook is ONE process no matter how many pools reference it, so this labeled self-report,
  not a per-pool endpoint, is how per-pool numbers surface. `histogram`+`quantiles` carries a
  latency distribution a mean would hide; `estimated`/`ci_*` marks a value your hook derived from a
  control group. Names/label keys are charset-enforced, every string sanitized + length-bounded,
  every number finite (a `prompt: ro` hook cannot smuggle content into a scrape). Busbar BOUNDS
  everything (64 entries/reply, 8 labels/entry); a malformed entry is dropped whole, a malformed
  optional member individually, never the reply. Time series are the CONSUMER's job in 1.3 (a
  dashboard samples `status` and accumulates); an engine-retained `series` member is the reserved
  additive path. Optional: reply `{}` and Busbar treats status as unsupported.
- **Reserved:** the reply field name **`report`** is reserved on per-request replies for per-request
  hook data (attached to the completion-stage tap payload in a future release); do not use it for
  anything else.

Fail-safety, precisely (don't over-generalize): `describe` and `status` are fully optional: a
hook that ignores them keeps working. **The socket `configure` preamble is NOT optional**: a
socket hook that never acks it has every connection rejected (each delivery then lands on the
gate's `on_error`), because a hook running settings it never acknowledged is running blind. The
exact-echo ack RULE is one; the DEADLINE is the delivery's own budget: the admin PATCH/management
calls allow 5s, but a request-path (re)connect acks within the gate's `timeout_ms` (default 1 ms;
ack `configure` immediately and apply settings asynchronously if application is slow). Webhooks
have no connection preamble (each PATCH push is its own POST). None of the management messages can
delay or fail request traffic: they ride fresh connections, never the request-path connection.

On a connection where you only ever receive `notify` (a tap), **never write anything**. Busbar
does not read tap replies, so even the polite `{}`-for-unknown-ops rule is scoped to
reply-expected connections; Busbar will never send a reply-expected op on a tap connection.

## First-party hook plugins (1.5.0)

Two `kind: hook` plugins ship signed by release CI and are auto-trusted by the embedded key:

**Headroom** (`busbar-headroom-hook`) is a `kind: hook` prompt-compression rewrite gate. It compresses context before dispatch, saving tokens and latency. Deploy it as a `prompt: rw` gate; it fires before dispatch on the normalized IR (see [What a gate receives](#what-a-gate-receives)), so the system prompt reaches it in one place whichever dialect the client speaks and its own local guard for in-band system turns is now redundant rather than load-bearing, token accounting runs on the rewritten body (the savings are real and measured), and a malformed or slow rewrite proceeds with the original body untouched. It reports `chars_saved_total` and related metrics via the `status` op.

**Webrequest** (`busbar-webrequest-hook`) is a `kind: hook` HTTP-forwarder plugin, the migration path for code you don't want in Busbar's address space. It forwards the routing projection over HTTPS to an operator-run sidecar, so you get out-of-process isolation (the sidecar can be any language) without running an untrusted library in-process. The artifact itself is signed and auto-trusted; forwarding is SSRF-guarded; and the sidecar's reply rides the same op-discriminated JSON contract.

Both plugins are installed from the release tarball and enabled under `plugins:` in the normal way. See [plugins.md](./plugins.md) for the artifact and trust model.

## Managing hooks over the API

Hooks are also lifecycle-managed over the frozen admin API: register, inspect, health-check, and remove at runtime, with a tamper-evident audit trail, and (opt-in) persistence across restart. See the [Admin API guide](./admin-api.md).

---

*Hooks fire before dispatch, on every protocol Busbar speaks, which is what makes Busbar the place your middleware runs. They fire on the **normalized IR** — the same representation the request that goes upstream is built from — so one hook is one hook on every protocol, and a screening gate is never handed a different payload than the provider receives.*
