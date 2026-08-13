# Architecture

This document traces a request end-to-end and explains the two seams that make
Busbar's thesis, *protocols, not providers*, work: the **superset IR** with its
`ProtocolReader` / `ProtocolWriter` traits, and the **two-stage failure-disposition
pipeline**.

## Three planes, one core

Busbar carries three kinds of traffic, and the point of the architecture is that
they are three *ingresses onto one core* rather than three products sharing a
process.

| plane | inbound: Busbar is the server | outbound: Busbar is the client |
|---|---|---|
| **LLM** | six wire protocols on `/v1/*` and friends | every provider or pool you configure |
| **MCP** | `/mcp`, an MCP server your agents log in to | the MCP tool servers you register |
| **A2A** | `/a2a/agents/{id}`, the agents you front | the backend agent a task is relayed to |

Each plane is bidirectional, and that is the whole claim: a caller speaks to
Busbar, and Busbar speaks onward under its own identity.

**What all three share, exactly once:**

- **One authentication chain**, failing closed on every plane.
- **One admission decision.** An inbound MCP `tools/call` authenticates with a
  virtual key exactly as a model request does, and is charged against the same
  budget and the same rate limits in the same step. There is no separate MCP
  meter and no separate MCP budget.
- **One grant vocabulary.** Authorization is `ScopeRef{kind, value}`, and `kind`
  is an open string rather than a closed enum: `pool` for the LLM plane,
  `mcp_server` and `mcp_tool` for MCP, `agent` for A2A. A fourth plane is new
  *data*, not new code.
- **One availability decision.** The circuit breaker is keyed on the *target* being
  called, not on the shape of the caller: a pool member, a registered MCP tool
  server, or a registered A2A agent. The same Closed → Open → HalfOpen state
  machine, the same cause attribution, the same cooldown backoff and the same
  single-flight recovery probe run on all three planes. See
  [Circuit-breaker state](#circuit-breaker-state-on-all-three-planes) below.
- **One audit chain**, hash-chained across all of it.
- **One outbound guard.** Every address a plane is about to reach is checked
  against cloud-metadata and internal ranges with alternate-encoding
  normalisation, the connection is pinned to the vetted address, and redirects
  are refused in both directions.

**What is specific to each, because the threat is specific.** On MCP, a tool's
schema is hash-pinned at approval and a drifted tool is quarantined rather than
called. A tool description is an instruction to a model, so a server that
rewrites its own description tomorrow is a live attack, not a version bump. On
A2A, an agent card is fetched through the same guard, verified Ed25519-only, and
pinned so the same card six hours later is checked against the one you approved.
Busbar's own card is served unauthenticated at `/.well-known/agent-card.json`
because that is where a conformant client looks first, and it deliberately names
**no** fronted agent: an endpoint that cannot ask who is calling must not hand an
anonymous caller the inventory.

## Request lifecycle: an LLM call, traced

The trace below follows a **model** request, because it is the path that exercises
every seam: protocol translation, pool selection and failover are LLM-plane
mechanics. The MCP and A2A planes enter at their own ingress and rejoin at the
shared steps. Authentication, admission, breaker availability, audit and metering
are the same code on all three.

<svg viewBox="0 0 700 1140" role="img" aria-label="A request enters over any of six wire protocols and hits the axum HTTP router, whose route fixes the ingress protocol. Auth middleware applies token, passthrough or none, or a virtual-key lookup for governance. If governance is enabled it runs allowed-pools, budget and rate-limit checks, returning 403 or 429 on failure. Pool and lane selection uses affinity preference then smooth weighted round-robin over the healthy candidate subset. Each attempt, up to the failover cap, translates the request to the lane protocol via the intermediate representation, rewrites the model and injects credentials, POSTs upstream, and classifies the outcome into relay, failover or dead-lane. The response is passed through when the protocol matches or translated frame-by-frame when it differs, usage is tapped to charge the virtual key, and the reply returns to the client." style="width:100%;height:auto;max-width:700px;font-family:ui-sans-serif,system-ui,sans-serif;">
  <defs>
    <marker id="rl-arw" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M0,0 L10,5 L0,10 z" fill="#94a3b8"/>
    </marker>
  </defs>
  <rect x="0" y="0" width="700" height="1140" fill="#ffffff"/>
  <g stroke="#94a3b8" stroke-width="2" marker-end="url(#rl-arw)">
    <line x1="350" y1="42"   x2="350" y2="62"/>
    <line x1="350" y1="150"  x2="350" y2="170"/>
    <line x1="350" y1="268"  x2="350" y2="288"/>
    <line x1="350" y1="396"  x2="350" y2="416"/>
    <line x1="350" y1="524"  x2="350" y2="544"/>
    <line x1="350" y1="722"  x2="350" y2="742"/>
    <line x1="350" y1="870"  x2="350" y2="890"/>
    <line x1="350" y1="998"  x2="350" y2="1018"/>
  </g>

  <!-- Client pill (top) -->
  <rect x="285" y="12" width="130" height="30" rx="15" fill="#f8fafc" stroke="#e2e8f0"/>
  <text x="350" y="31" text-anchor="middle" fill="#0f172a" font-size="12" font-weight="700">Client <tspan fill="#64748b" font-weight="400">· any protocol</tspan></text>

  <!-- 1. HTTP router -->
  <g>
    <rect x="40" y="62" width="620" height="88" rx="12" fill="#f8fafc" stroke="#e2e8f0"/>
    <circle cx="72" cy="92" r="14" fill="#a3e635"/><text x="72" y="97" text-anchor="middle" fill="#1a2e05" font-size="13" font-weight="700">1</text>
    <text x="100" y="90"  fill="#0f172a" font-size="14" font-weight="700">HTTP router <tspan fill="#64748b" font-weight="400" font-size="12">(axum)</tspan></text>
    <text x="100" y="110" fill="#64748b" font-size="11">route fixes the ingress protocol</text>
    <text x="100" y="130" fill="#4d7c0f" font-size="11" font-weight="700">anthropic · openai · responses · cohere · gemini · bedrock</text>
  </g>

  <!-- 2. Auth middleware -->
  <g>
    <rect x="40" y="170" width="620" height="88" rx="12" fill="#f8fafc" stroke="#e2e8f0"/>
    <circle cx="72" cy="200" r="14" fill="#a3e635"/><text x="72" y="205" text-anchor="middle" fill="#1a2e05" font-size="13" font-weight="700">2</text>
    <text x="100" y="198" fill="#0f172a" font-size="14" font-weight="700">Auth middleware</text>
    <text x="100" y="218" fill="#64748b" font-size="11">token · passthrough · none</text>
    <text x="100" y="238" fill="#64748b" font-size="11">or virtual-key lookup <tspan fill="#4d7c0f" font-weight="700">(governance)</tspan></text>
  </g>

  <!-- 3. Governance checks -->
  <g>
    <rect x="40" y="298" width="620" height="88" rx="12" fill="#f8fafc" stroke="#e2e8f0"/>
    <circle cx="72" cy="328" r="14" fill="#a3e635"/><text x="72" y="333" text-anchor="middle" fill="#1a2e05" font-size="13" font-weight="700">3</text>
    <text x="100" y="326" fill="#0f172a" font-size="14" font-weight="700">Governance checks <tspan fill="#64748b" font-weight="400" font-size="12">(if enabled)</tspan></text>
    <text x="100" y="346" fill="#64748b" font-size="11">allowed-pools &#8594; 403 · budget &#8594; 429</text>
    <text x="100" y="366" fill="#64748b" font-size="11">rate limit &#8594; 429 + Retry-After</text>
  </g>

  <!-- 4. Pool / lane selection -->
  <g>
    <rect x="40" y="426" width="620" height="88" rx="12" fill="#f8fafc" stroke="#e2e8f0"/>
    <circle cx="72" cy="456" r="14" fill="#a3e635"/><text x="72" y="461" text-anchor="middle" fill="#1a2e05" font-size="13" font-weight="700">4</text>
    <text x="100" y="454" fill="#0f172a" font-size="14" font-weight="700">Pool / lane selection</text>
    <text x="100" y="474" fill="#64748b" font-size="11">affinity preference &#8594; SWRR</text>
    <text x="100" y="494" fill="#64748b" font-size="11">over the healthy candidate subset</text>
  </g>

  <!-- 5. Per attempt -->
  <g>
    <rect x="40" y="554" width="620" height="168" rx="12" fill="#f8fafc" stroke="#e2e8f0"/>
    <circle cx="72" cy="584" r="14" fill="#a3e635"/><text x="72" y="589" text-anchor="middle" fill="#1a2e05" font-size="13" font-weight="700">5</text>
    <text x="100" y="582" fill="#0f172a" font-size="14" font-weight="700">Per attempt <tspan fill="#64748b" font-weight="400" font-size="12">(up to the failover cap)</tspan></text>
    <text x="100" y="606" fill="#64748b" font-size="11">translate to lane protocol (IR)</text>
    <text x="100" y="626" fill="#64748b" font-size="11">rewrite model + inject creds <tspan fill="#94a3b8">(bearer / api-key / SigV4)</tspan></text>
    <text x="100" y="646" fill="#64748b" font-size="11">POST upstream</text>
    <line x1="100" y1="662" x2="620" y2="662" stroke="#e2e8f0" stroke-width="1"/>
    <text x="100" y="682" fill="#4d7c0f" font-size="11" font-weight="700">classify &#8594;</text>
    <text x="176" y="682" fill="#64748b" font-size="11">2xx relay · 4xx relay (no penalty)</text>
    <text x="100" y="702" fill="#64748b" font-size="11">transient &#8594; failover · hard-down &#8594; dead lane</text>
  </g>

  <!-- 6. Response -->
  <g>
    <rect x="40" y="742" width="620" height="128" rx="12" fill="#f8fafc" stroke="#e2e8f0"/>
    <circle cx="72" cy="772" r="14" fill="#a3e635"/><text x="72" y="777" text-anchor="middle" fill="#1a2e05" font-size="13" font-weight="700">6</text>
    <text x="100" y="770" fill="#0f172a" font-size="14" font-weight="700">Response</text>
    <text x="100" y="790" fill="#64748b" font-size="11">same protocol &#8594; passthrough</text>
    <text x="100" y="810" fill="#64748b" font-size="11">cross protocol &#8594; translate each SSE / eventstream frame</text>
    <text x="100" y="836" fill="#4d7c0f" font-size="11" font-weight="700">tap usage &#8594; charge virtual key</text>
  </g>

  <!-- 7. Return to client -->
  <g>
    <rect x="40" y="890" width="620" height="108" rx="12" fill="#f8fafc" stroke="#e2e8f0"/>
    <circle cx="72" cy="920" r="14" fill="#a3e635"/><text x="72" y="925" text-anchor="middle" fill="#1a2e05" font-size="13" font-weight="700">7</text>
    <text x="100" y="918" fill="#0f172a" font-size="14" font-weight="700">Reply delivered</text>
    <text x="100" y="938" fill="#64748b" font-size="11">bytes stream back over the caller's ingress protocol</text>
    <text x="100" y="958" fill="#64748b" font-size="11">circuit-breaker state updated from the final disposition</text>
    <text x="100" y="982" fill="#4d7c0f" font-size="11" font-weight="700">&#8595; back to the client</text>
  </g>

  <!-- Client pill (bottom) -->
  <rect x="285" y="1018" width="130" height="30" rx="15" fill="#f8fafc" stroke="#e2e8f0"/>
  <text x="350" y="1037" text-anchor="middle" fill="#0f172a" font-size="12" font-weight="700">Client</text>
</svg>

### 1. Ingress & protocol detection

The route table (`crates/busbar/src/main.rs` `build_router`, `crates/busbar/src/ingress/mod.rs`) determines the
**ingress protocol** by path, not by sniffing the body. All six protocols are
first-class ingress, one handler per protocol (Gemini's handler is reachable via
two path prefixes, `v1` and `v1beta`):

- `POST /{name}/v1/messages` → ingress `anthropic`. `name` is a model or a pool.
- `POST /{provider}/{model}/v1/messages` → ingress `anthropic`, ad-hoc direct route.
- `POST /v1/chat/completions` → ingress `openai`. The body's `model` field names the
  model or pool.
- `POST /v1/responses` → ingress `responses` (OpenAI Responses API). Model in the body.
- `POST /v2/chat` → ingress `cohere`. Model in the body.
- `POST /v1/models/{*rest}` and `POST /v1beta/models/{*rest}` → ingress `gemini`. Both the
  stable `v1` and the `v1beta` path prefixes are accepted by the same handler, because the
  google-generativeai / Gen AI SDKs use either surface. The model and the action
  (`:generateContent` / `:streamGenerateContent`) are packed into the last path
  segment after a `:`; axum can't split on `:` inside a segment, so the tail is
  captured with a wildcard and split in `gemini_ingress`.
- `POST /model/{model_id}/converse` and `/model/{model_id}/converse-stream` → ingress
  `bedrock`. The model is in the path; the streaming variant is selected by the
  endpoint suffix.

This splits cleanly into **body-model protocols** (`openai`, `responses`, `cohere`, the model/pool lives in the request body) and **path-model protocols**
(`anthropic`, `gemini`, `bedrock`: the model/pool lives in the URL). A small
injection shim normalises both into the same internal model/pool selection so the
rest of the pipeline is protocol-agnostic.

Management/observability routes (`/stats`, `/healthz`, `/metrics`,
`/api/v1/admin/keys...`) are handled separately.

### 2. Authentication

`auth_middleware` (`crates/busbar/src/auth/mod.rs`) runs before routing:

- `/healthz` is always open (liveness probes must not require a token).
- `/metrics` is **not** exempted, Prometheus telemetry (lane/pool topology,
  per-protocol counters, error rates) is an information-disclosure surface, so it
  goes through the same auth check as any other route. It is gated by the data-plane
  auth chain (`auth.chain`): a request must satisfy some module in the chain (the
  built-in `keys` signed-token verifier, or a configured identity provider). With an empty chain
  (`chain: []`) the check admits unconditionally and `/metrics` is effectively open, so
  restrict it at the network layer if you need unauthenticated scraping.
- The admin API (`/api/v1/admin/*`) does not run on the data plane at all. It is served
  on a **physically separate listener**, `admin_listen` (default `127.0.0.1:8081`, loopback),
  and gated by its own chain, `admin_auth` (default `[admin-tokens]`). An admin token
  arrives as `Authorization: Bearer` or `X-Admin-Token`; no valid admin credential means
  a 401. Because the socket is separate, a caller on the data port can never reach the
  control plane. Exposing `admin_listen` off loopback is a boot error unless you set
  `admin_tls.client_ca` (mTLS on the admin listener) or set the explicit
  `admin_require_mtls: false` waiver (for operators fronting admin with their own mesh).
  (1.5.3 inverted the retired `admin_insecure:` flag into this one, so the safe posture is the default.)
- On the data plane, the caller's bearer token is threaded through the request. Whether
  Busbar signs the upstream call with its own lane key or forwards the caller's credential
  is a separate config knob, `pools.upstream_credentials:` (`own`, the default, vs `passthrough`).
  It sets the all-pools default, is overridable per pool, and is
  independent of which identity provider ran at the front door. Under governance the resolved
  virtual key is attached for downstream ACL and budget checks.
- **Bedrock ingress** takes one of two paths. When the data-plane chain does not verify a
  caller (an empty chain, passthrough egress), `extract_client_token` reads only bearer-style
  carriers and ignores the SigV4 header, which is forwarded upstream (passthrough) or dropped.
  When governance is active, `crates/busbar/src/auth/mod.rs` `verify_bedrock_sigv4` intercepts
  requests carrying `Authorization: AWS4-HMAC-SHA256`, verifies the full SigV4 signature plus
  body-hash integrity (`x-amz-content-sha256`), and on success attaches the resolved virtual
  key's `GovCtx` so all governance checks apply. The AWS credential pair (`aws_access_key_id`
  + `aws_secret_access_key`) is minted via `POST /api/v1/admin/keys` with
  `"issue_aws_credential": true`. `crates/busbar/src/sigv4.rs` provides signing primitives;
  the inbound verifier lives in `crates/busbar/src/auth/mod.rs`.

### 3. Governance checks

When a virtual key is resolved, the route handler enforces, in order:
allowed-pools (`403`), budget (`429`, or `400` for Bedrock ingress), and rate
limits (`429` + `Retry-After`) *before* forwarding. The budget check walks the
key's whole chain (the key's own bucket, then its `budget_group`, then that
group's parent, up to the root) and admits only if every bucket is under cap; the
429 names which bucket blocked. Budget exhaustion does **not**
emit `402`: no upstream vendor returns `402` for an over-quota condition, so a
`402` would be a router-side tell. Instead each ingress writer maps to its native
quota shape: `429` (`insufficient_quota`) for OpenAI / Responses / Anthropic /
Gemini / Cohere, and `400` (`ServiceQuotaExceededException`) for Bedrock. The flat
per-request fee is charged at admission; the token counts land on the ledger when
the response stream completes. Spend itself is never stored: it is derived at read
time from the accumulated per-model tokens times the current top-level `rate_card`,
so a rate correction re-prices past and present windows on the next read. See
[operations.md](operations.md).

### 4. Pool / lane selection

For a pool target, `forward_with_pool` (`crates/busbar/src/proxy/engine/mod.rs`) selects a member:

1. **Affinity preference**: if a session header is present and the sticky member is
   usable, use it; otherwise fall through.
2. **Exclusions**: configured `failover.exclusions` and already-tried lanes (across
   failover hops) are removed from the candidate set.
3. **SWRR**: `select_weighted` (`crates/busbar/src/store/mod.rs`) runs Nginx-style smooth weighted
   round-robin over the *usable* candidates, using per-pool `current_weight` state.
   A lane is usable only if it isn't dead, isn't out of lifetime budget, and its
   breaker cell admits it.
4. **Concurrency**: the selected lane's semaphore permit is acquired (a lane at its
   `max_concurrent` cap is skipped/awaited).

A direct/ad-hoc route is the degenerate case: a single-member candidate set of
weight 1.

### 5. Cross-protocol translation (the IR seam)

If the ingress protocol differs from the selected lane's protocol, Busbar
translates the **request** through the superset IR:

```
ingress.reader().read_request(body)  →  IrRequest  →  lane.writer().write_request(ir)
```

The IR (`crates/busbar/src/ir/mod.rs`) is a superset of all six protocols' representable content:
system blocks, messages with text / thinking (+signature) / tool-use / tool-result
/ image blocks, tools (name + description + JSON schema), `max_tokens`,
`temperature` (held as `f64` so a caller's value never silently mutates), a `stream`
flag, and an `extra` passthrough map for fields outside the modeled subset
(provider-specific sampling knobs with no first-class IR field, etc.). Same-protocol REQUESTS skip the IR entirely and pass through
byte-for-byte, but only when the client named the lane's exact wire model. A pool-alias route
(e.g. `model: "fast"` resolving to a specific lane) rewrites the model and re-serializes instead.
Same-protocol RESPONSES pass through byte-for-byte on the wire but still decode each frame through
the IR as a usage side-channel (see `docs/protocols.md`'s "Same-protocol passthrough"); only the
re-encode is skipped, not the IR round-trip.

`ProtocolReader` and `ProtocolWriter` (`crates/busbar/src/proto/mod.rs`) are the per-protocol
edges:

- **`ProtocolReader`**: `read_request` (wire → IR), `read_response` /
  `read_response_event(s)` (wire → IR, with stateful fan-out for flat streams like
  OpenAI's), and `extract_error` / `classify` (the breaker's Stage 1).
- **`ProtocolWriter`**: `write_request` (IR → wire), `write_response` /
  `write_response_event` (IR → wire), `rewrite_model`, `upstream_path[_for[_stream]]`,
  and the **auth hooks**: `auth_headers(key)` for static headers and
  `sign_request(key, ctx)` for per-request signing (overridden by Bedrock for
  SigV4). It also provides `probe_body`: a one-token request used by active health
  probes, so every protocol gets a valid probe for free.

A `Protocol` bundles a name + reader + writer; the `ProtocolRegistry` resolves them
by name at startup. This is the entire reason a "provider" needs no code: any
backend speaking a known protocol is just a catalog row.

### 6. Upstream auth & dispatch

The handler builds the upstream URL (`base_url` + the protocol's path, or the
provider's `path` override), selects the key (lane key, or the caller's key in
passthrough mode), and computes auth via `sign_request` against a `SigningContext`
(host, canonical URI, body, timestamp). For most protocols this is static headers;
for Bedrock it computes AWS SigV4 with the region parsed from the host. The model
field is rewritten to the selected lane's model.

### 7. Two-stage failure disposition

Every non-2xx upstream response is run through a pipeline that decides **who is at
fault** and therefore what to do (`crates/busbar/src/proxy/engine/mod.rs`, `crates/busbar/src/breaker.rs`):

```
Stage 1a  proto.reader().extract_error(status, body)  → RawUpstreamError
Stage 1b  normalize_raw_error(raw, provider.error_map) → CanonicalSignal (StatusClass)
Stage 2   classify_disposition(signal)                 → Disposition
```

`Disposition` is matched **exhaustively** (a project invariant: no `_ =>` catch-all
in breaker matches):

| Disposition | Cause (StatusClass) | Lane effect | Request effect |
|---|---|---|---|
| `ClientFault` | client 4xx (400/404/422, context-aside) | none (tracked separately as `client_fault`) | relay verbatim to caller |
| `TransientUpstream` | 5xx, timeout, network, overloaded, rate-limit | trip evaluation + cooldown (rate-limit honors Retry-After) | **failover** to next candidate |
| `HardDown` | billing/quota, auth (401/403) | lane marked dead (breaker trip) | auth → relay error to caller; billing → failover |
| `ContextLength` | context-length-exceeded | none (lane was healthy) | exclude ≤-context candidates, failover to a larger lane |

This is the core correctness property: **a healthy backend is never ejected because
a caller sent a bad request.** In `passthrough` mode, a `401`/`403` is the *caller's*
key failing, so it is relayed verbatim without touching lane health.

### 8. Response translation & usage accounting

On success, the response is streamed (SSE or Bedrock event-stream) or buffered:

- **Same protocol**: passthrough; native usage accounting and provider-specific
  fields survive untouched.
- **Cross protocol**: `StreamTranslate` (`crates/busbar/src/proto/mod.rs`) composes
  `egress.reader().read_response_events` with
  `ingress.writer().write_response_event`, re-framing each upstream event into the
  caller's wire format. It reassembles frames split across chunks, threads stream
  decode state, decodes Bedrock's binary `application/vnd.amazon.eventstream` on
  egress and re-encodes it (CRC32-valid frames) for Bedrock ingress, and emits the
  correct ingress terminator (`data: [DONE]` for OpenAI; Anthropic's
  `message_stop` carries its own).

In both cases a usage tap reads token counts from the response (protocol-agnostic
extraction across all six wire shapes), and, when governance is on, charges the
resolved virtual key's budget at stream completion. Failover is only possible
*before the first byte* reaches the client; a mid-stream upstream failure records
the breaker fault and emits a native error in the caller's protocol, an SSE
`error` event for SSE clients, a binary `:message-type: exception` frame for
Bedrock-ingress (AWS eventstream) clients.

## Circuit-breaker state, on all three planes

Breaker state is stored in `crates/busbar/src/store/mod.rs`. The FSM is Closed → Open
→ HalfOpen → Closed, with exponential cooldown backoff and single-flight half-open
probing. See [operations.md](operations.md) and
[circuit-breaker.md](circuit-breaker.md) for the full state machine, trip modes, and
recovery behavior.

The breaker is keyed on the **target** a request is about to reach. A target is a
pool member on the LLM plane, a registered tool server on MCP, or a registered agent
on A2A. Three identities, one state machine:

| plane | breaker target | live on the dispatch path? |
|---|---|---|
| LLM | a `(pool, lane)` cell | yes, and has been since the breaker landed |
| MCP | one registered tool server | not yet: the seam exists, `mcp/client/dispatch.rs` does not call it |
| A2A | one registered agent | not yet: same, for `a2a/relay.rs` |

**One state machine, and one place to tune it.** `BreakerCfg` (the cooldown bounds and
the `trip:` condition) is accepted under `pools:` and nowhere else. There is no
`breaker:` key under `tools:` or `agents:`, and both sections `deny_unknown_fields`, so
a config that writes one fails at boot. On MCP and A2A the breaker therefore runs on
built-in defaults, through `crate::failover`, which calls the same
`try_admit_breaker` the LLM plane calls and adds no second state machine.

**What generalises, and what it took to generalise it.** The state machine and the cause
attribution need a target identity and a failure history, and neither of those is
LLM-shaped. *Member selection* needs one thing more: members that can substitute for one
another. An earlier version of this section said MCP and A2A have none, and stated it as
a property of the protocols. It is not one. The case operators actually run is the same
server image deployed twice, or one agent registered twice, and busbar's inability to be
told about it was a missing config vocabulary rather than a law. `tool_pools:` and
`agent_pools:` (1.6.0) are that vocabulary, over one selection loop in `crate::failover`;
a candidate set of one remains exactly the degenerate case §4 already describes. Two
rules keep it safe and both are core's, not a plane's: two candidates are interchangeable
only when the pins busbar already computed AGREE, and a call that has already gone out is
repeated only when the operation is named in `repeatable:`. See
[circuit-breaker.md](circuit-breaker.md#failover-on-mcp-and-a2a-the-same-server-deployed-twice).

**What the caller gets when a target is Open** is protocol-native on each plane, and
the difference matters more than it looks. The LLM row is live; the MCP and A2A rows
are the contract the dispatch-path wiring is being written to and are **not emitted
today**, so do not test against them yet:

| plane | refusal | live? |
|---|---|---|
| LLM | the pool's `on_exhausted` policy: failover to another member, a fallback pool, `least_bad`, or `503` + `Retry-After` | yes |
| MCP | HTTP `503` with `Retry-After`, and a **JSON-RPC error** in busbar's implementation-defined `-320xx` band, with `data` carrying `reason`, `server` and `retry_after_ms` | not yet |
| A2A | a task in state **`rejected`** (not `failed`), returned with its task id | not yet |

On MCP this is an error, **never a tool result with `isError: true`**. `isError` means
the tool ran and failed; a tripped breaker means the call never happened. Reporting
the second as the first hands the model a false premise about the world, and the model
then reasons from it. On A2A, `rejected` says *we did not accept this work*, where
`failed` would say *we tried and it broke*. The caller keeps the task id, so the
calling agent owns the retry decision rather than inheriting a schedule Busbar
invented for it.

## Observability hooks

Metrics are emitted at the ingress boundary (`busbar_requests_total`, the duration
histogram) on EVERY plane, and at each upstream attempt/failure/trip/failover/translation
(`crates/busbar/src/metrics.rs`, `crates/busbar/src/proxy/engine/mod.rs`). The model plane emits from
`ingress::finish_inner`, the MCP and A2A planes from the plane ingress boundary layer
(`crates/busbar/src/plane/observe.rs`), distinguished by a `plane` label. Optional OTLP spans and a request-log webhook
are configured via the `observability` section.

## How it deploys, simplest first

Busbar is **one static binary** with no interpreter, no sidecar and no database
required to start. The topologies below are the same binary with progressively
more of its optional seams turned on; nothing is a different build or a different
edition.

All three planes are in the one binary. Serving MCP or fronting agents is a
`tools:` or `agents:` block in the config, not another process to run.

**1. One process, no store.** A binary and a config file. Virtual keys, budgets
and breaker state live in memory. This is a complete, working deployment. It
forgets accrued usage on restart, and nothing else. Suitable for a single node, a
development environment, or an air-gapped box where a database is a liability
rather than an asset.

**2. One process, durable.** Add a `store:` and the same process persists what it
would otherwise forget: keys, credentials, usage ledgers, the audit chain, the
revocation denylist, agent tasks and the MCP call log. Backends ship as signed
plugins (SQLite, PostgreSQL, MySQL and Valkey), so the storage decision is a
config line rather than a rebuild.

**3. A fleet behind a load balancer.** Several processes sharing one store. Each
member is independent on the request path and converges through the store: a key
revoked on one member reaches the others through the denylist, and usage
accrues into shared ledgers. A *deployment* is the cluster; a *member* is one
process, and the distinction is load-bearing because per-process state (config
version, boot epoch, in-memory audit ring) is real and observable per member.

The **admin plane is a separate listener** in every topology. It binds to
loopback by default, and exposing it further requires mutual TLS. Reaching the
data port does not reach the control surface: they are different sockets with
different authentication. See [Security](https://getbusbar.com/security/).

## What is in the store, and what is deliberately not

The store is a **durability sink, never a lookup on the request path.** Admission
(`try_admit`, which decides whether a request is allowed) makes **zero** store
calls. Budgets and the revocation denylist are hydrated into memory at boot and
written through afterwards, off the request path. This is why storage choice does
not appear in the latency numbers on the [performance page](https://getbusbar.com/performance/):
a slow database makes writes slow, not requests slow.

**Persisted:** virtual keys (secret **hashed**: the store holds a verifier, not
the key), outbound credentials, usage ledgers as accumulated per-model token
counts, the hash-chained audit record, the revocation denylist, A2A tasks and
their events, and the MCP tool-call log.

**Never persisted, and each for a reason:**

- **Spend.** There is no money column. Spend is *derived at read time* from
  accumulated tokens times the current `rate_card`, so correcting a rate re-prices
  past and present windows on the next read instead of leaving a stale number
  nobody can recompute.
- **Prompts, completions, and message content.** No request or response body
  reaches the store on any path. Content leaves Busbar only as its own named
  export stream an operator turns on for one specific sink, or to a plugin under
  an explicit per-hook grant that defaults to `no`. It never rides along inside
  something already subscribed to.
- **A caller's own credential.** It authenticates the request and is not stored,
  forwarded upstream, or reused as Busbar's identity to anyone.

## Credentials, in both directions

The two directions are separate mechanisms on purpose, because the interesting
failure is not leaking a key outright. It is using the right key on the wrong
hop.

**Inbound**, a caller presents a virtual key carrying its own scopes, budget and
rate limits. Comparison is constant-time. Revocation is immediate and does not
touch a provider account.

**Outbound**, each backend is reached with a credential chosen for that backend,
resolved from the configured secret source. A caller's key is never forwarded and
never substituted for Busbar's own. On the MCP and A2A planes the outbound
credential is bound to the inbound principal by a type whose private field makes a
call site that forgets to bind it a compile error rather than a review comment.

## Plugins, and what they are trusted with

Stores, hooks, exporters and auth providers load as **signed dynamic libraries**.
Identity comes from the signed manifest, never the filename: the publisher
signature is verified over a canonical manifest, and the manifest's `sha256` pins
it to the exact library bytes. An unsigned, wrong-key, tampered-library or
tampered-manifest load is refused.

A plugin sees what its declared grants allow and nothing more. Message content in
particular is gated behind a per-hook `prompt: no | ro | rw` grant that defaults
to `no`, is immutable after registration, and requires `full` admin scope to raise.
Busbar can also be built with plugins compiled out entirely, which is a distinct
CI-gated configuration rather than a documentation claim.
