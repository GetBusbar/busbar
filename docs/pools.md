# Pools

A **pool** is a named, weighted group of model lanes that share failover, circuit breaking, and session affinity. Your clients address a pool by name (as the `model` field), and Busbar decides which backend actually serves each request. Pools are how you turn several providers into one reliable endpoint.

Pools are optional: you can route directly to a single model. But the moment you want weighting, failover, cost-aware routing, or overflow, you reach for a pool.

<svg viewBox="0 0 760 360" role="img" aria-label="A client addresses pool chat. Smooth weighted round-robin (SWRR), the default policy, selects the top lane gpt-4o (weight 8); it fails before the first byte, so Busbar fails over to the next healthy lane claude-sonnet (weight 2); gemini-pro (weight 1) is skipped because its breaker is open. Each lane shows its per-(pool,lane) breaker cell: Closed, Closed, Open. A legend marks healthy and tripped lanes." style="width:100%;height:auto;max-width:760px;font-family:ui-sans-serif,system-ui,sans-serif;">
  <rect x="0" y="0" width="760" height="360" fill="#111a2e"/>
  <!-- client -->
  <rect x="16" y="150" width="120" height="56" rx="10" fill="#1a2740" stroke="#2c3a52"/>
  <text x="76" y="182" text-anchor="middle" fill="#e6edf7" font-size="15" font-weight="600">Client</text>
  <text x="76" y="224" text-anchor="middle" fill="#94a3b8" font-size="11">model: "chat"</text>
  <!-- client -> pool connector -->
  <line x1="136" y1="178" x2="202" y2="178" stroke="#94a3b8" stroke-width="2"/>
  <polygon points="202,173 214,178 202,183" fill="#94a3b8"/>
  <!-- pool -->
  <rect x="212" y="24" width="532" height="312" rx="16" fill="#a3e635" fill-opacity="0.05" stroke="#a3e635" stroke-opacity="0.5" stroke-width="1.5"/>
  <text x="236" y="52" fill="#ffffff" font-size="14" font-weight="700">pool: chat</text>
  <text x="724" y="52" text-anchor="end" fill="#94a3b8" font-size="11">SWRR default · failover</text>
  <text x="591" y="65" text-anchor="middle" fill="#94a3b8" font-size="9">breaker cell</text>
  <!-- SWRR-selected path: request enters the pool and continues to the top lane -->
  <polyline points="212,178 250,178 250,98 300,98" fill="none" stroke="#a3e635" stroke-width="2.5"/>
  <polygon points="292,93 304,98 292,103" fill="#a3e635"/>
  <text x="243" y="140" text-anchor="middle" transform="rotate(-90 243 140)" fill="#a3e635" font-size="10" font-weight="600">SWRR pick</text>
  <!-- lane 1: gpt-4o (selected) -->
  <g>
    <rect x="300" y="70" width="420" height="56" rx="10" fill="#1a2740" stroke="#2c3a52"/>
    <circle cx="324" cy="98" r="6" fill="#a3e635"/>
    <text x="344" y="94" fill="#e6edf7" font-size="13" font-weight="600">gpt-4o</text>
    <text x="344" y="112" fill="#94a3b8" font-size="11">via openai</text>
    <rect x="556" y="87" width="70" height="22" rx="6" fill="#1a2740" stroke="#2c3a52"/>
    <text x="591" y="102" text-anchor="middle" fill="#a3e635" font-size="12" font-weight="600">Closed</text>
    <text x="704" y="103" text-anchor="end" fill="#e6edf7" font-size="13" font-weight="700">weight 8</text>
  </g>
  <!-- failover: gpt-4o fails before first byte, hand to next healthy lane -->
  <polyline points="300,110 272,110 272,174 300,174" fill="none" stroke="#94a3b8" stroke-width="2" stroke-dasharray="5 4"/>
  <polygon points="292,169 304,174 292,179" fill="#94a3b8"/>
  <text x="308" y="140" fill="#94a3b8" font-size="10">fails before first byte -&gt; failover</text>
  <!-- lane 2: claude-sonnet (failover target) -->
  <g>
    <rect x="300" y="146" width="420" height="56" rx="10" fill="#1a2740" stroke="#2c3a52"/>
    <circle cx="324" cy="174" r="6" fill="#a3e635"/>
    <text x="344" y="170" fill="#e6edf7" font-size="13" font-weight="600">claude-sonnet</text>
    <text x="344" y="188" fill="#94a3b8" font-size="11">via anthropic</text>
    <rect x="556" y="163" width="70" height="22" rx="6" fill="#1a2740" stroke="#2c3a52"/>
    <text x="591" y="178" text-anchor="middle" fill="#a3e635" font-size="12" font-weight="600">Closed</text>
    <text x="704" y="179" text-anchor="end" fill="#e6edf7" font-size="13" font-weight="700">weight 2</text>
  </g>
  <!-- skip: gemini-pro breaker is open, so SWRR routes past it -->
  <line x1="272" y1="190" x2="272" y2="234" stroke="#f87171" stroke-width="2" stroke-dasharray="5 4"/>
  <line x1="266" y1="236" x2="278" y2="248" stroke="#f87171" stroke-width="2"/>
  <line x1="278" y1="236" x2="266" y2="248" stroke="#f87171" stroke-width="2"/>
  <text x="308" y="216" fill="#fca5a5" font-size="10">skipped (breaker open)</text>
  <!-- lane 3: gemini-pro (tripped) -->
  <g>
    <rect x="300" y="222" width="420" height="56" rx="10" fill="#2a1416" stroke="#f87171" stroke-opacity="0.55"/>
    <circle cx="324" cy="250" r="6" fill="#f87171"/>
    <text x="344" y="246" fill="#fca5a5" font-size="13" font-weight="600">gemini-pro</text>
    <text x="344" y="264" fill="#fca5a5" font-size="11">via gemini · skipped (breaker open)</text>
    <rect x="556" y="239" width="70" height="22" rx="6" fill="#2a1416" stroke="#f87171" stroke-opacity="0.55"/>
    <text x="591" y="254" text-anchor="middle" fill="#fca5a5" font-size="12" font-weight="600">Open</text>
    <text x="704" y="255" text-anchor="end" fill="#e6edf7" font-size="13" font-weight="700">weight 1</text>
  </g>
  <!-- legend -->
  <circle cx="320" cy="308" r="6" fill="#a3e635"/>
  <text x="334" y="312" fill="#e6edf7" font-size="11">healthy</text>
  <circle cx="424" cy="308" r="6" fill="#f87171"/>
  <text x="438" y="312" fill="#fca5a5" font-size="11">tripped</text>
</svg>

## The vocabulary

- **Pool**: a named group of lanes (what a client targets). Owns the selection policy, failover, and affinity.
- **Lane**: one model at one provider (a `models:` entry). The unit of concurrency, lifetime budget, and circuit breaking.
- **Cell**: the breaker state for a specific *(pool, lane)* pair. A lane that trips in pool A keeps serving in pool B, because each pool has its own cell. See [Circuit breaker](/docs/circuit-breaker/) for the breaker deep-dive.

## How selection works

By default a pool uses **smooth weighted round-robin (SWRR)** over the healthy members: each request goes to the next member by weight, and a tripped, dead, or capacity-exhausted member is skipped with its share redistributed to the rest. If the chosen lane fails before the client has seen a byte, Busbar fails over to the next member, even on a streaming request. That is the whole reliability story: weighting for the happy path, automatic failover for the bad one.

Want a different order than weighted? Name a **selection strategy** (`cheapest`, `fastest`, `least_busy`, `usage`, or your own ordering hook) as one entry in the pool's `hooks:` list. That is all of **[Routing](/docs/routing/)**, which owns every strategy, the routing signals, and the ordering-hook contract, with worked examples. The rest of *this* page is pool **structure**: members, weights, failover, and affinity.

## Config reference

The field-by-field reference, every pool and member field with its type, default, and validation rule, lives in one place: **[Configuration → `pools`](/docs/configuration/#pools)**. This guide stays conceptual so the two never drift.

In short: a pool takes a list of `members`, an optional `hooks` list (one ordering strategy, `weighted`/`cheapest`/`fastest`/`least_busy`/`usage`, plus any gates as inline `kind: hook` plugin refs), and optional `affinity`, `breaker`, `failover`, and `on_exhausted` blocks.

A member is written as it has been since 1.5: a `model:` naming an entry in `models:`, with an optional `weight:` and any per-member capabilities (`context_max`, `attempt_timeout_ms`, `reasoning`, `tier`, `tags`) beside it. That is the canonical form, it is what the field reference documents, and it is what `busbar --migrate-config` leaves exactly as you wrote it.

```yaml
pools:
  chat:
    members:
      - model: gpt-4o
        weight: 8
      - model: claude-sonnet
        weight: 2
      - model: gemini-pro                # weight defaults to 1
```

An equivalent shorthand is accepted for pools whose members carry nothing but a weight: list the members as bare names and put the weights in a pool-level `weights:` map (`weights:` present ⇒ weighted distribute; absent ⇒ ordered failover with the first member as primary). The two spellings mean the same thing and may be mixed; a per-member `weight:` written inline wins over the `weights:` map for that member. The bare-name form is also how MCP and A2A failover pools name their `tools:` / `agents:` members, since those carry no per-member capabilities.

Each block with its own guide: [Hooks](/docs/hooks/) for the selection strategies, the ordering-hook contract, and [what a gate receives](hooks.md#what-a-gate-receives); [Circuit breaker](/docs/circuit-breaker/#circuit-breaker-configuration) for the per-pool `breaker` block; and [In-flight failover](/docs/failover/) for `failover` and `on_exhausted`.

## Multi-protocol pools

**Multi-protocol pools**: members can span different providers and protocols. Busbar translates through its superset IR on cross-protocol hops (see [Protocols and translation](/docs/protocols/#cross-protocol-translation)). A warning is logged at startup for heterogeneous pools because the IR models a common superset: same-protocol requests are byte-exact on the wire (the client sees the upstream's bytes verbatim, with the request side byte-for-byte only when it already names the lane's exact wire model), but cross-protocol hops drop source-only fields that have no analog on the target (e.g. `logit_bias`, or `n` clamped to one candidate), along with the constructs that have no representation on the target at all ([Fields the target protocol cannot express](/docs/protocols/#fields-the-target-protocol-cannot-express)); every such drop emits a `warn!` naming the field. Attachments (documents, audio, video) DO cross — see [Closed in 1.6.0](/docs/protocols/#closed-in-160). For pools where all members speak the same protocol there is no field loss and no re-encoding. Responses still pay a per-frame IR decode as a usage side-channel; that cost is not translation overhead in the field-loss sense, but it is not zero either.

## Recipes

### Weighted split with automatic failover

```yaml
pools:
  chat:
    members:
      - { model: gpt-4o,        weight: 8 }   # ~80% of traffic
      - { model: claude-sonnet, weight: 2 }   # ~20%
      - { model: gemini-pro,    weight: 1 }   # picks up load when the others trip
```

The same pool in the bare-name shorthand:

```yaml
pools:
  chat:
    members: [gpt-4o, claude-sonnet, gemini-pro]
    weights: { gpt-4o: 8, claude-sonnet: 2, gemini-pro: 1 }
```

### Same model, two providers (cross-provider failover)

Run one real model behind two providers. The keys differ; `upstream_model` carries each provider's own model string. See [Configuration](/docs/configuration/#models).

```yaml
models:
  sonnet-anthropic: { provider: anthropic,         max_concurrent: 20, upstream_model: claude-3-5-sonnet-20241022 }
  sonnet-bedrock:   { provider: bedrock-us-east-1, max_concurrent: 10, upstream_model: "anthropic.claude-3-5-sonnet-20241022-v2:0" }
pools:
  sonnet:
    members:
      - { model: sonnet-anthropic, weight: 3 }   # primary
      - { model: sonnet-bedrock,   weight: 1 }   # same model, other cloud
```

### Context-length failover

```yaml
pools:
  long-context:
    members:
      - { model: gpt-4o,        context_max: 128000,  weight: 3 }
      - { model: gemini-15-pro, context_max: 2000000, weight: 1 }   # over-128k requests land here
```

### Sticky sessions

```yaml
pools:
  agents:
    affinity:
      mode: session
      header_name: x-session-id      # defaults to x-session-id if omitted
    members:
      - { model: gpt-4o,        weight: 1 }
      - { model: claude-sonnet, weight: 1 }
```

### Cost-, latency-, and custom-based routing

Choosing *which* member serves a request (cheapest, fastest, least busy, or your own `kind: hook` gate plugin returning an `order`) is a routing concern, not a pool-shape one: a pool names its selection strategy plus any gates in one `hooks: [...]` list. Those recipes, with a worked pool example, live in the [Hooks guide](hooks.md) and the [pool-hooks reference](configuration.md#pool-hooks-ordering-and-gates).

See the [Hooks guide](hooks.md) for the full ordering-hook contract and the signals each strategy and gate hook receives, and [Circuit breaker](/docs/circuit-breaker/) / [In-flight failover](/docs/failover/) for how the breaker and failover behave once a strategy or gate hook has chosen an order.
