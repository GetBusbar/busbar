# Reliability guide

Busbar keeps serving through provider failures. That reliability is not one feature but a stack of them, spread across a few guides. This page is the map, and the worked example at the end shows them working together.

**Structure**: how you describe your backends ([Core concepts](/docs/pools/)):

- **[Pools](/docs/pools/)** - group backends into one named target with weighting and automatic failover.
- **[Routing hooks](/docs/hooks/)** - choose which member serves each request: cheapest, fastest, least busy, or your own logic.

**Resilience**: what happens when a backend misbehaves (the guides in this section):

- **[Circuit breaker](/docs/circuit-breaker/)** - fault-attributed breaking that classifies each failure and benches only the target at fault. It runs on all three planes: pool members, MCP tool servers and A2A agents, one state machine and [one config struct in three places](/docs/circuit-breaker/#the-breaker-on-the-mcp-and-a2a-planes). On MCP and A2A it buys failing fast rather than paying a timeout per call, an operator signal naming the dead server or agent, and — where the operator has declared substitutable deployments as a [`pools:` failover pool](/docs/circuit-breaker/#failover-on-mcp-and-a2a-the-same-server-deployed-twice) — reroute to a verified twin before the first byte. Busbar never decides two registrations are interchangeable on its own: the operator names them and busbar checks the pins it already computed. What stays deliberately narrower than the LLM plane is what happens *after* a dispatch has gone out: only operator-listed `repeatable:` operations move, and an accepted A2A task is pinned to the member that accepted it.
- **[In-flight failover](/docs/failover/)** - reroute a failing request before the first byte, even on a streaming request, across protocols.
- **[Health and observability](/docs/observability/)** - `/healthz`, `/stats`, `/metrics`, and the signals to watch.

**Control**: who may spend what ([Governance](/docs/guides/governance/)):

- **[Governance and limits](/docs/guides/governance/)** - signed expiring keys, hierarchical group limits (requests / tokens / budget / concurrency), and pool access control.

The rest of this page ties them together with one production-like configuration.

## End-to-end worked example

The following config creates a production-like setup: a weighted primary pool with fast failover and a cheap overflow, context-length failover between members, session affinity, aggressive tripping with a low streak threshold, and governance with a group limit tree plus a per-model rate card so spend is priced from real token counts.

```yaml
listen: "0.0.0.0:8080"

identity-providers:
  admin-tokens: { module: admin-tokens, token: { env: BUSBAR_ADMIN_TOKEN } }

auth:
  chain:
    - keys                                 # built-in signed-key verifier: callers present minted keys
  signing_key: { file: /run/secrets/busbar-signing.key }  # REQUIRED with `keys`; no auto-gen
  #                                                        # generate with `busbar --generate-signing-key`,
  #                                                        # fleet-shared across every node
  admin_auth: [admin-tokens]           # a bare PROVIDER NAME (defined above)

groups:
  search-team:
    limits:
      - { requests: 300, per: minute }
      - { tokens: 500000, per: minute }
      - { budget: 2000000, per: month }    # $20k/mo cap over every search key

providers:
  anthropic:
    api_key: { env: ANTHROPIC_KEY }
    health:
      mode: dead
      interval_secs: 30
      timeout_secs: 5
  openai:
    api_key: { env: OPENAI_KEY }
  gemini:
    api_key: { env: GEMINI_KEY }

models:
  claude-sonnet:
    provider: anthropic
    max_concurrent: 20
    default_max_tokens: 4096

  gpt-4o:
    provider: openai
    max_concurrent: 20

  gemini-flash:
    provider: gemini
    max_concurrent: 30

  claude-haiku:
    provider: anthropic
    max_concurrent: 40

pools:
  primary:
    members:
      - model: claude-sonnet
        weight: 5
        context_max: 200000
      - model: gpt-4o
        weight: 3
      - model: gemini-flash
        weight: 2
        context_max: 1048576
    affinity:
      mode: session
      header_name: x-session-id
    breaker:
      trip:
        mode: consecutive
        consecutive_n: 2       # trip fast, 2 consecutive failures
      base_cooldown_secs: 5
      max_cooldown_secs: 60
    failover:
      timeout_secs: 30
      max_hops: 3
    on_exhausted: { fallback_pool: overflow }

  overflow:
    members:
      - model: claude-haiku
        weight: 1
    on_exhausted: least_bad    # degraded but available; never hard-503

plugins:
  enabled: true                          # the durable store is a signed plugin tarball in plugins/

store:
  module: sqlite                         # durable (the busbar-store-sqlite plugin); omit for the RAM default
  settings: { db_path: /var/lib/busbar/governance.db }

rate_card:                               # per-model token pricing, micro-units per token
  claude-sonnet: { input_utok: 3.0, output_utok: 15.0 }
  gpt-4o:        { input_utok: 2.5, output_utok: 10.0 }
  gemini-flash:  { input_utok: 0.15, output_utok: 0.6 }
  claude-haiku:  { input_utok: 0.8, output_utok: 4.0 }
per_request_fee: 0
```

What this achieves:

- **Weighted primary dispatch**: `claude-sonnet` gets 50% of traffic, `gpt-4o` 30%, `gemini-flash` 20%.
- **Fast trip**: two consecutive failures opens a member's breaker in the `primary` pool with a 5-second initial cooldown. Organic traffic triggers failover to the next member within the 30-second deadline.
- **Context-length failover**: if `claude-sonnet` rejects a request as too long (200k context), Busbar excludes `claude-sonnet` and retries to `gemini-flash` (1M context) without penalizing the `claude-sonnet` lane.
- **Session affinity**: callers with `x-session-id` headers stay pinned to the same member while it is healthy.
- **Overflow**: if all primary members are exhausted, traffic spills to `claude-haiku`. If haiku is also exhausted, `least_bad` picks the member with the soonest recovery rather than returning 503.
- **Health probing**: `anthropic` lanes are re-probed on trip (`mode: dead`), so a recovered Anthropic backend is brought back promptly without waiting for organic traffic to probe it.
- **Governance**: each team gets a signed, expiring virtual key bound to a `groups:` entry: every limit (requests, tokens, budget, concurrency) lives on the group, and the spend derives from the rate card above. Mint keys with `POST /api/v1/admin/keys`.

To mint a key for the search team, bind it to the `search-team` group declared above, with a label for external reporting:

```bash
curl -s -X POST http://localhost:8081/api/v1/admin/keys \
  -H "Authorization: Bearer $BUSBAR_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
        "name": "team-search",
        "group": "search-team",
        "allowed_pools": ["primary", "overflow"],
        "expires_in": "90d",
        "labels": {"team": "search"}
      }'
```

Admission now walks the `search-team` group's chain (300 requests/min AND 500k tokens/min AND $20k/mo, and any ancestor group's limits too); the request passes only when every limit is under cap, and the rejection names exactly which bucket blocked (group + metric + window). The `labels` ride onto the key's metric series so Grafana can `sum by (team)` without Busbar knowing what a team is.

The response's signed token (shown once, expires in 90 days) is what the team uses as their API key pointed at busbar. They set it wherever they previously set their Anthropic/OpenAI key. Busbar handles the rest.
