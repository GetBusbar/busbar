# In-flight failover

When a lane fails, Busbar reroutes the request to another pool member before your client sees a byte, even mid-stream, across protocol families. This page covers the first-byte boundary, the per-request failover budget, context-length failover, session affinity, and what happens when a pool is exhausted.

Cross-references: [Circuit breaker](/docs/circuit-breaker/) (how lanes trip) · [Pools](/docs/pools/) (structure) · [Configuration](/docs/configuration/) (field reference).

## The first-byte boundary

<svg viewBox="0 0 760 210" role="img" aria-label="A timeline split at the first byte reaching the client: before it, Busbar can transparently reroute connect errors, timeouts, 429s, and 5xxs; after it, no failover is possible because the client already holds tokens." style="width:100%;height:auto;max-width:760px;font-family:ui-sans-serif,system-ui,sans-serif;">
  <rect x="0" y="0" width="760" height="210" fill="#ffffff"/>
  <!-- divider marker -->
  <text x="420" y="34" text-anchor="middle" fill="#334155" font-size="12" font-weight="700">first byte reaches client</text>
  <line x1="420" y1="42" x2="420" y2="150" stroke="#94a3b8" stroke-width="1.5" stroke-dasharray="4 4"/>
  <!-- green (before) -->
  <rect x="56" y="56" width="360" height="64" rx="12" fill="#f0fdf4" stroke="#16a34a" stroke-width="2"/>
  <text x="236" y="84" text-anchor="middle" fill="#166534" font-size="15" font-weight="700">Failover window</text>
  <text x="236" y="105" text-anchor="middle" fill="#15803d" font-size="10.5">connect · timeout · 429 · 5xx  →  reroute</text>
  <!-- red (after) -->
  <rect x="424" y="56" width="280" height="64" rx="12" fill="#fef2f2" stroke="#dc2626" stroke-width="2"/>
  <text x="564" y="84" text-anchor="middle" fill="#991b1b" font-size="15" font-weight="700">No failover</text>
  <text x="564" y="105" text-anchor="middle" fill="#b91c1c" font-size="10.5">client already holds tokens</text>
  <!-- captions -->
  <text x="236" y="150" text-anchor="middle" fill="#475569" font-size="11">The bulk of real provider failures land here.</text>
  <text x="564" y="150" text-anchor="middle" fill="#475569" font-size="11">Mid-stream death → SSE error; client retries.</text>
  <!-- time axis -->
  <line x1="56" y1="180" x2="700" y2="180" stroke="#cbd5e1" stroke-width="1.5"/>
  <polygon points="700,175 712,180 700,185" fill="#cbd5e1"/>
  <text x="56" y="198" text-anchor="start" fill="#94a3b8" font-size="10.5">request starts</text>
  <text x="712" y="198" text-anchor="end" fill="#94a3b8" font-size="10.5">time →</text>
</svg>

Failover is bounded by when the upstream starts streaming a response body to the client. Before the first upstream byte reaches the client, any transport or pre-response failure (connect error, timeout waiting for headers, transient upstream response) transparently fails over to another pool member. From the client's perspective, the request is still in flight.

**This pre-first-byte window covers the bulk of real provider failures**: connect errors and timeouts, `429` rate-limit responses, and `5xx` errors returned on the response headers all arrive *before* any body byte, so they fail over transparently. A failure only becomes unrecoverable once the upstream has already streamed a byte to the client and *then* dies mid-generation.

**Why mid-stream failover is impossible: for every gateway, not just Busbar.** A streaming response is a stateful continuation. Once a byte has been sent, you cannot un-send it: the client has already rendered those tokens. A replacement provider cannot *resume* the first provider's half-finished generation either, it would start a brand-new completion from the prompt, so splicing its fresh output onto the partial stream produces duplicated or contradictory text. The only alternatives are to resend the whole response (the client sees tokens twice) or abandon the partial, neither is transparent. This is a property of streaming itself, so no transparent gateway (LiteLLM and OpenRouter included) does mid-stream failover; it is physics, not a missing feature.

**The one real lever: a configurable pre-release buffer (on the roadmap, not yet built).** The idea: hold the first *K* tokens / *T* ms of the upstream stream before releasing any byte to the client; if the provider dies inside that window, nothing has been sent yet, so Busbar can still reroute. The trade-off is up to *T* ms of added TTFT, so it would be opt-in per pool and default to off. It widens the failover window; it does not claim the impossible mid-stream splice above. Today Busbar has pure pre-first-byte behavior.

**After the first byte**: failover is impossible (per the reasoning above). The client already holds a partial response body. If the upstream then fails mid-stream:
- For SSE responses (OpenAI, Anthropic, Gemini, Cohere, Responses ingress): Busbar emits an SSE `error` event to the client and closes the connection. The lane records the failure, which may trip its breaker.
- For non-SSE responses: the body stream terminates.

In both cases the client must detect the incomplete response and retry. The breaker will have recorded the failure, so a subsequent retry to the same pool is likely to be routed to a different member.

The practical implication: for workloads where mid-stream failure recovery matters, keep responses short or use non-streaming calls where the full response is buffered before delivery. For long streaming responses, implement client-side retry with session affinity disabled on retry (or send the retry to a different pool).

## Failover budget and exclusions

Each request carries a per-request failover budget: a wall-clock deadline (`timeout_secs`) and a hop-count cap (`max_hops`), both configured per pool under `failover:`, plus an optional `exclusions` member blocklist. The field-by-field reference (types, defaults, and validation) lives in **[Configuration → `failover`](/docs/configuration/#failover)**; this page stays conceptual.

`exclusions` is a per-pool member blocklist. A model listed in `exclusions` is never selected through the pool: not as the initial pick and not as a failover destination. A request to the pool can never land on it. The model itself stays fully routable by its own name, because direct routing bypasses pools entirely: `"model": "last-resort-model"` on `/v1/chat/completions`, or `POST /last-resort-model/v1/messages`. That is the point of excluding rather than removing: the member keeps its `/stats` row (an expensive last resort a human or a specific job can still invoke deliberately), while the pool's automatic selection never spends on it. Each `exclusions` entry must name a member of this pool.

Already-tried lanes are accumulated in an `excluded` set across hops for the lifetime of the request. A lane that succeeded (2xx headers) but whose body then failed before the first byte is refunded its `max_requests` budget spend and is also excluded from further hops on that request.

## Catching hangs

Some providers fail by hanging: they accept the connection and never return response headers. The per-request failover budget does not catch this well, because the hang quietly eats the whole budget on one member before any hop can happen. Busbar closes that gap with a per-attempt cap on time to response headers, configured as `attempt_timeout_ms`. When the cap expires, the attempt is recorded as a transient breaker failure and the request hops to the next member immediately. Set it on a model as that model's default, and override it per pool member: the same model can carry a 10s cap in a batch pool and a 50ms cap in a latency-critical one. The cap never cuts a stream that has started answering (it covers connect + headers only), and it is always floored by the request's remaining `failover.timeout_secs`. Full semantics and examples in the [configuration reference](https://getbusbar.com/docs/configuration/#per-attempt-timeouts-attempt_timeout_ms).

## Context-length failover

When a request is too large for a member (the provider returns a context-length error), Busbar does not penalize the lane: it was healthy; the request simply did not fit. Instead, it excludes from this request's candidate set any member whose declared `context_max` is ≤ the failed lane's, then retries to a larger (or unknown-context) member.

```yaml
pools:
  long-context:
    members:
      - model: claude-haiku
        context_max: 200000
      - model: gemini-2.5-flash
        context_max: 1048576
```

A member with no `context_max` set is never excluded on context-length grounds, it is always a candidate, and if it also rejects the request as too long, that rejection is still treated as a context-length failure (no breaker penalty) and the lane is simply excluded for the rest of this request.

Context-length failover is suppressed on 5xx responses, even if the body mentions a context-length-related code, to prevent a broken backend from dodging normal breaker penalties.

## Session affinity

Pin a session to one member while it remains healthy: set `affinity.mode: session` on the pool and, optionally, `affinity.header_name` (the field reference for `mode` and `header_name` with their defaults is in **[Configuration → `affinity`](/docs/configuration/#affinity)**).

When a request carries `x-session-id: <value>` (the default header), Busbar pins that session to a specific member. If the pinned member is unavailable (tripped, at-capacity, or excluded), affinity is ignored and normal SWRR selection runs, affinity is a preference, and an unhealthy member releases it. The client receives no signal that the pin was broken. `session` is the only supported `mode`; `header_name` defaults to `x-session-id`.

## Pool exhaustion

When all candidates are unavailable, tripped, excluded, or at-capacity, the pool is exhausted. The `on_exhausted` action decides what happens:

```yaml
pools:
  primary:
    members:
      - model: fast-model
      - model: fallback-model
    on_exhausted: { fallback_pool: overflow }   # try another pool

  overflow:
    members:
      - model: cheap-model
    on_exhausted: least_bad    # degraded but not a hard error
```

Four actions are available:

- **`reject`** (default): return `503` with `Retry-After`. When a member is in breaker cooldown, `Retry-After` is the soonest genuine cooldown expiry; when exhaustion is pure saturation (every member at its `max_concurrent` limit, breakers closed), it is a small saturation floor rather than the misleading `1`.
- **`least_bad`**: select the least-bad member (the one whose cooldown expires soonest that still has a free concurrency permit) and send the request anyway, even though its breaker is Open, with a loud degraded-service warning. A soonest member that is itself at capacity is skipped in favour of a servable sibling rather than returning a hard `503`.
- **`{ fallback_pool: <name> }`**: route to another named pool. Loop-guarded: cycles through the fallback chain are detected and broken.
- **`{ queue: { max_ms: <ms> } }`**: wait a **bounded** time for a concurrency permit to free on an at-capacity member, then dispatch on the freed lane. The waiter acquires directly on the candidate lanes' own FIFO semaphores, so a freed permit wakes **exactly one** waiter (no lost wakeup, no thundering herd). The wait is bounded by `min(max_ms, remaining failover budget)` (it can never block past `failover.timeout_secs`), and the moment it wins a permit it **re-checks the breaker** on that lane (which may have tripped Open while queued); a lane whose breaker opened while waiting is dropped and the wait continues on the rest. On deadline, a closed semaphore, or no remaining candidates it falls through to `reject` (`503` + `Retry-After`). Queueing only helps **at-capacity** (saturation) exhaustion: if every excluded member is dead / budget-exhausted / breaker-open, nothing will free a slot, so the wait is skipped and it sheds immediately. `max_ms` is validated `> 0` and `<=` the resolved failover budget (`failover.timeout_secs × 1000`). Live park depth is exported as `busbar_pool_queued{pool}`.

The full value reference, including the accepted alias spellings for each keyword, lives in **[Configuration → `on_exhausted`](/docs/configuration/#on_exhausted)**.

A `503` from pool exhaustion sets `Retry-After` so clients and upstream proxies know how long to back off. The `/metrics` counter `busbar_requests_total{outcome="exhausted"}` tracks these. A rising exhausted rate combined with a falling `busbar_upstream_attempts_total` for the pool's lanes indicates breakers are tripping faster than they recover, check `busbar_breaker_trips_total` and `/stats` for individual lane state.

Multi-hop fallback chains, `primary → overflow → emergency`, work as long as they form a DAG (no cycles back to a visited pool). A self-referential or cyclic chain is rejected at config validation; a runtime loop is caught by the loop guard and results in a 503.

---
