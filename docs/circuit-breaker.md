# Circuit breaker

Busbar attributes every upstream failure to a cause, benches only the target at fault, and recovers it automatically with a single-flight probe. This page covers the breaker's scope, how failures are classified, the state machine, trip conditions, cooldown, and configuration.

The breaker runs on **all three planes**: a pool member on the LLM plane, an MCP tool server, an A2A agent. Most of this page is written in the LLM plane's vocabulary (pools, lanes and cells) because that is where member selection lives; [the breaker on the MCP and A2A planes](#the-breaker-on-the-mcp-and-a2a-planes) covers what is the same (everything about health) and what is deliberately different (there is no failover).

Cross-references: [Pools](/docs/pools/) (structure) · [In-flight failover](/docs/failover/) (what happens when a lane trips) · [Configuration](/docs/configuration/) (field reference) · [MCP](/docs/mcp/) and [A2A](/docs/a2a/) (the two other planes this breaker runs on, and what each returns when a target is tripped).

## Concepts: pools, lanes, and cells

> New to pools? The [**Pools**](pools.md) guide covers what a pool is, how member selection works, the full config reference, and copy-paste recipes. This section is the short version, focused on how the three terms map to the circuit breaker below.

Three terms underpin everything else.

**Lane**: one model on one provider. A lane has a concurrency semaphore (`max_concurrent`), an optional lifetime budget (`max_requests`), and health state. A lane is declared with a `models:` entry and backed by exactly one provider.

**Pool**: a named, weighted set of member lanes. Pools are optional; you can route to a model directly. A request routed to a pool is dispatched to one member at a time, with automatic failover if the chosen member is unhealthy or fails.

**Breaker cell**: the circuit-breaker state (Closed / Open / HalfOpen, failure streak, cooldown, error window) for a specific (pool, lane) pair. A lane that is a member of three pools carries three independent breaker cells. One pool's failures cannot trip the same lane in another pool.

The split matters for operator decisions:

| Concern | Scope | Implication |
|---|---|---|
| Concurrency cap (`max_concurrent`) | Lane-global | Aggregated across every pool the lane belongs to. |
| Lifetime budget (`max_requests`) | Lane-global | A budget-exhausted lane is unusable everywhere. |
| Breaker FSM (Open/Closed/HalfOpen) | Per (pool, lane) | A tripped lane in pool A remains eligible in pool B. |
| SWRR weight tracking | Per pool | Each pool does its own smooth weighted round-robin. |

Direct routes (`POST /<model>/v1/messages`) and the ad-hoc route (`POST /<provider>/<model>/v1/messages`) use a special lane-default breaker cell (pool name `""`), shared only among direct callers and `/stats`. An active health probe that succeeds clears the breaker in **all** cells for that lane simultaneously.

---

## What is per-pool vs lane-global

As described above, the breaker FSM: state, streak, cooldown, error window, is stored per (pool, lane) in a `BreakerCell`. A lane can be Open in one pool and Closed in another simultaneously.

What is **not** per-pool: the lane's concurrency semaphore and its lifetime budget. Those govern the shared upstream service and apply across all pools the lane belongs to.

## Disposition pipeline: how failures are classified

Before the breaker records anything, every upstream outcome runs through a two-stage classification pipeline.

**Stage 1: protocol normalization.** The per-protocol reader extracts a raw error signal: HTTP status, provider JSON error code (if any), and a `Retry-After` value (if the upstream sent one).

**Stage 2: `classify` → Disposition.** The raw signal is mapped to one of these outcomes, using the lane's configured `error_map` (provider JSON codes → disposition) first, then HTTP-status fallback:

| Disposition | What triggers it | What the breaker does |
|---|---|---|
| `TransientUpstream` | 5xx, 429, 408, 529, network error, timeout | Records a failure; drives trip evaluation. |
| `HardDown` | 401, 403 (auth/billing); JSON codes mapped to `auth` or `billing` | Trips the lane immediately, regardless of window/streak, with a 30-minute sticky cooldown. |
| `ClientFault` | 4xx other than 401/403/408/429 | Relayed verbatim; lane records nothing (the request was bad, not the upstream). |
| `ContextLength` | Provider signals context-length exceeded. The built-in code detection applies on 400/413 only; an operator `error_map` mapping to `context_length` applies on any non-5xx status | No lane penalty; request fails over to a larger-context member (see [context-length failover](/docs/failover/#context-length-failover)). |

One important guard: a `context_length` mapping in `error_map` is **suppressed on any 5xx**, so a provider returning 500 with a body that mentions `context_length` is still classified as `TransientUpstream`. This prevents a misconfigured or adversarial backend from masking an outage as a context-limit.

## Breaker state machine

<svg viewBox="0 0 720 340" role="img" aria-label="Breaker state machine: Closed trips to Open when the trip condition is met; Open moves to HalfOpen when the cooldown expires; HalfOpen returns to Closed if the recovery probe succeeds, or back to Open with an escalated cooldown if the probe fails." style="width:100%;height:auto;max-width:720px;font-family:ui-sans-serif,system-ui,sans-serif;">
  <defs>
    <marker id="brk-arw" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M0,0 L10,5 L0,10 z" fill="#64748b"/>
    </marker>
    <marker id="brk-ok" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M0,0 L10,5 L0,10 z" fill="#16a34a"/>
    </marker>
    <marker id="brk-fail" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M0,0 L10,5 L0,10 z" fill="#dc2626"/>
    </marker>
  </defs>
  <rect x="0" y="0" width="720" height="340" fill="#ffffff"/>
  <!-- nodes -->
  <rect x="48" y="48" width="180" height="64" rx="12" fill="#f0fdf4" stroke="#16a34a" stroke-width="2"/>
  <text x="138" y="80" text-anchor="middle" fill="#166534" font-size="16" font-weight="700">Closed</text>
  <text x="138" y="99" text-anchor="middle" fill="#15803d" font-size="11">healthy, serving</text>
  <rect x="492" y="48" width="180" height="64" rx="12" fill="#fef2f2" stroke="#dc2626" stroke-width="2"/>
  <text x="582" y="80" text-anchor="middle" fill="#991b1b" font-size="16" font-weight="700">Open</text>
  <text x="582" y="99" text-anchor="middle" fill="#b91c1c" font-size="11">tripped, skipped</text>
  <rect x="270" y="236" width="180" height="64" rx="12" fill="#fffbeb" stroke="#d97706" stroke-width="2"/>
  <text x="360" y="268" text-anchor="middle" fill="#92400e" font-size="16" font-weight="700">HalfOpen</text>
  <text x="360" y="287" text-anchor="middle" fill="#b45309" font-size="11">one probe admitted</text>
  <!-- Closed -> Open -->
  <line x1="228" y1="80" x2="486" y2="80" stroke="#64748b" stroke-width="2" marker-end="url(#brk-arw)"/>
  <text paint-order="stroke" stroke="#ffffff" stroke-width="5" stroke-linejoin="round" x="357" y="70" text-anchor="middle" fill="#334155" font-size="12" font-weight="600">trip condition met</text>
  <!-- Open -> HalfOpen -->
  <path d="M540,112 Q470,160 452,236" fill="none" stroke="#64748b" stroke-width="2" marker-end="url(#brk-arw)"/>
  <text paint-order="stroke" stroke="#ffffff" stroke-width="5" stroke-linejoin="round" x="470" y="176" text-anchor="middle" fill="#334155" font-size="12" font-weight="600">cooldown expires</text>
  <!-- HalfOpen -> Closed -->
  <path d="M270,258 Q168,202 150,116" fill="none" stroke="#16a34a" stroke-width="2" marker-end="url(#brk-ok)"/>
  <text paint-order="stroke" stroke="#ffffff" stroke-width="5" stroke-linejoin="round" x="176" y="182" text-anchor="middle" fill="#166534" font-size="12" font-weight="600">probe succeeds</text>
  <!-- HalfOpen -> Open (fail) -->
  <path d="M452,272 Q642,236 582,116" fill="none" stroke="#dc2626" stroke-width="2" stroke-dasharray="5 4" marker-end="url(#brk-fail)"/>
  <text paint-order="stroke" stroke="#ffffff" stroke-width="5" stroke-linejoin="round" x="632" y="204" text-anchor="middle" fill="#991b1b" font-size="12" font-weight="600">probe fails</text>
  <text paint-order="stroke" stroke="#ffffff" stroke-width="5" stroke-linejoin="round" x="632" y="220" text-anchor="middle" fill="#b91c1c" font-size="11">(escalated cooldown)</text>
</svg>

**Closed**: the lane is healthy and receives traffic. Failures are recorded against the window/streak. A single failure that does not meet the trip condition arms a brief cooldown on the cell (the lane is temporarily deprioritized) but the breaker stays Closed.

**Open**: the lane is tripped and skipped during member selection until its cooldown expires. Requests to this pool during this period are either failed over to another member or handled by the pool's `on_exhausted` policy.

**HalfOpen**: when the cooldown expires, the next selection attempt transitions the cell to HalfOpen via a compare-and-swap. Exactly one request is admitted as the recovery probe (single-flight: no thundering herd). `/healthz`, `/stats`, and SWRR selection reads are side-effect-free: they never consume the probe slot. If the probe succeeds, the lane recovers to Closed (streak and error window cleared). If it fails, the lane returns to Open with an escalated cooldown.

## Trip conditions

Configure per pool with `breaker.trip`:

**`error_rate`** (default): trips when the fraction of failures in the sliding `window_secs` reaches `threshold`, provided at least `min_requests` outcomes have accrued. Both numerator (errors) and denominator (total) come from the same window, so a burst of successes after a burst of failures can bring the rate below threshold before the window expires.

```yaml
breaker:
  trip:
    mode: error_rate
    window_secs: 30
    threshold: 0.5      # trip at 50% error rate
    min_requests: 5     # never trip on fewer than 5 in-window outcomes
```

**`consecutive`**: trips after `consecutive_n` consecutive failures, regardless of interspersed successes in the wider window. More aggressive; a good choice for a pool whose members are either fully up or fully down (batch APIs, fine-tuned models with narrow failure modes).

```yaml
breaker:
  trip:
    mode: consecutive
    consecutive_n: 3
```

Choose `error_rate` when you want the breaker to absorb a few errors without tripping (normal flakiness tolerance). Choose `consecutive` when a single sustained failure streak indicates the backend is down and you want fast failover with no "maybe it'll recover" window.

## Cooldown and backoff

Cooldown grows exponentially with the consecutive failure streak:

```
target   = min(base_cooldown_secs × 2^streak, max_cooldown_secs)
cooldown = clamp(target ± 10% jitter, max(target / 2, 1s), max_cooldown_secs)
```

Jitter is seeded by a hash of the current time, the cell's memory address, and the streak: so simultaneously tripped lanes desynchronize their recovery probes rather than flooding a recovering backend together.

The jitter band itself is floored at 1 second, so simultaneously tripped lanes always spread their recovery probes rather than collapsing onto the same instant. The cooldown value otherwise follows the formula above (with the default `base_cooldown_secs` of 15, the first cooldown is never near zero).

A server `Retry-After` header is always honored as a **floor**. If the upstream says to wait 90 seconds but your `max_cooldown_secs` is 60, the lane stays Open for 90 seconds. The floor is hard-capped at 24 hours to prevent overflow on malformed headers.

There is no configuration knob to disable `Retry-After` honoring: it is always on.

Default cooldowns (no `breaker:` block, or block present with fields omitted): `base_cooldown_secs: 15`, `max_cooldown_secs: 120`.

## Hard-down vs transient

**Transient** faults (5xx / timeout / rate-limit / overload / network) contribute to the trip window/streak. If the trip condition is met, the lane opens with an exponential cooldown. It will self-recover via the HalfOpen probe.

**Hard-down** faults (auth or billing, either by HTTP status 401/403 or by a matching `error_map` entry) trip the lane immediately: bypassing the window/streak entirely, with a **30-minute sticky cooldown** (`HARD_DOWN_COOLDOWN_SECS = 1800`). The distinction in behavior:

- An `auth` hard-down surfaces an auth error to the caller. If the caller presented their own key (passthrough), the upstream `401`/`403` is relayed verbatim; when Busbar's configured key is wrong, the caller instead gets a normalized ingress-native auth error (the status is remapped to the ingress protocol and the upstream body is suppressed). The lane is benched in this pool's cell.
- A `billing` hard-down fails the request over to another pool member (or exhausts the pool). The error is not relayed: the caller sees a failover, not a billing error.

A hard-down lane is still recoverable: a successful active health probe (or the organic half-open probe on cooldown expiry) brings it back automatically, no restart needed. Hard-down deliberately does **not** set the permanent `dead` flag (that would block recovery).

After an auth or billing hard-down, `/stats` shows the lane with `usable: false`, a non-zero `cooldown_remaining_s`, and a `dead_reason` describing the fault (an `auth rejected …` or `billing / insufficient balance` message) rather than `dead: true`. Fix the credential behind the provider's `api_key` reference for an auth fault or fund the account for a billing fault, and Busbar recovers on the next successful probe.

## Circuit breaker configuration

The breaker is configured per pool with a `breaker:` block: a trip condition (`trip.mode`
`error_rate` or `consecutive`, with its threshold/window/streak knobs) and the cooldown bounds
(`base_cooldown_secs`, `max_cooldown_secs`) that shape the exponential backoff described above.
Every field is optional; omitting the block is equivalent to accepting all defaults, and there is
no inheritance between pools. Each pool's breaker is independent.

The field-by-field reference (every `breaker` key with its type, default, and validation rule)
lives in one place: **[Configuration → `breaker`](/docs/configuration/#breaker)**. This guide stays
conceptual so the two never drift.

---

## The breaker on the MCP and A2A planes

An upstream that is hard down does not only fail. It fails **slowly**. Without a breaker, every call to a tool server whose auth was revoked or whose billing lapsed pays the full request timeout before it can fail: latency burned on a known-dead upstream, a concurrency slot held while it burns, retries piling onto a server that is already struggling, and no operator signal that anything is wrong. The operator finds out from a user complaint.

So the breaker is not an LLM-plane feature that MCP and A2A borrow. It is keyed on the **target** a request is about to reach, and a target is whatever the plane addresses: a `(pool, lane)` cell on the LLM plane, one registered tool server on MCP, one registered agent on A2A.

**Read the state of this honestly before you configure anything.** As of this revision the breaker's **trip and fast-fail** are live on the MCP client leg (both transports) and on the A2A relay (all three bindings): every registered tool server and agent has its own cell on the one core breaker, a failing target trips it on the same thresholds the LLM plane uses, a tripped target refuses in milliseconds — MCP answers `503` + `Retry-After` + a JSON-RPC error (never an `isError` tool result: the call never happened), A2A answers the submission `rejected` with a task id to poll — and recovery is the same single-flight half-open probe. What is **not yet wired** is failover and reroute on these planes: the selection seam and the `tool_pools:`/`agent_pools:` vocabulary below are real, proven and configurable, but on a live tool call or task submission no second candidate is tried today — a tripped target is refused, never rerouted. The failover half of this section is therefore the contract the seam is built to, not something you can observe on a request yet. The LLM plane, and everything above this section, is live and has been for every release since the breaker landed.

**A failure that did not trip the cell does not bench it, and on these planes that is a difference from the LLM plane rather than an omission.** ADR-0002 states the `TransientUpstream` rule as one sentence with two halves — drive trip evaluation *and* re-arm an exponential cooldown; **fail over** to the next candidate. On an LLM pool the cooldown is the *deprioritisation* half: it says "prefer a sibling for a while", and the failover half is what keeps the caller served while it lasts. These planes ship the first half and, as the paragraph above says out loud, not the second — so on a degenerate single-member cell the same cooldown would mean "refuse **every** caller of this server for the next 15–120 seconds", handed out after **one** transient blip, on a cell whose own trip predicate had just declined to trip, and rendered to the caller as `-32030` … *"open after repeated failures"*. So the MCP and A2A cells refuse on a **trip** and nothing less: the published predicate, `error_rate >= 0.5` over at least `min_requests` outcomes in the 30-second window. An upstream's own `Retry-After` is still honoured, for as long as the upstream asked for — that is the upstream's backpressure, not Busbar inventing an outage. On the LLM plane, where the walk has somewhere else to go, the sub-threshold cooldown is unchanged.

### What is identical

The Closed → Open → HalfOpen state machine, the two-stage disposition pipeline that decides whether an outcome was the upstream's fault or the caller's, the `error_rate` and `consecutive` trip modes, exponential cooldown with jitter, `Retry-After` honoured as a floor, hard-down's sticky cooldown, and single-flight half-open recovery. There is **one** breaker in the engine, keyed by `(pool, lane)`, and a tool server or an agent is a lane in a pool like any other. No second state machine was written for these planes and none should be.

**There is one place to configure a breaker, and it is `pools.<pool>.breaker:`.** There is no `breaker:` key under `tools:` or under `agents:`: an earlier version of this page and of the configuration reference said there was, and that was wrong. `tools:` and `agents:` use `deny_unknown_fields`, so a config written against that older text does not start Busbar; it fails at boot naming the key. Nor is there breaker tuning on a tool pool or an agent pool: `tool_pools:` and `agent_pools:` accept exactly two keys, `members:` and `repeatable:`, and reject anything else at boot. So on these planes the breaker's thresholds and cooldowns are the built-in defaults, and narrowing them is a config surface that has not been written rather than one you are missing.

### Failover on MCP and A2A: the same server, deployed twice

An earlier draft of this page said there was no failover on these planes, and gave a reason: a tool is namespaced to the server that exports it, so there is no second server to send the call to. That reason was about **two different vendors' servers**, and for that case it still holds. It was never true of the case operators actually run.

**Nobody runs one instance of anything important.** One MCP server image in two regions, a hosted instance beside a self-hosted twin, one agent registered twice against the same card — that is the normal shape, and busbar's inability to be told about it was busbar's absence, not the protocol's.

So `tool_pools:` and `agent_pools:` exist, they are **opt-in**, and an absent section is exactly today's behaviour:

```yaml
tools:
  search-eu: { url: https://eu.search.example/mcp, pin: { mechanism: cert_spki, key: "…" } }
  search-us: { url: https://us.search.example/mcp, pin: { mechanism: cert_spki, key: "…" } }

tool_pools:
  search:
    members: [search-eu, search-us]     # ORDERED; the first is the primary
    repeatable: [search_code]           # operations safe to perform TWICE. Default: none.

agent_pools:
  planner:
    members: [planner-eu, planner-us]
```

They are one grammar, in core, over two registries — the same sentence `pools:` already says on the LLM plane, so an operator learns the concept once. A pool may not straddle two planes: the section a pool is written in **is** which plane it is on, and a `tool_pools:` member naming an `agents:` entry refuses boot naming the section the entry really lives in.

#### Interchangeability is CHECKED, not claimed

This is the part that makes it safe. Naming two servers in a pool is **not** what makes them interchangeable. busbar compares the fingerprints it already computes — the approved tool schema digest on MCP, the approved canonical card fingerprint on A2A — and moves a request between two candidates only when those pins **agree**.

- Same image in two regions ⇒ same schemas, same descriptions, **same fingerprint** ⇒ interchangeable, provably.
- Two different vendors' `search` tools ⇒ different fingerprints ⇒ **refused**, with both digests named.
- A registration with nothing approved yet ⇒ never matches, not even another unapproved one. Two unknowns are not one fact.

The operator is asserting only *"these names are the same deployment"*, and that claim is verified before a single request moves. Failing over between genuinely different tools could hand a model a tool carrying different instructions, which is a confused deputy; it is refused rather than defaulted.

#### A REROUTE IS NOT A RETRY, and the difference is the safety rule

| movement | has anything been sent? | default |
|---|---|---|
| the primary's breaker is Open — **reroute** | no | **allowed** |
| the call went out and failed — **retry** | yes | **refused** |

When the breaker is Open the request never left busbar, so sending it to an equivalent deployment duplicates nothing. That is the case an agent never learns about, and it is on by default.

Once a call **has** gone out, moving it is a genuine repeat of work an upstream may already have done — and two deployments of the same image makes that worse, not better, because both are wired to the same downstream. `send_email` is not retried. `charge_card` is not retried. Only an operation the operator has written into `repeatable:` is, and there is deliberately no `repeatable: all` and no switch that turns the rule off wholesale.

The two rules compose, and the composition is the whole safety story: **repeat a call only when the pins match AND the operation is safe to repeat.**

#### What the breaker buys when there is nowhere to go

For a single registration with no pool, unchanged: **failing fast instead of failing slowly**, and an operator-visible reason why.

> **Landed state (1.6.0):** the selection seam, its config vocabulary and its proofs are in `crate::failover`, running on the one `try_admit_breaker` the LLM plane uses. Wiring the MCP dispatch and A2A relay call sites to it is a separate change; until it lands, a configured pool is validated at boot but not yet consulted at dispatch. This note is here rather than omitted because a page that describes a path before it is wired is how a reader learns something false.

### What a tripped target returns: MCP

A tripped tool server answers HTTP **`503`** with a **`Retry-After`** header populated from the cell's own remaining cooldown: an exact number rather than a guess, the same shape budget rejection already uses with `429`. The body is a **JSON-RPC error** with code **`-32030`**, in Busbar's implementation-defined band (JSON-RPC 2.0 §5.1 reserves `-32000`..`-32099` for exactly this), carrying structured `data`:

```json
{ "reason": "upstream_unavailable", "server": "acme", "retry_after_ms": 12000 }
```

The breaker is consulted before any socket, immediately after the authorization gate and before the dispatch loop, and the task-creating path consults it at the same position and *before* the task row is minted (`crates/busbar-core/src/mcp/method.rs:1410-1431`, `:1735-1754`; the refusal itself is `:2070-2109`). [MCP](/docs/mcp/#what-a-tripped-upstream-returns) carries the full response.

**It is an error, never a tool result with `isError: true`.** MCP's `isError` means *the tool ran and it failed*. A tripped breaker means *the call never happened*. Returning the second as the first tells the calling model that a tool executed and reported a failure. The model then reasons from a lie, and may report that false result onward as fact. The reserved JSON-RPC codes are each wrong for a specific reason: `-32603` internal error blames Busbar, `-32601` method-not-found says the tool does not exist when it does, and `-32602` invalid-params blames the caller.

### What a tripped target returns: A2A

A2A has what MCP lacks: task state is first class. A fresh submission to a tripped agent yields the task state **`rejected`**, not `failed`, returned **with a task id**, alongside `503` and the same exact `Retry-After` (`crates/busbar-core/src/a2a/relay.rs:1462-1481`, `crates/busbar-core/src/a2a/receive.rs:1991-2016`). A verb naming an *existing* task is different: the task lives at exactly one backend and a tripped backend must not end it, so the verb gets the refusal and the row keeps its last-known state. [A2A](/docs/a2a/#what-a-tripped-agent-returns) carries the full response.

The two states are different claims and the spec gives us both. `failed` means we tried and it broke. `rejected` means **we did not accept this work**, which is literally what a breaker refusing to start a call has done. The caller still gets a task id to poll and correlate, so it loses nothing, and **the calling agent decides whether and when to retry.** Busbar does not invent a retry schedule on another agent's behalf.

### What the operator sees

On all three planes a trip is an operator-facing signal that names the target and the cause the disposition pipeline attributed, and on MCP and A2A the caller is told too, in that plane's own vocabulary — the two sections above. What a hard-down tool server no longer produces is a queue of slow calls whose first report comes from a user.

What is still missing on MCP and A2A is only the *reroute*: with the selection walk unmounted, a tripped target is refused rather than sent to a verified twin. See the landed-state note above.

---

## Active health probing

By default, Busbar learns a lane is healthy or sick entirely from real traffic outcomes (passive health). Active probing adds a background task, configured per provider under `health:`, that sends periodic probe requests to check lanes independently of organic traffic. There are three modes:

- **`none`** (default): no probing; pure passive health from organic traffic.
- **`dead`**: re-probe only tripped or hard-down lanes, to recover a lane promptly once a backend restores without paying to probe healthy ones.
- **`active`**: probe every lane, including healthy ones, so a silently-dark backend is tripped out before organic traffic hits it. Sends a tiny billable one-token request per interval.

The field reference (`mode`, `interval_secs`, `timeout_secs`, their defaults and the 1-second floors) lives in **[Configuration → Health probing](/docs/configuration/#health-probing)**.

Probe behavior:

- A 2xx probe recovers a tripped lane to Closed and clears all per-pool breaker cells for that lane. It bumps the lane's `ok` stat counter exactly once.
- A failed probe records a failure against the per-pool breaker configuration (using the same disposition pipeline as organic traffic). This can trip a healthy-but-sick lane in `active` mode.
- A lane with no configured key is skipped (probing it would only produce 401s and thrash the breaker).

Choosing a mode: `none` is fine for pools with multiple members, one member going down will be detected on the first organic hit and failed over. Use `dead` when you care about prompt recovery without paying for constant probes. Use `active` when you operate a pool with few members and need pre-emptive trip-out of a dark backend.

---
