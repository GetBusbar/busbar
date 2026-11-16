# Tool and agent trust: verify-on-call

Busbar's core promise is to control what an AI can do **before** it acts. For the two planes that
front remote capabilities — MCP tool servers (`tools:`) and A2A agents (`agents:`) — that promise is
kept by **verify-on-call**: every `tools/call` and every agent delegation re-verifies the upstream's
advertised definition against the fingerprint you approved, live, within seconds, *before* the call
is dispatched. A tool or agent whose definition changed is refused, not called.

This page is the operator's reference for that model: what a fingerprint is, how verify-on-call
bounds staleness with `verify_ttl` and coalesces load with single-flight, why it fails closed, the
one honest limit of any proxy, and the single knob you have over it.

Cross-references: [MCP](/docs/mcp/) (the tool plane) · [A2A](/docs/a2a/) (the agent plane) ·
[Configuration](/docs/configuration/) (field reference) · [Diagnostics](/docs/diagnostics/).

---

<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 960 340" role="img" aria-label="Approval is checked before execution. Per-tool contract drift stays refused until explicit reapproval; registration recovery is separate." style="width:100%;height:auto;font-family:ui-sans-serif,system-ui,sans-serif">
<title>Approval is checked before execution</title><defs><marker id="trust-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0 0 L10 5 L0 10 Z" fill="#a3e635"/></marker></defs>
<rect width="960" height="340" rx="12" fill="#111a2e"/><text x="32" y="38" fill="#e6edf7" font-size="20" font-weight="700">Approval is checked before execution</text>
<rect x="32.0" y="76" width="197.0" height="108" rx="10" fill="#1a2740" stroke="#2c3a52" stroke-width="2"/>
<text x="130.5" y="105" text-anchor="middle" fill="#e6edf7" font-size="17" font-weight="700">Discover</text>
<text x="130.5" y="133" text-anchor="middle" fill="#94a3b8" font-size="14">Read tool or agent</text>
<text x="130.5" y="154" text-anchor="middle" fill="#94a3b8" font-size="14">Compute fingerprint</text>
<path d="M234.0 130 H258.0" stroke="#a3e635" stroke-width="2" marker-end="url(#trust-arrow)"/>
<rect x="265.0" y="76" width="197.0" height="108" rx="10" fill="#1a2740" stroke="#a3e635" stroke-width="2"/>
<text x="363.5" y="105" text-anchor="middle" fill="#e6edf7" font-size="17" font-weight="700">Approve + pin</text>
<text x="363.5" y="133" text-anchor="middle" fill="#94a3b8" font-size="14">Operator review</text>
<text x="363.5" y="154" text-anchor="middle" fill="#94a3b8" font-size="14">Record contract</text>
<path d="M467.0 130 H491.0" stroke="#a3e635" stroke-width="2" marker-end="url(#trust-arrow)"/>
<rect x="498.0" y="76" width="197.0" height="108" rx="10" fill="#1a2740" stroke="#2c3a52" stroke-width="2"/>
<text x="596.5" y="105" text-anchor="middle" fill="#e6edf7" font-size="17" font-weight="700">Verify on call</text>
<text x="596.5" y="133" text-anchor="middle" fill="#94a3b8" font-size="14">Freshness policy</text>
<text x="596.5" y="154" text-anchor="middle" fill="#94a3b8" font-size="14">Compare fingerprint</text>
<path d="M700.0 130 H724.0" stroke="#a3e635" stroke-width="2" marker-end="url(#trust-arrow)"/>
<rect x="731.0" y="76" width="197.0" height="108" rx="10" fill="#1a2740" stroke="#2c3a52" stroke-width="2"/>
<text x="829.5" y="105" text-anchor="middle" fill="#e6edf7" font-size="17" font-weight="700">Dispatch</text>
<text x="829.5" y="133" text-anchor="middle" fill="#94a3b8" font-size="14">Approved contract</text>
<text x="829.5" y="154" text-anchor="middle" fill="#94a3b8" font-size="14">Caller grant</text>
<path d="M596.5 184 V226" stroke="#f87171" stroke-width="2"/><rect x="451.5" y="226" width="290" height="54" rx="8" fill="#271e2a" stroke="#f87171"/><text x="596.5" y="259" text-anchor="middle" fill="#fca5a5" font-size="15" font-weight="600">Changed approved tool: refuse</text>
<text x="32" y="318" fill="#94a3b8" font-size="14">Per-tool contract drift stays refused until explicit reapproval; registration recovery is separate.</text></svg>

## The fingerprint: name + args + description

A remote tool is a function the model calls, and an agent is a card that advertises skills. What the
model reads to decide *how* to call — the tool's **name**, its **argument schema**, and its
**description** — is exactly what an attacker would change to redirect it. So Busbar pins all three
in one fingerprint:

- **MCP** hashes name + description + input schema into one per-tool `sha256:` digest over a
  canonical rendering, so re-ordering a schema's keys is not drift but changing one character of a
  description is (the MCP plane plugin, `busbar-plane-mcp`: `trust.rs`, `tool_digest`).
- **A2A** pins the card: a signed card is verified against the operator's out-of-band issuer key,
  or a transport-pinned mechanism (`cert_spki`, `mtls`) checks the key the serving hop presented, as
  the connector observed it; either way the card document's fingerprint is what is approved
  (`busbar-plane-a2a`: `card_trust.rs`). A registration with `pin.mechanism: unpinned` has no
  authenticity root, so it can never be approved and never serves.

The plane only reports what it saw. The verdict is the kernel's: the plane records each sighting on
the kernel's trust book and asks it whether the call may go; a first sighting is refused until you
approve it on `/admin/trust`, and a changed fingerprint is quarantined
(`crates/busbar-kernel/src/trust/book.rs`, `judge`). You approve that fingerprint once.
Verify-on-call re-compares it on every call.

> A digest over the received bytes would raise false drift on a meaningless re-order and teach you
> that drift alerts are noise. The canonical rendering is what makes "the description changed" and
> "the schema grew a field" real signals and "the keys sorted differently" a non-event.

---

## Verify-on-call, bounded by `verify_ttl`

On the request path — a `tools/call`, or an agent delegation — before the fingerprint comparison that
decides whether the call goes out, Busbar checks the age of the upstream's last observation:

- **Fresh** (`now - fetched_at < verify_ttl`): reuse the snapshot, compare, dispatch.
- **Stale** (`now - fetched_at >= verify_ttl`): re-fetch the upstream's advertised surface — an MCP
  `tools/list`, an A2A signed card — re-hash it, publish it under an atomic generation bump, then
  compare against what you approved.

`verify_ttl` is the **longest an observation may be reused** on the request path. It defaults to
**5 seconds** on both planes. The intrinsic verify→dispatch race is already milliseconds to seconds,
so sub-second precision buys nothing; five seconds bounds worst-case drift-serving to seconds while
staying off the request's own latency for the common (fresh) case.

There is **no background timer and no sweep**. Verify-on-call is lazy: between calls nothing runs, and
an upstream nobody calls is never fetched. The bound is a max-staleness ceiling, not a schedule.

The config keys:

| Plane | Key | Default |
| --- | --- | --- |
| MCP (`tools:`) | `verify_ttl` | `5s` |
| A2A (`agents:`) | `reverify_ttl` | `5s` |

(The two keys keep their plane-native spellings; the admin API projects both under one view field, so
the concept is one across the planes.)

### Single-flight coalescing

On the A2A plane, when many delegations hit a stale card at the same instant, exactly **one** look
runs per agent and every other caller waits for its verdict rather than fetching again; a look
abandoned before it lands releases its waiters to look again (`busbar-plane-a2a`: `agent_door.rs`,
`verify_agent_on_call`). Upstream load is then held to about one card fetch per `reverify_ttl` per
agent regardless of caller count.

The MCP plane also shares an in-flight `tools/list` fetch among concurrent calls to the same server and catalogue generation. The fetch lease is bounded by the server's `timeout:`; callers join the result instead of issuing a fetch each. `verify_ttl: 0s` still shares concurrent in-flight work. This is process-local coordination, not one fetch across the fleet. A failed verification does not authorize dispatch.

A clock that moved backwards, or a clock read that fails, is treated as stale, never as fresh, so a
corrected or tampered clock cannot make an observation permanently fresh
(`crates/busbar-kernel/src/trust/reverify.rs`, `Due::ClockWentBackwards`).

### `list_changed` may only mark stale, never adopt

An upstream's own `notifications/tools/list_changed` is attacker-controlled in both timing and
content. Busbar reads its *timing* only: an accepted, rate-limited notification marks the server's
snapshot stale so the **next** call re-verifies against the authoritative `tools/list`. The
notification's body is never read, and the notification can never itself install, approve or
promote anything (`busbar-plane-mcp`: `client/peer.rs`, `NotificationEffect`).

---

## Fail-closed

If the re-verification fetch fails — the upstream is unreachable or unverifiable — the call is
**refused**, not served against a snapshot older than `verify_ttl`. An unreachable upstream at verify
derives the trust state `Error`, which serves nothing. A fingerprint that
moved derives a quarantine, and the call is refused before dispatch. In
both cases the refusal is the signal, and the upstream's tool call never reaches the wire.

This is the same fail-closed floor a first-ever call takes: a server nobody has verified is verified
before it can serve, not served on trust.

---

## The one honest limit

Verify-on-call checks the **advertised surface** — the name, arguments and description you approved,
all in the fingerprint. It cannot check what a server *does* when invoked. A server that keeps an
identical surface and changes its behaviour on the backend is invisible to any proxy that sits in
front of it, Busbar included.

That residual risk is bounded by per-backend credential scoping, egress/SSRF policy (where a call
may go), and the audit chain (what happened). The credential choices differ by plane:

- **MCP:** `token_exchange:` obtains a target-scoped token narrowed to the caller's tool grants;
  `upstream_credentials: connection` uses that caller's separately consented upstream OAuth
  connection. With neither configured, no upstream credential is sent. Connection mode requires
  HTTPS and host connection services, excludes stdio, and cannot be combined with token exchange.
- **A2A:** `upstream_credentials: own` uses the operator-configured `upstream_credential:` for the
  target agent, leased for the hop. Without that configuration, the hop carries no credential.

Both planes refuse caller-credential passthrough: the caller's Busbar credential stays at Busbar.
The maximally true claim is
**"verified against the surface you approved, before every call"** — not a guarantee about the
upstream's runtime behaviour.

---

## The knob

`verify_ttl` (MCP) / `reverify_ttl` (A2A) is the only knob over **detection**, deliberately. There
is no key that slows detection below what it bounds, none that delays a quarantine, and no per-server
"skip if it failed last time" — every one of those would be a window an upstream could open for
itself by misbehaving.

A2A has one more key, `recovery_backoff:`, which works in the other direction: after drift is
observed, a clean answer is disbelieved for that long before the agent is trusted again. It can only
keep an agent refused longer, never serve one sooner.

- **`0`** is strict-live: re-verify on every call (bursts still coalesce into one fetch).
- **The `5s` default** bounds drift-serving to a few seconds while single-flight keeps upstream load
  flat.
- **A larger value is an explicit security downgrade.** It widens the window in which a rug-pulled
  tool can be dispatched before the next call re-verifies. the first-boot migration carries an old
  MCP `refresh_ttl:` value over to `verify_ttl:` unchanged and warns loudly that its meaning changed
  from a background cadence (old default `6h`) to a request-path staleness bound — a `6h` value that
  was a fine sweep cadence is a six-hour drift-serving window as a `verify_ttl`.

---

## In one sentence

> Every tool call and agent delegation is verified against the definition you approved — live, within
> seconds — before it runs. A tool or agent that changed is refused, not called. Your model only ever
> sees the definitions you approved.
