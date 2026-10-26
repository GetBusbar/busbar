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

### Single-flight coalescing (A2A)

On the A2A plane, when many delegations hit a stale card at the same instant, exactly **one** look
runs per agent and every other caller waits for its verdict rather than fetching again; a look
abandoned before it lands releases its waiters to look again (`busbar-plane-a2a`: `agent_door.rs`,
`verify_agent_on_call`). Upstream load is then held to about one card fetch per `reverify_ttl` per
agent regardless of caller count.

The MCP plane does **not** coalesce in this release: each `tools/call` that finds its server's last
fetch older than `verify_ttl` fetches `tools/list` itself, so a burst of calls against a stale server
can produce one fetch per call. Each fetch is bounded by the server's `timeout:`. Size `verify_ttl`
with that in mind for high-fan-in tools.

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

That residual risk is bounded by the other controls, not by the fingerprint: per-backend credential
scoping (Busbar spends a credential minted for *this* tool under *this* caller's grant), egress/SSRF
policy (where a call may go), and the audit chain (what happened). The maximally true claim is
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
  tool can be dispatched before the next call re-verifies. `busbar --migrate-config` carries an old
  MCP `refresh_ttl:` value over to `verify_ttl:` unchanged and warns loudly that its meaning changed
  from a background cadence (old default `6h`) to a request-path staleness bound — a `6h` value that
  was a fine sweep cadence is a six-hour drift-serving window as a `verify_ttl`.

---

## In one sentence

> Every tool call and agent delegation is verified against the definition you approved — live, within
> seconds — before it runs. A tool or agent that changed is refused, not called. Your model only ever
> sees the definitions you approved.
