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
[Configuration](/docs/configuration/) (field reference) · [Diagnostics](/docs/diagnostics/)
(BUSBAR-7097 / BUSBAR-7098).

---

## The fingerprint: name + args + description

A remote tool is a function the model calls, and an agent is a card that advertises skills. What the
model reads to decide *how* to call — the tool's **name**, its **argument schema**, and its
**description** — is exactly what an attacker would change to redirect it. So Busbar pins all three
in one fingerprint:

- **MCP** hashes name + description + input schema into one per-tool digest over a canonical
  rendering, so re-ordering a schema's keys is not drift but changing one character of a description
  is (`crates/busbar-core/src/mcp/client/catalogue.rs`, `tool_digest`).
- **A2A** pins the signed card: the operator's out-of-band issuer key (or transport-layer SPKI) plus
  a fingerprint of the card document (`crates/busbar-core/src/a2a/verify.rs`).

You approve that fingerprint once. Verify-on-call re-compares it on every call.

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

When many calls hit a stale snapshot at the same instant, exactly **one** re-fetch runs and every
caller uses its result. That is the primary load lever: upstream load is held to at most one fetch per
`verify_ttl` per server regardless of caller count. Bursts coalesce even at `verify_ttl: 0`.

The coalescing is clock-independent — it keys on a per-subject monotonic epoch bumped once per
completed fetch, not on a timestamp — so a caller that started waiting before the fetch completed is
answered by it, and does not fetch again
(`crates/busbar-core/src/trust/verify.rs`, `VerifyGate::ensure_fresh`).

### `list_changed` may only mark stale, never adopt

An upstream's own `notifications/tools/list_changed` is attacker-controlled in both timing and
content. Busbar reads its *timing* only: an accepted, rate-limited notification marks the server's
snapshot stale so the **next** call re-verifies against the authoritative `tools/list`. The
notification's body is never read.

---

## Fail-closed

If the re-verification fetch fails — the upstream is unreachable or unverifiable — the call is
**refused**, not served against a snapshot older than `verify_ttl`. An unreachable upstream at verify
derives the trust state `Error`, which serves nothing (`BUSBAR-7098`, latched). A fingerprint that
moved derives a quarantine, and the call is refused before dispatch (`BUSBAR-7097`, warn-once). In
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

`verify_ttl` (MCP) / `reverify_ttl` (A2A) is the only verification knob, deliberately. There is no
key that slows detection below what it bounds, none that delays a quarantine, and no per-server "skip
if it failed last time" — every one of those would be a window an upstream could open for itself by
misbehaving.

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
