# Plane 4 — The Duplex / Session Plane: busbar 1.6.0 EXECUTION PLAN (full scope)

Status: **AUTHORITATIVE EXECUTION PLAN.** This is the plan 1.6.0 is built from.
Owner: Matthew. This companion **supersedes the scope call** in
`docs/design/plane4-duplex-session.md` §8 and Part II §II.5 of
`docs/design/1.6.0-duplex-plane-and-realtime.md`: the owner has decided to pull Plane 4 **into
1.6.0 at FULL scope**. That design doc remains the authoritative *design* (the IR, the pump, the
gauntlet contract, the topologies); this doc is the *build program* that realizes it. It
**cross-references, does not duplicate** — every "why" lives in the design doc and is cited by
section; every "how / in what order / done-when / at what cost" lives here.

**The framing that governs this whole plan (owner, exact).** *The three axes are NOT the plugin —
they are a **substrate / core capability every plane uses**, exactly like the gauntlet and the hot
ABI. `busbar-voice` is just the first **plugin** that consumes all three.* So:

> **1.6.0 makes the substrate duplex/session/stateful-capable — a general capability every plane
> uses — and `busbar-voice` is the plugin that proves it, the same way `busbar-llm` proved the
> request/response substrate.**

This is why the tracks split the way they do: **T1 is the substrate CAPABILITY** (duplex transport,
per-frame governance lease, the neutral session/handle engine — all lifted into
`busbar-substrate`/`busbar-plugin`, consumed by MCP, A2A, the LLM plane, and voice alike); **T2 is
the first consuming PLUGIN** (`busbar-voice`) that exercises every one of those capabilities and
thereby proves them. A capability that only one plugin could use would be a plane in disguise; the
plan proves generality by making MCP and A2A consume the same seams (§T1.7, §T1.8) *before* voice
does.

**Citation base.** Every `crates/…:NNN` citation is against `integration/plane-extraction` (the
branch where the extracted plane crates live; the 1.6.0 `HEAD` monolith is the same code
pre-extraction). Cite-verify a seam with `git show integration/plane-extraction:<path>`. All
citations below were re-verified this pass; where a line drifted from the design doc's number I use
the verified one.

**The three binding owner decisions this plan executes (do not re-litigate — plan HOW):**
1. **FULL scope in 1.6.0** — the complete `busbar-voice` plane: BOTH topologies (server-to-server
   OpenAI Realtime GA WS bridge AND browser WebRTC: ephemeral `client_secret` mint + SDP broker +
   sideband control WSS) + an **adopted** media pump.
2. **GENERAL substrate WS transport** — `Transport::WebSocket` is a neutral axis ANY plane binds;
   the plan gives **MCP and A2A a WebSocket binding too** (proving generality, not voice-only wiring).
3. **BOTH axes first-class** — the substrate primitives serve bidirectional-streaming (axis A) AND
   stateful-async handles (axis C) equally; Track-3 **ships at least one axis-C capability** on the
   A2A `taskstore` engine + the inbound webhook **receiver**.

---

## 0. TL;DR — the program in one screen

| Track | Deliverable | Ships | One-way door |
|---|---|---|---|
| **T0** | Finish LLM-plane ABI purity → **0** and **arm** the plane-agnostic wall (`--check` blocking); add `voice` to the neutrality ban list; register `busbar-voice` in the delete test | prereq — a 4th plane must not land before the boundary is mechanically enforced | — |
| **T1 — substrate CAPABILITY** | The general duplex/session/stateful capability every plane uses: properly-dispatched `Transport` axis (**every variant → acceptor+driver**) incl. `WebSocket`; WS-upgrade **arrival kind**; substrate-owned bidirectional **pump** (MCP adopts it, deletes its bespoke loop); **the neutral session/handle engine LIFTED out of `busbar-a2a` into `busbar-substrate`**; `SessionScope` wire-out; the **D2 metering-lease slots**; `run_gauntlet_session` sibling; **MCP + A2A consume the lifted seams** | the neutral engine, proven by an echo plane, MCP/A2A-over-WS, AND A2A re-homed onto the substrate handle engine | **D2 vtable slots** (airlock minor-19), the `Transport` dispatch contract, WS Arrival kind, `SessionScope` shape, the substrate handle-engine API |
| **T2 — first consuming PLUGIN** | `busbar-voice` FULL, the plugin that proves the capability: four-layer IR; both topologies; adopted media pump; **Gemini Live** as 2nd dialect (earns the superset IR → backend-swap moat) | the product | media-pump adapter boundary; browser trust boundary |
| **T3** | Prove **one axis-C capability** (OpenAI Responses-stateful **or** Batch/Files) on the **substrate** handle engine (T1.8, never `busbar_a2a`) + the inbound **webhook receiver** | the stateful half, demonstrated | inbound-webhook security surface (net-new attack surface) |
| **T4** | Header-fidelity (design doc §1.5 / Phase 0) — fully orthogonal | any time | — |

Dependency order: **T0 → T1 → {T2, T3} (parallel) ; T4 anytime.** T2 and T3 both depend only on
T1's session/lease seams and are independent of each other. T4 depends on nothing.

Honest sizing (§D): **~38–51 PRs, ~6–9 focused weeks.** Big-risk items: the media pump adapter,
browser WebRTC/SDP, the `ArrivalPayload` `Any`-boundary for the WS arrival, the session/handle
engine lift out of `busbar-a2a`, and the inbound webhook receiver's security surface.

---

## 0.5 1.6.0 as an ENTERPRISE platform release

The substrate capabilities T1 lands are not voice plumbing — **they are enterprise controls, and
they apply to EVERY governed action, not just voice.** That is the whole force of the capability
framing: once the substrate is duplex/session/stateful-capable, the *same* controls that make a live
voice call safe make a runaway stream, a 20-minute batch job, and a long-running async handle safe
too. The enterprise headline to state, plainly:

> **Every governed action — one-shot, streaming, live-duplex, or long-running async — passes the
> same authenticate → verify → approve → budget → route → audit gauntlet, with mid-stream budget
> hard-stop and a durable, replayable audit chain, on a core that is provably plane-agnostic.**

The specific enterprise controls this release ships, each a *substrate* capability applied
universally:

- **Budget lease with mid-stream hard-stop (T1.5 / D2).** A reserve-then-settle lease
  (`CostHold::reserve`/`settle_partial`, `cost.rs:312/327`) that can **stop a live stream when its
  budget is exhausted** — the thing post-hoc `meter_charge` structurally cannot do (you cannot refund
  bytes already streamed). A runaway streaming/voice/long-task **cannot blow the budget**; the alert
  does not fire *after* the money is gone. Applies to any high-rate carrier, not just audio.
- **Durable, hash-chained, replayable per-turn audit under one session scope (T1.4 / T1.8 /
  `journal_append_scoped`, `host.rs:491`).** Every turn — audio, tool call, barge-in, batch
  transition, webhook delivery — is a hash-chained record under **one** session/handle scope that
  **verifies through the one digest and survives a restart** (rehydrated by the lifted engine's
  `restore_from_store`). "What did this live/long session do, and what did it cost, turn by turn" is
  answerable after the fact, cryptographically — for voice, batch, and stateful Responses alike.
- **Keys-never-leave-server, extended to live / duplex / WebRTC (T2.2–T2.3).** The server-side-key
  posture busbar already holds for one-shot calls now covers the persistent upstream WS bridge AND the
  browser WebRTC path (ephemeral `client_secret` mint + sideband control WSS). The browser gets a
  short-lived secret and peer-to-peer media; it never holds the real key and cannot author tools or
  override instructions.
- **Inbound webhook receiver INTO the governed boundary (T3).** Completion pushes (stateful Responses
  / batch / background) enter through an authenticated, replay-rejecting, anti-enumeration-correlated
  receiver — not a side door. The one net-new-vs-LiteLLM piece, and it lands *inside* the gauntlet.
- **Uniform, hardened WS transport across planes (T1.1 / T1.7).** One properly-dispatched
  `Transport` axis with a WebSocket binding that MCP, A2A, and voice all ride — one transport to
  harden, audit, and operate, not three bespoke sockets.
- **The plane-agnostic wall ARMED at purity 0 (T0).** The mechanical proof that "one operation, one
  path, same steps every time" is **literally true**: `plane-purity-lint --check` blocking at 0
  BACKWARDS means no plane can smuggle a private path around the gauntlet — the uniformity claim is
  enforced by CI, not asserted in a doc.

**Why these belong in one release.** They are the same substrate capability viewed from the
enterprise buyer's seat: continuous governance (budget + audit) over long-lived work, key custody
over new transports, and a provably uniform path. Shipping them together — and proving them with one
consuming plugin (voice) plus two existing planes (MCP/A2A) re-homed onto the same seams — is what
makes 1.6.0 a *platform* release rather than a voice feature.

---

## A. The phased build program (supersedes design §8 / Part II §II.5)

Every phase is green-per-commit; the composition gates + plane-purity + neutrality + no-plugins +
plane-delete gates hold at **every** commit. Dev-only branch (`integration/plane-extraction` →
`dev`); promote when green (§D).

**BUILD PRINCIPLE — audit-and-improve every reserved seam as it is wired out ("fix if needed, don't
just tack on").** Each seam below (`Transport` dispatch, the pump, `SessionScope`, the metering
lease, the handle engine, the WS arrival) was *reserved* under design pressure, not built under load.
Wiring it out is the first time real traffic proves its shape. The rule: when a phase touches a
reserved seam, it **audits that seam's current shape against the load it must now carry and fixes it
before extending it** — a half-wired enum gets properly dispatched, a documented limitation gets
resolved, a bespoke copy gets consolidated, a not-yet-frozen signature gets corrected *before* it
freezes. This is a **DoD clause on every seam phase** (each phase's DoD names its audit-and-improve
outcome explicitly). It is the opposite of accreting a new slot beside a seam that was never right.

### T0 — Finish the wall, then arm it (PREREQUISITE — nothing else starts until this is 0-and-armed)

**Why it gates everything.** A fourth plane must not land before the plane-agnostic boundary is
*mechanically enforced*, or the new plane's nouns leak into core during the build and the
neutrality story is decided by vigilance instead of by CI. The wall is the ABI-purity gate
(`scripts/plane-purity-lint.sh` reverse mode, emits `BACKWARDS` for a plane crate naming
`busbar_core::` implementation, :196-197) plus the neutrality gate
(`scripts/plane-abi-neutrality.sh`), the delete test (`scripts/plane-delete-test.sh`), and
no-plugins (`scripts/no-plugins-gate.sh`).

**Current state (owner-provided, consistent with `docs/design/1.6.0-llm-plane-abi-purity.md`):**
plane-purity `BACKWARDS` = **169**; the gate is `status = "active"` in `qa/segments.toml` but is
driven by `--baseline` (monotone-decreasing) not `--check` because the count is not yet 0.

**Deliverable.**
1. Execute `docs/design/1.6.0-llm-plane-abi-purity.md` P0–P7 to drive `BACKWARDS` **169 → 0**
   (repoint Bucket A/A′/B imports onto `busbar_substrate::`/`busbar_api::`; re-type the engine off
   `&App` onto `&dyn EngineHost` — Bucket C, the riskiest, one file per commit).
2. Flip the purity gate from `--baseline` to `--check` **blocking**; update the `qa/segments.toml`
   prose that still says "drained to 0" (the ABI-purity doc §5 caveat).
3. **Extend the neutrality ban list for the incoming plane, ahead of it.**
   `scripts/plane-abi-neutrality.sh` bans `(llm mcp a2a tool agent sampling task server card round
   prompt)` (:30). Add the Plane-4 nouns — **`voice audio realtime rtc sdp webrtc barge`** — to
   both `banned=` and the `mandated=` self-check (:30,:32) so the witness can catch a leak of a
   token it must forbid *before* `busbar-voice` exists. (Not `websocket`: WS is a **neutral
   transport** noun that legitimately lands in substrate — see §B.2 and §C.)
4. **Register `busbar-voice` in the delete test.** `scripts/plane-delete-test.sh` iterates
   `PLANES="llm mcp a2a"` (:76); add `voice`, and add its bin feature mapping (the `dep:busbar-voice`
   token, :82-94) so the strong-form deletion test covers the new plane from its first commit.

**Files/crates touched.** `crates/busbar-llm/src/**` (import repointing + engine re-type, per the
ABI-purity doc buckets); `scripts/plane-abi-neutrality.sh`; `scripts/plane-delete-test.sh`;
`qa/segments.toml`; `qa/method-coverage.status` (prose).

**Dependencies.** None. This is the prereq.

**Definition of Done.** `plane-purity-lint --check` GREEN at **0** BACKWARDS on `busbar-llm`;
`--selftest` GREEN; the neutrality ban list contains the seven voice nouns and its self-check
passes; the delete test iterates four planes (`git rm -r crates/busbar-voice` still compiles
core/substrate/api — vacuously true until T2 creates the crate, then a real assertion); the five
byte-identity oracles (`egress_differential_tests`, `crossproto_delivery_billing_tests`,
`on_exhausted_tests`, `pool_upstream_creds_tests`, health suite) unchanged.

**CI gates that must stay green.** All of the above + the existing composition gates. This is the
one track where the *purity* gate itself changes state (baseline→check); after T0 it is blocking
for every subsequent commit.

---

### T1 — The substrate CAPABILITY (general duplex / session / stateful, both axes)

This track makes the **substrate itself** duplex/session/stateful-capable — a general capability
that sits beside the gauntlet and the hot ABI and is consumed by **every** plane, not a voice
feature. **No voice noun appears in this entire track.** Generality is proven by three witnesses,
all landing before `busbar-voice` exists: an echo duplex test plane (axis A), a WebSocket binding
for MCP **and** A2A (decision #2), and **A2A re-homed onto the lifted substrate handle engine**
(§T1.8) — the same engine T3 and voice then consume. The D2 lease slots and the
`run_gauntlet_session` sibling (axis B/C seams) land here too.

**T1.1 — make `Transport` a properly-dispatched axis (audit-and-improve), then add `WebSocket`.**
`Transport` is the closed enum `{ Http, JsonRpc, HttpJson, Grpc, Stdio }`
(`crates/busbar-substrate/src/transport.rs:97-140`; no WebSocket — verified). Its module doctrine
is binding: variants are *"bought when a request drives them, not guessed"* (:35-49) and each
*"arrived on the commit that armed it."* **Audit-and-improve (the fix, not a tack-on):** the axis is
**half-wired today** — its only dispatch consumer is `upstream_wire()` (:143, on the MCP client
egress leg); the A2A variants are consumed *only as telemetry labels* (`name()`, :187 — verified).
Special-casing `WebSocket` onto that half-wired enum would deepen the debt. Instead, **complete the
axis**: give it a proper generic `Transport → { ingress acceptor, egress driver }` dispatch so
**every** variant maps to a real acceptor+driver (the existing five keep today's behavior, now
routed through the completed dispatch rather than an ad-hoc `upstream_wire` special-case), and *then*
add `WebSocket` (dials a persistent framed socket, accepts a WS upgrade) as one properly-dispatched
variant among equals. `Transport::WebSocket` lands on this commit, driven by the first WS session,
per the "armed when it arrives" doctrine.

**DoD (audit-and-improve):** `Transport` is a fully-dispatched axis — no variant is a mere telemetry
label; A2A's variants now resolve to real acceptors, not just `name()` strings; `WebSocket` is not a
special case.

**T1.2 — the WS-upgrade ARRIVAL KIND (not an axum route upgrade).**
The anti-pattern is loud and must not be taken: a `PlaneRouteFn` *can* return a
`WebSocketUpgrade::on_upgrade(...)`, handing a raw socket to a closure that **bypasses
`SessionScope`, the lease, and the audit chain** — i.e. bypasses the gauntlet (design §4.2; verified
zero `WebSocketUpgrade`/`on_upgrade`/`tungstenite` in the tree — greenfield). The right shape is a
new **substrate arrival kind** on the neutral `Arrival` seam
(`crates/busbar-substrate/src/ingress/arrival.rs:139` — `Arrival { host, ctx, path, headers, body }`
carrying an `Arc<dyn ArrivalHost>` the dialect calls back through, :141-149). The WS arrival runs
`run_gauntlet` (open), then hands the accepted socket to the pump under a populated `SessionScope`.
**Risk flag (see §D):** the arrival carries its per-kind payload through `ArrivalCtx(Box<dyn Any +
Send + Sync>)` (:36) — the WS arrival's payload (the upgraded socket handle) rides this `Any`
boundary and is downcast inside the `ArrivalHost` impl; the downcast must be single-core-instance
safe (the dual-compile constraint of the ABI-purity doc §2).

**T1.3 — the substrate-owned bidirectional pump (port MCP `Session<W>`, and FIX its known limitation;
MCP then ADOPTS it).**
MCP's duplex loop is the proven pattern (`crates/busbar-mcp/src/mcp/stdio_serve.rs`): `Session<W>`
(:383) with `factory: LiveHostFactory` (:388, per-frame re-mint), the single write lock `out:
tokio::sync::Mutex<W>` (:393), the inflight cancellation table (:399) and the pending correlation
table (:401); `run_session` (:280) with reply-correlation-first (`route_reply`, :310/:424) → spawn
per non-reply frame (:317) → all writes funnel through `emit` under the one lock (:415). Port this to
a substrate-owned pump over any byte-duplex `PipeId`: the reader is the plane's `DuplexReader` over
`pipe_read` (`crates/busbar-plugin/src/hot/host.rs:155-171` — *"host moves RAW BYTES only … framing
stays PLANE-side"*) instead of `read_until(b'\n')`; the writer is `pipe_write` under the same
single-lock discipline.

**Audit-and-improve (the fix, not a tack-on):** the port must **resolve MCP's documented limitation,
not preserve it.** MCP's *client* leg deliberately has **no reader task and no correlation table** —
it serializes whole exchanges behind a per-slot `tokio::sync::Mutex<ChildSlot>`
(`mcp/client/stdio.rs:829-831`) and documents *why*: demultiplexing on the JSON-RPC id would be *"a
second correlation table … Serialising is the honest shape until there is a reader task to own that
table"* (`:820-827`). The substrate pump **is** that reader task + that owned correlation table (a WS
upstream cannot serialize — audio flows continuously both ways), so the pump ships the exact thing
that limitation was waiting on, and it wires `SessionScope` / `pipe_read` / `pipe_write` / `WorkItem`
— which MCP stdio does not.

**Then MCP adopts the substrate pump and DELETES its bespoke stdio loop.** Once the pump exists and
MCP's WS binding (§T1.7) rides it, MCP's hand-rolled `Session<W>`/`run_session` in `stdio_serve.rs`
becomes a parallel copy of a now-general capability. Re-home MCP stdio onto the substrate pump and
remove the bespoke loop — a **net simplification** (one pump, not two), and the strongest possible
proof the capability is general (its own blueprint now consumes it).

**DoD (audit-and-improve):** the substrate pump owns a real reader task + correlation table (MCP's
documented `Mutex`-serialization limitation is *resolved*, not carried forward); `busbar-mcp` no
longer contains a bespoke duplex loop — it consumes the substrate pump, and total duplex-loop code in
the tree goes **down**, not up.

**T1.4 — wire out `SessionScope`.**
`SessionScope {}` is the empty `#[non_exhaustive]` stub whose own doc says *"the riders that add a
duplex/session plane wire this out"* (`crates/busbar-substrate/src/plane_host/scope.rs:361-366`).
Wire it (append-only — D3): the two `PipeId`s (client + pooled upstream), the `CostHold` lease, the
journal scope string `"session-<id>"`, and (plane-side) the correlation table. The pooled upstream
socket registers via `DispatchScope::register_pipe` (:302) for RAII reclaim on close.
**Audit-and-improve DoD:** the first field set is chosen deliberately (it defines the session model
every future duplex plane inherits, §D one-way door), the `Drop` reclaim is proven leak-free under
disconnect/cancel/panic, and no plane-shaped field (e.g. `CallRef`) leaks into the neutral struct.

**T1.5 — the D2 metering-lease slots (the ABI one-way door — audit CostHold BEFORE the slot freezes;
signatures in §B.1).**
Append `cost_reserve`/`cost_settle` as trailing `Option` slots at the reserved extension point
(`crates/busbar-plugin/src/hot/host.rs:533-536` — *"add `cost_reserve`/`cost_settle` as trailing
`Option` slots below this line and bump the airlock MINOR — an append-only add, never a reshape"*;
echoed on the POD, `hot/pod.rs:636-638`). Airlock **minor 18 → 19** (the last cluster, `gate_decide`,
was minor-18, `host.rs:526-532`). They drive the shipped `CostHold` (`cost.rs:304-341`).

**Audit-and-improve (the fix, not a tack-on) — this seam freezes on ship, so audit its shape NOW.**
The `MagnitudePod` correction in §B.1 (the design doc's `*const Magnitude` is not FFI-POD because
`Magnitude.unit: &'static str`, `cost.rs:271`) is exactly this instinct: fix the shape *before* the
signature becomes immovable, not after a plugin has compiled against a wrong one. The audit is
broader than that one fix — it asks whether `CostHold`'s shape (`cost.rs:304-341`, whose
`settle_partial` accrues one `CostBreakdown.total` per call) is right for a **high-rate per-frame
settle**: a 24 kHz voice session settles per `response.done.usage`, but a future carrier might settle
per-frame at kHz rates, and the slot's cost (a Mutex-guarded accrue + an exhaustion readback per
call) must be cheap enough for that. **DoD:** the `cost_reserve`/`cost_settle` signatures and the
`CostHold` accrue path are reviewed for high-rate per-frame settle and corrected (POD projection,
readback shape, lock granularity) *before* airlock minor-19 ships — because once shipped, a reshape
is a breaking MAJOR (§D one-way door).

**T1.6 — the `run_gauntlet_session` sibling.**
`run_gauntlet` is a *free fn* returning `axum::response::Response` (`plane_host/mod.rs:177,167`);
`GauntletPlane` is a *trait* (:158). A 20-minute metered session is not one `Response`. Add an
**append-only sibling** `run_gauntlet_session` that runs the same `verify_destination`-before-charge
sequence (:181) but returns a `SessionScope` handle instead of a `Response`. Session-*open* is still
exactly today's one pass; nothing existing reshapes (D3).

**T1.7 — MCP + A2A WebSocket bindings (decision #2 — the generality proof).**
Give MCP and A2A a `Transport::WebSocket` binding through the same neutral seam. A2A today publishes
only `jsonrpc/http+json/grpc` (`crates/busbar-a2a/src/a2a/serve.rs servable_bindings`) and WS is
*"not refused, just unimplemented"* (design §1.7); MCP is duplex-over-stdio only. Binding both over
the general WS transport proves the axis is neutral, not voice-shaped, and hardens the pump against a
second protocol before voice rides it.

**T1.8 — LIFT the neutral session/handle engine out of `busbar-a2a` into `busbar-substrate` (CRITICAL
— the axis-C capability must be a substrate capability, not another plane's crate).**
The stateful-handle engine that axis C rides — the process-wide registry, the lifecycle state machine
(`submit`/`transition`), retention/GC (`sweep`, `MAX_RETAINED_TASKS`), durable rehydration
(`restore_from_store`), the anti-enumeration scoped lookup (`get_scoped`), and the inbound-push cursor
(`set_push_callback`/`record_push_delivery`/`advance_cursor`) — **is A2A-owned today**: it lives as
`TaskRegistry` in `crates/busbar-a2a/src/taskstore.rs:385-386`, riding the neutral
`busbar_substrate::plane::store::PlaneStore` seam (`taskstore.rs:45`) and the `DurableScope` taxonomy
(`crates/busbar-substrate/src/plane_host/scope.rs:376`).

**Why this is a hard blocker, not a nicety.** If T3 (and later voice) reached into
`busbar_a2a::taskstore`, an LLM/voice plane would name **another plane's crate** — which **breaks the
plane-agnostic rule and fails plane-purity + grep-neutrality on the spot** (the purity gate flags a
plane crate naming anything but `busbar_substrate::`/`busbar_api::`; `busbar_a2a::` is neither). The
capability framing (top of doc) demands the opposite: a *substrate* capability every plane consumes.

**The fix (audit-and-improve — genuinely lift, don't copy).** Raise the neutral engine — the
registry/lifecycle/GC/rehydration/scoped-lookup/push-cursor machinery — **up into
`busbar-substrate`** as a first-class session/handle-store capability keyed by `DurableScope` +
`PlaneStore` (both already substrate). Then:
- **A2A CONSUMES it** — `busbar-a2a` keeps only its A2A-shaped task *semantics* (state names, the
  `tasks/*` verbs) and drives the substrate engine; its bespoke registry is deleted (net
  simplification, the same discipline as the MCP-pump adoption in §T1.3).
- **T3's axis-C capability and `busbar-voice`'s session record consume the SAME substrate engine**,
  never `busbar_a2a`. The voice `SessionScope` durable record (§B.4/§B.5) parks on it; the
  Responses-stateful handle (§T3) parks on it.
This is the axis-C half of "make the substrate stateful-capable" — the exact mirror of making it
duplex-capable (T1.1–T1.3). It stays plane-agnostic: the engine names no plane noun (its terminal set
is *string tokens*, `taskstore.rs:317` — *"names no `TaskState`"*), so the lift carries no A2A
vocabulary up with it.

**DoD (audit-and-improve):** the neutral engine lives in `busbar-substrate`; `busbar-a2a` consumes it
and no longer owns a private registry; a `git grep busbar_a2a:: crates/busbar-llm crates/busbar-voice`
is **zero**; plane-purity + neutrality stay green with the LLM/voice planes reaching only the
substrate engine.

**Files/crates touched.** `crates/busbar-substrate/src/{transport.rs, ingress/arrival.rs,
plane_host/mod.rs, plane_host/scope.rs}` + a new substrate session/handle-store module (the T1.8
lift); `crates/busbar-plugin/src/hot/{host.rs, pod.rs}` (D2 slots + airlock bump + the live-host
wiring of the two slots); the new substrate pump module; `crates/busbar-mcp/**` (WS binding **and**
deletion of the bespoke stdio loop, §T1.3); `crates/busbar-a2a/**` (WS binding **and** re-home onto
the lifted engine, §T1.8); a throwaway `echo` test plane.

**Dependencies.** T0 (the wall armed).

**Definition of Done.** (a) An echo duplex test plane accepts a WS client, holds a WS upstream, pumps
both ways, and reclaims `SessionScope` on close — **no voice noun**. (b) MCP **and** A2A each serve
at least one method over `Transport::WebSocket` through the substrate pump, and **MCP's bespoke stdio
duplex loop is deleted** (it consumes the substrate pump; tree-wide duplex-loop code goes down). (c)
The D2 slots compile on the live host and the STUB fixture (`host.rs:606`), airlock minor is 19, and
a POD-shape unit test round-trips a `cost_reserve`→`cost_settle`→exhaustion readback — the CostHold
shape audited for high-rate settle *before* the slot froze. (d) `run_gauntlet_session` opens a
session through one gauntlet pass and returns a `SessionScope`. (e) **The session/handle engine lives
in `busbar-substrate`; A2A consumes it (its private registry deleted); `git grep busbar_a2a::
crates/busbar-llm crates/busbar-voice` is zero.** (f) `Transport` is a fully-dispatched axis (no
variant is a telemetry-only label). All neutrality/purity/delete/no-plugins/composition gates GREEN.

**CI gates.** plane-purity `--check` = 0; neutrality (voice nouns still absent from core — vacuously,
since T1 introduces none); no-plugins; plane-delete (four planes; `busbar-voice` still absent →
vacuous); the ABI airlock version gate (minor bump is monotone + append-only); the D1 `WorkItem`
witness test (`hot/workitem.rs` — `InboundKind::Stream` :31 + `EmitKind::Unsolicited` :47 must not be
collapsed to `(ptr,len)+sink`, :17); byte oracles unchanged.

---

### T2 — the first consuming PLUGIN: `busbar-voice` FULL (both topologies + adopted media pump + 2nd dialect)

**The plugin that proves the T1 capability** — the same way `busbar-llm` proved the request/response
substrate. It is the first (and, in 1.6.0, only) plugin that consumes **all three** substrate
capabilities at once: the duplex transport/pump (axis A), the per-frame governance lease (axis B), and
the lifted session/handle engine (axis C). Everything protocol-shaped lives here; core/substrate/api
learn **no** voice noun (design §7), and voice reaches only substrate/api seams — never `busbar_a2a`
(the engine it uses for its durable session record is the T1.8 substrate engine). Named `busbar-voice`
for the capability class (design §7.1), not `busbar-realtime` (one-vendor noun) — mirroring
`busbar-llm` (6 dialects, not `busbar-openai`).

**T2.1 — the four-layer IR + `DuplexReader`/`DuplexWriter`** (design §2, §2.6). Its own busbar-owned
canonical mirror, `codec: None` while OpenAI Realtime is the only dialect
(`crates/busbar-substrate/src/proto.rs` `ProtocolDecl`, the MCP pattern). The genuine net-new IR
work is `IrClientEvent` — the **client→server event vocabulary** that has no analog in the tree
(`IrStreamEvent` is response-shaped only, `crates/busbar-llm/src/ir/types.rs:200-250`). Layers:
tool-call (full normalization; the `CallRef` correlation table in `SessionScope`), control/config
(translatable cross-dialect only; barge-in `audio_played_ms` is plane-computed decode state),
media/audio (verbatim identity relay — the meter/audit tap), usage/rate-limit (extraction → folds
into `CostBreakdown`, `cost.rs:178`, whose parts sum to `total`, :249/:156).

**T2.2 — Topology A: server-to-server WS bridge.** busbar terminates the client WS and holds a
persistent upstream WS with the real key (design §5.2). Session-open through `run_gauntlet_session`
(T1.6); per-frame govern via `govern_admit_reason` (`plane_host/mod.rs:264`) against the open lease;
per-`response.done.usage` `cost_settle` (T1.5, the shipped `CostHold::settle_partial`, `cost.rs:327`)
with exhaustion readback → hard-close (the one thing post-hoc `meter_charge` cannot do, design §3.3);
per-frame audit via `journal_append_scoped("session-<id>", …)` (`hot/host.rs:491`); the mid-call tool
loop (server-side execution under `gate_decide`, `plane_host/mod.rs:250`); barge-in bookkeeping. Full
gauntlet, no media pump, no browser.

**T2.3 — Topology B: browser WebRTC.** Both halves keys-server-side (design §5.2): mint the ephemeral
`client_secret` (`POST /v1/realtime/client_secrets` — a normal `Invoke`-shaped gauntlet pass, no
duplex transport); broker the SDP (`POST /v1/realtime/calls`, `Content-Type: application/sdp`, preserve
`Location: /v1/realtime/calls/rtc_<call_id>`); the **sideband control WSS** keyed by `rtc_<call_id>`
holding the real key — tools + instruction-locking run server-side, the browser is never trusted.

**T2.4 — the adopted media pump: LiveKit Agents (chosen; justified).**
Own the gauntlet, **adopt** the media leg (mic capture / 24 kHz resample / jitter-buffered playback /
WebRTC-SFU / SIP). **Choice: LiveKit Agents over Pipecat.** Justification: (i) LiveKit ships a
production WebRTC **SFU + SIP** stack, which Topology B's browser + any telephony lane needs as one
coherent transport, whereas Pipecat leans on external transports for SFU/SIP; (ii) LiveKit's
room/participant token model maps cleanly onto busbar's *"mint an ephemeral scoped secret"* posture
(the sideband holds the real OpenAI key; LiveKit tokens scope only the media room), keeping the trust
boundary crisp; (iii) both already run *behind* OpenAI Realtime, so the adapter surface is small
either way — the tiebreak is the bundled SFU/SIP. **The boundary:** busbar owns keys/routing/govern/
audit/server-side-tools and the sideband control WSS; LiveKit owns only the browser↔media leg and
sees no OpenAI key. If LiveKit is later dropped, the governed boundary (Topology A + the sideband) is
untouched — the adapter is one module in `busbar-voice`, not a core dependency.

**T2.5 — Gemini Live (2nd dialect → earns the superset IR → the backend-swap moat).**
The A2A rule (design §1.4): a plane earns a cross-dialect superset IR at its **second** wire format,
not before. OpenAI Realtime ⇄ Gemini Live `BidiGenerateContent` are two speech-native duplex dialects;
the four-layer IR bridges them (tool translate + `CallRef` id/name remap, control translate, media
verbatim tap, usage extract). This is the moat LiteLLM's WS↔WS passthrough structurally cannot reach
(design §9.3). Honest ceiling (design §2.7): the IR bridges speech-native duplex dialects; it does
**not** turn a speech-native model into a Whisper→LLM→TTS cascade — that is orchestration, not a codec.

**Files/crates touched.** New crate `crates/busbar-voice/**` (100% of voice nouns); its
`ProtocolDecl` registration; the LiveKit adapter module; **zero** edits to core/substrate/api beyond
the neutral seams T1 already shipped.

**Dependencies.** T1 (all of it). Independent of T3.

**Definition of Done.** Topology A holds a live voice session end-to-end (audio both ways, a mid-call
tool answered server-side, barge-in truncates correctly, usage metered per token-class, budget
hard-stops mid-session, session audited under one scope and restart-survivable). Topology B: a browser
establishes WebRTC voice with keys never leaving the server, a mid-call tool executes via the sideband,
locked instructions cannot be overridden by the client. Gemini Live serves the same client with no
client rewrite. The delete test proves `git rm -r crates/busbar-voice` leaves core/substrate/api
compiling; the neutrality gate finds zero voice nouns in core/substrate/api; the media byte-oracle
(§C) passes.

**CI gates.** plane-purity `--check` = 0 (voice crate names only substrate/api ABI); neutrality
(voice/audio/realtime/rtc/sdp/webrtc/barge zero in core/substrate/api); plane-delete (four planes,
voice now a real assertion); no-plugins; the new **voice conformance** suite; the **media
verbatim-relay byte-oracle**; composition gates; D1/D2/D3 witnesses.

---

### T3 — Prove one axis-C capability + the inbound webhook receiver (parallel with T2)

Axis C is a **separate** concern from duplex transport and must not wait behind WebSocket (design
Part II §II.1). The engine it rides is the one **T1.8 lifted into `busbar-substrate`** — the
process-wide registry, generic `transition<F>`, string-token terminal set (`is_terminal_state`),
retention/GC (`MAX_RETAINED_TASKS`, `sweep`), durable rehydration (`restore_from_store` via
`list_plane_records`), anti-enumeration scoped lookup (`get_scoped`), and the inbound-push cursor
(`set_push_callback`/`record_push_delivery`/`advance_cursor`). **T3 consumes the SUBSTRATE engine,
never `busbar_a2a`** — that is the whole point of the T1.8 lift; an LLM plane naming another plane's
crate would fail plane-purity on the spot. It rides the neutral `PlaneStore` seam and the
`DurableScope` taxonomy (*"the async plane parks a handle at a `202` and resumes it later"*,
`scope.rs:377`). (Pre-lift these mechanics were A2A-owned at `busbar-a2a/src/taskstore.rs` — cited in
T1.8; T3 does **not** reach there.)

**Deliverable.**
1. **Ship one axis-C capability.** Choose **OpenAI Responses-stateful** (`previous_response_id`
   handle tracking on the **substrate** handle engine, T1.8) as the first — it is the lowest-net-new
   (a handle row + a resume lookup, no new upload/download surface) and directly closes the design
   §1.6 gap where `previous_response_id`/`conversation`/`background` are *explicitly dropped* today
   (`chat_handle.rs:272-297`). (Batch/Files is the fallback if the owner prefers the async-job demo;
   it is more net-new — an upload→`file_id` store + a poller.)
2. **Ship the inbound webhook RECEIVER** — the one genuinely net-new-vs-LiteLLM piece (design §5.1,
   §1.6): busbar has **outbound** webhooks only (`export/webhook.rs` is fire-and-forget). Stateful
   Responses / batch / background all need busbar to *receive* a completion push, correlate it to a
   parked handle via the `taskstore` push cursor, verify it, and resume. This is orthogonal to voice.

**Files/crates touched.** The **substrate** session/handle engine (T1.8 module — reuse, no reach into
`busbar_a2a`); `crates/busbar-llm/**` (the Responses-stateful handle wiring off the substrate engine);
a new inbound-webhook receiver route + verifier; the session/handle record shape parked on
`DurableScope`.

**Dependencies.** T1 — specifically **T1.8** (the lifted substrate handle engine) and T1's
`DurableScope`/session seams. Independent of T2.

**Definition of Done.** A stateful Responses call parks a handle, a subsequent call resumes it by
`previous_response_id` through the scoped lookup, and an inbound completion webhook is received,
authenticated, correlated to the parked handle via the push cursor, and resumes the stream — durable
across a restart (rehydrated by `restore_from_store`). The receiver rejects unauthenticated /
replayed / mis-correlated pushes (security DoD, §D).

**CI gates.** The lifted substrate handle-engine suite (ex-A2A `taskstore`, moved with T1.8) green;
A2A still green consuming it; a new axis-C conformance test; the webhook-receiver security tests;
`git grep busbar_a2a:: crates/busbar-llm` = 0; plane-purity/neutrality/delete/no-plugins/composition
all green.

---

### T4 — Header-fidelity (orthogonal; any time)

The design doc's Phase 0 (§1.5, §6, Part II §II.2 item — *"headers are NOT forwarded; client
`anthropic-beta`/`OpenAI-Beta`/`anthropic-version` dropped on all paths"*). A client-header
forwarding seam (allowlist), egress + response side. Neither duplex nor stateful — de-linked from
everything above; lands on its own commit. **DoD:** a client beta header reaches upstream; a golden
asserts it; no cross-dialect leak. Relevant to voice only incidentally (GA-vs-beta Realtime selection
rides a header), so land it before or during T2 for convenience, not as a dependency.

---

## B. The EXACT ABI additions (shipped ABI, not a freeze)

Full scope means these **ship in 1.6.0**. Each is append-only / non-breaking to the ABI the
LLM/MCP/A2A planes already ride, and each stays plane-agnostic (core names no voice/WS/audio noun).

### B.1 — The two hot-vtable metering-lease slots (airlock minor 18 → 19)

Appended at the reserved extension point (`hot/host.rs:533-536`), trailing `Option` slots, mirroring
the existing slot shapes (all `Option<extern "C-unwind" fn>`, e.g. `GovernAdmitReasonFn` :66,
`JournalAppendFn` :80, `gate_decide` :532). **Precision correction vs design §6-D2:** the design doc
writes `magnitude: *const Magnitude`, but `Magnitude` (`cost.rs:270-277`) carries `unit: &'static
str` — a Rust reference, **not FFI-POD**. The slot must carry a POD projection of the magnitude
(unit as `ptr,len`; amount + caller_cap as scalars), exactly as the journal family crosses opaque
suffixes as `ptr,len`. Pinned signatures:

```rust
// APPENDED at hot/host.rs:533 (trailing Option slots) + mirrored on hot/pod.rs:636. Airlock MINOR 18→19.

/// A POD projection of `busbar_core::plane::cost::Magnitude` (whose `unit: &'static str` is not
/// FFI-safe). The host reconstructs the coarse magnitude; core never interprets `unit`.
#[repr(C)]
pub struct MagnitudePod {
    pub unit_ptr: *const u8,   // opaque plugin word ("audio_seconds" / "tokens"); host never parses it
    pub unit_len: usize,
    pub amount: u64,           // the over-estimate
    pub caller_cap: u64,       // 0 = none (mirrors Magnitude.caller_cap: Option<u64>)
}

/// Open a reserve-then-settle lease for a high-rate carrier: reserve a coarse over-estimate (host
/// debits the budget cell now) and return an opaque host-side lease id. Drives CostHold::reserve
/// (cost.rs:312). `flat_fee_nanos` is the once-only per-session fee folded into `reserved` (cost.rs:315).
pub type CostReserveFn = extern "C-unwind" fn(
    host: HostCtx,
    magnitude: *const MagnitudePod,
    flat_fee_nanos: u128,
    out_lease: *mut CostLeaseId,   // NEW POD newtype (u64); 0 = NONE sentinel
) -> StatusClass;

/// Settle one EXACT increment against an open lease (a turn's true cost) and read back exhaustion so
/// the plane can hard-close. Drives CostHold::settle_partial (cost.rs:327). The itemized CostBreakdown
/// crosses as an OPAQUE pre-framed suffix (the journal_append_scoped pattern); the host accrues only
/// its `total` (cost.rs:249) and answers exhaustion. Refund/finalize stays plane-side on CostHold
/// (cost.rs:334) — no refund policy is baked into the ABI.
pub type CostSettleFn = extern "C-unwind" fn(
    host: HostCtx,
    lease: CostLeaseId,
    breakdown_ptr: *const u8,      // opaque CostBreakdown suffix; host never parses the component labels
    breakdown_len: usize,
    out_exhausted: *mut bool,      // true ⇒ budget dry ⇒ plane hard-closes the session
) -> StatusClass;

pub cost_reserve: Option<CostReserveFn>,   // trailing slot (host.rs, below :536)
pub cost_settle:  Option<CostSettleFn>,    // trailing slot
```

**Append-only / non-breaking proof.** (a) Both are `Option` trailing slots under the sized/versioned
`AbiPreamble` discipline every appended cluster follows (the minor-18 `gate_decide` cluster is the
precedent, `host.rs:526-532`); an older plugin reads the struct through its preamble size and never
touches the new tail. (b) The two existing carriers of this ABI — the LLM plane and MCP/A2A — call
neither slot; their vtable offset for every slot they *do* call is unchanged (trailing append). (c)
The airlock MINOR bump (18→19) is the exact mechanism the reservation comment prescribes.

**Plane-agnostic proof.** Core mints nothing from the breakdown but the accrued `total`
(`cost.rs:249`); the labels cross as an opaque suffix the host never parses (`cost.rs:73-82` — "core
names no plane label"); `MagnitudePod.unit` is an opaque plugin word. No voice/audio noun appears.

### B.2 — `Transport::WebSocket` + the listener/dialer dispatch seam

```rust
// crates/busbar-substrate/src/transport.rs — appended to the enum (transport.rs:97-140) + ALL() (:170-174).
pub enum Transport { Http, JsonRpc, HttpJson, Grpc, Stdio, WebSocket }  // + WebSocket
```

Append-only: additive enum variant; the enum's only dispatch consumer today is `upstream_wire()`
(:143), which keeps its five arms and gains a `WebSocket` arm returning the framed-socket wire; the
telemetry `name()` (:187) gains `"websocket"`. **The net-new seam** is the generic `Transport → {
ingress listener, egress dialer }` map (§A T1.1) — the thing the module notes is *absent* today
(:143, one consumer only). Neutral: `WebSocket` is a transport noun, not a plane noun (it is
therefore **not** on the neutrality ban list — §C); MCP and A2A bind it too (T1.7).

### B.3 — The WS ingress Arrival kind

An additive arrival kind on the neutral `Arrival` seam (`ingress/arrival.rs:139`): the WS-upgrade
arrival populates `SessionScope` and runs `run_gauntlet` at open. Its per-kind payload (the upgraded
socket handle) rides the existing `ArrivalCtx(Box<dyn Any + Send + Sync>)` (:36) and is downcast
inside the `ArrivalHost` impl — the same mechanism the path-model dialects already use. Non-breaking:
the `Arrival` struct fields (:141-149) are unchanged; the kind is new data threaded through the
existing `ArrivalHost` trait (:59). Core names no "websocket" in the decision path — it sees an
arrival and a `PipeId`.

### B.4 — `SessionScope` wire-out fields

```rust
// crates/busbar-substrate/src/plane_host/scope.rs:366 — the empty #[non_exhaustive] stub, wired out.
#[non_exhaustive]
pub struct SessionScope {
    client_pipe:   PipeId,          // registered via DispatchScope::register_pipe (scope.rs:302)
    upstream_pipe: PipeId,          // pooled backend socket; RAII-reclaimed on Drop
    lease:         CostHold,        // the shipped reserve/settle lease (cost.rs:304)
    journal_scope: String,          // "session-<id>" for journal_append_scoped (host.rs:491)
    // correlation table (CallRef → (client_id, upstream_id)) is PLANE-owned, held plane-side, NOT here.
}
```

Append-only proof: the struct is already `#[non_exhaustive]` and documented as *"the riders … wire
this out"* (:361-366); nothing constructs it today (design §1.7 — "grep finds only its definition and
two re-exports"), so adding fields breaks no caller. Plane-agnostic: the field *types* are all neutral
(`PipeId`, `CostHold`, `String`); the plane-shaped `CallRef` table stays in `busbar-voice`, not here.

### B.5 — The `run_gauntlet_session` / session-handle-store seam

```rust
// crates/busbar-substrate/src/plane_host/mod.rs — appended BESIDE run_gauntlet (:177) & GauntletPlane (:158).
pub async fn run_gauntlet_session(
    req: GauntletRequest<'_>,
    plane: Box<dyn GauntletPlane + '_>,
) -> Result<SessionScope, axum::response::Response>;   // Ok(scope) on open; Err(response) on reject-at-open
```

Append-only proof: `run_gauntlet` is a free fn and `GauntletPlane` a trait (design §3.1, Part II
correction #5); the sibling adds beside them and reuses the same `verify_destination`-before-charge
sequence (:181) — session-open is still exactly today's one pass. No existing signature changes. The
durable session record parks on `DurableScope` (`scope.rs:377`) keyed `"session-<id>"`, rehydrated on
boot by the **lifted substrate handle engine** (T1.8) exactly as it rehydrates A2A's tasks and T3's
handles — one engine, three consumers, none reaching into another plane's crate.

---

## C. Neutrality & gates

**Nouns that live ONLY in `busbar-voice`** (verified absent from the tree today, so the crate
introduces them from zero — design §7.2): `realtime`, `input_audio_buffer`, `barge_in`,
`response.output_audio`, the OpenAI-Realtime event taxonomy, the IR types (`IrClientEvent`,
`IrServerEvent`, `IrAudioFrame`, `IrDuplexTool`, `IrDuplexControl`, `IrDuplexUsage`), the VAD surface,
`rtc_<call_id>`, `sdp`, the audio/text token-class split, the Gemini Live `BidiGenerateContent`
mapping, and the LiveKit adapter.

**How each gate stays green:**

- **grep-neutrality** (`scripts/plane-abi-neutrality.sh`): T0 adds `voice audio realtime rtc sdp
  webrtc barge` to `banned=` + `mandated=` (:30,:32). The gate scans **declaration lines** in the
  neutral crates for those substrings; `busbar-voice` names them freely, core/substrate/api name
  none. **`websocket` is deliberately NOT banned** — it is a neutral transport noun that legitimately
  lands in `Transport::WebSocket` and the substrate pump (the same reasoning that lets `Stdio` live in
  substrate). The one English-word collision, `client_secret`, is the OAuth sense already in core
  (`api/src/auth.rs`); the ban list keys on plane nouns, not shared words (design §7.3).
- **plane-purity** (`scripts/plane-purity-lint.sh` reverse mode): `busbar-voice` must name only
  `busbar_substrate::`/`busbar_api::`, never `busbar_core::` (the needle, :197). Must be **0 and
  armed** (`--check`, T0). New voice code is written to the ABI from its first line — the wall is up
  before the plane lands, which is exactly why T0 gates.
- **no-plugins** (`scripts/no-plugins-gate.sh`): core carries no plugin/plane branch; `busbar-voice`
  registers via `ProtocolDecl` (`codec: None` → `Some` at Gemini) exactly as MCP does — core's
  registry unions its verbs/keys without naming it.
- **plane-delete** (`scripts/plane-delete-test.sh`): T0 adds `voice` to `PLANES` (:76) + its bin
  feature token (:82). `git rm -r crates/busbar-voice` (+ drop the workspace member + strip the bin
  `dep:busbar-voice`) must leave core/substrate/api compiling. `Transport::WebSocket` + the pump are
  neutral substrate and **stay** (unused, like the pre-caller `Stdio` supervisor once was,
  `transport.rs:20-24`).
- **new voice conformance + MCP/A2A-WS conformance**: T2 adds the voice suite (session open through
  the gauntlet, mid-call tool, barge-in truncation, mid-session hard-stop, audit chain verify +
  restart); T1 adds MCP-over-WS and A2A-over-WS conformance (decision #2).
- **D1/D2/D3 witnesses**: D1 `WorkItem` tags (`hot/workitem.rs:31,47`) not collapsible; D2 slots
  present at minor-19 with the airlock version gate; D3 `SessionScope`/`run_gauntlet` shapes.

**The byte-oracle for the media verbatim relay.** Layer 3 (media) is an **identity** IR (design §2.4,
the same-proto-streaming precedent `proto_stream.rs` `same_proto`: re-emit original frame bytes
verbatim while the IR runs purely as a usage side-channel). The oracle: capture the upstream audio
frame bytes and the client-delivered bytes across a session and assert **byte-for-byte equality**
(both directions), while independently asserting the meter/audit tap fired per `response.done.usage`.
Any drift means the media path stopped being an identity transform (a fidelity regression, design §6).
The oracle sits beside the existing byte-identity suite (`egress_differential_tests` et al.).

---

## D. Honest cost & release boundary

**Sizing (realistic, PR-granular):**

| Track | PRs | Notes |
|---|---|---|
| T0 | ~14–20 | Dominated by ABI-purity P6 (engine off `&App`, one file/commit) — the ABI-purity doc's own estimate (§4). Plus ~2 for gate-list extensions. |
| T1 | ~12–16 | Full `Transport` dispatch + `WebSocket` (2–3, completing the half-wired axis is more than a variant add); WS arrival (2); pump port + fix + **MCP adopts/deletes bespoke loop** (3–4); **lift session/handle engine into substrate + A2A re-homes (T1.8)** (3–4); `SessionScope` wire-out (1); D2 slots + airlock + CostHold audit (1); `run_gauntlet_session` (1); A2A WS binding (1). Net simplification offsets some cost (two duplex loops → one; A2A registry deleted). |
| T2 | ~9–12 | Four-layer IR + `DuplexReader/Writer` (3, `IrClientEvent` is genuine net-new); Topology A (2); Topology B mint+SDP+sideband (2–3); LiveKit adapter (2); Gemini Live dialect + superset IR (2). |
| T3 | ~4–6 | Responses-stateful on `taskstore` (2); inbound webhook receiver + verifier + security tests (2–3). |
| T4 | ~1–2 | Header allowlist seam + golden. |
| **Total** | **~38–51 PRs** | **~6–9 focused weeks**, dominated by T0-P6, the T1 engine-lift/pump-consolidation, and T2. |

**The big risk items, named:**
1. **The media pump adapter (T2.4).** Largest external-dependency surface. Mitigation: the adapter is
   one module in `busbar-voice`; the governed boundary (Topology A + sideband) never depends on it.
   Owner-visible: LiveKit vs Pipecat is the biggest scope lever (§E).
2. **Browser WebRTC / SDP broker (T2.3).** `application/sdp` is a non-JSON body; the `Location:
   rtc_<call_id>` header must be preserved; the sideband WSS is a *second* long-lived socket per call.
   The trust boundary (browser never holds the key, never authors tools/instructions) is a security
   invariant, not a feature — test it adversarially.
3. **The `ArrivalPayload` `Any`-boundary for the WS arrival (T1.2, B.3).** The upgraded socket handle
   crosses `ArrivalCtx(Box<dyn Any>)` (`arrival.rs:36`) and is downcast in the `ArrivalHost` impl. The
   dual-compile constraint (ABI-purity doc §2) means the payload type must be substrate-owned or the
   downcast fails across the two core instances in a plane test binary. Get this wrong and it fails
   only at runtime in the test harness, not at compile time.
4. **The inbound webhook receiver's security surface (T3).** This is net-new *attack* surface: an
   unauthenticated external POST that resumes a parked handle. It must verify signature/origin,
   reject replays, and correlate to a handle via the anti-enumeration scoped lookup (`get_scoped`
   :859, single non-distinguishing `Denied::NotYours`) — never leak handle existence.
5. **The session/handle engine lift out of `busbar-a2a` (T1.8).** Moving a shipped, in-production
   engine (`TaskRegistry`, `taskstore.rs:385`) up a crate while A2A keeps running on it is a real
   refactor, not a copy. Risk: subtly changing rehydration/GC/scoped-lookup semantics A2A depends on.
   Mitigation: the engine's existing suite moves with it and must stay green *for A2A* at every commit
   (the engine names no plane noun — `is_terminal_state` is string-token, :317 — so the lift carries
   no A2A vocabulary up); do it before any new consumer (LLM/voice) attaches.

**One-way doors (call every one):**
- **D2 vtable slots (B.1)** — an ABI shape shipped at airlock minor-19. Once plugins compile against
  it, the signature is frozen; a later reshape is a breaking MAJOR. The `MagnitudePod` correction is
  the moment to get the shape right (§E Q1).
- **`Transport::WebSocket` variant (B.2)** — enum widening is cheap to add, but once MCP/A2A/voice all
  dispatch on it the *dispatch-seam contract* (what a `WebSocket` listener/dialer must provide) is
  load-bearing.
- **The WS Arrival kind (B.3)** and **`SessionScope` field shape (B.4)** — `#[non_exhaustive]` keeps
  them append-only-extendable, but the *first* field set defines the session model every duplex plane
  inherits.
- **The lifted substrate handle-engine API (T1.8)** — once A2A, the LLM plane, and voice all consume
  it, its public surface (park/resume/scoped-lookup/push-cursor) is a substrate contract; a later
  reshape touches three consumers. Audit-and-improve it *during* the lift, before the third consumer.
- **The media-adapter boundary (T2.4)** — choosing LiveKit's room/token model shapes the browser
  trust story; switching orchestrators later is a module rewrite (bounded, not a re-architecture).

**Release model: dev-only, promote-when-green.** All work lands on `integration/plane-extraction` →
`dev`; **never** `qa`/`main` directly (design §9). Human/CI handles promotion. Every commit keeps the
composition + plane-purity + neutrality + delete + no-plugins gates green; the plane is
`default`-feature-off until T2's DoD is met, so a red voice crate never reddens the neutral release
(the plane-delete test proves the app compiles without it at every commit).

---

## E. Open questions for the owner (short — scope is already chosen)

1. **Ratify the D2 signature with the `MagnitudePod` correction (§B.1).** The design doc's
   `*const Magnitude` is not FFI-POD (`Magnitude.unit: &'static str`, `cost.rs:271`); this plan pins a
   `MagnitudePod` projection. Ratify as written, or prefer raw `(amount, caller_cap, unit_ptr/len)`
   scalars inline on `CostReserveFn` (drop the struct)? This is the one-way door — five minutes now.
2. **Media orchestrator: confirm LiveKit Agents over Pipecat (§T2.4).** The plan picks LiveKit for its
   bundled WebRTC-SFU + SIP and its ephemeral-token model. If near-term telephony/SIP is *not* needed
   and the ops footprint of LiveKit is unwelcome, Pipecat is the lighter adapter. Biggest scope lever.
3. **T3 axis-C first capability: Responses-stateful (plan's pick) or Batch/Files?** Responses-stateful
   is lower net-new (handle row + resume lookup); Batch/Files better demonstrates the async-job engine
   but adds an upload/download surface. Which proves the stateful half most convincingly for 1.6.0?
