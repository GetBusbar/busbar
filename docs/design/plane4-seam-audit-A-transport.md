# Plane 4 — SEAM AUDIT A: Transport & Duplex I/O

Status: **READ-ONLY ADVERSARIAL AUDIT.** No code changed. Audit base commit
`e393b9e6` (`busbar 1.6.0 integration base-fix: relocate profile_tests.rs into busbar-substrate`),
verified with `git reset --hard e393b9e6`. Owner: Matthew.

Scope: the four transport / duplex-I/O seams Plane 4 (the duplex/session plane, `busbar-voice`)
must ride, audited against the PLANNED changes in `docs/design/plane4-duplex-session.md` (§4, §6)
and `docs/design/plane4-duplex-session-1.6.0-plan.md` (T1.1–T1.8, §B). Every claim is cited
`file:line` **at this commit** — the plan docs cite `integration/plane-extraction`, so line numbers
below are re-verified against `e393b9e6` and differ from the plan's.

**Reading key.** `[V]` = verified directly from code at this commit. `[I]` = inference / my
adversarial reading. `[PLAN]` = a claim taken from the design/plan docs, marked where it diverges
from what the code actually shows.

---

## SURFACE-NOW — the ranked actionable list (the key output)

Ranked by severity. Detail and citations under each seam below.

1. **[Seam 4 — HIGH] `ArrivalPayload` is `busbar-core`-owned, and `ArrivalCtx` mint+downcast are
   `pub` generics with no compilation-unit guard.** The `Any` payload is core's private
   `ArrivalPayload` (`crates/busbar-core/src/ingress/arrival_host.rs:32`), minted in core
   (`crates/busbar-core/src/ingress/dispatch.rs:537`) and downcast in core
   (`arrival_host.rs:38-41`, `.expect(...)`). Today mint and downcast are the **same crate/compile**,
   so TypeId is consistent and it works. But `ArrivalCtx::new<T>` and `downcast_ref<T>` are BOTH
   `pub` generic (`crates/busbar-substrate/src/ingress/arrival.rs:41,47`) with only a doc-comment
   ("Called only by core") as the guard — nothing structural stops a plane from minting its own
   payload type. The moment the WS-upgrade arrival (plan T1.2/B.3) carries a payload minted in one
   crate/core-instance and downcast in another — the dual-compile plane-ABI test binary has **two
   `busbar-core` instances** — the `TypeId` differs and `downcast_ref` returns `None`, tripping the
   `.expect()` **at runtime in the test harness, not at compile time**. FIX NOW: make the WS-arrival
   payload type **substrate-owned** (a concrete `pub` type in `busbar-substrate`, not core's private
   `ArrivalPayload`), and either (a) constrain `ArrivalCtx` to substrate-owned payload types, or (b)
   at minimum document+test the single-canonical-compile requirement before the second minter lands.
   This is the plan's own biggest-risk item (§D item 3) and the code confirms the hazard is real and
   currently unguarded.

2. **[Seam 2/1 — HIGH] `SessionScope` has NO arena and NO `Drop` — the "RAII reclaim on close" story
   is not wireable as the plan's field list is written.** `SessionScope {}` is a truly empty
   `#[non_exhaustive]` struct (`crates/busbar-substrate/src/plane_host/scope.rs:364-366`) with only
   `new()` (`:371-373`) — no arena, no `Drop`, no reclaim machinery. `register_pipe` (the RAII pipe
   reclaim) lives on **`DispatchScope`** (`scope.rs:302-311`), and the only scope that owns an arena
   for reclaim is `DurableScope { arena: DispatchScope }` (`scope.rs:404`). The plan's B.4 field list
   (`client_pipe: PipeId, upstream_pipe: PipeId, lease: CostHold, journal_scope: String`) stores
   **bare `PipeId(u64)` handles** — which carry no `Drop` and no reclaim closure. So as specified,
   nothing reclaims the pooled upstream socket on session close/panic/cancel; the plan's own prose
   ("pooled upstream socket registers via `DispatchScope::register_pipe` … RAII-reclaimed on Drop",
   §3.2/B.4) references a mechanism `SessionScope` does not have. FIX NOW / decide-before-freeze:
   the first `SessionScope` field set must include an owned arena (mirror `DurableScope`'s
   `arena: DispatchScope`) or an equivalent `Drop`-bearing reclaim holder, not bare `PipeId`s — this
   is a one-way door (T1.4 DoD: "the first field set defines the session model every future duplex
   plane inherits").

3. **[Seam 1 — MEDIUM] The `Transport` axis is genuinely half-wired: only `upstream_wire()` dispatches,
   and it lives behind `#[cfg(feature = "dispatch")]` on the MCP client leg.** `Transport`
   (`crates/busbar-substrate/src/transport.rs:96-140`) has one and only one dispatch consumer,
   `upstream_wire()` (`:218-224`), and it is **feature-gated** (`#[cfg(feature = "dispatch")]`
   `:217`) and returns an **MCP-plane-specific** `UpstreamWireKind` (`:151-156`, also
   `dispatch`-gated). Every other consumption is the telemetry label `name()` (`:185-196`). There is
   **no ingress-listener dispatch on `Transport` at all** — ingress arrives through the separate
   `Arrival`/`PathIngress` seam (arrival.rs), which is keyed by **protocol name string**, not by
   `Transport`. So the plan's T1.1 "generic `Transport → {ingress acceptor, egress driver}` dispatch"
   is not an extension of an existing axis; it is a **net-new dispatch primitive** that must be
   reconciled with the fact that (a) the sole existing arm is egress-only and plane-typed, and (b)
   ingress today keys on protocol name, not transport. Building `Transport::WebSocket` as "one variant
   among equals" requires first CREATING the equals — the acceptor side does not exist for ANY variant.
   Not a bug; a scope-honesty correction to the plan's framing.

4. **[Seam 3 — MEDIUM] The pump-port premise understates the server leg: a working single-reader +
   correlation table ALREADY exists in `stdio_serve.rs` — the "MCP punted on it" warning applies only
   to the CLIENT leg.** The MCP SERVER leg (`crates/busbar-mcp/src/mcp/stdio_serve.rs`) already has
   the exact pieces the plan calls net-new: a single reader loop (`run_session`, `:280`, `read_until`
   `:292`), a single write lock (`out: tokio::sync::Mutex<W>`, `:393`), a **correlation table** for
   busbar-originated asks (`pending: Mutex<HashMap<String, oneshot::Sender>>`, `:401`), reply routing
   (`route_reply`, `:310`/`:424`), a cancellation table (`inflight`, `:399`), and per-frame host
   re-mint (`:522`). The CLIENT leg (`mcp/client/stdio.rs`) is the one that serializes and lacks a
   reader task/correlation table, and documents why (`:822-827`). So the pump port is a
   **generalization of an existing working server loop**, not the invention the plan implies — LOWER
   risk than "the pump ships the exact thing that limitation was waiting on." SURFACE-NOW: audit the
   `pending` correlation table's semantics (it correlates by JSON-RPC id via `id_key`, an MCP-plane
   shape) before lifting — the substrate pump's correlation key must be plane-neutral (a `CallRef`
   the plane owns), not MCP's `id_key`, or the lift drags MCP vocabulary into substrate.

5. **[Seam 2 — LOW/MEDIUM] D2 `cost_reserve` signature vs the shipped `CostHold::reserve` shape.**
   Two shape mismatches to resolve BEFORE the airlock minor-19 freeze (one-way door): (a) the plan's
   `MagnitudePod` correction is **verified-correct** — `Magnitude.unit: &'static str`
   (`crates/busbar-core/src/plane/cost.rs:271-272`) is not FFI-POD, so the design doc's
   `*const Magnitude` cannot cross the seam; (b) a mismatch the plan does NOT flag: the shipped
   `CostHold::reserve(estimate: CostAmount, fee: CostAmount)` (`cost.rs:312`) takes an **already-computed
   `CostAmount` money scalar**, not a `Magnitude`/`MagnitudePod`. So the slot carrying a `MagnitudePod`
   (unit+amount+cap) implies a **host-side `Magnitude → CostAmount` conversion step that does not exist
   today** — who owns "audio_seconds × rate = nanos"? Decide whether the slot passes the coarse magnitude
   (host converts, host owns the rate) or the pre-computed `CostAmount` (plane converts, matches
   `CostHold::reserve` as shipped). This is the exact "get the shape right before it freezes" the plan
   demands (§E Q1), and it has a second edge the plan missed.

6. **[Seam 1 — LOW] `Transport::ALL` and `name()` are test-only / label-only; adding `WebSocket`
   touches the neutrality vocabulary.** `Transport::ALL` is `#[cfg_attr(not(test), allow(dead_code))]`
   (`transport.rs:168`) with test-only readers; `name()` returning `"websocket"` would be added at
   `:185-196`. Per plan §C, `websocket` is deliberately NOT on the neutrality ban list (it is a
   neutral transport noun, same tier as `stdio` at `:194`). Verified consistent — flagged only so the
   T0 ban-list edit does not accidentally add `websocket` and red the substrate crate.

---

## Seam 1 — the `Transport` enum + its dispatch (`crates/busbar-substrate/src/transport.rs`)

### (a) TODAY — verified from code

- **The enum** is the closed set `{ Http, JsonRpc, HttpJson, Grpc, Stdio }`
  (`transport.rs:96-140`) — **no `WebSocket` variant** `[V]`. `#[derive(Debug, Clone, Copy,
  PartialEq, Eq, Hash)]` (`:96`).
- **The ONE dispatch consumer** is `upstream_wire(self) -> Option<UpstreamWireKind>`
  (`:218-224`): `Http → StreamableHttp`, `Stdio → Stdio`, the three A2A variants → `None`. It is
  **`#[cfg(feature = "dispatch")]`-gated** (`:217`) and returns `UpstreamWireKind` (`:151-156`, also
  `dispatch`-gated) — an MCP-client-egress discriminant the plane maps to `&dyn McpWire` on its own
  side. This is the module's own stated "ONE match on this axis in the tree" (`:198-207`) `[V]`.
- **Every other consumption is a telemetry label**: `name(self) -> &'static str` (`:185-196`) maps
  each variant to a Prometheus/tracing string, three of them read from `crate::plane::WIRE_*`
  constants (`:188-193`). `Transport::ALL` (`:169-175`) is `#[cfg_attr(not(test), allow(dead_code))]`
  (`:168`) — the module states its "readers are TESTS today" (`:163-167`) `[V]`.
- **Ingress does NOT dispatch on `Transport`.** Path-model ingress keys on **protocol-name string**
  through the separate `Arrival`/`PathIngress` seam (arrival.rs — see Seam 4), and
  `path_ingress_for(name: &str)` (`arrival.rs:208`) resolves by name, never by transport `[V]`.

So the axis is, precisely: **an egress-only, feature-gated, plane-typed selector plus a telemetry
label.** The A2A variants (`JsonRpc`/`HttpJson`/`Grpc`) are consumed ONLY as `name()` labels — they
have no `upstream_wire` arm (they return `None`, `:222`) and no acceptor `[V]`. This confirms the
plan's T1.1 "half-wired today … A2A variants consumed only as telemetry labels" `[V]`.

### (b) WITH CHANGES

Plan T1.1/§B.2: complete the axis into a generic `Transport → {ingress acceptor, egress driver}`
dispatch, then add `WebSocket` as one properly-dispatched variant. The plan is right that this is
"audit-and-improve, not tack-on." But the code shows the gap is **deeper than half-wired**:

- The egress side has exactly one arm and it is **MCP-plane-shaped** (`UpstreamWireKind` names MCP's
  two wires). A generic egress-driver dispatch cannot reuse `upstream_wire` — it must be a new
  neutral seam, and `upstream_wire` either subsumes into it or stays the MCP special-case it is `[I]`.
- The **ingress-acceptor side does not exist for ANY variant** — ingress is name-keyed via `Arrival`,
  not transport-keyed. "Add `WebSocket` as one variant among equals" is misleading: there are no
  equals on the acceptor axis to join `[V→I]`.

Does the current shape accommodate cleanly? **Egress: adequately** (adding a `WebSocket` arm to the
existing `Option<UpstreamWireKind>` match is mechanical, though it deepens the MCP-typing debt the
plan wants to pay down). **Ingress: no** — there is no transport-keyed acceptor dispatch to extend;
it is net-new.

### (c) SURFACE-NOW

- **[MEDIUM] #3 above** — the axis is half-wired and the un-wired half (ingress acceptor) does not
  exist even in stub. The plan's "complete the axis, then WebSocket is a variant among equals" framing
  is optimistic: the "equals" (acceptors) must be built from zero. Reconcile the plan's sizing (§D:
  "2–3 PRs, completing the half-wired axis is more than a variant add") — it is, and the acceptor side
  is genuinely greenfield, not a completion.
- **[LOW] #6 above** — `name()`/`ALL` label-vocabulary touch; `websocket` stays off the neutrality
  ban list by design (plan §C). Clean, flagged for T0 hygiene.
- Otherwise the enum shape (`Copy` closed tag, exhaustive-match discipline) is exactly the right shape
  for the add — **no reshape needed for the enum itself** `[V]`.

---

## Seam 2 — byte-duplex host slots `pipe_read`/`pipe_write` (`crates/busbar-plugin/src/hot/host.rs`, `pod.rs`)

### (a) TODAY — verified from code

- **The slots are live and real.** `PipeReadFn` (`host.rs:160-166`) and `PipeWriteFn` (`:170-171`)
  are `extern "C-unwind"` fn types keyed by `PipeId`; the vtable slots `pipe_read: Option<PipeReadFn>`
  (`:474`) and `pipe_write: Option<PipeWriteFn>` (`:476`) are populated on the live host. Their
  contract is explicit: **"The host moves RAW BYTES only — line/message framing stays PLANE-side"**
  (`:156-159`, `:167-169`) `[V]`. `Ok` with `out_written = 0` = clean EOS (`:158`).
- **`PlaneHostVtable::STUB` is a compile fixture, not the live host.** `STUB` (`:606`) points every
  slot at an `unimplemented!()` (`pipe_read`/`pipe_write` stubs at `:854-870`). The header states it
  exists to type-prove signatures, not run (`:602-605`). So the plan's warning ("do not misread the
  `unimplemented!()` STUB as the live host") is **verified-correct** — the byte-duplex egress
  primitive genuinely ships `[V]`.
- **The metering lease slots are RESERVED, not present.** The header states metering `reserve`/`settle`
  (a `CostHold`) is "DELIBERATELY absent" (`:20-22`); the extension point comment sits after
  `gate_decide: Option<GateDecideFn>` (`:532`): *"add `cost_reserve`/`cost_settle` as trailing
  `Option` slots below this line and bump the airlock MINOR — an append-only add, never a reshape"*
  (`:534-536`). `ABI_MINOR = 18` (`crates/busbar-plugin/src/lib.rs:72`); last cluster was minor-18
  (gate_decide, `:526`). So D2 = minor 18→19 `[V]`.
- **The shipped `CostHold`** (`crates/busbar-core/src/plane/cost.rs:304`): `reserve(estimate:
  CostAmount, fee: CostAmount)` (`:312`), `settle_partial(&CostBreakdown)` (`:327`), `finalize() ->
  Settlement` (`:334`). `Magnitude.unit: &'static str` (`:271-272`) `[V]`.

### (b) WITH CHANGES

Plan: the WS egress driver rides `pipe_read`/`pipe_write`; the D2 `cost_reserve`/`cost_settle` slots
append at the reserved point. The byte primitive **accommodates cleanly** — an audio frame is a
plane-framed message over a `PipeId`, identical in shape to MCP's newline-delimited JSON-RPC (design
§2.4). No reshape of the pipe slots is needed `[V→I]`.

The D2 slots also append cleanly **as an ABI mechanism** (trailing `Option` under the sized/versioned
`AbiPreamble` discipline, `lib.rs:81-95`; older plugins read through the preamble size and never touch
the tail) `[V]`. But the **signature shape** is not yet right (see (c)).

### (c) SURFACE-NOW

- **[LOW/MEDIUM] #5 above** — two D2 signature shape issues to fix before the minor-19 freeze:
  `MagnitudePod` (verified-necessary: `Magnitude.unit: &'static str` is not FFI-POD, `cost.rs:271`)
  AND the un-flagged `reserve` mismatch (shipped `CostHold::reserve` takes `CostAmount`, not a
  magnitude — the `Magnitude → CostAmount` rate conversion has no owner today). Decide the ownership
  of that conversion before the slot freezes.
- **[INFO] nuance:** MCP stdio's server leg drives `tokio::io::{stdin,stdout}` directly
  (`stdio_serve.rs` `serve_io`, `:232`) rather than through the `pipe_read`/`pipe_write` FFI slots.
  The FFI pipe slots are the **subprocess/raw-connection tier** (`host.rs:155-159`). So "MCP stdio
  uses them in production" is true of the pipe-tier client egress path but the in-process serve loop
  uses tokio io directly — confirm the WS driver rides the FFI pipe slots for its pooled upstream
  socket `[V→I]`.
- Otherwise: **the byte-duplex primitive is clean and ships** — no fix needed on the pipe slots
  themselves `[V]`.

---

## Seam 3 — the bidirectional PUMP (`crates/busbar-mcp` — `Session<W>`/`run_session` server leg; `mcp/client/stdio.rs` client leg)

### (a) TODAY — verified from code

**Server leg (`stdio_serve.rs`)** — the proven duplex loop:
- `Session<W>` (`:383-410`): `factory: LiveHostFactory` (`:388`, per-frame re-mint),
  frozen `principal`/`gov` (`:389-390`), the single write lock `out: tokio::sync::Mutex<W>`
  (`:391-393`, *"ONE writer, one lock: two concurrent responses interleaving inside a line would be a
  frame no reader could parse"*), the cancellation table `inflight: Mutex<HashMap<String,
  AbortHandle>>` (`:398-399`), and **a correlation table** `pending: Mutex<HashMap<String,
  oneshot::Sender<Result<Value,String>>>>` (`:400-401`) for busbar-originated asks `[V]`.
- `run_session` (`:280`): single reader loop `read_until(b'\n')` (`:292`) → `route_reply` first
  (`:310`, `:424`) → spawn each non-reply frame as a task (`:317`) → all writes funnel through `emit`
  under the one lock (`:415`). Per-frame host re-mint `let host = (self.factory)();` (`:522`) `[V]`.

**Client leg (`mcp/client/stdio.rs`)** — the deliberate NON-template:
- `StdioPool` (`:828-831`): one child per registration, calls **serialized** by a per-slot
  `Arc<tokio::sync::Mutex<ChildSlot>>` (`:830`). The doc states why (`:822-827`): interleaved pairs
  "can only be told apart by demultiplexing on the JSON-RPC id — which is a second correlation table
  … Serialising is the honest shape **until there is a reader task to own that table**." So the
  client leg has **no reader task and no correlation table** — verified `[V]`.

### (b) WITH CHANGES

Plan T1.3: port `Session<W>` to a substrate-owned pump over any byte-duplex `PipeId`; FIX the missing
correlation/reader; MCP ADOPTS it and deletes the bespoke loop.

The **shape is right and the accommodation is clean** — the reader becomes `DuplexReader` over
`pipe_read` bytes instead of `read_until(b'\n')`, the writer is `pipe_write` under the same single
lock (design §4.3) `[V→I]`. Critically, the plan's claim that the pump "adds what MCP's loop lacks"
is **half true**: the server leg ALREADY has the reader task + a correlation table (`pending`,
`:401`); it is the CLIENT leg that punted. So the port is a **generalization of the working server
loop**, applying it to the egress (upstream) direction where the client leg serializes today `[V]`.

### (c) SURFACE-NOW

- **[MEDIUM] #4 above** — the plan understates existing coverage (server leg already has
  reader+correlation), and the correlation key in `pending` is MCP-plane-shaped (`id_key` on the
  JSON-RPC id). The substrate pump's correlation table must key on a **plane-neutral `CallRef`** the
  plane owns, not MCP's `id_key`, or lifting the loop drags MCP vocabulary into `busbar-substrate`
  and reds neutrality/purity. Audit the correlation-key type as part of the lift `[V→I]`.
- **[INFO] adopt-and-delete risk:** MCP's server loop carries MCP-specific behavior beyond framing —
  `notifications/cancelled` handling (`:701`), `logging/setLevel` floor (`:394-397`, `level`),
  `resources/subscribe` watchers (`:403-409`, `resource_subs`/`background`). The substrate pump is
  protocol-neutral; these must move to the plane side, not into the pump. "Delete the bespoke loop"
  is not a clean subtraction — it is a split of neutral-pump vs MCP-plane behavior `[V→I]`. Plan
  T1.3's "net simplification (one pump, not two)" holds only for the framing/correlation core, not
  the MCP semantics layered on it.

---

## Seam 4 — ingress ARRIVAL (`crates/busbar-substrate/src/ingress/arrival.rs`; `busbar-core` payload)

### (a) TODAY — verified from code

- **The `Arrival` seam** (`arrival.rs:139-150`): `Arrival { host: Arc<dyn ArrivalHost>, ctx:
  ArrivalCtx, path: String, uri: Uri, headers: HeaderMap, body: Bytes }`. Dispatched via a `fn`
  pointer `PathIngress = fn(Arrival) -> Pin<Box<dyn Future<Output=Response> + Send>>` (`:157`),
  resolved by protocol-name string in `path_ingress_for(name: &str)` (`:208`) `[V]`.
- **`ArrivalCtx(Box<dyn std::any::Any + Send + Sync>)`** (`:36`) — the opaque core context. Both
  `ArrivalCtx::new<T: Any + Send + Sync>(payload: T)` (`:41`) and `downcast_ref<T: Any>(&self)`
  (`:47`) are **`pub` generics** — the only guard is a doc-comment ("Called only by core … the type
  parameter is core's own private payload struct", `:39-40`) `[V]`.
- **The payload is `busbar-core`-owned.** `ArrivalPayload { app: Arc<App>, gov: GovCtx, caller:
  CallerToken }` is `pub(crate)` in `crates/busbar-core/src/ingress/arrival_host.rs:32-36`. It is
  minted in core: `ArrivalCtx::new(ArrivalPayload { app, gov, caller })`
  (`crates/busbar-core/src/ingress/dispatch.rs:537-539`), and downcast in core:
  `payload(ctx)` → `ctx.downcast_ref::<ArrivalPayload>().expect("… a wiring bug otherwise")`
  (`arrival_host.rs:38-41`) `[V]`.
- **The dialect crate does NOT downcast** — `busbar-llm/src/arrival.rs` only holds and forwards
  `ctx: ArrivalCtx` into the host methods (`:68-75`, `gemini_arrival`), never opening it. So today
  **mint and downcast are the same crate (`busbar-core`) and the same compilation unit** `[V]`.

### (b) WITH CHANGES

Plan T1.2/B.3: a WS-upgrade ARRIVAL KIND that runs `run_gauntlet` at open and populates
`SessionScope`, NOT an axum `on_upgrade` from a route handler. The upgraded socket handle rides the
existing `ArrivalCtx(Box<dyn Any>)` and is downcast inside the `ArrivalHost` impl.

- The `Arrival` **struct shape accommodates** an added kind without a reshape (the neutral fields are
  unchanged; a new kind is new data threaded through the existing trait) `[V→I]`.
- The anti-pattern the plan warns against (returning `WebSocketUpgrade::on_upgrade` from a
  `PathIngress`) is real: `PathIngress` returns `Response` (`:157`), so one COULD smuggle a raw socket
  out and bypass the gauntlet. Verified there is **zero** `WebSocketUpgrade`/`on_upgrade`/`tungstenite`
  in the tree (greenfield) `[V]`.
- **The payload boundary does NOT accommodate cleanly** — see (c).

### (c) SURFACE-NOW

- **[HIGH] #1 above** — the dual-compile TypeId hazard is real and currently unguarded. Today it is
  latent (single core compile, mint+downcast co-located in `busbar-core`). The WS arrival is the
  **first case** where the payload might be minted or downcast across a crate/core-instance boundary,
  and `ArrivalCtx::new`/`downcast_ref` being `pub` generics enforce nothing. Make the WS-arrival
  payload **substrate-owned** and add a guard/test before the second minter lands. This is the plan's
  §D-item-3 risk, confirmed in code.
- **[MEDIUM] the `.expect()` is a runtime panic surface** (`arrival_host.rs:40`). A TypeId mismatch
  from a dual-compile boundary manifests as a panic in the test harness, not a compile error — the
  plan (§D3) says exactly this. If the WS payload stays core-owned and gets downcast in a plane's
  `ArrivalHost` impl compiled against a second core instance, this `.expect()` fires. `[V→I]`
- **[INFO]** `SessionScope` population (the arrival's stated job) collides with SURFACE-NOW #2 —
  `SessionScope` has no arena to hold a reclaimable socket, so "populates `SessionScope`" is
  under-specified until #2 is resolved.

---

## Appendix — verified line-map at `e393b9e6` (for the builder)

| Claim | File:line | Status |
|---|---|---|
| `Transport` enum, 5 variants, no WebSocket | `busbar-substrate/src/transport.rs:96-140` | [V] |
| `upstream_wire()` — the ONE dispatch, `dispatch`-gated | `transport.rs:217-224` | [V] |
| `UpstreamWireKind` (MCP-plane-typed), `dispatch`-gated | `transport.rs:149-156` | [V] |
| `name()` telemetry label | `transport.rs:185-196` | [V] |
| `ALL` test-only | `transport.rs:168-175` | [V] |
| `ArrivalCtx(Box<dyn Any>)`, pub `new`/`downcast_ref` | `busbar-substrate/src/ingress/arrival.rs:36,41,47` | [V] |
| `Arrival` struct / `PathIngress` fn ptr | `arrival.rs:139-150,157` | [V] |
| `path_ingress_for(name)` name-keyed | `arrival.rs:208` | [V] |
| `ArrivalPayload` core-owned | `busbar-core/src/ingress/arrival_host.rs:32-36` | [V] |
| downcast+`.expect()` in core | `arrival_host.rs:38-41` | [V] |
| mint in core dispatch | `busbar-core/src/ingress/dispatch.rs:537-539` | [V] |
| dialect forwards ctx, no downcast | `busbar-llm/src/arrival.rs:68-75` | [V] |
| `PipeReadFn`/`PipeWriteFn` "raw bytes only" | `busbar-plugin/src/hot/host.rs:155-171` | [V] |
| `pipe_read`/`pipe_write` live slots | `host.rs:474,476` | [V] |
| `STUB` is compile fixture (`unimplemented!`) | `host.rs:602-606,854-870` | [V] |
| D2 extension point + "trailing Option, bump MINOR" | `host.rs:534-536` | [V] |
| `ABI_MINOR = 18` | `busbar-plugin/src/lib.rs:72` | [V] |
| `Magnitude.unit: &'static str` (not FFI-POD) | `busbar-core/src/plane/cost.rs:271-272` | [V] |
| `CostHold::reserve(CostAmount, CostAmount)` | `cost.rs:312` | [V] |
| `settle_partial`/`finalize`/`Settlement` | `cost.rs:327,334,282` | [V] |
| `SessionScope {}` empty, no arena/Drop | `busbar-substrate/src/plane_host/scope.rs:364-373` | [V] |
| `register_pipe` on `DispatchScope` | `scope.rs:302-311` | [V] |
| `DurableScope { arena: DispatchScope }` | `scope.rs:396-405` | [V] |
| `Session<W>`: out-lock, inflight, pending | `busbar-mcp/src/mcp/stdio_serve.rs:383-410` | [V] |
| `run_session` reader loop, per-frame re-mint | `stdio_serve.rs:280-357,522` | [V] |
| client leg serializes, no reader/correlation | `busbar-mcp/src/mcp/client/stdio.rs:820-831` | [V] |
| `InboundKind::Stream` / `EmitKind::Unsolicited` WIRED | `busbar-plugin/src/hot/workitem.rs:31,47` | [V] |
</content>
