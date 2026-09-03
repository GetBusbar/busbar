# T2 — the busbar-voice runtime session pump / duplex-session entry

Status: **BUILD PLAYBOOK** for the P2 runtime (design `plane4-duplex-session.md` §8, phase P2).
Read-only against CODE; the one write is this file. Scope: the `run_gauntlet_session` sibling to the
LLM `run_gauntlet` — the concrete session pump, its PlaneDecl wiring, the gauntlet witness that keeps
the session sibling from being foreclosed, and the stub/net-new/risk ledger.

**Citation base.** `integration/plane-extraction` worktree (`config-seam-work`). Every `crates/…:NNN`
below was re-verified this pass. Where a claim is a recommendation not a fact it is **[REC]**; where
it is a gap in the current tree it is **[GAP]**.

**One-line finding.** The pump BODY is already built and green behind the `runtime` feature
(`SessionCore` + the two `DuplexPlane` legs + `Carrier` + the D2 `MeteringLease` port). What is
genuinely missing is (a) the substrate `run_gauntlet_session` sibling so session-*open* is one
governed gauntlet pass (today `begin_session` opens the lease/handle but SKIPS `verify_destination`),
(b) the `PlaneDecl` `start`/`build`/`hydrate` hooks that mount and boot-rehydrate it, and (c) the
`GauntletPlane::drive` witness test that stops a 1.6.0 "simplification" from foreclosing the sibling
(audit D rank-2 / audit B seam-2: confirmed NOT foreclosed at this pin, guarded only by structure).

---

## 1. The concrete session pump (open → duplex loop → per-event IR → meter → hard-close)

The pump is a composition of shipped pieces; the flow below is the authoritative wiring, each step
cited to the file that owns it.

### 1.1 OPEN — one governed pass that mints the lease + durable handle + core

Today the open is `topology::begin_session` (`crates/busbar-voice/src/topology/mod.rs:106-136`):

1. **Reserve the D2 lease FIRST, fail-closed.** `rt.open_lease(estimate, fee, cap)`
   (`runtime/mod.rs:72` → `MeteringPort::reserve`, `runtime/metering.rs:72`) returns `None` on a
   refuse-all/zero budget → `StartError::BudgetRefused` → **no session** (`topology/mod.rs:120-122`).
   Production binds `HostMeteringPort` over the neutral `MeteringHost` slice
   (`cost_reserve`/`cost_settle`/`cost_settled`/`cost_close`, `metering.rs:201-220`, the minor-19 D2
   money hop); tests bind `LocalMeteringPort` (`metering.rs:164`) whose contract is byte-for-byte.
2. **Open the durable `SessionHandle` at genesis.** `rt.bind_session(owner, call_id)` →
   `SessionHandle::bind` → `SessionScope::new(engine, owner, id)` (`runtime/scope.rs:94`,
   substrate `plane_host/scope.rs:400`), then `handle.open(now)` submits the genesis row through the
   `DurableHandleEngine` (`runtime/scope.rs:119-150`). Owner is load-bearing: a foreign-owner rebind
   collapses to the one indistinguishable `NotYours` (`scope.rs:452-483`).
3. **Assemble the `SessionCore`** (`runtime/session.rs:87`) over `codec`, `lease`, `tools`, `pricing`,
   `carrier`, `locked_config` and return `(Arc<SessionCore<C>>, SessionHandle)`.

**[GAP — the net-new open work].** `begin_session` is a plane-crate-local entry; it does **not** run
the substrate gauntlet's stage-2 `verify_destination` before the reserve. Per design §3.1 and audit B
seam-2 items #1/#6, session-open must be *exactly one `run_gauntlet` pass* — `verify_destination`
(judge the upstream/model, `plane_host/mod.rs:169`) strictly BEFORE any charge, and the opening
reserve is net-new code that **cannot ride `drive`** (`drive(self: Box<Self>) -> Response` consumes
the plane and returns a `Response`, `plane_host/mod.rs:175`). The sibling to add (§2.3):

```
// busbar-substrate::plane_host — APPEND beside run_gauntlet (mod.rs:185), never inline it.
pub async fn run_gauntlet_session(
    req: GauntletRequest<'_>,
    plane: Box<dyn GauntletPlane + '_>,          // reuse verify_destination for the open pass
    open: impl FnOnce() -> Result<SessionScope, Response>,  // the plane's begin_session, post-verify
) -> Result<SessionScope, Response> {
    match plane.verify_destination(&req) {        // stage 2, BEFORE any reserve
        VerifyOutcome::Refuse(resp) => Err(resp),
        VerifyOutcome::Proceed => open(),         // begin_session: reserve → durable open → core
    }
}
```

The returned `SessionScope` must be **fully owned** (no borrow from `GauntletRequest<'a>` — a 20-min
session outlives the request; audit B seam-2 #2). The voice side already satisfies this: `SessionScope`
holds owned `Arc<engine>` + `String` owner/id (`scope.rs:382-391`), and the lease/carrier are owned.

### 1.2 The DUPLEX EVENT LOOP — over the neutral pump port

The pump is `busbar_substrate::ingress::byte_duplex::serve_messages(stream, sink, plane)`
(`byte_duplex.rs:318`) — the message-framed sibling of the stdio `serve` (`:276`), shaped for an
already-upgraded WS: `Stream<Item=Vec<u8>>` in, `Sink<Vec<u8>>` out, one `DuplexPlane` (`:81`) driving
each frame. The voice plane binds TWO legs to the ONE core so both directions of the full-duplex
carrier flow:

- **Upstream leg — `VoiceSession<C>`** (`session.rs:286`, `impl DuplexPlane :303`): served over the
  socket busbar holds to the provider (dialed by `topology::dial_provider` →
  `Transport::WebSocket.upstream_wire() == Duplex` → `duplex_ws::dial`, `topology/mod.rs:49-65`). Each
  `handle(frame, out)` (`session.rs:313`) decodes one server→client frame via `on_server_frame` and
  drives the plan: client→server writes back onto `out.emit` (`byte_duplex.rs:109`), downlink onto the
  `Carrier`.
- **Uplink leg — `UplinkForwarder<C>`** (`session.rs:334`, `impl DuplexPlane :350`): served over the
  client/telephony socket; each frame decodes via `on_client_frame` and funnels upstream through the
  shared `mpsc` sink into the same single upstream writer (`session.rs:358-364`) — the "one writer,
  one lock" discipline the design ports from MCP `Session<W>`.

`classify` returns `None` on both legs (`session.rs:307`, `:354`): Realtime events are
fire-and-forget notifications, so transport-level reply correlation is off — correlation is done at
the IR layer by voice `CallRef`, not the pump's `CallRef`.

### 1.3 PER-EVENT IR TRANSLATE — the synchronous decode+act core

`SessionCore::on_server_frame` (`session.rs:120`, async only for tool exec) and `on_client_frame`
(`session.rs:254`, sync) are the deterministic heart — unit-testable without async plumbing. Both
first short-circuit on `carrier.is_closed()` (the hard-close guarantee: nothing processed once dry,
`session.rs:121`, `:255`). Then `codec.read_down/read_up(frame, &mut decode)` yields IR events matched
by the four layers (design §2):

- **Layer 1 tool moat** (`session.rs:173-211`): `CallOpen→CallArgs*→CallClose` accumulate into a
  `PendingCall` keyed by `CallRef`; on close the tool executes **server-side** (`tools.execute`,
  after the lock is dropped, `:228-242`), then `CallResult` + `ResponseCreate` write upstream. The
  browser never authors a result.
- **Layer 2 control** (`session.rs:265-271`): a client `SessionConfigure` is a HINT reconciled against
  the plane's `locked_config` — the plane re-applies ITS tools+instructions, never the browser's.
  Barge-in `SpeechStarted` cancels + `ItemTruncate{audio_played_ms = decode.flush_playback()}`
  (`:151-171`) — plane-computed playback position, not a wire copy.
- **Layer 3 media** (`session.rs:213-219`): audio/`SpeechStopped`/`SessionCreated`/`Error` relay
  verbatim to the downlink `Carrier` (identity IR = the meter/audit tap).
- **Layer 4 usage** (`session.rs:137-149`): the metering step, below.

### 1.4 METER via the COST-LEASE + HARD-CLOSE on exhaustion

On `IrServerEvent::Usage(u)` (`session.rs:137`): `pricing.price(&u)` folds the audio/text token
classes into one already-priced nanodollar increment (saturating, `metering.rs:102-114` — core prices
nothing), then `lease.settle(nanos)` (`metering.rs:59`) accrues and reads back `LeaseState`. If
`must_close()` (`Exhausted` or fail-closed `Refused`/fault, `metering.rs:46-52`): write
`ResponseCancel` upstream and set `out.close` → `carrier.hard_close()` (`session.rs:244-246`). The
`Carrier` (`carrier.rs`) latches closed once (`hard_close :65`), drops all later downlink
(`send_downlink :82`), and wakes the supervisor parked on `carrier.closed()` (`:94`) — which aborts
the `serve_messages` task and drops the upstream socket. This is the one thing post-hoc metering
structurally cannot do (design §3.3).

### 1.5 CLOSE — reclaim

Teardown: `handle.settle_terminal(now)` then `handle.close()` (owner-gated, terminal-only eviction,
`runtime/scope.rs:180-198`). The **lease** is reclaimed by `HostLease::Drop` closing it host-side
(`metering.rs:251-258`, `cost_close`) — NOT by a `SessionScope::Drop` (substrate `SessionScope`
embeds engine+owner+id only, no arena/lease; see risk R2). The durable rows survive for boot-rehydrate.

---

## 2. PlaneDecl hooks + the neutral pump/session/lease seams

### 2.1 What is wired today

`PLANE_DECL` (`crates/busbar-voice/src/lib.rs:84`) declares identity (`key:"voice"`,
`config_section:"streams"`, `audit_kind:"voice_session"`, one wire format `openai_realtime`) and wires
exactly ONE runtime hook:

- **`build_runtime`** = `VOICE_BUILD_RUNTIME` (`lib.rs:54-59,132`) → `runtime::build_runtime`
  (`runtime/mod.rs:94`), which builds the per-generation `VoiceRuntime` (`runtime/mod.rs:35` — the
  type-erased `Arc<dyn Any>` slot read back via `EngineHost::plane_slot` under the neutral
  `runtime_slot_key("voice:runtime")`, `plane_host/mod.rs:208`). It binds `LocalMeteringPort` (dev) or,
  via the sibling `build_runtime_hosted` (`runtime/mod.rs:114`), `HostMeteringPort` over the real
  `MeteringHost` (prod D2 money hop).

Every other hook is `None` (`lib.rs:106-135`): `build`, `hydrate`, `start`, `parse_section`,
`default_section`, `routes`, `admin_routes`.

### 2.2 What each remaining hook must add (the mount)

- **`start`** [GAP]: the arrival/accept mount. On boot it must (i) register the WS-upgrade arrival kind
  (design §4.2 — a substrate arrival that populates `SessionScope`, NOT an axum `on_upgrade` from a
  route, which would bypass the gauntlet), and (ii) for each accepted session call
  `run_gauntlet_session` (§1.1) then spawn `serve_messages` over the two `DuplexPlane` legs. The
  provider socket is dialed by `dial_provider` (`topology/mod.rs:49`); the client socket arrives via
  the arrival kind. Supervisor parks on `carrier.closed()`.
- **`build`** [GAP]: constructs the config-conditional dispatch slot from the parsed `streams:` section
  (which upstreams/models a session may open — the destination `verify_destination` judges). Needs
  `parse_section`/`default_section` first (the config-grammar slice, currently `None`, `lib.rs:124-135`).
- **`hydrate`** [GAP]: boot-rehydrate durable session rows from the `DurableHandleEngine` exactly as
  A2A's `taskstore::restore_from_store` does — reload active `voice_session` handles, re-verify the
  audit chain, re-park them; a lease that cannot be re-reserved fails the session closed.

### 2.3 The neutral seams the hooks compose (no core edit)

| Seam | Neutral type | Owner | Cite |
|---|---|---|---|
| **pump** | `serve_messages` / `DuplexPlane` / `DuplexHandle` | busbar-substrate | `byte_duplex.rs:318,81,99` |
| **transport** | `Transport::WebSocket` → `upstream_wire()==Duplex` → `duplex_ws::dial` | busbar-substrate | `topology/mod.rs:61-64` |
| **session** | `SessionScope` (owned engine+owner+id) | busbar-substrate | `plane_host/scope.rs:382` |
| **lease** | `MeteringHost` (`cost_reserve/settle/settled/close`) → `HostMeteringPort` | substrate/plane | `metering.rs:188-258` |
| **audit** | `journal_append_scoped("session-<id>", …)` per turn | busbar-plugin host slot | design §3.2 |
| **re-mint** | `LiveHostFactory` per-frame (budget/key rotation seen next frame) | busbar-substrate | `plane_host/mod.rs:223` |

The open entry that ties them: `run_gauntlet_session` (§1.1) → `begin_session` (`topology/mod.rs:106`)
→ `serve_messages`. All plane nouns (`openai_realtime`, `input_audio_buffer`, `barge_in`) stay in
busbar-voice; core moves opaque framed bytes only.

---

## 3. The `GauntletPlane::drive` witness test (anti-foreclosure)

**Why.** Audit D rank-2 and audit B seam-2: `run_gauntlet`/`GauntletPlane` return one `Response`
(`plane_host/mod.rs:175,185`); the session sibling is append-safe ONLY because they stay a **free fn +
trait** — nothing inlines them and the one-`Response` return is not the *only* session shape. This is
D3, "confirmed NOT currently foreclosed" but guarded by structure alone. A 1.6.0 "simplification" that
inlined `run_gauntlet` into `EngineHost::run_gauntlet`'s body, or that made `drive` return `()` /
folded verify into drive, would silently foreclose `run_gauntlet_session`. Add a witness that fails to
compile the moment that happens — modeled on the existing const-block witness
`_assert_engine_host_is_sum_of_slices` (`plane_host/mod.rs`, the M4 god-trait guard).

**Where.** `crates/busbar-substrate/src/plane_host/mod.rs`, a `#[cfg(test)]`/const witness beside the
gauntlet defs (or `crates/busbar-substrate/src/plane_host/tests/`). Two parts:

```rust
// (A) COMPILE-TIME SHAPE WITNESS — free fn + trait, drive consumes self, verify is &self-cheap.
//     Any inline/reshape that removes the free fn, the Box<dyn GauntletPlane> param, or the
//     self: Box<Self>-by-move stops this compiling.
const _: () = {
    // run_gauntlet stays a FREE fn taking an owned Box<dyn GauntletPlane> and returning Response.
    let _f: fn(GauntletRequest<'_>, Box<dyn GauntletPlane + '_>)
        -> std::pin::Pin<Box<dyn std::future::Future<Output = axum::response::Response> + '_>>
        = |req, plane| Box::pin(run_gauntlet(req, plane));
    // verify_destination is &self (non-consuming) so the session sibling can reuse it for the open
    // pass WITHOUT calling the consuming drive.
    fn _verify_is_borrowing<P: GauntletPlane>(p: &P, r: &GauntletRequest<'_>) -> VerifyOutcome {
        p.verify_destination(r)
    }
};

// (B) BEHAVIORAL WITNESS — a session-returning entry can be built BESIDE drive, proving the
//     one-Response shape is not the only shape. This IS the foreclosure canary: it exercises the
//     exact reuse run_gauntlet_session needs (verify_destination for open, no drive), returning a
//     SessionScope instead of a Response.
#[tokio::test]
async fn session_sibling_can_be_built_beside_drive() {
    struct DummyPlane;                         // verify_destination -> Proceed; drive -> 200
    // Proceed path: reuse verify, then build an OWNED SessionScope (the sibling's return) — NOT drive.
    let scope: Result<SessionScope, axum::response::Response> =
        match DummyPlane.verify_destination(&req) {
            VerifyOutcome::Refuse(r) => Err(r),
            VerifyOutcome::Proceed  => Ok(SessionScope::new(engine, "owner", "sess-1")),
        };
    assert!(scope.is_ok());
    // AND the once-through shape still holds unchanged for a non-session plane:
    let resp = run_gauntlet(req2, Box::new(DummyPlane)).await;
    assert_eq!(resp.status(), 200);
}
```

Part (A) is the cheap always-on guard (const block, no runtime); part (B) is the explicit canary that
a `SessionScope`-returning sibling coexists with `drive`. Keep both in the release gate beside the D1
`WorkItem`-carrier witness (`workitem.rs:18-19`) — the audit's "keep the witness" action for D3.

---

## 4. Stub vs net-new

**Already built (green behind `runtime` feature) — do NOT rebuild:**
- `SessionCore` decode+act core, both legs, all four IR layers — `runtime/session.rs` (full).
- `Carrier` hard-close latch + downlink — `runtime/carrier.rs` (full).
- D2 lease port: `MeteringLease`/`MeteringPort`/`Pricing`/`LocalLease`/`HostLease`/`HostMeteringPort`
  over the shipped minor-19 `MeteringHost` seam — `runtime/metering.rs` (full, incl. `Drop` reclaim).
- Durable session binding over `SessionScope` — `runtime/scope.rs` (full, owner anti-enumeration).
- `begin_session` open (lease + durable + core) — `topology/mod.rs:106`.
- `dial_provider` net-guarded `Transport::WebSocket` egress — `topology/mod.rs:49`.
- The two topologies (webrtc sideband, telephony proxy) — `topology/webrtc.rs`, `telephony.rs`.
- `build_runtime` / `build_runtime_hosted` per-generation slot — `runtime/mod.rs:94,114`.
- Tests: pricing, lease exhaustion, host-lease cap, pump relay+close, tool interleaving, barge-in,
  scope reattach/foreign-owner — `runtime/tests.rs`.

**Net-new (this slice):**
1. `run_gauntlet_session` substrate sibling (§1.1) — routes open through `verify_destination` before
   the reserve; **not present** (`grep run_gauntlet_session` = only doc/comment hits).
2. WS-upgrade **arrival kind** populating `SessionScope` (design §4.2) — no `on_upgrade` in tree.
3. `PlaneDecl` **`start`** hook (mount: arrival + accept-loop + `serve_messages` spawn + supervisor).
4. `PlaneDecl` **`build`/`parse_section`/`default_section`/`hydrate`** — the `streams:` config grammar
   + destination table + boot-rehydrate (currently `None`, `lib.rs:106-135`).
5. The **`GauntletPlane::drive` witness** (§3).
6. Per-turn `journal_append_scoped("session-<id>", …)` audit chain call in the meter step (§1.4 wires
   the lease; the audit-tap call at Usage is not yet in `on_server_frame`).

---

## 5. Residual risks

- **R1 [HIGH] — open bypasses the gauntlet today.** `begin_session` (`topology/mod.rs:120`) reserves
  the lease and opens the durable handle but never calls `verify_destination`; a mounted session would
  charge before judging the destination — the exact invariant `run_gauntlet` exists to enforce
  ("nothing may reject after a charge", `plane_host/mod.rs:183`). Until `run_gauntlet_session` (§1.1)
  wraps it, session-open is not one governed pass. Mitigation: land the sibling + route `start` through
  it before the plane is mounted for real (not dev-only).
- **R2 [MEDIUM] — `SessionScope` Drop-reclaim divergence.** Audit B seam-1 recommended `SessionScope`
  embed a `DispatchScope` arena + `impl Drop` to reclaim the pooled socket and finalize the lease. The
  shipped `SessionScope` (`scope.rs:382-391`) embeds engine+owner+id only; lease reclaim rides
  `HostLease::Drop` (`metering.rs:251`) and socket teardown rides the supervisor aborting on
  `carrier.closed()`. This works for the normal path, but an abnormal drop (panic before the supervisor
  arms) relies on `HostLease::Drop` alone for the lease and on `serve_messages` EOF for the socket —
  no single arena guarantees LIFO reclaim. Confirm the panic/cancel path finalizes both, or adopt the
  audit's arena field before the `#[non_exhaustive]` shape is inherited by a second duplex plane.
- **R3 [MEDIUM] — WS-arrival `Any` payload is a dual-compile TypeId trap.** Audit D rank-1: the
  upgraded-socket handle rides `ArrivalCtx(Box<dyn Any>)` and is downcast plane-side; if voice boxes a
  plane- or core-owned handle type the downcast silently returns `None` across the two core instances
  in the witness harness (runtime-only failure). The arrival-kind payload (net-new #2) MUST be a
  substrate-owned newtype. Design it substrate-side before `start` wires the arrival.
