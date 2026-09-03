# Session-Drop & WS-Arrival one-way-door seams

Two coupled HIGH seams audited on branch `integration/plane-extraction`. Both were
reported with contradictory current-state claims; this doc RESOLVES each against the
code on THIS branch, gives the minimal freeze-safe change, the witness test, and the
M5-boot verdict.

---

## SEAM 1 — SessionScope Drop / D2 lease refund & pipe reclaim

### Current true state (resolving the contradiction)

`SessionScope` on THIS branch is the **durable-binding shape, NOT empty**:

- `crates/busbar-substrate/src/plane_host/scope.rs:382-391`
  ```rust
  pub struct SessionScope {
      engine: Arc<DurableHandleEngine>,   // 384
      owner: String,                      // 388
      id: String,                         // 391
  }
  ```
  It is documented (scope.rs:366-381) as a *thin neutral binding* that "NAMES no
  engine mechanic of its own"; every method delegates to `DurableHandleEngine`
  (`get`/`mutate`/`close` at :452/:461/:476). There is **no owned `DispatchScope`
  arena and no `impl Drop`** (`grep 'impl Drop for SessionScope'` → none).

- The "one agent says `{}` empty" report is **stale/wrong** for this branch.
  The "`{engine,owner,id}` durable binding" report is **correct**.

The D2 reserve is **NOT owned by `SessionScope`.** The audit framing ("SessionScope
leaks the reserve because it has no arena+Drop") is mis-aimed at the wrong type. The
lease's real ownership chain:

- `CostHold` (`crates/busbar-core/src/plane/cost.rs:334-403`): a by-value accounting
  object, `reserved/settled/cap`. `finalize(self)` (:396) is a **by-value consume, no
  `Drop`** — correct as flagged.
- Host registry: `crates/busbar-core/src/plane_host/cost_host.rs:41` `static LEASES:
  Mutex<Option<HashMap<u64, CostHold>>>`. `reserve_lease` (:78) inserts a `CostHold`;
  `close_lease` (:115-119) `remove`s it and calls `finalize()` — **but discards
  `Settlement.refund`, returning only `ledgered_total`.**
- Plane-side handle: `HostLease` (`crates/busbar-voice/src/runtime/metering.rs:225`)
  holds `Arc<dyn MeteringHost>` + `CostLeaseId`. **`HostLease::drop → cost_close`
  already exists** (metering.rs:251-257), idempotent/fire-and-forget.
- Owner of the lease: `SessionCore.lease: Box<dyn MeteringLease>`
  (`crates/busbar-voice/src/runtime/session.rs:75`), and `SessionCore` is shared as
  `Arc<SessionCore>` (session.rs:287, telephony.rs:48).

**So a RAII-via-`HostLease` refund path already exists** — `cost_close` fires when the
last `Arc<SessionCore>` drops. The leak is therefore **narrower than reported but
real**, in two spots:

1. **Refcount-gated close vs. detached tasks (the true residual leak).** The neutral
   pump `serve_messages`
   (`crates/busbar-substrate/src/ingress/byte_duplex.rs:246`) `tokio::spawn`s one
   detached handler per inbound frame, each holding `Arc<Self>` → `Arc<SessionCore>`.
   The pump stores `abort_handle`s (:254) and aborts the remainder at its OWN EOF
   (:257-267). But on the **hard-close race** — `tokio::select!{ serves => …,
   carrier.closed() => … }` in `telephony.rs:179-182` — the losing `serves` future is
   **dropped**, dropping the stored abort handles **without calling `.abort()`**, so a
   handler parked at an `.await` (a slow `tools.execute`, a blocked `out.emit`) keeps
   an `Arc<SessionCore>` alive detached. `drop(core)` (telephony.rs:187) then does NOT
   reach zero → `HostLease::drop` never runs → the `LEASES` entry (and, once a real
   budget cell is wired, the reserve) **leaks.** This is exactly the "parked-at-await"
   hole `DispatchScope` was built for (scope.rs:26-30), reappearing at the session
   layer because session ownership is spread across detached tasks.
2. **Discarded refund.** Even the clean path throws `Settlement.refund` away
   (cost_host.rs:118). Harmless *today* (no external budget cell is debited — the
   `CostHold` is self-contained), but it silently no-ops the refund the moment a real
   grant cell is wired.

Pipe reclaim (the provider WSS): `dial`'s two detached tasks
(`crates/busbar-substrate/src/egress/duplex_ws.rs:207,229`) end when their channels
drop; the writer sends a best-effort `close`. Same refcount dependency as the lease,
lower stakes (the OS eventually resets the TCP).

### Concrete minimal change

**Do NOT add an arena/lease/`Drop` to `SessionScope`.** Give the D2 lease a
**by-value close guard the topology owns**, so `cost_close` fires deterministically on
every exit of `run()` (EOF, hard-close race, OR a panic unwinding through it),
independent of stray detached `Arc<SessionCore>` clones:

- Split the metering handle into (a) a **settle handle** kept in `SessionCore`
  (`Arc<dyn MeteringHost>` + `Copy` `CostLeaseId`, close-less) used by per-frame
  `settle()`, and (b) a **`LeaseCloseGuard`** (owns the same `Arc<dyn MeteringHost>` +
  `CostLeaseId`, `impl Drop → cost_close`) stored **by value** in `TelephonyProxy` /
  the webrtc proxy and moved into `run()`'s stack frame. `run()` is consumed `self`,
  so the guard drops on any return path. `close_lease` idempotency (cost_host.rs:113)
  makes a redundant close from a lingering `HostLease` harmless.
- Fix `close_lease` to **apply `Settlement.refund`** (once a budget cell exists) rather
  than discard it — cost_host.rs:115-119. Until the cell is wired, at minimum add a
  doc-comment + test asserting the refund is computed, so the drop is not silent.

All of this lives in **`busbar-voice` + `busbar-core` cost_host**, NOT in the frozen
`SessionScope` ABI.

### Freeze / one-way-door risk

The one-way door is the `SessionScope` **ABI-freeze: its first field set is
permanent.** It is already `{engine, owner, id}`. **Adding an owned `DispatchScope`
arena + `Drop` to it would freeze the WRONG shape** — it conflates the connection-
lifetime *durable binding* (whose reclaim is the engine's retention sweep,
`abandon_secs=3600`, scope.rs docs) with the *resource arena* (`DispatchScope`, which
already exists as the leak keystone). **Verdict: freeze `SessionScope` as
`{engine,owner,id}`; put the lease RAII in the voice layer.** The guard-split above
needs **zero** new `SessionScope` fields, so freezing now is safe.

### Witness test to add

`crates/busbar-voice/src/runtime/tests.rs`: drive a session to the **hard-close race**
with a handler deliberately parked at `.await`, then assert (via a mock `MeteringHost`
counting `cost_close`) that `cost_close` fired **exactly once** when `run()` returned,
BEFORE the parked task is released. Red today (guard absent → close is refcount-gated →
0 closes while parked); green after the by-value guard. Add a `close_lease` unit test
asserting `finalize().refund == reserved − settled`.

### Blocks M5 boot?

**NO.** Voice runtime is feature-gated `runtime` (OFF by default, mod.rs:4); the
default `build_runtime` binds `LocalMeteringPort` (mod.rs:104). The leak is a
live-session resource/correctness issue on a dev-only path, not a boot wiring failure.
The **only M5-relevant action is the freeze decision** — ratify `SessionScope` as
`{engine,owner,id}` and keep the lease RAII out of it.

---

## SEAM 2 — A1/D1 WS-arrival substrate-owned payload newtype

### Current true state

**Already fixed on this branch** (App-retype "WEDGE 3 — THE FLIP", documented at
`crates/busbar-substrate/src/ingress/arrival.rs:51-69`).

- `ArrivalCtx` is the **substrate-owned** opaque newtype over `Box<dyn Any + Send +
  Sync>` — `crates/busbar-substrate/src/ingress/arrival.rs:35-49`.
- The boxed payload is the **substrate-owned neutral `ArrivalPayload`**
  (arrival.rs:61-69: `host: Arc<dyn EngineHost>`, `gov: PlaneRequestCtx`,
  `caller_token`) — no longer core's private `Arc<App>` payload.
- Core re-exports it at the historical path
  (`crates/busbar-core/src/ingress/arrival_host.rs:24`: `pub use
  busbar_substrate::ingress::arrival::ArrivalPayload;`), so all **core** box sites
  (`dispatch.rs:98,122`; `ingress/mod.rs:838`; `plane_host/mod.rs:357`) box the
  **substrate** type.
- The **LLM plane** downcasts to the SAME substrate type
  (`crates/busbar-llm/src/native_ingress.rs:654-656`
  `ctx.downcast_ref::<busbar_substrate::ingress::arrival::ArrivalPayload>()`), as does
  core's own host impl (arrival_host.rs:26-28).

Because the boxed type and the downcast type are **one type, defined in the once-
compiled substrate crate**, the `TypeId` matches across the core↔llm boundary and
across a dual-compiled (two-core-instance) build. The `.expect()` at arrival_host.rs:28
/ native_ingress.rs:656 cannot fire from the dual-compile hazard. The "core-private
type → `downcast_ref` returns `None` → runtime panic" failure the audit describes was
the **pre-FLIP** state; it is closed.

### Concrete minimal change

**None required for the mechanism.** Only a **guard against regression**: keep the
invariant "no core-private type is ever boxed into `ArrivalCtx`." All four core box
sites already box the re-exported substrate type; the risk is a future site boxing a
core-local struct.

### Freeze / one-way-door risk

`ArrivalPayload`'s field set is the neutral ABI both crates downcast — adding/reordering
fields is a coordinated change. The door is: **the payload type must stay substrate-
owned.** Reverting it to a core-private type (or having any crate box its own local
type) silently re-opens the dual-compile panic. Low risk while the re-export at
arrival_host.rs:24 is the single spelling.

### Witness test to add

A cross-crate test that boxes an `ArrivalPayload` via core's construction path and
downcasts it through the LLM-plane `payload(&ctx)` helper, asserting `Some` (not the
`.expect()` panic). Optionally a compile-time/grep guard in CI asserting no
`ArrivalCtx::new(` argument names a `busbar_core::`-local type. Guards the FLIP against
regression rather than proving a currently-broken path.

### Blocks M5 boot?

**NO.** Already closed. Were it still core-private, it would panic at RUNTIME on the
first path-model/body-model arrival (not at boot) — blocking any M5 test that exercises
an arrival, but not boot wiring itself. As shipped, no block.

---

## One-way-door summary

| Seam | State on this branch | Blocks M5 boot | Door to ratify |
|---|---|---|---|
| 1 — SessionScope / D2 refund | `{engine,owner,id}`, no arena/Drop; RAII-via-`HostLease` exists but is refcount-gated → leaks on the parked-at-await hard-close race; refund discarded | **No** (dev-only feature; local port default) | Freeze `SessionScope` as `{engine,owner,id}`; lease RAII goes in voice as a by-value `LeaseCloseGuard`, NOT as a SessionScope field |
| 2 — WS-arrival payload | Already substrate-owned (`ArrivalCtx`/`ArrivalPayload`); downcast crosses the plane boundary safely | **No** (already closed) | Keep `ArrivalPayload` substrate-owned; never box a core-private type into `ArrivalCtx` |
