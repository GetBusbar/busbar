# Money-path playbook — `run_gauntlet_session` (D2 verify-before-charge for the duplex plane)

**Status: STOP-condition. BLOCKS M5 boot (see bottom).**
**Scope: design only. No code changed by this document.**

## 0. The finding (verified against real code)

- `run_gauntlet` is the one shared open pass every request plane rides:
  `crates/busbar-substrate/src/plane_host/mod.rs:185`. It is a **free fn** —
  `run_gauntlet(req: GauntletRequest, plane: Box<dyn GauntletPlane>) -> axum::response::Response`
  — whose whole body is the verify-before-charge ORDER:
  ```rust
  match plane.verify_destination(&req) {          // STAGE 2, sync, pre-admission
      VerifyOutcome::Refuse(resp) => resp,          // refused BEFORE any charge
      VerifyOutcome::Proceed      => plane.drive(req).await,  // STAGES 4+5, plane engine
  }
  ```
- `GauntletPlane` (`plane_host/mod.rs:170`) is a **trait**: `verify_destination` (sync, stage 2)
  + `drive(self: Box<Self>) -> Response` (async, stages 4+5, admission→route→meter→finish).
- The LLM open pass proves the shape (`crates/busbar-llm/src/native_ingress.rs`):
  `verify_destination` → `host.destination_guard(...)` (200); `drive` →
  `host.admission_door(...)` (the ONE budget-admission door; on `Err` nothing was charged, 244–250)
  → candidate select → `forward_with_pool_parsed` (pool/breaker admit + egress) → `finish_admitted`.
- The voice open path **skips all of this**. `begin_session`
  (`crates/busbar-voice/src/topology/mod.rs:106`) does only: `rt.open_lease(...)` (D2
  `cost_reserve`, `runtime/mod.rs:72` → `MeteringPort::reserve`, `runtime/metering.rs:72`) →
  `bind_session` + `handle.open(now)` (durable genesis) → assemble `SessionCore`. There is **no
  `verify_destination`, no governance admit, no pool/breaker admit** before the first audio byte
  streams.
- `run_gauntlet_session` **does not exist** (`grep run_gauntlet_session` = 0 matches in `crates/`;
  the only references are the reserved-witness comments in `busbar-voice/src/lib.rs:105` and the
  seam-audit docs). Audit D2/D3 (`docs/design/plane4-seam-audit-D-abi.md:122`, `:651`) require it
  as an **append-only sibling** guarded by a witness test.

---

## 1. The concrete `run_gauntlet_session` design

An **append-only** sibling in `busbar-substrate/src/plane_host/mod.rs`, beside (never replacing)
`run_gauntlet` + `GauntletPlane`. It reuses the identical stage-2 verify, then runs a **session-open
admission** that mirrors `drive`'s open pass but hands off to the per-frame pump instead of driving
one request-response.

### 1a. New neutral seam (pure add — no existing signature changes)

```rust
/// A plane's contribution to the SESSION gauntlet: the SAME stage-2 destination verify as
/// `GauntletPlane`, then a session-OPEN admission that returns a live `SessionScope` handle
/// instead of one `Response`. Sibling to `GauntletPlane`; no method of that trait changes.
#[async_trait::async_trait]
pub trait GauntletSessionPlane: Send + Sync {
    /// STAGE 2 — byte-identical to `GauntletPlane::verify_destination`: pre-admission destination
    /// guard, sync, BEFORE any reserve. `Refuse` carries the plane's own finished rejection.
    fn verify_destination(&self, req: &GauntletRequest<'_>) -> VerifyOutcome;

    /// STAGES 3+4 (open only) — govern-admit + pool/breaker-admit + cost_reserve, then bind the
    /// durable handle and return the populated `SessionScope`. Runs ONCE at open; the per-frame
    /// metering loop settles against the reserved lease held in the returned scope. On any
    /// admission refusal returns the plane's own finished `Response` (fail closed) and reserves
    /// nothing.
    async fn open_session(self: Box<Self>, req: GauntletRequest<'_>)
        -> Result<SessionScope, axum::response::Response>;
}

/// THE SHARED SESSION-OPEN SEQUENCE — the session twin of `run_gauntlet`. Same verify-before-charge
/// ORDER; the ONLY difference is the terminal shape (a live `SessionScope`, not a `Response`).
pub async fn run_gauntlet_session(
    req: GauntletRequest<'_>,
    plane: Box<dyn GauntletSessionPlane + '_>,
) -> Result<SessionScope, axum::response::Response> {
    match plane.verify_destination(&req) {
        VerifyOutcome::Refuse(resp) => Err(resp),   // refused BEFORE any reserve — one-way door
        VerifyOutcome::Proceed      => plane.open_session(req).await,
    }
}
```

`SessionScope` is the already-reserved empty `#[non_exhaustive]` stub
(`crates/busbar-substrate/src/plane_host/scope.rs:366`, doc: *"the riders that add a
duplex/session plane wire this out"*). Plane 4 is that rider; it wires out the two `PipeId`s, the
reserved `MeteringLease`, the journal scope string `"session-<id>"`, and the `CallRef` table.

### 1b. What the open pass runs (mirror of `drive`'s open, in the SAME order)

1. **Destination verify (stage 2, sync, pre-admission).** Voice's plane resolves which upstream /
   Realtime model the session may talk to and judges it BEFORE any reserve — identical role to the
   LLM `destination_guard`. `Refuse` ⇒ `Err(resp)`, nothing charged.
2. **Governance admit + pool/breaker admit (stage 3+4).** The session claims its
   `scope_kinds = ["session"]` grant (`busbar-voice/src/lib.rs:98`) through the host
   `govern_admit` seam and wins the upstream pool/breaker probe (`breaker_admit`, `BreakerHost`,
   `plane_host/mod.rs`) — so a tripped upstream refuses the session at open, not mid-audio. RAII
   grant registered in the scope's arena (`DispatchScope::register_pipe`, `scope.rs:302`).
3. **Cost reserve (D2 `cost_reserve`).** `MeteringPort::reserve(estimate, fee, cap)`
   (`runtime/metering.rs:72`) debits a coarse over-estimate for the session cap. `None` ⇒ fail
   closed (`StartError::BudgetRefused` today) ⇒ `Err(resp)`.
4. **Durable open.** `bind_session` + `handle.open(now)` (genesis) — only AFTER 1–3 succeed.
5. **Hand off.** Return the `SessionScope` carrying the live `MeteringLease`. The per-frame loop
   (§3.2 of `plane4-duplex-session.md`) settles exact increments via `MeteringLease::settle`
   (D2 `cost_settle`, `runtime/metering.rs:59`); on `LeaseState::Exhausted`/`Refused`
   (`must_close() == true`) it hard-closes the carrier — the one thing post-hoc metering cannot do.

The metering loop is UNCHANGED by this document; `run_gauntlet_session` only guarantees the lease is
**reserved and the destination verified before it ever runs**.

---

## 2. Where `begin_session` must call it (the one-way door)

`begin_session` (`crates/busbar-voice/src/topology/mod.rs:106`) is the single choke point both
topologies funnel through (`topology/telephony.rs:82`, `topology/webrtc.rs`). The invariant:

> **Budget reserved AND destination verified BEFORE the first byte streams.**

Today `begin_session` reserves the lease but performs **no verify and no admission**, then returns a
`SessionCore` the carrier immediately pumps. That is the leak: the first audio frame can flow to an
unverified/unadmitted upstream.

The fix routes the open through the sibling, at the TOP of `begin_session`, before `open_lease` /
`bind_session`:

```
begin_session:
  scope = run_gauntlet_session(GauntletRequest{ gov, destination: upstream_model, ... },
                               Box::new(VoiceOpenPlane{ rt, budget, ... })).await
            .map_err(StartError::from_response)?;   // refuse ⇒ session never opens, nothing charged
  // scope now HOLDS the reserved lease + durable handle; SessionCore is built FROM scope's lease,
  // not from a second bare open_lease.
```

Ordering is load-bearing and one-way: verify (2) → admit (3+4) → reserve (D2) → durable open →
build core → *first pump*. No pump half (`TelephonyProxy::run` / webrtc `run`) may bind a socket
before `run_gauntlet_session` returns `Ok`. `begin_session` returning `Err` ⇒ zero bytes, zero
charge, zero durable record — fail closed, exactly the current `BudgetRefused` discipline extended
to cover verify + admission.

---

## 3. The `GauntletPlane::drive` one-Response witness test (audit D2/D3)

D3 (`plane4-seam-audit-D-abi.md:143`, `:292`, `:651`) is currently satisfied *by structure, not by a
test*. A 1.6.0 "simplification" that inlined `run_gauntlet` or made the one-`Response` return the
**only** session entry would foreclose the sibling. Add a compile-plus-behavior witness in
`busbar-substrate` (e.g. `plane_host/gauntlet_witness_tests.rs`):

```rust
// WITNESS D3 — the one-Response gauntlet and the session sibling are DISTINCT, coexisting seams.
// If a refactor inlines run_gauntlet, deletes GauntletPlane, or collapses the two terminal shapes
// into one, THIS FILE STOPS COMPILING — the money-path stop-condition fires in CI, not in prod.

#[test]
fn run_gauntlet_still_returns_exactly_one_response() {
    // Type-level lock: the request-plane seam yields ONE axum Response (byte-identical open+drive).
    fn _shape(f: fn(GauntletRequest, Box<dyn GauntletPlane>)
                    -> std::pin::Pin<Box<dyn Future<Output = axum::response::Response>>>) {}
    // A refuse plane returns its own finished Response verbatim — no charge, no drive reached.
    let refused = block_on(run_gauntlet(req(), Box::new(RefuseAllPlane)));
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);   // Refuse arm, pre-charge
    assert!(!DROVE.load(Relaxed), "verify=Refuse must NOT reach drive");
}

#[test]
fn run_gauntlet_session_is_a_live_sibling_not_a_response() {
    // Type-level lock: the SESSION seam yields a SessionScope, NOT a Response. This assertion is
    // what an "inline both into one entry" refactor cannot satisfy.
    fn _shape(f: fn(GauntletRequest, Box<dyn GauntletSessionPlane>)
                    -> std::pin::Pin<Box<dyn Future<Output = Result<SessionScope,
                                                                     axum::response::Response>>>>) {}
    // Verify-before-reserve ORDER: a Refuse plane reserves NOTHING.
    let out = block_on(run_gauntlet_session(req(), Box::new(RefuseThenPanicReservePlane)));
    assert!(out.is_err(), "Refuse must short-circuit before open_session/reserve");
    // RefuseThenPanicReservePlane panics if open_session runs — proving reserve never happened.
}
```

Key assertions the witness pins: (a) `run_gauntlet` (free fn) and `GauntletPlane` (trait) still
exist with their exact shapes; (b) `run_gauntlet_session` / `GauntletSessionPlane` exist as
siblings; (c) the two terminal shapes differ (`Response` vs `Result<SessionScope, Response>`) — so
they cannot be collapsed into one; (d) both enforce verify-strictly-before-charge (a `Refuse` plane
whose admission arm panics proves the reserve is unreachable on refusal).

---

## 4. How this stays plane-neutral

- **Core exposes the seam; it names no voice noun.** `run_gauntlet_session` + `GauntletSessionPlane`
  + the `SessionScope` wire-out live in `busbar-substrate` (the same crate as `run_gauntlet`), using
  the neutral `GauntletRequest` (`destination` is an opaque `&str` the plane spells) and the neutral
  `SessionScope`. Substrate mentions no `voice`/`streams`/`websocket` in the decision path — exactly
  as `run_gauntlet` names no MCP/A2A/LLM type.
- **Voice calls it.** `busbar-voice` implements `GauntletSessionPlane` for its own open plane
  (resolving the upstream Realtime model as `destination`, wrapping `VoiceRuntime`'s
  `open_lease`/`bind_session`), and `begin_session` invokes `run_gauntlet_session`. The plane owns
  admission/reserve/durable-open bytes; substrate owns only the verify-before-charge ORDER — the same
  split the LLM/MCP/A2A request planes already ride (`native_ingress.rs`, `mcp/method.rs:1234`,
  `a2a/receive.rs:834`). No `install_*` and no new `PlaneDecl` field are needed (audit D §(b)/(c));
  duplex-ness is carried by transport + arrival kind + `SessionScope`, not by decl fields.

---

## 5. Money-path byte-identity constraint (pure append)

- **`run_gauntlet`'s behavior must not change by a single byte.** `run_gauntlet_session` is an
  ADD beside it — a new free fn + a new trait. The existing free fn body, `GauntletPlane`'s two
  method signatures, and every request plane's `verify_destination`/`drive` bytes stay identical.
  No method is added to `GauntletPlane` (that would touch every impl); the session capability is a
  **separate trait**, so the LLM/MCP/A2A one-`Response` path recompiles unchanged.
- **No shared mutable state between the two entries.** `run_gauntlet_session` reserves through the
  same D2 `cost_reserve` slot the request path uses, but the request path's `admission_door` /
  `meter_charge` accounting is untouched; single-accounting per correlation id is preserved.
- **Fail-closed parity.** Refusal on either entry charges nothing (request: `admission_door` `Err`
  before charge; session: `Refuse`/`reserve == None` before durable open). The witness (§3) makes a
  regression that changes `run_gauntlet`'s one-`Response` shape a compile failure.

---

## Summary (≤8 lines)

1. `run_gauntlet` (free fn, `plane_host/mod.rs:185`) is the one verify-before-charge open pass; the
   session sibling `run_gauntlet_session` returning `Result<SessionScope, Response>` does not exist.
2. Voice `begin_session` (`topology/mod.rs:106`) opens the D2 lease + durable handle with NO verify
   and NO admission — the first audio byte can stream to an unverified/unadmitted upstream.
3. Fix: append `GauntletSessionPlane` + `run_gauntlet_session` in `busbar-substrate` (pure add, no
   existing signature touched); it runs verify → govern/breaker admit → `cost_reserve` → durable
   open, then hands off `SessionScope` to the per-frame settle loop.
4. `begin_session` must call it at the top: budget reserved AND destination verified BEFORE any pump
   binds a socket (one-way door; refusal ⇒ zero bytes, zero charge).
5. Guard with a D3 witness test so a 1.6.0 simplification can't inline/foreclose the sibling.

**File:** `docs/design/playbook/gauntlet-session.md`

## Does this BLOCK M5 boot? YES.

M5 boots the voice/duplex plane onto the live money hop (`build_runtime_hosted`,
`runtime/metering.rs`, binds the REAL host lease). Booting `begin_session` as-is puts a session on a
real caller budget that streams billable audio to an upstream **before** any destination verify or
governance/breaker admit — a charge-after-stream leak with no mid-session hard-stop guarantee at
open. The D2 invariant ("one open pass + N metered frames", reserve-before-first-byte) is the
plane's marquee guarantee; it is unmet until `run_gauntlet_session` exists AND `begin_session` routes
through it AND the D3 witness pins the seam. This is a STOP-condition: M5 must not boot the hosted
voice runtime until all three land.

## Top 3 risks

1. **Foreclosure by "simplification" (D3).** Without the witness, a 1.6.0 cleanup that inlines
   `run_gauntlet` or makes the one-`Response` the only session entry silently reshapes the append
   into a modification and reopens the leak. Mitigation: land the §3 witness with the sibling.
2. **Ordering regression at the call site.** If any pump half binds a socket before
   `run_gauntlet_session` returns `Ok` (e.g. `TelephonyProxy::run` racing the open), bytes flow
   pre-verify/pre-reserve. Mitigation: `begin_session` returns only a scope whose lease is already
   reserved; no socket is bound until `Ok`.
3. **D2 lease reserved-but-not-hosted.** Today `build_runtime` binds `LocalMeteringPort`
   (`runtime/metering.rs`), so a dev boot reserves against an in-process cell, not the caller's real
   grant; only `build_runtime_hosted` binds the real host lease. Booting M5 on the local port would
   make the reserve cosmetic. Mitigation: M5 must compose via `build_runtime_hosted` AND route open
   through `run_gauntlet_session`.
