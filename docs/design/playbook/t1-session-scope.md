# T1 — the `SessionScope` wire seam (playbook)

Status: **DESIGN.** No code changed by this doc. Read-only pass over the tree at branch
`integration/plane-extraction` (worktree `config-seam-work`). Companion to the authoritative design
`docs/design/plane4-duplex-session.md` (§3–§5), the plan `plane4-duplex-session-1.6.0-plan.md` (T1),
and the adversarial audits `plane4-seam-audit-B-session.md` (Seam 1) and `-A-transport.md` (Seam 2/1).

**One correction the citations below settle first.** The B/A audits describe `SessionScope` as an
**empty `#[non_exhaustive]` stub** (`plane4-seam-audit-B-session.md:29`) — that was true at their
base commit `e393b9e6`. It is **no longer true in this tree.** The *durable-binding half* has already
landed: substrate's `SessionScope` today is a populated, neutral binding over the lifted
`DurableHandleEngine` (`crates/busbar-substrate/src/plane_host/scope.rs:382-484`), and a voice plane
already consumes it (`crates/busbar-voice/src/runtime/scope.rs:82-199`). What is *still* stubbed is
the **RAII / money-path half** — the arena, the `Drop`, the lease, the pipes. This doc designs that
remaining half onto the shape that shipped, not onto the empty stub the audits assumed.

---

## 1. The concrete `SessionScope` type and how it wires in (neutrally)

### 1a. What exists today (the durable-binding core)

`SessionScope` (`scope.rs:382-391`) is a thin, plane-neutral binding — three fields, no plane noun:

```rust
pub struct SessionScope {
    engine: Arc<DurableHandleEngine>,  // scope.rs:384  process-wide store
    owner: String,                     // scope.rs:388  the ONLY scoped-lookup key
    id: String,                        // scope.rs:390  opaque working-set key
}
```

Every method delegates to the engine the substrate already owns (`scope.rs:370`):
- `new(engine, owner, id)` — pure binding, touches nothing (`scope.rs:400-410`).
- `open(now, bounds, plan, abandon, report_fail)` → `engine.submit(...)` (`scope.rs:433-447`), the
  durable genesis write.
- `get()` → `engine.scoped_get(&owner, &id)` (`scope.rs:452-454`).
- `mutate(plan)` → `engine.scoped_mutate(&owner, &id, plan)` (`scope.rs:461-469`).
- `close()` → prove ownership via `scoped_get`, then `engine.evict_if_terminal(&id)` (`scope.rs:476-483`).

**Durable store wiring.** The store is `DurableHandleEngine`
(`crates/busbar-substrate/src/plane/handle_engine.rs:289`), the T1.8-lifted A2A `taskstore` analog:
`submit` (`:392`) does durable `upsert_record`+`append_record` *before* taking the outer lock;
`scoped_mutate` (`:491`) owner-gates then durable-writes-then-updates-memory; `rehydrate` (`:605`)
reloads the working set on boot; `evict_if_terminal` (`:700`) drops terminal handles leaving durable
rows. `SessionScope` names none of this mechanic — it forwards `(owner, id)` and a caller closure.

**Scope / entitlement wiring — the anti-enumeration contract.** The entitlement seam is the engine's
**owner gate**, carried up to the session surface unchanged (`scope.rs:373-377`): a session bound to
an existing `id` under a *different* `owner` collapses to the exact same indistinguishable refusal
(`HandleDenied::NotYours` on read, `ScopedMutateError::NotYours` on write/close) as a missing handle
— a foreign owner can neither read, resume, nor evict, and cannot tell the handle exists. `owner` is
the principal string; it is *not* itself the `VirtualKey`. The session's *admission* entitlement (may
this principal open a session against this destination at all) is decided **once at open** by the
existing gauntlet (§3 below), not by `SessionScope`; `SessionScope` enforces only the *continuity*
entitlement (only the opening owner may drive/close this live session).

### 1b. The remaining fields the RAII/money half adds (append-only, `#[non_exhaustive]` NOT yet set)

The wire-out completes the connection-lifetime story the taxonomy promises (`scope.rs:12`,
"per-connection state, pooled backend conn, in-flight leases"). Adopting the B-audit fix
(`plane4-seam-audit-B-session.md:53-70`), the full field set is:

```rust
pub struct SessionScope {
    engine: Arc<DurableHandleEngine>,   // EXISTS
    owner: String,                      // EXISTS
    id: String,                         // EXISTS
    arena: DispatchScope,               // NET-NEW  (mirror DurableScope.arena, scope.rs:514)
    client_pipe: PipeId,                // NET-NEW  registered INTO self.arena
    upstream_pipe: PipeId,              // NET-NEW  the pooled backend socket
    lease: Option<CostHold>,            // NET-NEW  the billable reservation (§5)
    journal_scope: String,              // NET-NEW  "session-<id>" audit key
}
// + impl Drop for SessionScope  (NET-NEW): finalize the lease, then arena.reclaim_all()
```

The `arena: DispatchScope` embed is load-bearing, not cosmetic: a `PipeId` is a bare `u64` handle
into a `DispatchScope` registry (`scope.rs:310-319`), so storing `client_pipe`/`upstream_pipe` as
bare ids without the owning arena stores *handles with nothing to reclaim them*
(`plane4-seam-audit-B-session.md:53-61`). Registering the pipes into `self.arena` and giving
`SessionScope` a `Drop` (or leaning on the embedded arena's own `Drop`, `scope.rs:360-364`) makes
"connection closes → pooled socket reclaimed" real. **Mark the struct `#[non_exhaustive]` at this
point** (as `DurableScope` already is, `scope.rs:507`) so any *later* field is append-only.

---

## 2. Stubbed vs net-new (precise, against THIS tree)

| Piece | State today | Cite |
|---|---|---|
| `engine`/`owner`/`id` binding + `new/open/get/mutate/close` | **SHIPPED** (not a stub) | `scope.rs:382-484` |
| `DurableHandleEngine` durable store (submit/mutate/rehydrate/evict) | **SHIPPED** (T1.8 lift) | `handle_engine.rs:289,392,491,605,700` |
| Owner-gated anti-enumeration entitlement | **SHIPPED** | `scope.rs:373-377,452-483` |
| Voice consumer (`SessionHandle`, `VoiceSessionRow`) | **SHIPPED** in `busbar-voice` | `crates/busbar-voice/src/runtime/scope.rs:82-210` |
| `arena: DispatchScope` embed + `impl Drop` | **NET-NEW** | (design here; pattern `scope.rs:507-515,360-364`) |
| `client_pipe`/`upstream_pipe: PipeId` | **NET-NEW** | (`PipeId` exists `scope.rs:310-319`) |
| `lease: CostHold` + Drop-finalize | **NET-NEW** | (`CostHold` exists `busbar-core/.../cost.rs:303-341`) |
| `journal_scope: String` + first append | **NET-NEW** (seam ready) | `hot/host.rs:220` `journal_append_scoped` |
| `#[non_exhaustive]` on `SessionScope` | **NET-NEW** (NOT set yet) | contrast `scope.rs:507` |
| D2 vtable slots (`cost_reserve`/`cost_settle`) | **STUBBED — reserved comment only** | `hot/host.rs:533-536`, `hot/pod.rs:636-638` |
| Duplicate `busbar-core` copy of `SessionScope` | **STALE — should be dead** | `busbar-core/src/plane_host/scope.rs:7`, re-export `:54` |

Net: the *identity/continuity* seam is done; the *resource/money* seam is the T1 build.

---

## 3. How a voice session's scope is minted / bound / verified — without core naming "voice"

Core never sees the word "voice." Three neutral strings do all the work: `owner` (a principal),
`id` (opaque), and the plane's own record kind carried as `Arc<dyn Any>`.

- **MINT (admission + budget reserve).** Session-open is exactly **one** existing `run_gauntlet`
  pass (`plane4-duplex-session.md:357-375`) — `verify_destination`-before-charge, no new decision
  path. The append-only sibling `run_gauntlet_session(req, plane) -> Result<SessionScope, Response>`
  (plan T1.6; `plane4-seam-audit-B-session.md:96-119`) returns the *handle* instead of a `Response`.
  Because `drive(self: Box<Self>)` consumes the plane and returns a `Response`
  (`plane4-seam-audit-B-session.md:104-110`), the opening `cost_reserve` is **net-new code beside
  `drive`, not a reuse of it** — decide the reserve fires in the sibling, not in `drive`.
- **Session→principal binding.** The `owner` string is the principal resolved from the presented
  `VirtualKey` at open. For the browser (Topology B) the browser holds only the **ephemeral `ek_`
  client-secret**; the real key and the *mint* stay **server-side** — the `POST
  /v1/realtime/client_secrets` mint is itself a normal gauntlet pass
  (`plane4-duplex-session.md:565-587`). The durable identity binding rides the `VirtualKey` 1.6.0
  provenance fields — `binding_mode` (`crates/api/src/store.rs:345`) and `idp_subject`/`minted_by`
  (`:339,352`) — the same `Option<String>` attribution surface OpenAI's `safety_identifier` maps
  onto (`busbar-llm/.../field_carry_tests.rs:279`); core carries it as neutral attribution, never
  re-introspecting per frame.
- **BIND.** `SessionScope::new(engine, owner, id)` (`scope.rs:400`), then `open(...)` stamps the
  plane's opaque row (`VoiceSessionRow`, `busbar-voice/.../scope.rs:37-49`) — the plane owns the
  shape; the engine stores `Arc<dyn Any>`. The `plan` closure MUST stamp `id`+`HandleMeta.owner`
  equal to the session's (`scope.rs:429-432`), or the session cannot read what it opened.
- **VERIFY (per frame).** No re-mint of identity — `LiveHostFactory`
  (`plane_host/mod.rs:223`-ish, per design `:415`) re-mints a fresh host per frame so a mid-session
  budget/key rotation is seen next frame; per-frame governance is the **hot vtable against the
  populated `SessionScope`** (`plane4-duplex-session.md:388-402`), and continuity is the engine's
  owner gate (§1a). The word "voice" lives only in `busbar-voice`'s `VOICE_SESSION_KIND` string
  (`busbar-voice/.../scope.rs:22`); substrate and core see `(owner, id, Arc<dyn Any>)`.

---

## 4. Collision with Stage A (transport extraction) + the handle-engine

- **Two `SessionScope` copies mid-extraction (LOW→must-resolve-first).** Both
  `busbar-substrate::plane_host::SessionScope` (`scope.rs:382`) and a `busbar-core` copy
  (`busbar-core/src/plane_host/scope.rs:7`, re-export `mod.rs:54`) exist. The design/plan and the
  voice consumer target the **substrate** one (`busbar-voice/.../scope.rs:18`). Wire out **exactly
  one** and confirm the core copy is dead **before** any rider binds it
  (`plane4-seam-audit-B-session.md:72-75`), or two divergent shapes get frozen. The lease/arena
  fields must land on the substrate copy only.
- **Handle-engine lift already shipped (Stage A / T1.8).** The `DurableHandleEngine` is extracted and
  proven by a **non-A2A demo row** in its own tests (`plane4-seam-audit-C-handles.md:33`), so
  `SessionScope` is riding a genuinely neutral engine, not an A2A-shaped one — the extraction did not
  leave a plane noun in the store. Watch item from the C-audit: `advance_cursor`/push-delivery paths
  are **unscoped** (`handle_engine.rs:365`, C-audit `:206`) — a session that ever resumes purely by
  correlation id (not `(owner,id)`) would bypass the owner gate; keep every session resume on the
  scoped path.
- **Transport arrival (Stage A) must populate `SessionScope`, and today it has nowhere to put the
  socket.** The A-audit flags that the WS `Arrival` seam's job is to hand the accepted socket into
  `SessionScope`, but `SessionScope` "has no arena to hold a reclaimable socket"
  (`plane4-seam-audit-A-transport.md:295,318-319`). §1b's `arena`+`upstream_pipe`/`client_pipe`
  fields are exactly what closes that collision — land them before the WS transport lands, so
  "accept → populate `SessionScope`" reclaims on drop from day one.

---

## 5. Money-path touchpoints — a session IS a billable lease

A live session is a **standing reservation against a budget cell**, not a sequence of post-hoc
charges — for streamed audio you cannot refund bytes already sent, so only reserve-then-settle can
enforce a mid-session cap (`plane4-duplex-session.md:422-435`). Touchpoints:

1. **OPEN — reserve.** `CostHold::reserve(estimate, fee)` (`busbar-core/.../cost.rs:312`) debits the
   cell up front; the `CostHold` is moved into `SessionScope.lease`. This is the D2
   `cost_reserve` slot's job (`plane4-duplex-session.md:615-623`) once the slots land.
2. **PER TURN — settle.** On `response.done.usage`, `settle_partial(&CostBreakdown)`
   (`cost.rs:327`) accrues exact spend; audit link appended via `journal_append_scoped("session-<id>",
   …)` (`plane4-duplex-session.md:399-400`). Settle fires **per turn, not per audio frame**
   (`plane4-seam-audit-B-session.md:194-201`).
3. **EXHAUSTION — hard close.** `out_exhausted` (D2 `cost_settle`, design `:634`) ⇒ budget dry ⇒
   plane hard-closes the session — the one thing post-hoc metering cannot do.
4. **CLOSE / abnormal — refund.** `SessionScope::Drop` MUST `lease.finalize() -> Settlement`
   (`cost.rs:334`) and apply it to the cell. `CostHold` has **no `Drop`** and "carries no clock and
   no cell" (`cost.rs:298`; `plane4-seam-audit-B-session.md:63-70`), so a disconnect/cancel/panic
   that drops the scope without finalizing **leaks the up-front reserve** — the reservation is money
   held against the customer's budget. This is the leak-safety keystone the wire-out exists to close.

**Two D2 signature defects that touch this seam and are one-way doors (do NOT freeze §B.1 as
written).** (a) the reserve is denominated as `Magnitude` (a unit *count*) but drives
`CostHold::reserve` which takes **nanodollars** — the pricing bridge is undefined and would force the
*host* to price, violating core's no-pricing rule; decide who prices before minor-19
(`plane4-seam-audit-B-session.md:157-170,278`). (b) `out_exhausted` has **no backing accessor** on
`CostHold` (no `settled()`/`remaining()`/`is_exhausted()`) and the debit-up-front/refund-at-finalize
flow cannot surface a mid-session "cell dry" from an over-estimated reserve; pin
`out_exhausted := settled ≥ reserved` and drop "over-estimate" for the session lease
(`plane4-seam-audit-B-session.md:172-188,279`).

---

## 6. Residual risks

- **[HIGH] Lease-leak on abnormal close.** Until `SessionScope` embeds the arena AND its `Drop`
  finalizes the lease, every dropped/panicked/cancelled session leaks its up-front reserve against a
  real budget cell (`cost.rs:298,334`; `plane4-seam-audit-B-session.md:63-70`). Highest-value fix and
  a prerequisite to marking the struct `#[non_exhaustive]`.
- **[HIGH / one-way door] D2 reserve denomination + `out_exhausted` semantics unfrozen.** The two
  signature-level defects in §5 freeze at airlock minor-19; getting them wrong makes the fix a
  breaking MAJOR. `Magnitude`/`CostHold` have **zero** production consumers today
  (`plane4-seam-audit-B-session.md:132-138`), so nothing has forced the question — the slot is its
  first and last chance to be right.
- **[MEDIUM] Two-copy divergence.** The stale `busbar-core` `SessionScope` copy
  (`busbar-core/src/plane_host/scope.rs:7`) must be confirmed dead and removed before the
  lease/arena fields land, or the money-path fields could be added to the wrong copy and two session
  models freeze.
- **[MEDIUM] Owned-only lifetime.** A 20-minute `SessionScope` must own everything; no borrow may
  escape `GauntletRequest<'a>` into the handle (`plane4-seam-audit-B-session.md:111-116`). Today's
  fields are all owned (`String`/`Arc`); keep the new pipe/lease fields owned too.
- **[LOW] Unscoped resume/cursor path.** `advance_cursor`/push delivery is unscoped
  (`handle_engine.rs:365`); never resume a session off correlation id alone or the owner gate is
  bypassed.
</content>
</invoke>
