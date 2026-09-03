# T1 Playbook — the D2 cost-lease seam (billable duplex session, hard-close-on-exhaustion)

Status: **DESIGN / SEAM PLAYBOOK.** Read-only against the tree. Owner: Matthew.
Companion to `docs/design/plane4-duplex-session.md` (§3, §6-D2) and the seam audits
`plane4-seam-audit-B-session.md` (SessionScope RAII) and `plane4-seam-audit-C-handles.md`
(the freshly-extracted handle engine). Scope: the ONE money primitive a live, per-frame-metered
duplex session needs — a reserve-then-settle lease that can **hard-close a live stream when the
budget is exhausted** — plus the exact byte-identity constraints on the existing money path it must
NOT disturb.

The load-bearing rule (owner, §6-D2): **freeze the D2 shape in 1.6.0, ship the slots with the plane
in 1.7.0.** Voice bills through the SAME `usage_units`/`meter_charge` money path as text — audio and
text are token *classes* (`UsageComponent`), not a new meter. **Zero voice-specific code in core.**

---

## 0. TL;DR

- The lease **type already ships**: `CostHold` (`crates/busbar-core/src/plane/cost.rs:304`) —
  `reserve` (`:312`) / `settle_partial(&CostBreakdown)` (`:327`) / `finalize() -> Settlement`
  (`:334`). What is missing is the **FFI slot pair** to drive it across the hot ABI, at the reserved
  extension point `crates/busbar-plugin/src/hot/host.rs:533-536`.
- The lease **hangs off `SessionScope`** (`crates/busbar-substrate/src/plane_host/scope.rs:366`), the
  connection-lifetime scope, NOT the durable handle engine. `SessionScope` must gain an embedded
  `DispatchScope` arena + `impl Drop` so the lease is finalized-and-refunded on abnormal close
  (seam-B [HIGH] `cost.rs:334` is a *by-value consume*, `CostHold` has no `Drop`).
- **Hard-close-on-exhaustion** = `cost_settle` reads back `out_exhausted: bool`; `true` ⇒ the plane
  drops the session. The governance-probe checkpoint asserts a settle that crosses the reserve
  returns `exhausted = true` AND that no further `pipe_write` follows.
- **Byte-identity STOP condition**: `CostBreakdown::new`'s "parts add up" invariant
  (`cost.rs:186,222`), the `NANOS_PER_MICRO = 1_000` projection (`govern.rs:35`), and
  `record_metering`'s `(key_id, model, provider)` row (`state.rs:866`) must produce byte-identical
  ledger rows before and after. The lease is a NEW accrual path; it must not re-price or re-round.
- The concurrent-overshoot gap is **real and pre-existing** (`state.rs:1736`: token caps are
  best-effort, TPM lands post-response). The lease *narrows* it for sessions (reserve caps up front)
  but does not close the cross-session race; §4 says what to do.

---

## 1. The cost-lease type + reserve/settle/hard-close API, and how it hangs off the session

### 1.1 What already ships (do not rebuild)

`CostHold` (`cost.rs:304`) is the whole amount-correctness engine and it is **complete**:

- `reserve(estimate: CostAmount, fee: CostAmount) -> CostHold` (`:312`) — `reserved = estimate + fee`,
  the once-only flat fee folded in ONCE (`:315`). Caller debits `reserved()` (`:320`) from the budget
  cell now.
- `settle_partial(&mut self, exact: &CostBreakdown)` (`:327`) — accrues `exact.total()` into
  `settled`. Repeatable; the running sum is the TRUE charge, never the coarse reserve (the accuracy
  invariant, `:302,324-329`).
- `finalize(self) -> Settlement` (`:334`) — `Settlement { ledgered_total = settled, refund =
  reserved.saturating_sub(settled) }` (`:282-289`). Over-settle ledgers the true amount and refunds
  zero, never negative (`:335`).
- `Magnitude` (`cost.rs:270`) is the coarse pre-admission over-estimate: `unit: &'static str`,
  `amount: u64`, `caller_cap: Option<u64>`. Note the `&'static str` — **not FFI-POD** (§3.3).

`CostAmount(u128)` is nanodollars (`cost.rs:41`) — the same integer unit the engine's per-token
pricing already settles in (`cost::RateNanos`/`cost_nanos`, `cost.rs:36-38`).

### 1.2 The net-new FFI slot pair (the D2 add)

Appended at the reserved extension point (`host.rs:533-536`), trailing `Option` slots, airlock MINOR
bump, mirroring every prior appended cluster (the minor-18 `gate_decide` at `host.rs:526-532` is the
precedent). Frozen shape:

```rust
// APPENDED at hot/host.rs:533 (trailing Option slots) + mirrored on the POD at hot/pod.rs:636-638.

/// POD projection of `busbar_core::plane::cost::Magnitude` (whose `unit: &'static str` is NOT
/// FFI-safe, cost.rs:270). Host reconstructs the coarse magnitude; core never interprets `unit`.
#[repr(C)]
pub struct MagnitudePod {
    pub unit_ptr: *const u8,   // opaque plugin word ("audio_seconds" / "tokens"); host never parses it
    pub unit_len: usize,
    pub amount: u64,           // the over-estimate
    pub caller_cap: u64,       // 0 = none  (mirrors Magnitude.caller_cap: Option<u64>)
}

/// NEW POD newtype; 0 = NONE sentinel. Opaque host-side lease handle.
#[repr(transparent)]
pub struct CostLeaseId(pub u64);

/// Open a reserve-then-settle lease: reserve a coarse over-estimate (host debits the budget cell
/// now, driving CostHold::reserve, cost.rs:312) and return an opaque lease id.
pub type CostReserveFn = extern "C-unwind" fn(
    host: HostCtx,
    magnitude: *const MagnitudePod,
    flat_fee_nanos: u128,          // folded into `reserved` ONCE (cost.rs:315)
    out_lease: *mut CostLeaseId,   // 0 = NONE on refuse
) -> StatusClass;

/// Settle one EXACT increment against an open lease (a turn's true cost, driving
/// CostHold::settle_partial, cost.rs:327) and READ BACK exhaustion so the plane can hard-close.
/// The itemized CostBreakdown crosses as an OPAQUE pre-framed suffix (the journal_append_scoped
/// pattern); the host accrues only its `total` (cost.rs:249) and answers exhaustion.
pub type CostSettleFn = extern "C-unwind" fn(
    host: HostCtx,
    lease: CostLeaseId,
    breakdown_ptr: *const u8,      // opaque CostBreakdown suffix; host never parses component labels
    breakdown_len: usize,
    out_exhausted: *mut bool,      // true ⇒ budget dry ⇒ plane hard-closes the session
) -> StatusClass;

pub cost_reserve: Option<CostReserveFn>,   // trailing slot (host.rs, below :536)
pub cost_settle:  Option<CostSettleFn>,    // trailing slot
```

Both slots must also be added (as `None`) to `PlaneHostVtable::EMPTY` (`host.rs:554-600`) and (as
`Some(stub::…)`) to `PlaneHostVtable::STUB` (`host.rs:606-655`), with the `size`/`version` fields
picking up the new `size_of` automatically (`host.rs:556-557`). The `assert_send_sync` guard
(`host.rs:545-548`) re-fires on the grown struct — both slots are plain fn-pointers, so it stays
green.

**Host-side bodies** live beside the existing governance family in
`crates/busbar-core/src/plane_host/govern.rs` (where `charge`/`admit` already live, `:55,:207`). A
process-wide `HashMap<CostLeaseId, CostHold>` keyed on a host-minted id is the host's private lease
table; `cost_reserve` inserts a `CostHold::reserve(...)`, `cost_settle` looks it up, calls
`settle_partial`, then answers `out_exhausted = settled >= reserved && budget_cell_dry`.

### 1.3 How it hangs off the session

The lease is **connection-lifetime**, so it lives on `SessionScope` (`scope.rs:366`), the Axis-2
connection scope whose own doc says *"holds … in-flight leases (a2a session; DB-wire)"* (`:359`) and
*"the riders that add a duplex/session plane wire this out"* (`:361`). Per seam-B the wired-out field
set is:

```rust
struct SessionScope {                 // scope.rs:366, today an empty #[non_exhaustive] stub
    arena: DispatchScope,             // seam-B [HIGH]: embed the arena, like DurableScope (:462)
    client_pipe: PipeId,              // registered into `arena` via register_pipe (:302)
    upstream_pipe: PipeId,
    lease: CostLeaseId,               // the host-side lease handle (NOT the CostHold — that is host-side)
    journal_scope: String,            // "session-<id>"
    // (CallRef correlation table is plane-side, in busbar-voice — never crosses here)
}
```

- The **opening reserve** is minted at session-open, inside `run_gauntlet`'s open pass
  (`crates/busbar-substrate/src/plane_host/mod.rs:177`), immediately after `govern_admit_reason`
  (`mod.rs:264`) admits — a coarse over-estimate for the session cap (~60 min), `caller_cap` set from
  the request. This is **net-new open code, not a reuse of `drive`** (seam-B seam-2 [MEDIUM]: the
  existing charge rides `drive(self: Box<Self>)`, which the session sibling must not call).
- Per `response.done.usage`, the plane folds the audio/text token classes into a `CostBreakdown`
  (§2, §3) and calls `cost_settle`. If `out_exhausted` ⇒ hard-close (§2).
- **On close (normal OR abnormal) the lease must `finalize()` and apply the refund.** `SessionScope`
  gains `impl Drop` that reaches the host to `finalize` the lease and return `Settlement.refund`
  (`cost.rs:334`) to the budget cell. This is seam-B [HIGH #2]: `CostHold` has NO `Drop` and
  `finalize` is a by-value consume (`cost.rs:298,334`), so a dropped session that never finalized
  **leaks the reservation** — the budget cell stays debited forever. The Drop is the leak-safety
  keystone the whole scope taxonomy exists to protect (`scope.rs:15,22`), mirrored on `DispatchScope`
  (`scope.rs:352-356`).

---

## 2. Hard-close-on-exhaustion and the governance-probe checkpoint

### 2.1 Why post-hoc metering cannot do it

`meter_charge` (`plane_host/mod.rs:283`) debits **after the fact** and is fire-and-forget. For audio
you cannot refund bytes already streamed, so post-hoc charging cannot enforce a mid-session cap
(design §3.3). Only reserve-then-settle can: the reserve caps up front, and `settle_partial`'s
running sum crossing the reserve is the stop signal.

### 2.2 The mechanism

Per server→client turn (design §3.2):

```
pipe_read(upstream) → DuplexReader.read_down → on Usage:
    breakdown = fold(IrDuplexUsage → CostBreakdown)          // §3
    cost_settle(lease, breakdown, &mut exhausted)            // drives CostHold::settle_partial
    journal_append_scoped("session-<id>", …)                 // audit the turn
    if exhausted { session hard-close: stop pumping, Drop SessionScope }
```

Hard-close = the plane stops issuing `pipe_write` frames, closes the client `PipeId`, and drops
`SessionScope`; the Drop finalizes the lease (refund = 0 on an exhausted lease, `cost.rs:335`) and
reclaims the pooled upstream socket via the embedded arena (`scope.rs:302,352`).

### 2.3 Where the governance-probe checkpoint asserts it

The release-gate governance probe must assert, on a `STUB`/fake host whose lease table is seeded so
the next settle crosses the reserve:

1. **Exhaustion is reported.** `cost_settle` with a breakdown whose accrued `total` pushes
   `settled >= reserved` writes `out_exhausted = true`. (Unit-level: `CostHold::settle_partial` then
   `finalize().refund == 0`, `cost.rs:335`.)
2. **The stream actually stops.** After an `exhausted = true` settle, **no further `pipe_write`**
   reaches the client pipe — assert zero writes post-exhaustion (the "audio kept flowing while the
   alert fired" failure mode, design §9.1).
3. **The lease is finalized exactly once and the refund lands.** Dropping the `SessionScope` calls
   `finalize` once; `ledgered_total == sum of settle_partials` and the budget cell delta ==
   `reserved − refund` (seam-B leak keystone). Assert no double-finalize and no leaked reserve on the
   abnormal path (drop without an explicit close).

This mirrors the existing leak-keystone discipline the admission RAII grant already proves
(`govern.rs:51-68` — the `AdmitGrant` registered in the arena, reclaimed on scope-drop). The lease is
the *money* analogue of that grant.

---

## 3. Money-path byte-identity constraints — this is a STOP-condition area

The lease introduces a NEW accrual path. It must produce **byte-identical ledger rows and
byte-identical priced totals** to today's path. Any diff here is a STOP condition — halt and escalate,
do not "adjust the golden".

### 3.1 Pricing oracle — do not re-price, do not re-round

- The **only** micro→nano projection is `NANOS_PER_MICRO = 1_000` (`govern.rs:35`), a local mirror of
  the private `cost::NANOS_PER_MICRO`. The lease path must reuse the SAME constant and the SAME
  saturating multiply shape `micros.saturating_mul(NANOS_PER_MICRO)` (`govern.rs:207-209`). Do not
  introduce a second projection constant.
- Per-token pricing (`RateNanos::cost_nanos`, `cost.rs:117`; `rate_for`, `:498`) is unchanged. The
  lease NEVER prices — the plane hands it a `CostBreakdown` already in nanodollars. Core "mints
  nothing from the breakdown but the accrued `total`" (`cost.rs:249`, design §6-D2 note b). **The
  host never parses the component labels** (`cost.rs:73-82`).

### 3.2 `usage_units` ledger must not change bytes

- `CostBreakdown::new` (`cost.rs:186`) is the ONLY constructor and its "parts add up" invariant
  (`cost.rs:222`, `TopLevelSumMismatch`) is the trust anchor. Voice folds audio/text classes into
  top-level components whose amounts sum to `total` — exactly as `charge` builds a single opaque line
  today (`govern.rs:213-219`). No new relaxation of the invariant.
- The ledger row is `record_metering(key_id, model, provider, Option<&TokenUsage>, now)`
  (`state.rs:866`), bucketed by `metering_bucket(now)` (`:876`). Voice must record through the SAME
  fn with the SAME `(key_id, model, provider)` attribution tail (`Usage` POD, `pod.rs:657-690`), so a
  voice row is byte-identical in shape to a chat row — audio is a `TokenUsage` modality
  (`input_audio`/`output`), NOT a new meter (`billing.rs:22-40`; `token_usage_for`, `govern.rs:280`).
- `UsageComponent` (`pod.rs:191`) already has `Tokens=0, Bytes=1, Frames=2, Queries=3`. Audio frames
  map onto `Frames` (or `Tokens` for the token-class settle); `component_label` (`govern.rs:289`)
  labels them `"frames"`/`"tokens"` — **no new enum variant, no new label**. Adding a voice-only
  variant would be a byte-change to every price/label site and a `#[repr(u8)]` reshape — do NOT.

### 3.3 `Magnitude` is not FFI-POD — the one shape correction

`Magnitude.unit` is `&'static str` (`cost.rs:270-277`) and cannot cross the C ABI. The slot carries
`MagnitudePod` (§1.2) — `unit` as `(ptr,len)`, `amount`/`caller_cap` as scalars — the same
opaque-suffix discipline the journal family uses. Core reconstructs the coarse magnitude host-side;
`unit` is never interpreted. This is a shape projection, not a money-path change — the priced bytes
still come only from the exact `CostBreakdown` settles, never from `Magnitude` (the coarse estimate,
`cost.rs:268` "accuracy comes from the exact settlement").

**STOP-condition test set** (must be green, byte-for-byte, before/after the D2 add):
`charge_over_usage_matches_record_metering` (referenced `govern.rs:230`), the `plane/tests/cost_tests`
"parts add up" suite (`cost.rs:344`), and the `cost_tests.rs:566,583` rounding clamps. A settle-path
row must equal the chat-path row for the same `(key_id, model, provider, TokenUsage)`.

---

## 4. The concurrent-overshoot governance gap

### 4.1 What exists

`try_admit` (`state.rs:1741`) is careful: concurrent holds use a `fetch_update` CAS loop so *"N
racing admissions can never jointly overshoot"* (`state.rs:1780-1807`), and windowed limits are
charged all-or-nothing under ordered shard locks. RAII `AdmitGrant` refunds on non-2xx.

### 4.2 The real gap (pre-existing, not introduced by the lease)

Token/budget caps are **BEST-EFFORT** by the code's own admission (`state.rs:1736-1741`): *"tokens
land post-response, so the cap blocks the NEXT request once the ledgered total has crossed it;
in-flight requests' tokens are invisible to admissions racing them."* For a 20-minute voice session
this window is huge — N concurrent sessions can each admit under a shared budget that only one of them
would exhaust, and the overshoot is bounded by the tokens of every in-flight session, not by the cap.

### 4.3 Whether/how the lease closes it

The lease **narrows** it and should be the accepted answer, not a new limit engine:

- **Up-front reserve is the fix in-kind.** `cost_reserve` debits `reserved()` (`cost.rs:320`) from the
  budget cell **at open**, BEFORE any frame flows — so a session's coarse worst-case is subtracted
  from the shared budget immediately, and a racing session sees it. This converts voice from the
  worst case (post-response TPM) to the best case (pre-charged), the same posture the `budget` metric
  already has for the flat fee (`state.rs:1740`, "the fee component is hard").
- **What it does NOT close.** The reserve must be debited through the SAME `fetch_update`/shard-lock
  discipline as `try_admit` (`state.rs:1780`) or it reintroduces a TOCTOU. So the `cost_reserve` host
  body must route the debit through the governance engine's existing CAS path, not a naive
  `cell -= reserved`. **Do this, or the lease trades a bounded post-hoc overshoot for an unbounded
  reserve-time race.** This is the one real design obligation in this section.
- **Residual:** the reserve is a coarse over-estimate; a session that under-reserves and over-settles
  (`cost.rs:335`, over-settle path) can still transiently exceed the cap between two settles — but
  bounded by ONE turn's cost, not a whole session's, and the exhaustion hard-close (§2) fires on the
  crossing settle. That residual is acceptable and matches the owner's ruling (accuracy from
  settlement, `cost.rs:268`).

Recommendation: **close it via reserve-through-CAS; do not build a new concurrent token gauge.** The
gap shrinks from "a whole in-flight session invisible" to "one turn's over-settle", which the
hard-close bounds.

---

## 5. Collision with the handle-engine (audit-C) fixes

The lease lives on `SessionScope` (connection scope), the durable **session record** lives in the
handle engine / `DurableScope` (design §5.1). They interact, and three audit-C SURFACE-NOW items
collide:

1. **audit-C [1] — `mutate` holds the process-wide `handles` Mutex across durable store I/O**
   (`handle_engine.rs:373`→`:292`→`:274/:282`). **Collision:** if voice persists each `cost_settle`
   into the durable session row via a per-turn `mutate`, every settle serializes ALL handles behind
   one store round-trip — a process-wide bottleneck under concurrent sessions. **Resolution:** keep
   per-turn settle IN-MEMORY on the host-side `CostHold`; persist the running total only COARSELY
   (checkpoint every N turns / on close), so the hot per-frame path never touches the engine lock.
   The lease's accuracy is preserved by `CostHold` in memory; durability is a coarse checkpoint. If
   per-turn durable settle is ever required, it needs the per-handle lock shard audit-C [1] asks for
   FIRST.

2. **audit-C [2] — add `scoped_mutate(owner, id, plan)`.** **Collision:** a RESUMED session (T3
   inbound receiver, or a rehydrated session on boot) that re-attaches a lease by correlation id is a
   write-by-id — the exact unscoped-`mutate` hole (`handle_engine.rs:365`). A resume that re-opens a
   lease MUST scope on owner, or a guessed session id lets another tenant drive/exhaust a lease.
   **Resolution:** the session record's resume path rides `scoped_mutate` once it lands; the lease
   re-attach inherits the owner check for free. Do not bolt a per-site owner check onto the lease
   resume.

3. **audit-C [3] — make `SubmitRecord.event` `Option<SealedEvent>`** (`handle_engine.rs:138` vs
   `Mutation.event` `:123`). **Collision:** the durable session record is a plain row (which upstream,
   which lease id, open/settle timestamps) that does NOT want a per-event provenance hash chain — the
   per-turn audit chain is already carried by `journal_append_scoped` (`host.rs:491`), a SEPARATE
   authority. Forcing a genesis `SealedEvent` on the session row duplicates the chain. **Resolution:**
   land the optional-event change so the session handle is a chainless durable row; the turn-by-turn
   hash chain stays in the journal family, not the handle engine.

No collision with audit-C [4] (dual-compile witness) or the `DurableScope` handoff — the lease does
not ride an `Arc<dyn Any>` core slot; it is a plain owned `CostLeaseId` on `SessionScope`.

---

## 6. Residual risks

- **[HIGH] Refund-on-abnormal-close leak.** If `SessionScope::Drop` is not wired to `finalize()` the
  lease AND reach the budget cell, every disconnect/panic/cancel leaks the up-front reserve — the
  budget cell is debited forever (seam-B [HIGH #2], `cost.rs:298,334`). This is the single most likely
  correctness failure; the governance probe (§2.3 #3) must assert the abnormal path.
- **[HIGH] Reserve-time TOCTOU.** If `cost_reserve` debits the budget cell outside the
  `try_admit` CAS/shard-lock discipline (`state.rs:1780`), the lease trades a bounded post-hoc
  overshoot for an unbounded reserve-time race across concurrent session opens (§4.3).
- **[MEDIUM] Money-path byte drift.** A second nano projection, a new `UsageComponent` variant, or a
  voice-only label would change ledger/priced bytes and break the STOP-condition golden set (§3). The
  lease must reuse `NANOS_PER_MICRO` (`govern.rs:35`), `CostBreakdown::new` (`cost.rs:186`), and
  `record_metering` (`state.rs:866`) verbatim.
- **[MEDIUM] Two `SessionScope` copies.** `busbar-core` still has a `SessionScope`
  (`crates/busbar-core/src/plane_host/scope.rs:7`, re-export `:51`) alongside the substrate one
  (seam-B [LOW #3]); wire the lease onto ONE (substrate) and confirm the core copy is dead, or the
  lease's home is ambiguous.
- **[LOW] Coarse-checkpoint durability gap.** Keeping per-turn settle in-memory (§5.1) means a crash
  between checkpoints loses the last N turns' settled total — acceptable (the reserve already capped
  the budget; the loss is under-billing bounded by the checkpoint interval), but it must be a stated
  design choice, not an accident.
```
