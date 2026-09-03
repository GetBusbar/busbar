# Handle-Engine seam-audit-C fixes — design & landing record

Source audit: `docs/design/plane4-seam-audit-C-handles.md` (base `e393b9e6`). This playbook designs the
four second-consumer fixes and records their landing state on `integration/plane-extraction`.

**Head-of-branch reality check (read first).** Three of the four fixes are ALREADY LANDED on this branch
since the audit's base commit. Verified against the live file
`crates/busbar-substrate/src/plane/handle_engine.rs` and git log:

| Fix | Audit ID | Landed? | Commit(s) |
|-----|----------|---------|-----------|
| (a) shard the process-wide lock | [1] | LANDED | `db9a0678` (doc), `336d8ef1` (W4-shard) |
| (b) `scoped_mutate(owner,id,plan)` | [2] SECURITY | LANDED | `ac38f3fb` |
| (c) `SubmitRecord.event: Option` | [3] | LANDED | `2cbd3503` |
| (d) dual-compiled `Box<dyn Any>` readback witness | [4] | **NOT LANDED** | — |

So the actionable remaining work is (d) only. (a)-(c) are documented below as verification + regression
guard, not as work to do. Dependency order executed: (a) shard first (it defines the two-level lock
discipline (b) reuses), then (b), then (c), independently (d).

---

## (a) Shard the process-wide handles Mutex — LANDED, verify

**Was (audit, base `e393b9e6`):** one `handles: Mutex<HashMap<String, HandleSlot>>`; `mutate` took that
global lock and held it across `apply_mutation_locked` → `upsert_record` + `append_record` (real
`PlaneStore` round-trips). `submit` wrote durably BEFORE the lock; `mutate`/`sweep`/`rehydrate` wrote
UNDER it. Two lock disciplines; every handle's mutate serialized behind one store round-trip's latency.

**Is now (`handle_engine.rs`):** two-level shard.
- Outer `handles: Mutex<HashMap<String, Arc<Mutex<HandleSlot>>>>` (`:290`) guards MAP STRUCTURE only.
- Inner `Mutex<HandleSlot>` (`HandleSlot` `:281`) serializes ONE handle's chain across its I/O.
- `mutate` (`:447`) takes the outer lock, `.get(id).cloned()` the `Arc<Mutex<HandleSlot>>`, DROPS the
  outer lock (`:460-464`), then takes the inner lock (`lock_slot` `:466`) across plan + persist.
- `scoped_mutate` (`:491`) mirrors it. `apply_mutation_to_slot` (`:368`) does the persist-then-memory.
- `lock`/`lock_slot` are poison-recovering (`:316`, `:322`). Ordering is always outer-THEN-inner
  (module note `:56-59`), so no deadlock.

Residual — deliberate, documented, NOT a defect: `sweep_locked` (`:537`, invoked from `submit` `:424`)
still does abandon's durable I/O under the OUTER lock; `rehydrate` (`:605`, `:616`) holds the outer lock
across `classify`'s per-row I/O. Both are acknowledged in the module note (`:56-59`, `:531-536`,
`:598-604`): sweep's I/O is confined to the submit-driven path (not the hot mutate path), and rehydrate
is boot-only / single-threaded. The correctness need — per-HANDLE serialization so two concurrent
same-handle transitions cannot fork the chain against one `tail_hash` — is preserved by the inner lock.

**Witness (present, green):** `two_different_handles_mutate_concurrently_without_serializing_on_each_other`
(`plane/tests/handle_engine_tests.rs:412`). Parks handle "a"'s mutate INSIDE its plan holding a's inner
lock, proves handle "b"'s mutate runs to completion meanwhile — only possible if the outer map lock was
released before "a" took its inner lock. Red on the old single-global-lock shape (b would block on a).

**Money-path / byte-identity risk:** the seal reads `pos.tail_hash` and produces the next link; if the
outer-lock minimization had instead dropped ALL locking during seal/append, two concurrent same-handle
mutations would fork the chain against one `tail_hash` — a provenance-chain break (a money-path integrity
failure for A2A's `EV_*` chain). The inner lock is the guard that must never be removed; the shard lifts
only the CROSS-handle bottleneck. Regression guard: keep the concurrency witness AND add no path that
takes the outer lock while holding an inner one (would reintroduce deadlock).

**Voice prerequisite vs bankable:** HARD PREREQUISITE for voice. A2A is human-paced and tolerated the
global lock; voice-session frames / Responses-stateful streaming are concurrent + chatty and hit the
per-engine bottleneck. Hardest to change once a second consumer's concurrency freezes onto the semantics
— correctly ranked #1 and landed first.

---

## (b) `scoped_mutate(owner, id, plan)` — LANDED, SECURITY — verify

> **PRIORITY / SECURITY.** This closes an auth asymmetry: reads were anti-enumeration-hardened; the
> write/resume path was keyed by `id` alone. It is the exact primitive T3's inbound webhook receiver
> needs (untrusted write-by-correlation-id). Do not let T3 bolt a per-site owner check on instead.

**Was:** `mutate` keyed by `id` alone (still does — `:447`, deliberately, for TRUSTED internal callers
that scope upstream, e.g. A2A's front door). Reads (`scoped_get` `:639`) collapse foreign-or-missing to
one `HandleDenied::NotYours`. No scoped write existed → a receiver resuming purely by correlation id let
anyone who guesses/replays an id poke another tenant's handle.

**Is now:** `scoped_mutate` (`:491`) + `ScopedMutateError` (`:259`). Discipline:
1. Empty owner → `NotYours` before any lookup (`:503`).
2. Missing id → `NotYours`, indistinguishable from foreign (`:508`).
3. Owner gate runs BEFORE `plan` is ever invoked (`:515`) — so `plan`'s side effects and timing never
   leak whether the id exists. Only AFTER ownership proven do domain `Rejected` / durable `Store`
   surface distinctly (`:518-527`), because those facts belong to an already-authorized caller.
4. Same two-level lock discipline as `mutate` (reuses (a)).

`ScopedMutateError` intentionally has ONE auth variant (`NotYours` `:262`) — a distinguishable
not-found/not-yours is an enumeration oracle, exactly mirroring `scoped_get`.

**Witness (present, green):** `scoped_mutate_owner_gates_the_write_with_one_indistinguishable_refusal`
(`handle_engine_tests.rs:513`). Asserts: wrong owner ("bob"), missing id ("nope"), and empty owner all
refuse WITHOUT running the plan (the plan flips a flag proving it never fired); the rightful owner runs
the plan and applies the write. Red before the fix (no such fn / an unscoped write would apply).

**Money-path / security byte-identity risk:** this is the inverse of the outbound SSRF posture — a
WRITE from an untrusted third party. The four surrounding receiver obligations (audit seam 4, NOT engine
work, captured for T3): unguessable high-entropy correlation id (the id IS the capability), HMAC/bearer
+ replay window BEFORE the lookup, and the receiver's own 404/403 must be one indistinguishable refusal
mirroring `scoped_get`. The engine now supplies the resume-side primitive; the receiver must supply
auth-then-correlate-then-scoped-resume around it.

**Voice prerequisite vs bankable:** BANKABLE NOW and independently valuable (closes a live read/write
asymmetry), AND a hard prerequisite for the T3 receiver / any untrusted second-consumer resume. Cheapest
while the engine had one trusted consumer.

---

## (c) `SubmitRecord.event: Option<SealedEvent>` — LANDED, verify

**Was:** `SubmitRecord.event` non-optional `SealedEvent` — every `submit` MUST seal a genesis event.
`Mutation.event` was already `Option` (`:155`; `set_push_callback` submits an event-free mutation,
`taskstore.rs:842`). So the two carriers disagreed and a chainless durable handle (Responses-stateful,
keyed by response id, no per-event hash chain) could only be expressed by synthesizing a dummy genesis
event — an A2A assumption ("every handle opens a provenance chain") baked into the neutral submit.

**Is now:** `SubmitRecord.event: Option<SealedEvent>` (`:175`), matching `Mutation.event`. `submit`
(`:392`) branches on it (`:412-422`): `Some` → append the record and advance to `next_seq` 2; `None` →
keep `ChainPosition::genesis()` (empty tail, `next_seq` 1), so a LATER `mutate` that appends an event
seals the TRUE genesis link. A2A still passes `Some` (its `EV_SUBMITTED`) — unchanged behavior.

**Witness to add (GAP):** there is a concurrency + scoped witness but I did NOT find a submit-side witness
that a `None`-event submit installs a handle at genesis position AND that a first later `mutate` seals
seq 1. Add `a_chainless_submit_opens_at_genesis_and_a_later_event_seals_seq_1` in
`handle_engine_tests.rs`: submit `DemoRow` with `event: None`, assert `meta(id)` present and (via a
mutate whose plan inspects `pos`) that the first appended event sees `next_seq == 1` and empty
`tail_hash`. Cheap, closes the one un-witnessed arm of (c).

**Money-path / byte-identity risk:** LOW. Behavior for A2A (always `Some`) is byte-identical — same
record appended, same `next_seq` advance. The only new path is `None`, which no current consumer takes.
The risk to guard is the seq accounting: a `None` submit must NOT pre-advance `next_seq`, or the true
genesis event would seal at seq 2 and every downstream A2A chain digest would shift (a provenance-chain
byte divergence). The code keeps genesis (`:421`) — the added witness pins exactly this.

**Voice prerequisite vs bankable:** Ergonomic prerequisite for Responses-stateful (chainless rows); for
voice, only if voice wants chainless sessions. BANKABLE NOW (it is a pure widening — `Option` strictly
supersets the old mandatory event; no consumer regresses). Correctly ranked #3.

---

## (d) Dual-compiled `Box<dyn Any>` readback witness — **NOT LANDED, the real remaining work**

**Problem:** the whole opaque design — rows held as `Arc<dyn Any + Send + Sync>` (`:149`, `:164`,
`:190`), every read a downcast + clone — exists to survive a future per-plane opaque state slot
(`Box<dyn Any>`) that "core reads back" (module doc `:16-22`). That slot's PATTERN exists in the testkit
(`testkit.rs:33-41,61` — `plane_scratch_any` / `take_plane_scratch_any` return `Box<dyn Any>`;
`install_plane_runtime` takes `Arc<dyn Any + Send + Sync>`), but NO wiring rides the ENGINE through it.
The only non-test constructor of `DurableHandleEngine` is A2A's `TaskRegistry`, which holds it as a
concrete field (`taskstore.rs:504`) in a plane-crate static (`TASKS` `taskstore.rs:511`) — never boxed
into a core slot. So the design pays the opacity tax (downcast-on-every-read) for a constraint no passing
test exercises. The `TypeId`-divergence trap is real: a GENERIC `Engine<PlaneRow>` monomorphised inside
the plane crate would carry a `TypeId` that DIVERGES across the two core instances in a dual-compiled
plane test binary; the engine avoids it only by being substrate-single-compiled and non-generic — a claim
that must be PROVEN in a two-core binary, not asserted.

**Change (net-new test, no product code change):** land the witness in the DUAL-COMPILED plane test
binary — `busbar-a2a` built with `--features test-support` (`Cargo.toml:40,120`), which links both
substrate's single compile of the engine AND the plane's core-typed helpers, i.e. the two-core config the
trap needs. Single-compiled coverage in `handle_engine_tests.rs` is necessary but NOT sufficient — it has
only one core instance, so it cannot exhibit a cross-instance `TypeId` divergence.

Witness shape (add to `crates/busbar-a2a/src/a2a/tests/plane_tests.rs`, the dual-compiled binary):
1. Build a `DurableHandleEngine` and `submit` one plane row (an A2A task row, or a local `DemoRow`).
2. Erase the engine into the core-owned opaque slot: `Arc<dyn Any + Send + Sync>` via
   `install_plane_runtime` (`testkit.rs:61`) OR a `Box<dyn Any>` via the `plane_scratch_any` seam — the
   exact `Box<dyn Any>` core-readback path the design promises.
3. Read it BACK through the neutral seam in the plane crate and `downcast` to `DurableHandleEngine`.
   Assert the downcast SUCCEEDS — this is the load-bearing assertion: it proves the engine's `TypeId` is
   identical on the store side (core) and the read side (plane) because the type is substrate-single-
   compiled. A generic monomorphised-in-plane engine would FAIL this downcast in a two-core binary.
4. `scoped_get`/`get_unscoped` the row back out and downcast the inner `Arc<dyn Any>` to the plane row;
   assert it is BYTE-IDENTICAL to the submitted row (no re-encode round-trip) — proving the nested
   `Arc<dyn Any>` also survives the erase/read-back with its own preserved `TypeId`.

Red-before-green proof: temporarily make the engine generic (`Engine<Row>`) OR construct the row's `Any`
inside a second monomorphisation — the downcast in step 3/4 must fail in the dual-compiled binary,
confirming the witness actually exercises the trap and is not vacuously green.

**Money-path / byte-identity risk:** this witness EXISTS to protect byte-identity. If the engine's central
opacity claim is false (a `TypeId` diverges across the two core instances), every row read-back downcast
silently returns `None`/panics at the point core hands the plane its state back — the entire durable-
handle capability fails to rehydrate/resume for a plane wired through the core slot. Today no consumer is
wired that way, so the failure is latent; a voice/Responses consumer that DOES ride the core slot would be
the first to trip it, in production, at resume. The witness converts a latent production failure into a
compile/test failure.

**Voice prerequisite vs bankable:** ASSURANCE prerequisite for voice — voice is the first plausible
consumer to ride the engine through a `Box<dyn Any>` core slot rather than a plane-crate static, so it is
the first to depend on the unproven claim. Land the witness BEFORE that wiring so voice inherits a proven
seam, not an asserted one. Independently bankable as a regression guard for the existing opaque design.

---

## Summary ordering (by dependency)

(a) shard defines the two-level lock discipline → (b) `scoped_mutate` reuses it (SECURITY) → (c) `Option`
event (independent widening) → (d) dual-compile witness (independent assurance). (a)-(c) already landed
with witnesses on this branch; (c) is missing only its chainless-genesis unit witness; (d) is the sole
net-new deliverable.
