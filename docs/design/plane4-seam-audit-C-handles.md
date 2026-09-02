# plane4 SEAM AUDIT C — Handle Engine & Work Carrier (axis C)

Read-only adversarial audit. Base commit `e393b9e6` (INCLUDES the just-landed T1.8 handle-engine
extraction — audited as landed). Scope: the freshly-extracted `DurableHandleEngine`, the
`DurableScope` park/resume, the `WorkItem` duplex carrier, and the planned (net-new) inbound webhook
receiver (T3). No code changed; this is the only file written.

The key output: **is the freshly-extracted engine fit for a SECOND consumer (busbar-voice sessions,
busbar-llm Responses-stateful) as-is, or does it need adjustment now while it is fresh?** Short
answer: the capability/consumer split is genuinely clean and the neutral surface already carries a
non-A2A demo row in its own unit tests — but four things in the extraction will bite a second
consumer, and two of them are cheapest to fix NOW, before a second consumer's byte-behavior freezes
onto the current shape.

---

## Seam 1 — the extracted `DurableHandleEngine`

Files: `crates/busbar-substrate/src/plane/handle_engine.rs` (registered
`crates/busbar-substrate/src/plane/mod.rs:47`), consumer
`crates/busbar-a2a/src/taskstore.rs` (`TaskRegistry`, `taskstore.rs:497`).

### (a) TODAY

The split is correct and, for A2A, complete. The engine owns the mechanics — working-set registry
(`handle_engine.rs:223`), durable write-through (`upsert_record`/`append_record`,
`handle_engine.rs:274,282`), retention sweep (`sweep_locked`, `:403`), boot rehydrate (`:467`),
scoped anti-enumeration read (`scoped_get`/`scoped_list`, `:501,:517`), the inbound-push cursor
(`HandleMeta.cursor`, `:54`). busbar-a2a layers shape/statuses/vocab/digest through boxed callbacks
(`plan_abandon` `taskstore.rs:429`, the seal closures inside `submit`/`transition`
`taskstore.rs:642,681`, the rehydrate `classify` `taskstore.rs:548`). No `task`/`agent`/`a2a` noun
appears in the engine surface — confirmed by grep and by the engine's OWN unit tests, which drive it
with a non-A2A `DemoRow` (`plane/tests/handle_engine_tests.rs:19`). That demo is the strongest
positive signal for second-consumer fitness: the neutral surface already carries a foreign row shape.

Dual-compile: the engine is non-generic and substrate-single-compiled; a plane's row rides opaquely
as `Arc<dyn Any + Send + Sync>` (`:117`) and is downcast back INSIDE the plane crate
(`as_task`/`downcast_ref`, `taskstore.rs`). The engine never downcasts the `Any` itself — it treats
rows fully opaquely — so the `TypeId`-divergence trap the notes describe is genuinely avoided. The
generic METHODS (`submit`/`mutate`/`rehydrate`) monomorphise inside the plane crate, but their
closure types never cross a stored-`Any`/FFI boundary, so they do not reopen the trap.

### (b) WITH CHANGES — can it serve voice-sessions + Responses-stateful as-is?

Mostly yes, but four A2A-shaped edges leaked into the "neutral" engine or were left half-wired:

1. **`mutate` holds the process-wide handles `Mutex` ACROSS durable store I/O.** `mutate`
   (`:373`) takes `self.lock()`, runs the plane `plan`, then calls `apply_mutation_locked` (`:292`),
   which does `upsert_record` + `append_record` — real `PlaneStore` round-trips — WHILE STILL HOLDING
   the global `handles` lock. `submit` deliberately does the opposite: its durable writes happen
   BEFORE the lock (its own comment, `:320-323`; code `:339-347`). So the engine has two lock
   disciplines. The mutate discipline is correct for A2A (per-handle chain-seal must be serialized so
   two concurrent transitions cannot fork the chain against the same `tail_hash`), but it serializes
   ALL handles behind ONE store round-trip's latency. A2A is human-paced and tolerates it; a second
   consumer with concurrent, chatty handles (voice-session frames, Responses-stateful streaming) hits
   a process-wide bottleneck. `sweep_locked` (`:403`, run under the lock inside `submit`) and
   `rehydrate` (`:467`, holds the lock across per-row `list_plane_records` I/O in `classify`) have the
   same lock-across-I/O shape. The correctness need is per-HANDLE serialization; the implementation
   pays per-ENGINE. This is the #1 thing to settle before a second consumer freezes onto it.

2. **The write/resume path is UNSCOPED; only the READ path is anti-enumeration-hardened.**
   `scoped_get`/`scoped_list` (`:501,:517`) gate on `owner` and collapse foreign-or-missing to one
   `NotYours`. But `mutate` (`:365`) keys by `id` ALONE — there is no `scoped_mutate`. Authorization
   before a mutation is entirely the consumer's responsibility (A2A's front door scopes first). A
   second consumer — especially T3's inbound receiver, which is precisely a "resume a handle by
   correlation id" WRITE — inherits an engine that hardened reads against enumeration and left writes
   open. See seam 4.

3. **`submit` MANDATES a genesis provenance event; `Mutation` makes events optional but
   `SubmitRecord` does not.** `Mutation.event` is `Option<SealedEvent>` (`:123`) — `set_push_callback`
   already submits an event-free mutation (`taskstore.rs:842`). But `SubmitRecord.event` is a
   non-optional `SealedEvent` (`:138`): every `submit` MUST seal a genesis event. A2A always wants one
   (`EV_SUBMITTED`). A second consumer that wants a durable handle WITHOUT a per-event hash chain (a
   plain Responses-stateful row keyed by response id) is forced to synthesize a dummy genesis event.
   That is an A2A assumption ("every handle opens a provenance chain") baked into the neutral submit.

4. **The dual-compile justification is ASSERTED, not yet DEMONSTRATED.** The whole opaque-`Arc<dyn
   Any>` design (and its ergonomic tax — every read is a downcast + clone) exists to survive a future
   `Box<dyn Any>` per-plane core slot that "core reads back" (`handle_engine.rs:16-22`). That slot
   does not exist yet: the only non-test constructor of `DurableHandleEngine` is A2A's `TaskRegistry`
   (`taskstore.rs:504`), a plane-crate static — no busbar-core wiring rides the engine through a
   `Box<dyn Any>`. So the design pays the opacity cost now for a constraint no passing dual-compiled
   test exercises. A second consumer would build on a seam whose central safety claim is promised, not
   proven.

None of these is a redesign — the split holds. They are four rough edges that are far cheaper to
smooth while the engine has exactly one consumer than after voice/Responses freeze byte-behavior onto
it.

### (c) SURFACE-NOW (seam 1)

- **[1] lock-across-I/O in `mutate`/`sweep`/`rehydrate`** — shard to a per-handle lock (or at minimum
  document the constraint + the deliberate submit-vs-mutate asymmetry) before a high-concurrency
  second consumer builds on it.
- **[2] add `scoped_mutate(owner, id, plan)`** — close the read/write asymmetry now; it is the exact
  primitive T3's receiver needs.
- **[3] make `SubmitRecord.event` `Option<SealedEvent>`** — to match `Mutation.event`, so a chainless
  durable handle is expressible without a dummy event.
- **[4] land the dual-compiled `Box<dyn Any>` readback witness** — so the second consumer inherits a
  proven seam, not an asserted one.

---

## Seam 2 — `DurableScope` park-at-202 / resume + `workhandle_open`/`resume` slots

Files: `crates/busbar-substrate/src/plane_host/scope.rs` (`DurableScope`, `:398`);
`crates/busbar-plugin/src/hot/host.rs` (`workhandle_open`/`resume` slots `:430-432`, stubs
`:791-802`); `crates/busbar-plugin/src/hot/pod.rs` (`WorkHandleDesc` `:1361`).

### (a) TODAY

Two DIFFERENT "durable" notions sit here and must not be conflated:

- `DurableScope` (`scope.rs:398`) is a RESOURCE-HANDOFF arena, not a handle registry. Its job is to
  re-home a breaker probe-hold's reclaim from REQUEST end to TASK end (`handoff_settling_to`
  `scope.rs:270`, `settle` `:454`), so a task parked at a 202 does not release its breaker probe when
  the request future drops (the v4 arena bug, documented `:376-395`). It is settle-capable and
  reuses the `DispatchScope` machinery verbatim.
- `DurableHandleEngine` (seam 1) is the ROW registry that actually survives the process.

A parked-at-202 task therefore straddles both: its ROW is durable in the engine; its in-flight
RESOURCES (breaker probe) ride a `DurableScope` owned by the detached runner (dies at task end, NOT
process end). That division is coherent and correctly documented.

The FFI seam for a plane to open/resume a durable work-handle across the host boundary —
`workhandle_open`/`workhandle_resume` (`host.rs:430-432`) — is DECLARED but both stubs still
`unimplemented!()` (`host.rs:791-802`). A2A does not use them: it drives the engine directly in-plane
(`TASKS` static) and persists through the `journal_*` host family. So the FFI resume path is
reserved, not wired.

### (b) WITH CHANGES

For a second consumer the landscape is confusing: THREE overlapping durable primitives with no
signpost — the in-plane `DurableHandleEngine`, the `journal_*` host vtable family
(`host.rs:489-503`), and the stubbed `workhandle_open`/`resume` slots. A2A picked "engine + journal_*"
and skipped workhandle_*. A voice/Responses author has no doc telling them which to reach for or why
A2A skipped one. That ambiguity is the real risk, not a defect in any one primitive.

### (c) SURFACE-NOW (seam 2)

- **[5] signpost the three durable primitives** (engine vs `journal_*` vs `workhandle_*`) — one
  paragraph on which a new consumer uses and why A2A does not touch `workhandle_open`. Clarity, not
  correctness.
- Otherwise: none. `DurableScope`'s handoff/settle mechanics are sound and well-tested.

---

## Seam 3 — `WorkItem{ InboundKind::Stream, EmitKind::Unsolicited }` (D1 lock)

File: `crates/busbar-plugin/src/hot/workitem.rs`; witness
`crates/busbar-plugin/src/hot/tests/workitem_tests.rs:31`.

### (a) TODAY

The carrier CAN represent a duplex inbound + unsolicited emit without a reshape, and the witness is
present and green: `workitem_can_represent_duplex_session` (`workitem_tests.rs:31`) builds
`InboundHandle::stream(7)` + `EmitHandle::new(EmitKind::Unsolicited, 9)` and asserts the independent
tags. `InboundKind::Stream` (`workitem.rs:31`) and `EmitKind::Unsolicited` (`:47`) are declared from
day one; the `#[repr(C)]` sized/versioned `WorkItem` (`:150`) with independent kind-tagged in/out
handles means a new carrier is an append-only discriminant + trailing slot, never a `dispatch`
reshape. `all_reserved_kinds_are_declared` (`workitem_tests.rs:44`) is the compile-time
exhaustiveness keystone. This seam is in good shape — the D1 witness holds.

### (b) WITH CHANGES

Representation is not plumbing. There is NO host vtable slot that actually EMITS an unsolicited frame
— grep of `host.rs` finds only `metrics_emit`; there is no `emit_unsolicited`/`push_emit` fn, and
`egress_write` is for governed egress, not a session push channel. So `EmitKind::Unsolicited` is a
reserved SHAPE the carrier can name but the host cannot yet service. That is exactly the intended
"declare all tags now, wire later" posture, and correct for a keystone — but a second consumer (voice,
or the T3 receiver resuming a session) that wants to actually PUSH will find the emit slot missing.
Flag it so it is a known append-only add, not a surprise.

### (c) SURFACE-NOW (seam 3)

- None for the carrier itself — the witness holds and the shape is reshape-proof. Note only (not a
  fix): the host emit slot for `Unsolicited` is a future append-only add; it does not exist today.

---

## Seam 4 — the PLANNED inbound webhook RECEIVER (T3, net-new vs LiteLLM)

Files (what exists today): `crates/busbar-core/src/export/webhook.rs` (OUTBOUND only); ingress /
arrival `crates/busbar-llm/src/native_ingress.rs`, `arrival.rs`; the resume seam
`host.rs:430-432` (stub).

### (a) TODAY

There is no inbound receiver. `export/webhook.rs` is a fire-and-forget OUTBOUND POST behind the SSRF
guard (`webhook.rs:132` `deliver_logs`) — it never accepts a request. A2A's push-notification path is
also outbound (register a callback URL, `set_push_callback` `taskstore.rs:825`; deliver to it). So a
provider/peer calling BACK into busbar (LiteLLM-style async callback, an A2A push receiver, a voice
event) has nowhere to land.

### (b) WITH CHANGES — what a receiver must hook into, and its security surface

A receiver must: (1) ARRIVE at the ingress/arrival path and be authenticated by the inbound-identity
seam (the host auth chain / `guard_url`), then (2) CORRELATE the inbound to a parked handle and RESUME
it — i.e. look the handle up in `DurableHandleEngine` by correlation id and `mutate` it, ultimately
via the `workhandle_resume` slot once that stub is wired.

Security surface — this is a WRITE-BY-CORRELATION-ID from an untrusted third party, the inverse of
the outbound SSRF posture, and it lands squarely on seam-1 finding [2]:

- **Owner scope on resume.** `scoped_get` gives reads a non-distinguishing `NotYours`, but `mutate`
  is UNSCOPED (`handle_engine.rs:365`). A receiver that resumes purely by correlation id, with no
  owner check, lets anyone who can guess/replay a correlation id poke another tenant's handle. The
  read path is enumeration-hardened; the resume path must not reopen the hole. This is why
  seam-1 [2] (`scoped_mutate`) should land NOW — the receiver is its first real caller.
- **Unguessable correlation ids** — the id is the capability, so it must be high-entropy, not a
  monotonic/sequential handle id.
- **Caller authenticity + replay** — HMAC signature / bearer verification and a nonce/replay window,
  before the correlation lookup, so a spoofed callback cannot drive a resume.
- **Anti-enumeration on the receiver's own 404/403** — a resume for a missing OR foreign handle must
  return one indistinguishable refusal, mirroring `scoped_get`, or the receiver becomes the
  enumeration oracle the engine's read path deliberately is not.

### (c) SURFACE-NOW (seam 4)

- **[2] (again) add `scoped_mutate` to the engine now** — the receiver is the write-by-id path the
  unscoped `mutate` was never hardened for; do not let T3 bolt an owner check on per-site.
- Otherwise the receiver is net-new build, not an extraction defect — captured here so its
  security surface (auth-then-correlate-then-scoped-resume, unguessable id, replay window,
  indistinguishable refusal) is on record before it is built.

---

## Ranked SURFACE-NOW (global — fix before a second consumer builds on the fresh engine)

1. **`mutate`/`sweep`/`rehydrate` hold the process-wide `handles` Mutex across durable store I/O**
   (`handle_engine.rs:373`→`:292`→`:274/:282`; contrast `submit`'s pre-lock writes `:320-347`). A2A
   tolerates it; a concurrent second consumer (voice, Responses-stateful) hits a process-wide
   bottleneck. Shard to a per-handle lock, or at minimum document the constraint and the deliberate
   submit-vs-mutate asymmetry. *(engine, throughput — highest because it is the hardest to change
   once a second consumer's concurrency depends on the current semantics.)*
2. **Add `scoped_mutate(owner, id, plan)` — the write path is unscoped while the read path is
   anti-enumeration-hardened** (`scoped_get` `:501` vs `mutate` `:365`). It is T3's inbound receiver's
   exact primitive (seam 4); cheap to add while fresh. *(engine, security.)*
3. **Make `SubmitRecord.event` `Option<SealedEvent>`** (`:138`) to match `Mutation.event` (`:123`), so
   a durable handle without a per-event chain (Responses-stateful) is expressible without a dummy
   genesis event. *(engine, ergonomics — an A2A assumption in the neutral submit.)*
4. **Land the dual-compiled `Box<dyn Any>` readback witness** — the opacity design's central claim is
   asserted, not demonstrated (no core slot rides the engine today; only constructor is
   `taskstore.rs:504`). Prove it before a second consumer inherits it. *(engine, correctness
   assurance.)*
5. **Signpost the three overlapping durable primitives** — `DurableHandleEngine` vs the `journal_*`
   host family (`host.rs:489-503`) vs the stubbed `workhandle_open`/`resume` (`host.rs:791-802`) — so
   a new consumer knows which to use and why A2A skips `workhandle_*`. *(docs/clarity.)*
6. **Reconcile the extraction notes with what shipped** — `docs/design/1.6.0-handle-engine-extraction-notes.md`
   still describes `HandleUpdate`/`apply`/`sweep`/`advance_cursor`/`touch_meta`/`get_scoped` as the
   public API, but the landed engine ships `Mutation`, a single `mutate` that subsumes
   apply/transition/cursor-advance/touch, `scoped_get`, and an added `MutateError`/`Rejected` domain
   arm. *(docs drift.)*

Seam 3 (WorkItem duplex) needs no surface-now: the D1 witness holds and the shape is reshape-proof;
only note that the host emit slot for `Unsolicited` is a future append-only add.
