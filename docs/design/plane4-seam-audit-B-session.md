# Plane 4 — SEAM AUDIT B: session lifecycle & continuous governance

Status: **READ-ONLY ADVERSARIAL AUDIT.** No code changed. This doc is the only write.
Owner: Matthew. Companion to `docs/design/plane4-duplex-session.md` (the authoritative design) and
`docs/design/plane4-duplex-session-1.6.0-plan.md` (the execution plan). This audit pressure-tests the
five session/lifecycle seams that the plan wires out in T1, ranks what must be fixed *before* the
one-way doors close, and delivers a decisive verdict on the **D2 metering-lease shape** — the single
ABI freeze this release cannot take back.

**Citation base (IMPORTANT — differs from the plan's).** Every `crates/…:NNN` below is verified
against commit **`e393b9e6`** (`busbar 1.6.0 integration base-fix`), the tree this audit reset to.
The plan and design cite `integration/plane-extraction`, whose line numbers drift from `e393b9e6`;
where a number differs I use the `e393b9e6`-verified one. Note the extraction is mid-flight: `scope.rs`
and `plane_host/mod.rs` exist in **both** `busbar-core` and `busbar-substrate` at this commit; the
design targets the `busbar-substrate` copies and so does this audit.

**Headline (read this first).** The D2 lease signatures **should NOT be frozen as written** in
plan §B.1 / design §6-D2. The two-trailing-`Option`-slot *mechanism* is sound and append-only-safe,
and the `MagnitudePod` correction the plan already made is correct as far as it goes — but two of the
four defects below are **signature-level, not implementation-level** (the reserve *denomination*, and
whether `out_exhausted` is even answerable by the type it drives). The plan's own "audit-and-improve
before it freezes" clause (§A build principle) exists for exactly this. Fix the shape first; then freeze.

---

## Seam 1 — `SessionScope` (+ `DurableScope` park/resume)

### (a) TODAY
- `SessionScope` is an **empty** `#[derive(Default)] #[non_exhaustive] pub struct SessionScope {}`
  (`crates/busbar-substrate/src/plane_host/scope.rs:364-366`) with one constructor `new()` returning
  `SessionScope {}` (`:368-373`). Its doc: *"the riders that add a duplex/session plane wire this out …
  until then it exists only to NAME the scope in the hierarchy so a future add is append-only"*
  (`:361-363`).
- **Nothing constructs or reads it.** `git grep SessionScope` across the tree returns only the two
  re-exports (`plane_host/mod.rs:53`, core copy `plane_host/mod.rs:51`), the taxonomy doc lines, and
  its own definition — verified. It is genuinely dormant.
- The RAII machinery it will lean on lives on a **different** type: `DispatchScope::register_pipe(reclaim)
  -> PipeId` (`scope.rs:302-311`), `register_lease` (`:314`), `reclaim_all` LIFO (`:334-349`), and
  `impl Drop for DispatchScope` (`:352-356`). `DurableScope` **embeds** one — `arena: DispatchScope`
  (`scope.rs` DurableScope struct, field `arena`) exposed via `arena() -> &DispatchScope` (`:462`).
  `SessionScope` embeds **nothing**.

### (b) WITH CHANGES
The plan (§B.4) wires it to `{ client_pipe: PipeId, upstream_pipe: PipeId, lease: CostHold,
journal_scope: String }`, all owned/neutral types, correlation table held plane-side. Because the struct
is `#[non_exhaustive]` and unconstructed, the field add is genuinely append-only — no caller breaks. The
field *types* are neutral (no `CallRef` leak). So far the plan holds.

But the field set as listed **does not close the RAII story the design promises** ("SessionScope::Drop
reclaims lease + pooled socket", design §3.2). Two structural gaps:

### (c) SURFACE-NOW
1. **[HIGH] The field set omits the owning `DispatchScope` arena — so the promised Drop-reclaim cannot
   fire.** A `PipeId` is a bare `u64` handle into a `DispatchScope`'s registry (`scope.rs:302-311`);
   storing `client_pipe: PipeId` / `upstream_pipe: PipeId` stores *handles*, not the arena that reclaims
   them. `SessionScope` today has no arena and no `Drop`. For "the connection closes → reclaim the pooled
   socket" to hold, `SessionScope` must **embed a `DispatchScope`** (exactly as `DurableScope` does,
   `scope.rs:462`) and register the pipes into *its own* arena, and gain an `impl Drop` (or rely on the
   embedded arena's `Drop`, `:352-356`). The plan's `PipeId`-only field list is under-specified; fix the
   field set to `{ arena: DispatchScope, client_pipe, upstream_pipe, lease, journal_scope }` **before**
   the shape is inherited as the session model every future duplex plane copies (plan §D one-way door).

2. **[HIGH] `lease: CostHold` does not refund on Drop — the abnormal-close path leaks the reservation.**
   `CostHold` has **no `Drop`**; its refund is `finalize(self) -> Settlement` (`cost.rs:334`), a by-value
   consume that *returns* the refund for the caller to apply to the budget cell — and `CostHold` "carries
   no clock and no cell" (`cost.rs:298`). So dropping a `SessionScope` on disconnect/cancel/panic drops
   the `CostHold` **without finalizing**, and the up-front reserve is never returned to the cell. The
   design's "Drop reclaims lease" is not free: `SessionScope::Drop` must explicitly `finalize()` the lease
   **and** hold (or reach) the budget cell to apply the `Settlement`. This is the leak-safety keystone the
   scope taxonomy exists to protect (`scope.rs:15,22`) and must be designed into the wire-out, not assumed.

3. **[LOW] Two `SessionScope` copies (core + substrate) during extraction.** The design/plan target
   `busbar-substrate::…::SessionScope` but `busbar-core::…::SessionScope` still exists (`crates/busbar-core/
   src/plane_host/scope.rs:7`, re-export `:51`). Wire out **one** (substrate) and confirm the core copy is
   dead before a rider binds it, or the "which SessionScope" ambiguity gets frozen into two divergent shapes.

`DurableScope` (park-at-202/resume) is in better shape: it owns its arena, its Drop story is real, and
its doc already names the async-park pattern (`scope.rs:376-379`). No SURFACE-NOW item for it beyond the
T1.8 lift concerns, which are out of this audit's session scope.

---

## Seam 2 — `run_gauntlet` + `GauntletPlane` (does the `Response` return foreclose the session sibling?)

### (a) TODAY
- `run_gauntlet` is a **free `async fn`** — `run_gauntlet(req: GauntletRequest<'_>, plane: Box<dyn
  GauntletPlane + '_>) -> axum::response::Response` (`plane_host/mod.rs:185-193`). Its whole body is
  `match plane.verify_destination(&req) { Refuse(resp) => resp, Proceed => plane.drive(req).await }`.
- `GauntletPlane` is a **trait** (`:166`) with `verify_destination(&self, &GauntletRequest) ->
  VerifyOutcome` (`:169`, sync, `&self`) and `drive(self: Box<Self>, GauntletRequest<'_>) ->
  Response` (`:175`, async, **consumes `self`**).
- `GauntletRequest<'a>` is **borrowed** (`:133`), carrying `gov`/`destination`/`correlation_id`/
  `charged_at`.

### (b) WITH CHANGES
Plan §T1.6/§B.5 adds an append-only sibling `run_gauntlet_session(req, plane) -> Result<SessionScope,
Response>`. **Verdict: the `Response` return does NOT foreclose the sibling.** `run_gauntlet` is a free
fn and `GauntletPlane` a trait; nothing inlines them, nothing makes the one-`Response` shape the only
one — the design D3 hazard ("a 1.6.0 simplification that inlines run_gauntlet") has **not** materialized
at `e393b9e6`. The sibling is a clean add beside them.

### (c) SURFACE-NOW
1. **[MEDIUM] The plan overstates "reuses the same verify_destination-before-charge sequence." The
   *charge* is inside `drive`, which the sibling must NOT call.** In `run_gauntlet` the admission/reserve
   (the "charge") happens inside `plane.drive` (stages 4+5) — the sibling can reuse `verify_destination`
   (`&self`, cheap, non-consuming) for the open pass, but `drive(self: Box<Self>)` **moves and consumes**
   the plane and returns a `Response`, which is the once-through model. So session-open's budget
   *reservation* is **net-new code**, not a reuse of `drive`. That is fine (append-only), but the plan/
   design should stop describing it as reusing the existing charge path, and should decide **where the
   opening `cost_reserve` fires** — it cannot ride `drive`.
2. **[MEDIUM] Lifetime: `SessionScope` must be fully owned; it cannot borrow from `GauntletRequest<'a>`.**
   A 20-minute session outlives the request. `verify_destination` takes `&GauntletRequest` and `drive`
   takes `GauntletRequest<'_>` (borrowed). The returned `SessionScope` must own everything (owned
   `PipeId`/`CostHold`/`String` — the plan's types are all owned, good), and the sibling must **extract
   owned data at open** rather than hold the borrow. Pin this in the sibling's signature so no borrow
   escapes into the session handle.
3. **[LOW] `drive`'s `self: Box<Self>`-by-move is the right shape for once-through and is worth keeping**
   — it is *why* a session needs a sibling rather than an overload. No fix; a note so a future
   "unify drive and drive_session" refactor does not collapse it.

---

## Seam 3 — the PER-FRAME BUDGET LEASE (D2) — **THE ONE-WAY DOOR**

### (a) TODAY
- `CostHold` (`crates/busbar-core/src/plane/cost.rs:303-341`): two private fields `reserved: CostAmount`,
  `settled: CostAmount`. API surface is exactly `reserve(estimate: CostAmount, fee: CostAmount)` (`:312`),
  `reserved() -> CostAmount` (`:320`), `settle_partial(&mut self, exact: &CostBreakdown)` which does
  `self.settled = self.settled + exact.total()` (`:327-329`), and `finalize(self) -> Settlement` (`:334`).
  `CostAmount` is `u128` nanodollars (`:41`). **No `settled()`, no `remaining()`, no `is_exhausted()`,
  no `Drop`.**
- `Magnitude` (`:269-277`): `unit: &'static str` (`:272`, **not FFI-POD**), `amount: u64` (`:274`, a count
  of the unit, *not* nanodollars), `caller_cap: Option<u64>` (`:276`).
- **Both types are entirely unwired.** `git grep` finds **zero** production consumers of `Magnitude` and
  **zero** of `CostHold` outside `cost.rs` and its own `tests/cost_tests.rs` (verified). The reserved
  vtable point is only a comment — `hot/host.rs:533-536`: *"add `cost_reserve`/`cost_settle` as trailing
  `Option` slots below this line and bump the airlock MINOR"* (echoed `hot/pod.rs:636-638`). `ABI_MINOR = 18`
  (`crates/busbar-plugin/src/lib.rs:72`); the last cluster `gate_decide` is minor-18 (`host.rs:526-532`).
- The plan's D2 slots (`CostReserveFn`/`CostSettleFn`/`MagnitudePod`/`CostLeaseId`) do **not** exist:
  `git grep` for all four returns nothing but the reserved comment.

### (b) WITH CHANGES
Plan §B.1 appends `cost_reserve`/`cost_settle` as trailing `Option<extern "C-unwind" fn>` slots at
minor-19, driving `CostHold`, with a `MagnitudePod` POD projection of `Magnitude` (correct: `unit:
&'static str` cannot cross FFI). The **mechanism** — trailing `Option` slots under the sized/versioned
`AbiPreamble`, opaque-id lease surviving host re-mint (see Seam 4), opaque `CostBreakdown` suffix — is
append-only-safe and matches the minor-9 journal precedent. Nothing here is disputed.

The **shape driven across that mechanism is not yet right.** Because the slot freezes at minor-19 and a
reshape is then a breaking MAJOR (plan §D), the following must be resolved first.

### (c) SURFACE-NOW — the D2 verdict, ranked (this is the audit's most important output)

**VERDICT: do NOT freeze §B.1 as written. The mechanism is sound; the signature is not. Four defects,
two of them signature-level:**

1. **[CRITICAL, signature-level, one-way door] The reserve is denominated in the WRONG type; the
   Magnitude→nanodollar pricing bridge is undefined and contradicts core doctrine.** `CostReserveFn`
   carries `magnitude: *const MagnitudePod` — a coarse **unit count** (`amount: u64` of `"audio_seconds"`/
   `"tokens"`). But the type it drives, `CostHold::reserve`, takes `estimate: CostAmount` — **`u128`
   nanodollars** (`cost.rs:312,41`). Converting a unit count to nanodollars is **pricing**, and core
   "prices nothing and interprets no label" (`cost.rs:9`). So the frozen slot either (i) makes the *host*
   price the magnitude — a direct violation of the no-pricing rule and the neutrality thesis — or (ii)
   expects the *plane* to pre-price, in which case the slot should carry a **nanodollar `CostAmount`
   scalar, not a `MagnitudePod`**, and `Magnitude` has no place in the reserve signature at all. The
   design (§3.1) conflates the caller-cap refusal (a *unit-space* check `amount` vs `caller_cap`) with the
   nanodollar reserve (`CostHold`); these are two different mechanisms fused into one slot. **Decide which
   side prices before minor-19 freezes**; the choice changes the frozen argument type. That `Magnitude`
   has zero consumers today means nothing has ever forced this question — the slot would be its first, and
   its last chance to be right.

2. **[CRITICAL, semantics-level, one-way door] `out_exhausted` has no backing in `CostHold`, and the
   reserve/settle money-flow structurally cannot surface a mid-session "cell dry."** The frozen
   `CostSettleFn.out_exhausted: *mut bool` means "budget dry ⇒ plane hard-closes" (design §6-D2) — the
   entire reason D2 exists over post-hoc `meter_charge` (design §3.3). But: (i) `CostHold` exposes
   `reserved()` and nothing else — **no `settled()`, no `remaining()`, no `is_exhausted()`** — so the host
   has no in-type signal to answer the readback; and (ii) the model debits `reserved` from the cell **once,
   up front**, accrues `settled` internally, and reconciles only at `finalize()` (`cost.rs:334-340`) — so
   the cell is *already drained by the reserve* and settle touches no cell. A mid-session "cell dry"
   therefore **cannot** be derived from `settle_partial`; the only exhaustion signal available is
   `settled ≥ reserved`. That is meaningful as a hard cap **only if `reserved` is set to exactly the
   available budget** — which directly contradicts the design's repeated instruction to reserve a *"coarse
   over-estimate"* (§3.1, §3.3, `cost.rs:268` "accuracy comes from the exact settlement, not this coarse
   estimate"). An over-estimated reserve makes `out_exhausted` fire **late** — after true spend has passed
   the real budget, up to the over-estimate margin. **Pin the semantics before freeze:** define `reserved`
   = true remaining budget (drop "over-estimate" for the *session* lease), add `is_exhausted()`/`remaining()`
   to `CostHold`, and specify `out_exhausted := settled ≥ reserved`. (The `CostHold` method add is a
   non-ABI Rust change, safe anytime — but the *meaning* of the frozen `out_exhausted` bit must be fixed now.)

3. **[HIGH, one-way door] The opaque-breakdown-suffix settle is the wrong hot-path shape for the very
   "high-rate carrier" the slot is justified by.** `CostSettleFn` forces the plane to serialize a full
   itemized `CostBreakdown` and the host to parse it — per settle — to recover a single `u128 total`
   (`cost.rs:249,327`). For the *shipped* voice model this is a non-issue: settle fires per
   `response.done.usage` (per turn, seconds apart), not per audio frame — the plan itself confirms this,
   and the design's per-frame loop (§3.2) fires `cost_settle` only "on Usage." **But the slot's stated
   reason to exist is a future kHz-rate carrier** (`host.rs:20`, plan §T1.5), and for that case a
   serialize+parse-per-frame just to read a total is exactly the cost the plan asked to audit. Cheap
   insurance available only before freeze: add a `total_nanos: u128` scalar to `CostSettleFn` so the host
   accrues in O(1) and treats the `CostBreakdown` suffix as **audit-only / optional**. This keeps
   itemization for the audit tap while removing the parse from the hot path — and it costs one scalar now
   versus a MAJOR bump later.

4. **[MEDIUM] `MagnitudePod.caller_cap: u64` with `0 = none` silently loses `Some(0)`.** `Magnitude.
   caller_cap` is `Option<u64>` (`cost.rs:276`); a declared cap of exactly `0` (refuse-all) collapses into
   the "no cap" sentinel. Probably benign, but it is a lossy projection frozen into the ABI. Carry a
   `caller_cap_present: bool` (or `u8` flag) beside the scalar, or document `Some(0)` as unrepresentable.

**What is genuinely fine and should ship unchanged:** the two-trailing-`Option`-slot mechanism; the
opaque-id `CostLeaseId` (it is the *right* choice — see Seam 4, it survives host re-mint); the append-only
minor 18→19 bump; the plane-side `finalize`/refund staying off the ABI. The freeze blocker is the four
items above, not the mechanism.

---

## Seam 4 — `LiveHostFactory` (per-frame host re-mint)

### (a) TODAY
- `LiveHostFactory = Arc<dyn Fn() -> Arc<dyn EngineHost> + Send + Sync>` (`plane_host/mod.rs:223`):
  *"each call returns a host reading the current snapshot, so a config swap between calls is seen. Handed
  to transports that re-mint per frame."*
- Proven in production by MCP stdio: `Session<W>` holds `factory: LiveHostFactory` (`crates/busbar-mcp/
  src/mcp/stdio_serve.rs:388`) and re-mints per frame — `let host = (self.factory)();` (`:522`), and even
  the auth/identity path re-calls `factory()` fresh (`:139,154,180`). Session state that must survive
  re-mint (the single write lock `out: Mutex<W>` `:393`, the `inflight` cancel table `:399`, the `pending`
  correlation table `:401`) lives on `Session<W>`, **not** on the re-minted host.

### (b) WITH CHANGES
Voice re-mints identically so mid-session budget/key rotation is seen on the next frame. The pattern
carries over cleanly — the substrate pump (plan §T1.3) becomes the `Session<W>` analog and holds the
per-connection state (which, post-wire-out, is `SessionScope`).

### (c) SURFACE-NOW
1. **[POSITIVE — reinforces the D2 opaque-lease choice, no fix]** Because the host is re-minted every
   frame and carries **no** per-session state, the metering lease **cannot** live on the host object — it
   must live in durable host/engine-side state keyed by an opaque id. This is exactly what the D2
   `CostLeaseId` (opaque `u64`, resolved host-side) provides: any re-minted host resolves the same lease.
   Had D2 tried to hand back a `&mut CostHold` or a borrowed handle, per-frame re-mint would have broken
   it. So keep `CostLeaseId` opaque-by-id (Seam 3 verdict item: this is the part that is *right*).
2. **[LOW] Re-mint allocates a fresh `Arc<dyn EngineHost>` per frame.** At voice frame rates (~50/s/dir
   for 20 ms audio) this is negligible; at a hypothetical kHz carrier it compounds with the D2 hot-path
   cost (Seam 3 item 3). Not a freeze concern — `LiveHostFactory` is a Rust type, reshapeable anytime —
   but note it lives on the same high-rate axis the D2 audit flags.

---

## Seam 5 — the AUDIT CHAIN (`journal_append_scoped`)

### (a) TODAY
- `JournalAppendScopedFn` (`hot/host.rs:220-227`): `(host, kind_id: u32, scope_ptr/len, content_ptr/len)
  -> Seq`. The host **mints seq/prev_hash/hash via the ONE core chain**, frames the prelude in the
  stream's registered framing, joins the plane's **opaque pre-framed content suffix**, digests, persists,
  and returns the assigned `Seq` (or `Seq::NONE` fail-closed) (`:215-227`). Registration is via
  `JournalRegisterFn` + a plane-provided `JournalReframeFn` (`:194-214`); boot rehydrate via
  `JournalRestoreFn` (`:244-248`). This is the minor-9 durable-journal family (`host.rs:180-185`).
- Core "names no plane type"; the plane owns only its record shape, carried as the opaque suffix
  (`host.rs:184-185`).

### (b) WITH CHANGES
Per-session chain under one `String` scope `"session-<id>"` (plan §T1.4/§B.5). This is a **direct fit** —
the seam is already keyed by `(kind_id, String scope)` and already mints the hash chain host-side; a
session is just a new scope value. No signature change, no new slot. Boot-restore of a session's chain
rides the existing `JournalRestoreFn`. This is the healthiest of the five seams.

### (c) SURFACE-NOW
1. **[LOW] Per-append the host mints a chain link + persists — audit at true per-audio-frame rate would
   be heavy.** As designed this is a non-issue: the design journals only "on Usage" (per turn, §3.2), same
   cadence as `cost_settle`. Flag only so no future change starts journaling per audio frame (24 kHz) and
   turns the one-chain-authority + durable-write into the session's throughput ceiling. No shape fix.
2. **[NONE otherwise.]** The scope-string keying, opaque-suffix carriage, single-chain-authority, and
   restore path all accommodate the per-session model without a one-way-door decision.

---

## Overall ranked SURFACE-NOW list (fix before the corresponding door closes)

| # | Sev | Seam | Concern | Door |
|---|-----|------|---------|------|
| 1 | **CRITICAL** | 3 (D2) | Reserve denominated in `MagnitudePod` (unit count) but drives `CostHold::reserve` (nanodollars); the pricing bridge is undefined and would force the host to price — violating core's no-pricing rule. Decide who prices; the choice changes the frozen arg type. | minor-19 freeze |
| 2 | **CRITICAL** | 3 (D2) | `out_exhausted` has no backing accessor on `CostHold`, and the debit-up-front/refund-at-finalize flow cannot surface a mid-session "cell dry"; only `settled ≥ reserved` is available, which conflicts with the mandated "coarse over-estimate." Pin the semantics + add `is_exhausted()`/`remaining()`. | minor-19 freeze |
| 3 | HIGH | 3 (D2) | Opaque-`CostBreakdown`-suffix settle forces serialize+parse-per-settle to read one `u128 total` — wrong hot-path shape for the "high-rate carrier" the slot exists for. Add a `total_nanos: u128` scalar; make the suffix audit-only. | minor-19 freeze |
| 4 | HIGH | 1 | `SessionScope` wire-out field set omits the owning `DispatchScope` arena, so the promised Drop-reclaim of the pooled socket cannot fire; and `lease: CostHold` has no `Drop`, so an abnormal close leaks the reservation (finalize never runs). | `SessionScope` shape (`#[non_exhaustive]`) |
| 5 | MEDIUM | 3 (D2) | `MagnitudePod.caller_cap: u64` with `0 = none` loses the `Some(0)` (refuse-all) case. | minor-19 freeze |
| 6 | MEDIUM | 2 | Plan overstates reuse: the opening *charge* lives in `drive` (consumed, returns `Response`), which the session sibling cannot call — session-open reserve is net-new; decide where `cost_reserve` fires. | `run_gauntlet_session` add |
| 7 | MEDIUM | 2 | `SessionScope` must be fully owned; ensure no borrow from `GauntletRequest<'a>` escapes into the 20-min handle. | sibling signature |
| 8 | LOW | 1 | Two `SessionScope` copies (core + substrate) mid-extraction; wire out exactly one. | before a rider binds |
| 9 | LOW | 4 / 5 | Per-frame re-mint alloc and per-append chain-mint are fine at per-turn cadence; guard against a future change moving them to per-audio-frame (kHz). | not a freeze door |

**Non-foreclosures confirmed (good news):**
- `run_gauntlet`'s `Response` return does **not** foreclose the session sibling — it is a free fn + trait,
  un-inlined at `e393b9e6` (Seam 2). D3 vigilance is holding.
- `LiveHostFactory` re-mint accommodates the per-frame model and actively **validates** the D2 opaque-id
  lease choice (Seam 4).
- `journal_append_scoped` accommodates the per-session chain with no ABI change (Seam 5).
- The D1 `WorkItem` carrier tags are present and wired: `InboundKind::Stream` (`workitem.rs:31`) +
  `EmitKind::Unsolicited` (`:46-47`, *"WIRED for duplex-session"*) — not collapsed to `(ptr,len)+sink`.

**The single most important output:** freeze D2 (items 1–3, 5) only after resolving the reserve
denomination and the `out_exhausted` semantics. Those two are signature/meaning decisions, not
implementation details, and the plan's "audit-and-improve the seam before it freezes" clause names this
exact obligation. The mechanism is right; the shape is one editing pass away from right — and after
minor-19 ships, that pass is a breaking MAJOR.
