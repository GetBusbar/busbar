# busbar — Architecture Audit Log (history; NOT the design)

> The design is `ARCHITECTURE.md` v1.0. This file is the provenance trail: the v0.1–v0.5 drafts with
> their deltas (Δ, D, C, R), three rounds of independent adversarial review (two models each, fresh
> eyes every round), and every closure. Builders do not read this file. Auditors may.
>
> Round 1 — Opus 24 findings / Fable 23 → closed in Part 16 (C1–C20).
> Round 2 — Opus 12 blockers + 17 gaps / Fable 10 + 16 → closed in Part 17 (R1–R41).
> Round 3 — Opus 14 blockers + 13 gaps / Fable 8 + 10 → closed directly in ARCHITECTURE.md v1.0 (map
> in the final section of this file).

---

# busbar — The Plugin Architecture (v0.5 — rounds 1 and 2 closed; awaiting round-3 fresh-eyes audit)

> **`busbar.exe` (core) is the only thing that runs. Everything else is a plugin. Core registers
> plugins and drives them. Plugins are passive, return data, and never call core.**
>
> v0.2 = v0.1 stress-tested. §2 lists the strain points found and the hardening each forced.
> §3 is the full trait design that survives them. §6 is the parallel decomposition.

---

## Part 0 — The universal principle (every plugin kind)

1. **Core is `busbar.exe`** — the hub, the runner, the only active thing.
2. **Everything else is a plugin** — plane, auth, store, secret, hook. None "runs"; core calls them.
3. **Each plugin KIND is exactly one trait** shared by all its implementations.
4. **Core registers 0…N per kind** (from config) and **calls by kind**. Zero and a hundred are both valid.
5. **Plugins are passive**: take a read-only `Ctx`, do kind-specific work, **return data**. Core acts.
6. **One-way edge: core → plugin. NEVER plugin → core.** *(Structural for static plugins. For
   dynamically loaded plugins the boundary is the mandatory signature and the operator's key set —
   C7; a loaded dynamic plugin is inside the trust boundary.)* A plugin reaching back (even via a "neutral"
   seam) is the central bug. Everything a plugin needs arrives in `Ctx`.
7. **Callers are blind** to which plugin answered (github/ldap, sqlite/postgres, openai/anthropic).

**Consequence:** every core concern — billing, metering, admission, audit, persistence, identity —
has **exactly one implementation, in core.** No plugin can skip or reimplement it: it never touches it.

**The load-bearing refinement (found in validation, §2.5):** for the governance verbs, a plane does
NOT decide — it **extracts protocol-specific FACTS**; **core makes the ONE decision.** This is what
makes "there is JUST billing" literally true rather than aspirational.

---

## Part 1 — Plugin kinds (each = one trait, core-driven)

| Kind | Trait | Plugin does | Core does |
|---|---|---|---|
| **Plane** | `Plane` | translate one transport/protocol ↔ neutral `Unit`; extract per-step facts | drive the pipeline; **decide + do** billing/admission/audit/routing on the facts |
| **Auth** | `AuthPlugin` | resolve a candidate credential → outcome | run the chain; apply the principal |
| **Store** | `Store` | persist/read neutral records | call it for every durable op; own ledger/audit semantics |
| **Secret** | `SecretProvider` | `secret_ref` → secret | inject where needed |
| **Hook** | `Hook` | observe/gate/transform at a point | invoke at the pipeline point; enforce verdict |
| **Transport** | `Transport` (Part 12) | move bytes in ONE framing — HTTP req/resp · SSE · WebSocket duplex · gRPC · stdio — accept/read/write/close; knows **no** protocol | own every listener + connection; route an arrival to the plane that claims it; pump duplex frames; **gauntlet-before-accept is the loop's order, once** |

**Today:** `Store` (ABI, `crates/api/src/store.rs:950`) and auth already conform — core calls them,
they don't call core. **Planes are the lone outlier** (no trait; 13-slice `EngineHost` callbacks;
43-field `PlaneDecl`). The work is to bring planes to the model the rest already prove.

---

## Part 2 — Validation: where the pure model strains, and the hardening each forced

Each item below is a place the v0.1 "7 linear calls" story would have broken in practice.

| # | Strain point | Hardening (now in §3) |
|---|---|---|
| 2.1 | **Long-lived sessions** (voice; streaming). "7 calls then done" doesn't fit a connection that lives for N turns. | (v0.4, C5) A connection is not a unit; it is a transport yielding frames. The plane delimits **units** from frames; **every unit runs all 7 steps** — client turns, provider-initiated units, and kernel Tick units alike. A streamed response is one unit with N frames (accrue, settle once). There is no session loop and no "open-steps once". |
| 2.2 | **Duplex** (client↔provider). "transport→bytes→egress" is one-directional. | **Core owns BOTH sockets and pumps both directions.** The plane is a per-frame codec + fact-extractor. No plane holds a socket. |
| 2.3 | **Failover/retries inside Route** (try lane A, then B, cap N, only before first byte). | `route()` returns a **`RoutePlan` (candidate destinations, as data)**; **core's route loop** iterates it with breaker + failover + egress I/O, calling `encode_egress(unit, dest)` **per attempt**. |
| 2.4 | **Where does protocol translation live?** It's not one of the 7 verbs, yet it's the plane's main job. | The trait has **two method families**: **translation** (decode_ingress / encode_egress / decode_response / encode_response / encode_refusal) and **governance facts** (the 7 verbs). Both core-driven. |
| 2.5 | **Who decides?** If `plane.admit()` returns `Allow`, the plane is deciding governance — a plane-private policy by the back door. | **Facts vs. decide.** Each step on the plane returns **facts or locators** (`CredentialLocator`, `DestinationFacts`, `AdmitFacts`, `UsageLocator`…); **the unit that owns the step decides** (auth, trust, scope, admission, egress, usage/ledger, audit), and the kernel only sequences (D-A/D-B). A plane cannot decide billing/admission because it never returns a decision, an amount, or a credential. |
| 2.6 | **Short-circuit refusals** (Verify fails → 403 *before* Admit charges) must be rendered in the plane's dialect. | Core stops at the first refusal and calls `plane.encode_refusal(refusal)`; the plane renders its native 401/403/429. Verify-strictly-before-charge is a property of the core loop's order. |
| 2.7 | **Config-driven Admit** (fee/budget are operator config, not code). | Core reads the key's config/limits and charges/enforces; the plane's `admit()` only supplies **estimated cost + bucket facts**. No fee constant in any plane. |
| 2.8 | **Registration** ("core registers X planes by transport"). | `plane.claims() -> Vec<Claim>` read at boot; core's registry matches an arrival to the one plane whose claim fits. Replaces the 43-field decl. |
| 2.9 | **Byte-identity through migration** — the #1 risk; the money path must not change a wire byte. | **Shadow/differential**: run old + new paths on the same input, diff bytes, cut over only at zero diff; plus the 6 byte-exact oracles + conformance as hard gates per migration commit. |
| 2.10 | **Hot-path performance** (trait-object indirection per step; alloc/timing gates exist). | Facts are small/borrowed (`&Unit`, `Copy` structs); zero-alloc on the hot path; measured against `alloc_gate` + `timing_gate` per migration. |
| 2.11 | **dlopen'd plugins** (stores/hooks via a C ABI) vs a Rust trait. | The Rust trait is **canonical**; the C-ABI is a **projection** of it for dlopen'd kinds (as stores already do). Planes are statically linked; no new FFI. |
| 2.12 | **Session/durable state** (voice `SessionHandle`, codec state). | **The kernel owns the session registry + lifecycle** (open at Unit 0 / close; sessions are node-local — there is no reattach). The plane owns only its **protocol state** (codec/decode) as `PlaneSessionState`, split per direction, passed `&mut` to the two decode methods only (R7/R25). |
| 2.13 | **Hooks** at pipeline points. | Hooks are plugins **core invokes** at fixed points (pre-Admit gate, post-decode tap). Same one-way edge. |

Net: the model holds. The pure "7 linear calls" needed a lifecycle, a translation family, and the
facts-vs-decide split — none of which weaken the principle; all of which make it real.

---

## Part 3 — The `Plane` trait (full design)

*(v0.5 — this block is the contract as corrected by two rounds of fresh-eyes audit; Parts 16 and 17
give the reasoning for each change. Where an earlier paragraph in this document disagrees, THIS block
wins.)*

```rust
/// Transport-level bytes. A frame has NO meaning; only a plane can say where a unit begins and ends.
pub struct Frame { pub bytes: Bytes, pub direction: Direction /* Inbound | Outbound */ }

/// A governed transaction. ONE unit = ONE journal authorization (hold) + ONE settlement, whatever the
/// frame count. Identity: `(principal, client_key)` when the client supplies an idempotency key at the
/// location the plane's Claim declares; otherwise kernel-minted UUIDv7 + principal (R27).
/// THE UNIT HAS NO FIELD THAT CAN HOLD A CREDENTIAL (R4): step 0 strips credentials by the locations
/// the Claim declares, before any plane code runs.
pub struct Unit {
    pub key: IdempotencyKey,
    pub origin: Origin,                      // Client | Provider | Tick | Arrival | Bootstrap
    pub session: Option<SessionId>,
    pub reply_to: Option<IdempotencyKey>,    // provider-initiated REQUEST ↔ client reply correlation (R7)
    /* op, body-IR (credential-free), client correlation label, kernel-owned transport byte counts */
}

/// Everything a plane may READ. Provisioned by the kernel per call. A plane never calls back.
pub struct Ctx<'a> {
    pub clock: &'a dyn Clock,                 // wall + monotonic, kernel's
    pub config: &'a PlaneConfigView,
    pub session: Option<&'a SessionView>,     // resolved principal + session id; PRESENT for every non-one-shot unit
    pub telemetry_labels: &'a Labels,
    // NO handles that perform work (no ledger, no chain, no breaker, no store, no egress, no secret).
    // NO &mut: per-session plane state is an explicit parameter on the three methods that need it.
}

/// Build-time metadata — NOT on the object-safe trait (R1). `register_plugins!` names this; a
/// build script checks KEY uniqueness and CLAIM non-overlap (R36).
pub trait PlaneMeta { const KEY: &'static str; const CLAIMS: &'static [Claim]; }

/// Object-safe (`Box<dyn Plane>` is asserted to compile by a fixture in the contract crate).
pub trait Plane: Send + Sync + 'static {
    fn key(&self) -> &'static str;
    fn claims(&self) -> &'static [Claim];

    /// Plane-private per-session state (codec state, negotiated options), `Box<dyn Any + Send>`.
    /// Created by the kernel at Unit 0, passed `&mut` ONLY to the two decode methods, dropped by the
    /// kernel at close. Split per direction (client / upstream) so concurrent units never share it (R7).
    fn open_session(&self) -> PlaneSessionState;

    // ── TRANSLATION (the kernel does all I/O; every method can FAIL, never panic — R12/R25) ─────
    fn decode_ingress(&self, frames: &mut FrameCursor, st: &mut PlaneSessionState, ctx: &Ctx) -> Result<Option<Unit>, Decode>;
    /// Path + headers + body + the neutral AUTH SCHEME. The kernel builds the wire request from the
    /// VERIFIED destination (R5) and applies the secret after encoding (C6). The plane never sees either.
    fn encode_egress(&self, u: &Unit, dest: &VerifiedDestination, ctx: &Ctx) -> Result<EgressBody, Encode>;
    fn decode_response(&self, frames: &mut FrameCursor, st: &mut PlaneSessionState, dest: &VerifiedDestination, ctx: &Ctx) -> Result<Option<Response>, Decode>;
    fn encode_response(&self, r: &Response, ctx: &Ctx) -> Result<Bytes, Encode>;
    fn encode_refusal(&self, refusal: &Refusal, ctx: &Ctx) -> Result<Bytes, Encode>;

    // ── GOVERNANCE FACTS — every method returns LOCATORS or FACTS, never a credential, an amount,
    //    or a decision. The owning UNIT decides; the kernel sequences. ───────────────────────────
    fn authenticate(&self, u: &Unit, ctx: &Ctx) -> CredentialLocator;   // scheme + where (R4); FromSession is legal
    fn verify(&self, u: &Unit, ctx: &Ctx)       -> DestinationFacts;
    fn approve(&self, u: &Unit, ctx: &Ctx)      -> ScopeFacts;
    fn admit(&self, u: &Unit, ctx: &Ctx)        -> AdmitFacts;          // locators only: model id, max_tokens pointer,
                                                                        // input span. The COST UNIT computes the estimate (R2).
    fn route(&self, u: &Unit, ctx: &Ctx)        -> RoutePlan;           // Vec<VerifiedIdx> over the trust unit's set (R5)
    fn meter(&self, u: &Unit, r: &Response, ctx: &Ctx) -> UsageLocator; // CONFIRMS the kernel's per-dialect locator (R8)
    fn audit(&self, u: &Unit, out: &UnitEnd, ctx: &Ctx) -> AuditFacts;  // closed schema, same fields for every plane (C13)
}

pub struct EgressBody { pub method: Method, pub path: String, pub headers: Headers, pub body: Bytes, pub auth: AuthScheme }
pub enum AuthScheme { None, Bearer { header: HeaderName }, ApiKeyHeader { name: HeaderName }, SigV4 { service: String, region: String }, OAuthClientCredentials { .. } }

/// CAPABILITY types — constructed only inside the kernel or the named unit; planes, transports and
/// hooks cannot build them. trybuild fixtures prove each.
pub struct UnitToken<S: Step> { _priv: PhantomData<S> }      // per STEP (R11): a Meter token cannot mint an Admit decision
impl<S: Step> Decision<S> { pub fn allow(_: &UnitToken<S>, ..) -> Self; pub fn refuse(_: &UnitToken<S>, ..) -> Self; }
pub struct VerifiedDestination { _priv: () /* host, scheme, lane */ } // trust unit only (R5)
pub struct Usage { _priv: () /* tokens by class, bytes, priced amount in minor units, rate_card_version */ } // usage unit only (R32)
pub struct Hold { .. }  // #[must_use], non-Drop; consumed only by the Teller's exit path
pub struct Posted { .. } // minted only by Hold::settle(Usage); the exit path's return type requires one
```

**The Teller — the one loop, every unit, every transport, every plane:**
```
fn govern(core, plane, unit_frames, ctx) -> UnitEnd {
  // step 0 · ARRIVAL   kernel-owned size/rate/source gate; credentials STRIPPED here into a kernel-only
  //                    Credential by Claim-declared location (R4). Refusal = Refused(Arrival), audited to
  //                    the arrival; anonymous declines above rate R per source are aggregated LOSSLESSLY
  //                    (exact counts per (transport, claim, reason)) into one per-window entry (R37).
  // decode             plane.decode_ingress(..)?                       → Refused(Decode) on error
  // 1 · AUTHENTICATE   auth unit  ← plane.authenticate() locator + the kernel's Credential
  // 2 · VERIFY         trust unit ← plane.verify() ⇒ Vec<VerifiedDestination>  (strictly before any charge)
  // 3 · APPROVE        scope unit ← plane.approve(), hook veto facts
  // 4 · ADMIT          cost unit computes the estimate from kernel bytes × rate card (R2); admission unit
  //                    draws from the node's slice (C20) ⇒ HOLD = write-ahead journal entry, fsync'd BEFORE
  //                    the first response byte leaves (R28)
  // 5 · ROUTE          egress unit ← plane.route() indices → kernel builds the wire request from the
  //                    VerifiedDestination + EgressBody → egress-auth applies AuthScheme → send →
  //                    decode_response per frame; frames are RELAYED TO THE CLIENT INSIDE THIS STEP under
  //                    the hold's authority; accrual is per attempt (R31); breaker + failover in the unit
  // 6 · METER          usage unit builds Usage from the kernel's per-dialect locator + kernel byte floor
  //                    (R8); Hold::settle(usage) → Posted; settlement fsync'd BEFORE the terminal frame
  //                    leaves (R28); variance → MeterDisputed
  // 7 · AUDIT          audit unit ← plane.audit(); audit facts are a FIELD of the same journal entry
  // exit               ONE exit path. Every UnitEnd (Completed | Refused(step) | Failed(step) | Aborted |
  //                    TimedOut) runs 6 then 7 with what is known (partial: true). Plane calls run under
  //                    catch_unwind(AssertUnwindSafe) → Failed(step, PlanePanic) still settles and audits;
  //                    a panic inside a session poisons its state and hard-closes it (R25). encode_response
  //                    failure after posting → kernel-default error body + reversal posting; encode_refusal
  //                    failure → kernel-owned minimal refusal (R30). The exit path's return type REQUIRES
  //                    a Posted.
}
// Per session (R7): two frame streams (client, upstream), each with its own cursor and its own half of
// PlaneSessionState; a per-session task runs up to K units concurrently; Tick units are merged with
// select! and run at scheduler boundaries. A duplex client unit ENDS at "written to upstream"
// (Completed; zero-usage settle); the provider's answer is a provider-initiated unit correlated by
// reply_to. Provider-initiated REQUESTS (MCP sampling, A2A push) carry reply_to and the client's reply
// is a client unit whose Route is Destination::Upstream(session).
```

**The Teller — the one loop, every unit, every transport, every plane:**
```
fn govern(core, plane, unit_frames, ctx) -> UnitEnd {
  // step 0 · ARRIVAL   kernel-owned size/rate/source gate. A refusal here is Refused(Arrival), audited
  //                    to the arrival (source, transport, size); anonymous declines above rate R per
  //                    source are AGGREGATED into one per-window entry (no write amplification).
  // decode             plane.decode_ingress(..)?                       → Refused(Decode) on error
  // 1 · AUTHENTICATE   auth unit  ← plane.authenticate()               (FromSession is re-checked for revocation)
  // 2 · VERIFY         trust unit ← plane.verify()                     (strictly before any charge)
  // 3 · APPROVE        scope unit ← plane.approve(), hook veto facts
  // 4 · ADMIT          admission unit ← plane.admit()  ⇒ HOLD          ← WRITE-AHEAD journal entry ("authorization")
  // 5 · ROUTE          egress unit ← plane.route(): encode_egress → egress-auth applies AuthScheme →
  //                    send → decode_response (accrue per frame into the hold) ; breaker + failover in the unit
  // 6 · METER          usage unit ← plane.meter() locator + kernel byte counts ⇒ Usage ; Hold::settle(usage) → Posted
  //                    ("capture" journal entry; variance vs kernel floor → MeterDisputed, kernel value posts)
  // 7 · AUDIT          audit unit ← plane.audit() ; the audit facts are a FIELD of the same journal entry
  // exit               ONE exit path. Every UnitEnd (Completed | Refused(step) | Failed(step) | Aborted | TimedOut)
  //                    runs 6 then 7 with whatever is known (partial: true). Plane calls are wrapped in
  //                    catch_unwind → Failed(step, PlanePanic) still settles and audits. The exit path's
  //                    return type REQUIRES a `Posted` (linear: Usage is consumable only by Hold::settle).
}
```

**There is no session loop.** (v0.3, frozen.) A long-lived / duplex connection is not a second shape
the Teller serves; it is a *transport* that yields many units. `govern_unit` above is the ONLY loop.
```
// The kernel's whole job, for every transport, every plane:
for unit in transport.units(conn) {          // HTTP: exactly one. SSE: 1 in + N out. WS: many, both ways.
    let bytes_out = govern_unit(core, plane, unit, ctx);   // ALL 7 steps, EVERY unit, no exceptions
    transport.write(conn, bytes_out);
}
```
- Every frame/turn of a session runs Authenticate → … → Audit in full. Repeating Authenticate on
  frame 40 is cheap because the **auth unit** caches credential facts by session *internally* — a
  unit's private optimization, never a skipped step, never visible to the loop or the plane.
- Revocation therefore lands on the **next unit**: if the principal is disabled mid-stream, frame 41
  is refused (and audited) and the kernel closes the connection. No "once at open" grace.
- A crash mid-session loses nothing already metered: each completed unit posted its own entry.
- The kernel owns the connection and the pump; a plane sees one `Unit` at a time and nothing else.
This is the literal reading of "NO plane can ever NOT have that thing", and it is what makes voice
= (WS transport) × (voice plane) with zero special-casing.

**Invariants the loop guarantees (by construction, not by convention):**
- No plane can skip a step (core owns the loop; the plane only supplies facts).
- Every plane implements all methods (a missing one **won't compile**).
- Verify strictly precedes any charge (loop order).
- Billing/audit/admission have one implementation (core's deciders); a plane returns numbers/facts.
- `plane → core` edge count = **0** (Ctx has no work-performing handles).
- **Every outcome is audited — success AND each refusal** (Δ6). The `?` short-circuits above route
  through `core.refuse(step, reason)`, which seals a journal entry of the decline (attributed to the
  principal if resolved, else to the arrival) BEFORE `plane.encode_refusal`. A declined transaction is
  a journal entry, exactly as a bank logs declines.
- **Exactly-once posting** (Δ4): every unit carries an idempotency key (its correlation id); Meter
  is **exactly-once per key, where the key's first journal entry is the write-ahead Hold** (C3);
  Route's failover retries reuse the same key and never open a second hold.
- **Posting + audit are one committed entry** (Δ7): Meter's posting and Audit's facts are written as
  one journal entry; a crash between them is recovered by journal replay (tested by killing the
  process between steps).

---

## Part 4 — `EngineHost` disposition (the 13-slice callback surface → gone)

| Slice | Disposition |
|---|---|
| MeteringHost, BudgetHost, AdmissionHost, CompletionHost | **WORK → core deciders** (`ledger.debit`, `budget.admit`, …) applied to plane facts |
| JournalHost (audit) | **WORK → core** (`chain.seal/checkpoint`) |
| BreakerHost, LanePoolHost | **WORK → core** (`router.run`: breaker + failover + pool) |
| IdentityHost | **WORK → core** (`auth.resolve` over the auth-plugin chain) |
| ClockHost | **CONTEXT → `Ctx.clock`** |
| TelemetryHost | **CONTEXT → `Ctx.telemetry_labels`** (core emits; plane only labels) |
| RegistryHost, MountHost, HookConfigHost | **CONTEXT → `Ctx.config` / core-owned registry** |

Endstate: `EngineHost` is not a plane-facing trait. `PlaneDecl`'s 43 fields collapse into
`Plane::key/claims` + config. The reverse-edge gate goes from "names no core symbol" to
"calls no core function" for **every** plugin kind.

---

## Part 5A — COMPILE-TIME coherence (the compiler rejects deviation; no test needed)

The design is enforced by the type system and the crate graph so a non-conforming plugin **cannot
build**. Each mechanism is "impossible," not "tested":

| # | Rule | Compile-time mechanism |
|---|---|---|
| 5A.1 | Every plugin implements its kind's FULL trait | Trait methods have **no default bodies** → a missing method is a compile error. |
| 5A.2 | A plane returns FACTS or LOCATORS, never a DECISION, an AMOUNT, or a CREDENTIAL | (compile-time) Governance methods' return types ARE the facts/locator types. `Decision<S>` is built only with a `&UnitToken<S>` (private field, kernel-constructed, per step — R11); `VerifiedDestination` only by the trust unit (R5); `Usage` only by the usage unit (R32); `Credential` never enters a `Unit` (R4). A plugin holds none of these capabilities, so it cannot return one. trybuild fixtures prove each. |
| 5A.3 | `plugin → core` edge = 0 | Plugin crates depend **only on the ABI crate(s)**; `busbar-core` is **absent from `[dependencies]`** → any `busbar_core::` path fails to resolve. The crate literally cannot see core. (A manifest lint keeps the dep absent — §5B.5.) |
| 5A.4 | A plugin cannot perform core work | `Ctx` contains **only read-only views** (`&dyn Clock`, config view, session view, labels). There is **no** `&Ledger`, `&Chain`, `&Breaker`, `&Store`, `&Egress` in `Ctx` — those types live in core, which plugins can't depend on. You cannot call what you cannot name. |
| 5A.5 | Only core decides | Core's decider traits are **sealed** (`mod private { pub trait Sealed {} }`) → no plugin can implement or inject a decider. |
| 5A.6 | A plane cannot self-mount / bypass the loop | The ABI exposes **no** `mount`/`serve`/`bind`/`on_upgrade` API. The only way to be live is core's `register(Box<dyn Plane>)`. Unregistered = inert; registered = driven by the loop. |
| 5A.7 | Every kind is registered + driven the SAME way | One base trait `Plugin { kind(); key() }` is a supertrait of `Plane`/`AuthPlugin`/`Store`/`SecretProvider`/`Hook`; **one registry type** `Registry { by_kind: … Box<dyn Plugin> }`; per-kind drivers dispatch from it. Uniformity is structural — there is no second registration path to diverge into. |
| 5A.8 | The composition root lists only conforming plugins | (compile-time + build-time) `register_plugins![…]` expands to a type-level assertion `const _: fn() = \|\| { fn _a<P: Plane + PlaneMeta>() {} _a::<McpPlane>(); }` → a listed plugin that doesn't fully implement its kind's trait fails to compile. `PlaneMeta::KEY` uniqueness and `CLAIMS` **non-overlap** (a closed, decidable grammar — R36) are checked by the contract crate's build script over the registered set; overlap is a build error, and the registry re-checks at boot. |
| 5A.9 | Every unit posts | (compile-time, by linearity) `Usage` is consumable only by `Hold::settle(usage) -> Posted`; `Hold` is `#[must_use]` and non-`Drop`; the Teller's exit path **returns `Posted`**, so a path that never settles does not type-check. What linearity cannot prove — that the *right* amount was posted — is covered by R8/R32 (only the usage unit constructs `Usage`, from kernel-owned bytes) and by mutation testing of the usage crate (R23). |
| 5A.10 | No escape hatch | Plugin crates are `#![forbid(unsafe_code)]` and carry no FFI → a plugin cannot reach core outside the type system. |
| 5A.11 | The contract is feature-invariant | Trait definitions live in ONE ABI crate with **no feature flags that alter trait shape** (the `openapi_schemas`-style field-mismatch class becomes impossible). |
| 5A.12 | Object safety | Core stores `Box<dyn Plane>` / `Box<dyn Transport>` etc. Build-time metadata (`KEY`, `CLAIMS`) lives on the separate non-dyn `PlaneMeta` trait (R1), so the dispatch traits carry no associated consts or `impl Trait` returns (`Transport::frames` returns `Pin<Box<dyn Stream + Send>>`). A fixture in the contract crate asserts `let _: Box<dyn Plane>` compiles, so object-safety can never regress. |

Net: a plugin that skips a step, decides governance, reaches into core, self-mounts, or is missing
a method **does not compile.** The audit "read every plane's 7 methods" is no longer a human task
for completeness — only for *quality* of the facts each returns (§5B.6 no-stub).

## Part 5B — CI-time uniformity (every plugin, every kind, ONE harness)

One generic conformance harness runs the **same six assertions** against **every registered plugin
of every kind**. Kinds differ only in a small *adapter* ("how to hand this plugin one unit of work");
the assertions never differ. Adding a plugin automatically includes it (the harness iterates the
registry); a registered plugin with no adapter **fails** the harness (coverage is forced, not opted into).

For each `(kind, plugin)` in the registry:
1. **Registered** — it appears in core's registry under its kind, via the one registration path.
2. **Driven by core** — the driver is instrumented: every trait method is proven **called by core**
   (call-site attribution), never self-invoked. A plugin that runs a step on its own initiative fails.
3. **Returns the contract types** — each method's output is the kind's facts/data type (runtime
   check of the compile-time guarantee, for dlopen'd kinds whose C-ABI projection could drift).
4. **Core acted** — the observable core effect for the kind: plane → ledger/admission/audit;
   store → the record persisted and read back; auth → principal resolved; secret → resolved value
   injected; hook → verdict enforced.
5. **Edge = 0** — manifest lint (ABI-only deps) + symbol scan (no core names) + call scan (no
   work-performing core fn). All kinds.
6. **No stub** — no governance-facts method has a trivial-constant body without a reviewed
   allowlist entry (the mechanized "audit every plane's 7 methods" for *quality*).

Plus the migration gates: **byte-identity + shadow-diff** (old vs new bytes = 0 on the corpus; the
6 byte-exact oracles; all conformance) and **perf** (`alloc_gate` + `timing_gate` unchanged).

---

## Part 6 — Build strategy: GREENFIELD + TEMPLATE + COPY-IN (not patching, not in-place)

**Why not patch or migrate in place:** tried 5+ times. Each drive of call-ins to 0 surfaced ~300
more, because the old plumbing's *shape* — a host surface planes call into — stayed alive and kept
inviting them. The fix is a model where the call-in API **does not exist**. Greenfield gives that from
the first line; the template makes deviation impossible. (Grounding: `CODE-ANALYSIS.md` — 78% of the
code is good furnishings; ≈52k is plumbing of the wrong shape.)

**The strategy — "build the new house empty, then move the furniture in":**
1. **New house, empty.** A new **kernel** (the one Teller loop, the registry, `Ctx`, `UnitToken`,
   the frame pump) + the **units** (auth, trust, scope, admission, egress, usage, ledger, audit — each
   its own crate and trait) + the **contract crate** (`Plane`, `Transport`, the kind traits, the
   facts types). Written CLEAN from Part 3, referencing **none** of the old plumbing. **It compiles and
   passes its own battery with ZERO plugins registered** (0 plugins is valid). Foundation + walls.
2. **The plane TEMPLATE — fill-in-the-blank.** `plane-template/`: a complete `impl Plane` skeleton —
   every translation + facts method present with `todo!()` bodies — plus the conformance test that is
   **RED until every blank is filled**, plus a one-page checklist. **Adding a plane = copy the
   template, drop in a codec, fill the blanks.** The template *is* the shape; the trait and its tests
   make it impossible to deviate. (This is the "4th plane is a single file" test, built in.)
3. **Furniture in — per plane, in parallel.** For each plane: instantiate the template; **copy the
   codec verbatim** (the ≈35k of dialect translation, untouched); fill the fact-extractors by **reading
   the old glue as a spec** — what did old `method.rs` / `receive.rs` / `pipeline.rs` actually admit,
   meter, route against? — and writing **new, thin** code. The old glue is documentation, never
   migrated. Every plane unit targets the same frozen template ⇒ fully independent, fully parallel.
4. **Furnishings into the kernel's deciders.** Ledger, cost model, audit chain, breaker, failover,
   pool, net-guard, trust, egress client — **copied nearly as-is** into the kernel (they're good),
   invoked from the ONE loop. Their existing tests come with them as parity tests.
5. **The old binary is the oracle.** Shadow-diff: old vs new on the full corpus, **byte-equal**, before
   any cutover. The old code's *behavior* — not its code — is the acceptance test for the new.
6. **Delete the old plumbing wholesale**, once the new house passes: the 100% coverage battery (J),
   shadow-diff = 0, all conformance, the 6 byte-exact oracles, perf gates. `EngineHost`, `PlaneDecl`,
   both registries, the per-plane glue, voice's apparatus — **gone in one commit.** Nothing bent.

**Parity is mechanical, not a memory:** the coverage matrix (Part 7, unit J) is **derived from the OLD
system's feature set** (registry, config surface, existing tests) — so "did we lose a feature?" is a
red cell, not a recollection.

**Validation of the two load-bearing assumptions (measured):**
- **"Copy the codecs verbatim" — HOLDS.** 8 of 9 codec dirs have **zero** references to the old
  plumbing (host / `EngineHost` / `PlaneDecl` / `App` / metering): gemini 5,848 · openai_responses
  5,258 · openai_chat 5,141 · cohere 3,737 · anthropic 3,595 · llm ir 2,294 · mcp codec 688 · voice ir
  3,040 — all 0. Bedrock has 2 (trivial). ≈35k of translation moves into the new house untouched.
- **"Relocate the logic" — holds everywhere EXCEPT the LLM engine, which is a rewrite-from-spec.**
  Host-call density per function: `relay.rs` 0.1 (near-pure → **copy**) · `method.rs` 0.7 and
  `receive.rs` 0.8 (moderate → **relocate with a per-fn pass**) · **`walk.rs` 3.1 and `pipeline.rs`
  3.7** (the failover/pipeline logic is interleaved with host glue at the statement level → **cannot be
  copied; K-route is REWRITTEN in the kernel using the old walk/pipeline as the spec**, and its ≈70
  host calls become deciders/`Ctx` reads). This is the one true rewrite (≈4.5k) and it is exactly the
  money path — hence shadow-diff = 0 is non-negotiable there, and K-route lands first (by H18).

### The plan (v0.4). Three phases; the middle one is the 48 hours.

**Phase −1 — Foundation, done-by-test, NOT on the 48-hour clock.** Sequential-ish, integrator-owned,
its own hours and its own gate. It is finished when the following are GREEN, not when the list is
written:
- F9–F15 (Part 15.3): contract crate + trybuild fixtures, three templates with their red batteries,
  the Rust oracle with the 1.5.5 golden (LLM + admin + boot cells), unit goldens, `cargo xtask gate`,
  stream cards, the full-tree bookmark.
- **K-route** (the one true rewrite — `walk.rs`/`pipeline.rs` as the spec) and the **LLM streaming
  path** (SSE accrual into a hold), because they are the real critical path and cannot be parallel.
- **Journal-first ledger + WAL (C2) and branch-float admission (C20)**, because they touch the hot
  path and re-baseline the timing gate — landed once, by the integrator, before anyone builds on them.
- **The probe stream — the freeze criterion.** One dialect (`openai_chat`, non-streaming + SSE, one
  failover) driven end-to-end: transport → kernel → plane → K-route → journal → oracle replay against
  1.5.5, GREEN on bytes + ledger. The contract is frozen only when a real plane has exercised it. A
  contract frozen at zero planes is a contract that will churn at hour 14.
- The four stores re-released at ABI floor 5 (C2/C20), signed.

**Phase 0 — The 48 hours.** Parallel fill-in against the frozen contract. The streams are exactly the
stream cards in `docs/design/streams/` (F14) — one card per stream, disjoint file ownership, named
model, done = named tests. **This document carries no competing schedule or unit table**; the cards
are the single source. Stream names, for orientation only: P-llm (5 remaining dialects on the proven
template) · P-mcp · P-a2a · P-admin (D3/C15) · K-ledger · K-audit · K-admit · K-cost · K-trust ·
K-breaker · K-usage (C1) · K-egress-auth (C6) · T-http · T-sse · T-ws · T-grpc · T-stdio · G (gates)
· J (closed-loop battery + effects spec) · I (auth/store/secret/hook/export adapters, D8/C7).
Merge waves at H12/H24/H36/H48 with the full gate (P19). The test-LOC ratio is a
**stream-completion** gate, not a wave gate.

**Phase V — Voice at hour 49, the acid test.** Voice = one plane file filling the template + its
codec/ir (1,846 LOC, 0 plumbing refs) copied verbatim from `reference/voice-1.6.0-pre-rebuild`,
claiming `Ws`. It is proven by the same battery as every plane plus a passthrough-diff against a real
OpenAI Realtime rig. **Everything voice needs from the kernel is built and proven inside Phase 0 by
the echo plane: WS transport, Unit 0 (no 101 without it), client↔upstream session pairing through
K-route, provider-initiated units, Tick units, per-session plane state (C5).** If voice needs any
kernel or transport change, the model was wrong — and that is the finding, not a patch.

### Quality mechanisms (what "highest quality" means, concretely)
- **Frozen contract, proven before freezing** (the probe stream). Parallel streams cannot drift because
  they share one immutable, exercised interface.
- **Every stream has its own gate** (its card) AND must leave the full `cargo xtask gate` green on
  landing. No stream merges red.
- **Shadow/differential for anything on the money path**: bytes + ledger vs the 1.5.5 golden; audit +
  refusal metrics vs the committed effects spec (C10). Two approvers — integrator and owner — on any
  accepted diff that touches an `effects` field; normalizer rules are diff-accept entries with the same
  sign-off; no new accepts in the last 4 hours before cutover.
- **One stream = one commit series**, each gate-green, each reversible.
- **Design review against Part 0 before code review**: "does this add a `plugin → core` edge, or let
  a plugin supply a decision or an amount?" If yes, rejected regardless of tests.
- **STOP rule stands**: a stream that cannot hold the gate STOPs and reports rather than merging.
- **Integrator** (Fable, this session): holds the contract, the templates, the oracle; sequences
  merges; reads every merge. **Builders**: Opus/Sonnet per card. **Verifier**: an independent Fable
  read-through per merge.

---

## Part 7 — 100% coverage, closed-loop, user-perspective test structure
### ("meters were metered, audits audited")

The behavioral battery (§5B.4) proves core *acted*. This part makes that **exhaustive** (every
feature of every plugin), **user-perspective** (public surfaces only), and **closed-loop** (the result
was itself recorded, and the records agree). It generalizes tonight's lesson — "proven" must mean
shipped-path and result-landed — into a mechanical 100% gate.

### 7.1 The feature matrix (100% or red)
- **Rows:** every registered plugin (all kinds). **Columns:** every feature/function of its kind:
  - plane → the 7 governance verbs + the 5 translation methods + every supported op × dialect ×
    transport it claims;
  - store → every `Store` method; auth → every outcome (admit/refuse/audience-mismatch/…);
  - secret → resolve/refresh/missing; hook → every point × verdict.
- The **required cells are derived** by the harness from the registry + the kind's trait, so a new
  plugin or feature *cannot be forgotten* — it appears as an uncovered cell and reds the gate.
- A ledger (`qa/plugin-coverage.json`) records each cell → its proving test. **Coverage gate: 100%.**
  This supersedes today's 13×7 capability-equality ledger (a subset, with a weaker bar).

### 7.2 The proof bar per cell — ALL THREE required
| | Condition | What it rules out |
|---|---|---|
| **(a) Shipped-path** | driven through core's loop / the real binary via public surfaces — never a hand-built apparatus or mock host. Verified by the harness's call-site attribution, not by trust. | the voice-billing class: green in isolation, dead in the binary |
| **(b) Observable as a user** | the effect is read back exactly as an operator would — usage/spend API, audit-chain read, `/metrics`, store row via the admin API. No internal handles. | "it worked internally but nobody can see it" |
| **(c) Closed-loop (second-order)** | the effect is itself **recorded**, on **≥2 independent surfaces**, and they **agree**. | "it did the thing but the result never landed / was never auditable" |

Concrete (c) contracts:
- **Meters were metered:** the debit appears in the ledger **and** the audit chain **and** the metric,
  with **equal** numbers.
- **Audits audited:** the audit record's seal **verifies** (chain integrity) **and** the chain records
  that the seal occurred.
- **Refusals refused:** the native 4xx body, the chain's refusal record, and the refusal metric agree.
- **Admissions admitted:** the config fee charged == the ledger delta == the chain's admit record.
A plugin that "did the thing" but whose result didn't land fails (c) even when (a) and (b) look fine.

### 7.3 User-perspective only
Every cell's test speaks **only** public HTTP / admin / metrics / audit-read surfaces. No test may
reach an internal handle. This *is* "full CI testing from the user perspective."

### 7.4 Audit-of-results (the tests' own outcomes are auditable)
Each CI run emits a **coverage + agreement report** — per cell: pass/fail, the closed-loop values
that were compared, and drift vs. the last run — committed as an artifact (`docs/proof/coverage-
<branch>.json`, beside the existing proof manifest). A nightly job re-runs the full battery and
diffs. Not just "green": *what* was metered, *what* was audited, and that they matched — trended.

### 7.5 Placement in the decomposition
**Stream J (Phase 0, independent):** build the matrix derivation, the closed-loop harness, the coverage
gate, and the report. Gate: 100% on the migrated kinds; **red on a deliberately-unrecorded fixture**
(a plugin that acts but doesn't land its result — the harness must catch it, or the harness is wrong).

---

## Part 8 — How this plan absorbs the 1.6.0 "zero-leakage" audit (the old Phase B)

The prior goal audited ten leakage dimensions *after the fact*. This architecture makes most of them
**impossible by construction** and the rest **mechanical gates** — stronger than a periodic audit.

| Leakage dimension (old Phase B) | In this design |
|---|---|
| (1) FORWARD noun/name leak in neutral crates (incl. snake_case/CamelCase) | Core drives `dyn Plane` via an opaque `key()`; it never names a plane. Gate: plane-purity FORWARD + the dialect-confinement gate (landed) + §5B.5 symbol scan. |
| (2) REVERSE reach (plugin names core) | **Compile-impossible** — `busbar-core` absent from every plugin's deps (§5A.3). |
| (3) host-ABI single-plane methods | **Moot** — `EngineHost` is retired (Part 4); there is no plane-facing host ABI to carry single-plane methods. Edge = 0. |
| (4) store seam opacity | By construction — `Store` is an ABI trait over neutral records; the store can't see core (§5A.3). |
| (5) config/registry parse targets | One registry + `claims()` at boot (§2.8, §5A.7); the 43-field decl retired; config keyed by opaque plugin keys. |
| (6) observability labels | `TelemetryHost` → `Ctx.telemetry_labels`: core assigns bounded neutral labels, core emits; the plane only reads (Part 4). |
| (7) ingress/egress dialect-freedom | All dialect knowledge lives in the plane's decode/encode family (§2.4); core sees only `Unit`/`Bytes`. Core is dialect-free by construction. |
| (8) lean linear core (no `if plane ==`) | The ONE loop is generic over `dyn Plane` (Part 3) — core has no plane branch. Gate: a lint rejecting any plane-key match/branch in core. |
| (9) cross-plane off-diagonal = 0 | **Compile-impossible** — each plane crate depends only on the ABI; no plane depends on another (manifest-enforced). |
| (10) byte-identity through arming | §2.9 + §6: shadow-diff = 0 + the 6 byte-exact oracles per migration commit. |
| WS-F5 (ungated `accept`/`serve`) | **Structurally impossible** — the ABI exposes no `mount`/`serve`/`on_upgrade` (§5A.6); core owns every socket (§2.2). |

**Day-0 items carried into execution (not lost):**
- The dev-CI public-hygiene red on `dialect_identifier_confinement.rs:11` (a `§`-style finding-id in a
  doc comment) — one-line comment fix.
- The dim-1 residue relocation (`openai_context_length_prose_scan` / `openai_classify` → `busbar-llm`)
  — folds into Unit F (LLM → `Plane`); the confinement gate's allowlist then empties.
- The voice provider-dial leg going live (your ruling) — folds into Unit E (Voice → `Plane`, route-open
  + core-owned sockets).
- The voice Admit step (config-driven fee/budget) — folds into Unit A (core `budget.admit`) + Unit E.

---

## Part 9 — Adversarial review (trying to break the design before building it)

Ten attacks, each with its resolution or the open question it leaves. Three forced small design deltas
(marked **Δ**).

| # | Attack | Resolution |
|---|---|---|
| 1 | *"Facts-only is naïve — some steps need protocol-specific DECISIONS."* e.g. MCP `tools/call` admission depends on the tool's catalogue cost/scope; A2A's `registry.rs::admit` weighs grants vs exclusions. | Those are **facts**: the plane returns `AdmitFacts { model_id, max_tokens_ptr, input_span }` (locators — the cost unit computes the estimate, R2) / `ScopeFacts { agent_id, scope: "tool:X" }`; the exclusion list and limits are **config → the owning unit decides**. Protocol knowledge feeds facts; policy stays in the units. **Holds.** |
| 2 | *"Some gating must happen BEFORE decode"* (oversized body, rate-limit on raw arrival) — but the loop decodes first. | **Δ1: a step-0 `arrival` hook point** on the raw arrival (size/headers/rate) before `decode_ingress`. Core-driven, same one-way edge. |
| 3 | *"Admin verbs reach into planes (`planeverbs.rs`) — a core→plane call that isn't one of the 7."* | **Δ2: an optional second, smaller core-driven surface** — `AdminSurface::admin(verb, ctx) -> AdminFacts` a plane may implement. Still core→plane; the 7 are the *request* lifecycle, admin is a separate family. Direction holds. |
| 4 | *"The kernel does ALL I/O — but egress is per-transport"* (HTTP, WS, stdio for MCP, gRPC for A2A). | `RoutePlan` carries a `Transport` fact; **K-route owns one client per transport** (the existing egress client, duplex dialer, stdio client, gRPC — copied in as kernel furniture). Plane names the transport; kernel drives it. **Holds** — scope note: K-route owns 4 transport clients. |
| 5 | *"Streaming backpressure / disconnect / hard-close mid-frame — the pump is brand-new kernel logic."* | True and the riskiest new code. Mitigation: the pump is ONE place; **copy voice's proven `select!`/hard-close race handling as its spec** (that logic is good — it was just in the wrong room). Voice conformance + the ledger battery gate it. **Accepted risk, bounded.** |
| 6 | *"Config-driven Admit — who parses the fee/limit table, and the plane's own config section?"* | Config parsing is core furnishing (10.9k). The decl's `parse_section`/`lower_endpoint` fn-pointers become **`Plane::config_schema()` (a fact) + core's parser** → a read-only view in `Ctx.config`. **Holds.** |
| 7 | *"Cross-protocol: OpenAI ingress → Anthropic egress — a plane encoding for a different dialect's lane."* | `encode_egress(unit, dest)` with `dest.dialect ≠ ingress`. The LLM plane owns all 6 codecs so it can encode for any lane — **this is exactly why LLM is ONE plane with 6 dialects, not 6 planes.** Confirms the existing decision. **Holds.** |
| 8 | *"The unclassified ~11k 'other' in mcp/a2a might be mostly plumbing."* | Worst case ≈ +11k → ≈63k rebuilt. Still greenfield, still per-plane, strategy unchanged; P-mcp/P-a2a extend by hours. **Schedule risk, not design risk.** |
| 9 | *"Byte-identity: the new kernel's ONE step order vs the old planes' subtly different orders"* (MCP/A2A verify-inside-drive, voice's session sibling). Shadow-diff will flag drift. | Where the old order was **wrong** (a plane skipping/reordering a step) the new order is the *fix* and the diff is *expected*. **Δ3: a diff-accept ledger** — every non-zero shadow diff must be explicitly reviewed and recorded as either a bug (fix the kernel) or an intentional correction (accept, with the reason). Never silent. |
| 10 | *"Future dlopen'd customer planes — a Rust trait isn't ABI-stable across dlopen."* | The trait is canonical; a **C-ABI projection** (as stores/hooks already have) is a separate later unit. **Not in the 48h; noted.** |

**Net of the adversarial pass:** the model holds under every attack. Three small deltas (Δ1 arrival
hook point, Δ2 optional admin surface, Δ3 diff-accept ledger), two scope notes (K-route's four
transport clients; the pump built from voice's proven race handling), one accepted bounded risk (the
new pump), one schedule-only risk (the unclassified 11k). No attack found a reason to keep the old
plumbing or to soften the one-way edge.

---

## Part 10 — The Shadow Oracle (built FIRST, against the OLD binary)

**Purpose.** The acceptance instrument for the rebuild: capture the REFERENCE binary's exact
behavior — bytes out for bytes in, **plus the effects** (ledger, audit chain, metrics) — for every
feature cell, so the NEW binary is validated against recorded truth, not memory. It is **green today
(reference vs reference)**, which proves the harness before it matters, and becomes the hard gate at
cutover (shadow-diff = 0).

**Two oracle sources, by plane — because the planes have different provenance:**
| Plane | Reference | Bar |
|---|---|---|
| **LLM** | **the published 1.5.5 binary** — the last known-good, LLM-only, shipped release (not dev, which carries the sprawl) | **byte-identical to 1.5.5, or a reviewed improvement.** Every non-zero diff goes to the diff-accept ledger as either a regression (fix) or "intentional, better, because —" (accept). *"Identical or better," mechanized.* |
| **MCP / A2A** | new in 1.6 — no 1.5.5 baseline. Reference = **spec conformance**: the MCP rig + A2A TCK already compare busbar-as-subject to a reference control | conformance verdicts unchanged + byte-golden of the current subject transcripts (so a refactor can't silently change a response the rig doesn't assert on) |
| **Voice** | new; built LAST (Phase V) | voice conformance rig + the acid test (a plane in ~2 files) |
The recorder takes `BUSBAR_BIN` — for LLM cells it is pointed at the **downloaded 1.5.5 artifact**
(the same resolve-by-version step `plugin-functional.yml` uses); the oracle config must validate on
1.5.5's grammar (it contains no mcp/a2a/voice sections, so it does).

- **Cells are derived, not hand-listed:** `testing/shadow-oracle/enumerate-cells.py` reads
  `qa/method-inventory.json` (MCP/A2A: 230 method×originator×role×transport cells) and
  `qa/field-inventory.json` (LLM: dialect×direction×streaming) and crosses each with the **outcome
  classes** — ok · 401 unauthenticated · 403 out-of-scope · 429 over-budget · 400 malformed ·
  upstream-down (failover) · streaming. A new method/dialect appears as a new cell automatically.
- **Recorder** (`record.sh`, on the proven `fleet-fixtures/lib.sh` harness): start the OLD binary
  against a **multi-dialect mock upstream** + fake MCP/A2A peers, mint keys via the admin API, drive
  each cell through the **public HTTP surface only**, and capture per cell:
  `req` (bytes sent) · `resp` (status + normalized headers + body bytes) ·
  `effects` (ledger delta via the admin usage read · audit-chain record · `/metrics` delta).
  → `testing/shadow-oracle/golden/<cell-id>/{req,resp,effects}`.
- **Replayer** (`replay.sh`): the identical drive against **any** `BUSBAR_BIN`; byte-diff `resp` and
  `effects` against golden. One ledger row per cell; `verdict.sh`; **zero rows is RED**; any non-zero
  diff is FAIL unless recorded in the **diff-accept ledger** (Δ3: an intentional correction, reviewed,
  with its reason — never silent).
- **Normalizer** (`normalize.py`): strips only documented nondeterminism (timestamps, request/trace
  ids, `Date`, server-minted ids) with each rule named — so a byte-diff is meaningful and a normalizer
  change is itself reviewable.
- **Closed-loop effects** (this is unit J's first real implementation): `effects` records the SAME
  number on ≥2 surfaces and the replayer asserts they agree — "meters were metered" (ledger = metric),
  "audits audited" (the chain record verifies). A build that acts but doesn't land its result fails here.
- **CI:** `shadow-oracle.yml`, wired exactly like `plugin-functional.yml` (resolve `BUSBAR_BIN` → replay
  → verdict). Runs on every push; today green; after cutover it is *the* gate.

---

## Part 11 — Core UNITS: the furnishings get the same discipline as plugins (auditable solo)

**Principle.** The kernel is not a blob. It is composed of **units** — ledger, audit chain, cost
model, admission, breaker, trust/net-guard, egress clients (per transport), session registry — and
each unit has exactly the discipline a plugin has:
1. **one contract** (the narrow trait the kernel calls),
2. **one implementation**,
3. **stated invariants** — the properties that make it correct, written *as tests*,
4. **its own solo battery** — unit + property tests that drive ONLY this unit (fake clock, memory
   store, fixed rate card; no kernel, no plane, no transport),
5. **a closed-loop self-check** — "what it recorded == what it reports back,"
6. **no outward edge** — it depends on nothing but ABI types; it never calls the kernel or another
   unit. **The kernel loop is the only place units compose.**

So every furnishing can be **audited alone**, during the rewrite and forever after.

**Worked example — the LEDGER unit**
- Contract: `debit(principal, usage, model, pool, now)` · `derive(principal, cost, now) → {tokens,
  requests, spend}` · `headroom(principal, limits, now)` · window rollover.
- Invariants (each is a test): (i) **spend is priced ONCE, at settlement, and stored** — every
  posting carries its priced amount in integer minor units and the `rate_card_version` it was priced
  with; `derive` sums stored amounts and never re-prices (R3). A rate-card change never alters a
  closed window (test: change the card mid-window, historical spend is byte-identical); a "what would
  this cost today" figure is a separately labelled projection. (ii) accrual is additive and
  order-independent within a window (integers, so exactly — R39); (iii) **derive after
  debit returns exactly what was debited** (closed-loop); (iv) rollover resets exactly at the boundary;
  (v) an all-zero tier is a no-op; (vi) concurrent debits sum correctly (property test);
  **(vii) JOURNAL-FIRST (Δ5):** every debit is an immutable, append-only posting; the window cells are
  a derived cache **rebuildable from the journal**; a correction is a reversal posting, never an edit;
  **reconciliation = replay the journal and assert it equals the cells** — the bank's daily close, as
  a test.
- Today: `governance/state.rs` (3.8k) — copied in; its existing tests come along; the invariant
  battery is the new solo audit.

**Worked example — the AUDIT CHAIN unit**
- Contract: `seal(principal, facts, now) → SealedEvent` · `checkpoint(session, facts)` ·
  `verify(chain) → bool` · `read(principal, range) → Vec<SealedEvent>`.
- Invariants: (i) every sealed event verifies; (ii) append-only — a tampered or removed record fails
  `verify`; (iii) **read returns byte-equal what was sealed** (closed-loop); (iv) the chain records
  that a seal occurred ("audits audited"); (v) after restart, `verify` over the replayed journal
  succeeds and the chain head equals the last anchored head (C13/R6).
- Today: the durable handle engine + hash chain — copied in.

The same table is written for: **cost model** (rate lookup; unknown model → `None`, never 0),
**admission** (headroom + config fee on facts — note *verify-before-charge is the LOOP's order*, not
the unit's), **breaker** (trip/cooldown/fast-fail state machine), **trust/net-guard** (allow-list,
SSRF), **egress clients** (one per transport), **session registry** (open at Unit 0 / close;
node-local).

**Plan impact.** The kernel's decision work is **per-unit streams** — K-ledger, K-audit, K-cost, K-admit,
K-breaker, K-trust — each independently buildable and gated by its own solo battery: more
parallelism, finer gates. The rebuild's audit becomes three *bounded* audits instead of one tangle:
**each unit solo** (battery + invariants) · **the loop** (the order) · **each plane** (its 7 fact
methods).

---

## Part 12 — Transports are a plugin kind (orthogonal to planes)

**The WS saga was a category error.** Voice had to *build* transport inside a plane — the duplex
acceptor, `on_upgrade` confinement, gauntlet-before-upgrade, the ungated `accept`/`serve`. Transport
is not a plane concern. The design has **three orthogonal axes**, each a bounded plugin/unit,
composed **only** in the kernel's registry + loop:

**TRANSPORT** (how bytes move) × **PLANE** (what bytes mean) × **UNITS** (what core does about them)

- **`Transport` trait:** `kind()` · `listen(cfg) → Listener` · `accept(listener) → Conn` ·
  `read(conn) → Frame` · `write(conn, bytes)` · `close(conn)`. HTTP request/response is the degenerate
  one-frame-each-way case; SSE = one request, many response frames; WebSocket / gRPC-stream = duplex;
  stdio = duplex over pipes. **A transport knows no protocol, no plane, no governance.**
- **The kernel owns the transport registry and every listener/connection.** An arrival =
  `(transport kind, path/headers)`; the kernel routes it to the ONE plane whose `claims()` matches — a
  plane *declares* `transports: [Http, Ws]`, it never implements one. **"Gauntlet strictly before a
  duplex socket binds" is the LOOP's order, enforced once for every duplex transport** — never
  re-derived per plane (the exact invariant the WS-accept audit had to hand-patch into voice).
- **Voice = a Plane claiming `Ws`. WS = a Transport plugin.** Voice never touches a socket. MCP claims
  `Http`+`Stdio`; A2A claims `Http`+`Grpc`; LLM claims `Http` (+SSE streaming). Today's tangles —
  mcp `client/stdio.rs` (1,087), a2a gRPC, substrate `ingress/duplex_ws`, the WS-accept seam — become
  transport plugins, copied from the good parts (substrate `egress/` 4.3k + `ingress/` 1.8k are
  largely transport furniture).
- **Compile-time:** a plane crate cannot depend on a socket/transport crate (ABI-only manifest) and
  `Ctx` carries no connection handle → **a plane physically cannot open a socket.**
- **Plan impact:** the **T-** streams in Phase 0 — HTTP, SSE, WS, gRPC, stdio — each a unit
  with its solo battery (frame round-trip, close semantics, backpressure) plus the kernel's
  gauntlet-before-accept test. **WS is built in the 48h and proven by a trivial echo plane**, so
  Phase V's voice is *purely* a plane — the cleanest acid test of the whole model.

---

## Part 13 — Would it pass a bank's audit? (the money-movement standard, applied)

**Framing.** busbar is an accounting ledger; instead of cash it moves company data. The kernel loop
is an **authorization-and-posting pipeline**: *can this principal do these 7 things, in order? If so,
do it — and post it.* Judge the design by what a bank's auditor demands of a payments system.

| Bank requirement | Our step / mechanism | Verdict |
|---|---|---|
| Authenticated, non-repudiable actor on every transaction | Authenticate → the principal is on every record | ✓ |
| Authorization / mandate; **segregation of duties** (requester ≠ approver) | Verify + Approve; **facts-vs-decide** — a plane requests, only core decides | ✓ structural |
| Funds availability checked BEFORE execution; no overdraft by design | Admit (headroom, fail-closed) strictly before Route — "authorize before capture" | ✓ loop order |
| Exactly-once execution; retries never double-charge, crashes never under-charge | Route retries; Meter posts once per unit | **Δ4 + C3**: kernel-minted idempotency key; the write-ahead Hold is the key's first journal entry; Meter settles it exactly once; recovery settles open holds at estimate, flagged and audited |
| Append-only, immutable ledger; balances derived; corrections as reversals | today: mutable window counters + write-behind | **GAP → Δ5 journal-first ledger**: immutable postings are the truth; cells are a rebuildable cache; reconciliation = replay the journal == cells |
| Every action AND every decline recorded | the drafted loop short-circuited refusals before Audit | **GAP → Δ6** every outcome, incl. each refusal, seals a journal entry (a decline is a journal entry) |
| Posting + its audit record atomic under crash; recoverable | Meter then Audit as two calls | **GAP → Δ7** one committed journal entry (posting + audit facts); crash recovery by replay; a kill-between-steps test |
| Tamper-evident, verifiable trail | hash chain; `verify()`; read-back byte-equal | ✓ (+ sign the chain head) |
| Independent reconciliation | **Landing** (ledger, chain, metrics all show the entry) is Part 7. **Reconciliation** is separate and real (C1/R3): Σ postings priced at their *own* rate-card version == window cells == metric, and ledger tokens == provider-reported usage captured from the raw response; MCP/A2A/LLM with identical token counts produce identical postings (R24) | ✓ C1 / R3 / R24 |
| No path moves money without the controls | core owns the loop; compile-enforced trait; registration-only; a plane can't open a socket, supply an amount, or return a decision. **Holds for static plugins; for dynamic plugins the boundary is the mandatory signature + operator key set (C7) — a loaded dynamic plugin is inside the trust boundary.** | ✓ structural (static) / signature (dynamic) |
| Corrections, reversals, disputes under dual control | `adjust` and `resolve_dispute` admin verbs (R16), reversal postings referencing the original `Seq`, two admin principals above a threshold, per-window cap | ✓ R16 |
| Amounts in integer minor units, one currency per bucket, stated rounding | R39 | ✓ R39 |
| Rate-card and policy changes are themselves ledger entries; history never re-priced | `PolicyEffective` at every boot/reload (R21); `rate_card_version` on every posting (R3) | ✓ R3 / R21 |
| Evidence retained, queryable, exportable | usage/audit APIs; export plugins | ✓ |
| Test evidence to an auditor's standard | 100% matrix + closed-loop; **test LOC > prod LOC per unit**; **mutation testing** | **STANDARD** (below) |

**Verdict:** the *shape* passes — the controls are structural, not procedural. Four gaps a bank's
auditor would flag, all fixed in the design now (Δ4–Δ7). None requires bending the one-way edge.

**The test standard ("more test than code").** Today: core 90k test / 77k prod · llm 93k/47k ·
mcp 25k/24k · a2a 26k/22k — but **substrate 11k/30k and voice 4.3k/6.5k are UNDER 1**: the ABI and
the newest plane, exactly where it hurt. Gates: (i) test-to-prod LOC **≥ 1 per crate/unit, ≥ 2 for
the money units** (ledger, admission, audit, cost); (ii) **mutation score** via the existing
`run-mutants` rig as the real measure — a LOC ratio is gameable, a surviving mutant is not; a money
unit with a surviving mutant on a posting path is RED.

---

## Part 14 — The composition point: three blind axes, one small kernel

**TRANSPORT** (how bytes move) × **PLANE** (what bytes mean) × **UNITS** (what core does about them)

**The composition invariant.** Each axis is **blind to the other two**; **only the kernel composes
them**; **the kernel is small.**
- A transport cannot name a plane or a unit (ABI-only manifest; the `Transport` trait carries no
  plane/unit types).
- A plane names a transport **only as a claim** (`transports: [Http, Ws]`) and never holds a
  connection; it names no unit (it returns facts, it never calls a ledger).
- A unit takes **facts + a principal + the kernel's clock** and nothing else; it names no plane and no
  transport.
- This is the old "cross-plane off-diagonal = 0" goal generalized to three axes, and it is
  **compile-enforced** by the crate graph, not audited after the fact.

**The kernel is exactly two things — and a size budget.**
1. **The registry** — three tables: transports by kind · planes by claim · units (fixed kernel
   members). One registration path (`register_plugins!`). Zero of anything is valid.
2. **The Teller** — the one loop (Part 3). *Every transaction goes through the same clerk, who runs
   the same seven-step procedure, with no bypass.* One-shot units and sessions are the two shapes it
   serves. It is the ONLY code that sees all three axes.
**Budget: registry + Teller ≈ 1–2k LOC**, exhaustively tested by their own battery — every step
order, every refusal path (each audited, Δ6), every outcome shape, crash-between-steps (Δ7). Small
by design: it is the trusted computing base; everything else is a replaceable unit or plugin.

**Two more bank-audit items the axes make explicit:**
- **Trusted time.** Postings and audit entries are timestamped by the **kernel's clock only**
  (`Ctx.clock` is read-only and core's). A plane's or transport's notion of "now" is never trusted
  for a posting.
- **Admin operations are transactions.** Minting a key, changing a budget, revoking — these move
  "money" too. They enter through the Teller like any arrival (the `AdminSurface`, Δ2): authenticated,
  approved (admin mandate), **audited**. There is no side door that changes a balance unrecorded.

**The two acceptance tests of the whole model, stated as files:**
- *Add a plane* = one file implementing `Plane` over a codec + `register_plugins!`. Touches no
  transport, no unit, no kernel line. (Voice, Phase V.)
- *Add a transport* = one file implementing `Transport` + `register_plugins!`. Touches no plane, no
  unit, no kernel line. (WS, in the 48h, proven by an echo plane.)
If either needs a change anywhere else, the model is wrong — fix the kernel, not the plugin.

---

## Part 15 — v0.3: decisions frozen, the remaining gaps closed

### 15.1 Decisions (owner-acked; these override anything earlier in this document that disagrees)

| # | Decision | Consequence |
|---|---|---|
| D-A | **Core = registry + the Teller loop, and knows nothing else.** No plane-, verb-, or transport-flavored logic in the kernel. | The loop is "call step N's unit with step N's facts", seven times, in order. |
| D-B | **Units decide.** Authenticate→auth · Verify→trust · Approve→scope · Admit→admission · Route→egress+breaker · Meter→ledger · Audit→audit chain. Each behind its own trait, each solo-auditable. | `Decision` is constructible only inside the unit that owns the step. Planes and units never meet. |
| D-C | **Planes return facts only.** Decode/encode bytes ↔ facts. Never decide, never call in. | `Ctx` is read-only; plane crates cannot name `busbar-core`; compile-fail tests prove it. |
| D-D | **Transports produce units. Every unit runs all 7 steps.** HTTP = one per request; SSE = one in + N out; WS = many, both directions. No "once at open". | Part 3's session loop is deleted (above). Auth-unit caching is private and never a skipped step. |
| D-E | **Closed loop = all three surfaces, every cell, refusals included.** Ledger, audit chain, metrics must each show the expected delta. A surface that cannot show it is RED, never skipped. | Part 7's battery asserts three surfaces per cell; the oracle captures three effect surfaces per cell. |
| D-F | **Execution:** agents build the streams against the frozen contract; the integrator owns the kernel, the templates, the oracle, and every merge. Nothing lands without oracle + battery green and a read-through. | Stream cards (15.3) are the agents' whole brief. |
| D-G | **Order: LLM plane FIRST** (the only plane with an external golden — 1.5.5), then MCP + A2A in parallel, **voice at hour 49** as the acid test. Supersedes Part 6's "LLM last". | The LLM stream proves the plane template before anyone fills it a second time. |
| D-H | **Oracle in Rust** (`busbar-oracle` workspace crate); the sh/py prototypes are deleted. Bedrock cells are signed with `busbar_substrate::sigv4::sign_v4` — all 126 LLM cells record, no named gap. | New planes prove out by **passthrough-diff** (busbar absent vs present, same real client + real server → empty diff) × spec-shaped refusals × the shared effects table. Nothing is "whatever 1.6.0 did first". |

### 15.2 Design deltas (the gaps a bank auditor would still flag, closed)

**D1 — Unit terminal states.** A unit ends in exactly one of
`UnitEnd = Completed | Refused(step, reason) | Failed(step, reason) | Aborted(by: Client|Kernel) | TimedOut(step)`.
The Teller has **one exit path**, and that exit always runs Meter (what is known so far — possibly zero
usage with `partial: true`) then Audit. `UnitEnd` is constructed only by the exit path (private
constructor), so there is no way to leave the loop without posting. Battery: inject every terminal
state (client disconnect mid-stream, upstream hang, kernel shutdown, budget hit mid-stream) and assert
all three surfaces show the unit and its end state.

**D2 — Hold / settle at Admit.** Two concurrent units on one key, each under budget alone, together
over it. Admit returns a `Hold` — a reservation against the budget window, keyed by the unit's
idempotency key (Δ4). Meter takes the `Hold` **by value** and settles it (actual ≤ or > estimate; the
difference is a correcting posting, never a mutation). `Hold` is `#[must_use]` and non-`Drop`; the
Teller's single exit path is its only consumer (C11/C12). The "zero unsettled holds" canary is
derived from journal replay (a hold with no settlement) and asserted after every cell. Replay after
crash re-derives open holds from the journal and settles them per C3. (The existing
`settle_admission` code is the furnishing; the two-phase rule is the contract.)

**D3 — Admin is a plane.** `AdminPlane` claims `Http`; its credential facts are admin tokens (an auth
plugin kind); its Route step's destination is a **unit method** (mint key, set group, revoke, read
usage, read audit) rather than an upstream. Same 7 steps: minting a key is Admitted (rate/count),
Metered (count), Audited (who/what/when) like any transaction — "opening an account is a
transaction". The admin API's cells are enumerated from `openapi.json` and join the oracle; 1.5.5's
responses are the golden. Effects-read endpoints (`/usage`, `/audit`, `/metrics`) are themselves
admin units, so the closed-loop battery reads its evidence through the Teller too.

**D4 — Hooks have one seat.** A hook is an observer invoked **between** steps with the facts so far.
It may return `HookFacts` that are *appended* to the unit's fact set (e.g. a ranking hint Route's unit
may use); it cannot mutate an existing fact and cannot construct a `Decision` (type-enforced: hooks
receive `&Facts`, return `HookFacts`, and `Decision` has no public constructor). Ranking hooks are the
first client. A hook that panics or exceeds its time budget is recorded as `HookFailed` in Audit and
the unit proceeds — hooks are advisory by construction.

**D5 — Store trait grows for journal-first (Δ5).** *(Method names and ABI shape are as in C2/R29 —
`Journal::append` / `replay_batch` / `reserve` / `release`; the names below are historical.)* `Store` gains `append_posting(&Posting) ->
Result<Seq>` (append-only, ordered, idempotent on the posting's key) and `replay(from: Seq) ->
Stream<Posting>`. Budget cells are a derived cache rebuilt from replay; reconciliation is `replay ==
cells`. The store conformance suite (plugin-testkit `store`) gains the journal tests; memory, sqlite,
postgres and mysql must all pass before any store merges. This is an **additive** ABI change — the
existing operations keep their contracts.

**D6 — Config compatibility is a first-class oracle surface.** Every 1.5.5 user config must boot the
new binary unchanged. Fills: (i) regenerate the migration corpus through 1.5.5 — it currently stops
at 1.5.2, three releases unregenerated; (ii) one **boot cell** per corpus file in the oracle: the
config validates, and the registry it produces (transports, planes, units, plugins — serialized,
normalized) is identical on 1.5.5 and new; (iii) the `config-schema additive-only` gate stays. A
config that 1.5.5 accepts and the new binary rejects is RED before any request is sent.

**D7 — Duplex transport shape, defined now.** *(Corrected by C5, which is authoritative.)* Transports
yield **frames** (`fn frames(&self, conn) -> Pin<Box<dyn Stream<Item = Frame> + Send>>`, object-safe);
the plane delimits **units** from frames. HTTP: one frame, one unit. SSE: one client unit whose
response is N frames accrued into one hold. WS: Unit 0 (the upgrade; no 101 without it), client units,
provider-initiated units, and kernel Tick units — **every one runs all 7 steps** with the semantics
table in C5. Voice at hour 49 needs nothing added to `Transport` or the kernel. Backpressure and
close semantics belong to the transport's battery (frame round-trip, half-close, cancel mid-frame).

**D8 — Dynamic plugin ABI scope.** `busbar-plugin` (the dynamic ABI for auth / store / secret / hook
/ export) is kept as-is; each dynamic kind is wrapped by an adapter implementing the in-process kind
trait, so the kernel sees one trait per kind regardless of linkage. Planes and transports are static
crates in the 48 hours. No ABI churn; the existing plugin conformance suites keep running unchanged.

### 15.3 Foundation — exists at hour 0 or the streams idle

| # | Artifact | Definition of done |
|---|---|---|
| F9 | **Contract as code**: crate `busbar-kernel-contract` — the kind traits (`Plane`, `Transport`, `Auth`, `Store`, `Secret`, `Hook`, `Export`), the unit traits (auth, trust, scope, admission, egress, ledger, audit), facts types, `Ctx`, `Decision` (sealed), `Hold`, `UnitEnd`, `register_plugins!`. A kernel skeleton compiles with `Noop*` plugins. | `trybuild` compile-fail tests: a plugin naming `busbar_core` fails; a plugin constructing `Decision` fails; a kind trait with a default method body fails a lint; `register_plugins!` with a mismatched claim fails at const-eval. |
| F10 | **Templates + red battery**: `plane-template`, `transport-template`, `unit-template` crates with every method blank; `plugin-testkit` extended with the per-kind battery that runs against each template. | Battery runs and is RED against every template at hour 0; a stream's done = green. |
| F11 | **1.5.5 golden**: `busbar-oracle` records LLM (126) + admin (from openapi.json) + boot (D6) cells from the published 1.5.5 binary. | `oracle replay --against target/debug/busbar` produces a diff report; the diff-accept ledger file exists and is empty. |
| F12 | **Unit goldens before extraction**: solo suites for ledger / audit / admission written against the contract (journal-first, idempotent, replay reconciles, hold/settle, crash recovery); proptest for money. | Suites compile against `busbar-kernel-contract` and are RED until extraction. |
| F13 | **One gate**: `cargo xtask gate` — both feature builds, clippy `-D warnings`, fmt, purity + hygiene lints, oracle replay, every battery, test-LOC > prod-LOC per unit (≥2 for money units), coverage floor. | The same command for every agent and for every merge; CI runs exactly it. |
| F14 | **Stream cards**: `docs/design/streams/<name>.md` per stream — owned files (disjoint), inputs, outputs, done = named tests, forbidden list, gate command; a DAG with the critical path marked. | Every file in the tree is owned by exactly one stream or by the integrator. |
| F15 | **Bookmark**: `reference/1.6.0-pre-rebuild` for the entire tree (voice's bookmark already exists). | Pushed. |

### 15.4 Process rules

- **P16 Critical path.** F9–F15 are built *before* the clock starts, so hour 0 is parallel from the
  first minute. If they are not green, the clock does not start.
- **P17 Diff-accept authority.** Only the integrator accepts a golden diff, with a written reason in
  the diff-accept ledger. Agents cannot. "Byte-identical or accepted-with-reason" is the merge rule.
- **P18 Mutation.** `cargo-mutants` on the ledger, admission and audit crates only, run at H40; a
  surviving mutant on a posting path is RED; score floor 80%.
- **P19 Cadence.** Merge waves at H12 / H24 / H36 / H48 with the full gate each time. No big bang.
- **P20 Voice at hour 49.** Voice = one plane file filling the template + the codec furnishings copied
  from `reference/voice-1.6.0-pre-rebuild`, run through the same battery and a passthrough-diff
  against a real OpenAI Realtime rig. If it needs a kernel or transport change, the model was wrong
  and that is the finding.

### 15.5 What "gap-free" means before go / no-go
A fresh-eyes adversarial audit (two independent reviewers, two models) of this document against
`CODE-ANALYSIS.md`, looking for: a way a plugin can move money without the controls; a step that can
be skipped; a state that is not audited; a plane that needs a kernel change; a stream whose
done-criteria are not a test. Every finding is either closed in this document or explicitly accepted
by the owner. Then go / no-go. (`CORE-AND-PLUGIN-CONTRACT.md` v0.1 is SUPERSEDED — it describes the
call-in seam this design abolishes — and is not an audit input.)

**Round 1 (Opus 24 findings / Fable 23 findings, both "no")** — every finding is closed in Part 16
below, or listed there as an owner-accepted limitation. Where a closure changes an earlier part, the
earlier part has been rewritten, not merely overridden.

---

## Part 16 — Audit closures (v0.4)

Each closure names the findings it answers (O = Opus round 1, F = Fable round 1) and is stated as a
rule the contract crate, the batteries, or the gate will enforce.

**C1 — The plane never supplies the amount. (O1, O14, F5)**
`Plane::meter` returns a `UsageLocator` (JSON pointer / header name / SSE event name), never a
number. The kernel's **usage unit** extracts usage from the raw response bytes it already holds and
records the transport's own byte counts (kernel-owned) in the same journal entry. Variance rule: if a
plane-locatable value and the kernel's floor (bytes, frame count, provider-reported usage) disagree
beyond a per-dialect tolerance, the entry carries `MeterDisputed` and the kernel value posts. Battery:
(i) per plane, `meter` on a golden response with a known usage object locates exactly that object;
(ii) a deliberately under-reporting plane fixture is RED; (iii) **real reconciliation**, distinct from
"three surfaces landed": spend is recomputed from ledger tokens × the rate card read back from config
and compared to the metric, and ledger tokens are compared to provider-reported usage captured from
the raw response. Part 13's "independent reconciliation ✓" is re-labelled: landing ≠ reconciliation.

**C2 — One journal; store methods required; durable before confirm. (O2, O3, F2)**
There is ONE append-only journal. `JournalEntry { seq, key, principal, node, wall, mono, steps:
[StepOutcome], hold | settle, usage, byte_counts, audit: AuditFacts, prev_hash, hash }`. Ledger cells
and the hash chain are both DERIVED from it — Δ7's atomicity is trivial because posting and audit are
one entry. `Store::append(&JournalEntry) -> Seq` and `Store::replay(from: Seq)` are REQUIRED (no
default bodies); `append_audit`/`list_audit` lose their `Ok(())`/empty defaults (they become derived
reads). Store ABI floor → 5; a store whose manifest is below the floor **refuses to load** when
governance is configured. The four stores (memory in-tree; sqlite/postgres/mysql external) are
re-released and signed in Phase −1. Boot: write-read-back of a probe entry with hash verification;
replay detects sequence gaps. **Durability point:** the entry is durable before the response bytes
leave (post before confirm) via a **kernel-owned per-node WAL** (append-only file, fsync'd) flushed
asynchronously into the store — the store stays off the hot path; the timing gate is re-baselined
explicitly for the WAL append in Phase −1.

**C3 — Exactly-once by write-ahead hold; kernel-minted key; recovery rule. (O4, F7, F21)**
The idempotency key is kernel-minted (UUIDv7 + principal id), never read from the wire; the client's
correlation id is a separate audited label. The Hold IS the first journal entry for the key
("authorization"), written before egress; Meter writes the settlement ("capture"). Recovery: on boot,
every open hold older than the unit timeout is settled **at estimate** with `partial: true, recovered:
true` and an audit entry, and reported on `/usage` as recovered spend. Wording everywhere:
"exactly-once per idempotency key, where the key's first entry is the hold." Tested with `kill -9`
between every adjacent pair of steps, not just Meter/Audit.

**C4 — `Decision` sealed by capability. (O5, F3)**
`Decision::allow / refuse` take `&UnitToken`; `UnitToken` has a private field and is constructed only
in the kernel crate, which passes it into unit-trait methods. Planes, transports, hooks never receive
one. trybuild fixtures: a plane holding `&AdmitFacts` cannot build a `Decision`; a unit cannot build
one without the token. 5A.2's "`pub(crate)` inside core" is withdrawn.

**C5 — Unit ≠ frame; sessions; Unit 0; provider-initiated units; Ticks; plane session state.
(O6, O7, O8, F1, F13, F14, F15)**
- A **unit** is a governed transaction; a **frame** is transport bytes. A streamed response is ONE
  unit with N frames: Meter *accrues* per frame into the open hold and *settles once* at stream end.
  Posting cardinality per outcome class is stated in the effects spec (C10) and asserted by the oracle
  — this keeps the LLM ledger byte-identical to 1.5.5 ("token counts land when the stream completes").
- **Transports yield frames** (`fn frames(&self, conn: Conn) -> Pin<Box<dyn Stream<Item = Frame> +
  Send>>` — object-safe). The plane delimits units from frames (`decode_ingress` returns `None` until
  a unit is complete). HTTP: one frame, one unit.
- **Unit 0** is the open request (HTTP upgrade for WS, first message for stdio/gRPC-stream). It runs
  all 7 steps; if refused, the transport MUST NOT upgrade (HTTP 4xx, no 101). Its Route step yields a
  duplex `Destination`; the egress unit dials the upstream and the kernel registers `Session { client:
  Conn, upstream: Conn, principal }`. Transport battery: "no 101 without a Completed Unit 0."
- **Provider-initiated units.** A provider frame arriving with no open unit opens a unit with
  `origin: Provider`. Its 7 steps are defined, not degenerate: Authenticate = `CredentialLocator::
  FromSession` (revocation re-checked) · Verify = destination is `session.client`, re-checked against
  the deny-list · Approve = scope `stream:receive` · Admit = headroom check, no per-frame fee · Route =
  `Destination::Client(session)` — the egress unit writes it via the transport, blind to why · Meter =
  provider-reported usage via locator · Audit. No direction-flavored logic in the kernel: `Destination::
  Client` is one more destination kind the egress unit handles.
- **Tick units.** The kernel synthesizes a `origin: Tick` unit per session per configured interval;
  it runs all 7 steps (Authenticate re-checks revocation, Admit re-checks headroom, Meter posts
  elapsed-time usage where the rate card has one, Audit checkpoints). An idle session with a dry budget
  or a revoked principal is closed and audited within one tick. Battery cell: session with zero frames
  + exhausted budget → closed within one tick.
- A refused or failed unit inside a session hard-closes BOTH sockets and seals `Aborted(Kernel)` for
  the session.
- **Per-session plane state:** `Plane::open_session() -> PlaneSessionState`, created by the kernel at
  Unit 0, passed `&mut` to the two decode methods only (split per direction — R7), dropped at close.
  `Ctx.session` is present for every
  non-one-shot unit and carries the resolved principal.
- Proven in Phase 0 by the **echo plane dialing an echo upstream over WS through K-route**, including
  a Tick and a mid-session revocation — not by a client-only echo, and not at hour 49.

**C6 — Egress request + auth scheme; secrets never reach a plane. (O9, F6)**
`encode_egress` returns `EgressBody { method, path, headers, body, auth: AuthScheme }`; the kernel
builds the wire request from it and the `VerifiedDestination` (R5). The kernel's
**egress-auth unit** resolves the secret through the secret plugin and applies the scheme after
encoding (`busbar_substrate::sigv4::sign_v4` for Bedrock, kernel side). `Secret` and `Credential`
are non-`Serialize`, non-`Debug` newtypes with an explicit `expose()` that the gate's AST scan flags
outside the egress-auth and auth units — so neither can be copied into `AuditFacts` or response bytes.

**C7 — Plugin threat model. (O11)**
Static plugin crates: the gate runs a source denylist (`std::net`, `std::fs`, `std::process`,
`tokio::net`, `reqwest`, `hyper`, …) with a reviewed allowlist per crate. Dynamic plugins: signature
verification at load is MANDATORY against an operator-configured key set (`plugin-sign` wired as
required); every load seals a journal entry (kind, key, digest, signer); the design states plainly
that a loaded dynamic plugin is fully trusted native code — the signature is the control.

**C8 — Upgrade, rollback, chain continuity, resolved-policy diff. (O12, F17)**
D9: the store schema version is written and checked at boot. First boot on a 1.5.5 database: verify
the old chain head, seal a `migration` entry linking it (no seam in the trail), replay legacy window
cells into an opening-balance posting, and **dual-write window cells for one release** so a rollback to
1.5.5 keeps balances. Rollback is an oracle cell: boot 1.5.5 on a database written by the new binary;
usage reads match. D6 is extended: the boot cell serializes the **resolved policy** (fees, limits, rate
card, allow-lists, plugin set), not just the registry, and diffs it against 1.5.5.

**C9 — Hooks: bounded facts, veto as a fact, fail-closed, audited. (O13, F10)**
`HookFacts { permutation: Option<Permutation<CandidateIdx>>, veto: Option<Reason> }`. A permutation may
only reorder the plane-supplied, already-Verified candidate set — never introduce a candidate, never
alter cost or principal. The **Admit unit** consumes `veto` as a fact and refuses on it (audited
`Refused(Admit, hook:X)`). Per-hook failure policy is config: `on_failure: open | closed`, default
`closed` at gate points. Every applied permutation is sealed ("hook H applied P"). Parts 1, 2.13 and 7.1
use this one vocabulary.

**C10 — Honest effects reference; MCP/A2A effects oracle; four-eyes on accepts. (O15, F4, F19)**
The 1.5.5 golden supplies **response bytes and ledger deltas**. It cannot supply per-request audit
(1.5.5 records only admin actions) or refusal metrics. Those are asserted against an **integrator-owned
effects spec per outcome class** (7 classes × {action, outcome, principal, step, usage fields,
posting cardinality}) committed before Phase 0. For MCP/A2A/voice the effects oracle is independent
of the transcript: expected posting count and amount derive from the mock upstream's known usage;
refusal shapes are taken from the conformance rigs' reference control (`testing/mcp-conformance`,
`testing/a2a-tck`), not hand-written by the plane's builder. Normalizer rules are diff-accept ledger
entries with the same sign-off. Any accepted diff touching an `effects` field needs two approvers
(integrator + owner); accepts freeze 4 hours before cutover.

**C11 — What Rust can and cannot enforce, labelled honestly. (O16, F12, F13)**
Compile-time: trait completeness (no default bodies → a missing method is an error), `UnitToken`
capability, non-`Serialize` secrets, ABI-only manifests, `const CLAIMS` uniqueness via a build-time
check. CI-time (xtask AST scans, not lints): no default bodies in kind traits, claim uniqueness across
crates, source denylist, `expose()` confinement. Withdrawn: "`register_plugins!` fails at const-eval on
a mismatched claim" (claims are now `const`, checked by the build script); the `const _: () = { fn
_a<P: Plane>() {} … }` idiom (replaced by a type-level assertion); `#[must_use]` as a metering proof
(replaced by **linearity**: `Usage` is consumable only by `Hold::settle(usage) -> Posted`, and the exit
path's return type requires a `Posted`); `Hold` posting from `Drop` (Hold is `#[must_use]` and
non-`Drop`; the "zero unsettled holds" canary is derived from journal replay). 5A's table is relabelled
compile-time vs CI-time.

**C12 — Planes can fail, not panic; panics still post. (O19, F8)**
Every encode/decode method returns `Result`. The Teller wraps every plane call in `catch_unwind`; a
panic becomes `Failed(step, PlanePanic)` and still runs Meter (settling the hold) and Audit. Battery: a
deliberately panicking plane at each of the twelve call sites.

**C13 — `AuditFacts` is a closed schema; key custody; erasure. (O20)**
`AuditFacts` is kernel-defined with fixed fields and size caps; free-form plane content passes a
kernel redaction pass or is refused. Chain-head signing key: custody and rotation are operator config;
the head is periodically **anchored** to an operator-controlled sink the kernel cannot rewrite
(self-attestation is not tamper-evidence). Retention is config; erasure requests are met by
crypto-shredding per-principal payload keys, leaving the chain intact.

**C14 — Arrival is step 0, audited, flood-safe. (O21, F16)**
The size/rate/source gate is step 0 of the Teller, not a hook outside it. Its refusal is
`Refused(Arrival)`, audited to the arrival even with no principal. Anonymous declines above rate R per
source are aggregated into one per-window entry; the policy is itself audited config.

**C15 — Admin dispatch without unit→unit edges; evidence reads never charged. (O22, F9)**
A fifth registry table, `LocalDestination` (mint key, revoke, set group, read usage, read audit),
registered with opaque keys like plugins; the egress unit dispatches by key, blind to the verb. Evidence
reads (`/usage`, `/audit`, `/metrics`) run Authenticate, Approve and Audit but are **never Admitted
against a budget** — an operator can always read their own trail; the exemption is a stated rule with
its own battery cell. Read entries carry `entry_class: Access` in the ONE journal (R9 — there is no
second chain) so the battery's deltas exclude the observer's own reads by class. The battery additionally performs one **out-of-band direct store read** per cell
as a cross-check on the Teller-served read — the harness may hold an internal handle precisely because
its job is to catch the Teller lying.

**C16 — The contract document. (O23, F11)** `CORE-AND-PLUGIN-CONTRACT.md` v0.1 is marked SUPERSEDED
at its head, pointing here; it is not handed to builders. Its red test (billing/voice as the litmus)
is preserved in Part 7.

**C17 — No competing schedules. (O17, F23)** Part 6's wave tables, the A–J inventory and the old
Phase V paragraph are deleted; the stream cards are the single source (above).

**C18 — Plan realism. (O18, F20)** Phase −1 is named, done-by-test, off the clock, and contains the
serial work (K-route, LLM streaming, journal-first, the probe stream as the freeze criterion). The
48 hours are fill-in against an exercised contract. The LOC ratio gates stream completion, not merge
waves. Two approvers on effects diffs (integrator + owner).

**C19 — Clock discipline. (O24, F22)** Wall-clock for posting timestamps and window rollover; monotonic
for timeouts and hold expiry; every entry carries both plus the node id. A hold spanning a window
boundary settles into the window it was opened in. Ledger battery: clock-goes-backwards property test
(no double reset, no skipped window).

**C20 — Fleet-safe budgets in 1.6.0: branch floats. (O10, F18)** Nothing is deferred. Multi-node is
the design; there is no single-writer mode.
- `Journal::reserve(bucket, amount, node) -> Result<Slice { window_start, .. }, Insufficient>` (the
  STORE computes the window from its own clock — R18), `Journal::release(slice,
  unused)` and store-assigned journal `Seq` are REQUIRED store methods, atomic at the shared store
  (`UPDATE … WHERE remaining >= n` on sqlite/postgres/mysql; a mutex on memory).
- A node's admission unit draws a **slice** (a bank branch's float) of the window's budget — journaled
  at the store as it is taken — and Admit runs locally against the slice, off the network, so the
  timing gate is unchanged. Empty slice → draw another. **Σ slices ≤ budget is enforced by the
  store's atomic update, never by a node's memory**; overdraft is impossible by construction.
- Near exhaustion the slice shrinks to exactly the remaining amount: the last unit is exact.
- Every node holds an **instance lease** (id + heartbeat through a Tick unit). A node that dies
  mid-slice: its lease expires; the store releases only `slice − Σ settlements it has observed` and
  suspends the rest as `UnreconciledSpend` (R14) with an audit entry;
  its WAL replays on restart and its settlements land under the store's `Seq`.
- Reconciliation is global: Σ settlements + Σ open slices == store remaining; replay is ordered by
  store `Seq`.
- Store conformance (all four stores): N concurrent nodes × M units, the sum never exceeds the
  budget; kill a node mid-slice; clock skew between nodes. Any overdraft is RED.
  *(Refined by R5/R14/R18: the store derives the window; expired slices are suspended, not released;
  see Part 17.)*

---

## Part 17 — Round-2 audit closures (v0.5)

Round 2 (fresh Opus: 12 blockers / 17 gaps; fresh Fable: 10 blockers / 16 gaps; both "no") checked
whether Part 16's closures were REAL. Eight of the ten worst were found by both. Every finding is
closed here as a rule the contract crate, a battery, or the gate enforces. *Think bank teller.*

**R1 — Object safety. (O1, F1)** `PlaneMeta { const KEY; const CLAIMS }` is a separate non-dyn trait
named only by `register_plugins!` and the build script; `Plane` and `Transport` carry no associated
consts and no `impl Trait` returns (`Transport::frames -> Pin<Box<dyn Stream<Item = Frame> + Send>>`).
The contract crate contains `const _: fn() = || { let _: Option<Box<dyn Plane>> = None; }` and the
same for every kind, so `Box<dyn …>` can never regress.

**R2 — The plane never supplies an estimate either. (F2)** `AdmitFacts` carries locators only (model
id, `max_tokens` pointer, input byte span). The **cost unit** computes the estimate from kernel-owned
body bytes × the rate card; the hold is opened at that value. Recovery settles an open hold at
`max(estimate, kernel byte-floor)` with `recovered: true`. Battery: a plane fixture returning a zero or
negative "estimate" (it cannot — the type has no such field — but a fixture with a wrong locator)
produces the same hold as the honest plane, or `MeterDisputed`.

**R3 — Priced once, at settlement; never re-priced. (O9, F3)** Every posting carries `rate_card_version`
(content hash of the resolved card) and its priced amount in integer minor units. `derive` sums stored
amounts. Rate-card changes are effective-dated at a window boundary and are themselves journal entries
(R21). Closed windows are immutable. C1's reconciliation recomputes with the per-posting version.
Test: change the card mid-window; historical spend byte-identical.

**R4 — A plane never sees a credential. (F4)** Step 0 strips credentials from the arrival by the
locations the plane's `Claim` declares (header / query / first-frame field) into a kernel-only
`Credential`. `Unit` has no field that can hold one; `authenticate` returns a `CredentialLocator`
(scheme + where), exactly as `meter` returns a `UsageLocator`. Battery: a plane fixture that echoes
all inbound headers into its egress body puts no credential on the wire (the kernel already removed it).

**R5 — Route is bound to Verify. (F5)** The trust unit returns `Vec<VerifiedDestination>` (capability
newtype; kernel/trust-unit constructed). `RoutePlan` is `Vec<VerifiedIdx>` into that set. The kernel
builds the wire request from `VerifiedDestination` + the plane's `EgressBody`; the egress unit re-runs
net-guard/SSRF at dial. trybuild: a plane cannot construct `VerifiedDestination`.

**R6 — Per-node chains + global checkpoints. (O6, F6)** Each node seals its own chain over its WAL:
`(node_id, node_seq, prev_hash, hash)` computed at WAL time. The store's global `Seq` is an ordering
label OUTSIDE the hash. A kernel-synthesized `checkpoint` entry (every N entries or T seconds)
cross-links every node's chain head into a global head, which C13 anchors externally. `verify` =
every node chain verifies AND every checkpoint's cross-links resolve AND store `Seq` is monotonic per
node. Battery: tamper one node's WAL segment → `verify` fails at the next checkpoint.

**R7 — Concurrent units per session; duplex semantics. (O8, F7, F22)** Two frame streams per session
(client, upstream), each with its own cursor and its own half of `PlaneSessionState` (so no two units
share `&mut`). A per-session task runs up to K units concurrently (K config, default 4); Tick units
are merged with `select!` and run at scheduler boundaries — they never abort an in-flight unit except
by revocation, which hard-closes the session. A duplex **client** unit ends at Route = "written to
upstream" (`Completed`, zero-usage settle, hold released); the provider's answer is a **provider-
initiated** unit correlated by `reply_to`. Provider-initiated **requests** (MCP sampling, A2A push
events, Realtime tool calls) carry `reply_to`; the client's reply is a client unit whose Route is
`Destination::Upstream(session)`, Verified against the session's upstream. Phase −1 probe MUST
include: a duplex echo cell with a provider unit opening while a client unit is in Route, a Tick
interleaved, a mid-session revocation, and one bidirectional JSON-RPC (sampling) cell. The contract
does not freeze without them.

**R8 — Usage extraction is kernel-owned per dialect. (F8)** The usage locator per dialect lives in
kernel config (the rate-card entry: e.g. openai-chat → `/usage`, anthropic → `/usage`, SSE → the named
terminal event). The plane's `meter` CONFIRMS it; mismatch → `MeterDisputed`. The kernel byte floor is
a tokens *lower bound* (bytes ÷ per-dialect divisor) and is never posted as the amount on its own.
SSE without a usage object: the rule is whatever 1.5.5 does for that cell, recorded by the oracle and
stated per dialect in the effects spec (`estimated: true` where 1.5.5 estimates).

**R9 — Evidence reads run all 7 steps; no loop branch. (F9, O16)** The admission unit's decision for
scope `evidence:read` is `Allow` with a zero hold — a fact-driven rule inside the unit, stated in
config. Meter posts `count=1, cost=0`. There is ONE journal (C15's "access chain" is withdrawn): read
entries carry `entry_class: Access` and the battery filters on it. Every entry class is hash-chained,
anchored and `verify`-covered identically.

**R10 — Mixed-version fleets. (O11, F10)** Every entry carries `journal_schema_version` and
`hash_algo_version`; the hash input is versioned. A node refuses to start if the store's maximum
observed version exceeds its own. **1.5.5 → 1.6.0 is stop-the-world** (drain every 1.5.5 node before
the first 1.6.0 node boots); the boot check refuses to enable slices if the dual-written cells show a
write from an unleased node in the current window. Rolling upgrades between 1.6.x versions are
allowed with slice semantics frozen for the pair. Oracle cell: two binaries (N−1, N) driving one
store concurrently — chain verifies, no overdraft.

**R11 — Per-step tokens. (F11)** `UnitToken<S: Step>`; `Decision<S>::allow(&UnitToken<S>)`. trybuild:
`UnitToken<Meter>` cannot build `Decision<Admit>`.

**R14 — Lease expiry and WAL loss. (O5, F14)** Slice draws AND settlements are journaled at the store.
On lease expiry the store releases only `slice − Σ settlements observed at the store for that slice`;
the remainder becomes `UnreconciledSpend` — counted as consumed for headroom, never credited back —
with an audit entry and a `/usage` line. A late WAL replay lands as a correcting posting against the
unreconciled amount. An audited admin `resolve_slice` verb closes what never replays. Conformance
cells: kill node with WAL destroyed; kill node and restart after lease timeout.

**R15 — Fail-closed matrix. (O18, F15)** WAL append failure at Admit → `Refused(Admit,
DurabilityUnavailable)`, no egress, alarm. WAL failure at Meter → bounded retry, then hard-close the
unit's session, mark the node `draining` (heartbeat stops; its slice suspends per R14). Disk full =
WAL failure. Store unreachable when the slice is exhausted → fail closed after the current slice,
with at most one journaled grace slice per window (config, default 0). Backpressure: a bounded frame
buffer per unit; when full the kernel stops reading upstream (TCP backpressure); accrual is bounded by
the hold cap (R17). Battery: ENOSPC injected at both WAL points; store killed mid-run; slow client.

**R16 — Reversals, credits, disputes under dual control. (O10, F16)** `LocalDestination` gains
`adjust(principal, bucket, window, amount, reason, reference_seq)` — a reversal/credit posting that
references the original entry's `Seq`, never an edit — and `resolve_dispute(entry_seq, verdict)`.
Dual control (two distinct admin principals, both recorded) above a configured threshold; a per-window
adjustment cap. Every `MeterDisputed` must reach a terminal verdict or appear on the open-disputes
report. Both verbs run all 7 steps like any admin unit.

**R17 — The hold is a cap. (F17)** `Hold::accrue(delta)` returns `Exhausted` at the hold boundary →
one top-up from the node's local slice; if the slice is empty, one store `reserve`; else `Aborted
(Kernel)` with settlement at accrued-so-far. Top-ups are journaled. The timing gate applies to the
local path.

**R18 — The store owns window identity. (O4, F18)** `reserve(bucket, amount, node)` — no window
parameter. The store computes `window_start` from its own clock inside the atomic update and returns
it in the `Slice`. Nodes never compute a window boundary. Conformance: N nodes with ±60 s injected
skew; the sum across the true window never exceeds the budget.

**R19 — The effects spec covers every `UnitEnd` × step. (F19)** Client disconnect mid-stream,
`TimedOut`, `PlanePanic`, `Aborted(Kernel)` on revocation, `MeterDisputed`, recovered-at-estimate,
encode failure after posting, `attempt_abandoned` — each with posting cardinality and flags.

**R20 — The journal is unconditional. (F20)** "No governance configured" means unlimited budgets,
never no postings. The store floor applies always.

**R21 — Boot, reload, binary and policy are journal entries. (O12, F21)** At every boot and every
reload the kernel seals `PolicyEffective { binary_digest, resolved_policy_hash, resolved policy
(fees, limits, rate card, allow-lists, plugin set, store ABI level, schema version) }` and refuses to
serve if it cannot. Rate-card, budget and allow-list changes route through `LocalDestination` verbs
(`set_rate_card`, `set_budget`, `set_allow_list`) or through a reload that seals the diff. Battery:
change a fee, restart; a `PolicyEffective` entry with the diff exists and no posting before it prices
at the new fee.

**R23 — The kernel is mutation-tested. (F23, O15)** `cargo-mutants` over the kernel, the contract
crate and the usage crate, with a 100 % floor on the Teller loop file; plus ledger, admission, audit.

**R24 — Segregation of duties in the build. (O19, F24)** The effects spec's amounts are hand-computed
literals (rate card × known token counts) signed off by the owner BEFORE the cost unit exists; they
may not be derived from code under test. A verifier model with no access to the kernel diff hashes
the spec; the gate pins the hash. The integrator may not approve the effects diff of their own kernel
change — the owner or the verifier does. Cross-plane invariant: identical token counts through LLM,
MCP and A2A produce identical postings.

**R25 — Panic semantics. (O23, F25)** `catch_unwind(AssertUnwindSafe(..))` around every plane call;
`PlanePanic` poisons the session state, which is dropped, and hard-closes the session. Abort-class
failures (OOM, stack overflow) are process-level and covered by WAL replay, not `catch_unwind`.
`panic = "unwind"` is pinned in the workspace and asserted by the gate.

**R26 — Phase −1 is dated and has a stop-loss. (O27, F26)** Phase −1 gets its own plan with per-item
gates, a named owner, and a date D. Three items can independently sink it and are tracked as such:
the external store re-releases at floor 5; K-route shadow-diff = 0 on the streaming path; the WAL
timing budget (R28). If the probe stream (R7's cells included) is not green by D, the 48 hours do not
start. Phase −1 is the project; Phase 0 is the fill-in.

**R27 — Client idempotency keys. (O3)** The journal key is `(principal_id, client_key)` when the client
supplies one at the location the plane's `Claim` declares (e.g. `Idempotency-Key`), otherwise
kernel-minted UUIDv7 + principal. `Journal::append` is idempotent on the key. A second arrival on a
live key returns the first unit's outcome and is audited `Replayed`; no second hold. Oracle cell:
retry after a simulated 502, exactly one posting.

**R28 — Durability per phase; group commit; a numeric budget. (O2, O28)** The **hold** is fsync'd to
the WAL before the first response byte leaves. The **settlement** is fsync'd before the terminal frame
(`[DONE]`, final chunk, `response.done`) leaves. Intermediate frames are relayed under the hold's
authority. Group commit batches fsyncs across concurrently open units with a bounded delay. Budget,
stated once: WAL append adds ≤ 1 ms p99 to a unit and sustained throughput is not below 1.5.5's
measured baseline on the same hardware; the timing gate is re-baselined to that number once, in
Phase −1, and never again. Oracle cell: kill after N stream frames → recovery settles at
accrued-so-far.

**R29 — Store ABI, honestly. (O7)** D8 is corrected: the store kind's dynamic ABI DOES churn, to floor
5. The journal methods are a separate `Journal` trait projectable onto the `extern "C"` surface:
`append(&JournalEntry) -> Seq`, `replay_batch(from: Seq, max: usize) -> Vec<JournalEntry>` with a
watermark (no `Stream` across the ABI), `reserve`, `release`. Their signatures are explicitly
blocking-offloaded (`spawn_blocking` or a dedicated journal executor); the thread model is stated in
the contract crate. The cross-repo release of sqlite/postgres/mysql at floor 5 is a named, dated Phase
−1 deliverable with its own gate.

**R30 — Encode failure after posting. (O13)** `encode_response` error → the kernel emits a
kernel-default error body AND appends a reversal posting referencing the original `Seq` (R16
machinery). `encode_refusal` error → the kernel emits a kernel-owned minimal refusal (status + empty
body); a plane bug can never swallow a decline. Both are effects-spec classes with oracle cells.

**R31 — Failover and partial accrual. (O14)** Accrual is per attempt, tagged by attempt index.
Failover is permitted only before the first byte (as in 1.5.5) and discards the failed attempt's
accrual as an explicit `attempt_abandoned` line — visible, not silent. An upstream drop after the
first byte is `Failed(Route)`: settle at accrued, the client receives the dialect's native stream
error. Oracle cells: upstream drop at attempt 1 and at attempt 2.

**R32 — `Usage` is constructible only by the usage unit. (O15)** Private field; the constructor takes
the raw response bytes and the kernel byte counts and derives the value — it is never passed in.
trybuild: constructing `Usage` outside the usage unit fails.

**R33 — Erasure vs the chain; anchor policy. (O17)** The entry hash covers the ciphertext of the
erasable payload and the plaintext of the non-erasable financial fields (amounts, principal id, seq,
timestamps, rate-card version) — which are retained through an erasure request, as a bank retains
financial records, and documented as such. Per-principal payload keys live in a keyset separate from
the chain-head signing key; rotation and escrow are stated; key loss is treated as erasure and
journaled. Anchor cadence is config; N consecutive anchor failures alarm and are themselves journaled.

**R34 — The normalizer is kept honest mechanically. (O20)** A negative corpus: pairs of goldens that
differ in exactly one meaningful field (usage counts, model id, finish reason, status, every `effects`
field). CI asserts the normalizer leaves every pair different; a rule that collapses a pair fails the
gate before any sign-off. Diff-accept entries name the cells and fields they cover and expire.

**R35 — Call-site attribution is a conformance-build property. (O21)** A `cfg(busbar_conformance)`
build of the same source inserts a recording layer at the single registry dispatch point; the gate
asserts the conformance and release builds differ only in that file; the oracle replay runs the
release binary (artifact hash checked).

**R36 — Claims are a closed grammar; overlap is an error. (O22)** `Claim = transport kind + (exact
path | single-level prefix) + optional exact header match`. The build script and the boot registry
reject OVERLAPPING claims, not merely duplicates. Battery: two planes with overlapping claims → boot
refuses.

**R37 — Aggregated declines are lossless. (O24)** Above rate R per source, declines are counted, not
itemised: exact count, distinct-source count, first/last timestamps, and per-(transport, claim,
reason) counts. Δ6 says so plainly. Battery: 10×R declines → the aggregate equals the drive count.

**R38 — Admin bootstrap is a unit. (O25)** First boot synthesizes an `origin: Bootstrap` unit that
seals `BootstrapAdmin { credential fingerprint, source, node, wall+mono }`, single-use — refused
`(Approve, AlreadyBootstrapped)` if any admin key exists in the journal. Battery: bootstrap twice.

**R39 — Amounts. (O26)** Integer minor units (the existing nano-unit rates in `cost.rs` are the
model), an explicit currency on the rate card and on every posting, per-posting half-even rounding,
mixed currencies in one bucket = boot-time config error. Property test: Σ postings in any order ==
the window total, exactly.

**R40 — Dynamic-plugin caveat stated where the guarantee is stated. (O29)** Part 0 point 6 and Part
13's verdict table now say it.

**R41 — Nits. (F12, F13, F27, F28, F29)** Part 3's invariant sentence on the key is fixed; 5A rows
2/8/9/12 are rewritten with compile-time vs CI-time labels; "reattach" is deleted; D5's names defer
to C2/R29; Part 13's reconciliation cell is rewritten.

**Owner decisions recorded this round.** (i) Voice scope: OpenAI Realtime over WS and WebRTC (busbar
terminates WebRTC), Gemini Live as a second egress dialect, one-shot transcribe/TTS as HTTP units,
**Twilio Media Streams in scope** (a WS-carried transport plugin + μ-law codec), **raw SIP out of
scope**. (ii) Tools mid-call: relayed to the client AND executable through the MCP plane as a
governed cross-plane destination. (iii) **The audit record is a fixed schema, required for every
plane, never optional or plane-chosen**: who (principal), what (unit key, op class, verified
destination), when (wall + monotonic, node), outcome (`UnitEnd`, step), amount (usage, priced amount,
rate-card version), controls (hold/settle seqs, slice, hooks applied), integrity (prev hash). Content
— prompts, tool arguments, audio, transcripts — is never in the chain for any plane; a customer who
wants content retained gets it from an export plugin into their own sink under their own retention.


---

## Round 3 — findings and where v1.0 closes them

| Finding (O = Opus r3, F = Fable r3) | Closed in ARCHITECTURE.md |
|---|---|
| F1/O10/O11 voice scope needs WebRTC transport, Twilio-over-WS composition, query-param egress auth, HMAC ingress auth, cross-plane destination | §1.3 open vocabulary; §3.4 `COMPOSES_OVER`, multiplexed frames; §5 webrtc/twilio rows; §7 egress-auth plugins; §2.3 nested units; §9 built in Phase −1/0 |
| F2 media-rate ingress | §2.3 open client unit; §9.1 50 fps probe cell |
| F3 cross-node idempotency | §4.4 `claim_key` synchronous |
| F4 recovery captures never-dispatched holds | §4.4 `Dispatched` marker, void vs capture |
| F5/O19 capture exceeds slice; budgets | §4.4 overdraft rule; §4.3 two budgets |
| F6 `Posted` vs WAL failure | §2.2 `UnitEnd.posted: Result<Posted, DurabilityLost>`; §4.3 |
| F7/O3 capability types across crates | §3.1 `busbar-caps`; §3.5 tokens per type; manifest lint |
| F8/O25 replay semantics, in-flight duplicates | §4.4 409 Replayed / InFlight; liveness one window; 1.5.5 divergence pre-accepted |
| F9/O16 dual control shape, `resolve_slice`, `UnreconciledSpend` | §4.7 propose/approve verbs; §4.6 non-invoiced |
| F10/O18 hooks choose the price | §4.5 hold at max over candidates; priced delta sealed and attributed |
| F11 journal trait: heads, heartbeat, checkpoint election | §1.4 store row; §4.2 |
| F12 retention vs chain | §4.2 purge at anchored checkpoints |
| F13/O9 cross-direction state, server-VAD turn boundaries | §2.4 `SessionFacts` |
| F14/O30 Phase −1 contents, date, missing artifacts | §9.1 |
| F15 voice acceptance against a live model | §8.1 deterministic Realtime rig + live smoke |
| F16/O19 WAL budget realism | §4.3 |
| F17 window membership | §4.6 slice `window_start` on every posting |
| F18 config schema | §3.2 `CONFIG_SCHEMA` |
| F19/O5 two Teller blocks, stale trait text | v1.0 has one loop, one trait |
| F20 rate-card version at hold | §4.5 |
| O1 plane constructs `Unit` | §3.2 `UnitDraft`; kernel sole writer of identity |
| O2 duplex turns settle without a hold | §2.3 turn-level hold |
| O4 pre-Admit refusals cannot produce `Posted` | §2.2 zero-value hold at step 0; no `?` |
| O6 `Claim` lacks credential/idempotency locations | §3.3 |
| O7 `model_id` is the price | §4.5 three-way model cross-check |
| O8 1.6.x rollback | §4.8 committed write version + `commit_upgrade` |
| O12 frames carry no error | §3.4 `Result<(StreamId, Frame), TransportError>` |
| O13 `AdminSurface` side door | withdrawn; §4.7 `plane_facts` verb |
| O14 `Plane::audit` exfiltration | §3.2 two ids only; §4.9 |
| O15 memory/sqlite N-node conformance vacuous | §4.6 `FLEET_SAFE` |
| O17 arrival entries have no principal | §4.1 `subject` |
| O20 K concurrent vs `&mut` decode | §2.1 per-direction decode serialized |
| O21 build-script overlap check impossible | §3.3/§3.7 xtask + boot |
| O22 effects spec authorship | §8.1 verifier authors amounts; mechanical derivation |
| O23 drain | §2.3 |
| O24 erasure vestigial | §4.2 financial record exempt; content is the sink's |
| O26 unknown model at Admit | §4.5 `Refused(Admit, Unpriced)` |
| O27 mutation at H40 | §8.3 Phase −1 exit + every wave |
| O28 encode-failure reversal policy | §4.7 |
| O29/O30 nits, artifacts | v1.0 references only what Phase −1 creates |

## Plane-X litmus — decompositions (kernel change needed: none)

| Plane | Transport | Unit | Auth | Verify | Meter classes | Destination |
|---|---|---|---|---|---|---|
| VPN (WireGuard) | udp, one stream per peer | a flow (open client unit, Tick-settled) | noise-handshake plugin | dst ip/port allow-list at open | bytes_in/out, flow_seconds | Upstream(peer) |
| DNS resolver | udp / doh | one query | mtls / bearer | qname allow/deny | queries by qtype | Upstream(resolver) |
| SMTP relay | tcp line protocol | one message | smtp-auth plugin | recipient domains | messages, bytes, recipients | Upstream(MX) |
| SSH / git | ssh (multiplexed) | one pack negotiation | pubkey plugin | repo path | bytes, ops | Upstream(git) |
| Kafka / MQTT | tcp framed | publish; each delivery a provider unit | sasl plugin | topic ACL | messages, bytes | Client(selector) fan-out |
| S3-style blob proxy | http | streaming multipart (open unit) | sigv4 / bearer | bucket/key | bytes, objects | Upstream(store) |
| Embeddings | http | one request | bearer | model | tokens_in, requests | Upstream |
| Image generation | http / sse | one request; progress frames | bearer | model | images, pixels, requests | Upstream |
| SQL proxy | tcp (pg wire) | one statement | scram plugin | schema/table allow-list | statements, rows, bytes | Upstream(db) |
| Webhook fan-out | http | one event; deliveries as units | hmac plugin | target allow-list | deliveries, bytes | Client(selector) |
| Vector DB | http / grpc | one query/upsert | bearer | collection | vectors, queries | Upstream |
| Video | webrtc | a segment (open unit) | ephemeral secret | destination | video_seconds, bytes | Upstream / Client |

---

## Round 4 (on ARCHITECTURE.md v1.0) — findings and where v1.1 closes them

Opus: 10 blockers / 15 gaps / 6 nits / 13 dropped. Fable: 3 blockers / 20 gaps / 7 nits / 9 dropped.

| Finding | Closed in v1.1 |
|---|---|
| O1/F1 no per-frame ingress→egress codec; no open-unit / terminal signalling | §3.2 `Ingress`/`Progress` enums, `encode_ingress_frame`; §2.1 one open unit per direction |
| O2 encode methods have no session state | §3.2 per-direction `&mut PlaneSessionState` on every codec method; `open_session` returns both halves |
| O3/F12 hash preimage undefined; `window_start` outside the seal | §4.1 preimage = every field except `seq`; `window_start` node-written and hashed; `Slice` entries in node chains |
| O4/F4 no lease fencing for a partitioned node | §4.6 epochs, self-draining before expiry, `valid_until`, `StaleSlice` |
| O5/F26 transport plugin owns selector grammar and `overlaps` | §3.3 closed selector forms; kernel owns `overlaps`; boot reflexivity/symmetry |
| O6/F9 non-token quantities have no kernel source | §4.5 closed quantity sources bound in the rate card |
| O7/F20 "every path settles — compile-time" overstated | §2.2 `DurabilityToken`; §3.5 replay canary; §3.7 relabelled |
| O8/F15 arrival flood fsync amplification; R37 dropped | §2.2 restored with R, lossless counts, group-committed declines |
| O9 `plane_facts` had no trait method | §3.2 `plane_facts` + `ADMIN_VERBS` |
| O10 minted secrets pass through plane code | §3.2 `SecretOnce` placeholder substitution |
| O11 `SessionFacts` has no producer; cap behaviour | §2.4 last-write-wins, caps → `SessionFactsExhausted`; `facts` on `Ingress`/`Response` |
| O12 nested deadlock / depth / cycles | §2.3 separate pool, `max_nest_depth`, boot cycle check |
| O13 `DestinationFacts`/`VerifiedDestination` undefined | §3.6 field-by-field with verification rule per kind |
| O14 `Origin` lacks a delivery variant | §2.1 `Delivery { parent }`; §2.3 semantics + partial fan-out |
| O15 unsolicited provider unit has no hold | §2.3 own hold sized from `max_provider_push` |
| O16/F18 composition semantics; two Unit 0s | §3.4 top-transport rule; §5 twilio Unit 0 = the upgrade |
| O17/F5 `Dispatched` durability; recovery amount | §4.3 three durability points, dial blocks on flush; Tick checkpoints accrual; §4.4 |
| O18 R8 dropped | §4.5 floor is a lower bound; `estimated`; SSE per 1.5.5 |
| O19 manifest lint too narrow | §1.2 allow-list |
| O20 `verify` red forever after WAL loss | §4.2 `ChainBreak` |
| O21/F-voice passthrough-diff impossible for terminated transports | §8.1 rig triple |
| O22 overdraft unbounded | §4.4 overdraft ceiling |
| O23 hook `Facts` / export content undefined | §7 `HookView`, `HOOK_FACTS`; §3.2 `content_facts`; §4.9 access journaled |
| O24/F23 hour-49 transports outside the probe | §9.1 all transports in Phase −1; probe cells |
| O25/F29 kernel LOC budget | §1.1 ≤ 8k; four 100 % files |
| O26 Σ property | §4.5 window total defined as stored sum |
| O27 diff-accept over amounts | §8.1 forbidden; live-accept cap |
| O28 token invariants | §3.5 `!Clone + !Copy`, borrow-scoped |
| O29 `claim_key` budget | §4.3 third budget |
| O30 checkpoint election | §1.4/§4.2 `elect_checkpoint` |
| O31/F8 `client_key_candidate` | removed; `Location::UnitJsonPointer` |
| F2 nested result cannot return upstream; outbound sessions | §2.3 legs + `leg_results`; outbound sessions |
| F3 egress-auth plugin holds the secret and shapes the request | §3.6 `AuthDecoration`; unit asserts destination; dynamic schemes get `sign` only |
| F6 numeric contract vs 1.5.5 nano-units | §4.5 numeric contract |
| F7 1.5.5 admin idempotency | §3.3 `replay: Reference | Body`; §4.4 |
| F10 step-0 hold vs admission seal | §2.2 `arrival_hold(&AdmitToken<Arrival>)` |
| F11 task-level death bypasses exit path | §2.2 drop-guard `TaskLost`; Tick sweep |
| F13 price-list changes single-signatory | §4.7 maker-checker on every policy verb |
| F14 correlation label is client content | §4.1 hash + bounded label |
| F16 export content has no producer | §3.2 `content_facts` |
| F17 plane config can carry a secret | §4.8 |
| F19 slice spans a window boundary | §4.6 `valid_until` |
| F21 `FLEET_SAFE` self-asserted | §1.2/§4.6 verdict hash in `Load` |
| F22 mutation set | §8.3 adds trust, auth, egress-auth, cost |
| F24/F25/F27/F28/F30 nits | §2.1 `Step`; §3.6 `TransportEnvelope`; §3.3 scheme locations; §4.4 replay fields; §4.7 cap behaviour; §6 audio_tokens; §5 codec crate allow-list |
| Dropped closures (both lists) | R36 §3.3 · R37 §2.2 · C13 signing §4.2 · R8 §4.5 · R28 numbers §4.3 · alloc/timing gates §8.3/§10 · plane→plane manifest §1.2 · no-stub §3.7 · derived coverage §8.2 · meta-tests §8.2 · R25 caveat §2.2 · unit invariants §8.3 · C11 canary §3.5 · D4 `HookFailed` §7 · C5 Tick elapsed usage §2.3 · R26 date field §9.1 |

Owner additions this round: §10 performance and compatibility gates (≥ 120k rps, ≤ 15 MB peak, idle
and binary size ≤ 1.5.5, zero-allocation hot path, zero config changes, admin API superset); one
durability mode (group commit, no flags); Phase 0.5 performance sprint before voice; kernel sections
carry no plane-flavored language.

---

## Round 5 (on ARCHITECTURE.md v1.1) — findings and where v1.2 closes them

Fable: 4 blockers / 12 gaps / 8 nits / 7 dropped. Opus: 9 blockers / 18 gaps / 5 nits / 12 dropped.

| Finding | Closed in v1.2 |
|---|---|
| F1 epoch fencing rejects own WAL replay | §4.6 fencing split by kind; `append_batch` accepts epoch ≤ current, dedupe on (node, node_seq) |
| F2/O12 young holds from a dead incarnation; TaskLost vs recovery amounts | §4.4 recovery for every hold with lease_epoch < current; §2.2 one recovery amount |
| F3 fsync retry unsafe; mmap writeback | §4.3 pwrite + fdatasync, poisoned segment, EIO cells |
| F4/O4/O24 §10 incoherent; no instruments; no profile; baseline not transferable | §10 rewritten: two waits, reference profile file, instruments as Phase −1 deliverables, step-down alloc target, sequencer stated |
| F5 `reply_to` has no producer | §2.3 `correlates` + correlation map |
| F6/O1 numeric contract vs 1.5.5 | §4.5 1.5.5 arithmetic kept (cents, nano-cents, f64::round, truncation); stored amounts stated as the change; oracle compares quantities identical and amounts re-priced at the migration card |
| F7 non-HTTP credentials | §3.3 `HandshakeFrames`, `Selector::Port`; §5 `tcp-line`, `udp`; §6 `smtp` acid test |
| F8/O10 plane-flavored kernel wording | §1–§4/§10 scrubbed; doc scan in the gate; `UNIT0_TRIGGER` |
| F9 cross-node fan-out | §2.3 `sessions_for` directory + `peer` transport; §3.6 `Peer` kind; two-node probe cell |
| F10 operational reconciliation, anchoring kind, signing key on nodes | §4.2 `verify` verb, Tick reconciliation, `ANCHOR` export capability, signing via secret `sign` |
| F11/O16 WAL capacity, shipping, fixed-size records | §4.3 shipping SLO, high-water; §4.1 caps + continuation record; `append_batch` |
| F12/O15 store restore; epoch regression | §4.6 epoch floor in WAL header + anchor; `StoreRestore`; `reseal_epoch_floor` |
| F13/O5/O27 one-open-unit vs K vs multiplexing; one-shot sessions | §2.1 per (session, stream, direction); codec methods serialized, K past decode; `SESSION: bool` |
| F14 contract types allocate | §3.1 bounded types; §10 "outside the arena" |
| F15 hook seats | §1.3 closed `Before(step)` |
| F16/O31/O32 D blank; store ABI deliverable; kernel budget | §9.1 D set, named repos, fallback for freeze; §1.1 per-file budgets, WAL in its unit |
| F17–F24, O28–O30 nits | §4.3 wording; §3.2 `SecretOnce` exactly-one; §4.1 idempotency on (node, node_seq); §4.6 release definition; §3.4 bidirectional backpressure; §2.1 outbound idle-close, `NestPoolFull`; §3.7 profile-lock incl. panic; §4.8 mixed currencies; counts fixed; `forbid(unsafe_code)` scope; `Aborted(Client)` cancels the leg |
| O2 plane picks the priced lane | §3.6 permitted-lane set + max unit price; §4.5 hold at max always; §8.2 expensive-lane fixture |
| O3 hook permutation changes price | §4.5/§7 `max_priced_delta` default 0, `HookFailed` |
| O6 body-located credential stripping | §2.2 masking by span; §3.3 contiguous span rule; battery |
| O7 nested orphans spend after parent ends | §2.2/§2.3 cancellation scope; battery |
| O8 config file bypasses dual control | §4.7 policy diff vs approved entries |
| O9 barge-in and pacing | §2.3 `INTERRUPT_FACT` → `Aborted(Superseded)`; `EGRESS_PACING_FACT` |
| O11 ten steps vs seven | §2.1 kernel-owned steps with kernel tokens; counts fixed |
| O13 distributed decline flood | §2.2 node-global aggregation trigger |
| O14 policy/revocation propagation | §4.6 policy epoch, watermark, staleness drain |
| O17 claim release on recovery | §4.4 |
| O18 charging principal for encode failure | §4.7 always reverse; alarm/drain |
| O19 store ABI range | §7 `[4, 5]`; valkey named |
| O20 key rotation; stale payload-keys reference | §4.2 |
| O21 cardinality exception | §8.1 one named owner-signed exception |
| O22 verify after purge | §4.2 checkpoint cumulative totals |
| O23 mutation gate has no instrument | §8.3 mutation gate as Phase −1 deliverable with equivalent-mutant register |
| O25 §3.7 overstated rows | §3.7 relabelled; secrets row scoped |
| O26 `SecretOnce` | §3.2 |
| Dropped closures (both lists) | C9 §4.5 · C20 §4.6 · C20/R14 identity §4.2 · R33 stale ref removed · R39 §4.8 · R10 §4.6 · R26 §9.1 · R37 battery §8.3 · 5A.10 §1.2 · 5A.5 §1.2 · 5A.7 §1.2 · C13 caps §4.1 · R25 §3.7 · R21 battery §8.3 · C5 cell §8.3 · R7 tick §2.3 |

---

## Round 6 (on ARCHITECTURE.md v1.2) — findings and where v1.3 closes them

Opus: 10 blockers / 25 gaps / 10 nits / 11 dropped. Fable: 3 blockers / 15 gaps / 9 nits / 6 dropped.
Corrections to this log: F15 (`reference/1.6.0-pre-rebuild`) was recorded "Pushed" but only the voice
bookmark exists — it is a Phase −1 M1 deliverable. R39's "half-even" was wrong; 1.5.5 uses `f64::round`
(half away from zero) once at config load and truncates once at read — v1.3 §4.5 states 1.5.5's rule.
C20's "overdraft impossible by construction" is superseded by §4.4's `Overdraft` posting plus the full
reconciliation identity in §4.2.

| Finding | Closed in v1.3 |
|---|---|
| O1/F1/F4 numeric contract wrong (nano-units, Σ-then-truncate-once, no currency in 1.5.5) | §4.5 rewritten: nano-units stored per posting, cents only at read by one truncation, per-request fee as `Count`, currency a 1.6.0 addition; ≥10-line posting oracle cell; verifier re-derives against `cost.rs` |
| O2 RSS vs bounded types | §10 profile carries concurrency + upstream RT; arena budget formula; §3.1 ≤ 2 pinned legs; `SessionFacts` pre-allocated |
| O3 reconciliation identity omits overdraft/unreconciled | §4.2 full identity; checkpoint totals include both |
| O4/F8 dual control vs byte-identical endpoints; single-admin deadlock | §4.7 `single`/`required` posture sealed at Bootstrap; named exception only under `required` |
| O5 config-diff refusal vs edit-and-restart | §4.7 posture rule; boot cell for an edited fee under both |
| O6 interior mutability | §1.2 scan + §8.2 stateful-plane meta-test |
| O7 `op_class` widens the lane set | §2.2/§3.6/§4.5 lane permitted and hold at max over every op class the principal may use |
| O8 transports have no key material | §3.4 transport-key unit + `TransportKeyHandle`; `expose()` third unit |
| O9 `Hold` inside `catch_unwind` | §2.2 owned outside; AST scan; battery |
| O10/F16 remote `Delivery` hold | §2.3 own hold on owning node; N+1 postings; `peer` copy exception; `auth-lease` mandatory |
| O11/F2 recovery amounts contradictory | §2.2 one settlement table; recovered = last checkpoint, never the cap; disputes report |
| O12 `open_session` on one-shot planes | §3.2 `SessionPlane` sub-trait; `Option<&mut>` state |
| O13 `ArrivalRecord` undefined; non-span locations | §3.1 type; §3.4 `arrival`; §3.3 masking per form |
| O14/F14 `verify` infeasible; anchor read-back | §4.2 incremental since anchored checkpoint; `ANCHOR.read_head` |
| O15/F11 store ingest ratio; sequencer | §4.3 segment shipping, measured record rate per store, pipelined sync; hold+Dispatched one record, settle delta |
| O16 correlated auto-drain | §2.3 fleet coordination, `FleetOutage` |
| O17 per-core session tables vs fan-out/interrupt | §2.1 node-global sharded table |
| O18 kernel verbs vs open admin verbs | §1.3/§4.7 closed kernel verb table; plane `ADMIN_VERBS` open |
| O19 STARTTLS | §3.4 `upgrade`; §5 `tls`, `tcp-line`; `smtp` acid test uses it |
| O20/F9 `replay: Body` storage | §4.4 node-local sealed cache, TTL 600 s |
| O21 `SecretOnce` location | §3.2 target location asserted |
| O22 decoration can move the lane | §3.6 allow-list + post-decoration cross-check |
| O23 lying transport | §1.1 TCB statement; §4.5 socket counter; §8.2 meta-test |
| O24 pacing contract | §2.3 playout clock, bounded queue, emitted-only metering |
| O25 binary not signature-gated | §1.2 digest set in `Policy` via `commit_upgrade` |
| O26 hook veto seats | §1.4/§7 two seats only |
| O27 equivalent-mutant register | §8.3 signed by verifier, capped, expiring |
| O28/R10 version refusal | §4.8 restored |
| O29 kernel LOC ceiling | §1.1 numbers, gated |
| O30 panic profile, alloc-gate path, "107" | §3.7/§8.3/§10 corrected; measured 87 stated |
| O31 non-existent artifacts | §9.1 lists them as created there |
| O32/F18 plan realism | §9.1 milestones M1–M4, §10 measured at M2, D = 2026-10-29, rps floor at freeze |
| O33 declines lost in the commit window | §2.2 acknowledged and measured |
| O34 `MeterDisputed` rate | §4.5 alias map + rate bound |
| O35/F-keyed rps | §10 keyed-unit floor separate; unkeyed headline |
| F3 provider units inexpressible; turn-hold lifetime | §2.3 `Progress::Open(UnitDraft)`; turn close rule; correcting lines |
| F5 egress auth HTTP-shaped | §3.6 `Handshake` decoration; envelope equality |
| F6 static schemes see the secret; transports carry cleartext | §3.6 `SecretSlot`; §1.1/§3.7 transports in TCB, in-tree only |
| F7 open-ended dual-control field list | §4.7 closed key list constant; boot coverage check |
| F10 orphaned claims | §4.4 `void_claims` |
| F12 contract types allocate | §3.1 `ArenaBytes`, `Ctx.arena`, `Bytes` banned |
| F13 ingress-content quantities | §4.5 `Locator { direction }`, `TransportUnits`, `Count` defined |
| F15 ranking policies vs `max_priced_delta` | §4.5 `Migration` seals unbounded for named policies |
| F17 canary one-sided | §3.5 two-sided canary |
| C1 variance rule (dropped) | §4.5 restored |
| R31 attempt-1/2 cells (dropped) | §4.4/§8.1 |
| Nits (both) | counts = 16; masking fill bytes; `open_session(ctx)`; fact value types; `DurabilityLost` fate; doc-scan wording; FFI crate placement; type index; unit trait shapes; per-class pricing invariant; live accepts defined; supersede race; anchor trust statement; token lifetime mechanism; nested double-reserve; feature-invariance; no self-mount; `timing_gate` successor named |

---

## Round 7 (on ARCHITECTURE.md v1.3) — findings and where v1.4 closes them

Opus: 12 blockers / 23 gaps / 3 nits / 4 dropped + 17 weakened. Fable: 5 blockers / 14 gaps / 5 nits / 8 dropped.
v1.4 is fully self-contained (battery register, budgets, constants inline); from v1.4 on, edits are surgical.

| Finding | Closed in v1.4 |
|---|---|
| O1 no egress transport (`dial`) | §3.4 `dial`, `EGRESS_SELECTOR_FORMS`; `Upstream { transport }`; egress unit owns the pool |
| O2 breaker and pool deleted | §3.1 `breaker` unit + pool in egress; §8.3 breaker solo battery; §9.2 K-breaker |
| O3 settlement bills the maximum when evidence is missing | §2.2 table posts the lower; lane mismatch → cheaper |
| O4 `single` posture voids dual control; default unstated | §4.7 default stated; irreducible set needs an operator-key signature in both postures; residual risk in Appendix A |
| O5/F20 reconciliation identity | §4.2 `== budget − store remaining`; budget sealed in checkpoints |
| O6/F17 RSS vs bounded types; profile fields | §10 profile pinned (RT, concurrency, TLS, bodies, store); arena 4 KiB; second RSS row at 2 s RT |
| O7 session RSS unguarded | §10 per-session RSS row; alloc gate per session; `MAX_PLANE_SESSION_STATE_BYTES` |
| O8/F24 `panic` not set/checked | §3.7 honest; M1 deliverable |
| O9/F15 drop-guard vs `Hold` linearity | §2.2 detached tasks, abort scan, guard marks, Tick sweep as second sealed entry |
| O10 battery by reference | §8.3 full register inline |
| O11/F13 op class sets price | §1.4/§4.5 price = f(lane, meter_class) only |
| O12/F21 store ABI | §1.4/§7 floor 5 to admit; 4 read-only; 1.5.5 ABI 2 never loads; rollback via 1.5.5 binary |
| O13/F9 replay cache | §4.4 store-backed sealed `replay_put/get` |
| O14/F11 §4.5 title/claims; micro projection; clamps | §4.5 rewritten; §10 behavioural change named; divergence cell |
| O15 posting → 1.5.5 row grouping | §4.5 |
| O16 kernel parses JSON | §1.3/§3.3 JSON as the one closed grammar; scanner M1; §10 row |
| O17 fleet outage suspends revocation | §2.3 stated; `stale_policy` flag; `outage_grace` dual-controlled |
| O18 upgrade state | §2.3/§3.1 cleared; battery |
| O19 fan-out cardinality | §2.3 aggregate mode; §6 reconciled |
| O20 `PlaneSessionState` undefined | §3.1 |
| O21 cursor bounds | §3.1 |
| O22 supersede race; queue flush | §2.3 CAS; queue dropped, `unemitted` |
| O23 keyed rps floor | §10 ≥ 30k at M2 |
| O24 hook destination steering | §1.4/§3.6 `may_change_destination`; audit head |
| O25 `seq` cross-references | §4.1 refs `(node, node_seq, hash)` in the preimage |
| O26 cross-form overlap | §3.3 total, conservative |
| O27/F18 plan realism | §9.1 stop-loss actions; WebRTC impl named; webrtc → voice window if red |
| O28 alloc scope, binary size | §10 |
| O29 streamed value before settlement | §2.3 unposted-accrual budget; §10 row; probe cell |
| O30/F1 source denylist | §1.2 restored, transitive; §3.7 row; socket meta-test |
| O31 admin hold | §3.6/§4.5 `KernelVerb` section default 0 |
| O32 per-leg durability | §4.1/§4.3 `Dispatched` delta; battery |
| O33 doc-scan allow-list | §1.3 |
| O34 LOC ceiling | §1.1 union + per file |
| O35 non-existent artifacts | §9.1 |
| F2 provider accrual into a linear `Hold` | §2.3/§3.5 `HoldAccrual`; canary restated |
| F3 provider request inside an open response | §2.1/§3.2 `OneShot`; `for_` on Frame/Close; `OpenSlotBusy` |
| F4 `Unpriced` vs rate-card-less configs | §2.2/§4.5 card absent = zero prices; oracle cell |
| F5 kernel verbs vs 81 operations | §4.7 derived from `openapi.json`; registry generations |
| F6 hash preimage | §4.1 `body_hash` + chain `hash` |
| F7 no `encode_end`; queue on supersede | §3.2 `encode_end` (17 call sites); §2.3 |
| F8 upgrade trigger | §2.3/§3.6 `Upgrade { to }` leg |
| F9 transport handshake data | §2.3/§2.4 `TransportFacts`; `COMPOSES_OVER` list |
| F10 `TransportUnits` forgeable | §4.5 valid only with `DECODES_PAYLOAD`; webrtc via frames × ptime |
| F12 plane names the scheme | §2.2/§3.1 claim's scheme; narrowing only; `ScopeFacts` resources only |
| F14 principal refusals lossy | §2.2 committed before refusal bytes |
| F16 memory-store WAL story | §4.3 |
| F19 `peer` claimed by `msg` | §2.3 peer envelope; `msg` claims stdio only |
| F22/F23 nits | §5 `tcp` row; `Labels` defined; opaque replay token; both batches re-appended |
| Dropped (both lists) | C16 banner fixed · C13 erasure via pseudonymous ids · R30 minimal end · R33 anchor alarm · C7 denylist · C8 migration chain-head + opening balance · C18 LOC floors · R3 effective-dating + immutability test · R8 per-cell 1.5.5 rule · R15 matrix + EIO/ENOSPC cells · R16 cap + thresholds · R18 skew cell · R28 both quantities · R37 exactness cell · R38 cell · `encode_refusal` statelessness explained · per-file budgets inline |

---

## Round 8 (on ARCHITECTURE.md v1.4) — findings and where v1.5 closes them

Opus: 12 blockers / 19 gaps / 5 nits / 8 dropped. Fable: 4 blockers / 16 gaps / 10 nits / 8 dropped.
Log note: R12, R13 and R22 were never assigned in Part 17 (numbering gaps, not dropped closures).
Log correction: Round 7 F5 was closed against the dev tree's 81 operations; 1.5.5 has 66 (49 paths).

| Finding | Closed in v1.5 |
|---|---|
| O1/F3 RSS arithmetic impossible on the pinned profile | §10 pooled TLS buffers; connection count and per-connection bytes measured at M2; formula must close; RSS rows derived from measured terms |
| O2 fee inside Σ nanos | §4.5 clause 2/3: fee outside the usage sum, `fee_count`, added after truncation in both projections; cell |
| O3/F1 66 vs 81 operations | §4.7/§8.1/§10: 66 at the tag pinned by blob hash; 15 dev additions are new surface |
| O4/F8 `Hold` under task death; `HoldAccrual` lifetime | §2.1/§2.2/§3.5 `HoldCell` single-take CAS in the in-flight table; sweep takes the same cell; `HoldAccrual` runtime-sealed |
| O5 audit facts in a sealed record | §2.2 provisional end at Meter entry; audit before Settle; post-Meter amendment class |
| O6 `UnitJsonPointer` credential | §3.3 `ArrivalLocation` for auth schemes; `UnitJsonPointer` idempotency only |
| O7/F10 `encode_refusal` cannot correlate | §3.2 draft + read-only state; `Refusal { stream, correlates }`; cell |
| O8 pre-auth STARTTLS unreachable | §2.1/§2.3 `Origin::Handshake`, `HANDSHAKE_TRIGGER`, Anonymous principal |
| O9/F11 no session-upstream destination; provider Verify hard-coded | §3.6 `SessionUpstream`, `Client { Deliver | AwaitReply }`; permitted kinds by origin |
| O10 unauthenticated datagram sessions | §2.1/§3.4 `SESSION_BOUND`; `udp` re-authenticates; `dtls` row; cell |
| O11 `DurabilityUnavailable` refusal needs the WAL | §2.2 the single stated exception |
| O12 identity omits open holds | §4.2 Σ open holds; sixth checkpoint total |
| O13/F4 memory store unbounded; headline row inoperable | §4.3 replay from last checkpoint, purge after anchor on every store; store precondition row |
| O14/F26 locator evaluation retains frames | §2.2/§4.5 incremental evaluation; cursor budget row |
| O15 plane state per connection | §3.1/§3.2 `open_upstream` per dialed connection |
| O16/F9 operator key on the node | §4.7 off-node private half, `busbar policy sign`, rotation, escrow, break-glass |
| O17 residual-risk exception too narrow | Appendix A enumerated; `/usage` line for listed-key deltas under `single` |
| O18 correlation label is content | §4.1 hash only in the chain; label in `content_facts` |
| O19/F24 tenant keyset erasure | §4.2 per-principal sub-keys, reversible at read, rotation/escrow/loss |
| O20 two hold-sizing rules | §2.2 one rule; `max_response` listed |
| O21 evidence reads priced | §3.6/§4.7 `read_*` pinned at 0, always Allow; cell |
| O22/F18 interrupt and child cancellation mechanism | §2.2/§2.3 cancellation token at awaits; `interrupt_deadline`; bounds |
| O23 peer payload unbounded | §2.3/§3.1 `MAX_PEER_PAYLOAD_BYTES`; per-peer slab |
| O24 mutation floor on money units; register cap | §1.1/§8.3 cost/usage/ledger at 100 %; ≤ 3 per file, ≤ 90 days |
| O25 diff-accept exclusions omit flags | §8.1 |
| O26/F5 artifacts, stop-loss actions, M2 depends on M3 | §9.1 rewritten: M2 skeleton with in-tree postgres driver; real stop-loss actions; four external repos |
| O27 provenance | §8.3/§10 alloc gate is 1.6.0-dev work; 120k/15 MB unsourced until M1 |
| O28/F25 doc-scan allow-list | §1.3 extended with reasons; scan over the file is a meta-test |
| O29/F30 replay TTL | §4.4 `max(600 s, window + max_unit_duration)` |
| O30 litmus granularity | §6 governance granularity paragraph; `verify_frame` |
| O31 LOC ceilings | §1.1 per-file breakdown; call-graph rule |
| O32–O36 nits | §4.3 p50 budget; §4.5 numbered clauses; §2.2 `Aborted(Client)` ordering; §3.5 `LedgerToken`; §2.2 `SchemeNotDeclared` |
| F2 durable plane state | §2.3/§3.6 `PlaneRecord`; store `record_*`; `plane_record_write` verb |
| F6 JSON scan number | §10 ≤ 1 µs per KiB |
| F7 legacy dual-write has no writer | §1.4/§4.6 `legacy_cells_write`; conformance cell |
| F12 cursor node-wide | §3.1/§10 |
| F13 per-session RSS cannot close | §10 measured at M3; queue budgeted separately |
| F14 admission-path divergences | §4.4 `Exhausted` continues with `Overdraft`; §4.5/§8.1/§10 max-price hold named |
| F15 deflating transport | §4.5/§8.2 |
| F16 stale corpus | §8.1/§9.1 regenerated at M1; gate check |
| F17 `required` lockout | §4.7 `InsufficientApprovers` |
| F19 dispute aging | §4.2/§4.7 `dispute_max_age`; reconciliation carries counts |
| F20 default anchor | §4.2 posture reported; Appendix A |
| F21–F30 nits | sweep re-materialisation via the cell; per-wait fdatasync; boundary rule stated; tenant defined; `veto` closed code; `skew_max` in the wait |
| Dropped (both lists) | R7 `SessionUpstream` · R8 per-cell 1.5.5 estimator · C15/R9 evidence reads · R6 `Seq` monotonic in `verify` · R40 dynamic-plugin statement · R25 abort-class caveat · C10 class list enumerated · D6(i) corpus · C19 boundary rule · R33 rotation/escrow/loss · R15 grace slice semantics · R16 under `single` named · Part 7.4 nightly report |

## Round 9 closure map (v1.5 → v1.6)

Reviewers: fresh Opus (6 blockers / 10 gaps / 4 nits; dropped R29, C1) and fresh Fable (5 blockers /
21 gaps / 6 nits; dropped R29, R15, one stale sentence). Both "GREEN LIGHT: no". Every item closed in
`ARCHITECTURE.md` v1.6 as follows.

| # | Finding | Closure in v1.6 |
|---|---|---|
| O-B1 | tier multiplier / ExtraRates / `billing-unified.md` absent from the numeric contract | §4.5 clause 5 (bucket-level `tier_bp`, single divide over the sum, stored pre/post), extras table in clause 1; preamble names `billing-unified.md` as the pricing authority and the precedence rule; recompute applies the same rule |
| O-B2 | `Unpriced` refusal regresses 1.5.5 | `allow_unpriced` default **true**: priced 0, flagged; `false` refuses (§2.2 step 4, §4.5, §4.7 table, §8.1 cell) |
| O-B3 | no ingress challenge-response | auth `verify → CredentialFacts | Challenge { bytes, state, rounds_left }` inside Handshake units; delivered as a `Client { Deliver }` leg; ≤ N rounds + byte budget (§1.4, §2.2 step 1, §2.3, §5 battery, SMTP AUTH / SCRAM cells) |
| O-B4 | crash-recovery `Hold` has no constructor | `RecoveryToken` + `Recovery::materialize` / `Hold::from_journal`; `HoldCell` two-state `Arrival → Admitted` CAS (§2.1, §2.2 table, §3.1, §3.5) |
| O-B5 | media seconds billed on client-negotiated frame timing | §4.5: a peer-supplied handshake value is never sole evidence; `Count × TransportFacts` must carry a kernel-derived second line; `TransportUnits` from timestamp deltas where `DECODES_PAYLOAD`; lying-timing meta-test (§8.2) |
| O-B6 | correlation not principal-scoped | correlation map keyed `(session, principal, fact_key, value)`; cross-principal `correlates` → own hold `Uncorrelated` (§2.3; battery cell) |
| O-G1 | overdraft never reduces the next window | §4.4: `reserve` deducts carried overdraft; checkpoint `overdraft_carried_in/out`; identity term; battery cell |
| O-G2 | late accrual undefined | `late_accrual` row in the settlement table; own hold referencing the parent (§2.2, §2.3, §8.1 class) |
| O-G3 | denylist scope vs store/secret/export | §1.2: denylist scoped to pure kinds; I/O kinds bounded by signature, deadline, `Access`, review; §3.7 row |
| O-G4 | loader window `[4,5]` + read-only as M1 artifacts; external-store stop-loss | §7 store, §9.1 created-here list and M1 stop-loss |
| O-G5 | replay TTL for legacy ops | §4.4: 600 s for the 66 legacy operations; `max(600 s, window + max_unit_duration)` for new verbs; admin cell at t = 700 s |
| O-G6 | defaults table | §4.7 defaults table (23 keys) sealed in every `Policy` |
| O-G7 | boot assertion tick × rate | §4.7 config paragraph; §10 row; battery cell |
| O-G8 | `adjust` / `resolve_dispute` above threshold | irreducible set + `adjust_threshold` default 1 % (§4.7) |
| O-G9 | oversize peer payload | by `PlaneRecord` locator (§2.3 fan-out, §6 msg, probe cell) |
| O-G10 | M2/M3 stop-loss actions | §9.1 table, all four rows |
| O-N1..4 | Ctx one resource handle; doc-scan input vocabulary; register once-ever; `unposted` + oldest hold age on reports | §1.2 / §3.1; §1.3; §8.3 mutation gate; §4.2 checkpoint fields + §4.7 report list |
| O-drop | R29 thread model + `blocking-ffi-lint`; C1 independent recompute | §1.2 deadlines paragraph + gate list; §4.2 independent recompute on the node Tick + §8.2 |
| F-B1 | 1.5.5 bucket chain / `requests` / `concurrent` caps absent | §4.6 bucket chains and cap dimensions: all-or-nothing draw across the chain, one slice per `(bucket, dimension)`, `concurrent` leases (`Lease` records) released at Meter; identity per `(bucket, dimension)`; `over_budget { bucket, dimension }`; oracle cells per cap kind × chain depth; probe cell; §10 compat sentence |
| F-B2 | operator-key establishment on upgrade undefined | §4.7 ceremony: `busbar operator keygen`, `operator: unset` sealed at `Bootstrap`, `set_operator_key` admitted under `unset` with the admin credential; oracle and battery cells |
| F-B3 | denylist / pure `Auth::verify` vs LDAP/OIDC | as O-G3; auth `IO: bool`, per-call deadline, `refresh` on the node Tick (§1.4, §7) |
| F-B4 | `Transport` methods must be async | §3.4: boxed `Fut<'a, T>` on `listen/accept/dial/write/upgrade/unit0_refusal`; the one boxed future is a listed alloc-gate exclusion (§10) |
| F-B5 | default-store purge destroys the financial record | §4.2 retention: purge only when older than an anchored checkpoint, below `backup_watermark`, unreferenced by disputes/adjustments, and exported-with-ack or dual-controlled `discard`; keep-on-disk default; `purge_before` / `backup_watermark` store methods; battery cells |
| F-G1 | stalled plane/plugin calls | `PluginTimeout` (deadline on I/O kinds) and `Stalled` (Tick sweep + bounded abort) (§1.2, §2.2 exit, §8.1 classes, meta-test) |
| F-G2 | datagram decode failure hard-closes | `Ingress::Discard` / `Progress::Discard`; `udp` row; forged-source cell |
| F-G3 | `backup_watermark` | checkpoint field, store method, restore-below rule → `ChainBreak` (§4.2, §4.3) |
| F-G4 | `+ Σ adjustments` in the identity | §4.2 identity incl. adjustments and carried overdraft; scope rule for headroom |
| F-G5 | session-Tick checkpoint volume | only when the counter changed (§2.3, §4.7 table, §10 sizing row) |
| F-G6 | pin the constants | §4.7 defaults table; §3.1 bounded types with M2 pins named |
| F-G7 | store precondition row vs shipping row | §10: separate "store precondition" and "shipping lag" rows |
| F-G8 | `session_put/remove` | §2.1, §1.4 store methods, lease-expiry cleanup, battery cell |
| F-G9 | orphaned accrual | `late_accrual` (as O-G2) |
| F-G10 | `busbar-unit-verbs` crate | §1.1 ceilings, §3.1 graph, §4.7, §6 admin row |
| F-G11 | mandatory `secret-local` | §1.2, §3.1, §7 |
| F-G12 | HMAC not reversible | SIV-AEAD pseudonyms with sub-keys; `seal/unseal` on the secret kind (§1.4, §4.2) |
| F-G13 | hash the client key | `H(client_key)` in the entry; `claim_key` on the hash; no client bytes in the journal (§4.1, §4.4) |
| F-G14 | credential slab not arena | per-connection credential slab under the cursor cap (§2.2 step 0, §3.1) |
| F-G15 | media transport `DECODES_PAYLOAD` | `webrtc` row `DECODES_PAYLOAD = true` via timestamp deltas; `twilio-media` too (§5) |
| F-G16 | signalling → media pairing | `HANDOFF` transport form bound by a `TransportFacts` fingerprint (§1.4, §2.3, §3.4, §5, battery, probe cell) |
| F-G17 | name the "three ways"; `settle_observe` | three-way lane cross-check named at Meter (§2.2 step 6); no separate `settle_observe` — accrual per attempt is the observation |
| F-G18 | complete the fleet rule | `drain_quorum` rule fully stated (§2.3); default ⌈N/2⌉ |
| F-G19 | doc-scan deny list | §1.3: union of §6 plane keys, dialect names, pinned word list |
| F-G20 | external stores dated | M1 ≥ 2 of 4 at floor 5; M3 postgres + sqlite; M4 mysql + valkey or read-only with owners (§9.1) |
| F-G21 | lean-core scan mechanical | string-literal comparison against registered keys (§1.3, §3.7, §8.3) |
| F-N1..6 | define K-route/G/J/I; two admin exceptions; torn-tail rule; emission overrun rule; HandshakeFrames timing; fee in hold estimate | §9.2 streams; §10 admin superset; §4.1; §2.3 pacing; §2.2 step 0; §2.2 step 4 |
| F-drop | R29 thread model; "raw SIP out of scope" text; R15 weakening | §1.2 + gate; §6 voice row + Appendix A; refusal-path third wait restored in §2.2 step 4 and §4.3 |

Self-consistency sweep on v1.6: §1–§4/§10 plane-word scan clean after two edits (a media-protocol
name in §4.5 generalized; the per-kind trust rule inlined in §3.6 instead of "as v1.5"). Call-site count
18 unchanged. Numeric contract now five clauses.

## Round 10 closure map (v1.6 → v1.7)

Reviewers: fresh Fable (3 blockers / 10 gaps / 10 nits) and fresh Opus (8 blockers / 11 gaps / 7 nits).
Both "GREEN LIGHT: no". Every 1.5.5-parity claim was verified at the tag before closure
(`config/groups.rs`: `LimitMetric::Tokens` total, `pool:` scope, `on_exhaust: downgrade`, `enabled:
false`; `governance/mod.rs`: billable = admitted − refunded, `user:<sub>` auto-provisioning;
`hooks/mod.rs`: ranking via `pick_among`; `config_validate/mod.rs`: rate card present ⇒ complete or boot
fails; `admin/mod.rs`: idempotency on key mint + rotate only; `cost.rs`: token cap is post-hoc).
**Round 9's Opus finding O-B2 ("1.5.5 serves unpriced at 0") was wrong**: 1.5.5 refuses boot on an
incomplete card; v1.7 restores that rule and keeps `allow_unpriced` only for meter classes outside the
card's declared set.

| # | Finding | Closure in v1.7 |
|---|---|---|
| F-B1 / O-B3 / O-N2 | `tokens` (total) cap missing; pool scope, downgrade, frozen groups absent | `CapDimension` adds `Tokens`; buckets keyed `(bucket, dimension, scope)` with `BucketScope`; `GroupFrozen`; downgrade = Admit-time narrowing of the verified set, `downgraded` on the posting; window kinds incl. `total`; oracle cells per form (§2.2 step 4, §3.1, §4.6, §8.1) |
| F-B2 | ranking hooks disabled by `may_change_destination = false` | sealed `true` (and `max_priced_delta = unbounded`) at `Migration` for hooks in the 1.5.5 config; oracle cell; §10 named change; Appendix A residual risk (§3.6, §4.7 table) |
| F-B3 / O-B4 / O-G3 / O-G4 / O-G5 | hold sizing: `max()` under-sizes; no per-dimension draw amounts; no bytes→class divisor; no fan-out cardinality; client-controlled `max_response` | Σ per-class estimates × max price + fee; divisor from the card; recipient count from Approve; clamp to the lane's max; token dimensions settle post-hoc (1.5.5 parity, the one named exception to all-or-nothing) (§2.2 step 4, §4.5, §4.7) |
| O-B1 | `allow_unpriced` default true regresses 1.5.5's boot completeness | 1.5.5 boot rule restored (card present ⇒ complete over its declared class set, no unknown lanes); `allow_unpriced` covers only classes outside the set; oracle cell now asserts boot refusal (§2.2 step 4, §4.5, §8.1) |
| O-B2 / F-G2 | tier clause mis-attributed to 1.5.5; source undefined | clause 5 labelled new in 1.6.0; `tier_bp` from the bucket's config (default 10,000); upstream-reported tiers price through extras; tiered cell has no 1.5.5 reference — verifier hand computation only (§4.5, §4.7, §8.1) |
| O-B5 | `late_accrual` posts without a slice | synchronous slice draw at settle (overdraft if empty) (§2.2 table) |
| O-B6 | LOC call-graph rule unsatisfiable | rule restated: reachable without crossing a sealed unit-trait boundary (§1.1) |
| O-B7 | `drain_quorum` read from the unreachable store | peer-state table over `peer` on each node Tick, aged at `outage_grace` (§2.3) |
| O-B8 / F-G6 | `concurrent` lease leaks on non-Completed ends / dead incarnations | released on the exit-path CAS for every end; store counts current-epoch leases only; recovery releases with the settle (§2.2, §4.6) |
| O-G1 | uncapped (attribution) buckets undefined | attribution bucket form: unbounded slice, identity Σ settlements == Σ accrued; zero-config oracle cell (§2.2 step 4, §4.6, §8.1) |
| O-G2 / F-G3 | `fee_count` on non-Completed ends | `fee_count = 1` iff Completed or value delivered after the first relayed response frame; oracle cell per non-`ok` class (§2.2 table, §8.1) |
| O-G6 / F-G8 | overdraft ceiling not a bound; scoping | hard bound: `Aborted(Kernel, OverdraftCeiling)` mid-unit; per `(bucket, scope)` on the leaf; nano-units only (§4.4, §4.7) |
| O-G7 / F-G8 | unpinned N/T/X, `max_accrual_rate`, tolerance, challenge rounds, drain bound | `checkpoint_entries`/`checkpoint_interval`, `anchor_failures_alarm`, `challenge_max_rounds`/`_bytes`, `variance_tolerance`, `lane_mismatch_alarm`, `max_quantity_rate` (defines `max_accrual_rate`), drain ≤ `max_unit_duration` (§4.7 table, §2.2, §2.3, §4.2, §4.5) |
| O-G8 | verb count | 15 verbs enumerated incl. `set_escrow`; the "15 dev-tree operations" disambiguated (§4.7) |
| O-G9 / F-N7 | replay TTL scope | exactly the two 1.5.5 replayable operations + the new credential-minting verbs (§4.4) |
| O-G10 | read-only stores contradict "nothing deferred" | all four external stores signed at floor 5 is an M4 hard gate; stop-loss is D+14 only, scope never cut (§9.1) |
| O-G11 | "lane" undefined | `LaneId` defined in the type index (§3.1) |
| F-G1 | "window boundary" undefined | card version captured at hold from the current `Policy` epoch; applies to later holds only (§4.5 cl. 4) |
| F-G4 | SSO auto-provisioned leaf groups | `user:*` template instances minted by the token verb, exempt from dual control, bounded by `max_auto_provisioned_groups` (§4.6, §4.7) |
| F-G5 | escrow vs `operator: unset` | escrow a required argument of `set_operator_key`; `set_escrow` in the irreducible set (§4.7) |
| F-G9 | sessions with zero upstreams | "zero or more"; Unit 0's Route may yield any kind permitted for its origin (§2.1, §2.3) |
| F-G10 | RSS gate closed by construction | benchmark concurrency recorded at M1; the formula is a prediction confirmed at M2 (§10) |
| F-N1 | `blob` in §4.7; pinned word list absent | "git object hash"; word list inline (§1.3, §4.7) |
| F-N2..N10, O-N1, O-N3..N7 | `Conn` cloneable; Client → all except Peer; in-tree postgres in §7; aggregate = the only mode; turn-hold "earliest of"; residual risks (operator-key window, migrated hooks); `AuditFacts` mismatch → `MeterDisputed`; writable `data_dir` named change; `currency` in §4.1; `KernelVerb` scope wording; `profile-lock` wording; §3.1 crate-list ref; `encode_refusal` `&` deliberate | all applied |

Sweep on v1.7: §1–§4/§10 plane-word scan clean; no unpinned N/T/X placeholders remain.

## Round 11 closure map (v1.7 → v1.8)

Reviewers: fresh Fable (4 blockers / 7 gaps / 8 nits) and fresh Opus (7 blockers / 10 gaps / 7 nits).
Both "GREEN LIGHT: no". Parity claims verified at the tag by the reviewers (rotate idempotency scoped
`rotate:{id}:{header}`; fee refunded on non-2xx status only; `max_auto_provisioned_groups` 0 =
unlimited; 1.5.5 idempotency cache per-process).

| # | Finding | Closure in v1.8 |
|---|---|---|
| F-B1 | overdraft ceiling on the uncapped leaf = unbounded | ceiling belongs to the refusing capped `(bucket, dimension, scope)`, every capped bucket in the chain; attribution buckets have none (§4.4, §4.7) |
| F-B2 / O-B3 | token-cap overrun bound false; fleet read path unspecified | token dimensions pre-drawn from the per-class estimates with delta settle — same slice machinery and fencing; named behavioural change in §10 (§2.2 step 4, §4.6) |
| F-B3 / O-B7 | doc scan red on `model`/`mail`; no dialect column | seven phrases reworded; §6 gains a Dialects column as the deny-list source; `LaneId` gloss no longer names a dialect term (§1, §1.2, §2.3, §3.1, §4.5, §4.7, §6, §10) |
| F-B4 / O-B1 | idempotency key drops op and resource | key = `(principal, op_class, target locator, H(client_key))`; create+rotate shared-header cell (§4.4, §8.1) |
| F-G1 / O-B2 | fee cell contradicted §2.2 | §8.1 cells restated: non-2xx → 0; 2xx stream dying mid-way → 1 |
| F-G2 | provider units cannot authenticate on unbound transports | Provider Authenticate = kernel pairing (`issuer: Pairing`); `SessionUnbound` not applicable; unpaired upstream frame → `Discard` (§2.3) |
| F-G3 | multi-scope verified set | every intersecting scoped bucket draws; unselected scopes released at Route (§2.2, §4.6) |
| F-G4 | `secret-local` keyset continuity | public halves sealed in `Policy`/`Checkpoint`; `export_keyset`/`import_keyset`; `KeysetMissing` boot refusal (§1.2, §4.7) |
| F-G5 / O-B5 | `plugins/reload` under `unset`; digest set at `Bootstrap` | reload/rollback are ordinary verbs; digest set = self at `Bootstrap` with a key, `any` under `unset` (journaled, alarmed, residual risk, boot cell) (§4.7, Appendix A) |
| F-G6 | three headline bars | "which number governs" paragraph: 120k/15 MB absolute at Phase 0.5 exit; M4 interim = 1.5.5 baseline (§10) |
| F-G7 | fan-out `Delivery` payer | sender's chain pays, sized per recipient (§2.3) |
| O-B4 | unposted-accrual gate vacuous | `in_flight_cap × tick_interval × max_accrual_rate ≤ max_unposted_accrual`; `in_flight_cap` 10,000; measured at M2 (§4.7, §10) |
| O-B6 | no plane-visible cardinality source | `PlaneCount { content_fact_key }` with a mandatory kernel-derived companion line (§4.5) |
| O-G1 | Tick units on a money path | elapsed-time usage accrues into the session's open unit's hold; Tick units never post (§2.3, §3.6) |
| O-G2 | `drain_quorum` dead code | `stale { since }` peer state broadcast before acting; quorum on `stale + draining`; peer auth via last known lease keys through `outage_grace` (§2.3) |
| O-G3 | lying store/secret/anchor meta-tests | added (§8.2) with the detecting mechanism and latency |
| O-G4 | §10 missing-lane clause | corrected to "refuses boot exactly as 1.5.5 does" |
| O-G5 / F-N2 | lease battery wording | exit path for every end (§8.3) |
| O-G6 | `currency` default | `unit` (§4.7) |
| O-G7 | ABI-2 store present | `StoreAbiTooOld { found, floor }` boot refusal, plugin-before-binary ordering, boot cell (§10) |
| O-G8 | cross-node idempotency divergence | third named admin exception (a strengthening) + two-node t = 500 s cell (§8.1, §10) |
| O-G9 | stop-losses deferred scope / moved numbers | M1 and M2 stop-losses now move the date only; §10 numbers never move (§9.1) |
| O-G10 | plane invariant vs lane | §1.1 restated: a plane names a lane only from the config-declared set; the cross-check detects inconsistency; lying planes are for the meta-tests |
| nits (both) | `OverBudget` CamelCase; branch float defined; type index extended; `CredentialBudget` vs `CursorBudget` distinct; replay TTL window named; verb count 17; JSON row tagged; `tokens_in/out` marked 1.6.0; 250 µs "target, measured at M2"; 512 B with continuations; replay cell normalization; `max_auto_provisioned_groups` literal | all applied |

Sweep on v1.8: §1–§4/§10 scan clean against the full pinned word list.

## Round 12 closure map (v1.8 → v1.9)

Reviewers: fresh Fable (3 blockers / 7 gaps / 6 nits) and fresh Opus (11 blockers / 8 gaps / 7 nits).
Both "GREEN LIGHT: no". All parity claims verified at the tag (`HookKind {Tap, Gate}` × `HookStage
{Request, Candidate, Routing, Response}`, `TransformOutcome::Rewrite`; `ModelCfg.max_concurrent`;
`limits.max_inbound_concurrent` default 8,192; `RateEntryCfg` four token rates; `model_unpriced`
fail-closed 400; `LimitMetric::Budget` in cents; fee inside `derived`; downgrade cascade with visited
set and per-hop ACL; five dynamic ABI axes; `/usage` per-row floors with `requests` fee base;
self-serve `user:<sub>` on `/auth/token`). **Round 10's `allow_unpriced = true` closure was wrong for
the same reason round 9's was**: 1.5.5 is fail-closed; v1.9 defaults `false` and seals an explicit
`unpriced_classes` list at `Migration` for the classes 1.5.5 never priced.

| # | Finding | Closure in v1.9 |
|---|---|---|
| F-B1 | unposted-accrual assertion refuses 1.5.5's sample config | `max_unposted_accrual` derived and published; assertion only when operator-pinned; `unposted_alarm` (§4.7, §10) |
| F-B2 / O-B9(2) | fee on relayed upstream errors | `fee_count = 1` iff a relayed frame with `finish ∉ {Error}`; `Completed`+`Error` = 0 (§2.2 table) |
| F-B3 / O-B4 | "1.5.5's estimator" does not exist | removed everywhere; `max_response` = lane `context_max` else pinned 4,096 units/class; §10 names the full admission divergence; §8.1 exception widened |
| F-G1 / O-B9(1) | `/usage` byte-identity | `/usage` additive lines named; legacy spend projection reproduces 1.5.5's per-row floors and admitted-request fee base byte-for-byte; exact figure on the 1.6.0 reads; five named exceptions (§10) |
| F-G2 / O-B11 / O-N1 | doc scan red (list literal, "tool calls", "responses") | list sentence excluded; "calls"; "leg replies" (§1.3, §3.1, §4.5) |
| F-G3 | undefined declared max duration; stall clock | `UnitDraft.max_duration ≤ max_unit_duration` hard bound → `TimedOut(Route)`; frame relay resets the stall clock; flow re-open rule (§1.2, §2.3, §6) |
| F-G4 | migration read path | `legacy_cells_read`, `legacy_audit_head` store methods (§1.4, §4.2) |
| F-G5 | `backup_watermark` with no backup; memory-store growth | `:= anchored head`; `wal_capacity` 4 GiB with an 80 % alarm naming the two ways out; §10 operational requirement (§4.2, §4.7, §10) |
| F-G6 / O-N2 | `data_dir` default | `<config dir>/busbar-data`, `DataDirNotWritable` (§4.7) |
| F-G7 | `OpenSlotBusy` fatal; interrupt ordering | rendered refusal, session open; `INTERRUPT_FACT` before the slot check (§2.2) |
| F-N1..6 | nested key from claim config; tautology; replay TTL cap; zero-priced hold draws nothing; duplicate cell; `stale_policy` naming | all applied |
| O-B1 | `allow_unpriced` default | `false`; `UnknownLane` refusal byte-identical to 1.5.5's 400; `unpriced_classes` sealed at `Migration`, residual risk (§4.7, §8.1, Appendix A) |
| O-B2 | budget unit / per-draw truncation | caps lifted to nano-units at policy load; cents only as projection; one-cent-earlier divergence named (§4.5 cl. 1) |
| O-B3 | fee drawn but never settled | fee is a usage line (`fee` class, `per_request_fee` × 10^7); clause 3 simplified; identity balances (§2.2 step 4, §4.5 cl. 2–3, §1.4) |
| O-B5 | downgrade to unverified destinations | Verify computes the full cascade candidate set with per-hop ACL and visited bound; Admit narrows to a subset (§2.2 step 4) |
| O-B6 | one cached class vs two prices | `cache_read`, `cache_write` (§6) |
| O-B7 | 1.5.5 hook model has no seat | four seats mapping the four stages; `Tap`/`Gate`; `restrict`, `rewrite` (`IrPatch`, journaled, bounded), `tap`; compiled-in ranking strategies are in-tree hooks (§1.4, §7) |
| O-B8 | per-lane `max_concurrent` and node inbound cap | egress pool ceiling per destination with `DestinationSaturated`; `in_flight_cap` read from `limits.max_inbound_concurrent` (§4.7) |
| O-B9(3) | "divide rule" citation | deleted (§4.5 cl. 5) |
| O-B10 | `CapDimension` closed | `{ NanoUnits, Requests, Concurrent, Class(MeterClassId) }` — closed shape over an open key (§1.3, §3.1) |
| O-G1 | keyset export during the `unset` window | `export_keyset` admitted under `unset` (§4.7) |
| O-G2 | four dynamic ABIs unaddressed | per-kind floors and `PluginAbiTooOld { kind, found, floor }` (§10) |
| O-G3 | replay cache unbounded on `total` | finite windows only, capped at `dispute_max_age` (§4.4) |
| O-G4 | idle session time | unpriced by design unless a `session_seconds` class is declared (§2.3) |
| O-G5 | overdraft on `total` | no overdraft on `total`: `Aborted(Kernel, OverBudget)` at exhaustion (§4.4) |
| O-G6 | `verify_frame` phantom seat | dropped; destination change = new flow = new unit (§6) |
| O-G7 | probe cells vs freeze | probe uses M3 transports + template-derived thin plane slices; full planes in Phase 0 (§9.1) |
| O-G8 | dual-control hole under `required`; template attribution | Appendix A; self-serve exchange verb named (§4.7) |
| O-N3..7 | `BucketScope::Pool(name)`; reload rule; `drain_quorum` N; "operation"; `playout` removed | all applied |

Sweep on v1.9: §1–§4/§10 scan clean; no stale references to removed terms.

## Round 13 closure map (v1.9 → v1.10)

Reviewers: fresh Opus (6 blockers / 7 gaps / 3 nits) and fresh Fable (4 blockers / 9 gaps / 7 nits).
Both "GREEN LIGHT: no". **One finding rejected with evidence**: Opus B2 claimed the legacy `/usage`
projection over-reports because `derive_spend_cents` truncates once; round 12 verified at the tag that
`admin/v1/service.rs` calls the derive **per row** (`derive_spend_micros_row`, "Spend derives PER ROW
… aggregates ADDITIVELY") with `b.requests` as the fee base — Fable R13 independently confirmed both
(`service.rs:164`). The paragraph stands with its arithmetic stated precisely.

| # | Finding | Closure in v1.10 |
|---|---|---|
| O-B1 / F-B1 | `allow_unpriced` pinned both ways | the two residual "default true" statements corrected to `false` + `unpriced_classes` (§2.2, §4.5) |
| O-B3 | unknown-lane refusal ignores 1.5.5's keyed-only guard | keyed principal → refused byte-identical; anonymous unit served at 0 (`gov.key.is_some()`); oracle cell (§4.7) |
| O-B4 / F-G2 | `drain_quorum` at N = 0 | test `≥ max(1, quorum)`; N ∈ {0, 1} → drain immediately (§4.7) |
| O-B5 | crash-exposure bound rests on unenforced `max_quantity_rate` | re-derived from enforced quantities: `in_flight_cap × (max_hold + overdraft ceiling)`; `max_hold` defined; `max_quantity_rate` removed (§4.7, §10) |
| O-B6 | `session_seconds` has no price | `SessionAccrual { lane: Unit-0 lane }` Tick destination; hold `tick_interval × price` (§2.3, §3.6) |
| O-G1 / F-N6 | `total`-window abort excess outside the identity | journaled `Overdraft` posting, `carried_out = 0`; §8.3 cell (§4.4) |
| O-G2 | two takers of the `HoldCell` | Meter computes `Usage`; the exit path settles; one `take()` site by fixture (§2.2) |
| O-G3 | `adjust_threshold` undefined on uncapped buckets | floor 10^9 nano-units (§4.7) |
| O-G4 / F-G6 | 120k gate vs `wal_capacity` | headline row defined with a null-sink export; time-to-fill formula as a §10 row and boot warning (§10) |
| O-G5 | latency gate has no kernel headroom | pinned kernel term 0.1 ms p50 / 0.3 ms p99, measured at M2 (§10) |
| O-G6 / F-N5 | template-instance `parent` ungoverned; register wording | `parent` must lie in the exchanging principal's chain (named strengthening in §10); Appendix A says "any token-exchange principal" (§4.7, §10, Appendix A) |
| O-G7 / F-N1 | doc scan on backticked 1.5.5 identifiers | word-boundary matching; backticked 1.5.5 identifiers skipped (§1.3) |
| O-N1 | `Aborted` has no reason slot | `Aborted(Kernel { reason })` (§2.2, §4.4) |
| O-N2 | `per_request_fee` is deploy-level | own §4.7 row, independent of the card (§1.4, §4.7) |
| O-N3 | scan exclusion scope | marked block (§1.3) |
| F-B2 | 64 KiB cursor = 1.5.5's body floor | head + body-chunk frames; `Open` for the head; estimate from declared length; pointers over the scanned prefix; 32 MiB served unchanged; §10 row + ≥ 1 MiB oracle cell (§2.1) |
| F-B3 | `late_accrual` on a `total` bucket | always posts; flagged `Overdraft`, no carry; exposure ≤ `max_provider_push` (§2.2 table) |
| F-B4 | `context_max` as hold size | `max_response` applies to response-family classes only; input/cache-read use exact ingress estimates; `max_output` else 4,096; never `context_max` (§2.2, §4.7) |
| F-G1 | fleet keyset continuity | one deployment keyset: fingerprint sealed at `Bootstrap`; `auth-lease` refuses a differing node; `import_keyset` before a second node serves (§1.2, §10) |
| F-G3 / F-N4 | rewrite hooks vs the arena | rewrite over the scanned head in the connection slab; beyond-head rewrite `HookFailed`, owner-signed exception; price-neutral by default (§1.4) |
| F-G4 | `approve_set_*` has no verb | `approve { key, payload_hash }` verb, 18 additions (§4.7) |
| F-G5 | `concurrent` leases during an outage | leases are draws; node-local against the last observed count in stale-policy mode; exposure stated (§2.3) |
| F-G7 | candidate set bound vs unbounded pools | `ArrayVec<VerifiedDestination, 64>`; `CandidateSetTooLarge` boot refusal + cell (§3.1) |
| F-G8 | hard-close on any `Refused(Authenticate)` | bound-session / `SessionUnbound` / handoff mismatch close; unbound-session credential refusal renders and continues (§2.3) |
| F-G9 | idle close on unbound sessions | `session_idle_max` 300 s (§2.3) |
| F-N2, F-N3, F-N7 | dimension wording; dev-tree script; `peer_table_ttl` = 2 × `outage_grace` | applied |

Sweep on v1.10: §1–§4/§10 scan clean under the word-boundary + backtick rule; no stale term remains.

## Round 14 closure map (v1.10 → v1.11)

Reviewers: fresh Fable (3 blockers / 8 gaps / 8 nits) and fresh Opus (6 blockers / 4 gaps / 5 nits;
its review overlapped the Fable closures being applied live, and it re-checked against the final
file). Both "GREEN LIGHT: no". Parity facts verified: `USAGE_CURRENCY = "USD"`; `hooks-ranking` natives
`cheapest/fastest/least_busy/usage` by `strategy:` name and the inline SWRR floor; self-serve `parent`
from `role_bindings.<module>.<role>.group`; `plan_mint_group` existence-only parent check;
`provision_child` copies caps from the nearest `child_default`; rewrite gates `ensure_dom()` the full
body; 1.5.5 metering write-behind through store outages.

| # | Finding | Closure in v1.11 |
|---|---|---|
| F-B1 | lane locator beyond the 64 KiB head | every declared pointer resolves incrementally across body chunks before `Open`; spill buffer under a separate `spill_budget`; oracle cell with the lane key last (§2.1, §4.7, §10) |
| F-B2 / O-B2 | `max_unposted_accrual` had two formulas; `max_hold` lacked the input term | one formula from enforced quantities; `max_hold` gains Σ input-class (`request_body_max_bytes` ÷ divisor) × price; §10 duplicate row deleted (§4.7) |
| F-B3 | `export_keyset` under `unset` has no recipient | mandatory recipient public key; fingerprint in `Access`; residual risk (§4.7, Appendix A) |
| F-G1 | fee on non-client-origin units | `per_request_fee` prices only `Origin::Client` `Open`/`OneShot`; oracle cell (§4.5 cl. 2) |
| F-G2 | single-node store outage posture | N ∈ {0, 1}: stale-policy mode for `outage_grace`, then drain; §10 names the change from 1.5.5's write-behind (§4.7, §10) |
| F-G3 | committed schema version after Migration | sealed by `Migration` (§4.8) |
| F-G4 | cross-window top-up | transfer `Slice` line `{ window_from, window_to }`; per-window identity ± transfers (§4.6) |
| F-G5 | lane cross-check with undeclared legs | over declared legs; declared-but-absent → `MeterDisputed` (§2.2) |
| F-G6 / O-N5 | `CandidateSetTooLarge` unnamed; window wording | named in §10; store `[4, 5]` exception stated in §1.4 and §10 |
| F-G7 | `data_dir` on read-only config mounts | `BUSBAR_DATA_DIR` / `--data-dir`, sealed in `Policy` (§4.7) |
| F-G8 | cursor preallocation vs 15 MB | lazily grown; RSS counts actual bytes (§3.1, §10) |
| F-N1..N8 | table rows; time-to-fill arithmetic; `SessionAccrual` in the closed list; approve sentence; parent wording; price-axis wording; rewrite exception named | applied (the rewrite exception was then closed outright by O-G4) |
| O-B1 | `currency` default vs `/usage` `USD` | default `USD` label (§4.7) |
| O-B3 | SWRR floor never sealed | seal covers `strategy:` natives and the implicit SWRR floor (in-tree hook at `Migration`); no-policy oracle cell (§3.6, §8.1) |
| O-B4 | fan-out double charge | parent lines cover local recipients only; Σ parent + children == single-node figure cell (§2.2, §2.3, §8.1) |
| O-B5 | 4 KiB arena vs per-frame relay | arena reset per frame on the relay path (§3.1, §10) |
| O-B6 | spill charged to the 15 MB budget | separate `spill_budget` (8 × `request_body_max_bytes`), outside the headline row; `SpillBudget` refusal named in §10 |
| O-G1 | origin table not total | `Arrival → none`, `Bootstrap → KernelVerb { bootstrap }` (§3.6) |
| O-G2 | `user:*` template does not exist | caps from the nearest `child_default`; uncapped leaf possible; Appendix A (§4.7) |
| O-G3 | admin mint parent existence-only | parent must lie in the minting admin's chain; §10 named strengthening; oracle cell (§4.7, §8.1, §10) |
| O-G4 | rewrite scope vs spooled body | rewrite over the spooled body under `spill_budget`; 1.5.5 full-body rewrite gates work unchanged; §10 exception removed (§1.4) |
| O-N1..N4 | corrupted sentence; two `take()` sites; `in_flight_cap` at step 0; "carried" overdraft | applied |

Sweep on v1.11: §1–§4/§10 scan clean; no stale term remains.

## Round 15 closure map (v1.11 → v1.12)

Reviewers: fresh Opus (5 blockers / 5 gaps / 3 nits) and fresh Fable (2 blockers / 5 gaps / 13 nits).
Both "GREEN LIGHT: no"; both ran the doc scan mechanically and found §1–§4/§10 clean apart from the
missing exclusion markers. Parity facts verified: `refund_bucket` never refunds the admission
`requests` counter; the unknown-lane guard is four-way incl. `pricing_enabled()`; the 1.5.5 admin
credential is a config-level principal with no group; admin verbs never reach group admission;
`hooks-ranking` natives `Abstain` to the SWRR floor.

| # | Finding | Closure in v1.12 |
|---|---|---|
| O-B1 / O-N3 | fee predicate decided by the plane's `finish` | kernel-derived predicate (priced upstream leg + relayed frame + transport `status_class` fact); `finish` is a second source under the variance rule → lower `fee_count`, `MeterDisputed`; lying-`finish` meta-test; `http` declares `status_class` (§2.2 table, §3.2, §5, §8.2) |
| O-B2 | `requests` draw releasable on failure | settles at the drawn quantity for every end at or after Admit, never released; oracle cell (§2.2 table) |
| O-B3 / F-N8 | unknown-lane refusal without a card | conditioned on a card being present; no-card keyed unknown lane served at 0; two cells (§4.7, §8.1) |
| O-B4 | `in_flight_cap = 0` breaks the exposure formula | measured peak in-flight substitutes; an operator-pinned bound requires a finite cap (§4.7) |
| O-B5 / F-G3 | keyset ceremony unnamed; `import_keyset` unbounded | §10 names it; §4.8 migration sequence; 3-node battery cell; `import_keyset` irreducible, `KeysetPresent` refusal (§1.2, §4.8, §8.3, §10) |
| O-G1 | hook composition undefined | `permutation: Option` (None = abstain); config-declared seat order sealed in `Policy`; `restrict` intersects; first `veto` wins; SWRR floor last (§1.4) |
| O-G2 / F-N1 | identity indexed without window; missing terms | one identity per `(bucket, dimension, scope, window_start)` as a delta from the last checkpoint, ± transfers; attribution form (§4.2) |
| O-G3 / F-G2 | fan-out partition double-prices same-node cross-bucket recipients | `Delivery` units are cross-node only; same-node recipients priced on the parent; cell (§2.3, §8.1) |
| O-G4 | no default store | `memory` mandatory in-tree default (§1.4) |
| O-G5 | doc-scan exclusion markers absent | markers inserted around the §1.3 block (§1.3) |
| O-N1, O-N2 | Tick wording; `SessionAccrual` from Client origin | applied (§2.3, §3.6) |
| F-B1 | root admin has no chain | the config-level admin's chain is the whole tree; containment binds role-bound admins only; positive cell (§4.7, §8.1, §10) |
| F-B2 | fee and `requests` on admin-plane units | fee, `requests` and `concurrent` draws apply only to units whose Route selects a priced upstream leg; admin-plane cell (§2.2 table) |
| F-G1 | no ingress estimate without a declared length | chunked bodies size input classes at `request_body_max_bytes ÷ divisor`; cell (§2.1) |
| F-G4 | read-only config mount | probe order `BUSBAR_DATA_DIR` → config dir → `$XDG_STATE_HOME/busbar` → `/var/lib/busbar`; boot cell (§4.7) |
| F-G5 | 4 GiB preallocation | incremental 64 MiB segments; `wal_capacity` is a high-water cap; boot cell (§4.3) |
| F-N2..N13 | legacy row key; arena wording; journal formula terms; garbled sentence; duplicate idle clause; `Principal::Anonymous`; `TransportId`; signer/digest change path; `unposted_alarm` operand; new-transport-crate path | all applied |

Sweep on v1.12: §1–§4/§10 scan clean with the exclusion block honoured; no stale term remains.

## Round 16 closure map (v1.12 → v1.13)

Reviewers: fresh Opus (2 blockers / 5 gaps / 3 nits) and fresh Fable (3 blockers / 9 gaps / 9 nits).
Both "GREEN LIGHT: no"; both ran the doc scan mechanically and found it clean. Parity facts verified:
1.5.5 bills ZERO when the upstream reports no usage; the body is buffered whole before any handler;
`tokens` caps enforce with pricing off; auth ABI window `[1, 2]`.

| # | Finding | Closure in v1.13 |
|---|---|---|
| O-B2 / F-B1 | keyset ceremony deadlocks (no off-node form; `secret-local` mints on every boot; posture) | `secret-local` mints only under a `Bootstrap` unit; a joining node refuses `KeysetMissing { remedy }`; `busbar keyset import` is an OFF-NODE CLI on a stopped node, outside the verb posture; no on-node import verb (17 verbs); §4.8 sequence and battery cell rewritten (§1.2, §4.7, §4.8, §8.3) |
| O-B1 | `in_flight_cap` gates Arrival only; `max_hold` ignores fan-out | enforced on insertion into the in-flight table for every origin; `max_fanout_recipients` 10,000 folded into `max_hold` with the chain's max tier (§2.2 step 0, §4.7) |
| O-G1 | `requests`/`concurrent` draw condition stated at two times | decided at Admit over the verified set (contains an upstream candidate), never released; fee stays Route-derived (§2.2 table) |
| O-G2 / F-N2 | fan-out "or bucket boundary" | deleted; `Delivery` units are cross-node only (§2.3) |
| O-G3 | `session_seconds` undefined | kernel-owned meter class (like `fee`, `requests`); bucket `bill_idle: true`; priced by the card per lane (§2.3) |
| O-G4 | fee clause (c) vacuous off HTTP | kernel-derived on every transport: the unit is `Completed`; `status_class` corroborates where declared (§2.2 table) |
| O-G5 | journal formula omits checkpoints | checkpoint term: touched buckets × dimensions × scopes × 12 + heads; full population every `checkpoint_full_interval` 24 h (§10) |
| O-N1..N3 | joined table row; `unpriced_classes` vs boolean; held fee conditional | applied |
| F-B2 / F-N9 | locator-absent cell cannot be green | 1.5.5 posts 0; the cell asserts the flagged floor with 1.5.5's 0 recorded — owner-signed exception (§2.2 table, §8.1) |
| F-B3 | zero-config memory store stops admitting | retention posture sealed from the config: no store named → `discard-after-anchored-checkpoint` at `wal_capacity`, journaled, alarmed, Appendix A; explicit store keeps fail-closed (§4.2, §10, Appendix A) |
| F-G1 | maker = checker | approver fingerprint ≠ maker's, `Refused(Approve, SelfApproval)`, cell (§4.7, §8.1) |
| F-G2 | `tier_bp` missing from hold sizing | hold per bucket × `tier_bp`; `max_hold` uses the chain's max tier; boundary cell (§2.2 step 4, §4.5, §4.7, §8.1) |
| F-G3 | `late_accrual` bound asserted only | at parent exit, outstanding `HoldAccrual`s convert to child-owned `Hold`s sized `max_provider_push`, drawn synchronously (§2.3) |
| F-G4 | uncarried overdraft outside the identity | "carried or not"; sealed `Σ overdraft_uncarried` (§4.2) |
| F-G5 | no divisor without a card | pinned default divisor in `METER_CLASSES`, card may override (§2.2 step 4) |
| F-G6 | `unpriced_classes` derivation | ⋃ registered `METER_CLASSES` \ the kernel/1.5.5 set, sealed verbatim (§4.7) |
| F-G7 | signer set under `unset` | `any`, like the digest set; Appendix A (§1.2) |
| F-G8 | chunked-body hold ≈ 8M units | spool to end-of-body under `spill_budget` before Admit; exact sizing (§2.1) |
| F-G9 | SWRR floor on fresh installs | always kernel-registered, last at `Before(Route)`, flags pinned (§3.6) |
| F-N3..N8 | "× op classes" wording; "priced" = kind; `token` allow-list entry dropped; first veto at any seat; `peers:` excludes self; `set_dispute_max_age` residual risk | applied |

Sweep on v1.13: §1–§4/§10 scan clean; no stale term remains.

## Round 17 closure map (v1.13 → v1.14)

Reviewers: fresh Opus (3 blockers / 3 gaps / 3 nits) and fresh Fable (2 blockers / 6 gaps / 10 nits).
Both "GREEN LIGHT: no"; both ran the doc scan clean. Parity facts verified: the fee is decided on the
2xx headers and never reversed by a mid-stream cut; the idempotency key has no length cap; 1.5.5's
routes are `/{name}/v1/…`, `/{provider}/{model}/v1/…`, `/model/{id}/converse`, `/v1beta/models/*rest`;
`limits.default_max_tokens = 4096` and per-model `default_max_tokens`; `preopen_gate_hooks` and pool
rewrites run over the fully buffered body; check-and-charge charges nothing on refusal.

| # | Finding | Closure in v1.14 |
|---|---|---|
| O-B1 / F-N2 | fee clause (c) "Completed" contradicts the 2xx-stream-dies cell | fee decided at the FIRST response frame (`status_class == success` where declared, else plane `finish ≠ Error`), never reversed; empty-body 2xx bills (§2.2 table) |
| O-B2 / F-G6 / F-N3 / F-N8 | `requests`/`concurrent` bundled; draw condition | split: `requests` drawn at Admit for `Origin::Client` units with an upstream candidate, settled for every unit that reached `Admitted`, never released; `concurrent` one lease per capped-`concurrent` bucket for every unit of any origin except Handshake/Tick, always released at exit; non-upstream plane cell (§2.2 table, §2.2 step 4, §4.6, §8.1) |
| O-B3 | `MAX_CLIENT_KEY_BYTES = 64` | dropped; keys hashed streaming at any length, never truncated; cell (§3.1, §8.1) |
| O-G1 | no node-global session bound; bound sessions never idle-close | `session_budget` (count + bytes) at Unit 0; `session_idle_max` applies to every session (§3.1, §2.3, §8.1) |
| O-G2 / F-G1 | `InFlightCap` for non-client origins hard-closes; Ticks occupy slots | `Refused(Decode, InFlightCap)` outside the hard-close list, counted into the Aggregate; Tick units never occupy a slot (§2.2 step 0) |
| O-G3 | recompute skips the fee line | recompute from the `Policy` at the posting's epoch incl. `per_request_fee` and `tier_bp`; no-card cell asserts it (§4.2) |
| O-N1 / F-N1 | `import_keyset` naming | `busbar keyset import` uniformly (§1.2, §4.8, §10) |
| O-N2, O-N3 | "two ids"; row-key order | applied |
| F-B1 | closed `Selector` cannot claim 1.5.5's routes | `PathPattern([Lit | Var | Tail])`; per-segment `overlaps`; one boot cell per 1.5.5 route (§3.3, §8.1) |
| F-B2 | gates/rewrites/body signatures see a prefix | body-reading hooks, `may_rewrite`, and `Signed { over: Body | Both }` force "deepest pointer = end of body"; cell (§2.1, §8.1) |
| F-G2 | §2.3 vs §4.7 on a peerless node | one rule: stale-policy mode for `outage_grace`, then drain (§2.3) |
| F-G3 | "class family" undefined | `METER_CLASSES` entries carry `family`, `direction`, default divisor (§1.4) |
| F-G4 | flow re-open unspecified | after `Ingress::Close` the kernel re-presents the cursor once; battery cell (§2.3) |
| F-G5 | `grpc` declares no `status_class` | declared from `grpc-status`; rule: any transport carrying an upstream status declares it (§5, §2.2) |
| F-N4 | `max_response` source | 1.5.5's per-lane `default_max_tokens`, else `limits.default_max_tokens` (4,096) (§4.7) |
| F-N5, N6, N7, N9, N10 | store-plugin wording; fan-out sentence; `SessionAccrual` with no upstream (`*` row); `unset` dispute consequence named; §10 header wording | applied |

Sweep on v1.14: §1–§4/§10 scan clean; no stale term remains.

## Round 18 closure map (v1.14 → v1.15)

Reviewers: fresh Opus (3 blockers / 3 gaps / 2 nits) and fresh Fable (2 blockers / 8 gaps / 7 nits).
Both "GREEN LIGHT: no"; both ran the doc scan clean. Parity facts verified: 1.5.5 charges and refunds
only the selected pool's buckets (`applies_to_pool`); the unknown-lane 400 fires before the group
charge; `SecretRef` forms `{env:}`/`{file:}`/module on provider, TLS and admin-token keys.

| # | Finding | Closure in v1.15 |
|---|---|---|
| O-B1 | per-bucket `tier_bp` vs one scalar per posting | differing `tier_bp` within a chain is a boot refusal (`TierMismatch`, like currency) (§4.5 cl. 2, §4.7) |
| O-B2 | `max_hold` omits the tier | `× max tier_bp over configured buckets` (§4.7) |
| O-B3 | scoped-pool release vs "never released" | at Route every dimension drawn on an unselected scope is released; "never released" applies to routed scopes only; cell (§2.2 step 4, §8.1) |
| O-G1 | fee predicate has no origin clause | (a) requires `Origin::Client` `Open`/`OneShot`; provider-push cell `fee_count = 0` (§2.2 table, §8.1) |
| O-G2 | `tier_bp` unbounded | ≤ 100,000 boot refusal; delta a `/usage` line; Appendix A (§4.7, Appendix A) |
| O-G3 | 1.5.5 config blocks not mapped; secret-ref refusal unnamed | block mapping stated; secret refs never reach a plane; refusal named; corpus boot cell (§10) |
| O-N1, O-N2 | handshake parenthetical; "plane-sourced" middle leg | applied (§2.3, §1.1) |
| F-B1 | authenticate-once protocols cannot bind an unbound session | `session_bindable = true` from a Completed Unit 0 / Handshake unit binds the session; AUTH-then-N cell (§2.1, §8.1) |
| F-B2 | disk-full drain before the purge threshold | discard at the earlier of `wal_capacity` and `wal_free_min` (128 MiB); two-fill cell (§4.2, §8.1) |
| F-G1 | provider units have no priced lane | `SessionUpstream` carries the paired upstream's lane; `*` default row otherwise (§3.6, §1.4) |
| F-G2 | `SessionAccrual` outside the in-flight table | enters the table under `in_flight_cap`; only the heartbeat/sweep Tick is zero-hold (§2.2 step 0) |
| F-G3 | keyset recipient keypair | operator keypair or `busbar keyset recipient-keygen`; `--recipient-key` on import (§1.2) |
| F-G4 | planes may declare kernel class keys | `requests`, `fee`, `count`, `session_seconds` kernel-reserved; §6 rows corrected (§6) |
| F-G5 | `Unpriced` with no card | defined only relative to a present card; no card → 0, unflagged (§2.2 step 4) |
| F-G6 | `peer` sessions outside the grammar | kernel-internal, never Teller units; §5 battery exemption (§2.3, §5) |
| F-G7 | `transport:handshake` scope for Anonymous | kernel-granted for every principal (§2.3) |
| F-G8 | locator-absent contradiction | one statement: floor posted and flagged, owner-signed (§8.1) |
| F-N1..N7 | recompute origin rule; quorum difference; "up to the in-flight count earlier"; `max_output` additive; `*` row in the card grammar; `Class(tokens)` membership pinned; product-realistic row cap | applied |

Sweep on v1.15: §1–§4/§10 scan clean; no stale term remains.

## Round 19 closure map (v1.15 → v1.16)

Reviewers: fresh Opus (4 blockers / 2 gaps / 4 nits) and fresh Fable (3 blockers / 8 gaps / 7 nits).
Both "GREEN LIGHT: no"; both ran the doc scan clean. Parity facts verified: 1.5.5's atomic group
admission charges LAST and its 503s fire after the charge; per-lane `ModelCfg.max_requests` lifetime
budget spent on the 2xx headers and refunded on body failure, exposed to ranking hooks as
`budget_remaining`; Candidate/Routing restrict-to-empty rejects fire after the charge.

| # | Finding | Closure in v1.16 |
|---|---|---|
| O-B1 / F-N5 | Nested/Delivery origin rows circular | explicit rows (§3.6) |
| O-B2 | breaker at Verify drops the `requests` charge | breaker and destination budget order only, never empty the set; all-down → `Failed(Route)` after Admit with the slot retained; cell (§2.2 step 2, §8.1) |
| O-B3 | disaster recovery unreachable under `unset`; `chain_break` as a boot remedy | `chain_break`/`store_restore`/`reseal_epoch_floor` also exist as off-node CLI on a stopped node; §4.7 enumerates every verb refused under `unset`; keyset-lost cell (§1.2, §4.7, §8.1) |
| O-B4 / F-G3 | `max_fanout_recipients` undefined | defaults row, `Refused(Approve, FanoutTooLarge)` (§4.7) |
| O-G1 | the one change billing more than 1.5.5 unnamed | named in §10 with the flag and dispute path |
| O-G2 | store `[4, 5]` window with no ABI-4 store | `[5, 5]` like every kind; `StoreReadOnly` M1 artifact dropped (§1.4, §9.1, §10) |
| O-N1..N4 | `in_flight_cap` row codes; `SessionAccrual` origin wording; `late_accrual` exposure in nano-units; `recipients` is kernel `Count` | applied |
| F-B1 | per-lane lifetime `max_requests` missing | breaker unit owns the per-destination `total` budget; drawn with the fee, reversed on body failure; `DestinationBudgetExhausted` ordered last; `budget_remaining` hook fact; four cells; §10 block mapping (§3.4, §8.1, §10) |
| F-B2 | `HANDSHAKE_TRIGGER` puts protocol verbs in transports | `Ingress::Handshake(UnitDraft)` — the plane delimits protocol handshakes; transport triggers only for transport-native events; `tcp-line` row and §2.3 reworded; `Challenge` circularity removed (§2.3, §3.2, §5, §2.2 step 1) |
| F-B3 | Candidate/Routing seats before the draw | `After(Admit)` for Candidate; both seats after the `requests` draw; cell (§1.4, §8.1) |
| F-G1 | `status_class` an open key, session-level | `STATUS_CLASS: bool` on `TransportMeta`; closed `StatusClass` enum as per-frame meta; no slot → plane `finish` sole source, accepted (§3.4) |
| F-G2 | variance rule for `Locator` vs kernel floor | stated per source pair; `locator_floor_ratio` 4, one-sided, posts the floor (§4.5, §4.7) |
| F-G4 | quorum availability vs slice/peer bounds | bounded by `slice_ttl` 60 s extended tick by tick under quorum; peers keep broadcasting (§2.3) |
| F-G5 | staleness drain irreversible | reversible within `max_unit_duration`, else the process exits for its supervisor (§4.7) |
| F-G6 | ephemeral `data_dir` with an explicit store | `keyset_ref` resolves the keyset from the secret plugin at boot (§4.7) |
| F-G7 | refused `SessionAccrual` tick drops time | next tick sized at elapsed since last settled; `late_accrual` beyond one tick (§2.2 step 0) |
| F-G8 | "required locator" at no card | defined relative to a present card (§2.2 table) |
| F-N1..N7 | N = 1 formula; §4.8 refusals listed in §10; exceptions wording; step 4 "priced"; checkpoint-rate measured row; sealed `data_dir` honoured on later boots | applied |

Sweep on v1.16: §1–§4/§10 scan clean; no stale term remains.

## Round 20 closure map (v1.16 → v1.17)

Reviewers: fresh Fable (**0 blockers** / 3 gaps / 7 nits) and fresh Opus (2 blockers / 4 gaps / 4 nits).
Both ran the doc scan clean; both verified the pinned 1.5.5 figures again. Both converged on the quorum
branch of the fleet rule.

| # | Finding | Closure in v1.17 |
|---|---|---|
| O-B1 / F-G2 | quorum branch spends a slice the store has released | `stale_serve_max = lease_ttl + max_unit_duration` (630 s), strictly before the store's 635 s release; exposure for every dimension = Σ open holds on already-drawn slices, no window ever over-issued; partition-then-heal and 2-node cells (§2.3, §4.7) |
| O-B2 | N = 1 contradiction | quorum branch requires N ≥ 2; N = 1 → `outage_grace` only (§2.3, §4.7) |
| O-G1 | `PlaneCount` companion unsatisfiable for objects/rows/queries | same-unit companion where one exists; otherwise `estimated` under a one-sided implausibility bound; `blob` row; over-reporting-`objects` meta-test (§4.5, §6) |
| O-G2 | checkpoint path unbudgeted; phantom §10 row | §10 checkpoint row (p99 at M2, ≈ 24/s) and anchor-throughput precondition (§10) |
| O-G3 | `KernelVerb` units and `concurrent` | draw no dimension, take no lease; §8.3 cell covers `/audit` and `/usage` at a saturated cap (§2.2, §8.3) |
| O-G4 | `SessionAccrual` catch-up unbounded; `max_hold` lacks a session term | catch-up capped at `session_idle_max × price` (else close); `max_hold` gains the session term and "+ one accrual step" (§2.2 step 0, §4.7) |
| O-N1 / F-N2 | numbers pinned outside §4.7 | `stale_serve_max`, `slice_ttl`, segment size, `wal_free_min`, `MAX_SESSION_UPSTREAMS` rows (§4.7) |
| O-N2 / F-N3 | fee hold not origin-gated | `Origin::Client` only (§2.2 step 4) |
| O-N3 | no spill-engaged RSS row | added (§10) |
| O-N4 | fan-out sentence | rewritten as two sentences (§2.3) |
| F-G1 | fee decision point on trailer-status transports | `STATUS_CLASS: Option<StatusAt { FirstFrame | Terminal }>`; terminal-frame decision; missing trailer → 0 / `MeterDisputed` (§2.2 table, §3.4, §5) |
| F-G3 | multi-upstream sessions unaddressable | `SessionUpstream { upstream: UpstreamIdx, … }`, `MAX_SESSION_UPSTREAMS` 8 (§3.6, §4.7) |
| F-N1, N4..N7 | "transport fact" wording; `CacheWrite` direction; "+ one accrual step"; exceptions order; `peers:` additive | applied |

Sweep on v1.17: §1–§4/§10 scan clean; no stale term remains.

## Round 21 closure map (v1.17 → v1.18)

Reviewers: fresh Opus (2 blockers / 4 gaps / 3 nits) and fresh Fable (1 blocker / 6 gaps / 8 nits).
Both ran the doc scan clean. Parity facts verified: the rate card is keyed by the `models:` name while
the client-facing name is normally a pool (the 1.5.5 guard exempts pools and by-model names); 1.5.5's
shed is a generic non-dialect 503 with `Retry-After`; the SSRF metadata-host guard keys exist in
`RootCfg`.

| # | Finding | Closure in v1.18 |
|---|---|---|
| O-B1 | pool names refused as unknown lanes; cross-check disputes every pooled unit | a located name resolves to pool / by-lane / card lane; the trust unit expands pools; the request-side cross-check leg is set membership; `UnknownLane` only when none of the three; cell (§2.2, §3.6, §4.7) |
| O-B2 / F-1 | quorum branch vs `StaleSlice` at 60 s | in outage mode a drawn slice stays spendable past `valid_until` until the branch's bound; §4.6 rule qualified "outside outage mode"; t = 300 s cell (§2.3, §4.6) |
| O-G1 | `cache_write` in no hold arm; card re-families | family from `METER_CLASSES.direction`; `Response` → `max_response`, every other direction → ingress estimate (§2.2 step 4, §4.7) |
| O-G2 | `max_response` ignores `default_max_tokens` | lane `default_max_tokens` → `limits.default_max_tokens` → `max_output` → 4,096 (§4.7) |
| O-G3 / F-8 / F-10 | busy dry session; catch-up excess; unbound-session accrual | dry-budget close applies to busy sessions on `OverBudget`; excess posted flagged and journaled; unbound accrual to the last unit's principal (§2.2, §2.3) |
| O-G4 | product-realistic RSS row had no number | ≈ 75 MB from the formula, pinned at M2 (§10) |
| O-N1 | pre-decode refusal renderer | kernel through the transport's generic envelope, byte-identical to 1.5.5's shed 503; cell (§2.2 step 0) |
| O-N2, O-N3 | `requests` row qualification; `http`/`sse` row columns | applied |
| F-2 | provider frame refused at the cap dropped unposted | kernel-floor `estimated` line into the open unit, exceptions report, hard-close (§2.2 step 0) |
| F-3 | Verify lane rule over-excludes | permitted for the draft's op class; hold at the max over all (§2.2, §3.6) |
| F-4 | priced `KernelVerb` units have no bucket | `admin` attribution bucket; nano-units only (§2.2) |
| F-5 | keyset single point of loss silent | boot warning + `/usage` line on explicit-store deployments without `keyset_ref` or an export (§4.7) |
| F-6 | scatter to N upstreams | `Delivery` children may carry `Upstream` (§3.6) |
| F-7 | status leg on composed transports | inherited from the lower layer; `ws` after upgrade stated (§3.4, §5) |
| F-9, F-11..15 | Tick parenthetical; quorum re-evaluation and peer aging; config-delta maker; phrase matching; SSRF guard mapping; `encode_refusal` constraint | applied |

Sweep on v1.18: §1–§4/§10 scan clean; no stale term remains.

## Round 22 closure map (v1.18 → v1.19)

Reviewers: fresh Fable (4 blockers / 3 gaps / 5 nits) and fresh Opus (3 blockers / 5 gaps / 3 nits).
Both ran the doc scan clean. Parity facts verified: the shed 503 carries `Retry-After`; 1.5.5's proxy
path reads no client idempotency key; per-provider `allow_metadata_hosts` override exists and replaces.
Note: the round-21 `max_response` row edit had not applied; it is applied now.

| # | Finding | Closure in v1.19 |
|---|---|---|
| F-B1 | open holds at the store's 635 s release | `release_deadline = lease_ttl + 2 × max_unit_duration + skew_max` (1,235 s); every unit admitted by `stale_serve_max` settles first; cell (§2.3, §4.6) |
| F-B2 | peer keys / table die at 60–120 s | peer key validity through `stale_serve_max`; `peer_table_ttl` = `stale_serve_max + tick_interval` (§2.3, §4.7) |
| F-B3 | floor rule posts more than 1.5.5 | `locator_floor_ratio` posts the LOWER with `MeterDisputed`; input-family holds are a max over classes sharing the same bytes (§4.7) |
| F-B4 / O-B2 | provider frame at the cap on an idle session unposted | standalone `Transaction` against the session's principal, synchronous draw under the `late_accrual` overdraft rule; cell (§2.2 step 0) |
| F-G1 | revocation exposure in the quorum branch | store-reachable peers forward `Policy`/revoke tail over `peer`; otherwise exposure ≤ `stale_serve_max`, stated (§2.3) |
| F-G2 | `*` row absent | `bill_idle: true` without a `*` row is `MissingDefaultLaneRow` at boot (§1.4, §4.8) |
| F-G3 / O-B1 | `max_response` literal; card re-families; `max_hold` drops cache classes | row rewritten: direction from `METER_CLASSES`; effective `default_max_tokens`; `max_hold` sums by direction (§4.7) |
| F-N1..N5 / O-G1 | hard-close list; `approve` exempt; one boot-refusal list mirrored in §10; "dialect" reason | applied (§2.3, §4.7, §4.8, §10, §1.3) |
| O-B3 | idempotency location silently acquired by migrated configs | claim config, absent when migrated; §10 named change (§6, §10) |
| O-G2 | overdraft ceiling and grace slices missing from the residual register | added (Appendix A) |
| O-G3 | no SNI selector | `Sni(host)`, `ClientCertSubject(dn)` (§3.3) |
| O-G4 | restrict-to-empty at `Before(Route)` | `Failed(Route, RestrictedEmpty)`, outcome class, cell (§8.1) |
| O-G5 | cold boot under `required` with an unapproved delta | serve on the last sealed `Policy`, journal, alarm, `/usage`; cell expectation (§4.7) |
| O-N1..N3 | per-provider SSRF override; provider units on a dial-less session; "the chain's `tier_bp`" | applied |

Sweep on v1.19: §1–§4/§10 scan clean; no stale term remains.

## Round 23 closure map (v1.19 → v1.20)

Reviewers: fresh Opus (4 blockers / 2 gaps / 4 nits) and fresh Fable (6 blockers / 7 gaps / 5 nits).
Both ran the doc scan clean. Parity facts verified: restrict `on_empty` default `weighted` (SWRR
escape); hook `on_error` default `nothing`; a ranked order is walked as-is with SWRR only on abstain;
1.5.5 route precedence (pools before lanes, literal before variable); stage taps are fire-and-forget.

| # | Finding | Closure in v1.20 |
|---|---|---|
| O-B1 | provider unit refused after Decode dropped unposted | kernel-floor `estimated` posting for a provider unit refused at ANY step; outside the hard-close list; cell (§2.2 step 0) |
| O-B2 / F-G2 | op-class span stated three ways | the verified set is the draft op class only; mislabel caught by `audit` (§2.2 step 4, §4.5) |
| O-B3 | ingress apportionment among Input/CacheRead/CacheWrite undefined | whole estimate to the most expensive same-bytes class, 0 to the others; Σ = max (§2.2 step 4) |
| O-B4 / F-B5 | `peer_table_ttl` pinned twice | one value: `stale_serve_max + tick_interval` (§2.3) |
| O-G1 / F-G3 | `bill_idle` undefined | removed; the refusal binds to a declared `session_seconds` class with no `*` row (§1.4, §2.3, §4.8, §10) |
| O-G2 | `SessionAccrual` ticks reset the idle clock | "no NON-TICK unit"; cell (§2.3) |
| O-N1 / F-N1 | §4.8 list corrupt, not mirrored | one list, byte-identical in §4.8 and §10 |
| O-N2..N4 / F-N3 | `max_response` chain; `Recovery::materialize`; protocol-verb wording | applied |
| F-B1 | restrict-to-empty fail-open in 1.5.5 | `on_empty ∈ {weighted, reject, first}` sealed per migrated hook; cell per terminal (§1.4, §4.7, §8.1) |
| F-B2 | `on_failure` default breaks `on_error: nothing` | migrated hooks keep their resolved `on_error` chain; `closed` only for new hooks; cell (§4.7) |
| F-B3 | SWRR re-permutes a ranked order | a non-`None` permutation is terminal; the floor applies only on abstain (§1.4) |
| F-B4 | 1.5.5 routes overlap under the claim rule | overlap across planes; ordered intra-plane pattern set with sealed most-specific-wins; boot cell (§3.3) |
| F-B6 | lease-expiry release re-issues unobserved spend | the store releases NOTHING for a slice with unobserved settlements; `UnreconciledSpend` until replay or `resolve_slice` (§4.6) |
| F-G1 | one-sided locator bound | flag-only upper bound at floor × ratio (§4.7) |
| F-G4 | `After(Route)` admits veto/rewrite | `Tap`-only (§1.4) |
| F-G5 | §4.6 "stops admitting" wording | "no new draws, the §2.3 outage branches" (§4.6) |
| F-G6 | journal rows | `Access` entries in the formula; independent-recompute cost row (§10) |
| F-G7 | shed lands on open duplex sessions | `in_flight_reserve` 10 % for provider frames of open sessions (§2.2 step 0, §4.7) |
| F-N2, N4, N5 | "API-key principal" wording; arenas lazily grown; `adjust_threshold` floor noted | applied |

Sweep on v1.20: §1–§4/§10 scan clean; no stale term remains.

## Round 24 closure map (v1.20 → v1.21)

Reviewers: fresh Fable (1 blocker / 7 gaps / 7 nits — first explicit "no money-moving, house-favour,
credential-loss or plugin-decides path found") and fresh Opus (4 blockers / 1 gap / 2 nits). Both
were interrupted by a session rate limit and resumed. Parity facts verified: admin served on its own
loopback listener with `admin_require_mtls` boot guard; the inbound-concurrency cap applies to the
data router only; `/auth/token`, `/v1/models`, `/v1beta/models`, `/stats`, `/healthz`, `/metrics`
are data-plane routes outside the 66 admin operations; `reserved_admin_name` is not applied to groups.

| # | Finding | Closure in v1.21 |
|---|---|---|
| F-B1 / O-B4 | three sections disagree on hard-close for a refused provider unit | one source: cap or Admit-for-money → floor line + hard-close; Verify/Approve → floor line, session continues; §8.3 cell reworded (§2.2 step 0, §2.3, §8.3) |
| O-B1 | no listener axis; admin claims reachable on the public bind | listeners are a config axis with admissible claim sets sealed in `Policy`; 1.5.5's two listeners map with admin claims on the admin listener only; `admin_require_mtls` → `AdminListenerExposed` boot refusal; two cells (§10, §4.8) |
| O-B2 | `in_flight_cap` sheds the admin plane | `KernelVerb`-only units never take a table slot; cell (§2.2 step 0) |
| O-B3 | `/auth/token` and five data-plane routes outside the verb table | named non-admin surfaces added to the table, pinned by handler, with effects rows; `/auth/token` posture stated (§4.7) |
| O-G1 | spill retention window | retained until the egress body is encoded; hold-time term in the spill RSS row (§1.4, §10) |
| O-N1, O-N2 | kernel-declared reserved classes; boot assertion operand | applied (§6, §4.7) |
| F-G1 | `in_flight_reserve` an unnamed change | 0 when no session transport is claimed; named in §10 (§2.2 step 0) |
| F-G2 | kernel buckets collide with legal group names | `kernel:anonymous`, `kernel:admin` (§2.2) |
| F-G3 | open disputes pin discard-posture segments | disputed entries copied into the dispute register at purge (§4.2) |
| F-G4 | multi-round egress auth has no shape | `continue_handshake` on egress-auth schemes; `Auth::verify` takes the prior challenge state (§1.4) |
| F-G5 | quorum-branch exposure wording | branch bound named; `stale_policy` flag on both branches (§2.3) |
| F-G6 | revocation of an Admitted unit | `Aborted(Kernel { Revoked })` at the next Tick (§2.2 step 1) |
| F-G7 | fresh-install posture | `single` on both paths; `Bootstrap` distinguishes by legacy cells (§4.7) |
| F-N1..N7 | `Aborted` shape; `Access { KeysetExported }`; clause 2 leg condition; "reversal" = the mint; ephemeral-volume case in §10; lease wording; step-0 list tie | applied |

Sweep on v1.21: §1–§4/§10 scan clean. **Loop paused after round 24 at the owner's request.**

## Round 25 closure map (v1.21 → v1.22) — Opus only, at the owner's request

Reviewer: fresh Opus (2 blockers / 4 gaps / 3 nits). Doc scan clean; every pinned number re-verified
at the tag; §4.5 clause 2's fee-in-hold shape confirmed against `try_admit`.

| # | Finding | Closure in v1.22 |
|---|---|---|
| B1 | kernel-reserved classes have no legal `direction`; `fee` as `Input` over-holds 10^4× | `direction: Kernel` variant; reserved classes outside the partition and `max_response`, sized by their own rule; `max_hold` carries them only as explicit terms (§1.4, §2.2 step 4, §4.7, §6) |
| B2 | recompute "since the last checkpoint" covers ≈ 4 % at the headline rate | recompute watermark `(node, node_seq)` in the `Reconciliation` entry; watermark must reach the head every tick; corrupted-posting cell (§4.2) |
| G1 | `Class(tokens)` has no declaration site or draw rule | kernel-declared aggregate class; draws Σ of member estimates, settles Σ of actuals (§6) |
| G2 | `max_response` token-shaped for every response class | `default_max_response` per `METER_CLASSES` entry; the token chain is the token-family special case (§4.7) |
| G3 | settlement row vs `locator_floor_ratio` | the "two sources" row scoped to reported pairs; `Locator` figure is always the charge (§2.2 table) |
| G4 | `admin_in_flight_reserve` undefined | replaced by the plain exemption (§2.2 step 0) |
| N1..N3 | `Ingress::Handshake` in the decode line; §6 column meaning; `max_provider_push` term in `max_hold` | applied |

Sweep on v1.22: §1–§4/§10 scan clean. **Loop paused after round 25 at the owner's request.**

## Parity revision (v1.22 → v1.23) — owner mandate: identical to 1.5.5 from a user's perspective

Trigger: the owner ruled that 1.6.0 must be identical to 1.5.5 in every user-observable way, with only
the `mcp`, `a2a` and `voice` planes added. Eight extraction agents produced the citation-backed
inventory `1.5.5-BEHAVIOUR.md` (8 files, 11,256 lines, ≈ 2,900 rows, 122 UNVERIFIED). A parity clause
was added to the preamble, and every user-observable change the design had accumulated was reverted
to the 1.5.5 rule, with the stricter rule kept internal:

- Admission decision = 1.5.5's charge-then-check; the hold is accounting, never a gate (§2.2 step 4).
- Cents-truncated budget compare with fee lookahead (§4.5 cl. 1); post-hoc token cap (§2.2 step 4).
- Zero billing when the upstream reports no usage; the kernel floor is internal evidence (§2.2 table).
- Serve-through on store outage for peerless deployments (§2.3); fleet branches only with `peers:`.
- Per-node in-process idempotency cache with 1.5.5's composite keys (§4.4).
- Existence-only parent check on admin mint (§4.7).
- Unbounded pool candidate sets; spill sized to 1.5.5's buffering (§3.1, §4.7).
- Every 1.5.5 dynamic plugin loads through per-kind ABI adapters; `data_dir` optional with the keyset
  in the store; no new boot refusal can fire on a 1.5.5 config (§1.4, §4.7, §4.8, §7, §9.1).
- `/usage` byte-identical with NO additive lines; the legacy projection reprices at read time from the
  current card as 1.5.5 does (§4.5 cl. 4, §10).
- §10 rewritten: "Behavioural changes: NONE user-observable", the reversion list, and the single
  additive difference left for the owner (memory-store history across restart with `data_dir`).
- §8.1: no owner-signed exceptions on any 1.5.5-reachable surface.

Next: one parity-focused audit round (question: any user-observable difference from the inventory),
then freeze.

## Parity revision 2 (v1.23 → v1.24)

Two parity reviewers (Opus: 11 divergences / 5 unaddressed; Fable: 16 / 4; ≈ 25 distinct) read the
inventory against v1.23. Every item is "reproduce the inventory row; keep the stricter rule internal".
Closed by Appendix B — 25 parity bindings that override any conflicting sentence for every
1.5.5-reachable surface — plus strikes of the contradicting sentences (§1.2 trust boundary, §2.2
step 0/1/2, §3.4 destination budget, §4.5, §4.7 rows `on_empty`, `in_flight_cap`, `drain_quorum`,
`data_dir`, `max_response`, §6 llm row, §9.1 store gates). Notable corrections: `on_empty` default is
`reject` (a round-23 reviewer had it wrong; the inventory cites `hooks/mod.rs:976-980`); per-lane
`max_concurrent` fails and skips, never waits; tripped/exhausted lanes are excluded from the walk;
revocation gates new units only on `http`/`sse`; migrated hook seats run after the charge, last
ordering gate wins; the data-listener shed covers every route incl. `/healthz`; no `max_unit_duration`
cut or drain deadline for `http`/`sse`; `plugins.trust` reproduced verbatim; export plugins stay
at-most-once; `data_dir` default unset with the keyset in the store (rolling start, no ceremony);
peerless store outage = serve-through with `/usage` 500; no additive `/usage` lines anywhere;
`MissingGroup`; the legacy admin audit chain keeps appending; `on_exhausted` terminals and the
sticky-affinity pick reproduced; `--safe-mode` exit 2 reproduced and recorded as an OPEN owner decision.

## Parity revision 3 (v1.24 → v1.25)

Parity audit 2 on v1.24 — Opus: 21 divergences / 8 unaddressed inventory areas / 7 residual
sentences / 1 watch item; Fable: 9 divergences / 0 unaddressed / 5 residual sentences. ≈ 30 distinct
after merging (Fable D1/D2 = Opus PD-03, D7 = PD-21, D9 = PD-09). All closed by Appendix B PB-26..PB-57
plus rewording of every residual sentence in §1–§9 so an implementer reading the body is not misled.

Bindings added: post-charge refusals retain the `requests` slot and the pre-charge guard order
(PB-26); a terminal error on a stream bills zero (PB-27); gate vs base-policy `weighted` (PB-28) and
the four 503 literals (PB-29); the 14-rung protocol-detection ladder with three new selector forms
(PB-30); confined plugin routes kernel-mounted verbatim (PB-31); admin mutation rate limiting
(PB-32); `GET /auth/token` (PB-33); secret-ref timing, no watch for migrated refs (PB-34); auth chain
`Pass` arm and the credential cache incl. a real `flushed` count (PB-35); `admin_auth: []` open admin
(PB-36); ABI-2 store `Unsupported`-only fallback (PB-37); memory-store sweep scope (PB-38); reload
never applies restart-scoped keys (PB-39); byte-identical `expected one of` via the single `fleet:`
block (PB-40); 1.6.0 warnings gated on `data_dir`/`peers:` (PB-41); read-only boot hydrate for
migrated configs (PB-42); `/healthz`, `/metrics`, `/metrics/hooks`, `/stats` auth and presence gates
(PB-43); `in_flight_reserve` 0 without a session transport (PB-44); synchronous local revoke/rotate
(PB-45); migrated `Request` hooks seat `After(Admit)` (PB-46); scoped draws on the requested pool
only, fallback hop draws nothing (PB-47); stall sweep alarms only on `http`/`sse` (PB-48); the config
overlay subsystem (PB-49); `--migrate-config` (PB-50); `RUST_LOG` (PB-51); env-vs-config precedence
(PB-52); metric absences and gates (PB-53); CLI/env/signal/span oracle cells (PB-54); active health
probers (PB-55); egress HTTP-client parameters (PB-56); exclusion after SWRR selection (PB-57).

Residuals struck: §1.4 "TERMINAL" permutation → last wins; §1.4 `weighted` full-set wording; §1.2
no-self-mount carve-out; §1.2 stall on `http`/`sse`; §2.2 "refusal before that charges nothing";
§2.2 located-usage row on terminal error; §2.3 drain ≤ `max_unit_duration` (twice); §3.6 KernelVerb
"always checked"; §4.2/§4.3 high-water refusal and record-rate warning; §4.5 "named behavioural
change … §8.1 exception" and "floor at 0"; §4.6 grace slice; §4.7 `keyset_ref` warning,
`drain_quorum` "named change", `in_flight_reserve` row, kernel-verb surface list; §4.8 stop-the-world
ceremony and the serde key list; §5 `http` row; §7 store write-read-back and secret `watch`; §10
memory-store retention and the missing `config:` landing entry.

Next: parity audit 3 (Opus + Fable) on v1.25; freeze if clean.

## Parity revision 4 (v1.25 → v1.26)

Parity audit 3 on v1.25 — Opus: 24 divergences / 7 unaddressed areas; Fable: 11 / 3 (≈ 30 distinct;
both flag the in-flight money aborts, the 413 envelope, and misreads in PB-38/39/52). Nine of the
findings were bindings written in revision 3 from reviewer claims that the tag contradicts; each was
re-checked against the inventory row or the tag object and corrected (PB-1 `first` = the gate 503;
PB-4 `Retry-After` rule; PB-22 every bucket of the pool-filtered chain; PB-26 pre-charge exits are the
`finish_rejected` set — verified at `dispatch.rs:199-235` — and only the priced-but-unrouted 404 and
later ends retain the slot; PB-35 `Open` needs no `keys` arm and the `keys` arm is cache-exempt; PB-38
four sweeps incl. usage and metering; PB-39 enumerated restart keys; PB-52 `advanced.worker_threads`
rung; PB-57 exclusion before the credit walk). PB-72 records the precedence: the inventory row wins
over any binding that paraphrases it.

Added PB-58..PB-71: no money abort of an admitted `http`/`sse` unit and no `OverdraftCeiling` /
`StaleSlice` on a 1.5.5 config; node-local admission cells on a shared store without `peers:`; the
413 after auth, dialect-shaped; chunked bodies bounded by size only; `required_scope` (34 read-only /
32 full); plugin reload/rollback mechanics with store reuse; the token-minting egress-auth loop; egress
auth wire bytes; request/response header rules; per-dialect error mapping; the network guard; ingress
server posture; scrape shape; documented-vs-actual claims. PB-10 now 31 rows; PB-12 widened to the
built-in export sinks; PB-13 keeps the overlay file and probe; PB-18 `0 ⇒ unbounded`; PB-34 two
re-resolution exceptions; PB-40 covers every `deny_unknown_fields` struct; PB-45 reproduces the
per-node revoke/rotate bounds (faster propagation recorded as an OPEN owner decision, default
identical); PB-54 CLI as a subset invariant with the additive `--help` lines stated.

Body sentences reworded: §1.4 auth and hook rows, §2.2 step 0/2/4 and the `requests` row, §2.3 and
§3.1 `MAX_NEEDMORE_FRAMES`, §4.4 aborts, §4.5 cl. 3 (cents floor, micros none), §4.6 slices, §4.7
scope counts / reload / `spill_budget` / overdraft ceiling rows, §4.8 canary, §7 export, §8.1 `first`
cell, §10 memory-store sweeps. Inventory `1.5.5-auth-secrets.md:551` annotated with the actual
cross-node rotate mechanism (the row repeated a code comment).

Next: parity audit 4 (Opus + Fable) on v1.26; freeze if clean.

## Parity revision 5 (v1.26 → v1.27)

Parity audit 4 on v1.26 — Opus: 44 divergences / 7 unaddressed areas (Fable's run was killed by the
session rate limit before it reported; re-run on v1.27). Fourteen of the 44 were bindings that
paraphrased their inventory row wrongly, corrected per PB-72: PB-22 is CHECK-then-charge (pass 1
returns on the first blocking bucket in chain order charging nothing; pass 2 charges) — the
"charge-then-check" phrase, carried since the parity revision, was wrong in wording though not in
outcome; PB-9 now matches PB-45 on cross-node rotate; PB-47 charges the attempted (post-downgrade)
pool; PB-66 relayed response headers are per ingress writer (bedrock two, anthropic one, all others
none; `content-type`/`retry-after` busbar-set); PB-30 renders the path-inferred protocol and the
`/api`-prefix admin envelope; PB-20 eight wire fields with the digest string and empty genesis;
PB-31 the `DynExport::Err` 502 body; PB-39 five more restart families; PB-8 the walk deadline
applies to streams too; PB-64 the prober skips a pre-mint lane; PB-4 queue park only on an
`AtCapacity` exclusion; PB-12 names the inventory's own webhook-gate conflict and pins it by an
oracle cell; PB-34 five resolution sites, built-ins first, value semantics; PB-35 mandatory in-tree
plugins never count toward the chain, plus carrier precedence; PB-70 quantiles are unverified in the
repo and get scraped from the binary in Phase −1; PB-5 pick-time gate and SWRR fall-through; PB-21
in-flight 409 arm; PB-16 legacy row written only by the delivered-response tap; PB-18 the arena.

Added PB-73..PB-90: `advanced.response_headers`; reserved-name sets frozen; the served
`openapi.json` verbatim; the admin listener's exact route set and bare 404; `signing-key/rotate`
report-only; `revoke_key` on a tombstone; the refusing-bucket identity; breaker cooldown arithmetic;
no plugin deadlines for migrated plugins; usage extraction (cached subtraction, gemini thoughts,
`include_usage` hide-back); breaker scope per (pool, lane); response-stage taps on every end;
`max_tokens` injection; plane-normalized locators; non-chat billing classes sealed; 36 pairs never
refuse; migrated `on_error` default `nothing`; the ≈ 12 otherwise-unmentioned config keys.

Body: §2.2 step 4 check-then-charge; §1.4 hook row (SWRR fall-through, `After(Route)` fires on every
end); §3.4 breaker per (pool, destination); §4.2 and §4.7 the two remaining `/usage` additive lines
retagged to the ledger endpoint; §4.7 `plugins.trust.publishers` is an ordinary reload key (only the
binary-digest set is irreducible); §6 a plane is claimed only when configured; §7 `on_failure`
native-only; §3.1 bodies never in the arena; §10 cursor budget row, `wal_capacity` warning gated on
`data_dir`, "no other refusal or warning".

Next: parity audit 5 (Opus + Fable) on v1.27; freeze if clean.

## Parity revision 6 (v1.27 → v1.28)

Parity audit 5 on v1.27 — Fable: 7 divergences / **0 unaddressed**; Opus: 22 / **0 unaddressed**.
Both reviewers report every coverage-matrix area (C1–O6) addressed for the first time. Every
remaining item is a binding transcribing its row imprecisely or a row not yet transcribed; none is
a design-body contradiction. Closed:

Fable — fee follows the first frame RELAYED TO THE CLIENT (PB-91; a buffered cross-protocol 2xx that
becomes a 502/500 posts fee 0); PB-27 widened to every 1.5.5 not-billed arm incl. the SSE
`stream_failed` cut with the per-row `max_requests` refund; PB-79 phase order; `expires_at`
unenforced (PB-92); ABI-2 store shim for 1.6.0-only ops (PB-93); out-of-window ABI literal (PB-11);
plane blocks under `fleet:` (PB-74).

Opus — same-protocol `content-type` verbatim (PB-66); Bedrock 400 only for `budget`/`MissingGroup`
(PB-22/79); `upstream_credentials` passthrough (PB-94, new); freeze/concurrent phases before the
windowed pass (PB-22/79); hard-down park is lane-global (PB-83); streams bounded by the 300 s total
deadline, no idle timer (PB-48/8); `Server-Timing` unconditional, route headers gated (PB-73);
`enabled=false` is a pause propagated like rotate, revoke ≈ 10 s (PB-45/9); `literal` is not a
`SecretRef`, eight resolution sites (PB-34); `NO_WRITABLE_OVERLAY_MSG` is 400 (PB-49); admin
listener nested fallbacks, `/api` envelope data-listener only (PB-76/30); `config/reload` body
unchanged, `note` on `PUT /config/settings` (PB-39); bare plugin-route form (PB-31); `dirty` cell
arm (PB-38); context-length `<=` (PB-8); `anthropic-beta` rung (PB-30); taps fire only on the
forward path (PB-84); request-stage taps never reject (PB-6); 413 on admin paths (PB-60); env vs
config worker-thread warning text (PB-52); 49 `deny_unknown_fields` structs (PB-40).

Next: parity audit 6 (Opus + Fable) on v1.28. Freeze rule: both at 0 unaddressed AND no binding
misreads its row; residual row-transcription items are bound and the freeze proceeds.

## Parity revision 7 (v1.28 → v1.29) — and a stop

Parity audit 6 on v1.28 — Fable: 3 divergences / 0 unaddressed / 2 misreads; Opus: 88 / 1 (D2
streaming byte layout) / 24 misreads. Closed: PB-0 master rule (every inventory row is a binding and
an oracle cell; Appendix B restates only overrides); 24 misreads corrected against their rows — the
two that move money: PB-27 (the flat fee is KEPT on a client disconnect; only the lane unit refunds)
and PB-81 (hook gates 1 ms `timeout_ms` under a 64-slot `spawn_blocking` semaphore, auth chains fail
closed at 5 s — only STORE calls are deadline-free); 17 body contradictions fixed (concurrent gauge
per group, pool-name scope equality, lane budget after the upstream 2xx, downgrade hop needs both
ACLs, gates run concurrently, the literal `"anonymous"` actor, `child_default` not a template,
`FLEET_SAFE` never a 1.5.5 precondition, empty legacy head seals at zero, no self-drain on the
reference plane, no zero-config boot warning, no max-price check on a 1.5.5 card, panic = connection
drop, `/admin/info` reports the running binary, admin cells from handlers not `openapi.json`);
PB-95..PB-102 bind tap stages, the whole streaming byte layout, pristine request bytes and the
Vertex shim, `error_map` and lane-state carry-over, legacy rows / hydrate / erasure / metric timing,
admin wire details incl. ETag and both `/auth/token` flows, inbound SigV4 / mTLS / body-throughput,
and alarms as ledger-endpoint rows only. Inventory rows corrected under PB-72: the BEHAVIOUR rotate
trap (peer nodes refresh `by_id` only on local mutation/restart) and CFG-249 (per-instance gate).

Observation recorded for the owner: on the same v1.28 the two reviewers returned 3 and 88 items, and
Appendix B has grown from 25 to 102 bindings in five revisions while the misread rate stayed at
roughly one in four new bindings. The appendix is converging on "do what the inventory says" row by
row, which is what PB-0 now states outright. The loop is stopped here pending the owner's decision
on build strategy (see the session report).

## Parity revision 8 (v1.29 → v1.30) — owner decisions against `qa/DESIGN-BINDINGS.md`'s conflicts

`qa/DESIGN-BINDINGS.md`'s "Findings: bindings in conflict with the tree" section carried four
bindings that green, code-backed tests contradicted. The owner ruled code wins on all four; the
document is amended to say what was decided so the ledger stops listing them as contradictions:

- **PB-11** (plugin trust and ABI windows): the store plugin ABI window is `v2..=v4`, not `v2..=v2`
  — the published-1.5.5 floor (ABI 2) still loads, and ABI-4 stores (a later release) load too;
  `store_abi_below_or_above_the_range_is_refused_naming_v2_to_v4` and
  `supported_abi_store_floor_admits_v2` pin it. `supported_abi(kind)` now prints `v2..=v4` for a
  store.
- **PB-66** (request and response headers): an allow-listed `anthropic-beta` / `anthropic-version`
  (to a matching `anthropic` upstream) or `OpenAI-Beta` (to a matching `openai`/`responses`
  upstream) client header DOES ride upstream, scoped per egress dialect against cross-protocol leak;
  every other client header is still dropped. `client_anthropic_beta_reaches_matching_anthropic_upstream`,
  `client_openai_beta_reaches_matching_openai_upstream` and `non_allowlisted_client_header_is_not_forwarded`
  pin the rule as implemented (`engine/egress.rs` `FORWARDED_CLIENT_HEADERS`).
- **PB-75** (served OpenAPI document): `GET /admin/openapi.json`'s `info.version` reports the
  running binary's version (`CARGO_PKG_VERSION`, 1.6.0) — the same rule `GET /admin/info` (ADM-042)
  already applies — not a 1.5.5-verbatim pin; every other byte of the document stays VERBATIM.
  `openapi_doc_is_31_and_v1_prefixed` pins the version tracking the crate version.
- **PB-84** (response-stage taps): a pre-forward auth refusal (401) on a hooked pool DOES fire the
  completion tap once, with the synthetic outcome `rejected_by_auth` and the protocol-native status,
  so operators see refused requests in their taps; the published 1.5.5 binary does the same. Every
  other pre-forward refusal (403/429/413/404) is unchanged and still never taps.
  `completion_tap_fires_synthetic_rejected_by_auth` and oracle cell `hooks|hooked-pool|unauth` pin
  it (already the substance of the PR-0 owner decision recorded against PB-84 in revision 7; this
  revision moves the Appendix B row and its §1.4 hook-seat sentence into agreement with it).

Also recorded in Appendix A, not tied to a single PB row: the **maximum-spec-compliance** rule
(where the published 1.5.5 bytes deviate from a provider's own published spec, the spec wins and the
difference is registered as `improvement` in `accepted-differences.json` with owner sign-off — first
cases: Bedrock text blocks without a `contentBlockStart` frame, the Responses door's lifecycle
frames, the required members added on every dialect, and every Responses-door stream request
actually streamed); the **Anthropic `ping` stays** decision (a named, accepted gap against the
published spec); and the **fallback-lane streams are billed** decision (`stream_options.include_usage`
unified onto the degraded/fallback path so a fallback stream bills tokens like a hot-path stream,
registered as `improvement`, money-affecting, owner sign-off).

No inventory row was edited; these are Appendix A/B text changes only, made so the design says what
the owner decided rather than what an earlier draft assumed.
