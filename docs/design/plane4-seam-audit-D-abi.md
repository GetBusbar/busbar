# Plane-4 Seam Audit D — Plane ABI & Registry

Status: **READ-ONLY ADVERSARIAL AUDIT.** No code changed. Scope: the plane/registry ABI surface
across which `busbar-core` and a plane communicate, judged against the load a **fourth, DUPLEX**
plane (`busbar-voice`, `docs/design/plane4-duplex-session.md`) would place on it.

**Pin.** All citations are against a worktree hard-reset to `e393b9e6` (`busbar 1.6.0 integration
base-fix: relocate profile_tests.rs into busbar-substrate`). Concurrent agents are repointing the
registry (proto/handlers) and hooks in the shared checkout; this audit deliberately reads the
pinned tree and judges **ABI SHAPE and dual-compile correctness**, not the in-flight import counts.

**The one-line verdict (key output).** *No — the ABI does not take a 4th duplex plane "with nothing
else changing," but every gap is an **append**, not a **reshape**.* The registration shape, the
dual-compile discipline, and the type-erasure boundaries are all correct and duplex-ready. What is
missing is six **additive** substrate seams (a `Transport::WebSocket` variant, a WS arrival kind, a
`SessionScope` wire-out, the D2 lease slots, a `run_gauntlet_session` sibling, the pump) — each of
which the tree has already **reserved** a witness for, and none of which forces an existing
signature to change. The "add one plane, nothing else changes" test **fails as literally stated**
(substrate must grow); the weaker, real invariant the design leans on — *no existing seam reshapes,
every duplex need is a trailing/`#[non_exhaustive]`/new-variant append* — **holds**, and is the
thing worth protecting.

---

## Seam 1 — The PROTOCOL REGISTRY singleton + register-into-substrate plugin shape

### (a) Today

The protocol registry singleton was **relocated down into `busbar-substrate`**
(`crates/busbar-substrate/src/proto.rs:1155`). The pieces:

- `struct Registry` (`proto.rs:1171`) — the decls plus the boot-time aggregates (`head_keys`,
  `streaming_content_types`, `codec_protocols`, `declared_verbs`), built once by `Registry::new`
  (`proto.rs:1198`), leaked to `'static`.
- Production singleton: `static REGISTRY: OnceLock<Registry>` (`proto.rs:1310`) + `static INSTALLED:
  OnceLock<Vec<&'static ProtocolDecl>>` (`proto.rs:1315`), both **in substrate**. `install_protocols`
  (`proto.rs:1328`) is the composition root's one write; `registry()` (`proto.rs:1388`) folds
  `merged_boot_decls(installed, &[])` on first read (`proto.rs:1367`).
- Reads: `detect_protocol` (`proto.rs:1465`), `residual_protocol_for_path` (`proto.rs:1476`),
  `residual_default_protocol` (`proto.rs:1489`), `known_protocols` (`proto.rs:1499`).
- The `decl_for` wrapper **stays in `busbar-core`** (`crates/busbar-core/src/proto/registry.rs:117`)
  — it is a thin `registry().decl(name)` over the substrate registry, kept in core only so its
  `registry()` acquire can seed core's own-test built-in tail before first read.

**Dual-compile correctness — this is the load-bearing finding, and it is CORRECT.** The witness
build compiles `busbar-core` twice (core-under-test + the plane crate's normal-dep core). Because the
singleton and all its test-support storage live in the **single-compiled** substrate:

- Production (`busbar-core/src/proto/registry.rs:100-104`): core simply *re-exports*
  `busbar_substrate::proto::{registry, detect_protocol, …}`. Both core copies name the **same**
  substrate symbol, so there is exactly **one** `REGISTRY` OnceLock in the process.
- Test (`proto.rs:1400-1454`): `TEST_REGISTRY_MEMO`, `TEST_REGISTERED_PROTOCOLS`, `INSTALLED`, and
  `TEST_BUILTINS_HOOK` are all substrate statics. Core-under-test seeds its built-in tail via
  `set_test_builtins(builtin_decls)` (`busbar-core/src/proto/registry.rs:108`); the plane crate's
  own core copy registers its `&DECL`s via `register_test_protocol` (`proto.rs:1114`). Both fold into
  the **one** substrate memo. The header at `proto.rs:1099-1102` states exactly this — the
  externally-linked crate's `&DECL` is now the **same** `ProtocolDecl` type, so no `#[path]`
  re-include of dialect sources into core is needed.

**Register-into-substrate is the correct plugin shape, and a new plane registers identically.** A
new protocol (voice's OpenAI-Realtime dialect) contributes a `&'static ProtocolDecl` with `codec:
None` (its IR is its own — `proto.rs:654-664`) through `install_protocols` (prod) /
`register_test_protocol` (test), exactly as MCP does. Core's `Registry::new` unions its
verbs/head-keys/codec-name without naming it (`proto.rs:1208-1221`); the name-collision assert
(`proto.rs:1230-1239`) is the only global invariant. No core edit is required to add the dialect.

### (b) With a 4th DUPLEX plane

The **registration** shape needs **nothing new** for the duplex plane: `codec: None` → `Some` at
the second dialect (Gemini Live) is the shipped MCP/A2A pattern, and `ProtocolDecl` is read-only data.
The registry is genuinely "add a row." This seam **passes** the "nothing else changes" test.

### (c) SURFACE-NOW

None for correctness. **One asymmetry worth a note (not a defect):** the *protocol* registry
singleton lives in substrate (single-compiled), but the *plane* registry singleton (`PLANES` /
`INSTALLED` OnceLocks) stays in **core** (`busbar-core/src/plane/registry.rs:304-307`). That is safe
today because (i) in production core is compiled once, and (ii) in the dual-compile witness the plane
axis routes through the substrate-single `register_test_plane` set (`plane/registry.rs:528`,
`TEST_REGISTERED` in substrate) — so both core copies still fold one substrate list. The divergence
is deliberate (`decl_for` and the core-test built-in seeding pin the plane list to core), but it
means the *protocol* axis and the *plane* axis have **different** singleton homes. If a future
refactor ever makes a plane's production `PLANES` read happen across a dual-compiled boundary
(it does not today), it would split. Vigilance-only; ranked at the bottom of the global list.

---

## Seam 2 — `ProtocolDecl` / `PlaneDecl` / `install_*` — the plane↔core ABI surface

### (a) Today

Two declaration types, both `pub` data structs a plane crate constructs and hands to an `install_*`
seam:

- `ProtocolDecl` (`crates/busbar-substrate/src/proto.rs:648`) — the **wire/dialect** vocabulary:
  `name`, `codec: Option<&'static dyn DialectCodec>`, `handler`, `verbs`, `head_keys`,
  `streaming_content_type`, `ingress_auth`, `egress_auth_headers`, the detection predicates
  (`claims`/`residual_claims`/`residual_default`), etc. Every field type is
  substrate/`busbar-api`/`axum`/`std` — it names zero core type (`proto.rs:641-647`).
- `PlaneDecl` (`crates/busbar-substrate/src/plane/registry.rs:180`) — the **plane** vocabulary:
  `key`, `fallback`, `config_section`, `scope_kinds`, `audit_kind`, `wire_format_names: fn() ->
  &'static [&'static str]`, `claims`, `admission`, `build`, `routes`, `admin_routes`, `hydrate`,
  `build_runtime`, `viewer`, `retain_verify_gates`, `lower_endpoint`, `default_section`. Handlers
  are neutral `fn(&dyn Any) -> …` shapes over substrate spec types (`PlaneRouteSpec`,
  `AdminRouteSpec`, `PlaneBootCtx`), never an `axum` extractor or `&App`.
- `install_protocols` (`proto.rs:1328`) / `install_planes` (`busbar-core/src/plane/registry.rs:319`)
  — the composition-root writes; `register_test_protocol`/`register_test_plane` the test twins.

The design's per-plane-IR thesis lives entirely in `ProtocolDecl::codec` being `Option`
(`proto.rs:654-664`): `Some` = shared superset IR (LLM's six dialects), `None` = the plane's IR is
its own (MCP, A2A, and voice-at-one-dialect). This field **already expresses** what a duplex plane
needs at the registration layer.

### (b) With a 4th DUPLEX plane

Here is the honest gap. `ProtocolDecl`/`PlaneDecl` are **request/response-shaped**: every field is
either boot-constant data or a `fn(&dyn Any) -> Vec<…>` that answers one synchronous question. A
duplex plane needs **none of these reshaped**, but it needs a *session-shaped* entry the current
decl vocabulary cannot name:

1. **Session-open return type.** `GauntletPlane::drive` returns `axum::response::Response`
   (`crates/busbar-substrate/src/plane_host/mod.rs:167`) and `run_gauntlet` (`plane_host/mod.rs:177`)
   returns the same. A 20-minute metered session is not one `Response`. The design's answer (B.5) is
   an **append-only sibling** `run_gauntlet_session(...) -> Result<SessionScope, Response>` beside the
   free fn + trait — **not present** at this pin (`grep run_gauntlet_session` = 0). Because
   `run_gauntlet` is a *free fn* and `GauntletPlane` a *trait*, the sibling is a pure add; no existing
   signature changes.
2. **Transport.** `Transport` = `{ Http, JsonRpc, HttpJson, Grpc, Stdio }`
   (`transport.rs:97-140`) — **no `WebSocket`** (verified). Adding the variant is additive; the real
   net-new work is the generic `Transport → { acceptor, dialer }` dispatch the module notes is absent
   (its only dispatch consumer is `upstream_wire()`; A2A variants are telemetry labels today).
3. **A duplex `install_*`?** **No new `install_*` is needed.** A duplex plane still contributes one
   `PlaneDecl` + one/two `ProtocolDecl`s through the existing seams; the duplex-ness is carried by the
   *transport*, the *arrival kind*, and the *session scope* — substrate axes, not decl fields. This is
   the correct split (design §7.1): the protocol is a plane concern, the duplex transport is a neutral
   substrate concern MCP and A2A also bind.

So: adding voice needs **no new decl field and no new `install_*`**, but it needs the substrate
session/transport seams (Seam 3/4 + the six adds) that the decls *reference* but do not *contain*.

### (c) SURFACE-NOW

- **`GauntletPlane::drive` / `run_gauntlet` returning `axum::Response` is the one shape that could
  foreclose duplex if "simplified."** As a free fn + trait it is append-safe; if a 1.6.0 cleanup
  inlined `run_gauntlet` or made the one-`Response` return the *only* session entry, the duplex
  sibling becomes a reshape. This is design lock **D3** and it is currently satisfied by structure,
  not by a test at this pin. Rank: **medium** (guard it).

---

## Seam 3 — `PlaneRecord` / `plane_slots` / `LlmBuildInput` — the type-erased `Any` boundaries

### (a) Today — three distinct `Any` crossings, each judged for the dual-compile TypeId trap

**(i) `plane_slots` — the per-generation runtime map.** A plane's runtime object is erased to
`Arc<dyn Any + Send + Sync>` and read back through `EngineHost::plane_slot(key)`
(`plane_host/mod.rs:412`) / `plane_slot_live` (`:418`) and the `PlaneSlots` trait (`:505`). The
companion key convention `runtime_slot_key("<key>:runtime")` (`plane_host/mod.rs:200`) is **interned
in substrate** — both `appbuild` (writer) and the plane (reader) pass their decl key and get the
**same** `&'static str`, so neither crate holds a literal. Downcast happens **inside the plane crate**
(same crate, same `TypeId`), so byte-identity survives the dual compile. **Correct.**

**(ii) `LlmBuildInput` — the neutral build carrier.** `crates/busbar-substrate/src/plane_host/
build_input.rs:279`. Its module header (`:10-21`) states the dual-compile rule explicitly and obeys
it: **every field is a neutral scalar** (`String`/number/`bool`/`Vec`/`HashMap` + the neutral
`busbar_api::UpstreamCreds`) — **no `busbar_core::` type** — and it lives in substrate (compiled
once) so its own `TypeId` is stable across the two core instances. `appbuild` populates it from
`RootCfg`; the plane downcasts `&dyn Any` → `&LlmBuildInput` in `busbar-llm`. **Correct, and the
model to copy.** *Note for the taxonomy:* at this pin it is still named `LlmBuildInput`, not
`PlaneBuildInput` — the rename the task references has **not** landed here.

**(iii) `PlaneRecord` — the durable row.** `crates/api/src/store.rs:894`, a `busbar_api` leaf. The
body is an **opaque `Vec<u8>`** (`:915`) the store never decodes; every retention/index column
(`kind`/`id`/`parent`/`seq`/`ts`/`disposition`) is a typed sidecar (`:895-911`). Because the plane
serializes its own row into `body` and the type is a single-compiled leaf, this crosses the `Any`
boundary as **bytes**, not a live type — the TypeId trap cannot bite. **Correct.**

**The neutral durable-handle engine already exists in substrate** —
`crates/busbar-substrate/src/plane/handle_engine.rs`. Its header (`:14-27`) is the strongest evidence
the dual-compile constraint was designed *in*: it is **non-generic and substrate-single-compiled**,
holding a plane's row **opaquely** as `Arc<dyn Any>` beside a neutral `HandleMeta` projection
(`handle_engine.rs:42`), *precisely because* "a GENERIC `Engine<PlaneRow>` monomorphised inside the
plane crate would carry a `TypeId` that diverges across the two core instances." This is the T1.8
"lift" the plan calls for — **already largely done** at this pin (the A2A taskstore re-home landed in
recent commits `f358cf18`/`62f361ad`/`9a14d3a6`).

### (b) With a 4th DUPLEX plane

A duplex plane's session record parks on the **same** substrate handle engine via `PlaneRecord` +
`DurableScope` (`plane_host/scope.rs:376`) — the design's "session-`<id>`" handle. Nothing here
reshapes: voice serializes its session row into `PlaneRecord.body`, keys it by `owner` for the
anti-enumeration scoped lookup, and rehydrates on boot exactly as A2A tasks do. The `plane_slots`
runtime slot and the `LlmBuildInput`-style neutral carrier are **directly reusable patterns** — voice
adds a `VoiceBuildInput` (or reuses the generic carrier) as a **new substrate DTO**, not a reshape.

The **one** duplex-specific `Any` crossing that is *new* is the **WS arrival payload**: the upgraded
socket handle rides `ArrivalCtx(Box<dyn Any + Send + Sync>)` (`ingress/arrival.rs:35`) and is
downcast inside the `ArrivalHost` impl. Per the dual-compile rule this payload type **must be
substrate-owned** or the downcast fails at runtime (not compile time) in the plane test binary. The
`ArrivalCtx` mechanism itself already exists and is used by path-model dialects — but its current
payloads are core types recovered core-side; a *plane*-downcast socket handle is the untested case.

### (c) SURFACE-NOW

- **The WS-arrival `ArrivalCtx(Box<dyn Any>)` payload is a live dual-compile TypeId trap** (`arrival
  .rs:35`). Unlike `LlmBuildInput`/`PlaneRecord`, an upgraded-socket handle is not obviously bytes;
  if voice boxes a plane-crate-owned or `busbar_core`-owned handle type, the downcast silently returns
  `None` across the two core instances — a **runtime-only** failure in the witness harness. The fix is
  cheap and known (make the payload a substrate-owned newtype), but it is a real trap and must be
  designed before P1 wires the arrival. Rank: **high** (the sharpest genuine hazard in this audit).
- **`LlmBuildInput` is still LLM-named** (`build_input.rs:279`). If it is to be the general duplex
  build carrier, the rename to a plane-neutral `PlaneBuildInput` should land before voice references
  it, or voice ships its own DTO and the "one carrier" story is quietly dropped. Rank: **low**
  (naming/taxonomy, not correctness).

---

## Seam 4 — `EngineHost` — the App-read capability seam (god-trait watch)

### (a) Today

`EngineHost` (`crates/busbar-substrate/src/plane_host/mod.rs:232`) is the `Arc<dyn>`-held,
`Send + Sync`, `async_trait` seam a plane calls instead of naming `App::…`. Method census at this pin
(**~32 methods** + one provided `run_gauntlet`): the clocks (`clock_now_secs/ms`), governance/admission
(`gate_decide`, `govern_admit_reason`, `gate_attached`, `governance_enabled`, `identity_admit`,
`identity_audience_binding`, `principal_standing`, `approval_redeem`, `ask_state_sealer`), the breaker
family (`breaker_admit`/`settle`/`record_success`/`record_signal`/`retry_after_secs`), metering
(`meter_charge`), telemetry (`request_finished`, `next_request_id`), audit (`audit_emit`,
`call_log_emit`, `call_log_emit_hostless`, `quarantine_settle`), the slot/pool reads (`plane_slot`,
`plane_slot_live`, `tool_pool_members`, `plane_pool_members`, `plane_audience_bound`,
`secret_resolver`, `agent_defs`, `card_sign`), and the two async pipeline drivers
(`identity_admit`, `synthesize_completion`).

**Is it a god-trait? — Growing, but principled so far.** The size is real (~32), but three properties
keep it from being an anti-pattern *today*:

1. **Every method is a single, named, pre-existing `App::…` read** with a one-line "Identical to
   `busbar_core::…`" contract (e.g. `next_request_id` `:329-332`, `plane_slot` `:408-412`,
   `secret_resolver` `:445-450`). It is a **1:1 relocation** of reaches that already existed, not new
   capability — so the count reflects how many distinct App-reads the plane path always had, surfaced
   honestly rather than hidden behind `&App`.
2. **The C-ABI is unaffected.** Each method mints the `!Send` `HostCtx` *internally*, drives one hot
   vtable slot synchronously, returns owned — so trait growth costs **zero** airlock version (the
   header `:16-23` states this). Growth here is not ABI-freezing the way a `PlaneHostVtable` slot is.
3. **No method is duplex-shaped**; there is no per-frame smell yet. The trait is data-plane
   request/response reads.

The smell to name honestly: it is a **flat, un-grouped** interface where the breaker family (5
methods) and the slot/pool family (5) already read as sub-traits waiting to be extracted, and the
purity work is actively appending to it (Bucket C in `1.6.0-llm-plane-abi-purity.md` re-types the
engine off `&App` onto this trait). Left flat, each new plane's each new App-read lands here.

### (b) With a 4th DUPLEX plane

A duplex plane's **per-frame** governance (design §3.2) reaches the **same existing** slots
per frame — `govern_admit_reason` against the open lease, `journal_append_scoped` for audit,
`meter_charge`/(future)`cost_settle` for metering, `gate_decide` for the mid-call tool loop — via the
`LiveHostFactory` per-frame re-mint (`plane_host/mod.rs:215`, already present). Critically, the
duplex plane does **not** need new `EngineHost` *methods* for the hot per-frame path; it needs the
two **hot-vtable** lease slots (D2, `cost_reserve`/`cost_settle`) which are a *different* seam
(`busbar-plugin`, `host.rs:535`) — **reserved, not present** (only the comment exists at this pin).
That separation is correct: the per-frame budget hard-stop is a C-ABI slot (it must drive `CostHold`
across the FFI seam), not a Rust trait method.

So a duplex plane fits `EngineHost` **without new methods** — the growth it forces is on the
*hot-vtable* (D2), not here. The trait's shape is duplex-adequate. The risk is only accretion: if
duplex convenience wrappers (`session_open`, `frame_meter`, …) get parked here instead of composed
from the existing slots + the D2 vtable, the trait crosses from "relocated reads" into "god."

### (c) SURFACE-NOW

- **`EngineHost` is not yet a god-trait but has no structural brake.** At ~32 flat methods with the
  breaker (5) and slot/pool (5) families already cohesive, the principled move is to split them into
  supertraits (`BreakerHost`, `PlaneSlotHost`) *before* voice and the purity-work Bucket-C re-type add
  more — so the "one trait, everything" default doesn't harden. Rank: **medium** (design hygiene; not
  blocking, but cheapest to do before two more consumers attach).
- **Watch that D2 lands on the hot-vtable, not as `EngineHost` methods.** The per-frame lease MUST be
  the `cost_reserve`/`cost_settle` FFI slots (`host.rs:535`), because only a C-ABI slot can hard-stop
  a live stream across the plane boundary; parking them as trait methods would put the budget cap on
  the wrong side of the airlock version discipline. Rank: **low** (the reserved comment already points
  the right way; this is a "don't drift" note).

---

## Ranked SURFACE-NOW (global)

1. **[HIGH] WS-arrival `ArrivalCtx(Box<dyn Any>)` payload is a dual-compile TypeId trap.** The
   upgraded-socket handle downcast (`ingress/arrival.rs:35`) fails at *runtime* in the witness harness
   unless the payload type is substrate-owned. The sharpest genuine hazard: it is the one new duplex
   `Any` crossing that is not obviously bytes, and the failure mode is silent. Design the payload type
   substrate-side before P1 wires the arrival.
2. **[MEDIUM] `GauntletPlane::drive`/`run_gauntlet` one-`Response` shape (D3) is guarded only by
   structure.** It is append-safe *as a free fn + trait* (`plane_host/mod.rs:167,177`), but a 1.6.0
   "simplification" that inlines it or makes the single-`Response` return the only session entry
   forecloses the duplex `run_gauntlet_session` sibling. Keep a witness test.
3. **[MEDIUM] `EngineHost` god-trait accretion has no structural brake.** ~32 flat methods with two
   already-cohesive families; split into supertraits before voice + Bucket-C add more. Not correctness
   — hygiene, cheapest now.
4. **[LOW] `LlmBuildInput` is LLM-named** (`build_input.rs:279`) if it is meant to be the general
   duplex build carrier — rename to `PlaneBuildInput` before voice references it, or accept a
   per-plane DTO and drop the "one carrier" framing.
5. **[LOW / VIGILANCE] Protocol vs plane registry singletons have different homes** — protocol in
   substrate (`proto.rs:1310`), plane in core (`busbar-core/src/plane/registry.rs:304`). Safe today
   (both fold one substrate list under dual-compile via the test seams); note it so no future refactor
   makes a plane's production `PLANES` read cross the dual-compiled boundary.

**Not surfaced (verified adequate):** `plane_slots` interning + downcast-in-plane (`plane_host/mod
.rs:200,412`); `LlmBuildInput` neutral-scalar discipline (`build_input.rs:10-21`); `PlaneRecord`
opaque-body leaf (`api/src/store.rs:894`); the non-generic substrate `handle_engine`
(`handle_engine.rs:14-27`); the D1 `WorkItem` carriers (`InboundKind::Stream`, `EmitKind::Unsolicited`,
`workitem.rs:31,47`); the reserved D2 comment (`host.rs:535`); `SessionScope`/`DurableScope`
`#[non_exhaustive]` stubs (`scope.rs:366,398`); `pipe_read`/`pipe_write` (`host.rs:474,476`);
`LiveHostFactory` (`plane_host/mod.rs:215`). Each is a correctly-reserved witness for an append.

## The verdict, restated

The ABI **does not** take a 4th duplex plane with "nothing else changing" — substrate must grow six
additive seams (WebSocket transport + dispatch, WS arrival kind, `SessionScope` wire-out, D2 lease
slots, `run_gauntlet_session`, the pump). But **not one existing signature must reshape**: the
registration shape (`ProtocolDecl`/`PlaneDecl`/`install_*`) is duplex-ready as data; the type-erasure
boundaries (`plane_slots`, `LlmBuildInput`, `PlaneRecord`, the handle engine) all correctly obey the
dual-compile TypeId rule; and every gap has a reserved witness already in the tree. The design's real
claim — *append, never reshape* — holds. The single thing that could turn an append into a reshape is
the WS-arrival `Any` payload (rank 1); the single thing that could foreclose the session entry is a
"simplification" of the one-`Response` gauntlet (rank 2). Guard those two and the seam is sound.
