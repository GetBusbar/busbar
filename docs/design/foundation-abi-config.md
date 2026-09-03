# busbar core foundation — one authored host surface, generated FFI, generic config (Tier B)

Status: DECISION-READY DESIGN. No implementation in this document. Base: `integration/transport-core`
(`565d6f7f`). Owner directive: Tier A + Tier B both land in 1.6 — **nothing deferred**. This spec folds
billing's validated FFI change into the SAME ABI evolution so there is ONE minor bump, not several.

This will be adversarially audited (Sonnet + Opus) before build. Every "cannot diverge" / "single-crate"
claim below is stated as a *mechanism with a proof obligation*, not an aspiration. Where a claim rests on
a compile-time or golden check, the check is named.

---

## 0. Executive summary

Core is *nearly* plane-agnostic: a plane is a `PlaneDecl` (`busbar-substrate/src/plane/registry.rs:180`)
plus a `ProtocolDecl`, registered from the binary. But three seams still make "add plane 5" a multi-crate,
hand-diverging diff:

1. **Two host surfaces that hand-diverge.** Every host capability exists twice — the C-ABI
   `PlaneHostVtable` (POD / `u64` / `extern "C-unwind"`, `busbar-plugin/src/hot/host.rs:434`) and the
   neutral `EngineHost` trait (Rust / `u128` / async, `busbar-substrate/src/plane_host/mod.rs:434`) —
   bridged by **hand-written shims** (`busbar-core/src/plane_host/cost_host.rs`). The two are kept in
   step by human diligence; the billing `u64`/`u128` bug was a *symptom* of that gap, not a one-off.
2. **The vtable is an append-per-plane pile** — 44 slots, minors 9→19, with sibling-doubling
   (`govern_admit` **and** `govern_admit_reason`; `breaker_admit` **and** `breaker_admit_reason`) forced
   by the freeze rule: a capability that needed one more field spawned a twin slot instead of growing.
3. **Config hard-bakes one plane's shape as core.** `RootCfg` names `providers`/`pools`/`groups`/
   `rate_card` directly (`busbar-core/src/config/mod.rs:425-443`); the generic `PlaneCfg` path
   (`busbar-substrate/src/plane/config.rs:36`) only fits **named-definition maps** (`tools:` / `agents:`).
   A plane whose config is *not* a named map — voice's `sessions:` / `topologies:` — has no home, so
   voice's `parse_section` / `default_section` are `None` (`busbar-voice/src/lib.rs:107,118`).

The result: adding voice touched 8–11 sites **outside** its own crate. This spec drives that toward ~1.

**The four moves, all in 1.6:**

- **A — One authored surface, generated FFI.** The capability-sliced neutral traits become the SINGLE
  authored source. The C-ABI `PlaneHostVtable` (typedefs, slots, `EMPTY`/`STUB`, the trait↔vtable shims,
  the layout golden seed) is **generated** from them by one macro. There is no second hand-authored
  artifact, so the two surfaces *cannot* diverge by hand. The `u64`↔`u128` money boundary is a generated
  per-arg projection, not a hand shim — the bug class is removed structurally.
- **B — Fold in billing's validated FFI change.** The append-only `Usage` POD keyed-unit tail
  (`units_ptr`/`units_len`, `__size` 80→96, `POD_VERSION` 2→3) rides the SAME `ABI_MINOR` 19→20 bump as
  A. One ABI evolution carries both. Size-based `field_present` negotiation (audited SOUND) keeps older
  dlopen peers working.
- **C — Finish the god-trait split + version slot payloads.** Planes depend on capability *slices*
  (`MeteringHost` / `BreakerHost` / `LanePoolHost` / …); `EngineHost` becomes the LLM-only union, not the
  currency handed to every plane. Future capability growth appends a FIELD to a slot's sized args/out POD
  (payload-versioning) instead of spawning a sibling slot — the sibling-doubling fix.
- **D — Generic third config-shape.** An opaque per-plane `parse_section` / `lower` / `default` /
  `validate` triad lets a NON-named-map plane declare its own config grammar without core hard-typing it
  and without forcing a named map. Voice's `sessions:` / `topologies:` land through it; core stops naming
  any plane's config shape; the neutrality gate auto-derives its plane list from the workspace so it
  cannot go stale (it is stale for voice today).

Net: **plane 5 = a new crate + register in ~1 place.** §7 walks each of voice's cross-crate sites and
shows how the revamp makes it automatic or in-crate.

---

## 1. Verified grounding (each claim checked against code)

| # | Audit claim | Verified at |
|---|---|---|
| 1 | C-ABI vtable is POD / `u64` / `extern "C-unwind"`, 44 `Option<Fn>` slots | `busbar-plugin/src/hot/host.rs:434-585` (struct); slot count = 44 (fields `govern_admit`…`cost_settle`) |
| 1 | Neutral `EngineHost` trait is Rust / `u128` / async, a super-trait over slices | `busbar-substrate/src/plane_host/mod.rs:434` (`trait EngineHost: BreakerHost + LanePoolHost + MeteringHost`); `identity_admit` is `async` (`:844`), money is `u128` (`MeteringHost::cost_settle`, `:407`) |
| 1 | Two hand-written shim sets over one registry | `busbar-core/src/plane_host/cost_host.rs` — FFI shim `cost_reserve`/`cost_settle` (`:131,:174`, `u64`) AND neutral-seam `reserve_lease`/`settle_lease` (`:78,:98`, `u128`) over the SAME `LEASES` registry (`:41`); the `u64`→`u128` widen is hand-written (`:150,:154`, `settle_lease(id, u128::from(settle_nanos))` at `:61`) |
| 1 | The billing bug is a `u64`/`u128` boundary symptom | money crosses the frozen slot as `u64` and is hand-widened to `CostAmount(u128)` per shim (`cost_host.rs:13-18` doc + `:150`); nothing enforces the widen exists |
| 2 | 44-slot append pile, minors 9→19 | `host.rs:482-581` — APPENDED markers at minor-9 (`:522`), minor-10 (`:543`), minor-12 (`:550`), minor-17 (`:558`), minor-18 (`:565`), minor-19 (`:572`); `ABI_MINOR = 19` (`busbar-plugin/src/lib.rs:72`) |
| 2 | Sibling-doubling forced by freeze | `govern_admit` (`:443`) **+** `govern_admit_reason` (`:507`); `breaker_admit` (`:447`) **+** `breaker_admit_reason` (`:493`); `approval_redeem` (`:475`) **+** `approval_redeem_q` (`:501`) |
| 3 | `EngineHost` is a ~50-method god-trait post-split | `plane_host/mod.rs:434-966` — ~50 methods from `clock_now_secs` (`:437`) to `run_gauntlet` (`:959`), atop the three slices |
| 3 | Voice binds the narrow `MeteringHost` slice, routes around the union | `busbar-voice/src/runtime/metering.rs:188` (`HostMeteringPort { host: Arc<dyn MeteringHost> }`), doc `:184-187` ("the narrow lease slice of `EngineHost`") |
| 4 | Config hard-bakes LLM as core | `busbar-core/src/config/mod.rs:425` `providers`, `:427` `pools`, `:441` `groups`, `:443` `rate_card` are named `RootCfg` fields |
| 4 | Generic `PlaneCfg` only fits named-definition maps | `busbar-substrate/src/plane/config.rs:36-91` — the trait is `contains_def` / `def_names` / `entry_document` / `insert_def` / `validate_registry`: a registry of NAMED entries. No non-map shape |
| 4 | Voice's non-map config has no home | `busbar-voice/src/lib.rs:107` `parse_section: None`, `:118` `default_section: None`, `:113-114` doc ("need the plane's config-section grammar … outside this crate's scope") |
| 5 | Neutrality is enforced by SEVERAL grep gates, plane lists HARD-CODED per script, stale for voice | `scripts/plane-purity-lint.sh:110-111` `NEUTRAL_ROOTS`/`PLANE_ROOTS` list `llm/mcp/a2a` (no voice), `:205,:212,:236` banned path/symbol/KEY tokens `llm/mcp/a2a`; `scripts/plane-grep-gate.sh:92-96` same three; `scripts/plane-roots.sh` callers pass literal `mcp a2a`. `scripts/plane-abi-neutrality.sh:33` DOES already ban `voice/realtime/audio` (the one auto-consistent gate). `busbar-voice` IS a workspace member (`Cargo.toml:10`) yet absent from the code-side gates |

The billing FFI change folded in (§4) is the one authored in `docs/design/billing-unified.md §5.2` —
`hot::Usage` tail `units_ptr`@80 / `units_len`@88, `__size` 80→96, `POD_VERSION` 2→3, `ABI_MINOR` 19→20,
`abi-layout.golden` reseed. Its size-based negotiation is the SAME `field_present` /
`read_sized_field!` mechanism already shipping (`busbar-plugin/src/lib.rs:150,164`), audited SOUND
(borrowed buffer; a pre-minor-20 peer advertises `size==80`, so `units_*` reads as absent, never garbage).

---

## 2. Non-negotiable invariants (the frozen spine, untouched)

Everything below is preserved byte-for-byte; the revamp is a *build-mechanism and dependency* change, not
a wire change beyond the one billing tail.

- **Frozen preamble.** `AbiPreamble` + the leading `size`/`version` pair on `PlaneHostVtable`
  (`host.rs:435-440`) and on every POD are untouched. `check_preamble` still accepts an older minor
  (append-only compat, `lib.rs` doc `:86`).
- **Append-only / sized-field discipline.** New vtable slots append at the TAIL; new POD fields append at
  the TAIL; both guarded by `field_present` (`lib.rs:150`). No existing slot or field is reshaped or
  reordered. The layout golden (`crates/busbar-plugin/tests/golden/abi-layout.golden`) is the guard; it is
  *reseeded* (never edited in place) on an append.
- **init-only-on-Ok out-params.** Every large result is written into a caller `&mut MaybeUninit<Out>`
  INSIDE the callee `catch_unwind`, published only on `StatusClass::Ok` (`busbar_plugin::write_out`).
- **No `Vec` return on a hot call.** Variable-length results use the `egress_poll` copy-out pattern
  (`buf`, `buf_cap`, `out_written`).
- **plane-purity BACKWARDS 0.** No neutral crate (`busbar-core` / `busbar-substrate` / `busbar-plugin`)
  names a plane noun; no plane crate reaches back into core internals. The generated code lives in neutral
  crates and MUST contain no plane noun (§3.6).
- **Back-compat.** Existing dlopen plugins at an older `ABI_MINOR` keep working via the audited size-based
  negotiation. Existing `config.yaml` files parse byte-identically (§5.4).

---

## 3. Move A — one authored host surface → generated FFI

### 3.1 The problem, precisely

A capability lives in FOUR hand-maintained places today, and a human keeps them consistent:

1. the neutral trait method (rich Rust: `u128`, `&str`, `Arc<dyn …>`, maybe `async`) — the authored intent;
2. the C-ABI `extern "C-unwind"` fn-pointer typedef + the `Option<…Fn>` vtable slot (POD, `u64`);
3. the vtable's `EMPTY` and `STUB` entries + the `stub::` fixture fn (`host.rs:602,656,711`);
4. the trait↔vtable **shim** that recovers `HostState` from `HostCtx`, `catch_unwind`s, widens `u64`→`u128`,
   and writes the out-param (`cost_host.rs`).

Nothing *forces* (2) to match (1). The `u64`/`u128` billing bug lived exactly in the gap between (1)'s
`u128` and (2)'s `u64`, in a hand-written widen at (4).

### 3.2 The fix: ONE authored artifact, everything else generated

Make the **capability-sliced neutral traits the single authored source of truth**, annotated with an ABI
projection, and **generate** (2), (3), (4), and the golden seed from them. A macro — call it
`host_abi! { … }` (an attribute macro over the slice-trait module, or a declarative registry the traits
are declared through) — takes each capability's neutral method plus a per-arg / per-return **wire
projection** and emits:

- the `extern "C-unwind"` fn-pointer **typedef**;
- the `Option<…Fn>` **vtable slot** (in declaration order, at the tail);
- the `EMPTY` (`None`) and `STUB` (`unimplemented!()`) **entries** + the `stub::` fixture fn;
- the **shim**: recover `HostState`, `catch_unwind`, project each wire arg → rich arg, call the trait
  method on the live `EngineHostImpl`, project the rich result → wire out-param, `write_out` on `Ok`,
  `StatusClass::Fault` on a caught panic;
- the **layout-golden fragment** for that slot (offset + wire signature), machine-diffed against the
  checked-in golden.

Because (2)/(3)/(4) are now *pure functions of (1)*, there is **no second artifact to hand-diverge**. The
audit obligation "keep the vtable in step with the trait" becomes vacuous: they are one source.

### 3.3 The wire projection — where `u64`↔`u128` is GENERATED, not hand-shimmed

Each capability method carries a projection annotation per argument and per return field. The relevant
ones for the money boundary:

```
#[host_abi(slot = "cost_settle", minor = 19)]
fn cost_settle(
    &self,
    lease: CostLeaseId,                       // #[wire(pod)]      → CostLeaseId (already POD)
    #[wire(u64, widen = u128)] exact_nanos: u128,  // wire u64  ⇒  rich u128
    breakdown: OpaqueBytes<'_>,               // #[wire(ptr_len)]  → (breakdown_ptr, breakdown_len)
) -> Option<SettleOutcome>;                   // #[wire(out = CostSettleOut, none = Refused)]
```

From `#[wire(u64, widen = u128)]` the macro emits, in the generated shim, EXACTLY the widen the hand-shim
writes today (`u128::from(settle_nanos)`, `cost_host.rs:61`) — but now it is emitted from the annotation,
so a capability CANNOT declare `u128` on the trait and silently keep a `u64`-only path on the wire: the
projection is the single place the width is stated, and it is stated once. The `~$18.4B`-per-lease
rationale (a per-lease `u64` amount cannot overflow a single session) stays a documented property of the
*annotation*, checked by a range assertion the macro can emit, not a comment on a hand shim.

`widen` is a **lossless up-cast** (`u64 → u128`) on the inbound leg; there is deliberately **no narrowing
projection** — a rich value that does not fit the wire type is a *compile-time* rejection of the
annotation, so no capability can ship a lossy money boundary.

### 3.4 How the 44 existing slots map

The macro reproduces the CURRENT `PlaneHostVtable` field-for-field, in the current order, with the current
signatures — it is a *refactor to generated form*, not a reshape. Concretely:

- The 44 slots become 44 macro invocations (or 44 rows in the declarative registry), one per capability,
  each tagged with its historical `minor` (9…19) so the generated tail order is byte-identical.
- The generated struct's `size`/`version`/`EMPTY`/`STUB` are identical to today's
  (`host.rs:602-704`); the layout golden is *unchanged* by move A alone (the wire layout does not move —
  only the *authoring* of it moves). The single wire change in this evolution is billing's tail (§4).
- The six sibling pairs (§6) stay as two slots each **for back-compat** (they are frozen), but they are
  documented as the last hand-siblinged capabilities: all FUTURE growth uses payload-versioning (§6).

### 3.5 The lockstep proof (compile-time + golden, not prose)

Three independent guards, any one of which fails RED on divergence:

1. **Structural: there is one input.** The vtable is macro output of the trait module. A capability
   present in the trait but absent from the vtable (or vice-versa) is not *possible to express* — the
   macro emits both from one declaration. This is the primary, structural guarantee.
2. **Compile-time slot table.** The macro also emits a `const SLOTS: [SlotSig; N]` for the trait-projection
   AND reads `size_of::<PlaneHostVtable>()`; a `const _: () = assert!(generated_size == size_of::<…>())`
   plus a per-slot `const` offset check makes a mismatch a *build* error, not a test failure. (This
   generalizes the existing `assert_send_sync::<PlaneHostVtable>()` compile fixture at `host.rs:593`.)
3. **Golden lockstep.** The layout golden is *generated* from the same declaration and diffed against the
   checked-in `abi-layout.golden` by `layout_golden.rs` (billing-unified.md §5.2 names this test). An
   accidental reshape or reorder moves an offset and reds the golden. Reseed is a reviewed, deliberate act.

A fourth, belt-and-braces guard: the existing `STUB` vtable (`host.rs:656`) — now generated — is the
type-level proof that every generated signature is a real, well-typed `extern "C-unwind"` fn-pointer.

### 3.6 Neutrality of the generated code

The macro input names only NEUTRAL capability nouns (the taxonomy in
`docs/design/1.6.0-plane-abi-taxonomy.md`: govern / meter / breaker / verify / egress / journal /
nested-dispatch / work-handle / trust / metrics / clock / auth / gate / identity / cost-lease). The
generated output lives in `busbar-plugin` (the vtable) and `busbar-core`/`busbar-substrate` (the shims) —
all neutral crates — and contains no plane noun. The plane-purity gate (§7, item I) runs over the crate
INCLUDING generated code, so a plane-named capability would trip it.

---

## 4. Move B — fold in billing's validated `Usage` keyed-unit tail

This is the ONLY wire change in the evolution, and it rides the SAME `ABI_MINOR` bump as move A.

### 4.1 The change (from `docs/design/billing-unified.md §5.2`, audited SOUND)

Append two fields to `hot::Usage` (`busbar-plugin/src/hot/pod.rs:667`), after `provider_len`:

```
pub units_ptr: *const u8,   // golden offset 80  — BORROWED, packed keyed units {key → count}
pub units_len: usize,       // golden offset 88  → new __size = 96
```

- `POD_VERSION` 2→3; `ABI_MINOR` 19→20 (`busbar-plugin/src/lib.rs:72`).
- Layout golden reseeds `Usage.units_ptr=80`, `Usage.units_len=88`, `Usage.__size=96`.
- Semantics: `units_len > 0` ⇒ the host decodes the packed keyed units and prices via the rate card
  (`govern.rs::charge`); `units_len == 0` ⇒ byte-identical to today (single scalar). Borrowed buffer,
  never owned — the plane owns the bytes for the call's duration only.

### 4.2 Why one ABI evolution carries both

Move A changes *how the vtable is authored* (no wire change). Move B appends *one POD tail* (a wire
change). Shipping them under one `ABI_MINOR` 19→20 means: exactly one golden reseed, one preamble bump,
one back-compat negotiation story to audit — not "several ABI evolutions" the meta-audit warned against.
The generated shim for `meter_charge` (move A) reads the new tail through `read_sized_field!(usage,
Usage, units_len)` (move B), so the two moves *compose* in one generated call site rather than fighting.

### 4.3 Back-compat (the audited negotiation)

A pre-minor-20 dlopen plugin advertises `Usage.size == 80`. The host's generated `meter_charge` shim reads
`units_len` via `field_present(size, offset_of!(units_len)+size_of)` (`lib.rs:150`) → `false` → treats the
plane as sending no keyed units → prices exactly as today. A newer plugin sends `size == 96` and its units
are read. No plane recompilation is required for an old plugin to keep working. This is the SAME mechanism
already shipping for the minor-5 attribution tail (`pod.rs:682-694`), so it is not new surface — it is the
proven pattern applied once more.

---

## 5. Move D — the generic third config-shape

(Move C, the trait split + payload-versioning, is §6; move D is presented first because it is the config
half of "plane 5 is single-crate," and the sibling-doubling fix reads more cleanly after it.)

### 5.1 The problem, precisely

Core's config knows exactly TWO shapes:

- **LLM-shaped, hard-typed as core:** `RootCfg.providers` / `models` / `pools` / `groups` / `rate_card`
  (`config/mod.rs:425-443`) — one plane's grammar, named directly in a neutral crate.
- **Named-definition map, generic:** `PlaneCfg` (`busbar-substrate/src/plane/config.rs:36`) — a registry
  of NAMED entries (`tools:` servers, `agents:` agents). Its whole vocabulary is `contains_def` /
  `def_names` / `entry_document` / `insert_def` / `validate_registry` (`:46-71`): it *presumes* a map of
  named things.

Voice's config is neither. `sessions:` / `topologies:` are not a map of named registrations the admin API
creates/deletes; they are a plane-specific grammar (a small closed set of typed blocks). So voice cannot
implement `PlaneCfg` meaningfully, and its `parse_section` / `default_section` are `None`
(`busbar-voice/src/lib.rs:107,118`) — its config has nowhere to land.

### 5.2 The fix: an opaque per-plane config triad on `PlaneDecl`

Add a THIRD, fully opaque config path beside the two existing `PlaneDecl` config hooks
(`registry.rs:450` `parse_section`, `:517` `default_section`). It carries a plane's config through core
WITHOUT core naming its shape and WITHOUT presuming a named map:

```
// on PlaneDecl (busbar-substrate/src/plane/registry.rs)
pub opaque_config: Option<OpaqueConfigVtable>,

pub struct OpaqueConfigVtable {
    /// PARSE the plane's top-level section from a positionless serde value into an opaque, type-erased
    /// parsed config. No map assumption: the plane deserializes whatever grammar it declares.
    pub parse:    fn(&serde_yaml::Value) -> Result<Box<dyn OpaqueSectionCfg>, String>,
    /// DEFAULT (section absent): the plane's own Default, byte-identical to a parse of an empty doc.
    pub default:  fn() -> Box<dyn OpaqueSectionCfg>,
    /// VALIDATE the parsed config at resolve (cross-field rules the plane owns). Errs into the resolve
    /// error list verbatim, exactly as lower_endpoint does today.
    pub validate: fn(&dyn OpaqueSectionCfg) -> Result<(), String>,
    /// LOWER the parsed config into the plane's validated runtime resource, type-erased as Arc<dyn Any>
    /// — the value the plane's build_runtime downcasts back. Mirrors lower_endpoint (:469).
    pub lower:    fn(&dyn OpaqueSectionCfg) -> Result<Arc<dyn Any + Send + Sync>, String>,
}
```

`OpaqueSectionCfg` is the MINIMAL neutral contract — the intersection of what core actually needs from an
*unknown* section, and nothing the named-map path presumes:

```
pub trait OpaqueSectionCfg: Any + Send + Sync + Debug {
    fn secret_refs(&self) -> Vec<(String, &busbar_api::SecretRef)>; // credential enumeration (as PlaneCfg)
    fn is_present(&self) -> bool;                                    // deletion-gate leg (as PlaneCfg)
    fn as_any(&self) -> &dyn Any;                                    // downcast home
    fn clone_box(&self) -> Box<dyn OpaqueSectionCfg>;               // RootCfg/DeployCfg are Clone
    fn clone_arc_any(&self) -> Arc<dyn Any + Send + Sync>;         // App's type-erased slot
}
```

Note what is ABSENT versus `PlaneCfg`: no `contains_def` / `def_names` / `entry_document` / `insert_def` /
`validate_registry` / `container_gates`. Those are exactly the named-map-shaped methods a non-map plane
cannot honour. `OpaqueSectionCfg` keeps only the four genuinely-neutral needs (secrets, presence,
downcast, clone). A plane with hook gates still gets them: `container_gates` stays a named-map concept;
an opaque-config plane that wants request-admission gates uses the neutral `gate_decide` host capability
(`host.rs:385`) at runtime rather than declaring container gates at config time.

### 5.3 How voice's `sessions:` / `topologies:` land through it

Voice declares, IN ITS OWN CRATE:

- `parse`: `serde_yaml::from_value::<VoiceCfg>` where `VoiceCfg { sessions: SessionsCfg, topologies:
  TopologiesCfg }` is voice's own type — core never names it.
- `default`: `VoiceCfg::default()` (byte-identical to a parse of `{}`), replacing the `None` at
  `lib.rs:118`.
- `validate`: voice's cross-field rules (e.g. a topology references a defined session) — errs into the
  resolve error list.
- `lower`: builds voice's validated runtime resource, the `Arc<dyn Any>` its `build_runtime`
  (`lib.rs:115`, already wired to `VOICE_BUILD_RUNTIME`) downcasts back.

`RootCfg` gains ONE neutral, type-erased slot for opaque plane sections — reusing the existing
`endpoint_resources: HashMap<&'static str, Arc<dyn Any + Send + Sync>>` pattern already on `RootCfg`
(`config/mod.rs:403`), keyed by the plane's `config_section`. Core stores and threads it without naming
`VoiceCfg`. The plane downcasts it back via `as_any` — the SAME type-erased-slot discipline `PlaneCfg`
and `PlaneEndpointCfg` already use (`config.rs:82,115`).

### 5.4 Core stops naming plane config shapes; existing files parse identically

- The LLM plane's `providers` / `models` / `pools` / `groups` / `rate_card` are, in the Tier-A LLM-purity
  plan (`docs/design/1.6.0-llm-plane-abi-purity.md` Bucket B), the LLM plane's OWN runtime-config family,
  built from a neutral `LlmBuildInput`. This spec's config triad is the mechanism that lets those land as
  an opaque plane section too, so `RootCfg` need not name them as core fields. (Sequencing: the triad
  ships in 1.6; migrating the LLM fields onto it is the Tier-A LLM-purity work that runs alongside. The
  triad does not *require* moving them to be sound — it removes the *reason* core must name them.)
- **Existing `config.yaml` files parse byte-identically.** The `mcp:` / `tools:` / `agents:` wire keys and
  their named-map grammar are untouched (`PlaneCfg` path unchanged). The config-stability snapshot gate
  (`config-schema.snapshot.json`, referenced by the purity lint at `:221`) guards this: a section added
  through the opaque triad is additive; no existing key changes shape. The purity lint's carve-out for the
  frozen `mcp:` wire key (`plane-purity-lint.sh:49-54`) is unaffected.

### 5.5 The neutrality gate auto-derives its plane list (config auto-registers)

Today `default_plane_sections` (`config.rs:262`) already folds `test_registered_planes()` +
a frozen 4-name `NAMED_MAP_SECTIONS` tail — so a *registered* plane's section enters the hook-reference
grammar automatically. The gap is the **grep gates**: SEVERAL scripts hard-code the plane list, each
independently — `scripts/plane-purity-lint.sh:110-111,205,212,236`, `scripts/plane-grep-gate.sh:92-96`,
and the `plane_roots_resolve mcp a2a` callers (`response-header-lint.sh:136`, `structure-lint.sh:95`,
`blocking-ffi-lint.sh:335`, `settings-leak-lint.sh:218` via `scripts/plane-roots.sh`) — all list
`llm|mcp|a2a` and are **stale for voice**. Only `scripts/plane-abi-neutrality.sh:33` already lists
`voice/realtime/audio` (proving the pattern: it is self-checked against an identical `mandated` set at
`:36`). The fix (detailed in §7 item I) is to make ALL these gates derive their plane list from ONE source
— the workspace `members` matching `crates/busbar-*` that carry a `PlaneDecl`, plus each plane crate's
declared `key`/`config_section` — via a shared `plane-roots.sh`-style helper, so a new plane crate is
guarded the moment it is a workspace member, with zero per-script edit. This closes the loop: config
auto-registers (already true) AND every gate that enforces neutrality auto-registers (new). The one gate
that already works this way (`plane-abi-neutrality.sh`) is the existence proof.

---

## 6. Move C — finish the god-trait split + version slot payloads

### 6.1 Capability slices — planes depend on slices, not the union

Today three slices exist (`BreakerHost` `:265`, `LanePoolHost` `:314`, `MeteringHost` `:388`) and
`EngineHost` (`:434`) is their super-trait PLUS ~50 more methods. Voice already proves the target: it
binds `Arc<dyn MeteringHost>` (`metering.rs:188`), not `Arc<dyn EngineHost>`. The move: **`EngineHost`
becomes the LLM-only union**, and every non-LLM capability lives in a named slice a plane depends on
directly. A plane's `build_runtime` receives (or reaches, via `plane_slots`) only the slices it named — a
voice plane never sees the LLM union.

The ~50 residual `EngineHost` methods partition into slices as follows (enumerated so the auditors can
check the split is total and each method has exactly one home):

| Slice | Methods (from `plane_host/mod.rs`) |
|---|---|
| `ClockHost` | `clock_now_secs` (`:437`), `clock_now_ms` (`:441`) |
| `MeteringHost` (exists) | `cost_reserve` (`:395`), `cost_settle` (`:407`), `cost_settled` (`:411`), `cost_close` (`:416`); **+** `meter_charge` (`:485`), `meter_ledger` (`:756`), `meter_series` (`:774`), `cost` (`:746`) |
| `BreakerHost` (exists) | `breaker_admit` (`:270`), `breaker_settle` (`:281`), `breaker_record_success` (`:291`), `breaker_record_signal` (`:296`), `breaker_retry_after_secs` (`:302`) |
| `LanePoolHost` (exists) | `lane_store` (`:323`), `default_probe_interval_secs` (`:332`), `default_probe_timeout_secs` (`:337`), `tool_pool_members` (`:343`), `plane_pool_members` (`:349`); **+** `pool_label` (`:544`), `pool_rewrites` (`:616`) |
| `GovernHost` | `govern_admit_reason` (`:466`), `governance_enabled` (`:592`), `governance` (`:741`), `admission_door` (`:794`), `rate_headroom` (`:699`), `budget_state` (`:717`), `default_max_tokens` (`:728`), `reasoning_effort_budgets` (`:733`) |
| `TrustHost` | `quarantine_settle` (`:478`), `approval_redeem` (`:491`), `principal_standing` (`:855`) |
| `TelemetryHost` | `request_finished` (`:502`), `telemetry_upstream_attempt` (`:517`), `telemetry_upstream_failure` (`:523`), `telemetry_breaker_trip` (`:528`), `telemetry_failover` (`:532`), `telemetry_translation` (`:537`) |
| `GateHost` | `gate_decide` (`:452`), `pool_gates` (`:663`), `global_gates` (`:668`), `pool_policy` (`:673`), `gate_attached` (`:886`), `caller_in_hook_groups` (`:602`), `any_content_hook` (`:638`), `rewrite_hooks` (`:627`), `tap_hooks` (`:644`), `tap_hooks_response` (`:649`), `tap_hooks_routing` (`:653`), `tap_hooks_candidate` (`:658`), `requested_signals` (`:679`) |
| `IdentityHost` | `identity_admit` (`:844`, the one `async` method), `identity_audience_binding` (`:834`), `verify_token_test` (`:688`), `plane_audience_bound` (`:893`) |
| `EgressGuardHost` | `destination_guard` (`:550`), `secret_resolver` (`:900`) |
| `SigningHost` | `card_sign` (`:907`), `ask_state_sealer` (`:866`) |
| `AuditHost` | `audit_emit` (`:807`), `audit_record` (`:817`), `call_log_emit` (`:823`), `call_log_emit_hostless` (`:828`) |
| `RequestHost` | `next_request_id` (`:496`), `arrival_envelope_dialect` (`:922`), `arrival_fallback_error` (`:928`) |
| `PlaneSlotHost` | `plane_slot` (`:874`), `plane_slot_live` (`:880`), `agent_defs` (`:913`) |
| `EngineHost` (residual LLM union) | `finish_admitted` (`:564`), `finish_rejected` (`:580`), `synthesize_completion` (`:947`, async), `run_gauntlet` (`:959`, async) — the LLM/gauntlet-specific reach; keeps the slice super-traits it genuinely needs |

`EngineHostImpl` (core's live impl over `App`) implements ALL slices, so a full production host binds any
slice; a test binds only the tiny slice it mocks (the pattern `HostMeteringPort::new` already exploits,
`metering.rs:196`). The compile fixture at `:973` (`_assert_engine_host_brakes`) generalizes to assert
`EngineHost: <every slice>` so the union stays a super-trait of the parts.

**Neutrality note:** these slice names are neutral capability nouns; no `voice`/`mcp`/`llm` in any of them.
The residual `EngineHost` methods (`synthesize_completion`, `run_gauntlet`) are LLM-shaped *behaviour* but
neutrally *named* — and they stay on the union precisely so a non-LLM plane never depends on them.

### 6.2 Sibling-doubling fix — version the slot PAYLOAD

The freeze rule turned "grow a capability by one field" into "spawn a twin slot": `govern_admit` +
`govern_admit_reason`, `breaker_admit` + `breaker_admit_reason`, `approval_redeem` + `approval_redeem_q`.
Each twin exists only because its predecessor's args/out had no room to grow.

**The discipline going forward:** every slot takes ONE sized, append-only **args POD** and (for a large
result) writes ONE sized, append-only **out POD**. A capability grows a field by **appending it to its
args/out POD** — guarded by `field_present` — and bumping `ABI_MINOR`, NEVER by adding a sibling slot.
A newer host reads the appended arg via `read_sized_field!`; an older plane's smaller POD reads the field
as absent and the host falls back to the prior behaviour. This is the exact mechanism §4 uses for the
`Usage` tail — now made the *default* way any capability evolves.

Worked example (how the twin would NOT have been born): `breaker_admit_reason` (`host.rs:57,493`) added a
`*mut MaybeUninit<AdmitRefusal>` out-param to carry a refusal reason. Under payload-versioning,
`breaker_admit` would take an `AdmitArgs` POD and write an `AdmitOut` POD; the refusal reason is an
appended field on `AdmitOut`, read via `field_present`. A pre-refusal plane advertises the smaller
`AdmitOut` and never reads it; a newer plane advertises the larger one and does. One slot, not two.

**Retrofit stance (back-compat):** the six existing sibling slots stay frozen (removing them breaks shipped
plugins). They are the LAST hand-siblinged capabilities. The generated surface (§3) documents each as
"superseded pattern"; the layout golden freezes them; all NEW capabilities added in 1.6 and after use the
args/out-POD form. This is provable: a CI check (extending the layout golden diff) asserts no NEW slot is
added that is a `_reason`/`_q`-style twin of an existing slot — a new capability must either be genuinely
new or an appended field on an existing POD.

---

## 7. Payoff — the plane-5 tax removed, site by site

This section is not a fifth move; it is the *consequence* of moves A–D, measured against voice's real
cross-crate footprint.

Voice's cross-crate footprint, and how the revamp makes each site automatic or in-crate. Target: adding a
plane = a new crate + ONE registration push.

(Sites confirmed by an Explore sweep of the binary + scripts + manifests. Voice is a *skeleton* today, so
it has only paid site A of the list below; the rest is the footprint a FULLY-landed plane pays — which is
what "single-crate diff" must eliminate.)

| # | Site a landed plane must touch (outside its crate) | Where | After the revamp |
|---|---|---|---|
| A | Root `Cargo.toml` workspace member line | `Cargo.toml:3-30` (voice at `:10`) | Inherent build edge — a new crate must be a workspace member. Kept (see J). One line. |
| B | Push `&PLANE_DECL` into the plane registry | `main.rs:658-675` (`register_planes`) | **The one logic registration.** `installed.push(&busbar_voice::PLANE_DECL)`. C/D/L fold into this. |
| C | Extend the protocol `DECLS` / `PROTO_DECL` list | `main.rs:591-618` (`register_protocols`) | Folded into (B): `PlaneDecl` gains `protocols: &[&ProtocolDecl]`; the registrar installs them. The plane declares protocols once, on its decl. |
| D | Extend `DIAGNOSTICS` | `main.rs:690-696` (`register_diagnostics`) | Folded into (B): `PlaneDecl.diagnostics: &[…]`, installed by the registrar. |
| E | Config had no home for non-map config (`parse_section`/`default_section` = `None`) | `busbar-voice/src/lib.rs:107,118` | **In-crate** via the opaque config triad (§5): the plane sets `opaque_config` on its own decl; core stores the type-erased result. No core edit. |
| F | `RootCfg` would need a named field for the plane's config | `config/mod.rs:425-443` | **Never.** The opaque section lands in the existing `Arc<dyn Any>` slot keyed by `config_section` (§5.3). Core names nothing. |
| G | Host capabilities the plane needs (e.g. metering lease) risked a new vtable slot | `host.rs` (44-slot pile) | **No new slot** for a plane reusing existing capabilities — it depends on the trait *slice* (§6.1), statically dispatched; the FFI slot already exists and is generated. A genuinely-new capability is a generated append (§3), still not per-plane bespoke. |
| H | Cargo feature knobs across THREE manifests | `crates/busbar/Cargo.toml:37-91`, `crates/busbar-core/Cargo.toml:130-224`, `crates/busbar-substrate/Cargo.toml:180-181` (`plane-X` + `default` + forwards + dep edges) | The single largest residual. Reduced to ONE feature per plane by making the `plane-<key>` feature a mechanical forward (`busbar-core/plane-<key> → busbar-substrate/plane-<key> → capability`); the dep edge (A) plus one `plane-<key>=[]` line per manifest. A convention (feature name == `PlaneDecl.key`) lets the deletion/purity gates check the wiring is complete rather than requiring bespoke logic. Honest residual: ~1 line per manifest (see R6). |
| I | Neutrality/purity gates did not know the plane (stale for voice) | `plane-purity-lint.sh:110-236`, `plane-grep-gate.sh:92-119`, `plane-roots.sh` callers | **Auto-derives** from the workspace member list + each `PlaneDecl.key`/`config_section` via a shared helper (§5.5). `plane-abi-neutrality.sh` already works this way — generalize it to the other gates. Zero per-script edit. |
| J | Section list for hook-reference grammar | `config.rs:262` + `main.rs:735` (`install_plane_sections`) | **Already automatic** — folds registered planes. Once (B) registers the decl, the section is in the grammar. No edit. |
| K | Admin envelope registration | `main.rs:744` (`install_plane_admin_envelope`) | Folds off the plane registry (driven by `PlaneDecl.admin_noun`, `registry.rs:218`). Collapses into (B). |
| L | CI deletion-test matrix has no plane leg | `.github/workflows/ci.yml` deletion-test-matrix; `scripts/plane-delete-test.sh:76` (`PLANES="llm mcp a2a voice"`) | Derive the matrix leg + `PLANES` from the workspace member list (same source as I). `plane-delete-test.sh` already lists voice; the CI matrix must read the same source. Zero edit. |

**Result:** of the landed-plane sites, C/D/K fold into the single `PLANE_DECL` push (B); E/F/G become
in-crate; I/J/L auto-derive from the workspace. The honest residuals are: (A) the workspace member line,
(H) ~one `plane-<key>` feature line per manifest, and (B) the registration push. **Add plane 5 = new crate
+ one registration push + a mechanical `Cargo.toml`/feature edge**, all *logic* in the new crate, and the
purity gates red automatically if the plane leaks a noun into a neutral crate. This is "single-crate diff"
in the load-bearing sense (all behaviour in one crate); the residual out-of-crate lines are declarative
wiring, each guarded.

---

## 8. Mandatory table — problem → current shape → new abstraction → plane-5 tax removed

| Problem | Current shape | New abstraction | Plane-5 tax it removes |
|---|---|---|---|
| Two host surfaces hand-diverge (the `u64`/`u128` bug's class) | C-ABI `PlaneHostVtable` (`host.rs:434`) authored separately from `EngineHost` trait (`mod.rs:434`), bridged by hand shims (`cost_host.rs`) | ONE authored slice-trait surface; vtable + shims + golden **generated** by `host_abi!` (§3); `u64`↔`u128` a generated `#[wire(u64, widen=u128)]` projection | A new capability is one authored method, not four hand-synced artifacts; no plane can trip the width-mismatch bug |
| Vtable is a 44-slot append pile with sibling twins | minors 9→19; `govern_admit`+`_reason`, `breaker_admit`+`_reason`, `approval_redeem`+`_q` (`host.rs:493,501,507`) | Payload-versioned slots: grow an args/out POD field via `field_present`, never a twin slot (§6.2); existing twins frozen for compat | Adding a plane needs no bespoke slot; capability growth is an append, not a per-plane slot |
| `EngineHost` god-trait handed to every plane | ~50 methods atop 3 slices (`mod.rs:434-966`); voice already routes around it via `MeteringHost` (`metering.rs:188`) | ~15 capability slices; `EngineHost` = LLM-only union; planes depend on the slices they name (§6.1) | A plane depends on 1–2 slices, mockable in-crate; never inherits the LLM union |
| Config hard-bakes LLM as core; generic path only fits named maps | `RootCfg.providers/pools/groups/rate_card` (`config/mod.rs:425-443`); `PlaneCfg` is named-map-only (`config.rs:36`) | Opaque config triad `parse/lower/default/validate` + minimal `OpaqueSectionCfg` (§5); LLM fields become an opaque plane section | A non-map plane declares its own grammar in-crate; core names no plane config type; `RootCfg` gains no field |
| Several neutrality gates are hard-coded and stale | `plane-purity-lint.sh:110-236`, `plane-grep-gate.sh:92-119`, `plane-roots.sh` callers list `llm/mcp/a2a`, missing voice; `Cargo.toml:10` has voice | ALL gates derive their plane list from workspace members + each `PlaneDecl.key`/`config_section` via one shared helper (§5.5, §7 I); `plane-abi-neutrality.sh` already proves the pattern | A new plane crate is guarded automatically; no per-script edit; no gate can silently miss a plane |
| Registering a plane touches many binary + manifest + CI sites | `main.rs` `register_protocols`/`register_planes`/`register_diagnostics`/admin-envelope (`:591-744`); feature knobs in 3 `Cargo.toml`s; CI deletion matrix | `PlaneDecl` carries protocols + diagnostics + admin noun (one registrar fold); features become mechanical `plane-<key>` forwards; gates + CI matrix derive from workspace (§7) | 8–11 sites → 1 registration push + ~1 declarative feature line per manifest, all guarded |
| One ABI evolution, not several (billing) | billing `Usage` tail proposed separately (`billing-unified.md §5.2`) | Fold billing tail into the SAME `ABI_MINOR` 19→20 as the codegen (§4) | One golden reseed, one negotiation story to audit — not a per-change ABI churn |

---

## 9. Constraints — how each is met

- **Back-compat (dlopen plugins).** Only one wire change (billing `Usage` tail); size-based
  `field_present` negotiation keeps a pre-minor-20 plugin working unchanged (§4.3). The vtable's frozen
  preamble/size/version and all 44 existing slots are byte-identical; move A changes authoring, not layout.
- **Existing configs parse identically.** Named-map sections (`mcp:`/`tools:`/`agents:`) untouched; the
  opaque triad is additive; the config-stability snapshot gate guards it (§5.4).
- **Frozen preamble untouched.** `AbiPreamble` + `size`/`version` unchanged everywhere (§2).
- **plane-purity BACKWARDS 0.** Generated code lives in neutral crates and names only neutral capability
  nouns; the (now auto-deriving) purity gate runs over it (§3.6, §5.5).
- **Nothing deferred.** Moves A–E all land in 1.6 under one ABI evolution; the sibling-doubling discipline
  and slice split are structural, not phased-away.

---

## 10. Residual risks (for the two adversarial auditors)

For the **Sonnet** pass (mechanical / claim-vs-code):

- **R1 — "generated ⇒ cannot diverge" rests on the macro being the sole authoring path.** If any slot is
  ever added to `PlaneHostVtable` by hand (bypassing `host_abi!`), the guarantee is void. Mitigation: the
  compile-time slot-table assert (§3.5-2) reds if the hand-added slot is not in the generated table; the
  layout golden reds on the offset move. Auditor should confirm BOTH guards are wired, not just the macro.
- **R2 — the u64/u128 projection is only as safe as the annotation.** `#[wire(u64, widen=u128)]` is
  correct; a future author could annotate a genuinely-large value as `u64` and lose range. Mitigation: the
  macro emits a documented range assertion; there is NO narrowing projection (a rich value that overflows
  the wire type fails to compile). Auditor should confirm no narrowing arm exists.
- **R3 — the golden reseed is a manual, reviewed act.** A wrong reseed could mask a real reshape. Auditor
  should confirm the reseed diff is exactly the billing tail (offsets 80/88, `__size` 96) and nothing else.
- **R4 — `OpaqueSectionCfg` minimality.** If it grows a named-map method later, it recreates the coupling.
  Auditor should confirm the five-method contract (§5.2) stays the intersection, and that gate-input needs
  route through the runtime `gate_decide` capability, not a config-time method.

For the **Opus** pass (architectural / does-it-generalize):

- **R5 — slice-split totality.** §6.1 partitions ~50 methods into ~15 slices; the auditor should verify the
  partition is TOTAL (every method has exactly one home) and that the residual `EngineHost` union contains
  only genuinely-LLM behaviour (`synthesize_completion`/`run_gauntlet`/`finish_*`) — anything neutral left
  on the union is a plane that still inherits too much.
- **R6 — "single-crate diff" honesty.** §7 concedes out-of-crate lines: the `PLANE_DECL` push, the
  workspace member line, and ~one `plane-<key>` feature line per manifest across three `Cargo.toml`s
  (item H — the largest residual). The auditor should decide (a) whether folding C/D/K onto `PlaneDecl` is
  genuine or merely relocates the enumeration onto the decl struct (genuine iff the registrar fold is
  generic over `PlaneDecl` fields, naming no plane), and (b) whether the Cargo feature knobs can truly
  reduce to one mechanical line per manifest — a cargo feature cannot be workspace-derived at build time,
  so this residual is real; the design's claim is only that it is *declarative wiring guarded by a
  convention* (feature name == `PlaneDecl.key`, checked by the deletion gate), not that it vanishes.
- **R7 — one ABI evolution carrying two moves.** Move A (authoring) + move B (wire tail) share a minor
  bump. The auditor should confirm move A is provably layout-neutral (golden unchanged by A alone), so the
  single golden reseed is attributable entirely to move B — otherwise "one evolution" hides two.
- **R8 — payload-versioning vs the frozen twins.** The six existing sibling slots stay. The auditor should
  confirm the anti-twin CI check (§6.2) actually prevents a SEVENTH twin, and that the args/out-POD form is
  expressive enough for the capabilities most likely to grow (govern/breaker refusal fidelity), so the
  discipline is not quietly abandoned at the first hard case.
- **R9 — LLM config migration sequencing.** §5.4 lands the opaque triad in 1.6 but the LLM-field migration
  onto it is Tier-A LLM-purity work. The auditor should confirm the triad is sound WITHOUT that migration
  (it is: the triad adds a path; it does not require moving the LLM fields to be correct), so a slip in the
  LLM-purity work does not block this spec.

---

## 11. Acceptance (provability checklist)

A build is conformant iff:

1. `PlaneHostVtable` is generated by `host_abi!` from the slice traits; no hand-authored slot exists
   (grep: no `Option<…Fn>` field outside macro output). **[structural]**
2. `const _: () = assert!(generated_slot_size == size_of::<PlaneHostVtable>())` and the per-slot offset
   consts compile. **[compile-time]**
3. `layout_golden.rs::abi_layout_matches_golden` passes; the golden diff versus base is EXACTLY the
   billing `Usage` tail (80/88/`__size`96). **[golden]**
4. A pre-minor-20 dlopen plugin (fixture at `size==80`) meters byte-identically to today. **[differential]**
5. `EngineHost` is a super-trait of the ~15 slices; a mock of any single slice compiles as a host for a
   plane that names only that slice (voice-metering fixture). **[compile-time]**
6. Voice's `sessions:`/`topologies:` parse/validate/lower through `opaque_config` with `parse_section` no
   longer `None`; core names no `VoiceCfg`. **[integration]**
7. `plane-purity-lint.sh` derives its plane list from the workspace + decls; adding a stub plane crate is
   guarded with zero script edit; BACKWARDS == 0 over generated code. **[gate]**
8. The anti-twin check reds a newly-added `_reason`/`_q`-style sibling slot. **[gate]**
9. Existing `config.yaml` snapshot (`config-schema.snapshot.json`) unchanged for `mcp:`/`tools:`/`agents:`.
   **[snapshot]**

Every "cannot diverge / single-crate" claim above maps to one of these checks; none is left as prose.
