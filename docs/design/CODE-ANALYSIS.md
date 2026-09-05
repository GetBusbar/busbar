# busbar — Full Code Analysis: current state vs. the plugin-architecture end-state

> Measured, not remembered. Production LOC only (tests excluded). This is the "see what we have"
> that the plan is grounded in. Verdict at the bottom.

## 1. Inventory (production LOC)

| Crate | Prod LOC | Role |
|---|---|---|
| busbar-core | 77,050 | the hub (furnishings + plumbing mixed) |
| busbar-llm | 47,238 | LLM plane: 6 dialect codecs + engine plumbing |
| busbar-substrate | 30,192 | "neutral ABI": genuine ABI + the plane-host/decl plumbing |
| busbar-mcp | 23,688 | MCP plane (one 22k monolith dir) |
| busbar-a2a | 21,702 | A2A plane (one 19.6k monolith dir) |
| busbar-voice | 6,498 | voice plane (the "4th plane" test case) |
| busbar-plugin / plugin-loader / api / plugin-sdk / sign / pack | ~16,000 | plugin ABI + loading infra |
| store-*/auth-*/hook-*/secret-*/export-* plugins | ~1,900 | non-plane plugins |
| **Total (main + infra)** | **≈ 228,000** | |

## 2. Furnishings vs. plumbing (the split that matters)

**FURNISHINGS — good products, keep as-is (≈ 177k, ~78%)**
- **Dialect codecs (the crown jewels, ≈ 35k):** llm gemini 5,848 · openai_responses 5,258 · openai_chat
  5,141 · bedrock 4,851 · cohere 3,737 · anthropic 3,595 · llm ir 2,294 · proto_stream/codec 2,444 ·
  mcp codec ≈ 3,700 · a2a codec ≈ 1,450 · voice ir/codec 1,846. Pure translation. Irreplaceable.
- **Plane domain logic (≈ 13k):** mcp catalogue/registry/trust/sampling 4,633 · a2a taskstore/card/
  pin/trust 2,774+1,023 · llm engine domain 533.
- **Core furnishings (≈ 45k):** governance ledger 3,818 · auth chain 4,323 · store driver 3,585 ·
  config 10,871 · config_validate 2,557 · oauth_as 2,388 · hooks 2,896 · admin API 15,272 (mostly) ·
  export 1,294 · metrics 1,250.
- **Substrate furnishings (≈ 15k):** egress client 4,342 · diagnostics 3,828 · trust 1,664 ·
  egress_auth 1,285 · net_guard 1,281 · ir 889 · store 800 · failover logic 563 · proto (minus residue).
- **All non-plane plugins + plugin infra (≈ 18k):** already the correct direction (§4).

**PLUMBING — the walls (≈ 52k, ~23%)**

| Where | LOC | What it is | Disposition |
|---|---|---|---|
| substrate `plane_host/` | 2,770 | the `EngineHost` 13-slice TRAIT | **TRASH** → `Ctx` + core deciders |
| core `plane_host/` | 8,226 | the `EngineHost` IMPL | **TRASH** |
| substrate `plane/` | 2,474 | `PlaneDecl` (43 fields) + registry | **TRASH** → `Plane::key/claims` |
| core `plane/` | 3,798 | plane registry/dispatch | **TRASH** → one registry |
| core `appbuild.rs` (plane part) | ~1,200 | composition of plane slots | **REWRITE** (register_plugins!) |
| core `router.rs` (plane part) | ~400 | plane route wiring | **REWRITE** (one loop) |
| mcp plumbing | 10,090 | `method.rs` 2,889 · `client/stdio` 1,087 · `connect` 598 · `reroute` 487 … | **REWRITE-THIN** → `impl Plane` (~1.5k) + **RELOCATE** charge/admit logic → core |
| a2a plumbing | 8,977 | `receive.rs` 3,437 · `relay.rs` 2,402 · `verbs` 781 · `plane.rs` 533 · `route` 467 … | **REWRITE-THIN** → `impl Plane` (~2k) + **RELOCATE** relay/route/meter logic → core |
| llm engine plumbing | 7,095 | `pipeline.rs` 3,168 · `walk.rs` 1,368 · `hooks.rs` 1,048 · `tables` 589 · `usage` 224 … | **RELOCATE** failover/breaker/pool LOGIC → core route engine; **TRASH** UsageSink/host glue |
| llm ingress/lib glue | ~2,250 | `native_ingress` 767 · `arrival` 486 · `chat_handle` 566 · `lib` 428 | **REWRITE-THIN** → `impl Plane` (~1.5k) |
| voice plumbing | 3,625 | `mount.rs` 1,056 · `metering.rs` 480 · `topology/` 1,299 · `runtime/mod` 216 · `lib` 344 … | **TRASH** private metering/lease/topology; **REWRITE-THIN** → `impl Plane` (~300) |

Net of the ≈52k: **≈20k trashed outright** (EngineHost ×2, PlaneDecl/registries, voice apparatus,
plane composition), **≈8k relocated** (good logic, wrong room → core deciders/route engine),
**≈24k of per-plane glue → ≈5k of trait impls.** Post-rebuild ≈ 192k, of which ≈177k untouched.

## 3. The sprawl, quantified

| Signature | Today | End-state |
|---|---|---|
| ad-hoc governance-verb fns (`admit`/`verify`/`meter`/`charge`/…) | llm 18 · mcp 22 · a2a 16 · voice 16 · core 70 · substrate 32 = **174** | 7 × 4 planes + 7 core deciders = **35** |
| plane → core call-ins (`host.x()`) | llm 163 · mcp 73 · a2a 63 · voice 26 = **325** | **0** |
| distinct host methods a plane depends on | llm 46 · mcp 26 · a2a 27 · voice 18 | **0** (Ctx is read-only) |
| `Plane` lifecycle trait | **none** (a 43-field fn-pointer struct) | one 12-method trait |
| the "add a 4th plane" cost (voice, measured) | **25 files / 6,498 LOC**, 72% plumbing | ~2–3 files / ~2,100 LOC (1,846 codec + ~300 impl) |

## 4. App-wide direction audit (plugins → core?)

| Kind | Crates | core dep | `busbar_core::` in prod | Direction |
|---|---|---|---|---|
| store | store-memory, store-example | NO | 0 | ✅ correct (core-driven) |
| auth | auth-static, auth-admin-tokens | NO | 0 | ✅ correct |
| hook | hook-test, hooks-ranking | NO | 0 | ✅ correct |
| secret / export | secret-example, export-example | NO | 0 | ✅ correct |
| ABI / sdk | api, busbar-plugin, plugin-sdk | NO | 0 | ✅ correct |
| substrate | busbar-substrate | NO | 197 *mentions* | ⚠ comments/strings only (no dep ⇒ can't be code) — a "neutral ABI narrating core" hygiene smell, scrub in rewrite |
| **planes** | llm, mcp, a2a, voice | (via host seam) | **325 call-ins** | ❌ **WRONG direction** |

**Finding:** the inversion is **confined to the plane subsystem** — the four planes plus the
`EngineHost`/`PlaneDecl` surface built to serve them. Every other plugin kind already has the correct
direction. The blast radius of the rebuild is ≈52k LOC, not the whole app.

## 5. What the heuristic could NOT resolve (first task of each plane unit)
- "other" buckets: mcp 4,501 · a2a 6,394 · llm engine 928 — unclassified by filename; need a fn-level
  disposition pass.
- Inside `walk.rs`/`pipeline.rs` (llm) and `method.rs` (mcp) / `receive.rs` (a2a): logic and glue are
  interleaved at the function level. Each needs a per-fn table: RELOCATE / TRASH / KEEP-as-impl.
- ~~core `admin/` (15k)~~ **RESOLVED:** the admin API is furnishing. Plane coupling is thin — **10 code
  refs** across 5 files, concentrated in `admin/planeverbs.rs` (147 LOC). ≈150 LOC of plane-verb
  plumbing to re-hang on the new registry; the other ≈15k is untouched.

## 5b. Load-bearing assumptions — VERIFIED
- **Codec purity (copy verbatim):** 8/9 codec dirs have **0** plumbing refs (≈35k LOC); bedrock has 2 (trivial).
- **Tangling (relocate-ability), host calls per fn:** `relay.rs` 0.1 (copy) · `method.rs` 0.7 /
  `receive.rs` 0.8 (relocate w/ per-fn pass) · **`walk.rs` 3.1 / `pipeline.rs` 3.7 → rewrite-from-spec**
  (the one true rewrite, ≈4.5k, the money path).
- **Substrate's 197 `busbar_core::` mentions:** 0 in code — all comments (it has no core dep).
- **Every non-plane plugin kind:** correct direction already (0 core deps, 0 refs).

## 6. VERDICT

**Not a trash-all. A plumbing tear-down with furnishing salvage.**
- **78% untouched.** The codecs (≈35k of pure dialect translation), the ledger, stores, auth, config,
  trust, egress client, admin — genuinely good, and exactly "good products in the wrong room."
- **Tear down completely, do not bend:** `EngineHost` (trait + impl, 11k), `PlaneDecl` + both
  registries (6.3k), voice's private metering/lease/topology apparatus, the plane composition in
  `appbuild`. These *embody* the wrong direction; incremental bending would preserve it.
- **Relocate (≈8k):** the failover/breaker/pool logic, MCP charge-round semantics, A2A relay/route/
  meter policy — good logic that belongs in core's deciders and route engine.
- **Rewrite thin (≈24k → ≈5k):** each plane's dispatch/mount/receive/pipeline glue becomes a
  `impl Plane` that fills in the blanks over its existing codec.
- **The proof the design is right:** voice drops from 25 files / 6.5k to ~2–3 files / ~2.1k.

**48 hours is realistic** with the contract frozen first and ~8 parallel streams: the ≈52k of
plumbing is disjoint per unit (per-plane glue is per-crate; deciders/route-engine are core; the
EngineHost/PlaneDecl deletion is last). Critical path: contract → core deciders + route engine →
LLM (alone, shadow-diff) → collapse.
