# Unified billing: one money path every plane bills through identically

Status: design, decision-ready. No code in this change. Base branch
`integration/transport-core` (tip `8ef39da6`).

**Supersedes** `docs/design/billing-usage-units.md`. That document's v2 revision
answered its audit by *scoping the unification away* — "the FFI `Usage` POD is
UNCHANGED", "the D2 `CostHold` lease is UNCHANGED", "post-hoc-per-request vs
continuous-reserve/settle are DIFFERENT surfaces by design; v2 does not pretend
they unify." The owner **rejected that framing.** The governing law is *"one
operation, one path, the same steps every time"* — billing is not exempt, core
is plane-agnostic, and **every plane — LLM, MCP, A2A, voice, and dlopen FFI
plugin — bills through the identical money path.** This document specifies that
one path and proves the claim against real types, not aspiration.

---

## 0. Executive summary (6 lines)

1. **One neutral input:** every plane hands core `Usage { usage_units:
   BTreeMap<String,u64>, attribution }` — opaque keyed counts plus neutral
   facets; no key literal lives in any neutral crate (the `CostComponent.label`
   / `Magnitude.unit` opaque-string precedent, made plural).
2. **One currency:** nanodollars (`CostAmount(u128)`), which `plane/cost.rs`
   already declares is "the same integer unit the engine's per-token pricing
   already settles in (`RateNanos`/`cost_nanos`)." Every representation
   converges here; `derive_spend_cents` becomes a final display projection.
3. **One pricer → one breakdown → one ledger:** a single core function prices
   any plane's `Usage` into one `CostBreakdown` (each key a disjoint top-level
   component, so exact-sum holds by construction) and one ledger accrual. LLM,
   voice, and dlopen all reach this same function — the "one path" proof (§4).
4. **FFI billing identically:** the frozen `Usage` POD gains an **append-only**
   packed keyed-unit tail (`ABI_MINOR` 19→20, layout-golden reseed); a dlopen
   plane emits units and core prices them through the one pricer — no private
   `unit_cost_micros` self-price.
5. **Voice billing identically:** the `CostHold` lease reserves a *priced*
   estimate and settles *priced* exact increments through the same pricer — no
   private nanodollar self-price. `service_tier` (a closed enum × config
   multiplier) and Cohere `billed_units` ship in 1.6, each modelled correctly.
6. **Every prior-round audit finding cleared in-place:** Copy preserved for hot
   enforcement, never-silent-$0, structural double-count guard, bounded
   `MeterKey`, owned goldens/serde, and exact-sum `CostBreakdown` — §9.

---

## 1. The three representations, and the single fact that unifies them

Today one *operation* is billed three structurally different ways:

| # | Plane | Carrier today | Who prices | Priced form today |
|---|---|---|---|---|
| 1 | LLM per-request | `TierTokens` (4×`u64`) rate-card counts | **core** (rate card) | `RateNanos::cost_nanos` → `derive_spend_cents` |
| 2 | Voice / duplex continuous | `CostHold` nanodollar lease | **plane** (`settle_partial` scalar) | `CostBreakdown` (audit tap only) |
| 3 | dlopen FFI plugin | `hot::Usage` POD (`amount`/`unit_cost_micros`) | **plane** (`unit_cost_micros`) | `CostBreakdown` via `govern.rs::charge` |

The load-bearing discovery: **two of the three already meet at
`CostBreakdown` in nanodollars.** `plane_host/govern.rs::charge` (`crates/busbar-core/src/plane_host/govern.rs:207‑244`)
takes a `hot::Usage` POD, computes `CostAmount(amount × unit_cost_micros ×
NANOS_PER_MICRO)`, runs it through the *real* `CostBreakdown::new`
(`crates/busbar-core/src/plane/cost.rs:191`, fail-closed `Rejected` on any
invariant break), resolves `(key_id, model, provider)`, and calls
`gov.record_metering`. The host `CostHold` registry
(`crates/busbar-core/src/plane_host/cost_host.rs`) is documented as the
"Neutral-seam primitives (shared by static planes AND the FFI slots — ONE
ledger)." And `CostAmount` itself
(`plane/cost.rs:36‑39`) is *defined* as "the same integer unit the engine's
per-token pricing already settles in (`RateNanos`/`cost_nanos`)."

So the currency is already one (nanodollars) and the priced form is already one
(`CostBreakdown`). **The only thing that is not one is WHO prices** — LLM is
core-priced from a rate card; voice and dlopen are plane-priced scalars core
merely records. Unification = *make core price all three from the same rate
card via one function.* Everything below builds that one function and threads
all three planes into it.

---

## 2. The one neutral `Usage` representation

### 2.1 The type every plane hands core

```rust
// busbar-substrate (neutral). Opaque keyed counts + neutral attribution facets.
pub struct Usage {
    /// Billable keyed counts. Keys are OPAQUE plane/operator DATA (never
    /// interpreted by core), exactly like `CostComponent.label` and
    /// `Magnitude.unit`. The four rate-card tier names ("input"/"output"/
    /// "cache_read"/"cache_write") are reserved keys; all other keys are open.
    pub usage_units: BTreeMap<String, u64>,
    /// Neutral WHO/WHAT facets. Core stores and reports; never interprets.
    pub attribution: Attribution,
}

pub struct Attribution {
    pub virtual_key: String,   // who pays (already in MeterKey today)
    pub pool: String,          // which pool
    pub plane: Plane,          // CLOSED enum: Llm | Mcp | A2a | Voice | Ffi
    pub operation: Operation,  // CLOSED enum (§7.3), never free text
    pub model: String,         // who/what served (already in MeterKey)
    pub provider: String,      // already in MeterKey
}
```

`Plane` and `Operation` are **closed enums**, so attribution cardinality is a
bounded constant, not client-controlled (the cardinality proof, §9.4). `model`
and `provider` are already unbounded-but-operator-controlled today
(`MeterKey = (String, u64, String, String)`, `governance/mod.rs:983`).

### 2.2 Proof: no key literal is required in a neutral crate

Core prices by **opaque map lookup**, never by string comparison. The one
pricer (§4.1) does `rate.get(k)` for each key `k` in `usage_units`; it never
writes `k == "audio"`. This is the exact precedent already shipped three times
in this tree:

- `CostComponent.label: String` — "an OPAQUE plugin string (core never branches
  on it)" (`plane/cost.rs:80`).
- `Magnitude.unit: &'static str` — "an opaque plugin word, never interpreted by
  core" (`plane/cost.rs:276`).
- `MetricSample` — "label passthrough; the host interprets no label"
  (`hot/pod.rs:1685`).

The four reserved names (`input`/`output`/`cache_read`/`cache_write`) appear as
*string literals* in exactly two places, both of which exist today and neither
of which is a neutral crate: (a) the plane-side projection `tier_tokens`
(`crates/busbar-llm/src/engine/usage.rs:53`, a `busbar-llm` plane crate), and
(b) operator `rate_card` YAML. In the neutral crates they are **struct field
names on `TierTokens`**, not map keys — see §9.1. Audit grep (must return zero
in neutral crates):

```
grep -rE '"(input|output|cache_read|cache_write|audio|web_search|reasoning|classifications|priority|batch)"' \
  crates/busbar-core/src crates/busbar-substrate/src crates/api/src
```

### 2.3 Where the reserved four live (the Copy-preserving split)

`usage_units` is the **pricing/ledger/attribution** currency (non-`Copy`, one
allocation, only when a plane emits keys). The **hot enforcement** path keeps
the `Copy` numeric summary it uses today. The plane already computes both from
one projection: `tier_tokens` yields the `Copy` `TierTokens` (reserved four)
for enforcement, and the same projection fills `usage_units` (reserved four +
opens) for pricing. Core derives nothing from key strings; the plane hands core
**both** the `Copy` `TierTokens` summary and the opaque `usage_units` map. See
§9.1 for the exact Copy call-site enumeration.

---

## 3. One currency: nanodollars

Every representation converges on `CostAmount(u128)` nanodollars
(`plane/cost.rs:41`), whose `Add`/`Sum` are saturating (fail-closed money
discipline, `plane/cost.rs:54‑71`):

```
LLM:    units[k] × rate_nanos[k]  (u64×u64 → u128)         ─┐
Voice:  priced estimate / priced exact increment (u128)    ├─→ CostAmount(u128)
dlopen: units[k] × rate_nanos[k]  (core-priced, not micros) ─┘   nanodollars
```

The rate card prices keys → nanodollars. `derive_spend_cents`
(`cost.rs:527`) becomes a **final display projection** of a `CostBreakdown`
total: `CostAmount(total).0 / NANOS_PER_CENT`, keeping the C1 saturating guard
verbatim (`i64::try_from(nanos / NANOS_PER_CENT).unwrap_or(i64::MAX)`,
`cost.rs:539‑544`) so an adversarial ledger pins at `i64::MAX` (blocks) rather
than wrapping negative-then-floored-to-free. `NANOS_PER_CENT = 10_000_000`,
`NANOS_PER_MICRO = 1_000` (`cost.rs:37,40`).

---

## 4. One pricer, one breakdown, one ledger

### 4.1 The single pricing entry point

```rust
// busbar-core::cost — THE one function every plane's Usage reaches.
pub fn price(
    rate: &RateNanos,             // resolved reserved-four nano rates (Copy, unchanged)
    extras: &ExtraRates,          // resolved open-key nano rates (Arc<BTreeMap<String,u64>>)
    tier: ServiceTier,            // closed enum; multiplier resolved from config (§7)
    u: &Usage,                    // the neutral keyed usage + attribution (§2)
) -> Result<CostBreakdown, CostError>
```

Construction rules (each produces at most one *disjoint top-level*
`CostComponent`, so `Σ top_level == total` holds by `CostBreakdown::new`
without any post-hoc scaling):

1. **Reserved four** — priced by the existing `Copy` `RateNanos::cost_nanos`
   (`cost.rs:116`), unchanged, byte-identical. Each non-zero tier becomes one
   top-level component (`"Prompt"`, `"Output"`, `"Cache read"`, `"Cache
   write"`); a zero tier is omitted (the no-zero-component invariant,
   `plane/cost.rs:197`).
2. **Open keys** — for each `(k, n)` in `usage_units` outside the reserved
   four: `rate = extras.get(k)`. Present ⇒ one top-level component
   `(k, n × rate)`. **Present-but-unpriced ⇒ never a silent $0** (§9.2): emit a
   rate-limited WARN (`BUSBAR-3021`) + `unpriced_usage_key` metric and DO NOT
   emit a zero component (fail-closed to visible, not to hidden).
3. **Tier** — one top-level surcharge component (§7).
4. `CostBreakdown::new(total, components)` enforces exact-sum, unique labels,
   containment, and no-zero — a malformed breakdown cannot reach the ledger.

`ExtraRates` lives on the `RateCard` as `Arc<BTreeMap<model, BTreeMap<key,
nano>>>`, looked up **only when `usage_units` carries an open key**, so
`RateNanos` stays a four-field `Copy` struct and the 99% no-extras request pays
zero added cost and allocates nothing (§9.1).

### 4.2 One breakdown, one ledger accrual

`price` returns exactly one `CostBreakdown`. Its `.total()` drives:

- **Enforcement accrual** — the existing `GovState::record_usage(cost, key,
  pool, model, tokens: &TierTokens, now)` (`governance/state.rs:798`),
  signature **unchanged**, fed the `Copy` `TierTokens` summary exactly as
  today. Open keys do NOT enter the hot enforcement bucket (§9.4).
- **Spend derive** — `derive_spend_cents`/`derive_spend_micros` project the
  breakdown total to display cents/micros (§3), guard unchanged.
- **Metering series** — `gov.record_metering(...)` records the total + the
  breakdown components + attribution into the persisted usage record.

There is **no second ledger, no second rate table, no second pricing engine,
no second usage struct.** `UsageLedger`/`ModelTokens` (`store.rs:601`) is
unchanged in shape; open-key spend rides the persisted usage record's
`usage_units` beside the existing per-model `TierTokens`.

### 4.3 The "one path" proof — all three planes reach `price`

| Plane | Entry seam today | Rewires to |
|---|---|---|
| **LLM** | `ledger_and_meter` → `meter_ledger`/`meter_series` (`engine/usage.rs:85`) then core `derive_spend_cents` | builds `Usage` from `tier_tokens` + `IrUsageDetail` opens (§8), calls `price`, accrues the returned breakdown |
| **dlopen FFI** | `govern.rs::charge` (`plane_host/govern.rs:207`) already builds a `CostBreakdown` | reads the appended keyed-unit POD tail (§5), builds `Usage`, calls `price` instead of trusting `unit_cost_micros` |
| **Voice/duplex** | `CostHold::reserve`/`settle_partial` (`plane/cost.rs:348,389`) with a plane-priced scalar | reserve = `price`(estimate units); each settle = `price`(exact increment units) → `settle_partial(total)` (§6) |

**Single entry point every plane reaches: `busbar_core::cost::price`.** That is
the "same steps every time" proof — cited, not asserted (§12).

---

## 5. FFI unification — a dlopen plane bills identically

### 5.1 Constraint: the frozen, append-only ABI

`hot::Usage` (`crates/busbar-plugin/src/hot/pod.rs:665`) is a `#[repr(C)]` POD
leading with `size: u32`/`version: u16`; every extension appends `(ptr, len)`
fields at the TAIL, read only when `size` proves they were written (the
`read_sized_field!` sized-struct guard, `lib.rs:154`). Reorder/resize/insert is
a MAJOR event caught by the layout golden; an append is a MINOR bump
(`ABI_MINOR`, currently 19, `lib.rs:72`). Two existing tails prove the pattern:
the minor-5 attribution tail (`key_id`…`provider_len`) on `Usage` itself, and
the minor-7/8 egress-request tail on `EgressDesc` — and the packed-record
precedent (headers/env: a sequence of LE `u32 len` + bytes, `pod.rs:966`,
`:1017`).

### 5.2 The keyed-unit tail (append-only, `ABI_MINOR` 19→20)

Append two fields to `Usage`, after `provider_len` (current `__size = 80`,
`tests/golden/abi-layout.golden`):

```rust
// (minor-20) Borrowed packed keyed-unit records the host prices via the rate
// card — the dlopen analogue of the LLM plane's usage_units. Each record is a
// LE u32 key_len, key_len key bytes, then a LE u64 count. Null/0 ⇒ no keyed
// units (the host falls back to the frozen amount × unit_cost_micros path, so a
// pre-minor-20 plane bills byte-identically to today).
pub units_ptr: *const u8,   // golden offset 80
pub units_len: usize,       // golden offset 88   → new __size = 96
```

- The **frozen preamble and every existing field stay byte-identical** (offsets
  0…72 unchanged); only the tail grows. `POD_VERSION` bumps 2→3;
  `ABI_MINOR` bumps 19→20. `check_preamble` still accepts an older minor
  (append-only compatibility, `lib.rs:127`).
- **Semantics:** when `units_len > 0`, `govern.rs::charge` decodes the packed
  records into `Usage.usage_units` and calls `price` (§4.1) — **core prices via
  the rate card, identical to LLM.** When absent, the legacy `amount ×
  unit_cost_micros` scalar path is retained for pre-minor-20 planes
  (back-compat). The `UsageComponent` enum (`Tokens`/`Bytes`/`Frames`/`Queries`,
  `pod.rs:199`) selects the *reserved key spelling* for the legacy scalar; a
  keyed-unit plane names its own keys and no longer needs it.
- **Layout-golden reseed:** add `Usage.units_ptr=80`, `Usage.units_len=88`,
  `Usage.__size=96` to `crates/busbar-plugin/tests/golden/abi-layout.golden`;
  `layout_golden.rs::abi_layout_matches_golden` (`:494`) re-passes. This is the
  same reseed the D2 lease slots reserved for "when the carrier lands."

### 5.3 One ledger for static and dlopen

The substrate seam `EngineHost::meter_charge(scope, usage: &hot::Usage)`
(`plane_host/mod.rs:485`) and the FFI `MeterChargeFn` slot (`hot/host.rs:49`)
both carry the same POD; `govern.rs::charge` is the one shim behind both. After
this change both build the neutral `Usage` and call `price` — so a
statically-compiled plane and a dlopen plane bill through the identical
function, not merely the identical ledger.

---

## 6. Lease reconciliation — voice audio bills via the one path

The `CostHold` lease (`plane/cost.rs:333`) is nanodollar-denominated end to end
and its doc already says "the caller — the PLANE, or a substrate pricing seam
it delegates to — converts its own unit projection to nanodollars BEFORE
calling reserve/settle." Today the plane self-prices. **Unification: that
"substrate pricing seam" is `price` (§4.1), so the money the lease moves is
produced by the one pricer, not a private voice self-price.**

- **Reserve** = `price`(estimate `usage_units`, e.g. `{"audio_input":
  est_seconds_as_units}`) + flat fee → `CostHold::reserve(estimate, fee, cap)`
  (`:348`). The coarse over-estimate is now a *priced* estimate.
- **Settle** = each streamed turn emits exact keyed units; `price` yields the
  exact increment `CostBreakdown`; `settle_partial(breakdown.total())`
  (`:389`) accrues the O(1) scalar. The itemized breakdown continues to travel
  the existing **opaque audit tap** (`CostSettleFn.breakdown_ptr`,
  `hot/host.rs:424`; "the host never parses") — but the *scalar it settles* is
  now core-priced.
- **Exhaustion / finalize** unchanged (`is_exhausted` against `cap`,
  `finalize` refund `reserved − settled` saturating, `:380,:396`).

**FFI lease carrier (append-only, same minor-20 bump):** the minor-19
`cost_reserve`/`cost_settle` slots (`hot/host.rs:405,420`) are wired to `None`
in the shipping vtable and are *not yet in the layout golden* — so their keyed
form is defined now, before the carrier lands. `cost_settle` gains an appended
borrowed packed keyed-unit `(ptr, len)` (same record layout as §5.2) that the
host prices via `price`; when absent, the legacy `settle_nanos: u64` scalar is
retained. The frozen `AbiPreamble` and existing slots are untouched; the golden
gains the `CostSettleOut` rows + the new field on first reseed. Net: a dlopen
voice plane reserves/settles through the same pricer as the in-process voice
plane.

---

## 7. `service_tier` / tier multiplier — in 1.6, done right

### 7.1 The invariant problem, and the fix

A whole-charge *scalar* multiplier applied after the components are built
breaks `CostBreakdown`'s exact-sum invariant (`Σ top_level == total`,
`plane/cost.rs:221‑232`): scaling `total` alone leaves `Σ components ≠ total`.
The fix is to make the tier **its own top-level `CostComponent`**, included in
the sum:

- **Surcharge tiers** (`priority`, `mult > 1`): price the reserved/open keys at
  list rate → base components; add one top-level component
  `service_tier:<name>` = `base × (mult − 1)` (positive nanodollars). `Σ =
  base + surcharge = total`. All components positive; invariant holds by
  construction.
- **Discount tiers** (`batch`, `mult < 1`): a discount is *negative* money and
  `CostAmount` is unsigned, so it cannot be a positive line. The multiplier
  instead folds into each key's effective rate (`rate_eff = rate × mult`), so
  every per-key component is already the discounted amount and `Σ = total`
  exactly. (Asymmetry flagged for auditors, §13.6.)
- `mult == 1` (`standard`): no line.

Either way, **no post-hoc scalar touches `total`** — the invariant is never at
risk. Integer discipline: `mult` resolves to integer basis points at config
load (e.g. ×10000), applied `× bp / 10000` saturating before the single final
cents divide, so no per-key float drift compounds (§10).

### 7.2 Closed tier enum + config multiplier

```rust
pub enum ServiceTier { Standard, Priority, Batch, Flex }   // closed; extend additively
```

Rate-card config gains `tier_mult: BTreeMap<ServiceTier, f64>` (default 1.0).
The tier is sourced plane-side from `IrUsageDetail.service_tier`
(`ir/types.rs:944`) and carried as the `ServiceTier` on the pricer call — never
as an open `usage_units` key (a tier is a modifier, not a counted unit).

### 7.3 `operation` closed enum

```rust
pub enum Operation { Chat, Embeddings, Responses, Realtime, Rerank, Classify, /* … */ }
```

`operation` is a **closed enum, never free text**, so it is a bounded
attribution facet safe to persist on the ledger/reporting record — and
explicitly NOT added to the hot `MeterKey` (§9.4).

---

## 8. Cohere `billed_units` — in 1.6, explicit and tested

`IrUsageDetail` already carries the Cohere fields losslessly but
`to_token_usage` drops them (`ir/types.rs:1015`). The generalized plane
projection (a `busbar-llm` change, zero core edits) maps them into
`usage_units`:

| `IrUsageDetail` field | Emitted key | Rule |
|---|---|---|
| `billed_input_tokens` (`:980`) | reserved `input` | billed wins over raw when present |
| `billed_output_tokens` (`:983`) | reserved `output` | billed wins over raw |
| `billed_classifications` (`:986`) | open `classifications` | priced per classification |
| `search_units` (`:931`) | open `search` | priced per search unit |

This **changes the ledgered counts for Cohere** vs today's raw totals (more
correct billing truth, not byte-identical) — so it is an **explicit, tested
per-dialect mapping change**, not folded in as "zero-edit." Test: a Cohere
response with `billed_units` present ledgers `billed_*`, not raw
(red-before-green). Anthropic cache-TTL split (`cache_creation_1h_input_tokens`,
`:927` → open `cache-1h`) and web search (`web_search_requests`, `:937` → open
`web_search`) map the same way; slices already inside a reserved total
(`reasoning_tokens ⊂ output`, `input_audio_tokens ⊂ input`,
`tool_use_prompt_tokens ⊂ prompt`) are **never** emitted as billable keys — they
stay pure attribution (the `IrUsageDetail` "a SLICE OF a total, never an
addition" rule, the anti-double-count guard of §9.3).

---

## 9. Every prior-round audit finding, cleared explicitly

### 9.1 Copy cascade — resolved by the enforcement/pricing split

Confirmed `#[derive(Copy)]` today: `TierTokens` (`store.rs:563`),
`TierTokensDelta` (`store.rs:698`), `RateNanos` (`cost.rs:86`), `RateEntryCfg`
(`config/mod.rs:3678`). A `BTreeMap` field on any of them drops `Copy` and
breaks the sites below. **Resolution: the keyed map + attribution never touch
these types.** They ride the non-`Copy` `Usage`/ledger/pricing layer; the four
`Copy` structs are unchanged, so the hot enforcement path is untouched.

Exact call sites that stay `Copy` (all unchanged):

| Site | Location | Why it needs Copy |
|---|---|---|
| `rate_for` returns `table.get(model).copied()` | `cost.rs:498‑503` | `RateNanos: Copy` |
| `RateNanos::cost_nanos(&self, …)` reserved-four math | `cost.rs:116` | value-copy of rate |
| `ModelCell.cur: TierTokens` saturating field adds | `governance/mod.rs` accrual | `*cur` copy |
| `TierTokensDelta` fleet-flush deltas (`i64`) | `store.rs:698` | delta copy in `apply_model_delta` (`store.rs:664`) |
| `RateEntryCfg` config value | `config/mod.rs:3678` | copied out of the config map |

`ExtraRates` (the open-key nano table) is a **separate `Arc<BTreeMap>` on the
`RateCard`**, never inside `Copy` `RateNanos`, looked up only when
`usage_units` carries an open key.

### 9.2 Silent $0 — never silent, fail-closed to visible

Ground truth correction: there is **no `warn!` in `cost.rs`**. The fail-closed
unpriced-*model* gate is a REJECT at ingress admission
(`crates/busbar-core/src/ingress/mod.rs:410‑429`): when a rate card is present
(and boot/`--validate` enforce rate-card completeness over `config.models`), an
unpriced arbitrary model is rejected `BAD_REQUEST` with `tracing::info!` — never
served-then-billed-$0. `model_unpriced` (`cost.rs:509`) is the probe.

The unified rule extends this to **keys**: (a) **boot validation** checks
rate-card completeness over every declared open key exactly as it does over
models — a present key with no rate is a config error at `--validate`; (b) the
**runtime backstop** in `price` (§4.1 rule 2) never emits a zero component for a
present-but-unpriced key — it emits a rate-limited WARN (`BUSBAR-3021`, the
successor code to the G2 `BUSBAR-3020` fix) + an `unpriced_usage_key` counter,
so the gap is visible in logs and metrics, not hidden as free usage. (Optional
strict-mode reject is future; default = warn + metric.)

### 9.3 Double-count / single source of truth — enforced in core

Reserved names (`input`/`output`/`cache_read`/`cache_write`) are the **sole**
source for the four tiers; open keys are disjoint by construction. Two
enforcement points, both in core, both tested:

1. **Config validation REJECTS a reserved name in a `units:` rate map** (a
   reserved key priced twice) — the named point is the `RateCard` validator
   invoked at boot/`--validate` (alongside the model-completeness check of
   §9.2). Test: a rate card with `units: { input: … }` fails to load.
2. **The plane projection NEVER emits a reserved name into an open slot** — the
   `busbar-llm` projection routes the four to `TierTokens`/reserved `usage_units`
   keys and opens elsewhere; test asserts no reserved name in the open set.

Slices-of-a-total (§8) are never billable keys — the second half of the
anti-double-count guard.

### 9.4 MeterKey cardinality — attribution rides the ledger, not the hot key

`MeterKey = (String, u64, String, String)` (`governance/mod.rs:983`) is bounded
by `MAX_PENDING_METERING = 262_144` (`:993`), sharded, with an overflow-coalesce
sentinel that preserves billable totals while collapsing attribution under a
store outage (`accrue_pending`, `:1024`). **We do NOT add `plane`/`operation`/
open keys to `MeterKey`.** `operation` and `plane` are closed enums (bounded)
and ride the **persisted ledger/reporting record**, not the in-memory hot
enforcement key — so the 262144 bound and its coalesce behavior are unchanged.
`metrics.rs` stays bounded: `busbar_bucket_tokens`'s `tier` label remains "one
of the four fixed pricing tiers" (`metrics.rs:316`); **no open `usage_units`
key ever becomes a Prometheus label** (the module's cardinality invariant,
`metrics.rs:28‑42,144‑153`). Open-key visibility is via the ledger/reports.

### 9.5 Serialization / goldens — owned, back-compatible

Owned regen + tests:

- **Ledger/usage record** gains `#[serde(default, skip_serializing_if =
  "BTreeMap::is_empty")] pub usage_units: BTreeMap<String,u64>` (and the twin
  `BTreeMap<String,i64>` on the delta). Old persisted `UsageLedger`/`TierTokens`
  rows deserialize with an empty map (`#[serde(default)]`); a no-extras row
  serializes byte-identically (skip-if-empty). `TierTokens` (`store.rs:564`) is
  **not** touched — the map rides the enclosing usage record, so `TierTokens`
  serde and its `Copy` are unchanged.
- **`is_zero`/round-trip**: the enclosing record's `is_zero` folds
  `usage_units.is_empty()`; a round-trip test proves an old row and a
  no-extras new row are byte-identical.
- **`config-schema.snapshot.json`**: regenerated for the new `units:`/
  `tier_mult:` rate-card fields and `ExtraRates`; committed.
- **Layout golden**: reseeded per §5.2/§6.

### 9.6 CostBreakdown invariants — the classification

Every priced key is a **disjoint top-level component** (parent `None`), so
`Σ top_level == total` holds by `CostBreakdown::new` (`plane/cost.rs:221`).
Classification:

- Reserved four, opens, and the surcharge tier line: **top-level** (sum to
  total).
- Zero-amount keys: **omitted**, never a zero component
  (`ZeroComponent` guard, `:197`).
- True slices of a total (reasoning ⊂ output): **nested children** under their
  parent (do not add to total; must not exceed parent, `:234‑248`) when a plane
  chooses to surface them for reporting — otherwise pure attribution (§8).
- Unique labels enforced (`:202`); a duplicate key spelling fails construction.

---

## 10. Overflow / rounding / determinism

- **Overflow (ties to C1):** all money math accumulates in `u128` (`u64 count ×
  u64 rate` fits `u128`); the open-key loop and `CostAmount::Add`/`Sum` are
  `saturating` (`plane/cost.rs:54‑71`). `derive_spend_cents` keeps the C1
  `i64::try_from(…).unwrap_or(i64::MAX)` pin (`cost.rs:544`), so an adversarial
  many-key ledger caps at `i64::MAX` (blocks) and never wraps
  negative-then-floored-to-free.
- **Rounding:** rates round to nano-units **once** at resolve
  (`RateNanos::from_cfg`, `cost.rs:95`; `ExtraRates` identically); counts are
  exact integers; the priced sum accumulates exactly and divides by
  `NANOS_PER_CENT` **once** at the very end. Adding keys adds exact integer
  terms — no per-key rounding compounds. Tier bp scaling is integer, applied
  before the single final divide.
- **Determinism:** `BTreeMap` gives sorted, stable key order for the flush
  delta, the `CostBreakdown` components, and cross-node reconciliation. `Plane`/
  `Operation`/`ServiceTier` closed enums serialize stably.

---

## 11. Back-compat and migration

- **Existing rate cards** price unchanged: absent `units:`/`tier_mult:` ⇒ empty
  ⇒ identical pricing; `RateEntryCfg` keeps `deny_unknown_fields`; the four
  `*_utok` fields are untouched.
- **Existing ledgers** deserialize byte-identically (§9.5); a no-extras LLM
  request prices via the same `RateNanos::cost_nanos` and persists the same
  `TierTokens` row and the same derived cents as today — **byte-identical**.
- **ABI:** `ABI_MINOR` 19→20 is append-only; a pre-minor-20 plane advertises
  the shorter `size` and bills via the frozen `amount × unit_cost_micros` path;
  `check_preamble` accepts the older minor.
- **Reserved-key registry** (`input`/`output`/`cache_read`/`cache_write`) is
  doc-owned and additive; new reserved names or `Plane`/`Operation`/
  `ServiceTier` variants are additive minor changes. A cross-node node running
  old code that receives a delta carrying `usage_units` ignores the unknown map
  but still reconciles the reserved four — at-least-once under-attribution of
  open keys until upgrade, matching the existing flush baseline.

---

## 12. "Same steps every time" proof

Every plane's billing reduces to the identical five steps, at the identical
entry point:

1. Plane projects its native usage → neutral `Usage { usage_units, attribution }`.
2. Core calls **`busbar_core::cost::price(rate, extras, tier, &usage)`** — the
   single pricing entry point (§4.1).
3. `price` returns one `CostBreakdown` (nanodollars, exact-sum enforced).
4. `record_usage` (enforcement, `Copy` `TierTokens`, `governance/state.rs:798`)
   + `record_metering` (series) accrue the breakdown; `derive_spend_cents`
   projects the display total.
5. One ledger row, one metering series, one attribution record.

LLM, voice, and dlopen differ only in step 1 (native projection) and in the
*carrier* of the `Usage` (in-process struct vs FFI POD tail); steps 2–5 are
literally the same code. That is the law satisfied: one operation, one path,
the same steps every time.

---

## 13. Open questions + residual risks for the two auditors

1. **`ExtraRates` placement:** `Arc<BTreeMap<model, BTreeMap<key, nano>>>` on
   the `RateCard` vs a per-key column beside `RateNanos`. The `Arc` keeps
   `RateNanos` `Copy` and the no-extras path allocation-free — confirm no hot
   site clones the `Arc` per request (it should be borrowed).
2. **dlopen pricing shift:** moving dlopen from plane-priced `unit_cost_micros`
   to core rate-card pricing means a dlopen plane's spend now depends on
   operator rate-card completeness for its keys. Is the §9.2 boot-validation
   gate sufficient, or must an un-carded dlopen key fail the plane's admission
   rather than warn-and-zero?
3. **Voice reserve estimate accuracy:** the reserve now prices an *estimate*
   unit bundle; confirm the coarse over-estimate still admits (the `Magnitude`
   pre-admission cap, `plane/cost.rs:274`, is a separate unit-space check) and
   that `is_exhausted` still fires against the true `cap`, not the priced
   reserve.
4. **Reserved-vs-open collision depth:** is config-reject + projection-route
   (§9.3) enough, or should `price` also *assert* no reserved name appears in
   the open slot (debug panic / diag) as a third belt?
5. **Cross-node under-attribution window:** an old node dropping unknown
   `usage_units` deltas under-attributes open-key spend until upgrade; reserved
   four always reconcile. Acceptable against the existing at-least-once flush?
6. **Tier discount asymmetry (§7.1):** surcharge tiers get a named top-level
   `service_tier` component; discount tiers fold into per-key effective rates
   with no named line. Both keep exact-sum — but is the *reporting* asymmetry
   acceptable, or must a discount be surfaced (e.g. list-price components + a
   nested informational child that reduces from a synthetic list-price parent)?
7. **`billed_units` history:** re-pricing Cohere from `billed_*` changes ledger
   counts vs raw (§8). Confirm this is the intended billing truth and does not
   retroactively alter historical reconciliation.

---

## 14. Mandatory table — New/changed concept → existing type it unifies → what changes → duplicate avoided

| New/changed concept | Existing type it unifies | What changes | Duplicate avoided |
|---|---|---|---|
| Neutral keyed `Usage {usage_units, attribution}` | `TokenUsage` (`billing.rs:30`) + `hot::Usage` POD (`pod.rs:665`) + `CostHold` inputs | one opaque keyed map + closed-enum facets is the single pricing currency all planes hand core | a per-plane usage struct; the rejected "separate surfaces" split |
| `busbar_core::cost::price(...)` | `RateNanos::cost_nanos` (`cost.rs:116`) generalized | reserved four via unchanged `cost_nanos` + open-key loop + tier line → one `CostBreakdown` | a second pricing engine / `price_units()` beside `cost_nanos` |
| One currency nanodollars | `CostAmount(u128)` (`plane/cost.rs:41`) already = `cost_nanos` unit | LLM/voice/dlopen all converge here; `derive_spend_cents` becomes display projection | a per-plane money type (cents vs micros vs nanos) |
| One breakdown | `CostBreakdown` (`plane/cost.rs:183`) | every priced key a disjoint top-level component; exact-sum by construction | a keyed-breakdown type beside `CostBreakdown` |
| `ExtraRates` open-key rate table | `RateEntryCfg`/`RateNanos` (`cost.rs:86`) | `Arc<BTreeMap>` on the `RateCard`, looked up only when opens present; `RateNanos` stays `Copy` | open rates inside `Copy` `RateNanos` (the Copy cascade) |
| Copy enforcement summary | `TierTokens` (`store.rs:564`) | unchanged; map rides the non-`Copy` ledger/pricing layer | dropping `Copy` on `TierTokens`/`RateNanos`/`RateEntryCfg`/`TierTokensDelta` |
| FFI keyed-unit tail | `hot::Usage` POD (`pod.rs:665`) | append `units_ptr`/`units_len`; `ABI_MINOR` 19→20; golden reseed; core prices via `price` | a keyed POD *variant*; a second FFI charge seam |
| Lease priced through one pricer | `CostHold` (`plane/cost.rs:333`) | reserve/settle amounts produced by `price`, not a voice self-price | a private voice nanodollar pricing path |
| Tier as a component | `CostComponent` (`plane/cost.rs:79`) + closed `ServiceTier` | surcharge = one top-level delta line; discount folds into effective rate | an aggregate scalar × total (breaks exact-sum) |
| `operation`/`plane` facets | `MeterKey` (`governance/mod.rs:983`) | closed enums on the persisted ledger/reporting record | adding them to the hot `MeterKey` (cardinality blow-up) |
| Cohere `billed_units` mapping | `IrUsageDetail` (`ir/types.rs:907`) | explicit tested plane projection into reserved/open keys | folding it as a "zero-edit" behavior change |
| Attribution accrual | `GovState::record_usage` (`state.rs:798`) | signature unchanged; fed the same `Copy` `TierTokens` | a `record_keyed_usage` sibling |
