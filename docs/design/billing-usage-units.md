# Generic, plane-pure billing: keyed `usage_units` + billing attribution

Status: design, decision-ready. No code in this change. Target branch
`integration/transport-core` (tip `c8bf89f6`).

## 0. The one-sentence model

A billing record is **"request X, served by provider Y, carried these Z
billable fields."** Concretely:

- **Z** — an open, keyed `units: {key → count}` map priced by the rate card
  *by key*: `spend = ( Σ_k units[k] × rate[k] ) × tier_mult + fee`. Core never
  branches on a key. Key strings (`"input"`, `"output"`, `"audio"`,
  `"cache-1h"`, `"web_search"`…) are plane/operator DATA, exactly like the
  existing metrics-label passthrough and the opaque `Magnitude.unit` word.
- **X + Y** — neutral attribution facets `{virtual_key, pool, plane,
  operation, model, provider}` on the usage/ledger/metering record. Core
  stores and reports them; it never interprets them.

The single most important claim of this document, and the one the audit must
falsify: **every new concept lands as a field or a loop-bound on a type that
already exists.** There is no second ledger, no second rate table, no second
pricing engine, no second usage struct. The 4-tier token model is not thrown
away — its four fields become the four *reserved well-known keys* and remain
the zero-migration fast path.

---

## 1. The spine we are extending (ground truth)

Today one number flows through a chain of **parallel 4-field structs**, from
config to the priced ledger. Every one of them enumerates the same four token
classes `{input, output, cache_read, cache_write}`:

| Stage | Type | Location | Shape |
|---|---|---|---|
| Config rate | `RateEntryCfg` | `busbar-core/src/config/mod.rs:3680` | `{input_utok, output_utok, cache_read_utok, cache_write_utok}: f64` |
| Resolved rate | `RateNanos` | `busbar-core/src/cost.rs:87` | four `u64` nano rates |
| Priced kernel | `RateNanos::cost_nanos` | `cost.rs:117` | **four hardcoded multiply-adds** in `u128` |
| Ledger row | `TierTokens` | `api/src/store.rs:564` | four `u64` counts |
| Flush delta | `TierTokensDelta` | `api/src/store.rs:699` | four `i64` |
| Accrual cell | `ModelCell.cur: TierTokens` | `governance/mod.rs:159`,`:179` | four saturating adds |
| Neutral hub | `TokenUsage` | `busbar-substrate/src/billing.rs:30` | `{input, output, cache_read, cache_creation}` + optional modality |
| Plane→hub proj. | `IrUsage::to_token_usage` | `busbar-llm/ir/types.rs:1015` | 4 totals; **detail dropped** |
| Hub→ledger proj. | `tier_tokens()` | `busbar-llm/engine/usage.rs:53` | `TokenUsage → TierTokens` |
| Spend derive | `derive_spend_cents` | `cost.rs:527` | `Σ_model rate.cost_nanos(tokens)` |
| Accrual entry | `GovState::record_usage` | `governance/state.rs:798` | `(cost,key,pool,model,tokens,now)` |
| Host mirror | `meter_ledger` → `record_usage` | `plane_host/mod.rs:842‑862` | downcast, byte-identical call |

The design **generalizes the fixed quadruple into a keyed map at exactly these
sites and no others.** The four names survive as reserved keys.

The pattern already exists in this codebase twice, and we copy it rather than
invent it:

1. **`IrUsageDetail`** (`ir/types.rs:907`) — the totals on `IrUsage` were kept,
   and richer attribution was added *as an additive optional sub-struct that
   billing deliberately ignores*. `billable_tokens()` and `to_token_usage()`
   never read it. That is precisely the "keep the fast path, add the open
   detail beside it, don't let it change the bill" move — done plane-side.
2. **`rate_card: BTreeMap<String, RateEntryCfg>`** (`overlay.rs:386`,
   `config/mod.rs`) — pricing is *already an open string-keyed map* (keyed by
   model). We add a second keying dimension (by unit) to the entry, not a new
   map beside it.

---

## 2. The extension, precisely

### 2.1 Ledger row — `TierTokens` gains ONE additive field (not a replacement)

```rust
// api/src/store.rs — EVOLVES TierTokens; does NOT introduce a parallel row type.
pub struct TierTokens {
    pub input: u64,        // reserved key "input"        (unchanged, unchanged wire)
    pub output: u64,       // reserved key "output"
    pub cache_read: u64,   // reserved key "cache_read"
    pub cache_write: u64,  // reserved key "cache_write"
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub units: BTreeMap<String, u64>,   // OPEN keys: audio, cache-1h, web_search, …
}
```

Why keep the four fields rather than collapse everything into `units`:

- **Zero data migration.** Every persisted `UsageLedger`/`TierTokens` row
  deserializes byte-identically; `#[serde(default)]` on `units` fills an empty
  map for old rows. A "pure map" `TierTokens(BTreeMap)` would be a breaking
  wire reshape of a *durable, fleet-shared* store row — rejected (see §5).
- **Zero rate-card migration.** The four reserved `*_utok` fields keep pricing
  the four reserved keys.
- **The hot path stays branch-free integer math** on the four fixed fields;
  the map loop runs only when a plane actually emitted extra keys.

`TierTokens::is_zero`/`total`/`saturating_add` extend to fold `units` (all
`saturating_*`, §6). `UsageLedger` is **unchanged** — it already holds
`Vec<ModelTokens>` where `ModelTokens.tokens: TierTokens`, so keyed units
accrue into the *existing* per-model row. **No second ledger.** `TierTokensDelta`
gets the twin `units: BTreeMap<String, i64>` for the additive fleet flush;
`apply_model_delta` already floors at 0 and extends to the map identically.

### 2.2 Neutral hub — `TokenUsage` reserved-key view

`busbar_substrate::billing::TokenUsage` is the neutral currency the metering
sinks read. It already carries `input/output/cache_read/cache_creation` plus
*optional modality* fields (`input_text/audio/image`) — i.e. it already
anticipated "more than four buckets." We add the open map here too:

```rust
pub struct TokenUsage {
    pub input: u64, pub output: u64,
    pub cache_read: Option<u64>, pub cache_creation: Option<u64>,
    pub input_text: Option<u64>, pub input_audio: Option<u64>, pub input_image: Option<u64>,
    pub units: BTreeMap<String, u64>,   // NEW: open billable keys (empty for legacy chat)
}
```

`TokenUsage` is **extended, not replaced** — it stays the single projection
target. The `Billing` enum (`billing.rs:45`) is untouched: `Billing::Tokens`
still wraps `TokenUsage`; the open keys ride inside it.

### 2.3 The projection — where keys are minted (PLANE-SIDE)

This is the crux of plane-purity. The map from provider-specific concepts to
key strings lives **only** in `busbar-llm` (a plane crate), in the two existing
projections:

- `IrUsage::to_token_usage()` (`ir/types.rs:1015`) — today drops
  `IrUsageDetail`. It **generalizes** to also emit open keys *from that detail*
  (the audit findings, §4). The four totals still fill the four reserved
  fields, so chat is byte-identical.
- `tier_tokens()` (`engine/usage.rs:53`) — **generalizes** `TokenUsage →
  TierTokens` to copy `usage.units` into `TierTokens.units`. It is not replaced;
  its signature and the four reserved projections are unchanged.

Both already live plane-side (`busbar-llm`), so no neutral crate learns a key
string. The reserved-key spelling (`"input"` = uncached input, `"cache_write"`
= cache-creation) is fixed by these two functions, matching `tier_tokens`'
existing `cache_creation → cache_write` mapping.

### 2.4 Rate card — `RateEntryCfg` gains a per-key sub-map + a tier table

```yaml
rate_card:
  gpt-4o:                    # existing entries price identically, unchanged
    input_utok: 2.5
    output_utok: 10
    cache_read_utok: 1.25
    cache_write_utok: 3.125
  claude-sonnet:
    input_utok: 3
    output_utok: 15
    cache_read_utok: 0.3
    units:                   # NEW: open per-unit-key rates (micro-units per unit)
      cache-1h: 6
      web_search: 10000      # priced per web-search request, not per token
    tier_mult:               # NEW: pricing MODIFIER, not a bucket
      batch: 0.5
      priority: 1.5
```

```rust
pub struct RateEntryCfg {
    #[serde(default)] pub input_utok: f64,      // reserved key rates — unchanged
    #[serde(default)] pub output_utok: f64,
    #[serde(default)] pub cache_read_utok: f64,
    #[serde(default)] pub cache_write_utok: f64,
    #[serde(default)] pub units: BTreeMap<String, f64>,   // NEW open keys
    #[serde(default)] pub tier_mult: BTreeMap<String, f64>, // NEW multipliers, default 1.0
}
```

`#[serde(deny_unknown_fields)]` stays. Existing rate cards omit `units`/
`tier_mult` and price exactly as today. `RateNanos` (`cost.rs:87`) extends with
the parallel resolved map `units: BTreeMap<String, u64>` (nano rates) built by
`RateNanos::from_cfg` with the same finite/`>0` clamp; `tier_mult` resolves to
an integer basis-point map (e.g. ×1000) so the hot path stays integer.

### 2.5 The priced kernel — `cost_nanos` sums over keys (NOT a new engine)

`RateNanos::cost_nanos` (`cost.rs:117`) is the one arithmetic site. It
generalizes from four multiply-adds to *four multiply-adds plus a loop over
shared open keys, then one tier scaling*:

```rust
pub(crate) fn cost_nanos(&self, t: &TierTokens) -> u128 {
    let mut n =  (t.input as u128)       * (self.input as u128)
               + (t.output as u128)      * (self.output as u128)
               + (t.cache_read as u128)  * (self.cache_read as u128)
               + (t.cache_write as u128) * (self.cache_write as u128);
    for (k, &count) in &t.units {                    // open keys; only k present in BOTH
        if let Some(&rate) = self.units.get(k) {     // core does NOT branch on the string
            n = n.saturating_add((count as u128) * (rate as u128));
        }
    }
    // tier multiplier: a scalar on the whole priced sum, resolved from t.units["tier"] if present.
    n
}
```

The tier multiplier is applied as `n = n × mult / DENOM` (saturating, integer)
using the `tier` reserved-modifier key carried in `units` — *not* a bucket, so
it never adds a line item. `derive_spend_cents` (`cost.rs:527`) and
`derive_spend_micros` are **unchanged**: they already do `Σ_model
rate.cost_nanos(tokens)` and divide once at the end. Summing over keys happens
*inside* `cost_nanos`, so the C1 saturation guard (u128 accumulate → `i64::MAX`
pin, `cost.rs:539‑544`) covers the new terms for free.

### 2.6 Attribution X + Y — extend the metering key + `record_usage`, no new record

The attribution facets **mostly already exist** and are the strongest
"already-there" evidence:

- **`MeterKey = (String key_id, u64 bucket, String model, String provider)`**
  (`governance/mod.rs:983`) already carries `virtual_key`, `model`, `provider`.
- **`GovState::record_usage(cost, key, pool, model, tokens, now)`**
  (`state.rs:798`) already takes `key`, `pool`, `model`.

We extend the metering tuple to `(virtual_key, bucket, pool, plane, operation,
model, provider)` — three added facets — and thread `plane`/`operation` through
the `record_metering`/`ledger_and_meter` seam (`engine/usage.rs:85`). The
budget **ledger** does not need the extra facets (it enforces per `(bucket,
model)`), so `record_usage`'s signature grows only if we want plane/operation in
the *enforcement* pivot; the default is to add them to the **metering series**
(the FinOps read model) where `key_id/model/provider` already live. **No new
record type** — the metering `MeterKey` and the ledger `TierTokens` row absorb
X, Y, and Z respectively.

---

## 3. MANDATORY audit table — extends / generalizes / replaces

| New concept | Existing type it EVOLVES | What changes | Duplicate we deliberately did NOT create |
|---|---|---|---|
| Open `units` counts | `TierTokens` (`store.rs:564`) | +1 additive `units: BTreeMap<String,u64>` field; 4 fields become reserved keys | A parallel `KeyedUsage`/second ledger row |
| Open `units` deltas | `TierTokensDelta` (`store.rs:699`) | +1 `units: BTreeMap<String,i64>`; `apply_model_delta` folds it (floors at 0) | A second flush/reconciliation payload |
| Keyed accrual | `UsageLedger` / `ModelTokens` (`store.rs:601`) | unchanged shape — units ride inside each `ModelTokens.tokens` | A second per-key ledger keyed off `(model,unit)` |
| Neutral keyed hub | `TokenUsage` (`billing.rs:30`) | +1 `units` map beside the reserved+modality fields | A new neutral "GenericUsage" struct |
| Key minting | `IrUsage::to_token_usage` (`types.rs:1015`) | generalizes: also emits open keys from `IrUsageDetail` (was dropped) | A provider-branching mapper inside core |
| Hub→ledger keyed | `tier_tokens()` (`usage.rs:53`) | generalizes: copies `units`; 4 reserved projections unchanged | A replacement projection function |
| Per-key rates | `RateEntryCfg` (`config/mod.rs:3680`) | +`units`, +`tier_mult` maps; 4 `*_utok` unchanged | A second `rate_card_units:` config block |
| Resolved per-key rates | `RateNanos` (`cost.rs:87`) | +`units` nano map, +`tier_mult` bp map | A parallel resolved rate table |
| Keyed pricing | `RateNanos::cost_nanos` (`cost.rs:117`) | +loop over shared keys +tier scalar | A new pricing engine / `price_units()` |
| Spend derive | `derive_spend_cents` (`cost.rs:527`) | **unchanged** (delegates to `cost_nanos`) | A units-aware spend path beside it |
| Keyed accrual entry | `GovState::record_usage` (`state.rs:798`) | unchanged signature; `TierTokens` it takes now carries units | A `record_keyed_usage` sibling |
| Accrual cell | `BudgetCell::accrue` (`gov/mod.rs:179`) | folds `units` with `saturating_add` | A second cell map per key |
| Attribution X/Y | `MeterKey` (`gov/mod.rs:983`) | +`pool,plane,operation` facets | A new "attribution record" table |
| Host mirror | `meter_ledger`→`record_usage` (`plane_host/mod.rs:842`) | unchanged — same downcast, richer `TierTokens` flows through | A second host seam for keyed units |
| Itemized cost | `CostBreakdown` (`plane/cost.rs:183`) | one `CostComponent` **per key**, tiers as children of parents | A new keyed-breakdown type |

---

## 4. The four audit findings resolve as PLANE-SIDE key mappings — zero core edits

All four are already carried, losslessly, in `IrUsageDetail` (`types.rs:907`)
but dropped by `to_token_usage`. The generalized projection (§2.3) emits each as
an open key. Core prices it by key with no code change — only rate-card YAML.

| Finding | `IrUsageDetail` field | Emitted key(s) | Core edit |
|---|---|---|---|
| Anthropic cache-TTL split | `cache_creation_5m_input_tokens`, `cache_creation_1h_input_tokens` (`:923`,`:927`) | reserved `cache_write` stays = 5m; add `"cache-1h"` for the 1h slice (disjoint partition of the total) | none |
| Web search | `web_search_requests` (`:937`) | `"web_search"` = request count; rate card prices per request | none |
| Service tier | `service_tier` (`:944`) | reserved modifier key `"tier"` → `tier_mult[standard\|priority\|batch]` | none |
| Cohere billed units | `billed_input_tokens`,`billed_output_tokens`,`billed_classifications`,`search_units` (`:980`‑`986`,`:931`) | map billed input/output onto reserved `input`/`output` (billed wins over raw); `"classifications"`, `"search"` as open keys | none |

Each is a disjoint key, so it cannot double-count against a reserved total (§6).
Sub-bucket detail that is *already inside* a reserved total (`reasoning_tokens`
⊂ output, `input_audio_tokens` ⊂ input, `tool_use_prompt_tokens` ⊂ prompt) is
**not** emitted as a billable key — it stays pure attribution in the metering
series, exactly as `IrUsageDetail` documents it ("a SLICE OF a total, never an
addition"). This is the anti-double-count rule the plane mapping must enforce.

---

## 5. Migration, back-compat, versioning

- **Existing rate cards**: unchanged. Absent `units`/`tier_mult` ⇒ empty ⇒
  identical pricing. `deny_unknown_fields` preserved.
- **Existing ledgers/deltas**: `#[serde(default, skip_serializing_if =
  empty)]` on every new map ⇒ old rows deserialize with an empty map; new rows
  with no open keys serialize byte-identically (the map is skipped). A node
  running old code that receives a delta carrying `units` ignores the unknown
  field — but the reserved four still reconcile, so the fleet never
  *mis-prices*, at worst under-attributes an open key until the node upgrades
  (documented, at-least-once semantics match the existing flush baseline).
- **Reserved-key registry**: `input`, `output`, `cache_read`, `cache_write`,
  and the modifier `tier` are reserved and mapped to the struct fields. A
  plane emitting one of these in the open `units` map is a bug (double-count
  risk) — validated: the projection routes reserved names to the fields, never
  the map. A short doc-owned registry table is the versioning surface; new
  reserved names are additive.
- **Pure-map alternative (rejected)**: `TierTokens(BTreeMap)` is cleaner on
  paper but breaks the durable, fleet-shared store wire format and forces a
  data migration + a slower hot path for the 99% chat case. The additive-field
  form gives the same expressiveness with zero migration — this is the
  `IrUsageDetail` precedent applied to the ledger.

---

## 6. Correctness

- **Overflow / saturation (ties to C1)**: `cost_nanos` accumulates in `u128`
  (`count: u64 × rate: u64` fits `u128`); the added key loop uses
  `saturating_add`. `derive_spend_cents` keeps the C1 guard — u128 → `i64` via
  `try_from(..).unwrap_or(i64::MAX)` (`cost.rs:544`), so an adversarial
  many-key ledger pins at `i64::MAX` (fail-closed, blocks) and never wraps
  negative-then-floored-to-free. All ledger folds (`TierTokens::total`,
  `BudgetCell::accrue`, `apply_model_delta`) use `saturating_add`/
  `saturating_add_signed`.
- **Rounding across many keys**: rates round to nano-units **once** at resolve
  (`RateNanos::from_cfg`, `cost.rs:98`); counts are exact integers; the priced
  sum accumulates exactly in `u128` and divides by `NANOS_PER_CENT` **once**
  at the very end. Adding keys adds exact integer terms — no per-key rounding
  compounds. The tier multiplier is integer bp scaling before the single final
  divide.
- **No double-count vs existing tiers**: reserved keys own the four token
  classes; open keys are, by the §4 rule, disjoint separately-metered units or
  a re-partition of a reserved total (the 1h cache slice *replaces* part of
  cache_write only if the plane splits it — it must not emit both). Slices of a
  reserved total (reasoning/audio/tool-use) are never billable keys.
- **Determinism**: `BTreeMap` gives sorted, stable key order for the flush
  delta, the `CostBreakdown` components, and cross-node reconciliation.

---

## 7. Attribution granularity + storage

- **Z (units)**: stored in `TierTokens.units` inside the existing
  `UsageLedger`/`BudgetCell` per-`(bucket, model)` row. Enforcement (budget/
  token caps) reads the priced sum, unchanged.
- **X + Y (facets)**: `{virtual_key, model, provider}` already in `MeterKey`;
  add `{pool, plane, operation}`. Stored in the **metering series** (the FinOps
  read model, `record_metering`, `state.rs:866`), NOT the enforcement ledger —
  keeping enforcement keyed exactly as today. Spend pivots by who-pays
  (`virtual_key`/`pool`), what-ran (`plane`/`operation`/`model`), who-served
  (`provider`). Per-tier caps (`tokens_input_cap` … `tokens_cache_write_cap`,
  `cost.rs:145`) remain the reserved-key caps; open-key caps are a future
  additive `tokens_unit_cap: {key → N}` if ever needed (out of scope).

## 8. Plane-purity proof

Neutral crates: `busbar-substrate`, `busbar-core`, `busbar-api`. The claim: no
modality/provider/plane noun appears in them; keys are opaque data.

- The only key *strings* that exist are (a) the five reserved names, fixed in
  the two plane-side projections and the struct field names, and (b) operator
  YAML in `rate_card`. Every open key (`"audio"`, `"web_search"`, `"cache-1h"`,
  `"classifications"`) is minted only in `busbar-llm` (plane) and consumed only
  as a `BTreeMap` lookup in `cost_nanos` — `self.units.get(k)`, never
  `k == "audio"`.
- Audit grep (must return zero hits in neutral crates):
  `grep -rE '"(audio|web_search|reasoning|search|cache-1h|classifications|priority|batch)"' crates/busbar-core crates/busbar-substrate crates/api/src`
  — no key literal in core. Core branches on *presence in the rate map*, not on
  the string.
- This is identical to two shipped precedents: the metrics-label passthrough,
  and `Magnitude.unit: &'static str` (`plane/cost.rs:275`) — "an opaque plugin
  word, never interpreted by core." The `usage_units` map is the plural of that
  same idea.
- The `Billing` enum stays closed and neutral; keys ride *inside*
  `Billing::Tokens(TokenUsage)`, adding no provider/modality variant to core.

## 9. Open questions / risks for auditors to probe

1. **Reserved-vs-open collision**: is routing reserved names to fields (never
   the map) enough, or should the projection *assert* no reserved key appears
   in `units` (debug panic / diag)? Recommend the assert.
2. **Tier multiplier placement**: modifier-key-in-`units` vs a dedicated
   `TierTokens.tier: Option<String>` field. The former keeps the struct at one
   new field; the latter is more explicit. Trade-off: does a `tier` key in a
   *count* map read wrong? (It carries no count; it is a marker.)
3. **Per-key cap enforcement**: deferred. Confirm no current budget semantics
   silently depend on open keys being unpriced.
4. **Cross-node under-attribution window**: an old node dropping unknown
   `units` deltas under-attributes open-key spend until upgrade. Reserved four
   always reconcile. Acceptable? (Matches existing at-least-once flush.)
5. **`CostBreakdown` parent/child for keyed units**: which keys are top-level
   (sum to total) vs children (e.g. `cache-1h` under `cache_write`)? The
   invariant checker (`plane/cost.rs:216`) forbids children exceeding parents —
   the plane must classify keys correctly or construction fails loudly.
6. **`billed_*` vs raw for Cohere**: emitting reserved `input`/`output` from
   `billed_*` (when present) changes the *ledger counts* for Cohere vs today's
   raw totals — is that the intended billing truth? (It is more correct, but it
   is a behavior change, not byte-identical.)

## 10. Executive summary (extends-not-duplicates)

1. `TierTokens` gains ONE additive `units: BTreeMap<String,u64>` field; its
   four fields become the reserved well-known keys. No second ledger row.
2. `RateEntryCfg`/`RateNanos` gain a `units` (and `tier_mult`) map; the four
   `*_utok` rates are untouched and price identically. No second rate table.
3. `RateNanos::cost_nanos` sums four fixed multiply-adds **plus** a loop over
   shared open keys; `derive_spend_cents` is unchanged. No new pricing engine.
4. Keys are minted only plane-side in the two existing projections
   (`to_token_usage`, `tier_tokens`) from the already-carried `IrUsageDetail`;
   the four audit findings become key mappings with zero core edits.
5. Attribution X+Y extends the existing `MeterKey` and metering series
   (`virtual_key/model/provider` already present; add `pool/plane/operation`);
   enforcement ledger keying is unchanged. No new attribution record.

---

# v2 — Post-audit revision (THE BUILD SPEC; supersedes v1 where they differ)

Two independent adversarial audits (Sonnet, Opus) found v1's "additive / zero-edit /
byte-consistent" framing false and flagged 3 blockers (Copy cascade; host-lease FFI POD
cannot carry a map; CostBreakdown exact-sum vs per-key + tier_mult). v2 clears them by
SCOPING and SEPARATING, not by forcing unification.

## Core correction: keyed units are EXTRAS-ONLY, disjoint from the 4 tiers
- `TierTokens` / `TierTokensDelta` / `RateNanos` / `RateEntryCfg` stay EXACTLY as they are —
  **`Copy` preserved, hot enforcement path untouched** (clears BLOCKER: Copy cascade).
- Add `usage_units: BTreeMap<String,u64>` on the **usage/ledger record only** (NOT the Copy
  hot structs), holding ONLY signals OUTSIDE the 4 reserved tiers (e.g. `audio`, `reasoning`,
  `web_search`, `cache_write_1h`). Reserved tier names are FORBIDDEN as unit keys.
- Rate card gains a per-model **extra-key rate map**, looked up ONLY when `usage_units` is
  non-empty — the common no-extras request pays zero added cost and `RateNanos` stays `Copy`
  (extra rates live in a separate non-hot lookup, e.g. `Arc<BTreeMap<key,nano>>` on the
  RateCard keyed by model, NOT inside the `Copy` `RateNanos`).
- **Structural double-count guard (clears MAJOR):** config validation REJECTS a reserved tier
  name in a `units:` rate map; the plane projection NEVER emits a reserved name into
  `usage_units`. Enforced in core (named point + test), not hoped.

## Scope boundaries (clears BLOCKER: host-lease FFI + kills the "two pipelines" confusion)
- Keyed units = **per-request, direct-path (statically-compiled plane)** billing, priced via
  the rate card -> cents. All 4 audit findings are LLM-plane / direct-path -> solved here.
- The **FFI `Usage` POD (dlopen plugins) is UNCHANGED** — single scalar as today; keyed units
  do NOT cross the FFI in 1.6 (documented; a keyed POD variant is future work).
- The **D2 `CostHold` lease (voice/continuous) is UNCHANGED** — voice audio bills via the
  nanodollar lease (already real), NOT via rate-card keyed units. Post-hoc-per-request vs
  continuous-reserve/settle are DIFFERENT surfaces by design; v2 does not pretend they unify.

## Tier multiplier: DEFERRED to 1.7 (clears BLOCKER: CostBreakdown invariant)
- `service_tier` (batch/priority multiplier) is OUT of 1.6. A whole-charge multiplier conflicts
  with `CostBreakdown`'s exact-sum / no-zero-component invariants. Each `usage_units` key becomes
  a **disjoint top-level `CostComponent`** so `Σ components == total` by construction. No
  multiplier -> no invariant conflict.

## Unpriced-present-key: NEVER SILENT (clears MAJOR silent-$0, matches the G2 precedent)
- A `usage_units` key present but unpriced (rate card present, no rate): priced 0 BUT emits a
  rate-limited WARN diagnostic (new `BUSBAR-30xx`) + an `unpriced_usage_key` metric. Never
  silent. (Optional strict-mode reject is future; default = warn.)

## Attribution (X/Y): reporting record, NOT the hot enforcement key (clears MAJOR cardinality)
- Add `{plane, operation, provider}` to the **persisted ledger / usage record** for cost
  reporting (`virtual_key`/`pool`/`model` already there). `operation` is a **closed enum**
  (chat/embeddings/responses/realtime/…), never free text.
- Do NOT add these to the hot `MeterKey` (enforcement keyspace + 262k bound unchanged) and do
  NOT emit open `usage_units` keys as Prometheus labels (`metrics.rs` stays bounded at the 4
  known tiers). Open-key visibility is via the ledger/reports, not unbounded labels.

## Owned edits (v1's "zero core edits" was FALSE — own it)
usage/ledger record (+usage_units), rate entry (+extra-rate map), `cost_nanos` (+disjoint
extras loop -> components), `record_usage`/the two plane-side projections, the **config-schema
snapshot golden** (regen), and the serde `is_zero`/round-trip tests (fold `usage_units`). Cohere
`billed_units` -> an explicit, tested per-dialect mapping-truth change (NOT folded as
"zero-edit"); may defer to 1.7 if it risks changing historical counts.

## Acceptance tests — the build is NOT done until every one passes
1. `Copy` preserved: compile-time assert `TierTokens`/`RateNanos` still `Copy`.
2. Disjointness: config with a reserved name in `units:` -> rejected (test); projection never
   emits a reserved name into `usage_units` (test).
3. Back-compat: existing rate card + a no-extras request prices BYTE-IDENTICALLY to today (golden).
4. CostBreakdown: keyed components satisfy exact-sum (test).
5. Unpriced key -> WARN + metric, priced 0, never silent (red-before-green test).
6. `operation` is a closed enum; `MeterKey` unchanged; no per-key Prometheus label (grep/test).
7. config-schema snapshot + serde `is_zero` regenerated and green.
8. plane-purity `--check` BACKWARDS 0; no unit-key string literal in a neutral crate.
