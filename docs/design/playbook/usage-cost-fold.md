# Money-path design: `IrDuplexUsage → CostBreakdown` fold (voice hard-stop)

Status: design. Scope: the ONE missing link for the mid-session budget hard-stop — pricing a
duplex turn's extracted usage into nanodollars so `cost_settle` accrues real money and
`LeaseState::Exhausted` can fire. **Constraint (STOP condition): reuse the LLM money path
byte-identically — NO new `UsageComponent`/reserved unit, NO new nano constant, NO voice-only
label. Any of those changes golden ledger/pricing/header bytes.**

## 0. What exists vs what is unbuilt

Already wired (the hard-close mechanism itself is real):

- `crates/busbar-voice/src/runtime/session.rs:137-148` — `IrServerEvent::Usage(u)` (i.e.
  `response.done.usage`) → `self.pricing.price(&u)` → `self.lease.settle(nanos)`; on
  `.must_close()` it emits `ResponseCancel` and sets `out.close = true`. The hard-stop plumbing
  is complete.
- `crates/busbar-voice/src/runtime/metering.rs` — `MeteringLease`/`MeteringPort`, `LocalLease`
  (test) and `HostLease`/`HostMeteringPort` (prod), whose reserve/settle/exhaustion contract is
  byte-for-byte the host `CostHold` (`crates/busbar-core/src/plane/cost.rs`) reached through
  `crates/busbar-core/src/plane_host/cost_host.rs` (`reserve_lease`/`settle_lease` →
  `CostHold::settle_partial` → `is_exhausted` = `settled ≥ cap`).

Unbuilt / undesigned (the gap this doc closes):

1. **No rate source.** `Pricing` (metering.rs:83-115) is a plane-PRIVATE five-field per-token
   nano table, and `build_runtime` binds it to **all zeros**
   (`crates/busbar-voice/src/runtime/mod.rs:130-136`). `price()` therefore returns `0`, `settle`
   accrues `0`, `settled` never reaches `cap`, and **the hard-stop can never fire.** This is the
   real defect behind the headline.
2. **No `CostBreakdown` fold.** The session settles a bare `u64` scalar; the itemized,
   protocol-blind `CostBreakdown` that should travel the audit tap (the `breakdown_ptr/_len`
   argument `cost_settle` currently ignores — `cost_host.rs:174-179`) is never built.

## 1. The fold: each `IrDuplexUsage` field → an EXISTING reserved class

`IrDuplexUsage` (`crates/busbar-voice/src/ir/usage.rs`) carries five counts:
`audio_in, audio_out, text_in, text_out, cached`. The neutral money spine has exactly four
reserved unit keys (`crates/api/src/store.rs:565-572`,
`RESERVED_UNITS = [input, output, cache_read, cache_write]`) surfaced through
`busbar_substrate::billing::{TokenUsage, Usage}`.

Audio and text are SEPARATE token classes that price differently (audio dominates) — but the
reserved four are FIXED; you cannot add an `audio_input` unit (that is the forbidden new
`UsageComponent`). The separation is therefore modelled the way the LLM path already separates
two rates for the same reserved unit: **as two rate-card MODEL entries**, priced per `(model,
units)` exactly as `CostModel::derive_spend_cents` /
`busbar_core::cost::price` already iterate (`crates/busbar-core/src/cost.rs:698-723`,
`208-294`). The realtime model contributes two config `models:` lanes — an audio lane and a text
lane — each with its own `rate_card:` entry (its own `RateNanos`).

The fold builds ONE `busbar_substrate::billing::Usage` per lane (reserved keys only, zeros
omitted to stay sparse — the no-zero-entry rule `tier_usage` already honours,
`crates/busbar-llm/src/engine/usage.rs:55-70`):

| `IrDuplexUsage` field | lane (rate-card model) | reserved unit key | existing label |
|---|---|---|---|
| `audio_in`  | `<model>-audio` | `UNIT_INPUT`       | `Prompt`     |
| `audio_out` | `<model>-audio` | `UNIT_OUTPUT`      | `Output`     |
| `text_in`   | `<model>-text`  | `UNIT_INPUT`       | `Prompt`     |
| `text_out`  | `<model>-text`  | `UNIT_OUTPUT`      | `Output`     |
| `cached`    | `<model>-audio` | `UNIT_CACHE_READ`  | `Cache read` |

Notes:
- `cached` is cached INPUT billed at the cache rate → `UNIT_CACHE_READ` (never `cache_write`;
  voice creates no cache). Attribute it to whichever lane owns the cache (audio by default).
- The per-modality detail (`TokenUsage.input_audio`/`input_text`,
  `crates/busbar-substrate/src/billing.rs:37-40`) is the OBSERVABILITY partition of `input`; it
  rides the metering series, not the price. Pricing separation comes from the two lanes, not from
  these fields.
- If audio and text genuinely share one rate for a given deployment, they collapse to a single
  lane and one `Usage` map — still no new unit.

This yields, per turn, a set of `(model, Usage)` pairs — the SAME shape
`ledger_and_meter`/`derive_spend_*` consume — priced by the ONE pricer into a `CostBreakdown`
whose top-level lines are `Prompt`/`Output`/`Cache read` and sum to `total` by
`CostBreakdown::new` construction (`plane/cost.rs:191-251`). Zero new labels.

## 2. Where the rate table comes from (the EXISTING pricing book, not a new one)

The authoritative rates are the top-level `rate_card:` resolved into
`busbar_core::cost::CostModel { rates: HashMap<String, RateNanos> }`
(`crates/busbar-core/src/cost.rs:419-457`), the SOLE cost source. `RateNanos` is the integer
nano projection of the neutral `busbar_substrate::billing::RawTierRates` view via
`RateNanos::from_raw` — `(utok * 1000.0).round()` with the non-finite/negative → 0 clamp
(`cost.rs:135-152`). `RawTierRates` is the seam a plane is allowed to read (it is in substrate,
names no core type — `billing.rs:103-131`).

**Retire the plane-private `Pricing` five-float book.** It is a SECOND rate representation beside
`RateNanos` and the direct cause of drift risk #2 below. Replace it with the neutral rate view
the composition root already holds:

- `build_runtime` today ignores `_section` and `prior`
  (`crates/busbar-voice/src/runtime/mod.rs:94-105`) and binds zeros. The fix threads the resolved
  rate card in through the `prior: Option<&dyn PlaneSlots>` carry-over (or the plane's own
  `parse_section` once that slice lands): for each voice lane, take its `RawTierRates` and project
  with the SAME `from_raw`. `build_runtime_hosted` (the production entry, mod.rs:114-118) binds the
  real host lease; it must ALSO receive the real rates — dev-default zeros are the interim only.
- The projection `RawTierRates → nanos` and the `reserved_nanos` multiply-add
  (`cost.rs:181-186`) must be the **one shared function** both core's `price()` and the voice
  plane call. Recommendation: promote `from_raw` + `reserved_nanos` (pure integer, no core state)
  into `busbar_substrate::billing` so the plane prices its folded `Usage` through the identical
  arithmetic. That is what makes "byte-identical" a compile fact, not a convention.

## 3. The exact settle call, per `response.done.usage`

At `session.rs:137` (`IrServerEvent::Usage(u)`), replace the private-book price with the fold:

```
// 1. fold the extracted turn into per-lane neutral Usage maps (reserved keys only, sparse)
let priced: Vec<(&str, Usage)> = fold_duplex_usage(&u, &self.lanes); // §1 table
// 2. price each lane's Usage with its rate-card RateNanos via the ONE shared pricer → CostBreakdown
let breakdown: CostBreakdown = price_lanes(&priced, &self.rates)?;   // §2 projection
// 3. settle the SCALAR total (u128 nanodollars) against the lease; breakdown is the audit tap
let nanos = u64::try_from(breakdown.total().nanodollars()).unwrap_or(u64::MAX);
if self.lease.settle(nanos).must_close() {
    out.upstream.push(self.codec.write_up(IrClientEvent::Control(IrDuplexControl::ResponseCancel)));
    out.close = true;
}
```

- `settle` accrues ONLY the scalar `total` toward the cap (`CostHold::settle_partial`,
  `plane/cost.rs:389-391`); exhaustion is `settled ≥ cap`, judged against the TRUE money ceiling,
  not the coarse reserve. One settle per `response.done` turn (audio streams many deltas but bills
  once per turn's `usage`), so the hot path stays O(1).
- The `CostBreakdown` is the AUDIT TAP only — core never parses it on the settle hot path
  (`plane/cost.rs:385-391`; `cost_host.rs:174-179` names the `breakdown` bytes explicitly
  audit-only). It is the value journalled (`journal_append_scoped`) and, on the FFI path, passed
  as the currently-unused `breakdown_ptr/_len`. Passing it changes NO settle byte.
- Saturating throughout (`u64::MAX` clamp, `saturating_*` in `CostAmount`/`reserved_nanos`) so a
  runaway turn can never wrap the budget small and dodge the cap.

## 4. Proof it reuses the LLM money path byte-identically

Because voice folds to the SAME reserved-four `Usage` keys and prices through the SAME
`from_raw` / `reserved_nanos` / `price()`, the EXISTING oracles guard voice unchanged
(`crates/busbar-core/src/tests/cost_tests.rs`):

- `price_reserved_four_is_byte_identical_to_cost_nanos` — the reserved-four `CostBreakdown` total
  equals the shared `reserved_nanos` summation (the "parts add up" invariant, per-key).
- `four_tier_card_prices_each_tier_against_its_own_rate`,
  `partial_card_prices_known_models_and_zeroes_the_missing_one`,
  `explicit_zero_rate_model_is_known_and_derives_zero` — per-`(model, units)` pricing, exactly the
  two-lane audio/text shape.
- `rate_nanos_from_cfg_rounds_to_nearest_at_the_nano_boundary`,
  `rate_nanos_from_cfg_clamps_a_non_finite_positive_rate_to_zero_not_max` — the `from_raw`
  projection bytes.
- `CostBreakdown::new` "parts add up" / duplicate-label / containment tests
  (`crates/busbar-core/src/plane/tests/cost_tests.rs`) — the breakdown the fold emits is
  well-formed or it cannot be constructed.

The settle/exhaustion contract is separately guarded by the voice runtime tests
(`crates/busbar-voice/src/runtime/tests.rs`) and the in-flight conformance governance leg, whose
`LocalLease` is byte-for-byte the host `CostHold`. No golden ledger/pricing byte moves because no
label, unit, or constant is added.

## 5. Risk of any new label / variant / constant (STOP)

- **New label** (e.g. `Audio in`/`Audio out`): core surfaces `CostComponent.label` verbatim in
  headers and next to the ledgered total (`plane/cost.rs:12-15`). A new label changes the header
  split bytes and every golden breakdown — and `CostBreakdown::new` rejects a duplicate, so an
  adversarial audio name colliding with `Prompt` would fail the whole breakdown. Use the existing
  `Prompt`/`Output`/`Cache read`. Open-unit keys (`unit:` prefix, `cost.rs:42`) are ALSO a
  voice-only label — forbidden here.
- **New reserved unit / `UsageComponent` variant** (e.g. `audio_input`): changes
  `RESERVED_UNITS: [&str; 4]` (`api/src/store.rs:572`), hence `reserved_nanos`' iteration, every
  `price`/`derive_spend` byte, the store's `UNIT_*` schema, and the usage-migration fold
  (`api/src/usage_migration.rs`). A schema + golden break. Separate rates come from separate
  rate-card MODEL entries, never a new unit.
- **New nano constant** (a voice-only `NANOS_PER_*`): all money is already nanodollars end to end
  (`CostAmount`, `NANOS_PER_CENT`/`NANOS_PER_MICRO`, `cost.rs:57-61`). A second scale factor is a
  drift surface with no benefit and diverges the two planes' arithmetic.

## Top 3 money-path risks

1. **Zero-pricing dev default (the live defect).** `build_runtime` binds all-zero `Pricing`
   (`mod.rs:130-136`), so `price = 0`, `settle` accrues 0, `settled` never reaches `cap`, and the
   hard-stop **never fires**. Until real rates flow from the `rate_card:` into
   `build_runtime`/`build_runtime_hosted`, the marquee guarantee is inert.
2. **Parallel rate-table drift.** The plane-private `Pricing` five-float book is a second rate
   representation beside `RateNanos`; if its projection isn't the shared `from_raw`, voice and the
   LLM plane price identical tokens differently and the ledger disagrees (the exact
   wire-model-vs-config-model bug class documented at `usage.rs:72-94`). Retire it; price through
   the one shared projection.
3. **Audio/text collapse.** Folding `audio_in + text_in` into one `input` unit forces one rate; if
   audio must dominate at its own rate it needs a distinct rate-card model lane (per-`(model,
   units)` pricing), not a distinct unit. Mis-modelling it as a shared unit either loses the audio
   premium (under-charge → hard-stop fires late) or tempts a new unit/label (STOP condition).
