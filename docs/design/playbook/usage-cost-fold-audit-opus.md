# Adversarial money-path audit — `usage-cost-fold.md`

Auditor: Opus 4.8 (read-only code audit). Target: `docs/design/playbook/usage-cost-fold.md`.
Scope: try to BREAK the "fold `IrDuplexUsage` → `CostBreakdown` by reusing the LLM money path
byte-identically, wire real `rate_card` rates into `build_runtime`" design against real code.

## Verdict: SHIP-WITH-CHANGES (two structural blockers; the "free byte-identical reuse" framing is false as written)

The money ARITHMETIC and the 5→4 field mapping are sound and fail-closed. But the design's headline
— "reuse the LLM pricer byte-identically; the only real work is threading real rates into
`build_runtime`" — understates two hard blockers (F1, F2). Neither is cosmetic; both must be resolved
before a single byte of voice pricing exists, and both add NEW, currently-unguarded surface. Ship
only after F1 and F2 are designed explicitly.

---

## Findings (money-path)

### F1 — BLOCKER: core's pricer and `CostBreakdown` are UNREACHABLE from the production voice crate
The whole of §1–§3 ("fold to a `CostBreakdown`", "price through the ONE `price()`", "project with the
SAME `from_raw`/`reserved_nanos`") names types that the production voice build cannot see:

- `crates/busbar-voice/Cargo.toml:41-47` — **"busbar-core is NOT a production dependency of this
  plugin."** `busbar-core` is `optional = true`, pulled ONLY by the `test-support` feature. The
  default/prod closure has no `busbar-core`.
- `busbar_core::cost::price` (`cost.rs:208`), `RateNanos`, `RateNanos::from_raw` (`cost.rs:135`),
  `reserved_nanos` (`cost.rs:181`) are all `pub(crate)` — private to `busbar-core` even for crates
  that DO depend on it.
- `CostBreakdown` lives in `busbar_core::plane::cost` and is **not re-exported through
  `busbar-substrate`** (grep: zero `CostBreakdown`/`plane::cost` hits in `crates/busbar-substrate/`).
- Confirmed: `crates/busbar-voice/` has **zero** references to `from_raw`/`reserved_nanos`/`price`/
  `RateNanos` today.

Consequence: the plane cannot "reuse" the LLM pricer — it can't name it. Making §2/§3 real requires
RELOCATING the pricing arithmetic AND `CostBreakdown` into `busbar-substrate` (a neutral, purity-gated
home), then RE-PROVING byte-identity of the moved code. The design flags promoting
`from_raw`+`reserved_nanos` as a "Recommendation" but treats `price()`/`CostBreakdown` reachability as
solved. It is not. This is the largest piece of real work and it is the opposite of "just wire rates
into `build_runtime`."

### F2 — BLOCKER: two rate-card lanes COLLIDE on the fixed `Prompt`/`Output` labels
`price()` emits fixed reserved labels — `reserved_label(UNIT_INPUT)="Prompt"`, `UNIT_OUTPUT="Output"`,
`UNIT_CACHE_READ="Cache read"` (`cost.rs:46-53`). The design models audio vs text as two `(model,
Usage)` lanes and wants ONE `CostBreakdown` per turn (§3 `price_lanes(...) -> CostBreakdown`).

- Pricing the audio lane and the text lane each produces a component labeled `"Prompt"` and one
  labeled `"Output"`. Feeding both lanes' components into `CostBreakdown::new` → **`DuplicateLabel`**
  (`plane/cost.rs:202-206`) → the whole breakdown is rejected and the turn cannot price.
- Core's `price()` prices exactly ONE `(rate, Usage)` pair; it has NO cross-lane merge. `derive_spend_*`
  DO sum many models — but into a bare scalar (`cost.rs:698-723`), producing NO breakdown/labels.
- Escape routes, all bad: (a) give audio its own label (`"Audio in"`) = the design's explicit STOP
  condition (new label → header/golden byte move); (b) collapse to a single lane and one rate =
  the acknowledged audio/text under-charge (risk #3); (c) write NEW plane-side merge-by-label logic
  that SUMS `audio_in*audio_rate + text_in*text_rate` into one `"Prompt"` line — the only correct
  option, but it is new code guarded by NONE of the cited oracles (they all test single-lane `price()`).

So "two rate-card MODEL lanes, priced by the ONE pricer, into a `CostBreakdown`, no new label" is not
achievable with the existing pricer. It needs a new cross-lane fold. That fold is the untested heart of
the money path.

### F3 — Retiring the plane-private `Pricing` book breaks EXISTING voice tests and public surface
Not a golden LLM-byte oracle (design's claim #3 holds for LLM golden bytes), but retiring `Pricing`
(`metering.rs:83-115`) is not the clean delete the doc implies:
- `runtime/tests.rs:25-33, 53, 82-97` construct `Pricing{...}` and assert `p.price(&u)` == sum.
- `SessionCore::new` takes `pricing: Pricing`; `session.rs:138` calls `self.pricing.price(&u)`;
  `VoiceRuntime.pricing` field (`mod.rs:43`), `VoiceRuntime::new`, and the `pub use ...Pricing`
  (`mod.rs:21`) all ride it.
Retiring it rewrites the runtime's public constructor surface and its tests. Real churn; plan it.

### F4 — 5→4 mapping is lossless ONLY under two lanes; `cached` is single-counter
Under two lanes no class is lost (each field keeps its own rate). Two real limits:
- The design's own fallback "if they share a rate, collapse to one lane" is the under-/over-charge
  case (risk #3, correctly flagged): `audio_in+text_in` at one rate loses the audio premium →
  hard-stop fires LATE.
- `IrDuplexUsage.cached` is a SINGLE `u64` (`ir/usage.rs:26`); the fold pins it to ONE lane's
  `cache_read` ("audio by default", §1 note). If audio-cache and text-cache rates differ, cached text
  is mis-priced. This is an IR-shape limit (there is only one `cached` counter to split), acceptable
  but should be stated as a known mis-price, not hidden.

### F5 — Zero→real pricing does NOT flip any existing oracle (design claim holds)
Attack (5) fails to break it: no test asserts `build_runtime`'s zero-`Pricing`/never-closes behavior
(grep: none). Every voice test uses a nonzero `test_pricing()` or an explicit `Pricing{...}`. The
all-zero bind (`mod.rs:130-136`) is a live DEFECT (hard-stop can never fire — settled never reaches
cap), not a guarded invariant. Flipping to real rates flips no conformance/governance probe. Good.

### F6 — No rounding/overflow divergence that under-charges (design claim holds)
Attack (6) fails to break it. Core `price()` uses `saturating_mul`/`saturating_add` in u128
(`cost.rs:226,237,252`); `reserved_nanos` uses plain u128 `+` but `u64 as u128 * u64 as u128` ≤ ~3.4e38
so a realistic turn cannot overflow (a wrap needs ~10^19 tokens — non-physical). `session.rs:114`
clamps u128→u64 with `unwrap_or(u64::MAX)`; `LocalLease::settle` re-stores the saturated total
(`metering.rs:144-147`). Both paths fail-closed HIGH — a runaway turn over-charges/pins the cap, never
wraps small to dodge it. The current `Pricing::price` is u64-saturating end to end (clamps slightly
earlier) but in the same fail-closed direction. No under-charge divergence.

---

## Oracle coverage (attack 4)
The cited `cost_tests.rs` oracles (`four_tier_card_prices_each_tier_against_its_own_rate:370`,
`partial_card...:476`, `explicit_zero_rate...:447`, `rate_nanos_from_cfg_rounds...:578`,
`..._clamps...:597`, `price_reserved_four_is_byte_identical_to_cost_nanos:633`) guard SINGLE-lane
per-`(model,units)` pricing and the `from_cfg` projection. They guard NONE of the new surface this
design introduces: the `IrDuplexUsage → Usage` fold table (§1), the cross-lane merge-by-label (F2), or
the plane's REACH to the relocated arithmetic (F1). "Existing oracles guard voice unchanged" is true
only for arithmetic that is literally the same code — which it cannot be until F1's relocation lands
and is re-proven.

## Required changes before ship
1. (F1) Design the relocation of the pricer + `CostBreakdown` into `busbar-substrate` (or a substrate
   re-export), and add a byte-identity oracle over the MOVED code. Until then §1–§3 are unbuildable in
   prod.
2. (F2) Specify the cross-lane merge-by-reserved-label fold (sum `Σ lane token×rate` per reserved key
   into ONE `Prompt`/`Output`/`Cache read` line) and add an oracle for it. Do NOT introduce
   `"Audio in"` labels; do NOT collapse to one rate.
3. (F3) Scope the `Pricing` retirement as a public-surface + test change, not a silent delete.
4. (F4) State the single-`cached`-counter mis-price as a known limit.
</content>
</invoke>
