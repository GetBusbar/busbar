# Rate-card history: money as a lookup over quantities

Status: **owner decision, 2026-09-06.** Supersedes the recommendation of
`docs/design/rate-card-epochs.md` (which recommended "ship B, defer the verb"). That note's
evidence stands and is cited throughout; its conclusion does not.

Scope: what busbar stores when a unit settles, what a price is, what a rate-card edit does, and
what an invoice is. Docs only — no code in this pass.

Every claim about current behaviour is cited to a file and line in this tree
(`origin/integration/oracle-phase0`).

---

## 0. The decision, in the owner's words

> "keep root values and pricing is just a display/lookup concern. If I wanted to change to Yen from
> USD it should be a token > Yen conversion not a token > USD > Yen. And if pricing changes we
> could build a token 5c jan 1 > april 1, 10c april1 > sept etc. It feels wrong to boil it down to
> $ now and lose that flexibility."

and, on what an edit to the past may do:

> think banks. A booked line is never rewritten.

Those two sentences are the whole design. Everything below is their consequence.

**The one-line model.** A posting stores **quantities and the instant they happened**. A rate card
is a **dated, append-only history**. A price is a **lookup**: quantity × the rate of the card in
force at that instant, in the currency asked for, natively. Nothing priced is truth. A back-dated
edit **appends** — it never rewrites — and every line it moves gets an **adjusting entry** of its
own, so the original figure and the correction are both on the record forever.

**The seven rules.**

1. Postings store QUANTITIES per meter class (input, output, cache read, cache write, audio
   seconds, bytes, requests) and the instant they happened (`Arrived`: wall + monotonic). Nothing
   priced is authoritative.
2. Rate cards become an append-only DATED HISTORY: entries `(effective_from, card)` where a card
   gives per-class prices in one or more currencies **natively**. No pivot currency.
3. `price(posting, currency, snapshot) = Σ quantity × rate` of the card effective at the posting's
   instant, in that currency.
4. A config `PUT rate_card` **appends** an entry effective now. Back-dating is an explicit
   operator-signed admin verb — "amend history: from T1 to T2 the card is V" — which is itself a
   journaled record, and which emits **adjusting entries**, so any invoice is reproducible from
   postings + the history **as it stood when the invoice was read**.
5. Budgets, caps and holds decide at admission using the card in force **then**. A hold is a
   reservation, not a price of record.
6. The reconciliation identity becomes `Σ price(quantities, history@S) == legacy spend read at S`,
   exact for a single-entry history.
7. `/usage` after a mid-window card change diverges from 1.5.5. Registered **breaking** with a
   CHANGELOG note. Every other `/usage` byte is identical.

---

## 1. What is true today, precisely

Three pricing postures coexist in this tree, and the design below collapses them to one.

### 1.1 Legacy `/usage` — quantities stored, priced at read from the CURRENT card

A metering row per `(key_id, model, provider)` in a UTC-day bucket holds counts only —
`busbar_api::store::MeteringRow` (`crates/api/src/store.rs:802-818`): `tokens_input`,
`tokens_output`, `tokens_cache_read`, `tokens_cache_write`, `requests`, `billable_requests`,
`key_group_at_use`, and — already present, already crossing the store seam, already
`#[serde(default)]` — **`pricing_version: String`** (`crates/api/src/store.rs:817`). No money.

`GET /api/v1/admin/usage` (`crates/busbar-core/src/admin/v1/json/mod.rs:125`) clones the *current*
cost model at read time (`crates/busbar-core/src/admin/v1/service.rs:2187`) and derives spend per
row (`service.rs:2230` → `derive_spend_micros_row`, `service.rs:101-117`). The function's own
doc comment (`service.rs:95-100`) says it out loud:

> Recomputed on every read (reprice-on-read: a rate-card correction changes historical figures on
> the next read; tokens are the stored truth).

and the contract says it louder (`crates/busbar-core/src/admin/v1/contract/mod.rs:1077-1079`):

> LEDGER RULE (one loud contract sentence): `spend_micros` is a MUTABLE ESTIMATE — derived at read
> time from the operator's CURRENT prices, so a price change re-prices history. Never store it as a
> ledger charge; bill from the raw token split.

**A card edit is live, not boot-scoped.** `PUT /api/v1/admin/config/settings` writes `rate_card`
and `per_request_fee`; the exhaustive destructure at
`crates/busbar-core/src/admin/v1/json/handlers.rs:2778-2797` classifies both as GENUINELY LIVE
(`handlers.rs:2790-2791`, under the comment at `:2786-2788`). No restart, no epoch boundary.

**The recorded consequence.** Oracle cell `billing|rate-card|epoch-mid-window`, recorded from the
published 1.5.5 binary (`48e2800c`) on branch `keep-oracle-cells`: one window, four billable
requests, a hundredfold card written mid-window. Predicted totals were 257,530,000 (priced per row
at charge time), 10,000,000 (restart-to-apply) and 1,000,120,000 (read-time derivation over the
whole ledger). **Recorded: 1,000,120,000.** Every row — including the two before the edit — came
back at the new rate, with no restart, no epoch boundary and nothing in the response saying a card
had changed.

### 1.2 Admission — already a lookup, and it says so

`crates/busbar-unit-admission/src/cells.rs:7-10`:

> There is no money field anywhere — spend is derived from tokens and the current rate table on
> every read, which is why a rate correction reprices everything on the next request with no data
> fix.

`crates/busbar-unit-admission/src/price.rs:6-10` repeats it. The budget comparison
(`crates/busbar-unit-admission/src/decide.rs:358-366`, `:393-395`) derives cents from stored counts
against `Pricer` — which carries **no version, no date, no epoch**
(`crates/busbar-unit-admission/src/price.rs:124-128`) and is rebound per request
(`crates/busbar-unit-admission/src/lib.rs:130`, rationale `lib.rs:107-113`).

**The hold stores a quantity, not a price.** `busbar_caps::Hold`
(`crates/busbar-caps/src/hold.rs:113-124`) holds `reserved: u64` nano-units and nothing else — no
rate, no card version, no class breakdown, no currency. The prices that sized it are consumed and
discarded at `crates/busbar-unit-admission/src/estimate.rs:65`. This is rule 5 already built.

### 1.3 The 1.6.0 root book — priced once, at admission

`busbar_unit_cost::Posting` (`crates/busbar-unit-cost/src/posting.rs:40-50`) stores the answer:
`pre_tier_amount`, `priced_amount`, every `PricedLine` (`posting.rs:19-32`, carrying `quantity`,
`unit_price_nanos` **and** their product), and the `rate_card_version` it was priced against
(`posting.rs:42`, accessor `:54`). Built once by `price()` (`posting.rs:129-183`) against the card
pinned at the door — `RootCard` (`crates/busbar/src/root/kernel.rs:115-144`), `ROOT_CARD.pin()` at
`crates/busbar/src/root/units_llm.rs:464`, reasoning at `units_llm.rs:268-281`, late accruals on
the same pin at `units_llm.rs:695`.

Journaled: `crates/busbar/src/root/durability.rs:423` (`rate_card_version: u64`), written into the
signed body at `durability.rs:440`, `:467`, `:501`; migration marker at
`crates/busbar/src/root/migration.rs:74`, served at `crates/busbar/src/root/units_admin.rs:964-965`.

`ARCHITECTURE.md:856-858` holds both postures at once, on purpose, and calls it a parity clause.

### 1.4 The seams that already point at this design

| Seam | Where | What it is |
|---|---|---|
| `PolicyArchive` / `SealedPolicy` | `crates/busbar-unit-ledger/src/recompute.rs:76-112` | An epoch-keyed archive of cards + tiers, read by the independent recompute so that "pricing a two-day-old posting against today's card would report every price change as a defect" (`recompute.rs:99-101`). **Keyed by opaque epoch, not by date.** Nothing outside the blanket `BTreeMap` impl (`recompute.rs:108`) implements it. |
| Ledger-side `Posting` | `crates/busbar-unit-ledger/src/recompute.rs:137-162` | Already stores quantity-only lines (`PricedLine { class, quantity }`, `recompute.rs:117-122`) beside the amounts. |
| `MeteringRow.pricing_version` | `crates/api/src/store.rs:817` | Already crosses the store seam; `#[serde(default)]`, so filling it is not an ABI break. |
| The placeholder version | `crates/busbar/src/root/units_llm.rs:1539-1546` | *"the version is a constant name rather than a hash of the configuration… The day the books grow that column, this is the one line that fills it."* |
| `Arrived` | `crates/busbar/src/root/units_llm.rs:160-166` | Wall (`ms`) **and** monotonic (`mono`), with the reason spelled out at `units_llm.rs:155-159`: a wall clock DATES a record and cannot order one; the monotonic reading ORDERS it and cannot date it. |

### 1.5 The three vocabularies that must converge first

- `busbar_unit_cost::RateCardVersion` is a **`String`** (`crates/busbar-unit-cost/src/rate.rs:109`).
- `busbar_unit_ledger::recompute::Posting::rate_card_version` is a **`u64`**
  (`recompute.rs:149`), as are `MigrationMarker::rate_card_version`
  (`crates/busbar-unit-ledger/src/migration.rs:176`), `OpeningBalance::rate_card_version`
  (`crates/busbar-unit-ledger/src/legacy.rs:166`) and the journal's two records
  (`crates/busbar/src/root/durability.rs:368`, `:423`).
- The fee is spelled three ways: `per_request_fee` (config,
  `crates/busbar-core/src/config/mod.rs:1225`), `per_request_fee_cents`
  (`crates/busbar-unit-cost/src/rate.rs:230`), `price_per_request_cents`
  (`crates/busbar-unit-admission/src/price.rs:127`).

A lookup over a history needs **one** card identity. §3.1 picks it.

---

## 2. The model

### 2.1 The three layers

```
  layer 0   QUANTITIES        what happened, and when            immutable, journaled, the truth
  layer 1   HISTORY           what things cost, and since when   append-only, journaled, sequenced
  layer 2   LOOKUP            price(layer 0, layer 1, currency)  pure, derived, never stored as truth
```

Layer 0 and layer 1 are both append-only journals. Layer 2 is a pure function. **Nothing is ever
rewritten**, which is what makes an invoice reproducible: you name the two inputs and you get the
same answer forever.

### 2.2 Types

Sketches, in `busbar-unit-cost` unless noted. They are the crate's existing shapes with the
amounts removed and the dating added; the crate keeps its dependency closure (`busbar-caps` only)
and its `#![forbid(unsafe_code)]` / `#![deny(missing_docs)]` posture
(`crates/busbar-unit-cost/src/lib.rs:4-5`).

```rust
/// ISO 4217 alpha-3, upper-case, validated once at card build. Copy, no allocation.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct CurrencyCode([u8; 3]);

impl CurrencyCode {
    /// The currency's minor-unit exponent: USD 2, JPY 0, BHD/KWD/TND 3, CLF 4.
    /// The ONE place a currency's rounding scale is decided.
    pub fn minor_exponent(self) -> u8;
    /// Nano-units per one minor unit: 10^(9 - minor_exponent). USD => 10_000_000 (today's
    /// `NANOS_PER_CENT`, `crates/busbar-unit-cost/src/lib.rs:54`); JPY => 1_000_000_000.
    pub fn nanos_per_minor(self) -> u128;
}

/// One (lane, class) cell of a card, priced in every currency the card names. NO PIVOT: each
/// currency's rate is a first-class configured number, never a conversion of another.
#[derive(Clone, Debug)]
pub struct CellPrices(BTreeMap<CurrencyCode, u64>);   // nano-units of that currency's MAJOR unit

/// A card: prices keyed lane -> class -> currency, plus the flat fee per currency.
/// Same nested-map lookup shape as today (`crates/busbar-unit-cost/src/rate.rs:129-143`) with one
/// more level, so a lookup is still three borrowed-key steps and zero allocations.
#[derive(Clone, Debug)]
pub struct RateCard {
    present: bool,
    prices: BTreeMap<String, BTreeMap<String, CellPrices>>,
    fees: BTreeMap<CurrencyCode, i64>,      // minor units per billable request, clamped >= 0
    currencies: BTreeSet<CurrencyCode>,     // exactly the set every priced cell must name
}

/// The entry's own number: dense, monotone, assigned on append. THIS is the card identity, and it
/// replaces `RateCardVersion(String)` (rate.rs:109) and the four `u64` spellings of §1.5 alike.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct HistorySeq(pub u64);

/// Why an entry exists. The distinction is the whole audit trail.
#[derive(Clone, Debug)]
pub enum Author {
    /// Sealed at Bootstrap or Migration: the opening entry.
    Opening,
    /// A `PUT /config/settings rate_card`, or a config reload. Effective from `appended_at`.
    Config { policy_epoch: u64 },
    /// The signed amend verb (§4). Effective from an instant the operator named.
    Amend { operator_fingerprint: String, reason_hash: [u8; 32] },
}

/// One entry of the history.
#[derive(Clone, Debug)]
pub struct CardEntry {
    pub seq: HistorySeq,
    /// Inclusive, wall-clock milliseconds. The same scale `Arrived::ms` is in
    /// (`crates/busbar/src/root/units_llm.rs:163`).
    pub effective_from: u64,
    /// Exclusive. `None` = open-ended.
    pub effective_until: Option<u64>,
    pub card: RateCard,
    /// When the entry was WRITTEN. Equal to `effective_from` for `Config`; strictly greater for a
    /// back-dated `Amend`. The two being different fields is what makes a back-date visible.
    pub appended_at: u64,
    pub author: Author,
}

/// The whole history: append-only, ordered by `seq`, NEVER by `effective_from`.
#[derive(Clone, Debug, Default)]
pub struct History { entries: Vec<CardEntry> }

impl History {
    pub fn head(&self) -> HistorySeq;
    /// Everything with `seq <= at`. THE reproducibility primitive: an invoice cut at `S` is
    /// re-derivable forever by asking for `snapshot(S)`.
    pub fn snapshot(&self, at: HistorySeq) -> HistoryView<'_>;
    /// The only mutator. Returns the new head. Never modifies an existing entry.
    pub fn append(&mut self, e: CardEntryDraft) -> HistorySeq;
}

pub struct HistoryView<'a> { entries: &'a [CardEntry], at: HistorySeq }

impl HistoryView<'_> {
    /// THE RESOLUTION RULE. Among entries with `seq <= at` whose
    /// [effective_from, effective_until) covers `t`, the one with the HIGHEST `seq` wins.
    ///
    /// Overlap is legal and is the point: an amend does not delete the entry it corrects, it
    /// out-ranks it. `None` means no entry covers `t` at all — a hole, which is a refusal, never
    /// a zero (§3.4).
    pub fn card_at(&self, t: u64) -> Option<(HistorySeq, &RateCard)>;
    pub fn seq(&self) -> HistorySeq;
}
```

And the posting, with the amounts gone:

```rust
/// One quantity against one declared class. Same shape as
/// `busbar_unit_ledger::recompute::PricedLine` (recompute.rs:117-122) — which is already this.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Quantity { pub class: String, pub amount: u64 }

/// WHAT HAPPENED. No money in it anywhere.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Posting {
    pub lane: String,
    pub quantities: Vec<Quantity>,
    pub fee_count: u64,
    pub tier_bp: u32,
    /// The instant, both readings. Dates the record AND orders it
    /// (`crates/busbar/src/root/units_llm.rs:155-159`).
    pub arrived_ms: u64,
    pub arrived_mono: u64,
    pub estimated: bool,
    /// A CACHED LOOKUP, never a truth: see §6.
    pub cached: CachedPrice,
}

/// What the node computed at settlement, kept so a read is cheap and a recompute has something to
/// compare against. Re-derivable from `Posting` + `History` at any time; if it disagrees with the
/// lookup, the LOOKUP wins and the divergence alarms.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CachedPrice {
    pub history_seq: HistorySeq,   // the head at settlement
    pub card_seq: HistorySeq,      // the entry `card_at(arrived_ms)` resolved to
    pub currency: CurrencyCode,    // the bucket's currency
    pub pre_tier_nanos: u128,
    pub priced_nanos: u128,
}
```

### 2.3 The lookup

```rust
/// price(posting, currency, view) — the whole of layer 2.
pub fn price(
    view: &HistoryView<'_>,
    posting: &Posting,
    currency: CurrencyCode,
) -> Result<Priced, Unpriceable>;

pub struct Priced {
    pub card_seq: HistorySeq,
    pub currency: CurrencyCode,
    pub lines: Vec<PricedLine>,   // class, quantity, unit_price_nanos, amount_nanos, unpriced
    pub pre_tier_nanos: u128,
    pub priced_nanos: u128,
}

pub enum Unpriceable {
    /// No entry of the snapshot covers the posting's instant.
    NoCardInForce { at: u64 },
    /// The card in force does not name this currency. NEVER converted from another.
    CurrencyNotPriced { card_seq: HistorySeq, currency: CurrencyCode },
    /// A present card names no entry for the lane — today's fail-closed rule
    /// (`crates/busbar-unit-cost/src/rate.rs:243-245`).
    LaneUnpriced { card_seq: HistorySeq, lane: String },
}
```

The arithmetic, in the fixed order, unchanged from `price()` at
`crates/busbar-unit-cost/src/posting.rs:129-183`:

1. Resolve `(card_seq, card) = view.card_at(posting.arrived_ms)?`.
2. Resolve `rates = card.lane_rates(posting.lane, currency)?`.
3. Per quantity: `amount_nanos = u128(quantity).saturating_mul(u128(rate))`; a class the card is
   silent about is `unpriced: true` and prices at nothing — never a silent nothing, always a
   visible one (`posting.rs:144-154`).
4. The fee joins as a line of its own, class `FEE_CLASS = "fee"` (`posting.rs:16`), unit price
   `fee_minor × currency.nanos_per_minor()` — an exact multiple of one minor unit, which is the
   property that makes the projection exact (`rate.rs:235-239`, test at
   `crates/busbar-unit-cost/src/tests/rate_tests.rs:93`).
5. `pre_tier_nanos` = saturating sum over every line **including** the fee (`posting.rs:169-171`).
6. `priced_nanos = apply_tier(pre_tier_nanos, tier_bp)` — one saturating multiply, **one** divide
   (`posting.rs:119-121`), never a sum of per-line floors (test at
   `crates/busbar-unit-cost/src/tests/posting_tests.rs:296`).
7. Nothing is truncated until a projection asks (§3.3).

**Purity.** `price` reads no clock, no store, no config. `HistoryView` is a borrowed slice.
An auditor holding the postings and the history re-derives every invoice by hand — which is the
crate's stated bar (`crates/busbar-unit-cost/src/lib.rs:9-10`).

---

## 3. Currency, natively

### 3.1 No pivot, ever

A card's cell is `CellPrices: BTreeMap<CurrencyCode, u64>` — one configured integer rate per
currency. `price(·, JPY)` reads the JPY rate. There is no USD in the path, no FX table, no
conversion, and no rounding of a conversion. **token → Yen, not token → USD → Yen.**

Two consequences the design accepts on purpose:

- A currency a card does not name is `Unpriceable::CurrencyNotPriced` — a 400 on a read that asked
  for it, and a boot refusal if a bucket's declared currency is unpriced by the card in force at
  boot. It is never a converted figure and never a zero.
- Two currencies never sum. `Σ` is per currency. This is already the shape of the constraint at
  `ARCHITECTURE.md:850` (*"currency is a 1.6.0 addition (one per bucket; mixing is a boot
  refusal)"*) and matches the `TierMismatch` precedent at `ARCHITECTURE.md:991`.

### 3.2 The abstract unit is a currency

1.5.5's numbers are "abstract cost units" with no currency
(`crates/busbar-core/src/config/mod.rs:1221`, `crates/busbar-unit-cost/src/lib.rs:52-53`), and
`/usage` labels them `"USD"` through a synthetic serializer
(`crates/busbar-core/src/admin/v1/contract/mod.rs:1084-1089`). The migration reads a 1.5.5 card as
a card naming exactly one currency, `USD`, whose minor exponent is 2 — so
`nanos_per_minor() == 10_000_000 == NANOS_PER_CENT`
(`crates/busbar-unit-cost/src/lib.rs:54`) and every figure is bit-identical. Nothing about a 1.5.5
deployment changes.

### 3.3 Rounding, per currency minor unit

The rules, in one place, generalising `crates/busbar-unit-cost/src/project.rs:23-33`:

| Step | Rule | Today |
|---|---|---|
| Config decimal → integer rate | `round(micro × 1000)`, half away from zero, **once**, per currency, at card build. Non-finite, non-positive or overflowing ⇒ 0. | `nano_rate`, `crates/busbar-unit-cost/src/rate.rs:33-40` — unchanged |
| Accumulate | `u128` nano-units, every multiply and add saturating | `posting.rs:152,165,171`; `rate.rs:306-307` — unchanged |
| Tier | one saturating multiply, one truncating divide, over the SUM | `apply_tier`, `posting.rs:119-121` — unchanged |
| Project to minor units | `minor_of(nanos, ccy) = nanos / ccy.nanos_per_minor()`, truncating toward zero, **exactly once**, at the very end; floored at 0 | `cents_of`, `project.rs:23-26` generalised |
| Project to micro-units | `nanos / 1_000`, truncating, **no floor** | `micros_of`, `project.rs:31-33` — unchanged, and the floor asymmetry stays load-bearing (`project.rs:29-30`, PB-16) |
| Narrowing to `i64` | `try_from(...).unwrap_or(i64::MAX)` — saturate, never wrap | `project.rs:24,32,53,57,71,76` — unchanged, and the reason (`project.rs:19-22`) is that a wrapping cast lands negative and the floor turns it into free |

Worked: USD `exp = 2`, `nanos_per_minor = 10^7` — cents, identical to today. JPY `exp = 0`,
`nanos_per_minor = 10^9` — whole yen. BHD `exp = 3`, `nanos_per_minor = 10^6` — fils.

**The one law that gets more load-bearing, not less.** A lookup evaluates the arithmetic at every
read rather than once at settlement, so the single-rounding-law property matters more. It is
already known to have broken here: `crates/busbar-unit-admission/src/price.rs:57-69` records that
the admission unit once carried a second copy of the rate conversion, a clamp landed on one and not
the other, and a request was **judged at one rate and billed at another, silently**. The design
keeps the existing remedy — admission calls `busbar_unit_cost::nano_rate`
(`crates/busbar-unit-admission/src/price.rs:70-82`) — and extends it: `minor_of` and `apply_tier`
are likewise single-sited, and the agreement test at
`crates/busbar-unit-cost/tests/rate_conversion_agreement.rs:63` gains a currency axis.

One asymmetry is deliberate and stays: hold sizing rounds **up** (`div_ceil`,
`crates/busbar-unit-admission/src/estimate.rs:76`) while pricing truncates
(`recompute.rs:421-423`, `posting.rs:119-121`). A hold is a reservation; over-reserving is
conservative, over-billing is not.

### 3.4 A hole in the history is a refusal, not a zero

`card_at` returning `None` is `Unpriceable::NoCardInForce`. Reads report it per row (never a
silent 0); settlement refuses under `allow_unpriced: false` exactly as a missing lane does today
(`ARCHITECTURE.md:1030`, `Refused(Admit, Unpriced)`). The opening entry (§7) is what makes a hole
impossible in practice: it is effective from instant 0 with no end, so every instant is covered
unless an amend deliberately carves a window out — which the verb refuses to do (§4.2).

---

## 4. Editing the history

### 4.1 A config `PUT` appends

`PUT /api/v1/admin/config/settings` with a `rate_card` / `per_request_fee` body appends
`CardEntry { seq: head+1, effective_from: now, effective_until: None, author: Config { policy_epoch } }`
and closes the previous open entry at `now`. It stays GENUINELY LIVE
(`crates/busbar-core/src/admin/v1/json/handlers.rs:2790-2791`) — no restart, same ergonomics, same
1.5.5 wire bytes. The card's all-or-nothing completeness rule is unchanged
(`crates/busbar-core/src/config_validate/mod.rs:1431-1462`, the paste-able stub at `:1444-1455`)
and now also requires: every priced cell names the **same currency set**, else the same class of
refusal.

What changes is only what it means: an appended entry prices what happens **after** it. It does not
touch history. That is the `/usage` divergence of §9.

### 4.2 The amend verb

```
POST /api/v1/admin/ledger/amend-rate-history
{
  "from":       <epoch ms, inclusive>,
  "until":      <epoch ms, exclusive> | null,
  "card":       { ...complete card, every lane, every class, every currency... },
  "reason":     "<free text, hashed into the record, never the record itself>",
  "signature":  "<detached operator signature over the canonical payload>"
}
→ 200 { "history_seq": <new head>, "entries_adjusted": N, "delta": { "<CCY>": "<amount>" } }
```

Kebab-case POST under the admin prefix, exactly the binding rule the other 17 verbs follow
(`ARCHITECTURE.md:928-933`).

**Refusals.** No operator signature ⇒ refused (`Refused(Approve, ...)`). The verb joins the
**irreducible set** — required in both dual-control postures — because it moves money already
booked, which puts it beside `adjust`/`resolve_dispute` above `adjust_threshold`
(`ARCHITECTURE.md:952-956`). A `from`/`until` pair that would leave an instant covered by no entry
is refused (`HistoryHole`). A partial card is refused, as today. A `from` in the future is refused
(that is `PUT`, not an amend).

**Effects, in order, in one journal batch:**

1. **Append** `CardEntry { seq: head+1, effective_from: from, effective_until: until, card,
   appended_at: now, author: Amend { operator_fingerprint, reason_hash } }`. Journaled as a
   `RecordClass::Policy` record (`crates/busbar-unit-wal/src/journal.rs:153`) — the 14 record
   classes stay 14, because their discriminants are pinned to a byte on the medium
   (`journal.rs:143-146`) and a fifteenth would be unreadable to a node that has not upgraded.
2. **Emit adjusting entries.** For every `(window, TotalsKey)` carrying at least one posting whose
   `arrived_ms ∈ [from, until)`, one `RecordClass::Transaction` **repricing record**:

   ```rust
   pub struct Repricing {
       pub key: TotalsKey,
       pub window: WindowStart,
       pub currency: CurrencyCode,
       pub from_seq: HistorySeq,        // the head BEFORE the amend
       pub to_seq: HistorySeq,          // the head AFTER it
       pub old_card_seq: HistorySeq,    // what card_at resolved to under from_seq
       pub new_card_seq: HistorySeq,    // what it resolves to under to_seq
       pub quantities: Vec<Quantity>,   // summed over the affected postings, per class
       pub fee_count: u64,
       pub old_nanos: i128,
       pub new_nanos: i128,
       pub delta: i128,                 // new - old; the only figure that moves a balance
       pub operator_fingerprint: String,
       pub reason_hash: [u8; 32],
       pub postings: u64,               // how many lines it covers
   }
   ```

   Signed by the operator, sealed on the chain, and **never** collapsed into the postings it
   describes.
3. **Move the balance by the delta only.** `Ledger::record_adjustment`
   (`crates/busbar-unit-ledger/src/settle.rs:244`) takes `Σ delta` into `Totals::adjustments`,
   which is the cell the §4.2 identity already carries (`identity.rs:83-90`; the openapi
   `TotalsCell.adjustments`). **No posting is rewritten. `settled` for a booked line never moves.**
   The identity closes with no new term.
4. Alarm, journal, and surface on the ledger endpoint (PB-16), like every other irreducible verb.

**Why per (window, bucket) and not per posting.** A day's postings for one principal are one line
on an invoice; the correction has to be legible beside that line. Per-posting records would be
correct and unreadable, and would multiply the journal by the traffic rate rather than by the
number of balances. The record carries `postings: u64` so the granularity it summarises is stated.

### 4.3 Idempotency

The verb takes the standard `Idempotency-Key` (PB-21), and is additionally idempotent by
construction on a replay: an amend whose `(from, until, card_hash, operator_fingerprint)` equals the
newest `Amend` entry is a no-op returning the existing `history_seq`. Two *different* amends over
the same window both apply, in `seq` order; the second out-ranks the first and its adjusting entries
are computed against the first's result, not against the original. That is what "never rewritten"
requires.

---

## 5. Reading money: snapshots, not recomputes

### 5.1 `as_of` on every ledger read

Every `/api/v1/admin/ledger/*` read gains an optional `?as_of=<history_seq>` and an optional
`?currency=<CCY>`. Default: `as_of` = the current head; `currency` = the bucket's declared currency.
Every response echoes both, plus the head, at the top level:

```json
{ "history_seq": 7, "head": 9, "currency": "USD", "rows": [ ... ], "adjustments": [ ... ] }
```

- `history_seq` is what the figures were computed against. **A statement or invoice is cut AS OF a
  snapshot**, and reconstructing it is `?as_of=<the seq printed on it>`.
- `head` is what the history is now. `history_seq < head` tells a reader, without asking, that the
  world has moved.
- `adjustments` lists the repricing records whose `to_seq <= as_of` that touch the rows in this
  answer, each with `from_seq`, `to_seq`, `old_nanos`, `new_nanos`, `delta`, `operator_fingerprint`,
  `reason_hash`. **A read against the latest history reports the adjusting entries that make it
  differ from any earlier snapshot.** Money reads never recompute silently.

`?as_of` above the head is a 400. `?as_of` below the retention floor is a 410 naming the floor —
the history itself is never purged (it is small and it is the thing that makes old statements
reproducible), but the postings behind an answer are subject to §4.2 retention.

### 5.2 What this makes true

- Two reads at the same `as_of` are byte-equal, forever.
- Two reads at different `as_of` differ by exactly `Σ delta` over the adjusting entries between
  them — and both reads say so.
- An invoice sent on the 3rd, cut at `as_of = 7`, is regenerable on the 30th at `as_of = 7`,
  byte for byte, whatever has happened to the card since.
- The 1.5.5 hazard — an invoice that is only true at the instant it was rendered, with nothing in
  the response saying anything changed — is structurally impossible.

---

## 6. `priced_amount` and `rate_card_version`, as already journaled

They stay on the wire. Their **meaning** changes, and the change is a demotion.

- `rate_card_version: u64` (`crates/busbar/src/root/durability.rs:368`, `:423`; the openapi
  `MigrationMarker.rate_card_version`) becomes the `HistorySeq` — already a `u64`, already at a
  known offset (`durability.rs:440` writes `body.num(self.rate_card_version)`; the marker's decoder
  reads it at offset 80 of 88, `durability.rs:511-530`). This is the column
  `units_llm.rs:1539-1546` said would one day be filled. **Today it is dead**: every production
  `PostingStamp` in the tree hardcodes `rate_card_version: 0`
  (`crates/busbar/src/root/units_llm.rs:1498`, `units_mcp.rs:1402`, `units_a2a.rs:643`,
  `units_voice.rs:1844`), and the only real version anywhere is the constant
  `RateCardVersion::new("root-llm")` (`units_llm.rs:1563`).
- `priced_amount` becomes `CachedPrice.priced_nanos`: **a cached lookup, re-derivable, never
  authoritative.** It is kept because a totals read that had to re-price a day of postings on every
  request would be a different performance profile, and because a stored figure to compare against
  is what makes tampering detectable.
- **The recompute becomes the arbiter, not the auditor.** Today `recompute` compares the stored
  `priced_amount` against `Σ quantity × price` from the sealed policy and alarms on divergence
  (`crates/busbar-unit-ledger/src/recompute.rs:391-412`, `Divergence::Priced` at `:409`;
  `ARCHITECTURE.md:750-757` requires the watermark to reach the journal head every tick). Under the
  lookup model the recompute reads `card_at(arrived_ms)` from the history instead of `card(version)`
  from a `SealedPolicy`, and **where they disagree the lookup wins** and the cache is corrected in
  place with a `Reconciliation` entry. `Divergence::PreTier` and `Divergence::Priced`
  (`recompute.rs:173-...`) stop being "a defect somewhere" and become "the cache is stale", which
  is a normal, expected, journaled event after an amend.
- `RateCardVersion(String)` (`crates/busbar-unit-cost/src/rate.rs:109`) is deleted. The constant
  `RateCardVersion::new("root-llm")` (`crates/busbar/src/root/units_llm.rs:1543`) goes with it.
- `MeteringRow.pricing_version: String` (`crates/api/src/store.rs:817`) is filled with the
  `HistorySeq` in decimal — `#[serde(default)]`, so no store ABI moves (PB-93 window unchanged),
  and a 1.5.5 store that ignores it keeps working.

---

## 7. Migration from 1.5.5

**A single-entry history, effective at epoch 0.**

```rust
CardEntry {
    seq:              HistorySeq(0),
    effective_from:   0,
    effective_until:  None,
    card:             <the operator-named 1.5.5 card, one currency: USD>,
    appended_at:      <the Migration seal's wall clock>,
    author:           Author::Opening,
}
```

Then `card_at(t)` returns entry 0 for every `t`, and `price(posting, USD, snapshot(0))` is
**arithmetically identical** to `derive_spend_micros` at that card
(`crates/busbar-unit-cost/src/project.rs:64-81`) — same rates, same order, same saturation, same
single truncation. That equality is the migration's acceptance test (§10), and it is the sense in
which rule 6 says *"exact for a single-entry history"*.

The migration marker keeps its shape (`crates/busbar-unit-ledger/src/migration.rs:162-183`, opening
checkpoint `OPENING_CHECKPOINT_SEQ = 0` at `:69`, sealed at `:391`, `drawn == settled` at
`:320-327` so the identity closes at zero) with `rate_card_version = 0` now meaning `HistorySeq(0)`
rather than an operator's unchecked assertion.

**The one honesty gap this closes.** `docs/design/rate-card-epochs.md:280-284` named it: the
marker's `rate_card_version` is the operator's claim about what history was earned under, and today
nothing checks it. Under a history it is not a claim at all — entry 0 IS the card, it is journaled,
and if it was the wrong card the fix is an `Amend` from 0 to the migration instant, which leaves
adjusting entries. A wrong opening is now **fixable and visible** instead of unfixable and invisible.

**Pre-migration legacy rows** carry no instant finer than the UTC day. They price at entry 0 —
which is correct, because entry 0 is what they were earned under by definition.

---

## 8. Interactions

### 8.1 The kernel settlement table (ARCHITECTURE §2.2)

Every row of the table at `ARCHITECTURE.md:337-357` is a rule about **which quantity** to post, not
about money, and every one survives verbatim. The amendment (document B) changes only the wording
where a row implies the amount is the stored thing:

| Row (`ARCHITECTURE.md`) | Under the history |
|---|---|
| `Completed`, locator arrived → *located usage* (`:341`) | unchanged — a quantity |
| `fee_count` (`:342`) | unchanged — a count, kernel-derived, decided at the first relayed response frame and never reversed |
| `requests` dimension (`:343`) | unchanged — a count, never released |
| `Completed`, required locator absent → **ZERO** (`:344`) | unchanged: zero **quantity**, so the lookup yields zero money at every card and every snapshot. Stronger than today, where "`priced_amount = 0`" was a stored zero |
| live non-Completed, locator arrived (`:345`) / absent (`:346`) | unchanged |
| crash-recovered `Dispatched` present / absent (`:347-348`) | unchanged — quantities, `recovered` / `voided` |
| two evidence sources disagree → *the lower* (`:349`) | unchanged — the lower **quantity**, which is now unambiguous (comparing two prices was always comparing two lookups) |
| three-way lane mismatch → *the cheaper entry* (`:350`) | **needs the amendment**: "cheaper" is a price, so it is now "the cheaper entry **at the card in force at the unit's instant, in the bucket's currency**". Deterministic, and it does not move when the card does |
| refused `HoldAccrual` → the child's own posting (`:351`) | unchanged |
| settle record lost → retained and re-appended (`:352`) | unchanged |

### 8.2 `busbar-unit-cost`

Owns layers 1 and 2 entirely: `History`, `HistoryView`, `CardEntry`, `CurrencyCode`, `RateCard`,
`price`, `apply_tier`, `minor_of`, `micros_of`, `nano_rate`. `Posting` loses
`pre_tier_amount`/`priced_amount`/`rate_card_version` as fields and gains `arrived_ms`/`arrived_mono`
and `CachedPrice`. `PricedLine` (`posting.rs:19-32`) becomes an output of `price`, not a stored
thing — its redundancy (quantity, rate and product all stored) is the thing being removed.
`derive_spend_cents`/`derive_spend_micros` (`project.rs:46-81`) become thin wrappers over `price`
against a named snapshot, which is what makes the identity test (§10) a tautology rather than a
coincidence. Dependency closure unchanged (`busbar-caps` only).

### 8.3 `busbar-unit-ledger`

- `recompute` (`recompute.rs`) drops its private `RateCard` (`:47-74`) and `SealedPolicy`
  (`:78-99`); `PolicyArchive` (`:103-107`) becomes `HistoryArchive` returning a `HistoryView`.
  `Divergence::CardMissing`/`PolicyMissing` become `NoCardInForce`; `PreTier`/`Priced` become
  cache-staleness findings that self-correct (§6).
- `settle` (`settle.rs:135-212`) is unchanged in shape: it already takes `priced_nanos: u128` as an
  **argument** (`settle.rs:140`, `:158`) and hands it to `Posted::settle` (`:162`). The caller now
  gets that number from `price(·, ·, head)` instead of from a stored posting. The four-figure move
  at `settle.rs:184-187` is untouched.
- `identity::residual` (`identity.rs:82`) is untouched — it is a function of two `Totals`
  snapshots and nothing else (`identity.rs:28-33`), and the amend's delta rides `adjustments`,
  which is already a term.
- **The hardest interaction, named:** `Checkpoint::encode_body` digests 12 `Totals` money fields
  (`crates/busbar-unit-ledger/src/checkpoint.rs:293-306`) into a signed body. Those figures are a
  **materialised view of a lookup at a named snapshot**, so the checkpoint body gains
  `history_seq` as a length-prefixed field beside them (`checkpoint.rs:316` `push_text` /
  `push_num`). A checkpoint therefore means "these totals, at that history" — which is exactly
  what makes it re-derivable. Sealed bodies are never rewritten by an amend; an amend that touches
  a window behind an anchored checkpoint is expressed **forward**, as adjusting entries, which is
  why §4.2 step 3 moves `adjustments` and not `settled`.

### 8.4 `busbar-unit-admission`

Barely moves, because it is already this design (§1.2). `Pricer`
(`crates/busbar-unit-admission/src/price.rs:124-128`) gains a `card_seq: HistorySeq` and a
`currency: CurrencyCode` for reporting, and is constructed from `card_at(now)` rather than from the
live config. Its arithmetic (`price.rs:190-210`) is unchanged; it keeps delegating the rate
conversion to `busbar_unit_cost::nano_rate` (`price.rs:70-82`).

**The decision is never re-run.** A request admitted under the card in force then stays admitted:
`try_admit` (`decide.rs:252-437`) is check-then-charge at one instant, and PB-22 pins its refusal
set to 1.5.5's. An amend can move what a past unit is *billed*; it can never retroactively refuse a
unit that was served. Budgets, caps and holds decide with the card in force then — rule 5.

**A hold is a reservation, not a price of record.** Already true: `Hold`
(`crates/busbar-caps/src/hold.rs:113-124`) stores nano-units and no rate. Under the history, hold
and bill agree by construction on the ordinary path — the hold is sized at `card_at(arrived)` and
the bill is priced at `card_at(arrived)`, the same entry. After an amend they differ, and the
difference is an adjusting entry, never a re-decided admission.

**Refunds and overdraft.** Both are quantity-level and unchanged. A refund decrements
`billable_requests` only (`decide.rs:507-521`) — never `requests` (`cells.rs:64-66`), so a caller
cannot escape a cap by hammering failures. Overdraft is what a spend could not be backed by
(`hold.rs:255-259`); it is a quantity of nano-units at the instant, and it prices through the same
lookup. `Overdraft` postings, `late_accrual` postings and reversals all price at
`card_at(their own instant)`.

**The fee.** Three spellings converge on one: the card's `fees: BTreeMap<CurrencyCode, i64>`, in
minor units, clamped `>= 0` at build (`rate.rs:157`, `:179`), lifted to nano-units by
`currency.nanos_per_minor()`. It posts even with no card (`ARCHITECTURE.md:1023`), it counts toward
budget prospectively (`decide.rs:393-395`), and its origin rule is unchanged (Client only,
`recompute.rs:385-390`, `ARCHITECTURE.md:342`).

### 8.4a The posting record must grow the quantities and the lane

**This is the largest single cost of the design and it is not optional.** Today the journal's
posting body (`crates/busbar/src/root/durability.rs:433-442`) writes six things and none of them is
a quantity:

```
text(key.to_string())  ·  num(window)  ·  figure(reserved)  ·  figure(settled)
figure(overdraft)      ·  num(rate_card_version)
```

The priced lines exist only inside `busbar_unit_cost::Posting`, which is built by
`priced_amount()` (`crates/busbar/src/root/units_llm.rs:693-704`) and **discarded on the next
line** — `u64::try_from(posting.priced_amount()).unwrap_or(u64::MAX)` is all that survives. Worse
for a lookup: the card is keyed lane-first (`crates/busbar-unit-cost/src/rate.rs:141`) and the
node's books keep no lane at all — `WIDTH_THE_NODE_KEEPS = ""`
(`crates/busbar/src/root/units_admin.rs:451`), which is why the identity compares both sides with
`lane` and `provider` empty.

So the posting body gains, after `window` and before the figures:

```
text(lane)                         // the lane the card is keyed by
num(lines.len())                   // then, per line:
  text(class) · num(quantity)      // the QUANTITIES — the stored truth
num(fee_count)  ·  num(tier_bp)  ·  num(arrived_ms)
```

with the three `figure(...)` money fields retained as the cache of §6. The 160-byte journal header
(`crates/busbar-unit-wal/src/journal.rs:82-138`) and `JOURNAL_VERSION = 1` (`journal.rs:86`) are
untouched — the change is inside the opaque body, which the header only length-prefixes and hashes
(`journal.rs:430-435`). A posting body written by an older build is still readable: the reader takes
a short body as "quantities absent" and prices it from the cache, flagged, exactly as a
pre-migration legacy row is (§7).

The audit record already carries the flattened `amount` block including
`rate_card_version` (`durability.rs:452-471`, `:467`) and keeps it.

**Bytes that do not move**: the 160-byte header and its offsets (`journal.rs:108-138`), the 512-byte
frame layer and `FRAME_VERSION = 1` (`crates/busbar-unit-wal/src/record.rs:20-40`), the migration
marker's fixed 88 bytes (`durability.rs:489`, `:511-530`), and the 14 pinned record classes
(`journal.rs:147-176`).

### 8.5 The root book

- `RootCard` (`crates/busbar/src/root/kernel.rs:115-144`) becomes `RootHistory`: the same
  `ArcSwap`, holding a `History` instead of a single card. `pin()` (`kernel.rs:134-136`) returns an
  `Arc<History>`; `CardRepricer::apply` (`kernel.rs:161-175`) **appends** instead of replacing.
  The reason for pinning is unchanged and still good (`units_llm.rs:268-281`): an apply landing
  mid-body must not change what a request in flight is reading.
- `PostingStamp` (`durability.rs:366-373`) already carries `rate_card_version: u64`, `wall` and
  `mono`, and `wall` is already documented as *"the unit's pinned arrival epoch, never a fresh
  read"* (`durability.rs:370`). It gains `arrived_ms` (the millisecond reading, so the history
  resolves at the resolution `Arrived` already holds — `units_llm.rs:163`) and its
  `rate_card_version` becomes the `HistorySeq`.
- The other planes stamp `rate_card_version: 0` today (`units_mcp.rs:1401-1402`,
  `units_a2a.rs:642-643`, `units_voice.rs:1843-1844`) — which under the history is exactly right
  for a single-entry deployment and becomes a real resolution once they stamp a real `Arrived`.
- The voice classes (`units_voice.rs:951-964`: audio tokens in/out, audio seconds in) are open card
  keys today and stay so — the card's class map is string-keyed, so audio seconds, bytes and any
  future class price with no type change. `TierRates` (`rate.rs:62-72`), which can only express the
  four token classes, becomes one *constructor* for a card rather than the card's shape.

### 8.6 `/usage`

Unchanged in every byte except the one described in §9. It keeps its exact field list
(`crates/busbar-core/src/admin/v1/contract/mod.rs:1093-1117`: `window`, `as_of`, `currency`,
`total`, `by_model`, `by_key`, `by_key_truncated`, `others`), its `USAGE_CURRENCY = "USD"` constant
(`:1084`), its top-1000 `by_key` cap and `others` remainder (`:1108-1116`), its per-row derive and
additive rollup (`service.rs:2214-2244`), its 500 on a store error (`service.rs:2192-2211`) and its
`window`/`as_of` semantics (`contract/mod.rs:1067-1075`). PB-16 holds: no additive lines.

What changes is only which card each row is priced at: `card_at(the row's instant)` under the
current head, rather than the live card for every row.

The `LEDGER RULE` sentence (`contract/mod.rs:1077-1079`) is rewritten in place, because it is now
half wrong: `spend_micros` is still derived and still not a ledger charge, but a price change no
longer reprices history. New text in document B.

### 8.7 The ledger admin endpoints

The five read-only verbs (`crates/busbar/src/root/units_admin.rs:4310-4314`; totals `:750`,
checkpoints `:781`, reconciliation `:895`, migration `:942`) each gain `?as_of` and `?currency`,
and each response gains `history_seq`, `head`, `currency` and `adjustments` (§5.1). Two new reads
and one new write join them:

| Verb | Method + path | Scope |
|---|---|---|
| `get_rate_history` | `GET /api/v1/admin/ledger/rate-history` | `read-only` |
| `get_repricings` | `GET /api/v1/admin/ledger/repricings` | `read-only` |
| `amend_rate_history` | `POST /api/v1/admin/ledger/amend-rate-history` | `full` + operator signature, irreducible set |

Money figures stay JSON strings holding decimal integers, per the additive document's own rule
(`docs/openapi-1.6.0-additive.json:6`) — a nano-unit total passes 2^53 on a busy day. The 1.5.5
`openapi.json` is untouched, and its bytes stay pinned
(`crates/busbar-core/src/admin/v1/json/tests/tests.rs:350`).

### 8.8 The oracle

See §11.

### 8.9 Every ARCHITECTURE.md sentence that must move

Document B (`docs/design/1.6.0-rate-card-history-ARCHITECTURE-amendment.md`) rewrites exactly
these, and nothing else:

| Line(s) | What it says today | Why it must move |
|---|---|---|
| `:189` (§1.4 plugin-kinds table, Rate card row) | *"…with a bucket-level tier multiplier (§4.5); versioned;"* | "versioned" becomes "dated: an append-only history of `(effective_from, card)`, priced natively per currency" |
| `:287-288` (§2.2 ADMIT) | *"the rate-card version is captured NOW from the current Policy epoch"* | The entry resolved by `card_at(arrived)` is captured, and it is captured for the hold's SIZING only |
| `:350` (§2.2 settlement table, lane mismatch) | *"the cheaper entry"* | "cheaper" is a price; must name the card and currency it is cheaper under |
| `:718` (§4.1 `JournalEntry`) | `priced_amount … pre_tier_amount, tier_bp, fee_count, currency, rate_card_version` | `usage_lines` become authoritative; the amounts become the cache; `rate_card_version` becomes the history seq |
| `:729-738` (§4.2 checkpoint totals) | the sealed per-`(bucket, dimension, scope)` totals | gains `history_seq`: a checkpoint means "these totals, at that history" |
| `:749-753` (§4.2 recompute) | *"…compared to `priced_amount`; divergence alarms"* | The lookup becomes the arbiter and the cache is corrected; divergence after an amend is expected, not an alarm |
| `:842-865` (§4.5, clauses 1-5) | the five numbered clauses | Clause 2 (*Storage*) becomes quantities; clause 4 (*Immutability*) is replaced by the append-only history and the adjusting entries; clauses 1, 3 and 5 gain a currency axis and are otherwise unchanged |
| `:866-869` (§4.5 oracle equality) | *"1.5.5 re-priced at the pinned migration card == Σ stored nano-units"* | becomes "== Σ price(quantities, history@S)", and the mid-window cell's expectation flips |
| `:921-934` (§4.7 kernel verbs + HTTP bindings) | 17 verbs | 18: `amend_rate_history`, `POST amend-rate-history` |
| `:950-956` (§4.7 irreducible set) | the list | gains `amend_rate_history` |
| `:1049-1053` (§4.9 audit record) | *"…rate-card version…"* | history seq; currency stays |
| `:1170-1172` (§8.1 no-diff-accept list) | names `pre_tier_amount`, `priced_amount`, `rate_card_version` | gains `usage_lines` quantities, `history_seq`, `card_seq` and the repricing record's fields |
| `:1234-1237` (§8.3 ledger solo battery) | *"priced once and stored in nano-units … derive after settle returns exactly what was settled"* | **the sentence that most directly contradicts the model**: becomes "quantities stored once; the lookup at the settlement snapshot returns exactly what was settled" |
| `:1385-1386` (§10) | *"INCLUDING retroactive repricing at read time when the card changes"* | the one user-observable change; now the registered breaking difference |
| `:1406-1436` / new dated section (Appendix A) | — | the dated decision entry |
| `:1581` (PB-16), new PB row | — | PB-16 keeps its wording; a new binding pins the single divergence |

---

## 9. What breaks, and the registration

### 9.1 The one divergence

After a mid-window rate-card change, `GET /api/v1/admin/usage` for that window returns a different
`spend_micros` than 1.5.5 would. 1.5.5 prices **every** row at the current card
(`service.rs:2187`, `:2230`); 1.6.0 prices each row at the card in force when it was earned.

Scale, from the recorded cell: 1.5.5 read back 1,000,120,000 for a window whose first two requests
were served under a card that would have made them 2,500,000 each. 1.6.0 reads back the two
pre-edit requests at the old card and the two post-edit ones at the new — the honest number.

**Everything else is identical.** With no card change in the window — every cell of the
`billing` family today, and every deployment that does not edit prices mid-day — the two answers are
byte-equal, because a single-entry history is exactly the current card (§7).

### 9.2 Why it must be registered breaking

`spend_micros` moving is the `effects.usage` class, which is weight 10 in the differ
(`testing/shadow-oracle/diff-cells.py:65-69`, `MONEY_CLASSES`). The register's own rule
(`testing/shadow-oracle/accepted-differences.json:2-14`) is that `status` and `effects.usage` are
acceptable **only** as `kind: breaking` with a `changelog` field, and
`scripts/changelog-register-check.py:13-17` requires the line verbatim in the newest `## [1.6.0]`
section of `CHANGELOG.md`.

### 9.3 Register entry

```json
{
  "id": "D-NN money is a lookup over quantities against a dated rate-card history",
  "kind": "breaking",
  "changelog": "1.6.0 Changed: a rate-card edit prices what happens after it, not what happened before it.",
  "by": "owner (Matthew Jackson), 2026-09-06 rate-card history decision",
  "cells": "^billing\\|rate-card\\|",
  "classes": ["effects.usage", "body"],
  "rationale": "1.5.5 stores raw token counts and derives spend_micros at read time from the CURRENT cost model (crates/busbar-core/src/admin/v1/service.rs:2187, :2230; contract/mod.rs:1077-1079 'MUTABLE ESTIMATE'), so a PUT /config/settings rate_card re-prices every past row with no restart and no epoch boundary (oracle cell billing|rate-card|epoch-mid-window: a window totalling 10,000,000 micro-units reads back as 1,000,120,000 after a hundredfold card). 1.6.0 keeps quantities as the stored truth and keeps deriving the amount at read time, but derives it against the card in force AT THE POSTING'S INSTANT, read from an append-only dated rate-card history. A window with no mid-window card change answers byte-identically; a window with one answers with the money each request was actually earned under. Back-dating is still available and is now attributable: the signed amend-rate-history verb appends a dated entry and emits one journaled, operator-signed repricing record per affected (window, bucket) carrying the old and new card, the quantities, both amounts and the delta, so the original line and the correction are both visible forever and no booked line is rewritten.",
  "changelog_reason": null
}
```

### 9.4 CHANGELOG line, verbatim

> 1.6.0 Changed: a rate-card edit prices what happens after it, not what happened before it.

with the surrounding paragraph, in the `### Breaking` section of `## [1.6.0]`:

> **1.6.0 Changed: a rate-card edit prices what happens after it, not what happened before it.**
> Token counts are still the stored truth and busbar still derives `spend_micros` at read time —
> but it derives it against the rate card that was in force when the tokens were spent, read from
> an append-only dated history, instead of against whatever card is configured at the moment you
> read. A window in which nobody changed prices answers exactly as 1.5.5 did. A window in which
> somebody did now answers with what each request actually cost, rather than re-pricing the whole
> day at the newest card. **Migration:** if you relied on editing `rate_card` to correct figures
> that had already accrued, that correction is now an explicit, operator-signed admin verb —
> `POST /api/v1/admin/ledger/amend-rate-history` — which back-dates the card over a window you name
> and records what it moved; the config `PUT` you use today keeps working and takes effect from the
> moment you make it. No config change is needed.

`ARCHITECTURE.md:1544` (PB-16) is unaffected: no additive line, no changed field, no changed key
set — only a value, and only after a card edit.

---

## 10. The identity test

### 10.1 What it proves — exactly, and per snapshot

Today (`crates/busbar/src/root/ledger_identity.rs:8-14`):

```text
  Σ ledger priced_amount, projected once to micro-units  ==  the row's spend_micros
  Σ ledger fee_count                                     ==  the row's billable_requests
```

Under the history, the left side becomes a lookup and **both sides are read at the same snapshot**:

```text
  for a history snapshot S, per RowKey (bucket, day, lane, provider), per currency C:

    Σ over the row's postings of price(posting, C, history@S).priced_nanos,
        projected ONCE to micro-units                    ==  the row's spend_micros read at S
    Σ over the row's postings of fee_count               ==  the row's billable_requests
```

Three statements, and the design says precisely which the test proves:

1. **Exact per snapshot.** For any `S`, the residual is **0** — not "within tolerance", not
   "modulo rounding". Both sides run the same `price` over the same quantities against the same
   `HistoryView`, and the micro projection happens once per row on both sides
   (`ledger_identity.rs:32-40`: eight postings each half a micro-unit short of a boundary are eight
   floors of zero where the single divide over the sum is four). This is the statement rule 6
   makes, and it holds for a history of any length, not only a single-entry one.
2. **Exact against 1.5.5 for a single-entry history.** With one entry effective at 0, `price` is
   arithmetically `derive_spend_micros` at that card (§7), so the residual against the *published
   1.5.5 binary's* figures is 0 too. That is the migration acceptance criterion and it is what rule
   6's "exact for a single-entry history" names.
3. **Explained across snapshots.** For `S1 < S2`:

   ```text
     Σ price(·, C, history@S2) − Σ price(·, C, history@S1)
       ==  Σ delta over the repricing records with S1 < to_seq <= S2, for that RowKey and C
   ```

   The divergence between two snapshots is not a tolerance and not an alarm — it is **exactly the
   adjusting entries**, and the test asserts the equality. This is the reproducibility guarantee of
   §5.2 stated as arithmetic.

The `fee_count` half is unaffected by any card change, at any snapshot, which is why it stays
checked separately (`ledger_identity.rs:16-18`, which already names the failure mode: *"a card edit
moves the money and leaves the count alone"*).

### 10.2 Red proofs

The existing red proofs (tier, fee, a one-micro-unit drift — tracker row G4) stay. Four are added:

- A history whose entry 1 is effective mid-window: reading at `as_of = 0` and at `as_of = 1` must
  differ, and by exactly `Σ delta`.
- An amend that moves a window: `settled` must not move, `adjustments` must move by `Σ delta`, and
  `identity::residual` must stay 0 through both.
- A repricing record deleted from the journal: statement 3 must go red.
- A `CachedPrice.priced_nanos` hand-corrupted: the recompute must correct it and journal a
  `Reconciliation`, and the identity must hold before and after (proving the cache is not
  authoritative).

---

## 11. The oracle: which cells move, and the register text

### 11.1 Cells that move

| Cell | Today | Under the history |
|---|---|---|
| `billing\|rate-card\|epoch-mid-window` (branch `keep-oracle-cells`; def. in `enumerate-cells.py`) | 1,000,120,000 — every row at the new card | **MOVES.** The two pre-edit requests price at the boot card, the two post-edit at the hundredfold card. The one cell the breaking registration of §9.3 covers, and the only cell in the `billing` family that does. |
| the other 11 `billing\|*` cells (`billing\|admin-usage\|after-2`, `\|past-day`, `\|group-usage\|*`, `\|key-usage\|*`) | as recorded | **IDENTICAL.** None edits a card mid-window, so each runs against a single-entry history. |
| `hazard\|*`, `plugins.store-persist\|*`, `admin.ops\|*` | as recorded | IDENTICAL — no money path change without a card edit. |

### 11.2 Cells that are added

1. **`billing|rate-card|history-mid-window`** — the epoch cell's shape, asserting the *new* split
   (two rows at the boot card, two at the new one) plus `pricing_version` on the persisted rows.
2. **`ledger|rate-history|as-of`** — write a card mid-window, then read
   `/ledger/totals?as_of=<pre>` and `?as_of=<head>`; the two answers must differ by exactly the
   figure `adjustments` names, and the second must carry the adjusting entries.
3. **`ledger|amend|adjusting-entries`** — amend a past window under an operator signature; assert
   (a) 200 with `entries_adjusted` and `delta`, (b) `/ledger/totals` `settled` unchanged and
   `adjustments` moved, (c) `/ledger/repricings` carries the record with both card seqs, both
   amounts and the operator fingerprint, (d) `/usage` unchanged by the verb at the pre-amend
   snapshot, (e) a replay of the identical payload is a no-op returning the same `history_seq`.
4. **`ledger|amend|refused-unsigned`** — the same call without a signature refuses, journals, and
   moves no figure.
5. **`ledger|currency|native`** — a card pricing one lane in two currencies natively; assert
   `/ledger/totals?currency=` for each is the configured rate × quantity with no cross-rate
   anywhere, and that a third currency is a 400 rather than a conversion.
6. **`ledger|currency|minor-unit-rounding`** — a zero-exponent currency (JPY) and a
   three-exponent one (BHD) against the same quantities; assert the projection divides by
   `10^(9-exp)` once, truncating, and that USD is bit-identical to today's cents.
7. **`config|rate-card|append-not-replace`** — two consecutive `PUT`s; assert
   `/ledger/rate-history` carries three entries (opening + two) with distinct `effective_from` and
   contiguous coverage, and that nothing was overwritten.

Cells 2–7 are 1.6.0-only surfaces and register as `improvement` (additive; a 1.5.5 operator sees
nothing). Cell 1 is the breaking one and is covered by §9.3. Every entry, improvement or breaking,
owes its verbatim CHANGELOG line (`scripts/changelog-register-check.py:13-17`).

### 11.3 Register text for the additive half

```json
{
  "id": "D-NN+1 dated rate-card history, native currencies, and the signed amend verb",
  "kind": "improvement",
  "changelog": "The 1.6.0 ledger endpoints read money as of a rate-card history snapshot.",
  "by": "owner (Matthew Jackson), 2026-09-06 rate-card history decision",
  "cells": "^ledger\\||^config\\|rate-card\\|",
  "rationale": "Additive 1.6.0 surface: /api/v1/admin/ledger/{rate-history,repricings} are new reads; /api/v1/admin/ledger/amend-rate-history is a new operator-signed write in the irreducible set; the five existing ledger reads gain optional ?as_of=<history_seq> and ?currency=<CCY> and echo history_seq, head, currency and the adjusting entries that make the answer differ from an earlier snapshot. A card prices in one or more currencies natively, with no pivot and no conversion. No 1.5.5 path, field or byte is touched: crates/busbar-core/src/admin/v1/json/openapi.json is unchanged and the 1.6.0 operations are described at docs/openapi-1.6.0-additive.json, reached by name at GET /api/v1/admin/ledger/openapi.json."
}
```

CHANGELOG line, verbatim:

> The 1.6.0 ledger endpoints read money as of a rate-card history snapshot.

---

## 12. What this costs, stated plainly

- **A history to persist.** Small (one entry per price change for the life of the deployment), but
  it must outlive the config it came from and it must be readable at recovery before the first
  posting is priced. It rides the journal as `RecordClass::Policy` records, so the 14 pinned record
  classes (`crates/busbar-unit-wal/src/journal.rs:143-176`) do not move.
- **Checkpoint bodies gain a field.** `history_seq` beside the 12 digested `Totals` figures
  (`checkpoint.rs:293-306`). Every checkpoint sealed before the change verifies against the old
  encoding; the version byte in the record header (`journal.rs` fixed 160-byte header) is what
  tells them apart.
- **An operator-signed verb where none exists.** `/ledger/*` is read-only today
  (`crates/busbar/src/root/units_admin.rs:4310-4314`) and nothing in this tree implements an
  operator-signed admin verb. This is genuinely new work, and it touches eight enforced tables:
  `crates/busbar-unit-verbs/src/verb.rs:322-334` (+ `VERB_COUNT`),
  `crates/busbar-plane-admin/src/verbs.rs:139-181`, `crates/busbar-unit-scope/src/lib.rs:285`,
  `crates/busbar/src/root/units_admin.rs:1283` and `:4310-4314`,
  `docs/openapi-1.6.0-additive.json`, `testing/shadow-oracle/enumerate-cells.py` (+ `cells.json`),
  `testing/shadow-oracle/accepted-differences.json` + `CHANGELOG.md`.
- **A one-line fix stops being a one-line fix.** Today an operator corrects a rate with one `PUT`
  and every past figure silently becomes right. Under the history that same `PUT` corrects the
  future only, and correcting the past is a signed verb that leaves a permanent record. That is the
  point, and it is a real ergonomic loss; it is named here rather than discovered later.
- **The three vocabularies must converge before anything else lands** (§1.5). One card identity —
  `HistorySeq(u64)` — one fee spelling, one `RateCard`.
- **The posting record grows** (§8.4a): quantities per class, the lane, `fee_count`, `tier_bp` and
  `arrived_ms` join the body. This is the design's real price, and it is unavoidable — a lookup
  over quantities cannot be performed against a record that keeps no quantities and no lane.
- **The migration path has no production caller today.** `MigrationConfig` / `run` / `seal_opening`
  (`crates/busbar/src/root/migration.rs:62-156`) appear only in that file and its tests; the root
  carries `#![allow(dead_code)]` (`crates/busbar/src/root/mod.rs:57`). Wiring the opening entry is
  part of the work, not a rename of something already running.

- **What is NOT paid.** The 160-byte journal header and its offsets, `JOURNAL_VERSION = 1`, the
  512-byte frame layer, the migration marker's 88 fixed bytes and the 14 pinned record classes are
  all untouched (§8.4a). The store ABI does not change (`pricing_version` is already there,
  `#[serde(default)]`, `crates/api/src/store.rs:817`). `/usage`'s field list, wire order, caps and
  error behaviour do not change. The admission decision does not change. The settlement table's
  quantity rules do not change. The identity's terms do not change.
