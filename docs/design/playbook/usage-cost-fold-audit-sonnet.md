# Adversarial audit: `usage-cost-fold.md`

Scope: mechanical verification of every type/field/call-site claim in
`docs/design/playbook/usage-cost-fold.md` against real code as of this worktree.

## 1. `busbar_substrate::billing::Usage` — actual fields

`crates/busbar-substrate/src/billing.rs:97-101`:

```rust
pub struct Usage {
    pub usage_units: std::collections::BTreeMap<String, u64>,
}
```

There is **no four-field reserved struct**. The "reserved-four keys" are `RESERVED_UNITS: [&str; 4]
= [UNIT_INPUT, UNIT_OUTPUT, UNIT_CACHE_READ, UNIT_CACHE_WRITE]` (`crates/api/src/store.rs:565-572`),
consumed as ordinary map keys of `usage_units`. The doc's §1 table only ever calls these out as "unit
keys," never as struct fields, so this part is **accurate**, if imprecisely worded ("surfaced through
`busbar_substrate::billing::{TokenUsage, Usage}`" invites the reader to think both types carry the
same four fields — they don't: `TokenUsage` is a *different*, older typed struct with
`cache_creation`, not `cache_write` — but the fold code path the doc actually proposes uses `Usage`,
not `TokenUsage`, so this is cosmetic, not a defect).

## 2. `IrDuplexUsage` — actual fields

`crates/busbar-voice/src/ir/usage.rs:16-28`:

```rust
pub struct IrDuplexUsage {
    pub audio_in: u64,
    pub audio_out: u64,
    pub text_in: u64,
    pub text_out: u64,
    pub cached: u64,
}
```

Matches the doc's §1 table exactly (`audio_in, audio_out, text_in, text_out, cached`).

## 3. Does the proposed mapping compile against the real types? **No — three break points.**

a. **`self.lanes` and `self.rates` do not exist.** §3's snippet writes
   `fold_duplex_usage(&u, &self.lanes)` and `price_lanes(&priced, &self.rates)` inside
   `SessionCore::on_server_frame`. The real `SessionCore<C>` struct
   (`crates/busbar-voice/src/runtime/session.rs:66-73`) has exactly these fields: `codec, inner,
   locked_config, lease, tools, pricing, carrier`. No `lanes`, no `rates`. Neither `VoiceRuntime`
   (`runtime/mod.rs:31-41`: `engine, metering, tools, pricing`) carries them either. The snippet is
   pseudocode for state that has not been designed, not code that compiles against today's structs.

b. **`fold_duplex_usage` and `price_lanes` do not exist anywhere in the tree** (`grep -rn
   "fold_duplex_usage\|price_lanes"` returns zero hits outside this doc). That's expected for a
   design doc, but the doc's prose in §1 ("This yields... priced by **the ONE pricer**... the SAME
   shape `ledger_and_meter`/`derive_spend_*` consume") reads as if `price_lanes` already resolves to
   an existing function. It does not; it would have to be written from scratch.

c. **The only existing pricing functions the doc cites are `pub(crate)` inside `busbar-core`, not
   reachable from `busbar-voice` at all.** Verified in `crates/busbar-core/src/cost.rs`:
   - `pub(crate) struct RateNanos` (line 122)
   - `pub(crate) fn from_raw(...)` (line 135)
   - `pub(crate) fn reserved_nanos(...)` (line 181)
   - `pub(crate) fn price(rate: &RateNanos, extras: &ExtraRates, tier_bp: u32, usage: &Usage) ->
     Result<CostBreakdown, CostError>` (line 208) — takes **one** `RateNanos` and **one** `Usage`,
     producing **one** `CostBreakdown`. It does **not** iterate `(model, Usage)` pairs the way the
     doc's §1/§4 claim ("exactly the two-lane audio/text shape").
   - `pub(crate) fn derive_spend_cents(...)` (line 698) **does** iterate `(model, units)` pairs, but
     it (i) is also `pub(crate)`, unreachable from `busbar-voice`, and (ii) returns a lossy `i64`
     **cents** scalar (`nanos / NANOS_PER_CENT`, floor division), not a `CostBreakdown` and not
     nanodollar-precise — it cannot be the "ONE shared pricer" that emits the itemized, nanodollar
     `CostBreakdown` §3 settles.

   So today there is no single existing function with the signature "two `(model, Usage)` lanes in →
   one nanodollar `CostBreakdown` out." The doc partially owns this: §2's last bullet proposes
   *promoting* `from_raw`+`reserved_nanos` into `busbar_substrate::billing` so the plane can reach
   them — a real, correctly-scoped fix for point (c) on `from_raw`/`reserved_nanos`. But it does not
   propose a multi-lane `CostBreakdown` combinator (merging two `price()`-shaped calls, one per model
   lane, into one breakdown whose components sum to `total`), and no such combinator exists today.
   `price_lanes` in §3 is therefore unimplemented glue the doc presents as already having a home
   ("the ONE pricer"), when it does not yet exist at any visibility level.

**Verdict on this section: the mapping does NOT compile against real code today.** It requires (i) a
new multi-lane-to-`CostBreakdown` pricer that isn't sketched beyond a function name, and (ii)
promoting `RateNanos`/`from_raw`/`reserved_nanos` out of `pub(crate)` — both correctly flagged as
work but not yet done, and the doc's phrasing overstates how much of "the ONE pricer" already exists.

## 4. Where `build_runtime` binds the zero `Pricing` book

`crates/busbar-voice/src/runtime/mod.rs`, `fn build_runtime_with_metering` (the shared body both
`build_runtime` (line 94) and `build_runtime_hosted` (line 114) delegate to):

```rust
fn build_runtime_with_metering(
    metering: Arc<dyn MeteringPort>,
) -> Arc<dyn std::any::Any + Send + Sync> {
    Arc::new(VoiceRuntime::new(
        Arc::new(DurableHandleEngine::new()),
        metering,
        Arc::new(EchoToolExecutor),
        Pricing {
            audio_in_nanos: 0,
            audio_out_nanos: 0,
            text_in_nanos: 0,
            text_out_nanos: 0,
            cached_nanos: 0,
        },
    ))
}
```

Confirms the doc's claim precisely, including that **`build_runtime_hosted` — the production entry —
inherits the same zero book**, since it's just `build_runtime_with_metering(Arc::new(HostMeteringPort::new(host)))`.
The real rate source that must replace this: the top-level `rate_card:` resolved into
`busbar_core::cost::CostModel { rates: Option<HashMap<String, RateNanos>>, ... }`
(`crates/busbar-core/src/cost.rs:419-457`, `CostModel::resolve_parts`), which the doc correctly
identifies as "the ONLY cost source." Getting that card into `busbar-voice` requires the visibility
fix in §3(c) above — `RateNanos`/`from_raw` are core-`pub(crate)` today, so nothing on the voice side
can construct a `RateNanos` from a `rate_card:` entry without the promotion the doc proposes but has
not implemented.

## 5. Does `session.rs` call settle with a `CostBreakdown` total per `response.done.usage`?

**Not today — the doc's §0 claim describes the CURRENT (pre-fold) code correctly, and its §3 snippet
is explicitly the proposed replacement, not existing code.** Current code,
`crates/busbar-voice/src/runtime/session.rs:137-139`:

```rust
IrServerEvent::Usage(u) => {
    let nanos = self.pricing.price(&u);
    if self.lease.settle(nanos).must_close() {
```

This settles a bare `u64` from the private five-field `Pricing::price`, exactly as the doc's §0
describes — there is no `CostBreakdown` in the current call at all. The doc is honest about this
being the gap it's closing (§3 explicitly says "replace the private-book price with the fold"); no
mismatch here, just confirming the doc doesn't misrepresent current state as already-fixed.

## Concrete mismatches found

1. §1/§3/§4 treat "the ONE shared pricer" as an existing thing voice can call; no function in the
   tree takes multiple `(model, Usage)` lanes and returns a nanodollar `CostBreakdown`. `price()` is
   single-lane; `derive_spend_cents()` is multi-lane but scalar-cents and lossy. `price_lanes` is a
   name with no implementation anywhere.
2. §3's code references `self.lanes` and `self.rates` on `SessionCore` — neither field exists on the
   real struct (`session.rs:66-73`), nor on `VoiceRuntime` (`mod.rs:31-41`). This is unbuilt state,
   not a wiring detail.
3. `RateNanos`, `RateNanos::from_raw`, `RateNanos::reserved_nanos`, and `cost::price()` are all
   `pub(crate)` in `busbar-core` today — `busbar-voice` cannot reach any of them without the crate
   API change §2 proposes (correctly identified, but not yet a small change: it's a new public
   surface on `busbar_substrate::billing`, not just "thread a value through").
4. `TokenUsage.cache_creation` vs. the design's assumed `cache_write` naming is a latent trap if a
   future author confuses `TokenUsage` (chat/embeddings path) with the `Usage`/`usage_units` map the
   fold actually targets — worth a one-line doc clarification, not a blocking defect.

## Verdict: SHIP-WITH-CHANGES

The defect diagnosis (zero `Pricing` book, no `CostBreakdown` fold, unused `breakdown_ptr/_len`) is
accurate and independently verified byte-for-byte at every cited line. But §1/§3's "the ONE pricer
already exists, this is just wiring" framing overstates readiness: the multi-lane
`(model, Usage)* → CostBreakdown` pricer does not exist at any visibility level, and the two
candidate existing functions (`price`, `derive_spend_cents`) are both `pub(crate)`-sealed to
`busbar-core` and structurally wrong shapes (single-lane / lossy-scalar respectively) to be called
as-is. Before implementation: (a) name and design the actual multi-lane combinator explicitly instead
of a single placeholder function name, (b) scope the `busbar_substrate::billing` visibility promotion
as a real sub-task (crate API surface change), (c) fix the `self.lanes`/`self.rates` placeholders into
an actual field/config design on `VoiceRuntime`/`SessionCore` before treating §3 as buildable.
