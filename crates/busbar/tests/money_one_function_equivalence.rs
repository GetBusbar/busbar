// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE EQUIVALENCE PROOF.** Every implementation of `f` in this tree, run side by side on one
//! constructed ledger slice and one constructed card history, with the figures each answers.
//!
//! `f` is `money = f(ledger, rate_card)`. The governing design says there is ONE of it. A census
//! taken on 2026-09-22 found it implemented more than twenty times across five crates, which is why
//! this file exists: a disagreement nobody can reproduce is a rumour, so each pair below is
//! CONSTRUCTED, RUN, and its two figures asserted. Where the numbers are equal that is an
//! equivalence the consolidation must preserve; where they differ that is a defect with a size.
//!
//! The composition root is the only crate entitled to name all five, which is why the proof lives
//! here rather than beside any one of them.
//!
//! Run `cargo test -p busbar --test money_one_function_equivalence -- --nocapture` to print the
//! table. The assertions are the contract; the printing is for the reader.

use std::collections::BTreeMap;

use busbar_kernel_ledger::cost::{
    self as ledger_cost, Author, CardEntryDraft, CurrencyCode, History, LaneClass, LedgerEntry,
    RateCard,
};

/// The lane every case serves on.
const LANE: &str = "gpt-4o";

const INPUT: &str = "input";
const OUTPUT: &str = "output";
const CACHE_READ: &str = "cache_read";
const CACHE_WRITE: &str = "cache_write";

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE FIXTURES — one consumption, expressed in each of the shapes the tree's pricers consume.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// The counts, as the ENFORCEMENT ledger (`UsageLedger` / `ModelTokens.usage_units`) holds them:
/// a name-keyed map of whole counts, with no instant on it.
fn enforcement_units(pairs: &[(&'static str, u64)]) -> BTreeMap<String, u64> {
    pairs.iter().map(|(k, v)| ((*k).to_string(), *v)).collect()
}

/// The same counts as the LEDGER CRATE's read-time derivation consumes them.
fn usage_lines(pairs: &[(&'static str, u64)]) -> Vec<busbar_contract::caps::UsageLine> {
    pairs
        .iter()
        .map(|(class, quantity)| busbar_contract::caps::UsageLine {
            class: busbar_contract::caps::step::MeterClassId::new(class),
            quantity: *quantity,
            source: busbar_contract::caps::QuantitySource::Count,
            estimated: false,
        })
        .collect()
}

/// The same counts as a [`LedgerEntry`] for the ONE function, dated at an instant.
fn one_entry(pairs: &[(&'static str, u64)], arrived_ms: u64, fee_count: u64) -> LedgerEntry {
    pairs
        .iter()
        .fold(LedgerEntry::new(LANE, arrived_ms), |e, (class, q)| {
            e.with_whole(*class, *q)
        })
        .with_fee_count(fee_count)
}

/// A `busbar-kernel` cost model — the pricer behind `derived_bucket_usage`, and therefore behind
/// `GET /groups/{g}/usage`, `GET /keys/{id}/usage`, `budget_state` and the `/metrics` gauges.
fn kernel_cost_model(
    rates: Option<&[(&str, [f64; 4])]>,
    per_request_fee: i64,
) -> busbar_kernel::cost::CostModel {
    let card: Option<BTreeMap<String, busbar_kernel::config::RateEntryCfg>> = rates.map(|rows| {
        rows.iter()
            .map(|(model, r)| {
                (
                    (*model).to_string(),
                    busbar_kernel::config::RateEntryCfg {
                        input_utok: r[0],
                        output_utok: r[1],
                        cache_read_utok: r[2],
                        cache_write_utok: r[3],
                    },
                )
            })
            .collect()
    });
    busbar_kernel::cost::CostModel::resolve_parts(card.as_ref(), per_request_fee, &BTreeMap::new())
}

/// A `busbar-kernel-budget` pricer — the ADMISSION door's own copy, the one the budget gate
/// compares against a cap.
fn budget_pricer(
    rates: Option<&[(&str, [f64; 4])]>,
    per_request_fee: i64,
) -> busbar_kernel_budget::Pricer {
    match rates {
        None => busbar_kernel_budget::Pricer::flat(per_request_fee),
        Some(rows) => {
            let table: BTreeMap<String, busbar_kernel_budget::RateNanos> = rows
                .iter()
                .map(|(model, r)| {
                    (
                        (*model).to_string(),
                        busbar_kernel_budget::RateNanos::from_micros_per_token(
                            r[0], r[1], r[2], r[3],
                        ),
                    )
                })
                .collect();
            busbar_kernel_budget::Pricer::with_card(per_request_fee, table)
        }
    }
}

/// A `busbar-kernel-ledger` card over one lane's four reserved classes.
fn ledger_card(rates: [f64; 4], fee: i64) -> RateCard {
    RateCard::from_micro_rates(
        [
            (LaneClass::new(LANE, INPUT), rates[0]),
            (LaneClass::new(LANE, OUTPUT), rates[1]),
            (LaneClass::new(LANE, CACHE_READ), rates[2]),
            (LaneClass::new(LANE, CACHE_WRITE), rates[3]),
        ],
        fee,
    )
}

/// **`v1/service.rs:109 derive_spend_micros_row`, REPRODUCED.** The admin crate's private flat
/// pricer, copied here verbatim because the test cannot reach a private item. It is three lines and
/// they are the whole of it: project the row's four tier fields onto the name-keyed map, resolve the
/// alias, call `CostModel::derive_spend_micros`. A change to the original that this copy does not
/// track would show up as this file's numbers ceasing to match the endpoint's.
fn admin_row_flat(
    cost: &busbar_kernel::cost::CostModel,
    model: &str,
    counts: &[(&'static str, u64)],
    requests: u64,
) -> i64 {
    let units: BTreeMap<String, u64> = counts
        .iter()
        .filter(|(_, v)| *v != 0)
        .map(|(k, v)| ((*k).to_string(), *v))
        .collect();
    let resolved = cost.resolve_model_alias(model);
    cost.derive_spend_micros([(resolved, &units)].into_iter(), requests, true)
}

/// **`v1/service.rs:216 derive_spend_micros_row_at_card`, REPRODUCED**, for the same reason.
fn admin_row_at_card(
    card: &RateCard,
    model: &str,
    counts: &[(&'static str, u64)],
    requests: u64,
) -> i64 {
    let lines = usage_lines(
        &counts
            .iter()
            .copied()
            .filter(|(_, q)| *q != 0)
            .collect::<Vec<_>>(),
    );
    ledger_cost::derive_spend_micros(card, [(model, &lines[..])].into_iter(), requests, true)
}

/// **`v1/service.rs:201 row_priced_at_ms`, REPRODUCED.** The instant `GET /admin/usage` resolves a
/// metering row at: the later of the UTC-day bucket's start and the row's own price era.
fn admin_row_priced_at_ms(bucket_start_secs: u64, priced_from_ms: u64) -> u64 {
    bucket_start_secs.saturating_mul(1_000).max(priced_from_ms)
}

/// One row of the printed table.
fn row(label: &str, figure: impl std::fmt::Display) {
    eprintln!("  {label:<62} {figure:>22}");
}

fn rule(title: &str) {
    eprintln!(
        "\n── {title} {}",
        "─".repeat(84usize.saturating_sub(title.len()))
    );
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// D1 — THE DATED HISTORY vs THE CURRENT CARD. The headline park: two admin reads, one
//      consumption, two figures.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// Card A, in force from instant zero; card B appended effective from instant 1,000,000.
fn edit_history() -> History {
    let mut history = History::opening(ledger_card([3.0, 16.0, 0.0, 0.0], 2), 0);
    history.append(CardEntryDraft {
        effective_from: 1_000_000,
        effective_until: None,
        card: ledger_card([1.0, 4.0, 0.0, 0.0], 1),
        appended_at: 1_000_000,
        author: Author::Config { policy_epoch: 1 },
    });
    history
}

#[test]
fn d1_a_rate_card_edit_splits_the_tree_into_two_answers() {
    rule("D1  a rate-card edit: the dated read vs every flat read");

    // ONE consumption, recorded in both books: 1,000 input + 250 output, twice — once before the
    // card edit and once after it, one billable request each.
    let counts: [(&str, u64); 2] = [(INPUT, 1_000), (OUTPUT, 250)];

    // ── THE DATED READ (#79): each row prices against the card in force when it arrived.
    let history = edit_history();
    let dated = ledger_cost::price_ledger(
        &[
            one_entry(&counts, 500_000, 1),
            one_entry(&counts, 2_000_000, 1),
        ],
        &history,
        CurrencyCode::USD,
    )
    .expect("every class is priced on both cards");

    // The same thing said through the admin endpoint's own two lines, row by row.
    let view = history.current();
    let admin_dated: i64 = [500_000u64, 2_000_000]
        .iter()
        .map(|arrived| {
            let (_seq, card) = view.card_at(*arrived).expect("both instants are covered");
            admin_row_at_card(card, LANE, &counts, 1)
        })
        .sum();

    // ── THE FLAT READS: `get_group_usage`, `GET /keys/{id}/usage`, `budget_state` and the
    //    `busbar_bucket_spend_cents` gauge all price the WHOLE window at whatever card is
    //    configured at the moment of the read — which is card B.
    let current = kernel_cost_model(Some(&[(LANE, [1.0, 4.0, 0.0, 0.0])]), 1);
    let units = enforcement_units(&counts);
    let flat_micros = current.derive_spend_micros(
        [(LANE, &units), (LANE, &units)].into_iter(),
        2, // two billable requests
        true,
    );
    let flat_cents =
        current.derive_spend_cents([(LANE, &units), (LANE, &units)].into_iter(), 2, true);

    // And the door's own copy, which must agree with the gate it feeds.
    let door = budget_pricer(Some(&[(LANE, [1.0, 4.0, 0.0, 0.0])]), 1);
    let door_cents = door.derive_spend_cents([(LANE, &units), (LANE, &units)].into_iter(), 2, true);

    row(
        "ONE function  price(ledger, history)   [micro-units]",
        dated.micros(),
    );
    row(
        "GET /admin/usage  (dated, #79)         [micro-units]",
        admin_dated,
    );
    row(
        "GET /groups/{g}/usage  (flat)          [micro-units]",
        flat_micros,
    );
    row(
        "GET /keys/{id}/usage   (flat)          [cents]      ",
        flat_cents,
    );
    row(
        "budget gate  Pricer::derive_spend_cents [cents]     ",
        door_cents,
    );

    // Row one at card A: 1000×3 + 250×16 + 1 fee×2 minor = 3,000 + 4,000 + 20,000 = 27,000.
    // Row two at card B: 1000×1 + 250×4  + 1 fee×1 minor = 1,000 + 1,000 + 10,000 = 12,000.
    assert_eq!(dated.micros(), 39_000, "the dated answer");
    assert_eq!(
        i128::from(admin_dated),
        dated.micros(),
        "the endpoint agrees with the function"
    );

    // Both rows at card B: 2 × 12,000 = 24,000 micro-units.
    assert_eq!(flat_micros, 24_000, "the flat answer");
    assert_eq!(flat_cents, 2, "the same thing truncated to whole cents");
    assert_eq!(
        door_cents, flat_cents,
        "the door and the group read agree with each other"
    );

    row(
        "DISAGREEMENT  dated − flat             [micro-units]",
        dated.micros() - i128::from(flat_micros),
    );
    assert_eq!(dated.micros() - i128::from(flat_micros), 15_000);
    // 15,000 micro-units of 39,000 — 38.5% of the bill — is the size of the park, for this slice.
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// D2 — THE RESERVED FOUR. Every `derive_spend_*` on the ENFORCEMENT side prices only
//      input/output/cache_read/cache_write and silently drops every other declared meter class.
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn d2_an_open_meter_class_bills_as_nothing_on_the_enforcement_side() {
    rule("D2  an open meter class (a2a `hops`, mcp `calls`, streaming `audio-seconds`)");

    // A card that prices `output` at 2 micro-units and `hops` at 5.
    let card = RateCard::from_micro_rates(
        [
            (LaneClass::new(LANE, OUTPUT), 2.0),
            (LaneClass::new(LANE, "hops"), 5.0),
        ],
        0,
    );
    let counts: [(&str, u64); 2] = [(OUTPUT, 100), ("hops", 1_000)];

    // ── THE ONE FUNCTION: both classes are ordinary card entries.
    let one = ledger_cost::price_ledger(
        &[one_entry(&counts, 0, 0)],
        &History::opening(card.clone(), 0),
        CurrencyCode::USD,
    )
    .expect("the card prices both classes");

    // ── THE LEDGER CRATE's read-time derivation: also sees both, because it walks the lines.
    let lines = usage_lines(&counts);
    let ledger_micros =
        ledger_cost::derive_spend_micros(&card, [(LANE, &lines[..])].into_iter(), 0, true);

    // ── THE ENFORCEMENT SIDE: `RateNanos` has four fields and `reserved_nanos` folds over four
    //    names. `hops` cannot be represented, let alone priced.
    let kernel = kernel_cost_model(Some(&[(LANE, [0.0, 2.0, 0.0, 0.0])]), 0);
    let units = enforcement_units(&counts);
    let kernel_micros = kernel.derive_spend_micros([(LANE, &units)].into_iter(), 0, true);
    let door = budget_pricer(Some(&[(LANE, [0.0, 2.0, 0.0, 0.0])]), 0);
    let door_cents = door.derive_spend_cents([(LANE, &units)].into_iter(), 0, true);

    row(
        "ONE function                            [micro-units]",
        one.micros(),
    );
    row(
        "ledger  derive_spend_micros             [micro-units]",
        ledger_micros,
    );
    row(
        "kernel  CostModel::derive_spend_micros  [micro-units]",
        kernel_micros,
    );
    row(
        "budget  Pricer::derive_spend_cents      [cents]      ",
        door_cents,
    );

    assert_eq!(one.micros(), 5_200, "100×2 + 1000×5");
    assert_eq!(i128::from(ledger_micros), one.micros());
    assert_eq!(kernel_micros, 200, "only the 100 output tokens are visible");
    assert_eq!(door_cents, 0, "and in whole cents that is nothing at all");

    row(
        "DISAGREEMENT  one − kernel              [micro-units]",
        one.micros() - i128::from(kernel_micros),
    );
    assert_eq!(one.micros() - i128::from(kernel_micros), 5_000);
    // 96.15% of this slice's bill is invisible to the budget gate and to two of the three admin
    // money reads. This is what "the oracle is structurally blind to plane money" costs in figures.
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// D3 — TWO COPIES OF `reserved_nanos`, ONE SATURATING AND ONE NOT. The door pins at the top; the
//      admin read and the metrics gauge wrap or panic on the same numbers.
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn d3_the_two_copies_of_reserved_nanos_disagree_at_the_top_of_the_range() {
    rule("D3  `RateNanos::reserved_nanos` — kernel copy vs budget copy");

    // A rate at the top of what `nano_rate` will build (1e16 micro-units a token is 1e19
    // nano-units), against counts at the top of `u64`. Two such products already exceed `u128`.
    let rates = [1.0e16f64; 4];
    let big = u64::MAX;
    let units = enforcement_units(&[
        (INPUT, big),
        (OUTPUT, big),
        (CACHE_READ, big),
        (CACHE_WRITE, big),
    ]);

    let budget_rate = busbar_kernel_budget::RateNanos::from_micros_per_token(
        rates[0], rates[1], rates[2], rates[3],
    );
    let budget_nanos = budget_rate.reserved_nanos(&units);

    let kernel_rate =
        busbar_kernel::cost::RateNanos::from_raw(&busbar_substrate_values::billing::RawTierRates {
            input: rates[0],
            output: rates[1],
            cache_read: rates[2],
            cache_write: rates[3],
        });
    let kernel_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        kernel_rate.reserved_nanos(&units)
    }));

    row(
        "budget  reserved_nanos (saturating)     [nano-units]",
        budget_nanos,
    );
    match &kernel_result {
        Ok(v) => row("kernel  reserved_nanos (plain `+`)      [nano-units]", v),
        Err(_) => row(
            "kernel  reserved_nanos (plain `+`)      ",
            "PANIC (overflow)",
        ),
    }

    assert_eq!(
        budget_nanos,
        u128::MAX,
        "the door pins at the top and blocks"
    );
    assert!(
        kernel_result.is_err(),
        "the kernel copy has no saturation: `acc + (n as u128) * (rate as u128)` at \
         crates/busbar-kernel/src/cost.rs:178. In a debug build it PANICS — which on the admin \
         read path is a 500 on `GET /groups/{{g}}/usage`, `GET /keys/{{id}}/usage` and every \
         `/metrics` scrape. In a release build (this workspace sets no `overflow-checks`) it WRAPS, \
         and a wrapped total lands back near zero: an over-the-top ledger deriving as nearly free."
    );
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// D4 — A PRESENT CARD SILENT ABOUT A LANE. #42 says REFUSE; every derivation in the tree says 0.
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn d4_an_unpriced_lane_bills_as_free_on_every_read_and_refuses_only_in_the_one_function() {
    rule("D4  a present card that does not name the lane (#42)");

    let card = ledger_card([3.0, 16.0, 0.0, 0.0], 2);
    let counts: [(&str, u64); 2] = [(INPUT, 1_000_000), (OUTPUT, 1_000_000)];
    let unknown = "a-model-nobody-priced";

    let lines = usage_lines(&counts);
    let ledger_micros =
        ledger_cost::derive_spend_micros(&card, [(unknown, &lines[..])].into_iter(), 1, true);

    let kernel = kernel_cost_model(Some(&[(LANE, [3.0, 16.0, 0.0, 0.0])]), 2);
    let units = enforcement_units(&counts);
    let kernel_micros = kernel.derive_spend_micros([(unknown, &units)].into_iter(), 1, true);

    let door = budget_pricer(Some(&[(LANE, [3.0, 16.0, 0.0, 0.0])]), 2);
    let door_cents = door.derive_spend_cents([(unknown, &units)].into_iter(), 1, true);

    let one = ledger_cost::price_ledger(
        &[counts
            .iter()
            .fold(LedgerEntry::new(unknown, 0), |e, (c, q)| {
                e.with_whole(*c, *q)
            })
            .with_fee_count(1)],
        &History::opening(card.clone(), 0),
        CurrencyCode::USD,
    );

    row(
        "ledger  derive_spend_micros             [micro-units]",
        ledger_micros,
    );
    row(
        "kernel  CostModel::derive_spend_micros  [micro-units]",
        kernel_micros,
    );
    row(
        "budget  Pricer::derive_spend_cents      [cents]      ",
        door_cents,
    );
    row(
        "ONE function                                        ",
        format!("{:?}", one.as_ref().err()),
    );

    // Nineteen million micro-units of real consumption, and every derivation in the tree charges
    // the flat fee and nothing else.
    assert_eq!(ledger_micros, 20_000, "the fee alone");
    assert_eq!(kernel_micros, 20_000, "the fee alone");
    assert_eq!(door_cents, 2, "the fee alone");
    assert!(
        matches!(one, Err(ledger_cost::MoneyError::LaneUnpriced { .. })),
        "#42: rate_card PRESENT and the class is not priced ⇒ REFUSE, never a silent 0"
    );
    // The consumption that went unbilled, had the lane been priced at the card's own rates:
    let priced_instead =
        ledger_cost::derive_spend_micros(&card, [(LANE, &lines[..])].into_iter(), 1, true);
    row(
        "  …the same counts, had the lane been priced         ",
        priced_instead,
    );
    assert_eq!(priced_instead, 19_020_000);
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// D5 — A PRESENT CARD SILENT ABOUT A CLASS IT DOES NAME THE LANE FOR.
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn d5_an_unpriced_class_on_a_priced_lane_bills_as_free_everywhere_but_the_one_function() {
    rule("D5  a priced lane, a class the card is silent about (#42)");

    // The card prices input and output. The row reports cache_read too.
    let card = RateCard::from_micro_rates(
        [
            (LaneClass::new(LANE, INPUT), 3.0),
            (LaneClass::new(LANE, OUTPUT), 16.0),
        ],
        0,
    );
    let counts: [(&str, u64); 3] = [(INPUT, 1_000), (OUTPUT, 250), (CACHE_READ, 10_000_000)];

    let lines = usage_lines(&counts);
    let ledger_micros =
        ledger_cost::derive_spend_micros(&card, [(LANE, &lines[..])].into_iter(), 0, true);
    let kernel = kernel_cost_model(Some(&[(LANE, [3.0, 16.0, 0.0, 0.0])]), 0);
    let units = enforcement_units(&counts);
    let kernel_micros = kernel.derive_spend_micros([(LANE, &units)].into_iter(), 0, true);

    let one = ledger_cost::price_ledger(
        &[one_entry(&counts, 0, 0)],
        &History::opening(card, 0),
        CurrencyCode::USD,
    );

    row(
        "ledger  derive_spend_micros             [micro-units]",
        ledger_micros,
    );
    row(
        "kernel  CostModel::derive_spend_micros  [micro-units]",
        kernel_micros,
    );
    row(
        "ONE function                                        ",
        format!("{:?}", one.as_ref().err()),
    );

    assert_eq!(
        ledger_micros, 7_000,
        "3,000 + 4,000; the ten million cache-reads price at nothing"
    );
    assert_eq!(kernel_micros, 7_000, "identically silent");
    assert!(matches!(
        one,
        Err(ledger_cost::MoneyError::ClassUnpriced { .. })
    ));
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// D6 — THE TIER MULTIPLIER EXISTS ON ONE PRICER AND NOT THE OTHER.
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn d6_the_tier_multiplier_is_applied_by_the_lookup_and_ignored_by_every_derivation() {
    rule("D6  the service-tier multiplier");

    let card = ledger_card([3.0, 16.0, 0.0, 0.0], 0);
    let history = History::opening(card.clone(), 0);
    let counts: [(&str, u64); 2] = [(INPUT, 1_000), (OUTPUT, 250)];
    let half = busbar_kernel_ledger::cost::STANDARD_TIER_BP / 2;

    let usage = {
        let seal = busbar_contract::caps::KernelSeal::acquire_for_kernel();
        let token = busbar_contract::caps::Grant::<busbar_contract::caps::Consumption>::mint(&seal);
        busbar_contract::caps::Usage::report(&token, usage_lines(&counts))
            .expect("a report within the line bound")
    };
    let posting = ledger_cost::Posting::from_usage(LANE, &usage, 0, half, 0, 0);
    let lookup = ledger_cost::price(&history.current(), &posting, CurrencyCode::USD)
        .expect("the lookup prices");

    let lines = usage_lines(&counts);
    let derived =
        ledger_cost::derive_spend_micros(&card, [(LANE, &lines[..])].into_iter(), 0, true);

    let one = ledger_cost::price_ledger(
        &[one_entry(&counts, 0, 0).with_tier(half)],
        &history,
        CurrencyCode::USD,
    )
    .expect("prices");

    row(
        "cost::price  (lookup, tier applied)     [micro-units]",
        lookup.micros(),
    );
    row(
        "derive_spend_micros  (no tier at all)   [micro-units]",
        derived,
    );
    row(
        "ONE function  (tier applied)            [micro-units]",
        one.micros(),
    );

    assert_eq!(derived, 7_000, "full price");
    assert_eq!(lookup.micros(), 3_500, "half price");
    assert_eq!(
        one.micros(),
        3_500,
        "the one function agrees with the lookup"
    );
    // A deployment that ever uses a non-standard tier bills double on every read that derives.
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// D7 — `nano_rate` TAKES AN `f64`. #77(8)/#81 ban binary floating point on any money path, and
//      the ban is not decoration: the double picks the wrong side of a rounding boundary.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// The exact decimal answer `nano_rate` is specified to give: the configured decimal times a
/// thousand, rounded half AWAY FROM ZERO, computed over the digit text with no double in it.
fn nano_rate_exact_from_text(decimal: &str) -> u64 {
    let count = busbar_contract::count::Count::parse(decimal).expect("a decimal literal");
    // A `Count` is a mantissa at scale 6. ×1000 lands at scale 3; rounding half away from zero at
    // scale 0 is (mantissa×1000 + 500_000) / 1_000_000 for a positive value.
    let scaled = count.micros() * 1_000;
    let rounded = (scaled + 500_000) / 1_000_000;
    u64::try_from(rounded).expect("inside the range")
}

#[test]
fn d7_the_f64_rate_conversion_rounds_the_wrong_way_at_a_decimal_half_boundary() {
    rule("D7  `nano_rate(f64)` vs the exact decimal conversion (#77(8), #81)");

    // Search the neighbourhood of the half-boundary for a configured rate whose exact decimal
    // conversion and whose `f64` conversion differ. The value is not cherry-picked out of thin
    // air — it is whatever the scan finds first, so the defect is a property of the conversion and
    // not of one unlucky literal.
    let mut disagreements: Vec<(String, u64, u64)> = Vec::new();
    for thousandths in 1u64..200_000 {
        // A configured rate with exactly four decimal places, i.e. ending in a half-nano boundary.
        let text = format!(
            "{}.{:04}",
            thousandths / 10_000,
            (thousandths % 10_000) * 10 + 5
        );
        let exact = nano_rate_exact_from_text(&text);
        let through_f64 = ledger_cost::nano_rate(text.parse::<f64>().expect("parses"));
        if exact != through_f64 {
            disagreements.push((text, exact, through_f64));
            if disagreements.len() == 5 {
                break;
            }
        }
    }

    for (text, exact, through_f64) in &disagreements {
        row(
            &format!("rate `{text}` micro-units/token  exact / via f64"),
            format!("{exact} / {through_f64}"),
        );
    }

    assert!(
        !disagreements.is_empty(),
        "the scan found no disagreement — which would mean the f64 path is exact, and it is not"
    );
    // Every one of these is one nano-unit per token, forever, on a rate an operator typed exactly.
    for (_, exact, through_f64) in &disagreements {
        assert_eq!(exact.abs_diff(*through_f64), 1);
    }
    let (text, exact, through_f64) = &disagreements[0];
    eprintln!(
        "  → over a billion tokens, `{text}` bills {} nano-units too {} \
         ({exact} vs {through_f64} per token)",
        1_000_000_000u64,
        if exact > through_f64 {
            "little"
        } else {
            "much"
        }
    );
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// D8 — THE METRICS GAUGES CAST MONEY THROUGH AN `f64`.
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn d8_the_metrics_gauge_serves_a_different_number_than_the_admin_read() {
    rule("D8  `busbar_key_spend_cents` / `busbar_bucket_spend_cents` — `spend_cents as f64`");

    // `metrics.rs:401` and `metrics.rs:462` set the gauge to `spend_cents as f64`. Above 2^53 an
    // `f64` has no room for the ones digit, so the gauge and the admin JSON serve two numbers for
    // one figure.
    let spend_cents: i64 = 9_007_199_254_740_993; // 2^53 + 1
    let served = spend_cents as f64;
    let read_back = served as i64;

    row(
        "admin read   (i64)                      [cents]      ",
        spend_cents,
    );
    row(
        "/metrics gauge  (f64)                   [cents]      ",
        read_back,
    );

    assert_ne!(
        read_back, spend_cents,
        "#77(8): no f32/f64 on any money path — and the gauge is a served money byte"
    );
    assert_eq!(read_back, 9_007_199_254_740_992);
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// D9 — THE ADMIN READ RESOLVES AT A BUCKET-LEVEL INSTANT, NOT AT EACH POSTING'S OWN
//      `arrived_ms`, so a sub-day back-dated correction cannot reach the rows it was written for.
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn d9_a_sub_day_back_dated_correction_is_a_no_op_for_the_admin_read() {
    rule("D9  `row_priced_at_ms` clips to the bucket; #79 resolves at the posting");

    const DAY: u64 = 86_400;
    let bucket_start_secs = DAY; // the second UTC day
    let bucket_start_ms = bucket_start_secs * 1_000;

    // The deployment's opening card, effective from zero. Every row accrued under it carries
    // `priced_from_ms == 0`, which is that entry's own `effective_from`.
    let mut history = History::opening(ledger_card([3.0, 16.0, 0.0, 0.0], 0), 0);
    // A SIGNED BACK-DATED CORRECTION over three hours of that day — the sanctioned repair path for
    // "the ratecard was wrong" (#79).
    history.append(CardEntryDraft {
        effective_from: bucket_start_ms + 3 * 3_600_000,
        effective_until: Some(bucket_start_ms + 6 * 3_600_000),
        card: ledger_card([30.0, 160.0, 0.0, 0.0], 0),
        appended_at: bucket_start_ms + 48 * 3_600_000,
        author: Author::Amend {
            operator_fingerprint: "operator".to_string(),
            reason_hash: [0u8; 32],
        },
    });
    let view = history.current();

    let counts: [(&str, u64); 2] = [(INPUT, 1_000), (OUTPUT, 250)];
    // A row genuinely accrued at 04:00 on that day, inside the corrected window.
    let arrived_ms = bucket_start_ms + 4 * 3_600_000;
    let priced_from_ms = 0; // the opening entry's `effective_from`, which is what the row carries

    // ── WHAT THE ADMIN READ DOES.
    let admin_instant = admin_row_priced_at_ms(bucket_start_secs, priced_from_ms);
    let (_seq, admin_card) = view.card_at(admin_instant).expect("covered");
    let admin_figure = admin_row_at_card(admin_card, LANE, &counts, 0);

    // ── WHAT #79 SAYS: the posting's OWN instant.
    let one = ledger_cost::price_ledger(
        &[one_entry(&counts, arrived_ms, 0)],
        &history,
        CurrencyCode::USD,
    )
    .expect("prices");

    row(
        "GET /admin/usage  (resolves at bucket start)         ",
        admin_figure,
    );
    row(
        "ONE function      (resolves at arrived_ms)           ",
        one.micros(),
    );

    assert_eq!(
        admin_instant, bucket_start_ms,
        "clipped to midnight, outside the corrected window"
    );
    assert_eq!(admin_figure, 7_000, "the uncorrected card");
    assert_eq!(one.micros(), 70_000, "the correction, applied");
    // The sanctioned repair path moves nothing for exactly the rows it was written to repair, and
    // it is a tenfold difference on this slice.
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// E — THE EQUIVALENCES. Where every implementation is supposed to agree, it does, and the ONE
//     function is one of them. These are the rows the consolidation must not move.
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn e_every_implementation_agrees_on_the_case_they_were_all_written_for() {
    rule("E  one card, whole counts, the standard tier, every class priced");

    let rates = [3.0f64, 16.0, 0.5, 4.0];
    let fee = 2i64;
    let counts: [(&str, u64); 4] = [
        (INPUT, 1_000_000),
        (OUTPUT, 250_000),
        (CACHE_READ, 7_000_000),
        (CACHE_WRITE, 30_000),
    ];
    let requests = 3u64;

    let card = ledger_card(rates, fee);
    let history = History::opening(card.clone(), 0);
    let lines = usage_lines(&counts);
    let units = enforcement_units(&counts);
    let kernel = kernel_cost_model(Some(&[(LANE, rates)]), fee);
    let door = budget_pricer(Some(&[(LANE, rates)]), fee);

    // ── MICRO-UNITS
    let ledger_micros =
        ledger_cost::derive_spend_micros(&card, [(LANE, &lines[..])].into_iter(), requests, true);
    let kernel_micros = kernel.derive_spend_micros([(LANE, &units)].into_iter(), requests, true);
    let admin_flat = admin_row_flat(&kernel, LANE, &counts, requests);
    let admin_dated = admin_row_at_card(&card, LANE, &counts, requests);
    let usage = {
        let seal = busbar_contract::caps::KernelSeal::acquire_for_kernel();
        let token = busbar_contract::caps::Grant::<busbar_contract::caps::Consumption>::mint(&seal);
        busbar_contract::caps::Usage::report(&token, usage_lines(&counts))
            .expect("a report within the line bound")
    };
    let posting = ledger_cost::Posting::from_usage(
        LANE,
        &usage,
        requests,
        ledger_cost::STANDARD_TIER_BP,
        0,
        0,
    );
    let lookup = ledger_cost::price(&history.current(), &posting, CurrencyCode::USD)
        .expect("the lookup prices");
    let one = ledger_cost::price_ledger(
        &[one_entry(&counts, 0, requests)],
        &history,
        CurrencyCode::USD,
    )
    .expect("prices");

    row(
        "ledger  derive_spend_micros             [micro-units]",
        ledger_micros,
    );
    row(
        "kernel  CostModel::derive_spend_micros  [micro-units]",
        kernel_micros,
    );
    row(
        "admin   derive_spend_micros_row         [micro-units]",
        admin_flat,
    );
    row(
        "admin   derive_spend_micros_row_at_card [micro-units]",
        admin_dated,
    );
    row(
        "ledger  cost::price (the lookup)        [micro-units]",
        lookup.micros(),
    );
    row(
        "ONE function                            [micro-units]",
        one.micros(),
    );

    // 1,000,000×3 + 250,000×16 + 7,000,000×0.5 + 30,000×4 = 3,000,000 + 4,000,000 + 3,500,000
    // + 120,000 = 10,620,000, plus 3 fees × 2 minor units × 10,000 = 60,000 ⇒ 10,680,000.
    for (label, figure) in [
        ("ledger derive", i128::from(ledger_micros)),
        ("kernel derive", i128::from(kernel_micros)),
        ("admin flat row", i128::from(admin_flat)),
        ("admin dated row", i128::from(admin_dated)),
        ("the lookup", i128::from(lookup.micros())),
        ("the one function", one.micros()),
    ] {
        assert_eq!(figure, 10_680_000, "{label} answers the same figure");
    }

    // ── AND THE CENT PROJECTION, WHICH IS WHERE THE ENFORCEMENT SIDE READS.
    let ledger_cents =
        ledger_cost::derive_spend_cents(&card, [(LANE, &lines[..])].into_iter(), requests, true);
    let kernel_cents = kernel.derive_spend_cents([(LANE, &units)].into_iter(), requests, true);
    let door_cents = door.derive_spend_cents([(LANE, &units)].into_iter(), requests, true);
    row(
        "ledger  derive_spend_cents              [cents]      ",
        ledger_cents,
    );
    row(
        "kernel  CostModel::derive_spend_cents   [cents]      ",
        kernel_cents,
    );
    row(
        "budget  Pricer::derive_spend_cents      [cents]      ",
        door_cents,
    );
    row(
        "ONE function  .minor(USD)               [cents]      ",
        one.minor(CurrencyCode::USD),
    );

    for (label, figure) in [
        ("ledger derive", i128::from(ledger_cents)),
        ("kernel derive", i128::from(kernel_cents)),
        ("the door", i128::from(door_cents)),
        ("the one function", one.minor(CurrencyCode::USD)),
    ] {
        assert_eq!(figure, 1_068, "{label} answers the same figure");
    }
}

#[test]
fn e_billing_off_is_zero_everywhere_and_the_fee_still_posts() {
    rule("E  rate_card ABSENT — the one place a silent zero is right (#42)");

    let counts: [(&str, u64); 2] = [(INPUT, 1_000_000), (OUTPUT, 1_000_000)];
    let card = RateCard::absent(2);
    let lines = usage_lines(&counts);
    let units = enforcement_units(&counts);
    let kernel = kernel_cost_model(None, 2);
    let door = budget_pricer(None, 2);

    let ledger_micros =
        ledger_cost::derive_spend_micros(&card, [(LANE, &lines[..])].into_iter(), 3, true);
    let kernel_micros = kernel.derive_spend_micros([(LANE, &units)].into_iter(), 3, true);
    let door_cents = door.derive_spend_cents([(LANE, &units)].into_iter(), 3, true);
    let one = ledger_cost::price_ledger(
        &[one_entry(&counts, 0, 3)],
        &History::opening(card, 0),
        CurrencyCode::USD,
    )
    .expect("an absent card prices everything at nothing");

    row(
        "ledger  derive_spend_micros             [micro-units]",
        ledger_micros,
    );
    row(
        "kernel  CostModel::derive_spend_micros  [micro-units]",
        kernel_micros,
    );
    row(
        "budget  Pricer::derive_spend_cents      [cents]      ",
        door_cents,
    );
    row(
        "ONE function                            [micro-units]",
        one.micros(),
    );

    assert_eq!(ledger_micros, 60_000);
    assert_eq!(kernel_micros, 60_000);
    assert_eq!(door_cents, 6);
    assert_eq!(one.micros(), 60_000);
    assert_eq!(one.minor(CurrencyCode::USD), 6);
}
