// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE EQUIVALENCE PROOF.** `money = f(ledger counts, dated ratecard)` — ONE function, and every
//! former copy of it in this tree now answers through it.
//!
//! A census taken on 2026-09-22 found `f` implemented more than twenty times across five crates;
//! the six that survived into Phase 2 (item 104) answered a card silent about a model in THREE
//! ways — `i64::MAX` (block), the flat fee alone (free), `Err(LaneUnpriced)` (refuse) — with three
//! rounding rules and two overflow policies. They are collapsed onto
//! `busbar_kernel_ledger::cost::Tally`, the one function, and this file proves it two ways:
//!
//! 1. **BEHAVIOURALLY** — every former copy is RUN on one constructed ledger slice and one card, and
//!    must answer exactly what the one function answers: the same figure, or the same refusal. The
//!    fixtures cover the cases the copies used to disagree on: an unpriced lane and an unpriced
//!    class (#42), an overflow (item 28), a rate below the card's quantum (item 22), a non-standard
//!    tier on the settlement path and on the read path (item 27), and billing off (#42's one
//!    silent zero). A copy that DIVERGES reddens here.
//! 2. **STRUCTURALLY** — the production source is walked and every function that derives money must
//!    route through the one function; the tier arithmetic and the multiply-and-sum fold may be
//!    CALLED only where the census names. A planted SEVENTH COPY — a new `derive_spend_*` with its
//!    own arithmetic, a new call to the tier rule, a new fold — reddens here even if it happens to
//!    agree on every fixture above. The census proves it can see one: it is run over the real tree
//!    plus a planted copy and must flag it.
//!
//! The composition root is the only crate entitled to name all five crates, which is why the proof
//! lives here. Run with `-- --nocapture` to print the table.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use busbar_kernel_ledger::cost::{
    self as ledger_cost, Author, CardEntryDraft, History, HistorySeq, LaneClass, LedgerEntry,
    MoneyError, RateCard,
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

/// The counts as the ENFORCEMENT ledger (`UsageLedger` / `ModelTokens.usage_units`) holds them.
fn enforcement_units(pairs: &[(&'static str, u64)]) -> BTreeMap<String, u64> {
    pairs.iter().map(|(k, v)| ((*k).to_string(), *v)).collect()
}

/// The same counts as the ledger crate's read-time derivation consumes them.
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

/// The same counts as a sealed usage report, for the settlement posting.
fn usage_report(pairs: &[(&'static str, u64)]) -> busbar_contract::caps::Usage {
    let seal = busbar_contract::caps::KernelSeal::acquire_for_kernel();
    let token = busbar_contract::caps::Grant::<busbar_contract::caps::Consumption>::mint(&seal);
    busbar_contract::caps::Usage::report(&token, usage_lines(pairs))
        .expect("a report within the line bound")
}

/// The same counts as a [`LedgerEntry`] for the ONE function, dated at an instant.
fn one_entry(
    lane: &str,
    pairs: &[(&'static str, u64)],
    arrived_ms: u64,
    fee_count: u64,
) -> LedgerEntry {
    pairs
        .iter()
        .fold(LedgerEntry::new(lane, arrived_ms), |e, (class, q)| {
            e.with_whole(*class, *q)
        })
        .with_fee_count(fee_count)
}

/// One lane's four reserved rates, in configured micro-units per token.
type Rates4 = [f64; 4];

/// A `busbar-kernel` cost model — behind `GET /groups/{g}/usage`, `GET /keys/{id}/usage`, the
/// `/metrics` gauges, the hook seam's `budget_state`, and the live LLM door `try_admit`.
fn kernel_cost_model(
    rates: Option<&[(&str, Rates4)]>,
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
                        ..Default::default()
                    },
                )
            })
            .collect()
    });
    busbar_kernel::cost::CostModel::resolve_parts(card.as_ref(), per_request_fee, &BTreeMap::new())
}

/// A `busbar-kernel-budget` pricer — the BUDGET door's — holding the card the ledger built.
fn budget_pricer(
    rates: Option<&[(&str, Rates4)]>,
    per_request_fee: i64,
) -> busbar_kernel_budget::Pricer {
    busbar_kernel_budget::Pricer::from_card(ledger_card(rates, per_request_fee))
}

/// The ledger crate's card over lanes' four reserved classes — the card the one function prices.
fn ledger_card(rates: Option<&[(&str, Rates4)]>, fee: i64) -> RateCard {
    RateCard::from_config(
        rates.map(|rows| {
            rows.iter().map(|(lane, r)| {
                (
                    *lane,
                    ledger_cost::TierRates {
                        input: r[0],
                        output: r[1],
                        cache_read: r[2],
                        cache_write: r[3],
                    },
                )
            })
        }),
        fee,
    )
}

use busbar_core_admin::v1::service::read_path_money as admin;

/// One metering row in the shape `GET /api/v1/admin/usage` aggregates before it prices.
fn admin_row(
    counts: &[(&'static str, u64)],
    requests: u64,
) -> busbar_kernel::admin::v1::contract::UsageBreakdown {
    let at = |unit: &str| {
        counts
            .iter()
            .find(|(k, _)| *k == unit)
            .map(|(_, v)| *v)
            .unwrap_or(0)
    };
    busbar_kernel::admin::v1::contract::UsageBreakdown {
        tokens_input: at(INPUT),
        tokens_output: at(OUTPUT),
        tokens_cache_read: at(CACHE_READ),
        // The row's field name for the cache-WRITE tier; the endpoint maps it onto `cache_write`.
        tokens_cache_creation: at(CACHE_WRITE),
        requests,
        spend_micros: 0,
    }
}

/// `GET /admin/usage`'s DATED derivation — `v1/service.rs`'s `derive_spend_micros_row_at_card`,
/// CALLED, against a history whose only entry is `card`.
fn admin_row_at_card(
    card: &RateCard,
    cost: &busbar_kernel::cost::CostModel,
    model: &str,
    counts: &[(&'static str, u64)],
    requests: u64,
) -> Result<i64, MoneyError> {
    let only = History::opening(card.clone(), 0);
    admin::derive_spend_micros_row_at_card(
        &only.current(),
        0,
        card,
        cost,
        model,
        &admin_row(counts, requests),
    )
}

fn row(label: &str, figure: impl std::fmt::Debug) {
    eprintln!("  {label:<58} {figure:>30?}");
}

fn rule(title: &str) {
    eprintln!(
        "\n── {title} {}",
        "─".repeat(84usize.saturating_sub(title.len()))
    );
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE BEHAVIOURAL HALF — every former copy, run, against the one function.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// What every former copy answered for one case, projected to the one function's vocabulary:
/// `Ok(micro-units)` or the refusal. A copy that only speaks whole minor units is compared at the
/// minor projection instead (see [`Case::check`]).
struct Answers {
    one_micros: Result<i128, MoneyError>,
    one_minor: Result<i128, MoneyError>,
    micros: Vec<(&'static str, Result<i128, MoneyError>)>,
    minor: Vec<(&'static str, Result<i128, MoneyError>)>,
    /// Copies with their own refusal vocabulary: they must refuse exactly when the one function
    /// refuses, and otherwise match its figure (in micro-units).
    refuse_alike: Vec<(&'static str, Option<i128>)>,
}

/// One consumption on one card, fed to every copy.
struct Case {
    title: &'static str,
    rates: Option<&'static [(&'static str, Rates4)]>,
    fee: i64,
    lane: &'static str,
    counts: &'static [(&'static str, u64)],
    fee_count: u64,
}

impl Case {
    fn run(&self) -> Answers {
        let card = ledger_card(self.rates, self.fee);
        let history = History::opening(card.clone(), 0);
        let kernel = kernel_cost_model(self.rates, self.fee);
        let door = budget_pricer(self.rates, self.fee);
        let lines = usage_lines(self.counts);
        let units = enforcement_units(self.counts);

        // THE ONE FUNCTION.
        let one = ledger_cost::price_ledger(
            &[one_entry(self.lane, self.counts, 0, self.fee_count)],
            &history,
        );
        let one_micros = one.clone().map(|m| m.micros());
        let one_minor = one.map(|m| m.minor());

        let micros: Vec<(&'static str, Result<i128, MoneyError>)> = vec![
            (
                "ledger  derive_spend_micros",
                ledger_cost::derive_spend_micros(
                    &card,
                    [(self.lane, &lines[..])].into_iter(),
                    self.fee_count,
                    true,
                )
                .map(i128::from),
            ),
            (
                "kernel  CostModel::derive_spend_micros (hooks, reads)",
                kernel
                    .derive_spend_micros([(self.lane, &units)].into_iter(), self.fee_count, true)
                    .map(i128::from),
            ),
            (
                "admin   derive_spend_micros_row (current card)",
                admin::derive_spend_micros_row(
                    &kernel,
                    self.lane,
                    &admin_row(self.counts, self.fee_count),
                )
                .map(i128::from),
            ),
            (
                "admin   derive_spend_micros_row_at_card (dated, #79)",
                admin_row_at_card(&card, &kernel, self.lane, self.counts, self.fee_count)
                    .map(i128::from),
            ),
        ];
        let minor: Vec<(&'static str, Result<i128, MoneyError>)> = vec![
            (
                "ledger  derive_spend_cents",
                ledger_cost::derive_spend_cents(
                    &card,
                    [(self.lane, &lines[..])].into_iter(),
                    self.fee_count,
                    true,
                )
                .map(i128::from),
            ),
            (
                "kernel  CostModel::derive_spend_cents (the LLM door)",
                kernel
                    .derive_spend_cents([(self.lane, &units)].into_iter(), self.fee_count, true)
                    .map(i128::from),
            ),
            (
                "budget  Pricer::derive_spend_cents (the budget door)",
                door.derive_spend_cents([(self.lane, &units)].into_iter(), self.fee_count, true)
                    .map(i128::from),
            ),
        ];

        // THE SETTLEMENT LOOKUP, in its settlement posture — it refuses exactly where the one
        // function refuses, and otherwise posts the one function's figure.
        let posting = ledger_cost::Posting::from_usage(
            self.lane,
            &usage_report(self.counts),
            self.fee_count,
            ledger_cost::STANDARD_TIER_BP,
            0,
            0,
        );
        let settled = ledger_cost::price_fail_closed(&history.current(), &posting)
            .ok()
            .and_then(|p| ledger_cost::Money::of_nanos(p.priced_nanos).ok())
            .map(ledger_cost::Money::micros);
        // THE HOST METERING SEAM (`MeteringHost::price_usage`): nano-units, no fee.
        let metered = kernel
            .price_usage_nanos(
                self.lane,
                &busbar_substrate_values::billing::Usage {
                    usage_units: units.clone(),
                },
            )
            .map(|nanos| {
                // Lift to the case's micro figure: the seam prices the tokens; the fee is the
                // door's, added here from the card so the two are comparable.
                i128::try_from(nanos / 1_000).expect("fits")
                    + i128::from(card.fee()) * 10_000 * i128::from(self.fee_count)
            });

        Answers {
            one_micros,
            one_minor,
            micros,
            minor,
            refuse_alike: vec![
                ("ledger  price_fail_closed (settlement)", settled),
                ("kernel  price_usage_nanos (metering seam)", metered),
            ],
        }
    }

    /// Every copy answers what the one function answers: the same figure, or the same refusal.
    fn check(&self) -> Answers {
        rule(self.title);
        let a = self.run();
        row("THE ONE FUNCTION  [micro]", &a.one_micros);
        for (label, got) in &a.micros {
            row(label, got);
            assert_eq!(
                got, &a.one_micros,
                "{}: `{label}` diverges from the one function",
                self.title
            );
        }
        row("THE ONE FUNCTION  [minor]", &a.one_minor);
        for (label, got) in &a.minor {
            row(label, got);
            assert_eq!(
                got, &a.one_minor,
                "{}: `{label}` diverges from the one function",
                self.title
            );
        }
        for (label, got) in &a.refuse_alike {
            row(label, got);
            assert_eq!(
                *got,
                a.one_micros.clone().ok(),
                "{}: `{label}` must refuse exactly when the one function refuses, and otherwise \
                 answer its figure",
                self.title
            );
        }
        a
    }
}

/// E — one card, whole counts, the standard tier, every class priced. The case all six copies were
/// written for, and the figure the consolidation must not move.
#[test]
fn e_every_former_copy_answers_the_one_functions_figure() {
    let a = Case {
        title: "E  every class priced",
        rates: Some(&[(LANE, [3.0, 16.0, 0.5, 4.0])]),
        fee: 2,
        lane: LANE,
        counts: &[
            (INPUT, 1_000_000),
            (OUTPUT, 250_000),
            (CACHE_READ, 7_000_000),
            (CACHE_WRITE, 30_000),
        ],
        fee_count: 3,
    }
    .check();
    // 3,000,000 + 4,000,000 + 3,500,000 + 120,000 + 3 fees × 2 minor × 10,000 = 10,680,000.
    assert_eq!(a.one_micros, Ok(10_680_000));
    assert_eq!(a.one_minor, Ok(1_068));
}

/// D4 / items 124, 25, 31 — A PRESENT CARD SILENT ABOUT THE LANE. The copies used to answer three
/// ways: the kernel door and every read the flat fee alone (FREE — 19 million micro-units of
/// consumption dropped), the budget door `i64::MAX`, the one function a refusal. Now every copy
/// refuses: BOTH admission doors block, every read fails.
#[test]
fn d4_an_unpriced_lane_refuses_at_both_doors_and_on_every_read() {
    let a = Case {
        title: "D4  a present card that does not name the lane (#42)",
        rates: Some(&[(LANE, [3.0, 16.0, 0.0, 0.0])]),
        fee: 2,
        lane: "a-model-nobody-priced",
        counts: &[(INPUT, 1_000_000), (OUTPUT, 1_000_000)],
        fee_count: 1,
    }
    .check();
    assert!(
        matches!(a.one_micros, Err(MoneyError::LaneUnpriced { .. })),
        "#42: rate_card PRESENT and the lane is not priced ⇒ REFUSE, never a silent 0"
    );
}

/// D5 / item 37 — A PRESENT CARD SILENT ABOUT A CLASS IT NAMES THE LANE FOR. The ledger and kernel
/// derivations used to price the ten million cache-reads at 0 (7,000 micro-units served for the
/// input and output alone). #42 inverts it: every copy REFUSES.
#[test]
fn d5_an_unpriced_class_on_a_priced_lane_refuses_everywhere() {
    // The card the operator wrote names input and output and nothing else for this lane.
    let card = RateCard::from_micro_rates(
        [
            (LaneClass::new(LANE, INPUT), 3.0),
            (LaneClass::new(LANE, OUTPUT), 16.0),
        ],
        0,
    );
    let counts: [(&str, u64); 3] = [(INPUT, 1_000), (OUTPUT, 250), (CACHE_READ, 10_000_000)];
    let one = ledger_cost::price_ledger(
        &[one_entry(LANE, &counts, 0, 0)],
        &History::opening(card.clone(), 0),
    );
    let derived = ledger_cost::derive_spend_micros(
        &card,
        [(LANE, &usage_lines(&counts)[..])].into_iter(),
        0,
        true,
    );
    let posting = ledger_cost::Posting::from_usage(
        LANE,
        &usage_report(&counts),
        0,
        ledger_cost::STANDARD_TIER_BP,
        0,
        0,
    );
    let settled = ledger_cost::price_fail_closed(&History::opening(card, 0).current(), &posting);

    rule("D5  a priced lane, a class the card is silent about (#42)");
    row("THE ONE FUNCTION", &one);
    row("ledger  derive_spend_micros", &derived);
    row(
        "ledger  price_fail_closed (settlement)",
        settled.as_ref().err(),
    );
    let refusal = MoneyError::ClassUnpriced {
        card_seq: HistorySeq::OPENING,
        lane: LANE.to_string(),
        class: CACHE_READ.to_string(),
    };
    assert_eq!(
        one,
        Err(refusal.clone()),
        "#42: a hit class not priced ⇒ REFUSE"
    );
    assert_eq!(
        derived,
        Err(refusal),
        "the read-time derivation refuses too — never 7,000"
    );
    assert!(
        matches!(settled, Err(ledger_cost::Unpriceable::ClassUnpriced { ref class, .. }) if class == CACHE_READ),
        "settlement refuses the same class"
    );
}

/// Item 22 — A RATE BELOW THE CARD'S QUANTUM. `0.0004` micro-units a token used to become a cell
/// priced at 0 while the card called the class PRICED. It is an unpriced cell now, and every copy
/// — the kernel door included, which used to hold its own rate table — refuses a hit on it.
#[test]
fn i22_a_sub_quantum_rate_refuses_everywhere_instead_of_pricing_at_zero() {
    let a = Case {
        title: "22  a configured rate below the half-nano quantum",
        rates: Some(&[(LANE, [0.0004, 16.0, 0.0, 0.0])]),
        fee: 0,
        lane: LANE,
        counts: &[(INPUT, 1_000_000_000), (OUTPUT, 10)],
        fee_count: 0,
    }
    .check();
    assert!(
        matches!(a.one_micros, Err(MoneyError::ClassUnpriced { ref class, .. }) if class == INPUT),
        "the card cannot represent 0.0004 and must not price it at zero: {:?}",
        a.one_micros
    );
}

/// Item 28 — OVERFLOW REFUSES, NEVER SATURATES. The copies used to pin at `i64::MAX` (≈ $92
/// quadrillion served as a figure) — on the success arm. Every copy refuses now.
#[test]
fn i28_an_overflow_refuses_everywhere_and_is_never_billed_at_the_ceiling() {
    let a = Case {
        title: "28  u64::MAX tokens at 1e15 micro-units a token",
        rates: Some(&[(LANE, [1.0e15, 0.0, 0.0, 0.0])]),
        fee: 0,
        lane: LANE,
        counts: &[(INPUT, u64::MAX)],
        fee_count: 0,
    }
    .check();
    assert_eq!(a.one_micros, Err(MoneyError::Overflow));
}

/// #42's ONE SILENT ZERO — rate_card ABSENT: tokens read 0, the fee still posts, nothing refuses.
#[test]
fn e_billing_off_is_zero_everywhere_and_the_fee_still_posts() {
    let a = Case {
        title: "E  rate_card ABSENT",
        rates: None,
        fee: 2,
        lane: LANE,
        counts: &[(INPUT, 1_000_000), (OUTPUT, 1_000_000)],
        fee_count: 3,
    }
    .check();
    assert_eq!(a.one_micros, Ok(60_000));
    assert_eq!(a.one_minor, Ok(6));
}

/// D6 / item 27 — THE TIER APPLIES IDENTICALLY FOR SETTLE AND READ. `with_tier` used to have no
/// production caller and the settlement lookup carried its own tier call: settlement could apply a
/// tier no read applied. Both are the one function's tier rule now, over the same pre-tier sum,
/// and a half-price posting settles and reads at the same figure.
#[test]
fn d6_the_tier_is_one_rule_for_settlement_and_for_every_read() {
    rule("D6  the service-tier multiplier (item 27)");
    let card = ledger_card(Some(&[(LANE, [3.0, 16.0, 0.0, 0.0])]), 1);
    let history = History::opening(card, 0);
    let counts: [(&str, u64); 2] = [(INPUT, 1_001), (OUTPUT, 251)];
    for tier in [5_000u32, 8_000, 10_000, 15_000] {
        let posting = ledger_cost::Posting::from_usage(LANE, &usage_report(&counts), 1, tier, 0, 0);
        let settled = ledger_cost::price(&history.current(), &posting).expect("settles");
        let read = ledger_cost::price_exact(
            &[one_entry(LANE, &counts, 0, 1).with_tier(tier)],
            &history.current(),
        )
        .expect("reads");
        row(
            &format!("tier {tier} bp  settled / read  [nano]"),
            (settled.priced_nanos, read / 1_000_000),
        );
        assert_eq!(
            settled.priced_nanos,
            ledger_cost::nanos_of_exact(read).expect("fits"),
            "tier {tier}: the settlement posting and the read must be one tier rule"
        );
    }
    // Hand-computed at half price: (1,001×3,000 + 251×16,000 + 10,000,000) × ½ = 8,509,500 nano.
    let half = ledger_cost::price_exact(
        &[one_entry(LANE, &counts, 0, 1).with_tier(5_000)],
        &history.current(),
    )
    .expect("reads");
    assert_eq!(ledger_cost::nanos_of_exact(half), Ok(8_509_500));
}

/// D1 — A RATE-CARD EDIT. The dated read (#79) prices each row at its own card; the enforcement
/// book carries no instant and prices the window at the current card. Both are the one function
/// now — the difference is the INPUT (which card), not the arithmetic, and it is item 23's park.
#[test]
fn d1_a_rate_card_edit_is_one_function_over_two_different_inputs() {
    rule("D1  a rate-card edit: the dated read vs every current-card read");
    let counts: [(&str, u64); 2] = [(INPUT, 1_000), (OUTPUT, 250)];
    let mut history = History::opening(ledger_card(Some(&[(LANE, [3.0, 16.0, 0.0, 0.0])]), 2), 0);
    history.append(CardEntryDraft {
        effective_from: 1_000_000,
        effective_until: None,
        card: ledger_card(Some(&[(LANE, [1.0, 4.0, 0.0, 0.0])]), 1),
        appended_at: 1_000_000,
        author: Author::Config { policy_epoch: 1 },
    });
    let dated = ledger_cost::price_ledger(
        &[
            one_entry(LANE, &counts, 500_000, 1),
            one_entry(LANE, &counts, 2_000_000, 1),
        ],
        &history,
    )
    .expect("every class is priced on both cards");

    // The current card, both rows — the one function at the current card, and the copies at it.
    let current = ledger_card(Some(&[(LANE, [1.0, 4.0, 0.0, 0.0])]), 1);
    let at_current = ledger_cost::price_ledger(
        &[
            one_entry(LANE, &counts, 0, 1),
            one_entry(LANE, &counts, 0, 1),
        ],
        &History::opening(current, 0),
    )
    .expect("prices");
    let kernel = kernel_cost_model(Some(&[(LANE, [1.0, 4.0, 0.0, 0.0])]), 1);
    let units = enforcement_units(&counts);
    let flat_micros = kernel
        .derive_spend_micros([(LANE, &units), (LANE, &units)].into_iter(), 2, true)
        .expect("prices");

    row("ONE function, dated history  [micro]", dated.micros());
    row("ONE function, current card   [micro]", at_current.micros());
    row("kernel derive (current card) [micro]", flat_micros);
    assert_eq!(dated.micros(), 39_000);
    assert_eq!(i128::from(flat_micros), at_current.micros());
    assert_eq!(at_current.micros(), 24_000);
}

/// D8 — THE METRICS GAUGE IS THE ONE FUNCTION'S INTEGER, UP TO THE ONE EGRESS BOUNDARY. Item 24
/// moved the money gauges to `metrics/money.rs`, where the only float is `set_gauge` — the declared
/// `MONEY_EGRESS` boundary the exporter forces. Everything before it is integer: the figure the
/// gauge is handed is `CostModel::derive_spend_cents`, which is the one function, exact above 2^53
/// where a float would have lost the ones digit.
#[test]
fn d8_the_gauge_figure_is_the_one_functions_integer_up_to_the_egress_boundary() {
    rule("D8  `busbar_*_spend_cents` — integer up to MONEY_EGRESS");
    let requests: u64 = (1u64 << 53) + 1;
    let kernel = kernel_cost_model(None, 1);
    let gauge_input = kernel
        .derive_spend_cents(std::iter::empty(), requests, true)
        .expect("a fee-only bucket prices");
    let mut tally = ledger_cost::Tally::at_card(kernel.card());
    tally
        .fee(
            0,
            ledger_cost::STANDARD_TIER_BP,
            ledger_cost::whole(requests),
        )
        .expect("prices");
    let one = tally.money().expect("fits").minor_i64().expect("fits");
    row("one function  [minor]", one);
    row("gauge input   [minor]", gauge_input);
    assert_eq!(gauge_input, one);
    assert_eq!(
        gauge_input, 9_007_199_254_740_993,
        "2^53 + 1, exact — no float before egress"
    );
}

/// D9 — M32, PARKED-OWNER (Q14): the admin read resolves a row at a BUCKET-level instant, not at
/// each posting's own `arrived_ms`, so a sub-day back-dated correction cannot reach its rows. Kept
/// verbatim as the parked measurement; not this collapse's to resolve.
#[test]
fn d9_a_sub_day_back_dated_correction_is_a_no_op_for_the_admin_read() {
    rule("D9  `row_priced_at_ms` clips to the bucket; #79 resolves at the posting");
    const DAY: u64 = 86_400;
    let bucket_start_secs = DAY;
    let bucket_start_ms = bucket_start_secs * 1_000;
    let mut history = History::opening(ledger_card(Some(&[(LANE, [3.0, 16.0, 0.0, 0.0])]), 0), 0);
    history.append(CardEntryDraft {
        effective_from: bucket_start_ms + 3 * 3_600_000,
        effective_until: Some(bucket_start_ms + 6 * 3_600_000),
        card: ledger_card(Some(&[(LANE, [30.0, 160.0, 0.0, 0.0])]), 0),
        appended_at: bucket_start_ms + 48 * 3_600_000,
        author: Author::Amend {
            operator_fingerprint: "operator".to_string(),
            reason_hash: [0u8; 32],
        },
    });
    let view = history.current();
    let counts: [(&str, u64); 2] = [(INPUT, 1_000), (OUTPUT, 250)];
    let arrived_ms = bucket_start_ms + 4 * 3_600_000;

    let admin_instant = admin::row_priced_at_ms(bucket_start_secs, 0);
    let (_seq, admin_card) = view.card_at(admin_instant).expect("covered");
    let alias_seam = kernel_cost_model(None, 0);
    let admin_figure =
        admin_row_at_card(admin_card, &alias_seam, LANE, &counts, 0).expect("prices");
    let one = ledger_cost::price_ledger(&[one_entry(LANE, &counts, arrived_ms, 0)], &history)
        .expect("prices");
    row("GET /admin/usage  (resolves at bucket start)", admin_figure);
    row("ONE function      (resolves at arrived_ms)", one.micros());
    assert_eq!(admin_instant, bucket_start_ms);
    assert_eq!(admin_figure, 7_000);
    assert_eq!(one.micros(), 70_000);
}

/// D2 — ITEM 123, INVERTED FROM ITS BASELINE TO THE CONVERGENCE. This case used to MEASURE the
/// residue: the enforcement side (the kernel's cost model and the budget door) projected its unit
/// map onto the RESERVED FOUR before handing the row to the one function, so an open meter class
/// (a2a `hops`, a rerank's `search_units`) priced there as nothing — 200 micro-units against the
/// one function's 5,200, and 0 at the door. Item 123 converged it: every class reaches the one
/// function on both sides, and the card (built from config's `units:` on the kernel side) prices
/// it. So the figures now AGREE — and a card silent about the class REFUSES on both sides (#42)
/// rather than dropping it.
#[test]
fn d2_an_open_meter_class_is_handed_to_the_one_function_by_the_enforcement_side() {
    rule("D2  an open meter class — item 123 converged");
    let card = RateCard::from_micro_rates(
        [
            (LaneClass::new(LANE, OUTPUT), 2.0),
            (LaneClass::new(LANE, "hops"), 5.0),
        ],
        0,
    );
    let counts: [(&str, u64); 2] = [(OUTPUT, 100_000), ("hops", 1_000_000)];
    let one = ledger_cost::price_ledger(
        &[one_entry(LANE, &counts, 0, 0)],
        &History::opening(card.clone(), 0),
    )
    .expect("the card prices both classes");
    let ledger_micros = ledger_cost::derive_spend_micros(
        &card,
        [(LANE, &usage_lines(&counts)[..])].into_iter(),
        0,
        true,
    );
    let units = enforcement_units(&counts);
    let config_card: BTreeMap<String, busbar_kernel::config::RateEntryCfg> = serde_yaml::from_str(
        &format!("{LANE}: {{ output_utok: 2, units: {{ hops: 5 }} }}\n"),
    )
    .expect("an open class parses under units:");
    let kernel =
        busbar_kernel::cost::CostModel::resolve_parts(Some(&config_card), 0, &BTreeMap::new());
    let kernel_micros = kernel.derive_spend_micros([(LANE, &units)].into_iter(), 0, true);
    let door = busbar_kernel_budget::Pricer::from_card(card.clone());
    let door_cents = door.derive_spend_cents([(LANE, &units)].into_iter(), 0, true);
    row("ONE function                 [micro]", one.micros());
    row("ledger derive (every class)  [micro]", &ledger_micros);
    row("kernel derive (every class)  [micro]", &kernel_micros);
    row("budget door   (every class)  [minor]", &door_cents);
    assert_eq!(one.micros(), 5_200_000, "100,000×2 + 1,000,000×5");
    assert_eq!(ledger_micros.map(i128::from), Ok(one.micros()));
    assert_eq!(
        kernel_micros.map(i128::from),
        Ok(one.micros()),
        "item 123: every class reaches it"
    );
    assert_eq!(
        door_cents.map(i128::from),
        Ok(one.minor()),
        "and the door caps on the same figure"
    );

    // A card that prices the lane but is silent about `hops`: both sides REFUSE (#42).
    let silent = kernel_cost_model(Some(&[(LANE, [0.0, 2.0, 0.0, 0.0])]), 0);
    let silent_door = budget_pricer(Some(&[(LANE, [0.0, 2.0, 0.0, 0.0])]), 0);
    for refusal in [
        silent
            .derive_spend_micros([(LANE, &units)].into_iter(), 0, true)
            .map(i128::from),
        silent_door
            .derive_spend_cents([(LANE, &units)].into_iter(), 0, true)
            .map(i128::from),
    ] {
        assert!(
            matches!(refusal, Err(MoneyError::ClassUnpriced { ref class, .. }) if class == "hops"),
            "an unpriced open class refuses, never a silent 0: {refusal:?}"
        );
    }
}

/// D7 — `nano_rate` TAKES AN `f64` (#77(8), #81). PARKED (`1.6.0-money-sweep.md`): the double picks
/// the wrong side of a decimal half-boundary. Kept verbatim as the parked measurement — card-build
/// quantisation is outside this collapse, which keeps it byte-identical (#44).
fn nano_rate_exact_from_text(decimal: &str) -> u64 {
    let count = busbar_contract::count::Count::parse(decimal).expect("a decimal literal");
    let scaled = count.micros() * 1_000;
    let rounded = (scaled + 500_000) / 1_000_000;
    u64::try_from(rounded).expect("inside the range")
}

#[test]
fn d7_the_f64_rate_conversion_rounds_the_wrong_way_at_a_decimal_half_boundary() {
    rule("D7  `nano_rate(f64)` vs the exact decimal conversion (#77(8), #81)");
    let mut disagreements: Vec<(String, u64, u64)> = Vec::new();
    for thousandths in 1u64..200_000 {
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
            (exact, through_f64),
        );
    }
    assert!(
        !disagreements.is_empty(),
        "the scan found no disagreement — which would mean the f64 path is exact, and it is not"
    );
    for (_, exact, through_f64) in &disagreements {
        assert_eq!(exact.abs_diff(*through_f64), 1);
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE STRUCTURAL HALF — the census. A copy that AGREES is still a copy.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// The workspace root, from this crate's manifest directory.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crates/busbar sits two below the workspace root")
        .to_path_buf()
}

/// Every PRODUCTION `.rs` file under `crates/*/src`, as (workspace-relative path, source). Test
/// modules are excluded by the tree's own conventions: a `tests/` directory, `*_tests.rs`, and the
/// `tests.rs` leaf files a parent mounts under `#[cfg(test)]`.
fn production_sources() -> Vec<(String, String)> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if matches!(name, "tests" | "testkit" | "test_support" | "target") {
                    continue;
                }
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    let root = workspace_root();
    let mut files = Vec::new();
    let Ok(crates) = std::fs::read_dir(root.join("crates")) else {
        panic!("the census must see the tree: crates/ is not readable");
    };
    for c in crates.flatten() {
        walk(&c.path().join("src"), &mut files);
    }
    files.sort();
    files
        .into_iter()
        .filter_map(|p| {
            let rel = p
                .strip_prefix(&root)
                .ok()?
                .to_string_lossy()
                .replace('\\', "/");
            let leaf = rel.rsplit('/').next().unwrap_or("");
            if leaf == "tests.rs" || leaf.ends_with("_tests.rs") || leaf.ends_with("_test.rs") {
                return None;
            }
            Some((rel, std::fs::read_to_string(&p).ok()?))
        })
        .collect()
}

/// Strip `//` comments so prose that NAMES a function is never read as a call to it.
fn code_only(src: &str) -> String {
    src.lines()
        .map(|l| match l.find("//") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The body of every `fn <name>` in a source, by brace matching from the signature.
fn fn_bodies(code: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let bytes = code.as_bytes();
    let mut i = 0;
    while let Some(off) = code[i..].find("fn ") {
        let at = i + off;
        i = at + 3;
        // `fn` must be a whole word.
        if at > 0 && (bytes[at - 1].is_ascii_alphanumeric() || bytes[at - 1] == b'_') {
            continue;
        }
        let name: String = code[at + 3..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if name.is_empty() {
            continue;
        }
        // The body opens at the first `{` after the signature (or the item is a declaration `;`).
        let rest = &code[at..];
        let (Some(brace), semi) = (rest.find('{'), rest.find(';')) else {
            continue;
        };
        if semi.is_some_and(|s| s < brace) {
            continue;
        }
        let mut depth = 0usize;
        let mut end = None;
        for (k, ch) in rest[brace..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(brace + k + 1);
                        break;
                    }
                }
                _ => {}
            }
        }
        if let Some(end) = end {
            out.push((name, rest[brace..end].to_string()));
        }
    }
    out
}

/// Is this function name a money derivation? The six surviving copies and every name a seventh
/// would plausibly take.
fn is_derivation_name(name: &str) -> bool {
    name.starts_with("derive_spend")
        || name.starts_with("price_usage")
        || name.starts_with("spend_micros")
        || name.starts_with("spend_cents")
        || matches!(
            name,
            "price_exact" | "price_at_card" | "price_in_view" | "one_function_total"
        )
}

/// **THE CENSUS.** Every finding is a copy of `f` outside the one function.
///
/// - **R1** — a function named like a derivation must reach the one function: its body names
///   `Tally`, or calls another derivation / the local `tally` helper (which itself names `Tally`),
///   or `price_in_view` / `price_ledger`. A derivation that does its own arithmetic is a copy.
/// - **R2** — the tier rule (`checked_apply_tier` / `apply_tier` / `apply_tier_signed`) is CALLED
///   only inside the one function (`cost/view.rs`) and its own definition file (`cost/posting.rs`).
/// - **R3** — the multiply-and-sum fold (`nanos_sum`) is called only by its definition file and by
///   the budget HOLD estimate (`estimate.rs`), which sizes a reservation and is not a spend figure.
/// - **R4** — the one function's accumulator is constructed only by the callers the collapse
///   registered. A new `Tally` user is a new route onto the one function, which is fine — but it
///   must be seen, so the list is exact.
fn census(sources: &[(String, String)]) -> Vec<String> {
    const TIER_RULE_HOMES: &[&str] = &[
        "crates/busbar-kernel-ledger/src/cost/view.rs",
        "crates/busbar-kernel-ledger/src/cost/posting.rs",
    ];
    const FOLD_HOMES: &[&str] = &[
        "crates/busbar-kernel-ledger/src/cost/rate.rs",
        "crates/busbar-kernel-budget/src/estimate.rs",
    ];
    const TALLY_ROUTES: &[&str] = &[
        "crates/busbar-kernel-ledger/src/cost/view.rs",
        "crates/busbar-kernel-ledger/src/cost/project.rs",
        "crates/busbar-kernel-ledger/src/cost/posting.rs",
        "crates/busbar-kernel/src/cost.rs",
        "crates/busbar-kernel-budget/src/price.rs",
    ];
    let mut findings = Vec::new();
    let mut exempt_seen: BTreeMap<(&str, &str), usize> = BTreeMap::new();
    for (path, src) in sources {
        let code = code_only(src);
        let bodies = fn_bodies(&code);
        let has_tally_helper = bodies
            .iter()
            .any(|(n, b)| n == "tally" && b.contains("Tally"));
        for (name, body) in &bodies {
            if !is_derivation_name(name) {
                continue;
            }
            let routes = body.contains("Tally")
                || (has_tally_helper && (body.contains("tally(") || body.contains(".tally(")))
                || body.contains("price_in_view(")
                || body.contains("price_exact(")
                || body.contains("price_ledger(")
                || body.contains("price_usage_nanos(")
                // Delegation to the host metering seam, whose kernel implementation is
                // `price_usage_nanos` (the one function) — see `plane_host`.
                || body.contains(".price_usage(")
                || body.contains("derive_spend_micros(")
                || body.contains("derive_spend_minor(")
                || body.contains("one_function_total(");
            if !routes {
                if let Some((file, fname, _, _)) = KNOWN_OUTSIDE_THIS_COLLAPSE
                    .iter()
                    .find(|(f, n, _, _)| *f == path.as_str() && *n == name.as_str())
                {
                    *exempt_seen.entry((file, fname)).or_default() += 1;
                    continue;
                }
                findings.push(format!(
                    "R1 {path}: `fn {name}` derives money without reaching the one function"
                ));
            }
        }
        for rule_fn in ["checked_apply_tier(", "apply_tier(", "apply_tier_signed("] {
            if !TIER_RULE_HOMES.contains(&path.as_str()) && code.contains(rule_fn) {
                findings.push(format!("R2 {path}: calls the tier rule `{rule_fn}..)`"));
            }
        }
        if !FOLD_HOMES.contains(&path.as_str()) && code.contains("nanos_sum(") {
            findings.push(format!(
                "R3 {path}: calls the multiply-and-sum fold `nanos_sum`"
            ));
        }
        if !TALLY_ROUTES.contains(&path.as_str()) && code.contains("Tally::") {
            findings.push(format!(
                "R4 {path}: a new route onto the one function — register it in the census"
            ));
        }
    }
    // An exemption is a MEASUREMENT, armed at today's count: one more such function in that file is
    // a new copy (RED), and one fewer means the residue was fixed and the entry must be struck.
    for (file, name, count, why) in KNOWN_OUTSIDE_THIS_COLLAPSE {
        let seen = exempt_seen.get(&(*file, *name)).copied().unwrap_or(0);
        if seen != *count && sources.iter().any(|(p, _)| p == file) {
            findings.push(format!(
                "R1 {file}: `fn {name}` seen {seen} time(s) outside the one function, the census \
                 names {count} ({why}) — a new copy, or a fixed one whose entry must be struck"
            ));
        }
    }
    findings
}

/// Derivation-named functions the census SEES and that are not routed through the one function,
/// each owned outside this collapse and named with its reason. Armed at today's count (§9.4).
const KNOWN_OUTSIDE_THIS_COLLAPSE: &[(&str, &str, usize, &str)] = &[
    (
        "crates/busbar-voice/src/runtime/metering.rs",
        "price_usage",
        1,
        "a `#[cfg(test)]` MockMeteringHost (LocalLease's stand-in and voice-conform's mock host \
         went with 1ee8dac1d, the session meter)",
    ),
];

/// THE TREE HOLDS ONE `f`. Every derivation routes through it; no copy of the tier rule or the
/// fold is called anywhere the census does not name.
#[test]
fn census_every_former_copy_routes_to_the_one_function() {
    let sources = production_sources();
    assert!(
        sources.len() > 500,
        "the census must walk the real tree, walked {}",
        sources.len()
    );
    // Positive control: the census SEES the derivations it certifies, by name, in their files.
    let seen: Vec<(String, String)> = sources
        .iter()
        .flat_map(|(p, s)| {
            fn_bodies(&code_only(s))
                .into_iter()
                .filter(|(n, _)| is_derivation_name(n))
                .map(|(n, _)| (p.clone(), n))
                .collect::<Vec<_>>()
        })
        .collect();
    for (file, name) in [
        (
            "crates/busbar-kernel-ledger/src/cost/view.rs",
            "price_exact",
        ),
        (
            "crates/busbar-kernel-ledger/src/cost/project.rs",
            "derive_spend_micros",
        ),
        (
            "crates/busbar-kernel-ledger/src/cost/posting.rs",
            "price_at_card",
        ),
        ("crates/busbar-kernel/src/cost.rs", "derive_spend_cents"),
        ("crates/busbar-kernel/src/cost.rs", "price_usage_nanos"),
        (
            "crates/busbar-kernel-budget/src/price.rs",
            "derive_spend_cents",
        ),
        (
            "crates/busbar-core-admin/src/v1/service.rs",
            "derive_spend_micros_row",
        ),
        (
            "crates/busbar-core-admin/src/v1/service.rs",
            "derive_spend_micros_row_at_card",
        ),
    ] {
        assert!(
            seen.iter().any(|(p, n)| p == file && n == name),
            "positive control: the census must see `{name}` in {file}; saw {seen:?}"
        );
    }
    let findings = census(&sources);
    for f in &findings {
        eprintln!("  {f}");
    }
    assert!(
        findings.is_empty(),
        "a copy of `money = f(ledger, card)` outside the one function:\n{}",
        findings.join("\n")
    );
}

/// THE CENSUS CAN SAY NO. The real tree plus one planted SEVENTH COPY — a derivation doing its own
/// multiply, a second call to the tier rule, a second fold — must be flagged on every rule. A census
/// that cannot fail proves nothing.
#[test]
fn census_flags_a_planted_seventh_copy() {
    let mut sources = production_sources();
    sources.push((
        "crates/busbar-kernel/src/seventh.rs".to_string(),
        r#"
        pub fn derive_spend_seventh(units: u64, rate: u64) -> u128 {
            let pre = u128::from(units).saturating_mul(u128::from(rate));
            busbar_kernel_ledger::cost::apply_tier(pre, 10_000)
        }
        pub fn spend_cents_elsewhere(pairs: Vec<(u64, u64)>) -> u128 {
            busbar_kernel_ledger::cost::nanos_sum(pairs)
        }
        pub fn quietly(card: &busbar_kernel_ledger::cost::RateCard) {
            let _ = busbar_kernel_ledger::cost::Tally::at_card(card);
        }
        "#
        .to_string(),
    ));
    let findings = census(&sources);
    for rule in ["R1", "R2", "R3", "R4"] {
        assert!(
            findings
                .iter()
                .any(|f| f.starts_with(rule) && f.contains("seventh.rs")),
            "the planted copy must trip {rule}; findings: {findings:?}"
        );
    }
    assert!(
        findings.iter().any(|f| f.contains("derive_spend_seventh")),
        "the planted derivation must be named"
    );
    // And the prose of a comment naming the tier rule is NOT a call to it.
    let only_prose = vec![(
        "crates/busbar-kernel/src/prose.rs".to_string(),
        "// see `apply_tier(` and `nanos_sum(` in the ledger\nfn nothing() {}\n".to_string(),
    )];
    assert!(census(&only_prose).is_empty());
}
