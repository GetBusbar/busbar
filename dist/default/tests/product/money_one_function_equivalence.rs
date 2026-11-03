// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::BTreeMap;

use busbar_kernel_ledger::cost::{
    self as ledger_cost, Author, CardEntryDraft, EntryKey, History, LaneClass, LedgerEntry,
    MoneyError, RateCard,
};

const LANE: &str = "gpt-4o";
const OPENING_ENTRY: EntryKey = EntryKey([0; 20]);

const INPUT: &str = "input";
const OUTPUT: &str = "output";
const CACHE_READ: &str = "cache_read";
const CACHE_WRITE: &str = "cache_write";

fn enforcement_units(pairs: &[(&'static str, u64)]) -> BTreeMap<String, u64> {
    pairs.iter().map(|(k, v)| ((*k).to_string(), *v)).collect()
}

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

fn usage_report(pairs: &[(&'static str, u64)]) -> busbar_contract::caps::Usage {
    let token = busbar_contract::caps::Grant::<busbar_contract::caps::Consumption>::mint(
        &busbar_kernel::seal::acquire(),
    );
    busbar_contract::caps::Usage::report(&token, usage_lines(pairs))
        .expect("a report within the line bound")
}

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

type Rates4 = [f64; 4];

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

fn ledger_card(rates: Option<&[(&str, Rates4)]>, fee: i64) -> RateCard {
    RateCard::from_config(
        rates.map(|rows| {
            rows.iter().map(|(lane, r)| {
                (
                    *lane,
                    ledger_cost::TierRates {
                        input: busbar_kernel_ledger::cost::representable_nano_rate(r[0]),
                        output: busbar_kernel_ledger::cost::representable_nano_rate(r[1]),
                        cache_read: busbar_kernel_ledger::cost::representable_nano_rate(r[2]),
                        cache_write: busbar_kernel_ledger::cost::representable_nano_rate(r[3]),
                    },
                )
            })
        }),
        fee,
    )
}

use busbar_core_admin::v1::service::read_path_money as admin;

fn admin_row(counts: &[(&'static str, u64)], requests: u64) -> admin::UsageBreakdown {
    let at = |unit: &str| {
        counts
            .iter()
            .find(|(k, _)| *k == unit)
            .map(|(_, v)| *v)
            .unwrap_or(0)
    };
    admin::UsageBreakdown {
        tokens_input: at(INPUT),
        tokens_output: at(OUTPUT),
        tokens_cache_read: at(CACHE_READ),

        tokens_cache_creation: at(CACHE_WRITE),
        requests,
        spend_micros: 0,
        classes: Default::default(),
    }
}

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

struct Answers {
    one_micros: Result<i128, MoneyError>,
    one_minor: Result<i128, MoneyError>,
    micros: Vec<(&'static str, Option<EntryKey>, Result<i128, MoneyError>)>,

    refuse_alike: Vec<(&'static str, Option<i128>)>,
}

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
        let units = enforcement_units(self.counts);

        let one = ledger_cost::price_ledger(
            &[one_entry(self.lane, self.counts, 0, self.fee_count)],
            &history,
        );
        let one_micros = one.clone().map(|m| m.micros());
        let one_minor = one.map(|m| m.minor());

        let micros: Vec<(&'static str, Option<EntryKey>, Result<i128, MoneyError>)> = vec![
            (
                "ledger  MeteredRow::spend_micros_at_card",
                None,
                ledger_cost::MeteredRow::new(
                    self.lane,
                    units.clone(),
                    self.fee_count,
                    &BTreeMap::new(),
                )
                .spend_micros_at_card(&card)
                .map(i128::from),
            ),
            (
                "admin   derive_spend_micros_row (current card)",
                None,
                admin::derive_spend_micros_row(
                    &kernel,
                    self.lane,
                    &admin_row(self.counts, self.fee_count),
                )
                .map(i128::from),
            ),
            (
                "admin   derive_spend_micros_row_at_card (dated, #79)",
                Some(OPENING_ENTRY),
                admin_row_at_card(&card, &kernel, self.lane, self.counts, self.fee_count)
                    .map(i128::from),
            ),
        ];

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

        let metered = kernel
            .price_usage_nanos(
                self.lane,
                &busbar_contract::billing::Usage {
                    usage_units: units.clone(),
                },
            )
            .map(|nanos| {
                i128::try_from(nanos / 1_000).expect("fits")
                    + i128::from(card.fee()) * 10_000 * i128::from(self.fee_count)
            });

        Answers {
            one_micros,
            one_minor,
            micros,
            refuse_alike: vec![
                ("ledger  price_fail_closed (settlement)", settled),
                ("kernel  price_usage_nanos (metering seam)", metered),
            ],
        }
    }

    fn check(&self) -> Answers {
        rule(self.title);
        let a = self.run();
        row("THE ONE FUNCTION  [micro]", &a.one_micros);
        for (label, expected_entry, got) in &a.micros {
            row(label, got);
            // A current card has no history identity; a dated read names its actual opening
            // entry. Pin both provenances while comparing every pricing/refusal field.
            match (got, &a.one_micros) {
                (
                    Err(MoneyError::LaneUnpriced { card_seq, lane }),
                    Err(MoneyError::LaneUnpriced {
                        card_seq: one_seq,
                        lane: one_lane,
                    }),
                ) => {
                    assert_eq!(
                        *one_seq,
                        Some(OPENING_ENTRY),
                        "the ledger names its opening entry"
                    );
                    assert_eq!(card_seq, expected_entry, "{label}: exact card provenance");
                    assert_eq!(lane, one_lane, "{label}: the same unpriced lane");
                }
                (
                    Err(MoneyError::ClassUnpriced {
                        card_seq,
                        lane,
                        class,
                    }),
                    Err(MoneyError::ClassUnpriced {
                        card_seq: one_seq,
                        lane: one_lane,
                        class: one_class,
                    }),
                ) => {
                    assert_eq!(
                        *one_seq,
                        Some(OPENING_ENTRY),
                        "the ledger names its opening entry"
                    );
                    assert_eq!(card_seq, expected_entry, "{label}: exact card provenance");
                    assert_eq!(lane, one_lane, "{label}: the same lane");
                    assert_eq!(class, one_class, "{label}: the same unpriced class");
                }
                _ => assert_eq!(
                    got, &a.one_micros,
                    "{}: `{label}` diverges from the one function",
                    self.title
                ),
            }
        }
        row("THE ONE FUNCTION  [minor]", &a.one_minor);
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

    assert_eq!(a.one_micros, Ok(10_680_000));
    assert_eq!(a.one_minor, Ok(1_068));
}

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

#[test]
fn d5_an_unpriced_class_on_a_priced_lane_refuses_everywhere() {
    let card = RateCard::from_micro_rates(
        [
            (LaneClass::new(LANE, INPUT), 3.0),
            (LaneClass::new(LANE, OUTPUT), 16.0),
        ],
        0,
    );
    let counts: [(&str, u64); 3] = [(INPUT, 1_000), (OUTPUT, 250), (CACHE_READ, 10_000_000)];
    let history = History::opening(card.clone(), 0);
    let one = ledger_cost::price_ledger(&[one_entry(LANE, &counts, 0, 0)], &history);
    let derived =
        ledger_cost::MeteredRow::new(LANE, enforcement_units(&counts), 0, &BTreeMap::new())
            .spend_micros_at_card(&card);
    let posting = ledger_cost::Posting::from_usage(
        LANE,
        &usage_report(&counts),
        0,
        ledger_cost::STANDARD_TIER_BP,
        0,
        0,
    );
    let settled = ledger_cost::price_fail_closed(&history.current(), &posting);

    rule("D5  a priced lane, a class the card is silent about (#42)");
    row("THE ONE FUNCTION", &one);
    row("ledger  MeteredRow", &derived);
    row(
        "ledger  price_fail_closed (settlement)",
        settled.as_ref().err(),
    );
    let refusal = MoneyError::ClassUnpriced {
        card_seq: history.head_key(),
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
        Err(MoneyError::ClassUnpriced {
            card_seq: None,
            lane: LANE.to_string(),
            class: CACHE_READ.to_string(),
        }),
        "the undated read-time derivation refuses too — never 7,000"
    );
    assert!(
        matches!(settled, Err(ledger_cost::Unpriceable::ClassUnpriced { ref class, .. }) if class == CACHE_READ),
        "settlement refuses the same class"
    );
}

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

    let half = ledger_cost::price_exact(
        &[one_entry(LANE, &counts, 0, 1).with_tier(5_000)],
        &history.current(),
    )
    .expect("reads");
    assert_eq!(ledger_cost::nanos_of_exact(half), Ok(8_509_500));
}

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
    let flat_row = admin::derive_spend_micros_row(&kernel, LANE, &admin_row(&counts, 1))
        .expect("the current-card admin reader prices");
    let flat_micros = flat_row.checked_add(flat_row).expect("the two rows fit");

    row("ONE function, dated history  [micro]", dated.micros());
    row("ONE function, current card   [micro]", at_current.micros());
    row("admin read (current card)   [micro]", flat_micros);
    assert_eq!(dated.micros(), 39_000);
    assert_eq!(i128::from(flat_micros), at_current.micros());
    assert_eq!(at_current.micros(), 24_000);
}

#[test]
fn d8_the_gauge_figure_is_the_one_functions_integer_up_to_the_egress_boundary() {
    rule("D8  `busbar_*_spend_cents` — integer up to MONEY_EGRESS");
    let requests: u64 = (1u64 << 53) + 1;
    let kernel = kernel_cost_model(None, 1);
    let store = crate::root::real_store::records();
    const BUCKET: &str = "fee-only-gauge";
    const NOW: u64 = 1_700_000_000;
    busbar_contract::records::RecordStore::put_usage(
        store.as_ref(),
        BUCKET,
        busbar_kernel::governance::budget_window(busbar_kernel::governance::WINDOW_TOTAL, NOW),
        &busbar_contract::records::UsageLedger {
            requests,
            billable_requests: requests,
            models: Vec::new(),
        },
    )
    .expect("the raw fee count persists");
    let gov = busbar_kernel::governance::GovState::new(store, None).expect("governance builds");
    let gauge_input = gov
        .viewed_bucket_usage(
            &kernel,
            BUCKET,
            busbar_kernel::governance::WINDOW_TOTAL,
            true,
            NOW,
        )
        .expect("the actual metrics reader prices the fee-only bucket")
        .spend_cents;
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
    let over_range = kernel_cost_model(None, i64::MAX);
    assert!(
        matches!(
            gov.derived_bucket_usage_priced(
                &over_range,
                BUCKET,
                busbar_kernel::governance::WINDOW_TOTAL,
                true,
                NOW,
            )
            .expect("the raw bucket reads"),
            Err(MoneyError::Overflow)
        ),
        "the actual reader refuses an overflowing fee"
    );
    assert_eq!(
        gov.viewed_bucket_usage(
            &over_range,
            BUCKET,
            busbar_kernel::governance::WINDOW_TOTAL,
            false,
            NOW,
        )
        .expect("excluding the fee leaves a representable empty amount")
        .spend_cents,
        0,
        "excluding fees preserves the raw request count without pricing it"
    );
}

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
    let ledger_micros =
        ledger_cost::MeteredRow::new(LANE, enforcement_units(&counts), 0, &BTreeMap::new())
            .spend_micros_at_card(&card);
    let units = enforcement_units(&counts);
    let config_card: BTreeMap<String, busbar_kernel::config::RateEntryCfg> = serde_yaml::from_str(
        &format!("{LANE}: {{ output_utok: 2, units: {{ hops: 5 }} }}\n"),
    )
    .expect("an open class parses under units:");
    let kernel =
        busbar_kernel::cost::CostModel::resolve_parts(Some(&config_card), 0, &BTreeMap::new());
    let kernel_nanos = kernel.price_usage_nanos(
        LANE,
        &busbar_contract::billing::Usage {
            usage_units: units.clone(),
        },
    );
    let kernel_micros = kernel_nanos
        .map(|nanos| i128::try_from(nanos / ledger_cost::NANOS_PER_MICRO).expect("fixture fits"));
    let open_card = format!("{OPEN_LANE}: {{ output_utok: 2, units: {{ hops: 5 }} }}\n");
    let (door_cents, _) = accrued_on_the_book(Some(&open_card), &counts);
    row("ONE function                 [micro]", one.micros());
    row("ledger derive (every class)  [micro]", &ledger_micros);
    row("kernel derive (every class)  [micro]", kernel_micros);
    row("governance read (every class) [minor]", &door_cents);
    assert_eq!(one.micros(), 5_200_000, "100,000×2 + 1,000,000×5");
    assert_eq!(ledger_micros.map(i128::from), Ok(one.micros()));
    assert_eq!(
        kernel_micros,
        Some(one.micros()),
        "item 123: every class reaches it"
    );
    assert_eq!(
        door_cents.map(i128::from),
        Ok(one.minor()),
        "the actual governance read answers the same figure"
    );

    let silent = kernel_cost_model(Some(&[(LANE, [0.0, 2.0, 0.0, 0.0])]), 0);
    let refusal = ledger_cost::MeteredRow::new(LANE, units.clone(), 0, &BTreeMap::new())
        .spend_micros_at_card(silent.card());
    assert!(
        matches!(refusal, Err(MoneyError::ClassUnpriced { ref class, .. }) if class == "hops"),
        "an unpriced open class refuses, never a silent 0: {refusal:?}"
    );
    assert_eq!(
        silent.price_usage_nanos(
            LANE,
            &busbar_contract::billing::Usage { usage_units: units }
        ),
        None
    );
    let silent_card = format!("{OPEN_LANE}: {{ output_utok: 2 }}\n");
    assert!(
        accrued_on_the_book(Some(&silent_card), &counts).0.is_err(),
        "the actual enforcement read refuses the unpriced open class too"
    );
}

fn nano_rate_exact_from_text(decimal: &str) -> Option<u64> {
    let count = busbar_contract::count::Count::parse(decimal).expect("a decimal literal");
    let scaled = count.micros() * 1_000;
    (scaled % 1_000_000 == 0).then(|| u64::try_from(scaled / 1_000_000).expect("inside the range"))
}

#[test]
fn d7_a_rate_converts_from_its_decimal_exactly_and_is_never_rounded() {
    rule("D7  `nano_rate`: the decimal exactly, or refused, never rounded (#81, #77(8))");
    let (mut refused, mut exact) = (0u64, 0u64);
    for thousandths in 1u64..200_000 {
        let half = format!(
            "{}.{:04}",
            thousandths / 10_000,
            (thousandths % 10_000) * 10 + 5
        );
        assert_eq!(
            nano_rate_exact_from_text(&half),
            None,
            "{half}: no whole nano-unit"
        );
        let double = half.parse::<f64>().expect("parses");
        assert_eq!(
            ledger_cost::nano_rate(double),
            0,
            "{half} micro-units/token is refused, never rounded (#81)"
        );
        assert_eq!(
            ledger_cost::representable_nano_rate(double),
            None,
            "{half} micro-units/token is a rate the card cannot hold"
        );
        refused += 1;

        let whole = format!("{}.{:03}", thousandths / 1_000, thousandths % 1_000);
        let nanos = nano_rate_exact_from_text(&whole).expect("three decimals are whole nano-units");
        assert_eq!(
            ledger_cost::nano_rate(whole.parse::<f64>().expect("parses")),
            nanos,
            "{whole} micro-units/token is exactly {nanos} nano-units"
        );
        exact += 1;
    }
    row(
        "half-boundary rates refused / whole-nano rates exact",
        (refused, exact),
    );
}

const OPEN_LANE: &str = "m";
const OPEN_AT: u64 = 1_700_000_000;

fn accrued_on_the_book(
    card_yaml: Option<&str>,
    units: &[(&str, u64)],
) -> (Result<i64, String>, BTreeMap<String, u64>) {
    let gov = busbar_kernel::governance::GovState::new(crate::root::real_store::records(), None)
        .expect("a governance book over the actual product store");
    let card: Option<BTreeMap<String, busbar_kernel::config::RateEntryCfg>> =
        card_yaml.map(|yaml| serde_yaml::from_str(yaml).expect("the card parses"));
    let cost = busbar_kernel::cost::CostModel::resolve_parts(card.as_ref(), 0, &BTreeMap::new());
    gov.set_signing_key(Some(
        busbar_kernel::governance::signing::TokenSigner::generate(
            busbar_kernel::governance::signing::DEFAULT_KID,
        )
        .expect("the product signing key is generated"),
    ));
    let (key, _secret) = gov
        .mint_signed(
            busbar_kernel::governance::NewKeySpec {
                name: "open-class".to_string(),
                ..Default::default()
            },
            u64::MAX,
            OPEN_AT,
        )
        .expect("create key");
    let counts: BTreeMap<String, u64> = units
        .iter()
        .map(|(class, count)| ((*class).to_string(), *count))
        .collect();
    gov.record_usage(&cost, &key, "", OPEN_LANE, &counts, OPEN_AT);
    let spend = gov
        .usage_for(&cost, &key.id, OPEN_AT)
        .map(|usage| usage.expect("the key exists").spend_cents)
        .map_err(|refusal| format!("{refusal:?}"));
    gov.flush_budgets();
    let lines = gov
        .store()
        .get_usage(
            &key.id,
            busbar_kernel::governance::budget_window(
                busbar_kernel::governance::WINDOW_TOTAL,
                OPEN_AT,
            ),
        )
        .expect("the governance ledger reads")
        .models
        .iter()
        .find(|row| row.model == OPEN_LANE)
        .map(|row| {
            row.usage_units
                .iter()
                .filter(|(_, count)| **count > 0)
                .map(|(class, count)| (class.clone(), *count))
                .collect()
        })
        .unwrap_or_default();
    (spend, lines)
}

#[cfg(linked_axis_plane_door)]
mod declared {
    include!(concat!(env!("OUT_DIR"), "/linked_plane_doors.rs"));

    pub(super) fn open_classes() -> Vec<&'static str> {
        LINKED_PLANE_DOORS
            .iter()
            .flat_map(|door| {
                busbar_plugin_loader::dispatch::kinds::plane::stated_facts(*door)
                    .expect("the linked plane door declares valid billable classes")
                    .1
                    .served
                    .billable_classes
            })
            .filter(|class| !busbar_contract::records::RESERVED_UNITS.contains(class))
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect()
    }
}

#[cfg(linked_axis_plane_door)]
#[test]
fn every_open_class_ledgers_one_line_priced_by_the_card() {
    let classes = declared::open_classes();
    assert!(
        !classes.is_empty(),
        "the linked plane doors declare open classes: nothing to price"
    );
    for class in classes {
        let one_line = BTreeMap::from([(class.to_string(), 3)]);
        let priced = format!("{OPEN_LANE}: {{ units: {{ {class}: 10000 }} }}\n");
        let (spend, lines) = accrued_on_the_book(Some(&priced), &[(class, 3)]);
        assert_eq!(spend, Ok(3), "{class}: 3 units at 1 cent each");
        assert_eq!(lines, one_line, "{class}: exactly one ledger line");

        let silent = format!("{OPEN_LANE}: {{ input_utok: 1 }}\n");
        let (spend, _) = accrued_on_the_book(Some(&silent), &[(class, 3)]);
        assert!(
            spend.is_err(),
            "{class}: a present card silent about the class REFUSES (#42), never a silent 0: \
             {spend:?}"
        );

        let (spend, lines) = accrued_on_the_book(None, &[(class, 3)]);
        assert_eq!(spend, Ok(0), "{class}: no card, billing off reads 0");
        assert_eq!(lines, one_line, "{class}: the line is still the record");
    }
}

#[test]
fn an_open_class_beside_the_tokens_moves_no_token_line() {
    let card = format!(
        "{OPEN_LANE}: {{ input_utok: 10000, output_utok: 20000, units: {{ classifications: 10000 }} }}\n"
    );
    let (spend, lines) = accrued_on_the_book(Some(&card), &[(INPUT, 2), (OUTPUT, 1)]);
    assert_eq!(spend, Ok(4), "2 in at 1 cent + 1 out at 2 cents");
    assert_eq!(
        lines,
        BTreeMap::from([(INPUT.to_string(), 2), (OUTPUT.to_string(), 1)])
    );
    let (spend, lines) = accrued_on_the_book(
        Some(&card),
        &[(INPUT, 2), (OUTPUT, 1), ("classifications", 5)],
    );
    assert_eq!(
        spend,
        Ok(9),
        "the same 4 cents plus 5 classifications at 1 cent"
    );
    assert_eq!(
        lines,
        BTreeMap::from([
            ("classifications".to_string(), 5),
            (INPUT.to_string(), 2),
            (OUTPUT.to_string(), 1),
        ])
    );
}
