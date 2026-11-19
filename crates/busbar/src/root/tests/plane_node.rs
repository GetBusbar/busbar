// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#[test]
fn response_clock_shares_the_actual_node_sequence_and_samples_wall_once() {
    struct Clock(std::sync::atomic::AtomicU64);
    impl busbar_kernel::Clock for Clock {
        fn now(&self) -> u64 {
            self.0.fetch_add(1, Ordering::SeqCst);
            12_345
        }
    }
    let clock = Arc::new(Clock(std::sync::atomic::AtomicU64::new(0)));
    let node = Node::with_clock(clock.clone());
    assert_eq!(node.arrived(), Arrived::at(12_345, 0));
    let stamp = node.checked_arrived().unwrap();
    assert_eq!(stamp, Arrived::at(12_345, 1));
    assert_eq!(stamp.secs(), 12);
    assert_eq!(clock.0.load(Ordering::SeqCst), 2);
}

#[test]
fn response_clock_exhaustion_never_wraps_or_samples_an_unused_wall_time() {
    struct NoClock;
    impl busbar_kernel::Clock for NoClock {
        fn now(&self) -> u64 {
            panic!("exhausted node clock must refuse before wall sampling")
        }
    }
    let node = Node::with_clock(Arc::new(NoClock));
    node.mono.store(u64::MAX, Ordering::SeqCst);
    assert!(node.checked_arrived().is_err());
    assert!(node.checked_arrived().is_err());
    assert_eq!(node.mono.load(Ordering::SeqCst), u64::MAX);
}

fn ledger_entry(report: &Report, at: Arrived) -> busbar_kernel_ledger::cost::LedgerEntry {
    report.usage.usage_units.iter().fold(
        busbar_kernel_ledger::cost::LedgerEntry::new(&report.lane, at.ms())
            .with_fee_count(report.fee_count.into()),
        |entry, (class, count)| entry.with_count(class, *count),
    )
}
fn project_nanos(
    history: &crate::root::kernel::PinnedHistory,
    at: Arrived,
    report: &Report,
) -> Result<u128, busbar_kernel_ledger::cost::MoneyError> {
    busbar_kernel_ledger::cost::price_exact(&[ledger_entry(report, at)], &history.view())
        .and_then(busbar_kernel_ledger::cost::nanos_of_exact)
}
fn fixture_seal(key: u64) -> UnitSeal {
    use busbar_kernel::test_hooks::tokens::{origin, pass};
    UnitSeal {
        facts: busbar_contract::caps::AuditFacts {
            op_class: busbar_contract::caps::OpClassId::new("call"),
            finish: busbar_contract::FinishClass::Complete,
        },
        pass: pass(),
        key: UnitKey::new(key),
        origin: origin(OriginKind::Client),
        parent: None,
    }
}
fn native_budget() -> busbar_kernel::persistence::journal::runtime::BufferBudget {
    busbar_kernel::persistence::journal::runtime::BufferBudget {
        records: 4096,
        bytes: 32 * 1024 * 1024,
    }
}
async fn native_journal(
    node: u64,
    records: usize,
) -> Arc<busbar_kernel::persistence::journal::runtime::RuntimeJournal> {
    let core = (crate::root::real_store::core()).await;
    let budget = busbar_kernel::persistence::journal::runtime::BufferBudget {
        records,
        ..native_budget()
    };
    (busbar_kernel::persistence::journal::runtime::RuntimeJournal::open(core, node, budget))
        .await
        .expect("native journal opens")
}
async fn native_fixture() -> Result<crate::root::durability::Durability, std::io::Error> {
    let journal = native_journal(
        busbar_kernel::door::op_id().counter(),
        native_budget().records,
    )
    .await;
    (crate::root::durability::build_on_store(
        &crate::root::durability::DurabilityConfig::default(),
        journal.node(),
        journal,
        None,
        native_budget(),
    ))
    .await
}
async fn native_node_book() -> crate::root::durability::NodeBook {
    let journal = native_journal(
        busbar_kernel::door::op_id().counter(),
        native_budget().records,
    )
    .await;
    (crate::root::durability::node_book(journal, native_budget()))
        .await
        .expect("native node book opens")
}
async fn selected(
    journal: &Arc<busbar_kernel::persistence::journal::runtime::RuntimeJournal>,
) -> Vec<busbar_kernel_wal::JournalRecord> {
    (journal.flush()).await.expect("staged originals confirm");
    (journal.read_records(native_budget()))
        .await
        .expect("selected native history verifies")
}

use super::*;
use busbar_contract::json::{self, JsonValueMutTrait, JsonValueTrait};

use busbar_kernel::teller::Ended;
const LANE: &str = "m0";

#[tokio::test]
async fn one_arrival_reading_spells_both_the_figures_the_loop_asks_for() {
    const LAST_MILLISECOND: u64 = 1_700_000_000_999;
    let arrived = Arrived::at(LAST_MILLISECOND, 0);
    assert_eq!(arrived.ms(), LAST_MILLISECOND, "the reading, unmodified");
    assert_eq!(
        arrived.secs(),
        1_700_000_000,
        "and the window it lands in, which is the second that has not ended yet"
    );
    assert_eq!(
        arrived.ms() / 1_000,
        arrived.secs(),
        "the two figures are one instant: neither can be on the far side of a boundary the \
         other is on the near side of"
    );
}

#[tokio::test]
async fn two_units_of_one_second_are_ordered_by_the_monotonic_stamp() {
    let node = Node::new();
    let taken: Vec<Arrived> = (0..4).map(|_| node.arrived()).collect();

    for pair in taken.windows(2) {
        let (before, after) = (pair[0], pair[1]);
        assert!(
            after.mono() > before.mono(),
            "the reading that orders them only goes up: {} then {}",
            before.mono(),
            after.mono()
        );
    }

    assert!(
        taken
            .iter()
            .all(|a| a.secs() == taken[0].secs() || a.secs() == taken[0].secs() + 1),
        "the four were taken within a second of each other"
    );

    assert_ne!(taken[0].mono(), taken[0].secs());

    let durability = native_fixture()
        .await
        .expect("a memory-buffered journal cannot fail to open");

    let book = std::sync::Arc::new(std::sync::Mutex::new(durability));
    node.bind_book(book.clone());
    let who = PrincipalId::new("acct:node");
    for (index, arrived) in [Arrived::at(EPOCH * 1_000, 7), Arrived::at(EPOCH * 1_000, 8)]
        .into_iter()
        .enumerate()
    {
        use busbar_kernel::test_hooks::tokens::{end, grant};
        let ledger = grant::<busbar_contract::caps::WriteMoney>();
        let hold = busbar_contract::caps::Hold::open(
            &grant::<busbar_contract::caps::Admittance>(),
            who.clone(),
        );
        let usage = busbar_contract::caps::Usage::report(
            &grant::<busbar_contract::caps::Consumption>(),
            Vec::new(),
        )
        .expect("an empty report fits the record");
        let posted = busbar_contract::caps::Posted::settle(hold, 0, &usage, &ledger);
        node.seal_end(
            &who,
            arrived,
            None,
            Ended::Settled {
                end: end(Outcome::Completed, Ok(posted)),
                requests: 0,
                fee: 0,
            },
            Some(fixture_seal(index as u64 + 1)),
            Vec::new(),
        );
    }
    let durability = book.lock().unwrap_or_else(|p| p.into_inner());
    let journal = durability.journal.clone();
    drop(durability);
    let replayed = selected(&journal).await;
    assert_eq!(replayed.len(), 2, "two postings, two records");
    assert_eq!(
        replayed[0].wall, replayed[1].wall,
        "settled at one wall second, so the date cannot separate them"
    );
    assert!(
        replayed[1].mono > replayed[0].mono,
        "and the stamp that can does: {} then {}",
        replayed[0].mono,
        replayed[1].mono
    );
}

const EPOCH: u64 = 1_700_000_000;

const RERANK_LANE: &str = "rerank-v3.5";

fn history_of(entries: &[(u64, f64)]) -> crate::root::kernel::PinnedHistory {
    let mut history = busbar_kernel_ledger::cost::History::new();
    for (n, (from, output)) in entries.iter().enumerate() {
        let card = crate::root::kernel::card_from_config(
            [(
                "lane",
                busbar_contract::billing::RawTierRates {
                    input: busbar_kernel_ledger::cost::representable_nano_rate(0.0),
                    output: busbar_kernel_ledger::cost::representable_nano_rate(*output),
                    cache_read: busbar_kernel_ledger::cost::representable_nano_rate(0.0),
                    cache_write: busbar_kernel_ledger::cost::representable_nano_rate(0.0),
                },
            )],
            0,
            true,
        );
        history.append(busbar_kernel_ledger::cost::CardEntryDraft {
            effective_from: if n == 0 { 0 } else { *from },
            effective_until: None,
            card,
            appended_at: *from,
            author: busbar_kernel_ledger::cost::Author::Config {
                policy_epoch: n as u64,
            },
        });
    }
    crate::root::kernel::PinnedHistory::for_test(
        std::sync::Arc::new(history),
        busbar_kernel_ledger::cost::HistorySeq((entries.len() - 1) as u64),
    )
}

fn report_of(output: u64) -> Report {
    Report {
        usage: busbar_contract::billing::ExactUsage {
            usage_units: std::collections::BTreeMap::from([(
                busbar_contract::records::UNIT_OUTPUT.to_string(),
                output.into(),
            )]),
        },
        fee_count: 0,
        lane: "lane".to_string(),
        attribution: String::new(),
    }
}

#[tokio::test]
async fn a_unit_prices_at_the_entry_in_force_when_it_arrived_and_not_at_the_head() {
    let history = history_of(&[(0, 1.0), (5_000, 100.0)]);

    let early = project_nanos(&history, Arrived::at(4_999, 1), &report_of(1_000));
    let late = project_nanos(&history, Arrived::at(5_000, 2), &report_of(1_000));

    assert_eq!(
        early,
        Ok(1_000_000),
        "a unit that arrived before the appended entry was re-priced at it"
    );
    assert_eq!(
        late,
        Ok(100_000_000),
        "a unit that arrived after the appended entry was priced at the entry it superseded"
    );
}

#[tokio::test]
async fn a_snapshot_pinned_at_admission_cannot_see_an_entry_appended_behind_it() {
    let holder = crate::root::kernel::RootHistory::default();
    holder.apply(
        crate::root::kernel::card_from_config(
            [(
                "lane",
                busbar_contract::billing::RawTierRates {
                    input: busbar_kernel_ledger::cost::representable_nano_rate(0.0),
                    output: busbar_kernel_ledger::cost::representable_nano_rate(1.0),
                    cache_read: busbar_kernel_ledger::cost::representable_nano_rate(0.0),
                    cache_write: busbar_kernel_ledger::cost::representable_nano_rate(0.0),
                },
            )],
            0,
            true,
        ),
        1_000,
    );
    let admitted = holder
        .pin()
        .expect("the boot resolution put an entry in place");

    holder.apply(
        crate::root::kernel::card_from_config(
            [(
                "lane",
                busbar_contract::billing::RawTierRates {
                    input: busbar_kernel_ledger::cost::representable_nano_rate(0.0),
                    output: busbar_kernel_ledger::cost::representable_nano_rate(100.0),
                    cache_read: busbar_kernel_ledger::cost::representable_nano_rate(0.0),
                    cache_write: busbar_kernel_ledger::cost::representable_nano_rate(0.0),
                },
            )],
            0,
            true,
        ),
        2_000,
    );
    let next = holder.pin().expect("the apply put a second entry in place");

    let at = Arrived::at(9_000, 1);
    assert_eq!(
        project_nanos(&admitted, at, &report_of(1_000)),
        Ok(1_000_000),
        "the pinned snapshot saw an entry appended after the unit was admitted"
    );
    assert_eq!(
        project_nanos(&next, at, &report_of(1_000)),
        Ok(100_000_000),
        "the next admission did not see the appended entry"
    );
}

#[tokio::test]
async fn a_pin_below_the_head_reads_the_history_as_it_stood_at_that_seq() {
    let head = history_of(&[(0, 1.0), (5_000, 100.0)]);
    let earlier = crate::root::kernel::PinnedHistory::for_test_at(
        &head,
        busbar_kernel_ledger::cost::HistorySeq(0),
    );

    let at = Arrived::at(9_000, 1);
    assert_eq!(
        project_nanos(&earlier, at, &report_of(1_000)),
        Ok(1_000_000),
        "a snapshot at seq 0 resolved an entry that was appended after it"
    );
    assert_eq!(
        project_nanos(&head, at, &report_of(1_000)),
        Ok(100_000_000),
        "the head snapshot did not resolve the entry appended onto it"
    );
}

#[tokio::test]
async fn the_posting_carries_no_price_and_its_figure_is_the_lookups() {
    let history = history_of(&[(0, 1.0)]);
    let at = Arrived::at(4_000, 7);

    let report = report_of(1_000);
    let entry = ledger_entry(&report, at);
    let priced = project_nanos(&history, at, &report).unwrap();
    assert_eq!(entry.arrived_ms, 4_000);
    assert_eq!(
        entry.counts[busbar_contract::records::UNIT_OUTPUT],
        busbar_contract::Count::from(1_000u64)
    );
    assert_eq!(
        busbar_kernel_ledger::cost::price_exact(&[entry], &history.view())
            .and_then(busbar_kernel_ledger::cost::nanos_of_exact)
            .unwrap(),
        priced,
        "counts remain independent of their price projection"
    );
}

#[tokio::test]
async fn the_nodes_interner_leaks_a_lane_name_once() {
    let node = Node::new();
    let lanes = node.lanes();
    let first = lanes
        .lock()
        .expect("the node's interner is never poisoned")
        .lane(LANE);
    let again = lanes
        .lock()
        .expect("the node's interner is never poisoned")
        .lane(LANE);
    assert_eq!(first, again);
    let first = first.expect("an unfrozen image interns a configured lane");
    let again = again.expect("a repeated lane is the same lane");
    assert!(std::ptr::eq(first.as_str(), again.as_str()));
}

#[tokio::test]
async fn a_lane_name_reaches_the_interner_once_however_often_it_is_resolved() {
    let node = Node::new();
    let mut names = node
        .lane_names
        .lock()
        .expect("the node's lane table is never poisoned");

    let first = names
        .resolve(LANE)
        .expect("an unfrozen image interns a lane");
    for _ in 0..64 {
        let again = names
            .resolve(LANE)
            .expect("a repeated lane is the same lane");
        assert!(std::ptr::eq(first.as_str(), again.as_str()));
    }
    assert_eq!(names.consulted(), 1);

    let _ = names.resolve("a-second-configured-lane");
    assert_eq!(
        names.consulted(),
        2,
        "a name the node has not resolved still reaches the interner, exactly once"
    );
}

#[tokio::test]
async fn the_node_provenance_stamp_names_the_card_in_force_when_the_unit_arrived() {
    const SECOND_CARD_MS: u64 = 1_700_000_500_000;
    const THIRD_CARD_MS: u64 = 1_700_000_900_000;

    let holder = crate::root::kernel::RootHistory::default();
    holder.apply(busbar_kernel_ledger::cost::RateCard::absent(3), 1_000);
    holder.apply(
        busbar_kernel_ledger::cost::RateCard::absent(11),
        SECOND_CARD_MS,
    );
    holder.apply(
        busbar_kernel_ledger::cost::RateCard::absent(29),
        THIRD_CARD_MS,
    );
    let pinned = holder.pin().expect("three applies put entries in place");
    assert_eq!(
        pinned.view().entries().last().unwrap().seq().get(),
        2,
        "the snapshot's head is the third entry — the figure a stamp must NOT be for a unit that \
         arrived before it, and the one a `read the head` implementation would answer every time"
    );

    let keys: Vec<_> = pinned
        .view()
        .entries()
        .iter()
        .map(|entry| entry.key().0)
        .collect();
    let stamped_ms = |ms: u64| card_in_force(Some(&pinned), ms);

    assert_eq!(
        stamped_ms(1_700_000_100_000),
        Some(keys[0]),
        "a unit that arrived before the second card was published is priced by the opening entry"
    );
    assert_eq!(
        stamped_ms(1_700_000_600_000),
        Some(keys[1]),
        "a unit that arrived in the second card's window names the SECOND entry — not the third, \
         which had not been published when it arrived (#79: publishing never reprices backwards)"
    );
    assert_eq!(
        stamped_ms(1_700_001_000_000),
        Some(keys[2]),
        "a unit that arrived after the third card names the third entry"
    );

    assert_eq!(
        card_in_force(None, 1_700_000_600_000),
        None,
        "no pinned history has no card entry identity"
    );

    assert_eq!(
        stamped_ms(1_700_000_600),
        Some(keys[0]),
        "a seconds-valued instant matches only the from-zero opening entry — which is why the \
         settle path resolves at `Arrived::ms()` and never at `Arrived::secs()`"
    );
}

fn fee_history_of(
    entries: &[(u64, f64, f64, i64)],
    present: bool,
) -> crate::root::kernel::PinnedHistory {
    let mut history = busbar_kernel_ledger::cost::History::new();
    for (n, (from, input, output, fee)) in entries.iter().enumerate() {
        let card = crate::root::kernel::card_from_config(
            [(
                "lane",
                busbar_contract::billing::RawTierRates {
                    input: busbar_kernel_ledger::cost::representable_nano_rate(*input),
                    output: busbar_kernel_ledger::cost::representable_nano_rate(*output),
                    cache_read: busbar_kernel_ledger::cost::representable_nano_rate(0.0),
                    cache_write: busbar_kernel_ledger::cost::representable_nano_rate(0.0),
                },
            )],
            *fee,
            present,
        );
        history.append(busbar_kernel_ledger::cost::CardEntryDraft {
            effective_from: if n == 0 { 0 } else { *from },
            effective_until: None,
            card,
            appended_at: *from,
            author: busbar_kernel_ledger::cost::Author::Config {
                policy_epoch: n as u64,
            },
        });
    }
    crate::root::kernel::PinnedHistory::for_test(
        std::sync::Arc::new(history),
        busbar_kernel_ledger::cost::HistorySeq((entries.len() - 1) as u64),
    )
}

fn split_report(input: u64, output: u64, fee_count: u32) -> Report {
    let mut units = std::collections::BTreeMap::new();
    if input != 0 {
        units.insert(
            busbar_contract::records::UNIT_INPUT.to_string(),
            input.into(),
        );
    }
    if output != 0 {
        units.insert(
            busbar_contract::records::UNIT_OUTPUT.to_string(),
            output.into(),
        );
    }
    Report {
        usage: busbar_contract::billing::ExactUsage { usage_units: units },
        fee_count,
        lane: "lane".to_string(),
        attribution: String::new(),
    }
}

fn invoice_micros(
    history: &crate::root::kernel::PinnedHistory,
    arrived_ms: u64,
    report: &Report,
) -> i64 {
    use busbar_core_admin::v1::service::read_path_money as invoice;
    let view = history.view();
    let era = view
        .entry_at(arrived_ms)
        .map_or(0, busbar_kernel_ledger::cost::CardEntry::effective_from);
    let bucket_start_secs = arrived_ms / 1_000 / 86_400 * 86_400;
    let at = invoice::row_priced_at_ms(bucket_start_secs, era);
    let (_, card) = view.card_at(at).expect("a card covers every instant");
    let unit = |k: &str| {
        report
            .usage
            .usage_units
            .get(k)
            .copied()
            .unwrap_or(busbar_contract::Count::ZERO)
    };
    let row = invoice::UsageBreakdown {
        tokens_input: unit(busbar_contract::records::UNIT_INPUT),
        tokens_output: unit(busbar_contract::records::UNIT_OUTPUT),
        tokens_cache_read: unit(busbar_contract::records::UNIT_CACHE_READ),
        tokens_cache_creation: unit(busbar_contract::records::UNIT_CACHE_WRITE),
        requests: u64::from(report.fee_count),
        spend_micros: 0,
        classes: Default::default(),
    };
    let cost =
        busbar_kernel::cost::CostModel::resolve_parts(None, 0, &std::collections::BTreeMap::new());
    invoice::derive_spend_micros_row_at_card(&view, at, card, &cost, &report.lane, &row)
        .expect("the invoice's card prices every lane the fixture serves")
}

fn projected_micros(
    second_book: Result<u128, busbar_kernel_ledger::cost::MoneyError>,
) -> Result<i64, String> {
    let nanos = second_book.map_err(|refusal| format!("the second book refused: {refusal:?}"))?;
    busbar_kernel_ledger::cost::Money::of_nanos(nanos)
        .and_then(busbar_kernel_ledger::cost::Money::micros_i64)
        .map_err(|refusal| format!("{nanos} nano-units do not project: {refusal:?}"))
}

fn projection_agrees(
    label: &str,
    second_book: Result<u128, busbar_kernel_ledger::cost::MoneyError>,
    invoice: i64,
) -> Result<(), String> {
    let projected = projected_micros(second_book.clone());
    if projected == Ok(invoice) {
        Ok(())
    } else {
        Err(format!(
            "{label}: the kernel-loop book posted {second_book:?} nano-units ({projected:?} micro) \
             but the invoice (/admin/usage over the governance ledger) serves {invoice} micro"
        ))
    }
}

#[tokio::test]
async fn the_second_book_agrees_with_the_invoice_cell_by_cell_and_a_divergence_is_red() {
    let billed = fee_history_of(
        &[
            (0, 0.5, 1.0, 0),
            (5_000, 5.0, 10.0, 0),
            (9_000, 50.0, 100.0, 3),
        ],
        true,
    );
    let billing_off = fee_history_of(&[(0, 0.0, 0.0, 1)], false);

    let cells: [(&str, &crate::root::kernel::PinnedHistory, u64, Report); 7] = [
        (
            "boot card, before A",
            &billed,
            1_000,
            split_report(11, 7, 1),
        ),
        (
            "card A, between A and B",
            &billed,
            6_000,
            split_report(11, 7, 1),
        ),
        (
            "card B + fee, after B",
            &billed,
            10_000,
            split_report(11, 7, 1),
        ),
        (
            "fee only (billing failed)",
            &billed,
            10_000,
            split_report(0, 0, 1),
        ),
        (
            "provider origin (no fee)",
            &billed,
            10_000,
            split_report(11, 7, 0),
        ),
        (
            "billing off, tokens + fee",
            &billing_off,
            10_000,
            split_report(11, 7, 1),
        ),
        (
            "billing off, fee only",
            &billing_off,
            10_000,
            split_report(0, 0, 1),
        ),
    ];

    let mut failures = Vec::new();
    for (label, history, at, report) in &cells {
        let second = project_nanos(history, Arrived::at(*at, 1), report);
        let invoice = invoice_micros(history, *at, report);
        if let Err(e) = projection_agrees(label, second, invoice) {
            failures.push(e);
        }
    }
    assert!(
        failures.is_empty(),
        "the second book disagrees with the invoice on {} cell(s):\n{}",
        failures.len(),
        failures.join("\n")
    );

    assert_eq!(
        Ok(invoice_micros(&billed, 10_000, &split_report(11, 7, 1))),
        // 11 x 50 + 7 x 100 + the 3-unit fee at the one scale.
        projected_micros(project_nanos(
            &billed,
            Arrived::at(10_000, 1),
            &split_report(11, 7, 1)
        )),
    );
    assert_ne!(invoice_micros(&billed, 10_000, &split_report(11, 7, 1)), 0);

    let early = split_report(11, 7, 1);
    let at_head = project_nanos(&billed, Arrived::at(10_000, 1), &early);
    assert!(
        projection_agrees(
            "planted: priced at head",
            at_head,
            invoice_micros(&billed, 1_000, &early)
        )
        .is_err(),
        "a second book priced at the head card was NOT caught disagreeing with the invoice"
    );

    let fee_dropped = project_nanos(&billed, Arrived::at(10_000, 1), &split_report(11, 7, 0));
    assert!(
        projection_agrees(
            "planted: fee dropped",
            fee_dropped,
            invoice_micros(&billed, 10_000, &split_report(11, 7, 1))
        )
        .is_err(),
        "a second book that dropped the fee was NOT caught disagreeing with the invoice"
    );
}

fn cache_silent_history() -> crate::root::kernel::PinnedHistory {
    use busbar_kernel_ledger::cost::{History, HistorySeq, LaneClass, RateCard};
    let card = RateCard::from_micro_rates(
        [
            (
                LaneClass::new("lane", busbar_contract::records::UNIT_INPUT),
                3.0,
            ),
            (
                LaneClass::new("lane", busbar_contract::records::UNIT_OUTPUT),
                16.0,
            ),
        ],
        0,
    );
    crate::root::kernel::PinnedHistory::for_test(
        std::sync::Arc::new(History::opening(card, 0)),
        HistorySeq(0),
    )
}

#[tokio::test]
async fn an_unpriced_class_on_a_present_card_keeps_its_counts_row_and_the_read_refuses() {
    let history = cache_silent_history();
    let mut report = split_report(1_000, 250, 1);
    report.usage.usage_units.insert(
        busbar_contract::records::UNIT_CACHE_READ.to_string(),
        10_000_000u64.into(),
    );
    let at = Arrived::at(4_000, 7);

    let entry = ledger_entry(&report, at);
    let priced = project_nanos(&history, at, &report);
    let counts: std::collections::BTreeMap<&str, u64> = entry
        .counts
        .iter()
        .map(|(class, n)| (class.as_str(), n.whole_u64().unwrap()))
        .collect();
    assert_eq!(
        counts,
        std::collections::BTreeMap::from([
            (busbar_contract::records::UNIT_INPUT, 1_000),
            (busbar_contract::records::UNIT_OUTPUT, 250),
            (busbar_contract::records::UNIT_CACHE_READ, 10_000_000)
        ])
    );
    assert_eq!(entry.fee_count, busbar_contract::Count::from(1u64));

    assert!(
        matches!(
            priced,
            Err(busbar_kernel_ledger::cost::MoneyError::ClassUnpriced { ref class, .. })
                if class == busbar_contract::records::UNIT_CACHE_READ
        ),
        "settlement priced a class the present card is silent about: {priced:?}"
    );
    assert!(
        matches!(
            project_nanos(&history, at, &report),
            Err(busbar_kernel_ledger::cost::MoneyError::ClassUnpriced { .. })
        ),
        "the second book was handed a figure — a partial is a silent zero for the unpriced class"
    );

    use busbar_core_admin::v1::service::read_path_money as invoice;
    let view = history.view();
    let (_, card) = view.card_at(at.ms()).expect("the card is in force");
    let row = invoice::UsageBreakdown {
        tokens_input: 1_000u64.into(),
        tokens_output: 250u64.into(),
        tokens_cache_read: 10_000_000u64.into(),
        tokens_cache_creation: 0u64.into(),
        requests: 1,
        spend_micros: 0,
        classes: Default::default(),
    };
    let cost =
        busbar_kernel::cost::CostModel::resolve_parts(None, 0, &std::collections::BTreeMap::new());
    assert!(
        invoice::derive_spend_micros_row_at_card(&view, at.ms(), card, &cost, "lane", &row)
            .is_err(),
        "the read priced a class the present card is silent about"
    );
}

#[tokio::test]
async fn a_settled_figure_past_the_record_refuses_and_is_never_pinned() {
    let history = history_of(&[(0, 1_000.0)]);
    let report = report_of(100_000_000_000_000_000);
    let nanos = project_nanos(&history, Arrived::at(4_000, 7), &report).unwrap();
    assert!(nanos > u128::from(u64::MAX));
    assert!(
        u64::try_from(nanos).is_err(),
        "a narrow projection refuses instead of truncating"
    );
    let saved = record_report(
        &history,
        Arrived::at(4_000, 7),
        "wide-native-price",
        &report,
    )
    .await;
    assert_eq!(
        recorded_rows(&saved).await[0].nanos,
        Ok(nanos),
        "native counts preserve the complete accepted projection"
    );
}

#[tokio::test]
async fn a_unit_whose_task_went_away_is_marked_and_the_sweep_posts_its_hold() {
    let node = Node::new();
    let book = Arc::new(Mutex::new(
        native_fixture()
            .await
            .expect("a memory-buffered journal cannot fail to open"),
    ));
    node.bind_book(Arc::clone(&book));

    let who = PrincipalId::new("acct:swept");
    let key = UnitKey::new(41);
    let call = node.kernel.next_call();
    let reservation = node
        .reserve_terminal(
            busbar_kernel::limits::process_admission::AdmissionClass::Data,
            key,
            call,
        )
        .expect("the fixture terminal book reserves the unit's slot (e5b8ff5fb8)");
    let slot = node
        .inflight
        .insert(busbar_kernel::inflight::Enter {
            key,
            origin: OriginKind::Client,
            session: None,
            admin_listener: false,
            zero_hold_tick: false,
            arrival: busbar_kernel::inflight::arrival_hold(&node.kernel, &node.door, who, call),
            now: EPOCH * 1_000,
        })
        .expect("the uncapped table takes the unit");

    drop(Occupied {
        node: &node,
        reservation,
        slot: Arc::clone(&slot),
        arrived: Arrived::at(EPOCH * 1_000, 7),
        op_class: busbar_contract::caps::OpClassId::new("call"),
        post: None,
        reached_end: false,
    });
    assert!(
        slot.is_marked(),
        "the guard MARKS the slot it could not end"
    );
    assert!(
        node.inflight.get(key).is_some(),
        "and leaves it in the table, where the sweep can see it"
    );
    assert_ne!(
        slot.cell().state(),
        busbar_contract::caps::HoldCellState::Taken,
        "the hold is still in the cell: nobody has settled it"
    );

    assert_eq!(node.sweep(Arrived::at(EPOCH * 1_000 + 5, 99)), 1);
    assert_eq!(
        slot.cell().state(),
        busbar_contract::caps::HoldCellState::Taken,
        "the sweep took the hold out of the cell"
    );
    assert!(node.inflight.get(key).is_none(), "and gave the slot back");
    {
        let durability = book.lock().unwrap_or_else(|p| p.into_inner());
        let journal = durability.journal.clone();
        drop(durability);
        let replayed = selected(&journal).await;
        assert_eq!(
            replayed
                .iter()
                .filter(|r| r.class == busbar_kernel_wal::RecordClass::Transaction)
                .count(),
            1,
            "the swept unit has exactly one native audit record"
        );
    }

    assert_eq!(node.sweep(Arrived::at(EPOCH * 1_000 + 6, 100)), 0);

    let key = UnitKey::new(42);
    let call = node.kernel.next_call();
    let reservation = node
        .reserve_terminal(
            busbar_kernel::limits::process_admission::AdmissionClass::Data,
            key,
            call,
        )
        .expect("the fixture terminal book reserves the unit's slot (e5b8ff5fb8)");
    let slot = node
        .inflight
        .insert(busbar_kernel::inflight::Enter {
            key,
            origin: OriginKind::Client,
            session: None,
            admin_listener: false,
            zero_hold_tick: false,
            arrival: busbar_kernel::inflight::arrival_hold(
                &node.kernel,
                &node.door,
                PrincipalId::new("acct:finished"),
                call,
            ),
            now: EPOCH * 1_000,
        })
        .expect("the uncapped table takes the unit");
    drop(Occupied {
        node: &node,
        reservation,
        slot: Arc::clone(&slot),
        arrived: Arrived::at(EPOCH * 1_000, 8),
        op_class: busbar_contract::caps::OpClassId::new("call"),
        post: None,
        reached_end: true,
    });
    assert!(!slot.is_marked());
    assert!(node.inflight.get(key).is_none());
}

async fn swept_node() -> (
    Node,
    Arc<std::sync::Mutex<crate::root::durability::Durability>>,
) {
    let node = Node::new();
    let book = Arc::new(Mutex::new(
        native_fixture()
            .await
            .expect("a memory-buffered journal cannot fail to open"),
    ));
    node.bind_book(Arc::clone(&book));
    (node, book)
}

fn lose_a_unit(node: &Node, key: UnitKey, op_class: &'static str, _hold: Option<u64>) {
    // The unit's terminal slot is reserved before it enters, as every occupied constructor
    // reserves its original slot (e5b8ff5fb8, STORAGE-JOIN-r2).
    let call = node.kernel.next_call();
    let reservation = node
        .reserve_terminal(
            busbar_kernel::limits::process_admission::AdmissionClass::Data,
            key,
            call,
        )
        .expect("the fixture terminal book reserves the unit's slot");
    let slot = node
        .inflight
        .insert(busbar_kernel::inflight::Enter {
            key,
            origin: OriginKind::Client,
            session: None,
            admin_listener: false,
            zero_hold_tick: false,
            arrival: busbar_kernel::inflight::arrival_hold(
                &node.kernel,
                &node.door,
                PrincipalId::new("acct:swept"),
                call,
            ),
            now: EPOCH * 1_000,
        })
        .expect("the uncapped table takes the unit");
    drop(Occupied {
        node,
        reservation,
        slot,
        arrived: Arrived::at(EPOCH * 1_000, key.get()),
        op_class: busbar_contract::caps::OpClassId::new(op_class),
        post: None,
        reached_end: false,
    });
}

#[tokio::test]
async fn a_swept_unit_seals_exactly_one_audit_record_whose_amount_is_its_ledger_line() {
    let (node, book) = swept_node().await;
    let key = UnitKey::new(51);
    lose_a_unit(&node, key, "widget_call", Some(3));
    assert_eq!(node.sweep(Arrived::at(EPOCH * 1_000 + 5, 99)), 1);

    let durability = book.lock().unwrap_or_else(|p| p.into_inner());
    let records: Vec<_> = durability
        .audit_records()
        .iter()
        .filter(|r| r.what.unit_key == key)
        .collect();
    assert_eq!(
        records.len(),
        1,
        "one record for the one swept unit: {:?}",
        durability.audit_records()
    );
    let record = records[0];
    assert_eq!(
        record.outcome.unit_end,
        Outcome::Failed(
            busbar_contract::caps::StepName::Route,
            busbar_contract::caps::ReasonCode::TaskLost
        )
    );
    assert_eq!(record.outcome.finish, RecordFinish::Error);
    assert_eq!(record.what.op_class.as_str(), "widget_call");
    assert_eq!(
        record.controls.hold_ref, None,
        "no second money hold is encoded"
    );

    assert!(
        record.usage.lines.is_empty(),
        "a record names no money-class line: {:?}",
        record.usage.lines
    );
    assert!(durability.retained_audit_findings().is_empty());

    let journal = durability.journal.clone();
    drop(durability);
    let replayed = selected(&journal).await;
    let read_back: Vec<_> = replayed
        .iter()
        .filter_map(|r| crate::root::durability::decode_audit(r).expect("every record decodes"))
        .filter(|r| r.what.unit_key == key)
        .collect();
    assert_eq!(
        read_back.len(),
        1,
        "the swept unit's record is on the journal"
    );
}

#[tokio::test]
async fn no_swept_unit_settles_with_zero_audit_records() {
    let (node, book) = swept_node().await;
    let keys = [UnitKey::new(61), UnitKey::new(62), UnitKey::new(63)];
    for key in keys {
        lose_a_unit(&node, key, "widget_call", None);
    }
    assert_eq!(node.sweep(Arrived::at(EPOCH * 1_000 + 5, 99)), keys.len());

    let durability = book.lock().unwrap_or_else(|p| p.into_inner());
    let journal = durability.journal.clone();
    drop(durability);
    let replayed = selected(&journal).await;
    assert_eq!(
        replayed
            .iter()
            .filter(|r| r.class == busbar_kernel_wal::RecordClass::Transaction)
            .count(),
        keys.len(),
        "each swept unit has exactly one native audit original"
    );
    let durability = book.lock().unwrap_or_else(|p| p.into_inner());
    for key in keys {
        assert_eq!(
            durability
                .audit_records()
                .iter()
                .filter(|r| r.what.unit_key == key)
                .count(),
            1,
            "unit {key:?} settled and must have exactly one record: {:?}",
            durability.audit_records()
        );
    }
    assert_eq!(durability.audit_records().len(), keys.len());
}

const SEARCH_UNITS: &str = "search_units";

fn declare_test_classes() {
    let mut registration = crate::root::kernel::new_registration();
    for class in busbar_contract::records::RESERVED_UNITS {
        let _ = registration.key(class);
    }
    let _ = registration.key(SEARCH_UNITS);
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RecordedCounts {
    lane: String,
    fee_count: u64,
    classes: std::collections::BTreeMap<String, u64>,
}
impl RecordedCounts {
    fn entry(&self, at: u64) -> busbar_kernel_ledger::cost::LedgerEntry {
        self.classes.iter().fold(
            busbar_kernel_ledger::cost::LedgerEntry::new(&self.lane, at)
                .with_fee_count(self.fee_count),
            |entry, (class, count)| entry.with_whole(class, *count),
        )
    }
}
#[derive(Debug, Clone)]
struct NativeLedgerObservation {
    counts: Option<RecordedCounts>,
    nanos: Result<u128, String>,
}
struct RecordedReport {
    core: Arc<busbar_kernel::persistence::facade::CoreStore>,
    principal: String,
    lane: String,
    at: u64,
    history: crate::root::kernel::PinnedHistory,
}
async fn observe_native_ledger(
    core: &busbar_kernel::persistence::facade::CoreStore,
    principal: &str,
    lane: &str,
    history: &crate::root::kernel::PinnedHistory,
    at: u64,
) -> Vec<NativeLedgerObservation> {
    let usage = (core.ledger().get_usage(principal, 0).await).expect("canonical usage reads");
    let classes = usage
        .models
        .iter()
        .filter(|row| row.model == lane)
        .flat_map(|row| {
            row.usage_units
                .iter()
                .filter(|(_, value)| **value != 0)
                .map(|(class, value)| {
                    let count = busbar_contract::Count::from_stored(*value, row.scale)
                        .expect("stored exact scale")
                        .whole_u64()
                        .expect("whole fixture count");
                    (class.clone(), count)
                })
        })
        .collect();
    let counts = RecordedCounts {
        lane: lane.into(),
        fee_count: usage.billable_requests,
        classes,
    };
    let nanos = busbar_kernel_ledger::cost::price_exact(&[counts.entry(at)], &history.view())
        .and_then(busbar_kernel_ledger::cost::nanos_of_exact)
        .map_err(|error| format!("{error:?}"));
    vec![NativeLedgerObservation {
        counts: Some(counts),
        nanos,
    }]
}
async fn record_report(
    history: &crate::root::kernel::PinnedHistory,
    at: Arrived,
    principal: &str,
    report: &Report,
) -> RecordedReport {
    declare_test_classes();
    let core = (crate::root::real_store::core()).await;
    let key = busbar_contract::records::VirtualKey {
        id: principal.into(),
        enabled: true,
        ..Default::default()
    };
    (core.identity().put_key(&key))
        .await
        .expect("canonical fixture key");
    let gov = (busbar_kernel::governance::GovState::new_with_core(core.clone(), None, None))
        .await
        .unwrap();
    let cost = busbar_kernel::cost::CostModel::flat(0);
    for _ in 0..report.fee_count {
        gov.try_admit(&cost, &key, "", at.secs())
            .expect("fixture admission");
    }
    gov.record_counts_served_in_era(
        &cost,
        &key,
        "",
        &report.lane,
        None,
        &report.usage.usage_units,
        at.secs(),
        busbar_kernel::rate_apply::era_at(at.ms()),
    )
    .expect("exact fixture accrual");
    (gov.flush_budgets()).await;
    (gov.flush_metering()).await;
    RecordedReport {
        core,
        principal: principal.into(),
        lane: report.lane.clone(),
        at: at.ms(),
        history: history.clone(),
    }
}
async fn recorded_rows(report: &RecordedReport) -> Vec<NativeLedgerObservation> {
    observe_native_ledger(
        &report.core,
        &report.principal,
        &report.lane,
        &report.history,
        report.at,
    )
    .await
}
fn governance_row(report: &Report) -> RecordedCounts {
    RecordedCounts {
        lane: report.lane.clone(),
        fee_count: report.fee_count.into(),
        classes: report
            .usage
            .usage_units
            .iter()
            .filter(|(_, n)| !n.is_zero())
            .map(|(class, n)| (class.clone(), n.whole_u64().expect("whole report fixture")))
            .collect(),
    }
}
fn every_cell_agrees(
    label: &str,
    rows: &[NativeLedgerObservation],
    expected: &RecordedCounts,
    history: &crate::root::kernel::PinnedHistory,
    at: u64,
) -> Result<(), String> {
    let [row] = rows else {
        return Err(format!("{label}: {} observations for one unit", rows.len()));
    };
    let counts = row
        .counts
        .as_ref()
        .ok_or_else(|| format!("{label}: no counts"))?;
    for class in counts.classes.keys().chain(expected.classes.keys()) {
        if counts.classes.get(class) != expected.classes.get(class) {
            return Err(format!(
                "{label}: class {class}: {:?} vs {:?}",
                counts.classes.get(class),
                expected.classes.get(class)
            ));
        }
    }
    if counts.lane != expected.lane || counts.fee_count != expected.fee_count {
        return Err(format!("{label}: lane or fee count differs"));
    }
    let invoice = busbar_kernel_ledger::cost::price_exact(&[expected.entry(at)], &history.view())
        .and_then(busbar_kernel_ledger::cost::nanos_of_exact)
        .map_err(|error| format!("{error:?}"));
    if row.nanos != invoice {
        return Err(format!("{label}: money: {:?} vs {invoice:?}", row.nanos));
    }
    Ok(())
}

fn rerank_history(fee: i64, search_units: Option<u64>) -> crate::root::kernel::PinnedHistory {
    rerank_history_on("lane", fee, search_units)
}

fn rerank_history_on(
    lane: &str,
    fee: i64,
    search_units: Option<u64>,
) -> crate::root::kernel::PinnedHistory {
    use busbar_kernel_ledger::cost::{History, HistorySeq, LaneClass, RateCard};
    let card = RateCard::from_micro_rates(
        [
            (
                LaneClass::new(lane, busbar_contract::records::UNIT_INPUT),
                3.0,
            ),
            (
                LaneClass::new(lane, busbar_contract::records::UNIT_OUTPUT),
                16.0,
            ),
        ],
        fee,
    )
    .with_unit_rates(search_units.map(|nanos| (LaneClass::new(lane, SEARCH_UNITS), nanos)));
    crate::root::kernel::PinnedHistory::for_test(
        std::sync::Arc::new(History::opening(card, 0)),
        HistorySeq(0),
    )
}

fn rerank_report(units: u64) -> Report {
    Report {
        usage: busbar_contract::billing::ExactUsage {
            usage_units: std::collections::BTreeMap::from([(
                SEARCH_UNITS.to_string(),
                units.into(),
            )]),
        },
        fee_count: 1,
        lane: "lane".to_string(),
        attribution: String::new(),
    }
}

#[tokio::test]
async fn an_unpriced_class_on_a_present_card_leaves_a_durable_counts_row_and_the_read_refuses() {
    let history = cache_silent_history();
    let mut report = split_report(1_000, 250, 1);
    report.usage.usage_units.insert(
        busbar_contract::records::UNIT_CACHE_READ.to_string(),
        10_000_000u64.into(),
    );
    let at = Arrived::at(4_000, 7);
    let node = record_report(&history, at, "vk_refused", &report).await;

    let rows = recorded_rows(&node).await;
    assert_eq!(rows.len(), 1, "one counts row per refused unit: {rows:?}");
    let row = &rows[0];
    let counts = row.counts.as_ref().expect("the row carries the counts");
    assert_eq!(
        counts.classes,
        std::collections::BTreeMap::from([
            (busbar_contract::records::UNIT_INPUT.to_string(), 1_000),
            (busbar_contract::records::UNIT_OUTPUT.to_string(), 250),
            (
                busbar_contract::records::UNIT_CACHE_READ.to_string(),
                10_000_000
            ),
        ]),
        "every count, whole — not zeroed, not trimmed to the priced classes"
    );
    assert_eq!((counts.lane.as_str(), counts.fee_count), ("lane", 1));
    assert!(
        row.nanos
            .as_ref()
            .err()
            .map(String::as_str)
            .is_some_and(|why| why.contains("ClassUnpriced") && why.contains("cache_read")),
        "the money is refused and says which class: {:?}",
        row.nanos
    );
    assert!(
        row.nanos.is_err(),
        "unpriced counts never become a zero or partial price"
    );

    every_cell_agrees(
        "refused",
        &rows,
        &governance_row(&report),
        &history,
        at.ms(),
    )
    .expect("both books refuse the same unit");
}

#[tokio::test]
async fn a_reranks_search_units_agree_across_both_books() {
    let at = Arrived::at(4_000, 7);

    let priced = rerank_history(3, Some(2_000_000));
    let report = rerank_report(50);
    let node = record_report(&priced, at, "vk_rerank", &report).await;
    let rows = recorded_rows(&node).await;
    every_cell_agrees(
        "rerank, priced",
        &rows,
        &governance_row(&report),
        &priced,
        at.ms(),
    )
    .expect("the books agree on the rerank");

    let fee_only = record_report(&priced, at, "vk_fee", &rerank_report(0)).await;
    let fee_only = recorded_rows(&fee_only).await;
    assert_eq!(
        rows[0].nanos.clone().unwrap() - fee_only[0].nanos.clone().unwrap(),
        50 * 2_000_000,
        "the second book priced the 50 search units"
    );

    let silent = rerank_history(3, None);
    let node = record_report(&silent, at, "vk_silent", &report).await;
    let rows = recorded_rows(&node).await;
    every_cell_agrees(
        "rerank, card silent about search units",
        &rows,
        &governance_row(&report),
        &silent,
        at.ms(),
    )
    .expect("both books refuse a rerank the card is silent about");
    assert!(
        rows[0]
            .nanos
            .as_ref()
            .err()
            .map(String::as_str)
            .is_some_and(|w| w.contains(SEARCH_UNITS)),
        "{:?}",
        rows[0].nanos
    );

    let billed = fee_history_of(
        &[
            (0, 0.5, 1.0, 0),
            (5_000, 5.0, 10.0, 0),
            (9_000, 50.0, 100.0, 3),
        ],
        true,
    );
    let mut failures = Vec::new();
    for (label, at_ms, report) in [
        ("boot card", 1_000, split_report(11, 7, 1)),
        ("card A", 6_000, split_report(11, 7, 1)),
        ("card B + fee", 10_000, split_report(11, 7, 1)),
        ("fee only", 10_000, split_report(0, 0, 1)),
        ("no fee", 10_000, split_report(11, 7, 0)),
    ] {
        let at = Arrived::at(at_ms, 1);
        let node = record_report(&billed, at, "vk_tokens", &report).await;
        if let Err(e) = every_cell_agrees(
            label,
            &recorded_rows(&node).await,
            &governance_row(&report),
            &billed,
            at_ms,
        ) {
            failures.push(e);
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[tokio::test]
async fn a_planted_open_class_divergence_goes_red() {
    let at = Arrived::at(4_000, 7);
    let priced = rerank_history(3, Some(2_000_000));
    let report = rerank_report(50);
    let governance = governance_row(&report);
    let rows = recorded_rows(&record_report(&priced, at, "vk_rerank", &report).await).await;
    every_cell_agrees("unplanted", &rows, &governance, &priced, at.ms())
        .expect("the unplanted rows agree, so a red below is the plant's");

    let mut undercounted = rows.clone();
    if let Some(counts) = undercounted[0].counts.as_mut() {
        counts.classes.insert(SEARCH_UNITS.to_string(), 49);
    }
    let red = every_cell_agrees("planted: 49", &undercounted, &governance, &priced, at.ms());
    assert!(
        red.as_ref()
            .is_err_and(|e| e.contains("class search_units")),
        "an under-counted open class was NOT caught: {red:?}"
    );

    let mut dropped = rows.clone();
    if let Some(counts) = dropped[0].counts.as_mut() {
        counts.classes.remove(SEARCH_UNITS);
    }
    assert!(
        every_cell_agrees("planted: dropped", &dropped, &governance, &priced, at.ms()).is_err(),
        "a dropped open class was NOT caught"
    );

    let fee_only =
        recorded_rows(&record_report(&priced, at, "vk_fee", &rerank_report(0)).await).await;
    let mut head_shaped = rows.clone();
    head_shaped[0].nanos = fee_only[0].nanos.clone();
    assert!(
        every_cell_agrees(
            "planted: fee only",
            &head_shaped,
            &governance,
            &priced,
            at.ms()
        )
        .is_err_and(|e| e.contains("money")),
        "a second book that priced the rerank at the fee alone was NOT caught"
    );
    head_shaped[0].counts = None;
    assert!(
        every_cell_agrees(
            "planted: no counts",
            &head_shaped,
            &governance,
            &priced,
            at.ms()
        )
        .is_err(),
        "a second book with no counts was NOT caught"
    );
}

#[tokio::test]
async fn binding_the_node_keeps_every_confirmed_card_in_the_native_store() {
    use crate::root::kernel::RootHistory;
    use busbar_kernel::config::card::CardFields;
    let card = |input| CardFields {
        rate_card: Some(std::collections::BTreeMap::from([(
            "gpt".into(),
            busbar_kernel::config::RateEntryCfg {
                input_utok: input,
                ..Default::default()
            },
        )])),
        ..Default::default()
    };
    let core = (crate::root::real_store::core()).await;
    let holder: &'static RootHistory = Box::leak(Box::default());
    holder
        .keep_in_store(core.clone(), 7)
        .expect("native price owner binds");
    holder.card_applied(&card(3.0), "boot");
    (holder.boot_in_store(None))
        .await
        .expect("opening card is confirmed");
    let journal = (busbar_kernel::persistence::journal::runtime::RuntimeJournal::open(
        core.clone(),
        7,
        native_budget(),
    ))
    .await
    .unwrap();
    let book = Arc::new(Mutex::new(
        (crate::root::durability::build_on_store(
            &crate::root::durability::DurabilityConfig::default(),
            7,
            journal.clone(),
            Some(holder),
            native_budget(),
        ))
        .await
        .unwrap(),
    ));
    super::bind_node_book(&Node::new(), holder, book);
    let prices = holder.card_store().unwrap();
    let prepared = (prices.prepare(&card(5.0), "test"))
        .await
        .expect("successor prepares");
    let successor = (prepared.confirm_activation())
        .await
        .expect("successor activation applies")
        .commit();
    let cards = prices.entries();
    assert_eq!(
        cards.len(),
        2,
        "opening and confirmed successor are both persisted"
    );
    assert!(cards.iter().any(|entry| entry.key == successor));
    let restarted: &'static RootHistory = Box::leak(Box::default());
    restarted.keep_in_store(core, 7).unwrap();
    restarted.card_applied(&card(5.0), "boot");
    (restarted.boot_in_store(None))
        .await
        .expect("native price history reopens");
    assert_eq!(
        restarted.card_store().unwrap().entries(),
        cards,
        "binding never loses a confirmed card"
    );
    assert_eq!(restarted.card_store().unwrap().in_force(), Some(card(5.0)));
    (journal.flush())
        .await
        .expect("node journal confirms its originals");
    prices.stop_background().await.unwrap();
    restarted
        .card_store()
        .unwrap()
        .stop_background()
        .await
        .unwrap();
}

#[tokio::test]
async fn a_late_arm_with_no_reading_writes_the_exits_own_line() {
    let node = Node::new();
    let book = native_node_book().await;
    let history = rerank_history_on(RERANK_LANE, 3, Some(2_000_000));
    let arm = LateAccrual {
        custody: node.ticket_custody.clone(),
        book: book.durability.clone(),
        line: None,
        history,
        durability_token: node.kernel.durability_token(),
        principal: PrincipalId::new("acct:late-none"),
        arrived: Arrived::at(EPOCH * 1_000, 3),
        late: Box::new(|| None),
        posted: true,
        outcome: Some(Outcome::Completed),
        seal: Some(fixture_seal(1).into()),
    };
    arm.post();
    let journal = book.durability.lock().unwrap().journal.clone();
    assert_eq!(selected(&journal).await.len(), 1);
    let durable = book.durability.lock().unwrap();
    assert_eq!(durable.audit_records().len(), 1);
    assert!(durable.audit_records()[0].usage.lines.is_empty());
}

#[tokio::test]
async fn a_class_no_plane_declared_is_refused_and_keeps_its_counts() {
    assert!(Registration::resolve("units_nobody_declared").is_none());
    let history = cache_silent_history();
    let mut report = split_report(1_000, 0, 1);
    report
        .usage
        .usage_units
        .insert("units_nobody_declared".to_string(), 40u64.into());
    let at = Arrived::at(4_000, 7);
    let node = record_report(&history, at, "vk_undeclared", &report).await;

    let rows = recorded_rows(&node).await;
    assert_eq!(rows.len(), 1, "one line per unit: {rows:?}");
    let row = &rows[0];
    let counts = row.counts.as_ref().expect("the line carries the counts");
    assert_eq!(counts.classes.get("units_nobody_declared"), Some(&40));
    assert_eq!(
        counts.classes.get(busbar_contract::records::UNIT_INPUT),
        Some(&1_000)
    );
    assert!(
        row.nanos
            .as_ref()
            .err()
            .map(String::as_str)
            .is_some_and(
                |why| why.contains("ClassUnpriced") && why.contains("units_nobody_declared")
            ),
        "the money is refused and names the class: {:?}",
        row.nanos
    );
    assert!(
        row.nanos.is_err(),
        "unpriced canonical counts refuse projection"
    );

    let absent = fee_history_of(&[(0, 0.0, 0.0, 0)], false);
    let node = record_report(&absent, at, "vk_undeclared_absent", &report).await;
    let rows = recorded_rows(&node).await;
    assert_eq!(rows.len(), 1, "one line per unit: {rows:?}");
    assert_eq!(
        rows[0].nanos,
        Ok(0),
        "the canonical absent-card projection has no price policy; declaration refusal belongs to actual plane admission"
    );
}

#[tokio::test]
async fn a_declared_open_class_on_an_absent_card_posts_its_counts_unrefused() {
    let absent = fee_history_of(&[(0, 0.0, 0.0, 0)], false);
    let mut report = split_report(0, 0, 0);
    report
        .usage
        .usage_units
        .insert(SEARCH_UNITS.to_string(), 50u64.into());
    let node = record_report(&absent, Arrived::at(4_000, 7), "vk_absent", &report).await;
    let rows = recorded_rows(&node).await;
    assert_eq!(rows.len(), 1, "one line per unit: {rows:?}");
    assert_eq!(
        rows[0].nanos,
        Ok(0),
        "a declared class on an absent card prices at zero"
    );
    assert_eq!(
        rows[0]
            .counts
            .as_ref()
            .and_then(|c| c.classes.get(SEARCH_UNITS)),
        Some(&50)
    );
}

#[tokio::test]
async fn a_dispatch_record_is_written_on_the_book_under_its_units_facts() {
    use busbar_kernel_egress::ports::{Dispatched, DurabilityUnavailable, Journal};
    let node = Arc::new(Node::new());
    let durability = native_fixture()
        .await
        .expect("a memory-buffered journal cannot fail to open");
    let book = Arc::new(std::sync::Mutex::new(durability));
    node.bind_book(Arc::clone(&book));
    let written = async || {
        let journal = book
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .journal
            .clone();
        selected(&journal).await.len()
    };
    let site = NodeEndPost::new(Arc::clone(&node));
    let record = |unit: u64| Dispatched {
        leg: 0,
        attempt: 1,
        pool: busbar_contract::kept::Text::EMPTY,
        destination: busbar_contract::DestinationId::new(0),
        lane: None,
        unit: UnitKey::new(unit),
    };
    site.open(
        UnitKey::new(51),
        PrincipalId::new("acct:dispatch"),
        Arrived::at(EPOCH * 1_000, 0),
        None,
    );
    let before = written().await;
    assert_eq!(site.dispatched(&record(51)), Ok(()));
    assert!(
        site.lock(UnitKey::new(51)).contains_key(&UnitKey::new(51)),
        "the actual open unit retains its dispatch facts"
    );
    assert_eq!(
        written().await,
        before,
        "dispatch facts wait for the single terminal audit original"
    );
    assert_eq!(
        site.dispatched(&record(52)),
        Err(DurabilityUnavailable),
        "no open facts, no record, no dial"
    );
    assert_eq!(written().await, before);
    site.close(UnitKey::new(51));
}

#[tokio::test]
async fn the_exit_arm_seals_no_money_figure_into_the_record() {
    use busbar_contract::caps::{Admittance, Hold, Posted, Usage, WriteMoney};
    use busbar_kernel::test_hooks::tokens::{end, grant, origin, pass};

    let node = Node::new();
    let durability = native_fixture()
        .await
        .expect("a memory-buffered journal cannot fail to open");
    let book = Arc::new(std::sync::Mutex::new(durability));
    node.bind_book(Arc::clone(&book));

    const MONEY: u64 = 150;
    let who = PrincipalId::new("acct:h2");
    let hold = Hold::open(&grant::<Admittance>(), who.clone());
    let usage = Usage::report(&grant::<busbar_contract::caps::Consumption>(), Vec::new())
        .expect("an empty report fits the record");
    let posted = Posted::settle(hold, MONEY, &usage, &grant::<WriteMoney>());
    assert_eq!(posted.quantity(), MONEY, "the posting moved money");
    let ended = Ended::Settled {
        end: end(Outcome::Completed, Ok(posted)),
        requests: 0,
        fee: 0,
    };
    let seal = UnitSeal {
        facts: busbar_contract::caps::AuditFacts {
            op_class: busbar_contract::caps::OpClassId::new("call"),
            finish: busbar_contract::FinishClass::Complete,
        },
        pass: pass(),
        key: UnitKey::new(77),
        origin: origin(OriginKind::Client),
        parent: None,
    };
    node.seal_end(
        &who,
        Arrived::at(EPOCH * 1_000, 0),
        None,
        ended,
        Some(seal),
        Vec::new(),
    );

    let durability = book.lock().unwrap_or_else(|p| p.into_inner());
    let record = durability
        .audit_records()
        .last()
        .expect("the exit arm sealed the unit's record");
    assert!(
        record.usage.lines.iter().all(|line| line.class
            != busbar_kernel::teller::KERNEL_ACCRUAL_CLASS
            && line.quantity != MONEY),
        "the record carries counts, never the settled money figure: {:?}",
        record.usage.lines
    );
}

#[tokio::test]
async fn a_late_body_terminal_stage_refusal_is_a_body_error() {
    use http_body_util::BodyExt;
    let node = Node::new();
    let book = native_node_book().await;
    let journal = book.durability.lock().unwrap().journal.clone();
    journal.stop_staging().unwrap();
    let arm = LateAccrual {
        custody: node.ticket_custody.clone(),
        book: book.durability.clone(),
        line: None,
        history: rerank_history_on(RERANK_LANE, 3, Some(2_000_000)),
        durability_token: node.kernel.durability_token(),
        principal: PrincipalId::new("acct:late-refused"),
        arrived: Arrived::at(EPOCH * 1_000, 3),
        late: Box::new(|| None),
        posted: true,
        outcome: Some(Outcome::Completed),
        seal: Some(fixture_seal(1).into()),
    };
    let body = LateBody::new(axum::body::Body::empty(), arm);
    assert!(
        body.collect().await.is_err(),
        "EOF must not hide refused audit staging"
    );
    assert!(book.durability.lock().unwrap().audit_records().is_empty());
}
