// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE NODE'S MONEY, PROVEN WITH NO PLANE LINKED (Law 10, `BUSBAR-1.6.0.md` l.2110): the node's
//! cells whose subject lives on after the legacy engine is deleted, built in EVERY test build.
//!
//! `tests/plane_node.rs` drives the node through a plane the build links on the `node` axis
//! (`cfg(linked_axis_node)`), so it compiles only while such a plane is linked. Its cells whose
//! subject is the node's own money code (the late arm, the one pricing site and its card pin, the
//! sweep and its drop guard, the abandoned-end posting site, the dispatch record, the lane-name
//! interner, the book binding, and the two books agreeing) are ported here, each naming the cell it
//! ports and holding that cell's assertions as they were: the same amounts, the same nano-units,
//! the same books-agree checks.
//!
//! Two shapes. A cell that already named no plane is ported VERBATIM. A cell that reached the node
//! through the plane's handed unit is ported onto the DOOR PATH: a unit of the test's own, driven
//! through [`Node::drive_borrowed`] exactly as `root::serve` drives a door unit (its late reading
//! handed in as the door's `report_of` hands it), onto a bound book.

use super::*;
use busbar_contract::caps::{
    Admit, Admittance, Approve, Arrival, Authenticate, Consumption, Decode, Dial, Encode, Meter,
    Refusal, SeatVerdict, Verify,
};
use busbar_kernel::slice::GroupLeaseSlip;

use std::sync::atomic::AtomicBool;

use busbar_contract::caps::{
    Admission, ArrivalRecord, Authenticated, Frame, ReasonCode, RoutePlan, ScopeFacts,
};
use busbar_kernel::teller::Kernel;

/// A configured lane name the interner cells resolve.
const LANE: &str = "m0";

/// **One arrival is one reading, and both figures come out of it.**
///
/// The pure half of the straddle. A unit arriving at the last millisecond of a window has its
/// seconds in that window and its milliseconds one tick short of the next: read the clock twice
/// there and the second read is already over the line, so the table stamps the unit in one
/// window and the books bill it in another. Read once and the two figures are two spellings of
/// one instant, which is the property asserted here.
// PORT of `crates/busbar/src/root/tests/plane_node.rs::one_arrival_reading_spells_both_the_figures_the_loop_asks_for`, verbatim: it names no plane.
#[test]
fn one_arrival_reading_spells_both_the_figures_the_loop_asks_for() {
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

/// **Two units of one second are ordered by the monotonic stamp, not by the wall clock.**
///
/// The node's two clocks answer two different questions and the audit record and the posting
/// stamp each want both. The wall clock DATES: it says which window a unit belongs to, and it is
/// steppable, so an operator, an NTP correction or a leap second can hand two events timestamps
/// that run backwards. The monotonic reading ORDERS: it only goes up, whatever the wall clock
/// does.
///
/// So: units taken from one node inside one second — indistinguishable by the wall reading, and
/// on a stepped clock possibly backwards by it — still come out of the monotonic reading in the
/// order they were taken. Stamped from the wall clock twice, as this leg's postings were, the
/// second field is a copy of the first and this ordering does not exist.
// PORT of `crates/busbar/src/root/tests/plane_node.rs::two_units_of_one_second_are_ordered_by_the_monotonic_stamp`, verbatim: it names no plane.
#[test]
fn two_units_of_one_second_are_ordered_by_the_monotonic_stamp() {
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
    // Four units off one node inside one second is the ordinary case, not a contrived one — and
    // it is exactly the case a wall clock cannot resolve, whichever direction it was stepped.
    assert!(
        taken
            .iter()
            .all(|a| a.secs() == taken[0].secs() || a.secs() == taken[0].secs() + 1),
        "the four were taken within a second of each other"
    );
    // Two readings, not one written twice: a monotonic counter is a SEQUENCE and an epoch is a
    // date, so the day they compare equal is the day one of them stopped being what it is.
    assert_ne!(taken[0].mono(), taken[0].secs());

    // AND THE STAMP CARRIES IT. Two postings settled at one wall second, taken through the real
    // settle path onto a real journal, come back off it in the order they were written — which
    // is the ordering the record is FOR, and which does not exist if the second field is the
    // first one copied.
    let durability = crate::root::durability::build(
        &crate::root::durability::DurabilityConfig { data_dir: None },
        Box::new(busbar_kernel_wal::NullShipper::new()),
        Box::new(busbar_kernel_ledger::legacy::RecordingRows::new()),
    )
    .expect("a memory-buffered journal cannot fail to open");
    // Both settlements through the ONE money-book seam over the shared book — the pass-through the
    // live exit arm now takes, and what a second exit arm settling behind the first takes too.
    let book = std::sync::Arc::new(std::sync::Mutex::new(durability));
    let seam = crate::root::durability::SharedBook::over(std::sync::Arc::clone(&book));
    let who = PrincipalId::new("acct:node");
    for arrived in [Arrived::at(EPOCH * 1_000, 7), Arrived::at(EPOCH * 1_000, 8)] {
        let ledger_token =
            busbar_kernel::test_support::tokens::grant::<busbar_contract::caps::WriteMoney>();
        let accrual =
            busbar_contract::caps::HoldAccrual::after_terminal(who.clone(), 0, &ledger_token);
        let posted = busbar_contract::caps::Posted::settle_late(accrual, &ledger_token);
        settle(
            &seam,
            &who,
            arrived,
            None,
            &busbar_kernel::test_support::tokens::grant::<busbar_contract::caps::DurableWrite>(),
            posted,
        )
        .expect("the memory-buffered journal takes it");
    }
    let durability = book.lock().unwrap_or_else(|p| p.into_inner());
    let replayed = durability
        .journal
        .replay()
        .expect("reads back")
        .expect("verifies");
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

/// The unit-arrival epoch this proof pins, so the window a posting lands in is a fixed one.
const EPOCH: u64 = 1_700_000_000;

/// A history of one entry per `(effective_from_ms, output rate)`, built OUTSIDE the process
/// holder so these proofs name their own instants instead of racing the wall clock.
///
/// The first entry is effective from zero for the same reason the holder's is: an instant before
/// the first entry is a hole and a hole is a refusal.
fn history_of(entries: &[(u64, f64)]) -> crate::root::kernel::PinnedHistory {
    let entries: Vec<_> = entries
        .iter()
        .map(|&(from, output)| (from, 0.0, output, 0))
        .collect();
    fee_history_of(&entries, true)
}

/// A report of `output` tokens on the lane the histories above price.
fn report_of(output: u64) -> Report {
    Report {
        usage: busbar_contract::billing::Usage {
            usage_units: std::collections::BTreeMap::from([(
                busbar_contract::records::UNIT_OUTPUT.to_string(),
                output,
            )]),
        },
        fee_count: 0,
        lane: "lane".to_string(),
    }
}

/// **THE UNIT PRICES AT THE INSTANT IT ARRIVED**, not at the instant the question is asked.
///
/// Two units, one snapshot, one call each: the one that arrived before the second entry took
/// effect prices at the first entry's rate and the one that arrived after prices at the
/// second's. Both readings are taken from the SAME history at the SAME moment, so the only thing
/// that can be producing two answers is the arrival instant — which is the whole of rule 3.
///
/// A node that priced against "the current card" answers the later figure for both, which is
/// exactly the recorded 1.5.5 behaviour and exactly what this replaces.
// PORT of `crates/busbar/src/root/tests/plane_node.rs::a_unit_prices_at_the_entry_in_force_when_it_arrived_and_not_at_the_head`, verbatim: it names no plane.
#[test]
fn a_unit_prices_at_the_entry_in_force_when_it_arrived_and_not_at_the_head() {
    let kernel = Kernel::new();
    let token = kernel.usage_token();
    let history = history_of(&[(0, 1.0), (5_000, 100.0)]);

    let early = priced_amount(&history, Arrived::at(4_999, 1), &token, &report_of(1_000));
    let late = priced_amount(&history, Arrived::at(5_000, 2), &token, &report_of(1_000));

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

/// **THE PIN HOLDS.** A snapshot taken at admission cannot see an entry appended after it, so an
/// apply landing mid-body does not reprice a request halfway through.
///
/// The pinned reader and the head are both asked about the SAME instant, and they answer
/// differently — which is only possible because the pin stops the snapshot's slice short of the
/// later entry. A holder that handed out the whole history and a live head would answer the new
/// figure to a request that was admitted under the old one.
// PORT of `crates/busbar/src/root/tests/plane_node.rs::a_snapshot_pinned_at_admission_cannot_see_an_entry_appended_behind_it`, verbatim: it names no plane.
#[test]
fn a_snapshot_pinned_at_admission_cannot_see_an_entry_appended_behind_it() {
    let kernel = Kernel::new();
    let token = kernel.usage_token();
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

    // The apply that lands while the body is still draining.
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
        priced_amount(&admitted, at, &token, &report_of(1_000)),
        Ok(1_000_000),
        "the pinned snapshot saw an entry appended after the unit was admitted"
    );
    assert_eq!(
        priced_amount(&next, at, &token, &report_of(1_000)),
        Ok(100_000_000),
        "the next admission did not see the appended entry"
    );
}

/// **THE PIN IS A SEQ, NOT ONLY AN `Arc`.** A reader holding the same history at a lower
/// snapshot reads it as it stood at that snapshot.
///
/// The `Arc` alone is not the pin: an amendment, and a copy-on-write apply that a second reader
/// already took, both leave one history holding entries a reader was never admitted under. The
/// seq is what stops the slice short of them, and this asks the SAME history at two snapshots to
/// prove the stopping is real rather than an accident of when the `Arc` was cloned.
// PORT of `crates/busbar/src/root/tests/plane_node.rs::a_pin_below_the_head_reads_the_history_as_it_stood_at_that_seq`, verbatim: it names no plane.
#[test]
fn a_pin_below_the_head_reads_the_history_as_it_stood_at_that_seq() {
    let kernel = Kernel::new();
    let token = kernel.usage_token();
    let head = history_of(&[(0, 1.0), (5_000, 100.0)]);
    let earlier = crate::root::kernel::PinnedHistory::for_test_at(
        &head,
        busbar_kernel_ledger::cost::HistorySeq(0),
    );

    let at = Arrived::at(9_000, 1);
    assert_eq!(
        priced_amount(&earlier, at, &token, &report_of(1_000)),
        Ok(1_000_000),
        "a snapshot at seq 0 resolved an entry that was appended after it"
    );
    assert_eq!(
        priced_amount(&head, at, &token, &report_of(1_000)),
        Ok(100_000_000),
        "the head snapshot did not resolve the entry appended onto it"
    );
}

/// **THE POSTING CARRIES NO PRICE; THE FIGURE IS THE LOOKUP'S.**
///
/// The posting the pricing builds holds the counts and the instant and no figure at all, so there is
/// nothing on it a reader could take for the money: asked again over the same history, the posting
/// answers exactly the figure the pricing returned, and the instant it kept is the unit's own.
// PORT of `crates/busbar/src/root/tests/plane_node.rs::the_posting_carries_no_price_and_its_figure_is_the_lookups`, verbatim: it names no plane.
#[test]
fn the_posting_carries_no_price_and_its_figure_is_the_lookups() {
    let kernel = Kernel::new();
    let token = kernel.usage_token();
    let history = history_of(&[(0, 1.0)]);
    let at = Arrived::at(4_000, 7);

    let (posting, priced) = priced_posting(&history, at, &token, &report_of(1_000));
    let priced = priced.expect("a card in force at the instant prices the report");
    assert_eq!(
        posting.arrived_ms, 4_000,
        "the posting kept its own instant"
    );
    assert_eq!(posting.arrived_mono, 7);
    assert_eq!(
        posting
            .priced_nanos(&history.view())
            .expect("the lookup still answers"),
        priced.priced_nanos,
        "the posting's figure is the lookup's, asked again"
    );
}

/// THE INTERNER IS THE NODE'S, and it is idempotent.
///
/// A lane name is leaked to become the borrowed static one the priced axis is written in, so
/// interning the same name twice must yield the same pointer: a leak per request would be a
/// leak per request whatever it was called.
// PORT of `crates/busbar/src/root/tests/plane_node.rs::the_nodes_interner_leaks_a_lane_name_once`, verbatim: it names no plane.
#[test]
fn the_nodes_interner_leaks_a_lane_name_once() {
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

/// AND THE INTERNER IS REACHED ONCE PER NAME, not once per request.
///
/// The interner is one mutex for the whole image, and the Verify step resolves a name per
/// candidate lane, per request — so a node that asks it every time makes every plane in the
/// process queue behind one lock for an answer that was settled the first time. The count is
/// per distinct name and does not grow with how often the name is asked for.
// PORT of `crates/busbar/src/root/tests/plane_node.rs::a_lane_name_reaches_the_interner_once_however_often_it_is_resolved`, verbatim: it names no plane.
#[test]
fn a_lane_name_reaches_the_interner_once_however_often_it_is_resolved() {
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

/// THE PROVENANCE STAMP NAMES THE CARD IN FORCE WHEN THE UNIT ARRIVED (#79), not the newest card
/// ever published and not a literal.
///
/// This stamp used to be a hardcoded `0`, and `0` is not a neutral placeholder: it is
/// `HistorySeq::OPENING`, a REAL entry number. So every posting this plane made claimed the opening
/// card had priced it — and the node (`plane_node`) is the root unit module that is live on the
/// serving path, so this was a confident wrong answer on shipped traffic, which is worse than none.
///
/// THE CANARY IS THE POINT. Three dated entries over one history and three arrivals, one in each
/// window. Two of the three expected values are NON-ZERO, so the pre-fix code — which answered `0`
/// for every unit — fails this test on those two. A test whose expectations were all `0` would have
/// passed against the bug it was written for.
///
/// It also pins the MILLISECOND binding: `effective_from` is written on the millisecond scale
/// (`root/kernel.rs:435`), so a resolution handed the seconds reading matches only the from-zero
/// opening entry and reports it forever. The `_at_seconds` assertion below is that hazard made
/// visible — it is the bug wearing a different hat, and it would pass a "reads a history" review.
// PORT of `crates/busbar/src/root/tests/plane_node.rs::the_node_provenance_stamp_names_the_card_in_force_when_the_unit_arrived`, verbatim: it names no plane.
#[test]
fn the_node_provenance_stamp_names_the_card_in_force_when_the_unit_arrived() {
    // Dated on the MILLISECOND scale the history is written on. The first is effective from instant
    // zero however it is dated — one entry has to cover every instant, or an early arrival falls in
    // a hole and is reported as OPENING for a different reason.
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
        pinned.seq().get(),
        2,
        "the snapshot's head is the third entry — the figure a stamp must NOT be for a unit that \
         arrived before it, and the one a `read the head` implementation would answer every time"
    );

    let stamped_ms = |ms: u64| card_in_force(Some(&pinned), ms);

    assert_eq!(
        stamped_ms(1_700_000_100_000),
        0,
        "a unit that arrived before the second card was published is priced by the opening entry"
    );
    assert_eq!(
        stamped_ms(1_700_000_600_000),
        1,
        "a unit that arrived in the second card's window names the SECOND entry — not the third, \
         which had not been published when it arrived (#79: publishing never reprices backwards)"
    );
    assert_eq!(
        stamped_ms(1_700_001_000_000),
        2,
        "a unit that arrived after the third card names the third entry"
    );

    // NO HISTORY PINNED — a build with no root ledger. The opening entry is the only one that
    // covers every instant by construction, so it is the honest fallback rather than a silent hole.
    assert_eq!(
        card_in_force(None, 1_700_000_600_000),
        0,
        "no pinned history falls back to the opening entry"
    );

    // THE SECONDS/MILLISECONDS HAZARD, made visible. Handed the SECONDS reading of the same instant
    // that resolves to entry 1 above, every arrival collapses onto the opening entry — the original
    // bug with a lookup in front of it. `Arrived::ms()` is what the settle path passes, and this is
    // why.
    assert_eq!(
        stamped_ms(1_700_000_600),
        0,
        "a seconds-valued instant matches only the from-zero opening entry — which is why the \
         settle path resolves at `Arrived::ms()` and never at `Arrived::secs()`"
    );
}

// ---------------------------------------------------------------------------------------------
// ITEM 126 — TWO BOOKS OVER ONE EVENT: WHICH ONE IS THE INVOICE, AND A DISAGREEMENT IS RED
// ---------------------------------------------------------------------------------------------

/// A dated history of `(effective_from_ms, input rate, output rate, flat fee)` entries over the one
/// lane `"lane"`, built outside the process holder so the proof names its own instants. `present`
/// is the #42 switch: `false` builds the ABSENT card (billing off — every class at nothing, the flat
/// fee still carried, `card_from_config`'s documented shape).
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

/// A late report of `input`/`output` tokens and `fee_count` billable requests on `"lane"`.
fn split_report(input: u64, output: u64, fee_count: u32) -> Report {
    let mut units = std::collections::BTreeMap::new();
    if input != 0 {
        units.insert(busbar_contract::records::UNIT_INPUT.to_string(), input);
    }
    if output != 0 {
        units.insert(busbar_contract::records::UNIT_OUTPUT.to_string(), output);
    }
    Report {
        usage: busbar_contract::billing::Usage { usage_units: units },
        fee_count,
        lane: "lane".to_string(),
    }
}

/// **THE INVOICE'S FIGURE for one unit** — what `GET /api/v1/admin/usage` serves for the metering
/// row this unit lands on, computed by the admin read's OWN function (`read_path_money`, a `pub use`
/// of the served derivation, never a copy) at the instant that read resolves the row at:
/// `row_priced_at_ms(bucket start, era start)`, where the era is the `effective_from` of the entry
/// in force when the unit accrued (what `record_metering` stamps as `priced_from_ms`).
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
    let unit = |k: &str| report.usage.usage_units.get(k).copied().unwrap_or(0);
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

/// The second book's figure (nano-units) through the CHECKED micro-projection — the one money type,
/// which refuses a figure it cannot hold rather than pinning it at the ceiling (item 28).
fn second_book_micros(
    second_book: Result<u64, busbar_kernel_ledger::cost::Unpriceable>,
) -> Result<i64, String> {
    let nanos = second_book.map_err(|refusal| format!("the second book refused: {refusal:?}"))?;
    busbar_kernel_ledger::cost::Money::of_nanos(u128::from(nanos))
        .and_then(busbar_kernel_ledger::cost::Money::micros_i64)
        .map_err(|refusal| format!("{nanos} nano-units do not project: {refusal:?}"))
}

/// The reconciliation: the second book's posting (nano-units) projected through the ONE checked
/// micro-projection must equal the invoice's figure. A second book that REFUSED where the invoice
/// served a figure disagrees with it. `Err` names the cell and both figures.
fn books_agree(
    label: &str,
    second_book: Result<u64, busbar_kernel_ledger::cost::Unpriceable>,
    invoice: i64,
) -> Result<(), String> {
    let projected = second_book_micros(second_book.clone());
    if projected == Ok(invoice) {
        Ok(())
    } else {
        Err(format!(
            "{label}: the kernel-loop book posted {second_book:?} nano-units ({projected:?} micro) \
             but the invoice (/admin/usage over the governance ledger) serves {invoice} micro"
        ))
    }
}

/// **TWO BOOKS, ONE EVENT — THE INVOICE IS THE GOVERNANCE LEDGER, AND THE SECOND BOOK MUST AGREE WITH
/// IT CELL BY CELL.**
///
/// A delivered node unit leaves two records. The walk's completion tap accrues its counts onto the
/// GOVERNANCE LEDGER (the metering series + usage ledger) — raw counts, no price, which is what
/// `/usage` serves and what 1.5.5 billed. Then [`LateAccrual`] PRICES the same reading and posts
/// the priced amount onto the kernel-loop Durability book. By the money model (BUSBAR-1.6.0.md
/// Part 0: *money = f(ledger, ratecard), derived at read time*; #43/#71: the ledger stores counts;
/// #77(3): a price is NEVER stored) only the first can be the invoice: it holds the facts and the
/// served figure is the read-time view over them. The Durability posting carries a priced figure,
/// so it is a derived reading — sound exactly while it agrees with the invoice, and a defect the
/// moment it does not.
///
/// The cells mirror `billing|rate-card|history-mid-window`: a boot card, a 10x card, then a 100x card
/// with a 3-unit flat fee, and a unit arriving in each window — plus a fee-only unit (a failed
/// billing that still carries its request), a token-only provider-origin unit (fee count 0), and a
/// billing-OFF deployment (absent card, #42: tokens at nothing, fee still carried).
///
/// THE NEGATIVE CONTROL is inside the test: the same comparator fed a PLANTED divergence — the
/// second book priced against the head card instead of the card in force at arrival, and the second
/// book dropping the fee — must report RED. A comparator that could not see those would make the
/// green above meaningless.
// PORT of `crates/busbar/src/root/tests/plane_node.rs::the_second_book_agrees_with_the_invoice_cell_by_cell_and_a_divergence_is_red`, verbatim: it names no plane.
#[test]
fn the_second_book_agrees_with_the_invoice_cell_by_cell_and_a_divergence_is_red() {
    let kernel = Kernel::new();
    let token = kernel.usage_token();
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
        let second = priced_amount(history, Arrived::at(*at, 1), &token, report);
        let invoice = invoice_micros(history, *at, report);
        if let Err(e) = books_agree(label, second, invoice) {
            failures.push(e);
        }
    }
    assert!(
        failures.is_empty(),
        "the second book disagrees with the invoice on {} cell(s):\n{}",
        failures.len(),
        failures.join("\n")
    );

    // A NON-VACUITY FLOOR: the billed cells are not all zero, so agreement is not 0 == 0.
    assert_eq!(
        Ok(invoice_micros(&billed, 10_000, &split_report(11, 7, 1))),
        // 11 x 50 + 7 x 100 + the 3-unit fee at the one scale.
        second_book_micros(priced_amount(
            &billed,
            Arrived::at(10_000, 1),
            &token,
            &split_report(11, 7, 1)
        )),
    );
    assert_ne!(invoice_micros(&billed, 10_000, &split_report(11, 7, 1)), 0);

    // THE PLANTED DIVERGENCES — each must go RED.
    // (1) the second book prices a unit that arrived under the boot card at the HEAD card.
    let early = split_report(11, 7, 1);
    let at_head = priced_amount(&billed, Arrived::at(10_000, 1), &token, &early);
    assert!(
        books_agree(
            "planted: priced at head",
            at_head,
            invoice_micros(&billed, 1_000, &early)
        )
        .is_err(),
        "a second book priced at the head card was NOT caught disagreeing with the invoice"
    );
    // (2) the second book drops the flat fee.
    let fee_dropped = priced_amount(
        &billed,
        Arrived::at(10_000, 1),
        &token,
        &split_report(11, 7, 0),
    );
    assert!(
        books_agree(
            "planted: fee dropped",
            fee_dropped,
            invoice_micros(&billed, 10_000, &split_report(11, 7, 1))
        )
        .is_err(),
        "a second book that dropped the fee was NOT caught disagreeing with the invoice"
    );
}

/// A PRESENT card (#42) that prices `"lane"`'s input and output and is SILENT about cache reads.
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

/// **AN UNPRICED CLASS ON A PRESENT CARD KEEPS ITS COUNTS ROW, AND THE READ REFUSES** (#42, #43).
///
/// The unit read 1,000 input, 250 output and 10,000,000 cache-read tokens; the card in force names
/// input and output for the lane and says nothing about cache reads. Before, settlement priced
/// through the READ posture, which flags the silent class and prices it at nothing, so the second
/// book took 7,000,000 nano-units — the input and output alone — for a unit whose largest line
/// was never priced: a RATECARD fault (a class the card should have refused) booked as a figure.
///
/// Now settlement prices fail-closed and REFUSES; the posting still carries every count, whole,
/// and the served read over the same counts refuses the same class. Nothing is zeroed, nothing is
/// dropped, and no partial figure reaches a book.
// PORT of `crates/busbar/src/root/tests/plane_node.rs::an_unpriced_class_on_a_present_card_keeps_its_counts_row_and_the_read_refuses`, verbatim: it names no plane.
#[test]
fn an_unpriced_class_on_a_present_card_keeps_its_counts_row_and_the_read_refuses() {
    let kernel = Kernel::new();
    let token = kernel.usage_token();
    let history = cache_silent_history();
    let mut report = split_report(1_000, 250, 1);
    report.usage.usage_units.insert(
        busbar_contract::records::UNIT_CACHE_READ.to_string(),
        10_000_000,
    );
    let at = Arrived::at(4_000, 7);

    // THE ROW: the counts, whole — not zeroed, not dropped, not trimmed to the priced classes.
    let (posting, priced) = priced_posting(&history, at, &token, &report);
    let counts: std::collections::BTreeMap<&str, u64> = posting
        .quantities
        .iter()
        .map(|q| (q.class.as_str(), q.amount))
        .collect();
    assert_eq!(
        counts,
        std::collections::BTreeMap::from([
            (busbar_contract::records::UNIT_INPUT, 1_000),
            (busbar_contract::records::UNIT_OUTPUT, 250),
            (busbar_contract::records::UNIT_CACHE_READ, 10_000_000),
        ]),
        "the posting lost or zeroed a count the unit reported"
    );
    assert_eq!(posting.fee_count, 1, "the billable count rides the row");

    // SETTLEMENT REFUSES the class: no figure stands for it.
    assert!(
        matches!(
            priced,
            Err(busbar_kernel_ledger::cost::Unpriceable::ClassUnpriced { ref class, .. })
                if class == busbar_contract::records::UNIT_CACHE_READ
        ),
        "settlement priced a class the present card is silent about: {priced:?}"
    );
    assert!(
        matches!(
            priced_amount(&history, at, &token, &report),
            Err(busbar_kernel_ledger::cost::Unpriceable::ClassUnpriced { .. })
        ),
        "the second book was handed a figure — a partial is a silent zero for the unpriced class"
    );

    // THE READ over the same counts row — the served /admin/usage derivation — refuses too.
    use busbar_core_admin::v1::service::read_path_money as invoice;
    let view = history.view();
    let (_, card) = view.card_at(at.ms()).expect("the card is in force");
    let row = invoice::UsageBreakdown {
        tokens_input: 1_000,
        tokens_output: 250,
        tokens_cache_read: 10_000_000,
        tokens_cache_creation: 0,
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

/// **A FIGURE THE RECORD CANNOT HOLD REFUSES; IT IS NEVER PINNED AT THE CEILING** (item 28).
///
/// 10^17 output tokens at 1,000 micro-units each is 10^23 nano-units: inside the one function's
/// arithmetic, past a `u64`. The narrowing used to answer `u64::MAX` — a bill nobody posted.
// PORT of `crates/busbar/src/root/tests/plane_node.rs::a_settled_figure_past_the_record_refuses_and_is_never_pinned`, verbatim: it names no plane.
#[test]
fn a_settled_figure_past_the_record_refuses_and_is_never_pinned() {
    let kernel = Kernel::new();
    let token = kernel.usage_token();
    let history = history_of(&[(0, 1_000.0)]);
    let (_, priced) = priced_posting(
        &history,
        Arrived::at(4_000, 7),
        &token,
        &report_of(100_000_000_000_000_000),
    );
    assert!(
        priced.is_ok_and(|p| p.priced_nanos > u128::from(u64::MAX)),
        "the fixture must price past the record, or this pins nothing"
    );
    assert_eq!(
        priced_amount(
            &history,
            Arrived::at(4_000, 7),
            &token,
            &report_of(100_000_000_000_000_000)
        ),
        Err(busbar_kernel_ledger::cost::Unpriceable::Overflow),
    );
}

/// ITEM 129: THE DROP GUARD MARKS, AND THE SWEEP SETTLES WHAT IT MARKED.
///
/// A unit whose task goes away before its end is reached leaves its hold in its cell. The guard used
/// to REMOVE the slot on every way out, so the sweep — the second holder of a key to that cell —
/// could never see it, and nothing in production called the sweep anyway: the hold stayed in a cell
/// nothing would ever take it out of and the unit posted nothing. Now the guard marks and leaves the
/// slot, and the next arrival's sweep takes the hold, posts it onto the node's book, and gives the
/// slot back.
// PORT of `crates/busbar/src/root/tests/plane_node.rs::a_unit_whose_task_went_away_is_marked_and_the_sweep_posts_its_hold`, verbatim: it names no plane.
#[test]
fn a_unit_whose_task_went_away_is_marked_and_the_sweep_posts_its_hold() {
    let (node, book) = swept_node();

    let who = PrincipalId::new("acct:swept");
    let key = UnitKey::new(41);
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
                who,
                node.kernel.next_call(),
            ),
            now: EPOCH * 1_000,
        })
        .expect("the uncapped table takes the unit");

    // The task goes away with its hold still in the cell: an end nobody reached.
    drop(Occupied {
        node: &node,
        slot: Arc::clone(&slot),
        arrived: Arrived::at(EPOCH * 1_000, 7),
        op_class: busbar_contract::caps::OpClassId::new("call"),
        hold: None,
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

    // The next arrival sweeps.
    assert_eq!(node.sweep(Arrived::at(EPOCH * 1_000 + 5, 99)), 1);
    assert_eq!(
        slot.cell().state(),
        busbar_contract::caps::HoldCellState::Taken,
        "the sweep took the hold out of the cell"
    );
    assert!(node.inflight.get(key).is_none(), "and gave the slot back");
    {
        let durability = book.lock().unwrap_or_else(|p| p.into_inner());
        let replayed = durability
            .journal
            .replay()
            .expect("reads back")
            .expect("verifies");
        assert_eq!(
            replayed
                .iter()
                .filter(|r| r.class == busbar_kernel_wal::RecordClass::Transaction)
                .count(),
            2,
            "the swept hold's posting is on the journal, and its one audit record beside it"
        );
        assert_eq!(durability.ledger.book().len(), 1, "and on the book");
    }
    // Nothing marked is left, so the next arrival's sweep walks nothing.
    assert_eq!(node.sweep(Arrived::at(EPOCH * 1_000 + 6, 100)), 0);

    // A unit that reached its own end gives its slot straight back, unmarked.
    let key = UnitKey::new(42);
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
                node.kernel.next_call(),
            ),
            now: EPOCH * 1_000,
        })
        .expect("the uncapped table takes the unit");
    drop(Occupied {
        node: &node,
        slot: Arc::clone(&slot),
        arrived: Arrived::at(EPOCH * 1_000, 8),
        op_class: busbar_contract::caps::OpClassId::new("call"),
        hold: None,
        reached_end: true,
    });
    assert!(!slot.is_marked());
    assert!(node.inflight.get(key).is_none());
}

/// A fresh node over a memory-buffered book, and that book.
fn swept_node() -> (
    Node,
    Arc<std::sync::Mutex<crate::root::durability::Durability>>,
) {
    let node = Node::new();
    let book = Arc::new(Mutex::new(
        crate::root::durability::build(
            &crate::root::durability::DurabilityConfig { data_dir: None },
            Box::new(busbar_kernel_wal::NullShipper::new()),
            Box::new(busbar_kernel_ledger::legacy::RecordingRows::new()),
        )
        .expect("a memory-buffered journal cannot fail to open"),
    ));
    node.bind_book(Arc::clone(&book));
    (node, book)
}

/// Enter unit `key` into `node`'s table with its arrival hold, then drop its guard unfinished: a
/// unit whose task went away under operation class `op_class`, its hold at `hold` on the chain.
fn lose_a_unit(node: &Node, key: UnitKey, op_class: &'static str, hold: Option<u64>) {
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
                node.kernel.next_call(),
            ),
            now: EPOCH * 1_000,
        })
        .expect("the uncapped table takes the unit");
    drop(Occupied {
        node,
        slot,
        arrived: Arrived::at(EPOCH * 1_000, key.get()),
        op_class: busbar_contract::caps::OpClassId::new(op_class),
        hold,
        reached_end: false,
    });
}

/// Q128 p29#5: A SWEPT UNIT SEALS EXACTLY ONE AUDIT RECORD, AND ITS AMOUNT IS ITS LEDGER LINE.
///
/// THE DESIGN §1 (`BUSBAR-1.6.0.md` l.190-197): "The audit step writes one fixed record, for every
/// plane ... never optional"; §7 U14 (l.1061-1065): one audit record per unit, sealed at its one
/// line. A unit whose task disappeared is ended by the node's sweep, never by its own exit, so the
/// record is the sweep's to seal: outcome `Failed(at, TaskLost)`, finish `Error`, the operation class
/// the unit's guard recorded, the hold its admission opened, and the posted line by its registered
/// class. The swept unit's evidence went with its task, so its line is the estimated zero under the
/// kernel's own class: a money figure no registration declares and a record may not hold (§1
/// l.193-195, #43, #77(3)), so the record names no line and its amount, zero, is the zero the line
/// moved. And the record reads back, as every record on the journal must at the next boot.
///
/// RED before the fix: the sweep posted the unit's line with `None::<Sealing>` ("A unit the sweep
/// ends never handed back its audit pass: it has no record"), so the book had a posting and the
/// chain no record.
// PORT of `crates/busbar/src/root/tests/plane_node.rs::a_swept_unit_seals_exactly_one_audit_record_whose_amount_is_its_ledger_line`, verbatim: it names no plane.
#[test]
fn a_swept_unit_seals_exactly_one_audit_record_whose_amount_is_its_ledger_line() {
    let (node, book) = swept_node();
    let key = UnitKey::new(51);
    lose_a_unit(&node, key, "widget_call", Some(3));
    assert_eq!(node.sweep(Arrived::at(EPOCH * 1_000 + 5, 99)), 1);

    let durability = book.lock().unwrap_or_else(|p| p.into_inner());
    assert_eq!(
        durability.ledger.book().len(),
        1,
        "the swept unit posted one line"
    );
    let records: Vec<_> = durability
        .audit_records
        .iter()
        .filter(|r| r.what.unit_key == key)
        .collect();
    assert_eq!(
        records.len(),
        1,
        "one record for the one swept unit: {:?}",
        durability.audit_records
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
    assert_eq!(record.controls.hold_ref.as_deref(), Some("3"));
    // The amount: the line the sweep posted was the estimated zero under the kernel's own class,
    // which the record does not name, and the money it moved is that zero.
    assert!(
        record.usage.lines.is_empty(),
        "a record names no money-class line: {:?}",
        record.usage.lines
    );
    let settled: i128 = durability
        .ledger
        .book()
        .iter()
        .map(|(_, totals)| totals.settled)
        .sum();
    assert_eq!(
        settled,
        record
            .usage
            .lines
            .iter()
            .map(|l| i128::from(l.quantity))
            .sum::<i128>(),
        "the record's amount equals the money its line moved"
    );
    assert!(durability.retained_audit_findings().is_empty());
    // It reads back off the journal, as the next boot reads it.
    let replayed = durability
        .journal
        .replay()
        .expect("reads back")
        .expect("verifies");
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

/// Q128 p29#5: NO UNIT SETTLES WITH ZERO AUDIT RECORDS. Every unit the sweep settles has its one
/// record on the chain, one each, so the book's lines and the chain's records count the same units.
///
/// RED before the fix: the swept units posted their lines and sealed nothing.
// PORT of `crates/busbar/src/root/tests/plane_node.rs::no_swept_unit_settles_with_zero_audit_records`, verbatim: it names no plane.
#[test]
fn no_swept_unit_settles_with_zero_audit_records() {
    let (node, book) = swept_node();
    let keys = [UnitKey::new(61), UnitKey::new(62), UnitKey::new(63)];
    for key in keys {
        lose_a_unit(&node, key, "widget_call", None);
    }
    assert_eq!(node.sweep(Arrived::at(EPOCH * 1_000 + 5, 99)), keys.len());

    let durability = book.lock().unwrap_or_else(|p| p.into_inner());
    let replayed = durability
        .journal
        .replay()
        .expect("reads back")
        .expect("verifies");
    assert_eq!(
        replayed
            .iter()
            .filter(|r| r.class == busbar_kernel_wal::RecordClass::Transaction)
            .count(),
        2 * keys.len(),
        "each swept unit has its posting on the journal and its one record beside it"
    );
    for key in keys {
        assert_eq!(
            durability
                .audit_records
                .iter()
                .filter(|r| r.what.unit_key == key)
                .count(),
            1,
            "unit {key:?} settled and must have exactly one record: {:?}",
            durability.audit_records
        );
    }
    assert_eq!(durability.audit_records.len(), keys.len());
}

// ---------------------------------------------------------------------------------------------
// P2A-books (#71/#43/#42; follows items 126 and 71): THE SECOND BOOK CARRIES THE COUNTS, AND THE
// TWO BOOKS AGREE ON EVERY CLASS CELL
// ---------------------------------------------------------------------------------------------

/// The open class a rerank's search units are ledgered under (the rerank dialect codec's
/// `SEARCH_UNITS_CLASS`, which `record_resp_usage` ledgers verbatim — item 134). Spelled here because
/// this crate does not depend on the codec.
const SEARCH_UNITS: &str = "search_units";

/// The classes the units these tests drive report are DECLARED — what the boot's registration
/// (`register_classes`: the reserved four, the node plane's declared `search_units`) makes true in a
/// real process. The vocabulary is the process's, so registering them again is idempotent.
fn declare_test_classes() {
    let mut registration = crate::root::kernel::new_registration();
    for class in busbar_contract::records::RESERVED_UNITS {
        let _ = registration.key(class);
    }
    let _ = registration.key(SEARCH_UNITS);
}

/// Run the late arm's posting for one drained `report` onto a fresh node book, and hand the book
/// back.
fn late_post(
    history: &crate::root::kernel::PinnedHistory,
    at: Arrived,
    principal: &str,
    report: &Report,
) -> crate::root::durability::NodeBook {
    declare_test_classes();
    // The book prices its chain against the same history the arm priced the unit against.
    let pinned = history.clone();
    let node = crate::root::durability::node_book_over(Box::new(move || Some(pinned.clone())));
    let kernel = Kernel::new();
    let (durability, ledger, usage) = (
        kernel.durability_token(),
        kernel.ledger_token(),
        kernel.usage_token(),
    );
    post_late(
        &crate::root::durability::SharedBook::over(Arc::clone(&node.durability)),
        &LateTokens {
            durability: &durability,
            ledger: &ledger,
            usage: &usage,
        },
        history,
        &PrincipalId::new(principal),
        at,
        report,
        None,
    );
    node
}

/// The unit records the second book's chain holds (settlements and counts rows), read back off the
/// journal — each with the figure the book derives from its counts at its epoch (the chain itself
/// holds no money, #71).
fn second_book_rows(
    node: &crate::root::durability::NodeBook,
) -> Vec<crate::root::durability::Posting> {
    let durability = node.durability.lock().expect("unpoisoned");
    durability
        .read_back()
        .into_iter()
        // The overdraft CARRY beside a late settlement repeats its unreserved part and carries no
        // counts; it is the same unit's second record, not a second unit.
        .filter(|p| p.kind != crate::root::durability::PostingKind::Carry)
        .collect()
}

/// THE GOVERNANCE LEDGER'S ROW for one unit — the invoice's facts: the class map the tap ledgers
/// VERBATIM (`meter_ledger`; for a rerank `record_resp_usage` ledgers `{search_units: n}`), the
/// serving lane, and the billable count the fee is charged on.
fn governance_row(report: &Report) -> crate::root::durability::UnitCounts {
    crate::root::durability::UnitCounts {
        lane: report.lane.clone(),
        fee_count: u64::from(report.fee_count),
        classes: report
            .usage
            .usage_units
            .iter()
            .filter(|(_, count)| **count > 0)
            .map(|(class, count)| (class.clone(), *count))
            .collect(),
    }
}

/// **THE AGREEMENT CHECK, EVERY CLASS CELL** — the second book's record of one unit against the
/// governance ledger's, cell by cell over the UNION of their classes (reserved and open alike), the
/// lane and the fee count; then the money: the invoice is the one function over the governance row
/// at the unit's arrival (`price_exact`, which every served read prices through), and the second
/// book must hold that figure as a settlement — or, where the invoice is nothing or REFUSES, a
/// counts row with no figure (a refused one where it refuses). `Err` names every cell that differs.
///
/// 21f725601's comparator priced the TOKEN cells alone (`UsageBreakdown`), so a class outside the
/// reserved four could differ between the books and both sides of it would still read equal.
fn every_cell_agrees(
    label: &str,
    second: &[crate::root::durability::Posting],
    governance: &crate::root::durability::UnitCounts,
    history: &crate::root::kernel::PinnedHistory,
    arrived_ms: u64,
) -> Result<(), String> {
    use crate::root::durability::PostingKind;
    let [row] = second else {
        return Err(format!(
            "{label}: the second book holds {} records for one unit, not one",
            second.len()
        ));
    };
    let Some(counts) = row.counts.as_ref() else {
        return Err(format!(
            "{label}: the second book's record carries no counts"
        ));
    };
    let mut cells = Vec::new();
    let classes: std::collections::BTreeSet<&String> = counts
        .classes
        .keys()
        .chain(governance.classes.keys())
        .collect();
    for class in classes {
        let (second_book, invoice) = (counts.classes.get(class), governance.classes.get(class));
        if second_book != invoice {
            cells.push(format!(
                "class {class}: second book {second_book:?}, governance ledger {invoice:?}"
            ));
        }
    }
    if counts.lane != governance.lane {
        cells.push(format!("lane: {:?} vs {:?}", counts.lane, governance.lane));
    }
    if counts.fee_count != governance.fee_count {
        cells.push(format!(
            "fee count: {} vs {}",
            counts.fee_count, governance.fee_count
        ));
    }
    let invoice =
        busbar_kernel_ledger::cost::price_exact(&[governance.entry(arrived_ms)], &history.view())
            .and_then(busbar_kernel_ledger::cost::nanos_of_exact);
    let money_agrees = match (&invoice, row.kind, row.refusal.as_ref()) {
        (Ok(nanos), PostingKind::Settlement, None) => {
            u128::try_from(row.settled).is_ok_and(|settled| settled == *nanos) && *nanos != 0
        }
        (Ok(0), PostingKind::Counted, None) => true,
        (Err(_), PostingKind::Counted, Some(_)) => true,
        _ => false,
    };
    if !money_agrees {
        cells.push(format!(
            "money: second book {:?} settled {} (refusal {:?}), invoice {invoice:?} nano-units",
            row.kind, row.settled, row.refusal
        ));
    }
    if cells.is_empty() {
        Ok(())
    } else {
        Err(format!("{label}: {}", cells.join("; ")))
    }
}

/// A PRESENT card over `"lane"` pricing input 3 / output 16 micro-units, a fee of `fee`, and — when
/// `search_units` is `Some` — the open class `search_units` at that many nano-units per unit
/// (the `units:` grammar, item 123). `None` is a present card SILENT about search units.
fn rerank_history(fee: i64, search_units: Option<u64>) -> crate::root::kernel::PinnedHistory {
    rerank_history_on("lane", fee, search_units)
}

/// [`rerank_history`], over the lane named `lane`.
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

/// A rerank's drained report on `"lane"`: `units` search units and one billable request, no tokens.
fn rerank_report(units: u64) -> Report {
    Report {
        lane: "lane".to_string(),
        ..rerank_report_on(Some(units))
    }
}

/// **AN UNPRICED CLASS ON A PRESENT CARD LEAVES A DURABLE COUNTS ROW, AND THE READ REFUSES**
/// (#71/#43/#42).
///
/// The card prices input and output and is silent about cache reads; the unit read all three. The
/// late arm used to post NO row at all — it warned with the counts and returned, so the second book
/// held nothing for a unit the node served. Now it posts the counts row: every class, whole, with
/// the money UNPRICED (no figure, no zero, no partial), the balance unmoved, and the read over it
/// refusing. Rows posted per refused unit: 0 -> 1.
// PORT of `crates/busbar/src/root/tests/plane_node.rs::an_unpriced_class_on_a_present_card_leaves_a_durable_counts_row_and_the_read_refuses`, verbatim: it names no plane.
#[test]
fn an_unpriced_class_on_a_present_card_leaves_a_durable_counts_row_and_the_read_refuses() {
    use crate::root::durability::PostingKind;
    let history = cache_silent_history();
    let mut report = split_report(1_000, 250, 1);
    report.usage.usage_units.insert(
        busbar_contract::records::UNIT_CACHE_READ.to_string(),
        10_000_000,
    );
    let at = Arrived::at(4_000, 7);
    let node = late_post(&history, at, "vk_refused", &report);

    let rows = second_book_rows(&node);
    assert_eq!(rows.len(), 1, "one counts row per refused unit: {rows:?}");
    let row = &rows[0];
    assert_eq!(row.kind, PostingKind::Counted);
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
        row.refusal
            .as_deref()
            .is_some_and(|why| why.contains("ClassUnpriced") && why.contains("cache_read")),
        "the money is refused and says which class: {:?}",
        row.refusal
    );
    assert_eq!(
        (row.reserved, row.settled, row.overdraft),
        (0, 0, 0),
        "no figure: no zero posted as a price, no partial"
    );

    let durability = node.durability.lock().expect("unpoisoned");
    let key = balance(&PrincipalId::new("vk_refused"));
    let window =
        busbar_kernel::governance::budget_window(busbar_kernel::governance::WINDOW_DAY, at.secs());
    assert_eq!(
        durability.ledger.book().get(&key, window).settled,
        0,
        "a refused unit moves no balance"
    );
    assert!(
        durability.settled_read(&key, window).is_err(),
        "the read over a refused counts row refuses (#42), never the priced remainder"
    );
    assert_eq!(durability.refused_rows().len(), 1);

    // And the two books agree on it cell by cell: the governance read refuses the same class.
    every_cell_agrees(
        "refused",
        &rows,
        &governance_row(&report),
        &history,
        at.ms(),
    )
    .expect("both books refuse the same unit");
}

/// **A RERANK'S SEARCH UNITS AGREE ACROSS BOTH BOOKS** (items 123/134 on the governance ledger; this
/// book now carries and prices them too). Priced: the settlement carries `{search_units: 50}` and
/// the figure the invoice derives from it. A present card silent about search units: both REFUSE.
/// And the 21f725601 token cells, through the every-cell check, still agree.
// PORT of `crates/busbar/src/root/tests/plane_node.rs::a_reranks_search_units_agree_across_both_books`, verbatim: it names no plane.
#[test]
fn a_reranks_search_units_agree_across_both_books() {
    let at = Arrived::at(4_000, 7);
    // 2,000 micro-units = 2,000,000 nano-units per search unit, and a 3-unit fee.
    let priced = rerank_history(3, Some(2_000_000));
    let report = rerank_report(50);
    let node = late_post(&priced, at, "vk_rerank", &report);
    let rows = second_book_rows(&node);
    every_cell_agrees(
        "rerank, priced",
        &rows,
        &governance_row(&report),
        &priced,
        at.ms(),
    )
    .expect("the books agree on the rerank");
    // NON-VACUITY: the search units are in the figure, not only the fee.
    let fee_only = late_post(&priced, at, "vk_fee", &rerank_report(0));
    let fee_only = second_book_rows(&fee_only);
    assert_eq!(
        rows[0].settled - fee_only[0].settled,
        50 * 2_000_000,
        "the second book priced the 50 search units"
    );

    let silent = rerank_history(3, None);
    let node = late_post(&silent, at, "vk_silent", &report);
    let rows = second_book_rows(&node);
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
            .refusal
            .as_deref()
            .is_some_and(|w| w.contains(SEARCH_UNITS)),
        "{:?}",
        rows[0].refusal
    );

    // The token cells of 21f725601, every class cell compared.
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
        let node = late_post(&billed, at, "vk_tokens", &report);
        if let Err(e) = every_cell_agrees(
            label,
            &second_book_rows(&node),
            &governance_row(&report),
            &billed,
            at_ms,
        ) {
            failures.push(e);
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// **A PLANTED OPEN-CLASS DIVERGENCE GOES RED.** The second book's rerank row, planted three ways —
/// the open class under-counted, the open class dropped, and the figure priced without it (the
/// shape this book had: fee only, no counts) — each is named by the every-cell check.
// PORT of `crates/busbar/src/root/tests/plane_node.rs::a_planted_open_class_divergence_goes_red`, verbatim: it names no plane.
#[test]
fn a_planted_open_class_divergence_goes_red() {
    let at = Arrived::at(4_000, 7);
    let priced = rerank_history(3, Some(2_000_000));
    let report = rerank_report(50);
    let governance = governance_row(&report);
    let rows = second_book_rows(&late_post(&priced, at, "vk_rerank", &report));
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

    // The pre-change second book: priced at the fee alone, with no counts on the record.
    let fee_only = second_book_rows(&late_post(&priced, at, "vk_fee", &rerank_report(0)));
    let mut head_shaped = rows.clone();
    head_shaped[0].settled = fee_only[0].settled;
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

/// The serving lane of the served-rerank fixture: a Cohere lane, the one dialect whose rerank reader
/// reads `meta.billed_units.search_units`.
const RERANK_LANE: &str = "rerank-v3.5";

/// The search units the scripted Cohere upstream bills.
const RERANK_UNITS: u64 = 50;

/// **THE NODE PLANE'S BOOK BINDING JOURNALS THE APPLIED CARDS** (#79): a build with this plane and no
/// admin surface binds the dated rate-card history to the book here or nowhere, so a card applied
/// after the boot must land on the chain through this binding alone. Before, only the admin
/// assembly bound it: this plane's node settled onto the book while every live apply stayed in
/// memory, and a restart repriced the node's postings at the boot card.
// PORT of `crates/busbar/src/root/tests/plane_node.rs::binding_the_node_to_the_book_journals_every_card_applied_after_it`, verbatim: it names no plane.
#[test]
fn binding_the_node_to_the_book_journals_every_card_applied_after_it() {
    use crate::root::kernel::{CardApplied, RootHistory};
    fn apply(holder: &RootHistory, input: f64, at: u64) {
        let lanes = [(
            "gpt".to_string(),
            busbar_contract::billing::RawTierRates {
                input: busbar_kernel_ledger::cost::representable_nano_rate(input),
                output: busbar_kernel_ledger::cost::representable_nano_rate(0.0),
                cache_read: busbar_kernel_ledger::cost::representable_nano_rate(0.0),
                cache_write: busbar_kernel_ledger::cost::representable_nano_rate(0.0),
            },
        )];
        let _ = holder.apply_rates(
            &busbar_kernel::rate_apply::RawRates {
                lanes: &lanes,
                units: &[],
                flat_minor: 0,
                present: true,
                plane_fees: &busbar_kernel::config::PlaneFeesMap::new(),
            },
            at,
        );
    }
    let dir = std::env::temp_dir().join(format!(
        "busbar-node-book-cards-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch directory");

    // The production boot's holder: armed, resolved at boot, its history rebuilt by the book.
    let holder: &'static RootHistory = Box::leak(Box::default());
    holder.arm_journal();
    apply(holder, 3.0, 1_000);
    let book = Arc::new(Mutex::new(
        crate::root::durability::build_with_cards(
            &crate::root::durability::DurabilityConfig {
                data_dir: Some(dir.clone()),
            },
            7,
            Box::new(busbar_kernel_wal::NullShipper::new()),
            Box::new(busbar_kernel_ledger::legacy::RecordingRows::new()),
            Box::new(move || holder.pin()),
            Some(holder),
        )
        .expect("the journal opens"),
    ));

    // THE NODE PLANE'S BINDING, and nothing else — no admin assembly.
    super::bind_node_book(&Node::new(), holder, Arc::clone(&book));
    apply(holder, 5.0, 20_000);

    let cards = book
        .lock()
        .expect("the book")
        .journal
        .replay()
        .expect("reads")
        .expect("verifies")
        .iter()
        .filter(|r| r.class == busbar_kernel_wal::RecordClass::Policy)
        .filter_map(|r| CardApplied::from_body(&r.body))
        .map(|applied| applied.effective_from)
        .collect::<Vec<_>>();
    assert_eq!(
        cards,
        vec![0, 20_000],
        "the boot card and the card applied after the binding are both on the chain"
    );
    drop(book);
    let _ = std::fs::remove_dir_all(&dir);
}

/// ONE LINE PER UNIT, WHEN THE LATE READING NEVER ARRIVES (KERNEL<>PLUGINS step 14).
///
/// The exit hands its posting to the late arm and writes none itself. A body that drains with no
/// reading behind it (the tap never filled) must still leave the unit's line: the exit's own
/// posting, written by the arm, closing the reservation. An arm that dropped it would leave the
/// unit with no line at all.
// PORT of `crates/busbar/src/root/tests/plane_node.rs::a_late_arm_with_no_reading_writes_the_exits_own_line`, verbatim: it names no plane.
#[test]
fn a_late_arm_with_no_reading_writes_the_exits_own_line() {
    let history = rerank_history_on(RERANK_LANE, 3, Some(2_000_000));
    let pinned = history.clone();
    let book = crate::root::durability::node_book_over(Box::new(move || Some(pinned.clone())));
    let kernel = Kernel::new();
    let who = PrincipalId::new("acct:late-none");
    let hold = busbar_contract::caps::Hold::open(&kernel.admit_token(), who.clone(), 0);
    let usage = busbar_contract::caps::Usage::report(&kernel.usage_token(), Vec::new())
        .expect("an empty report fits");
    let exit = busbar_contract::caps::Posted::settle(hold, 0, &usage, &kernel.ledger_token());
    let arm = LateAccrual {
        book: Arc::clone(&book.durability),
        history,
        durability_token: kernel.durability_token(),
        ledger_token: kernel.ledger_token(),
        usage_token: kernel.usage_token(),
        principal: who,
        arrived: Arrived::at(EPOCH * 1_000, 3),
        late: Box::new(|| None),
        exit: Some(exit),
        outcome: None,
        seal: None,
    };
    arm.post();
    let rows = second_book_rows(&book);
    assert_eq!(rows.len(), 1, "the unit keeps its one line: {rows:?}");
    assert_eq!(
        rows[0].kind,
        crate::root::durability::PostingKind::Settlement,
        "and it is the exit's settlement: {rows:?}"
    );
    assert_eq!(rows[0].settled, 0);
}

/// **A CLASS NO PLANE DECLARED IS REFUSED FAIL-CLOSED, NEVER BILLED AT ZERO**
/// (`BUSBAR-1.6.0.md` §7). The unit read 1,000 input tokens and 40 units of a class nothing
/// declares or configures. The line is still written with EVERY count, its money is refused
/// (`UndeclaredClass`), no balance moves, and the read over it refuses — even on a card that prices
/// input.
// PORT of `crates/busbar/src/root/tests/plane_node.rs::a_class_no_plane_declared_is_refused_and_keeps_its_counts`, verbatim: it names no plane.
#[test]
fn a_class_no_plane_declared_is_refused_and_keeps_its_counts() {
    let history = cache_silent_history();
    let mut report = split_report(1_000, 0, 1);
    report
        .usage
        .usage_units
        .insert("units_nobody_declared".to_string(), 40);
    let at = Arrived::at(4_000, 7);
    let node = late_post(&history, at, "vk_undeclared", &report);

    let rows = second_book_rows(&node);
    assert_eq!(rows.len(), 1, "one line per unit: {rows:?}");
    let row = &rows[0];
    let counts = row.counts.as_ref().expect("the line carries the counts");
    assert_eq!(counts.classes.get("units_nobody_declared"), Some(&40));
    assert_eq!(
        counts.classes.get(busbar_contract::records::UNIT_INPUT),
        Some(&1_000)
    );
    assert!(
        row.refusal.as_deref().is_some_and(
            |why| why.contains("UndeclaredClass") && why.contains("units_nobody_declared")
        ),
        "the money is refused and names the class: {:?}",
        row.refusal
    );
    assert_eq!((row.reserved, row.settled, row.overdraft), (0, 0, 0));
    let durability = node.durability.lock().expect("unpoisoned");
    let key = balance(&PrincipalId::new("vk_undeclared"));
    let window =
        busbar_kernel::governance::budget_window(busbar_kernel::governance::WINDOW_DAY, at.secs());
    assert_eq!(durability.ledger.book().get(&key, window).settled, 0);
    assert!(durability.settled_read(&key, window).is_err());
    drop(durability);

    // And on a node with NO card, where a declared class would post at nothing, the undeclared one
    // is still refused — the written line and every replay of it (`read_back` re-derives the chain).
    let absent = fee_history_of(&[(0, 0.0, 0.0, 0)], false);
    let node = late_post(&absent, at, "vk_undeclared_absent", &report);
    let rows = second_book_rows(&node);
    assert_eq!(rows.len(), 1, "one line per unit: {rows:?}");
    assert!(
        rows[0]
            .refusal
            .as_deref()
            .is_some_and(|why| why.contains("UndeclaredClass")),
        "never billed at zero, and a replay keeps the refusal: {:?}",
        rows[0].refusal
    );
}

/// **A DECLARED OPEN CLASS ON AN ABSENT CARD IS NOT REFUSED** — 1.5.5's billing-off shape is
/// unchanged: a rerank's declared `search_units` on a node with no card posts its counts row at
/// nothing, with no refusal, exactly as before the undeclared-class rule.
// PORT of `crates/busbar/src/root/tests/plane_node.rs::a_declared_open_class_on_an_absent_card_posts_its_counts_unrefused`, verbatim: it names no plane.
#[test]
fn a_declared_open_class_on_an_absent_card_posts_its_counts_unrefused() {
    let absent = fee_history_of(&[(0, 0.0, 0.0, 0)], false);
    let mut report = split_report(0, 0, 0);
    report
        .usage
        .usage_units
        .insert(SEARCH_UNITS.to_string(), 50);
    let node = late_post(&absent, Arrived::at(4_000, 7), "vk_absent", &report);
    let rows = second_book_rows(&node);
    assert_eq!(rows.len(), 1, "one line per unit: {rows:?}");
    assert_eq!(rows[0].refusal, None, "a declared class is never refused");
    assert_eq!(
        rows[0]
            .counts
            .as_ref()
            .and_then(|c| c.classes.get(SEARCH_UNITS)),
        Some(&50)
    );
}

/// THE WALK'S DISPATCH RECORD, ON THE BOOK (ARCHITECT P3 (c), 2026-10-02): a write-ahead record the
/// egress walk makes for a unit whose facts are open is written onto the node's book under that
/// unit's balance, window and arrival before the dial; one for a unit with no open facts is refused,
/// so its dial never happens.
// PORT of `crates/busbar/src/root/tests/plane_node.rs::a_dispatch_record_is_written_on_the_book_under_its_units_facts`, verbatim: it names no plane.
#[test]
fn a_dispatch_record_is_written_on_the_book_under_its_units_facts() {
    use busbar_kernel_egress::ports::{Dispatched, DurabilityUnavailable, Journal};
    let (node, book) = swept_node();
    let node = Arc::new(node);
    let written = || {
        book.lock()
            .unwrap_or_else(|p| p.into_inner())
            .journal
            .replay()
            .expect("reads back")
            .expect("verifies")
            .len()
    };
    let site = NodeEndPost::new(Arc::clone(&node));
    let record = |unit: u64| Dispatched {
        leg: 0,
        attempt: 1,
        pool: String::new(),
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
    let before = written();
    assert_eq!(site.dispatched(&record(51)), Ok(()));
    assert_eq!(written(), before + 1, "the dispatch is on the book");
    assert_eq!(
        site.dispatched(&record(52)),
        Err(DurabilityUnavailable),
        "no open facts, no record, no dial"
    );
    assert_eq!(written(), before + 1);
    site.close(UnitKey::new(51));
}

/// THE RECORD'S AMOUNT IS COUNTS AND A CARD VERSION, NEVER A PRICE (`BUSBAR-1.6.0.md` THE DESIGN
/// §1, "The amount is the unit's counts plus the rate-card version, never a price"; §7).
///
/// A unit whose exit settles a non-zero figure (the settlement writer's money, in nano-units) seals
/// its record beside that line. The record names what the unit reported, by class; the exit's
/// posting carries no class and no count, only the figure it moved, so the record it seals has no
/// line of it at all.
// PORT of `crates/busbar/src/root/tests/plane_node.rs::the_exit_arm_seals_no_money_figure_into_the_record`, verbatim: it names no plane.
#[test]
fn the_exit_arm_seals_no_money_figure_into_the_record() {
    use busbar_contract::caps::{Admittance, Hold, Posted, Usage, WriteMoney};
    use busbar_kernel::test_support::tokens::{end, grant, origin, pass};

    let (node, book) = swept_node();

    // The figure the settlement writer moved: 150 nano-units against a hold of 100.
    const MONEY: u64 = 150;
    let who = PrincipalId::new("acct:h2");
    let hold = Hold::open(&grant::<Admittance>(), who.clone(), 100);
    let usage = Usage::report(&grant::<busbar_contract::caps::Consumption>(), Vec::new())
        .expect("an empty report fits the record");
    let posted = Posted::settle(hold, u128::from(MONEY), &usage, &grant::<WriteMoney>());
    assert_eq!(posted.settled(), MONEY, "the posting moved money");
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
    node.settle_end(&who, Arrived::at(EPOCH * 1_000, 0), None, ended, Some(seal));

    let durability = book.lock().unwrap_or_else(|p| p.into_inner());
    let record = durability
        .audit_records
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

// ---------------------------------------------------------------------------------------------
// THE DOOR PATH: a unit driven through `Node::drive_borrowed`, as `root::serve` drives a door unit
// ---------------------------------------------------------------------------------------------

/// Whose unit every door cell below drives.
const PRINCIPAL: &str = "acct:door";

/// The one destination Verify seals for a door unit.
const DESTINATION: &str = "door-dest";

/// A DOOR UNIT OF THE TEST'S OWN: every seat proceeds (its door at a zero hold, as a door plane's
/// is), its Route leg answers at once, and its record is sealed under [`DoorUnit::op_class`]. It
/// can be told to refuse at Decode or to screen itself out before the door, and it notes whether
/// its first seat and its admission seat were ever reached.
struct DoorUnit {
    /// Refuse at Decode with this reason: a request the unit cannot read.
    decode_refusal: Option<ReasonCode>,
    /// Screen the unit out before the door with this reason (SEAM-4j).
    screen: Option<ReasonCode>,
    /// The Arrival seat ran.
    reached_arrival: AtomicBool,
    /// The Admit seat (the door) ran.
    reached_admit: AtomicBool,
}

impl DoorUnit {
    fn served() -> Self {
        DoorUnit {
            decode_refusal: None,
            screen: None,
            reached_arrival: AtomicBool::new(false),
            reached_admit: AtomicBool::new(false),
        }
    }

    fn refused_at_decode() -> Self {
        DoorUnit {
            decode_refusal: Some(ReasonCode::DecodeFailed),
            ..DoorUnit::served()
        }
    }

    fn screened_by(reason: ReasonCode) -> Self {
        DoorUnit {
            screen: Some(reason),
            ..DoorUnit::served()
        }
    }

    fn op_class() -> OpClassId {
        OpClassId::new("call")
    }
}

impl busbar_kernel::teller::DoorSeats for DoorUnit {
    fn arrival(&self, token: &Pass<Arrival>, _ctx: &UnitCtx) -> SeatVerdict<Arrival> {
        self.reached_arrival.store(true, Ordering::SeqCst);
        SeatVerdict::proceed(
            token,
            ArrivalRecord {
                source: String::new(),
                port: 0,
                alpn: None,
                sni: None,
                peer_cert: None,
                transport_chain: Vec::new(),
            },
        )
    }

    fn decode(&self, token: &Pass<Decode>, _ctx: &UnitCtx) -> SeatVerdict<Decode> {
        match self.decode_refusal {
            Some(reason) => SeatVerdict::refuse(token, Refusal::new(reason)),
            None => SeatVerdict::proceed(token, Self::op_class()),
        }
    }

    fn authenticate(
        &self,
        token: &Pass<Authenticate>,
        _ctx: &UnitCtx,
    ) -> SeatVerdict<Authenticate> {
        SeatVerdict::proceed(token, Authenticated::Principal(PrincipalId::new(PRINCIPAL)))
    }

    fn verify(
        &self,
        token: &Pass<Verify>,
        trust: &Grant<Dial>,
        _ctx: &UnitCtx,
        _principal: &PrincipalId,
    ) -> SeatVerdict<Verify> {
        SeatVerdict::proceed(
            token,
            vec![VerifiedDestination::seal(trust, LaneId::new(DESTINATION))],
        )
    }

    fn approve(
        &self,
        token: &Pass<Approve>,
        _ctx: &UnitCtx,
        _principal: &PrincipalId,
        _destinations: &[VerifiedDestination],
    ) -> SeatVerdict<Approve> {
        SeatVerdict::proceed(token, ScopeFacts::default())
    }

    fn admit(
        &self,
        token: &Pass<Admit>,
        _admit: &Grant<Admittance>,
        _ctx: &UnitCtx,
        _principal: &PrincipalId,
        _destinations: &[VerifiedDestination],
        _leases: &GroupLeaseSlip,
    ) -> SeatVerdict<Admit> {
        self.reached_admit.store(true, Ordering::SeqCst);
        // The arrival hold is the hold the exit settles: a door plane's door opens at zero.
        SeatVerdict::proceed(token, Admission::ZeroHold)
    }
}

impl busbar_kernel::teller::UnitEnds for DoorUnit {
    fn route(
        &self,
        token: &Pass<Route>,
        _ctx: &UnitCtx,
        _destinations: &[VerifiedDestination],
    ) -> SeatVerdict<Route> {
        // Reached through the awaited leg below, never here.
        SeatVerdict::refuse(token, Refusal::new(ReasonCode::TaskLost))
    }

    fn meter(
        &self,
        token: &Pass<Meter>,
        usage: &Grant<Consumption>,
        _ctx: &UnitCtx,
        _provisional: &Outcome,
        _destinations: &[VerifiedDestination],
    ) -> SeatVerdict<Meter> {
        SeatVerdict::proceed(
            token,
            busbar_contract::caps::Usage::report(usage, Vec::new())
                .expect("an empty usage report never overflows"),
        )
    }

    fn audit(&self, token: &Pass<Audit>, _ctx: &UnitCtx, _outcome: &Outcome) -> SeatVerdict<Audit> {
        SeatVerdict::proceed(
            token,
            busbar_contract::caps::AuditFacts {
                op_class: Self::op_class(),
                finish: busbar_contract::FinishClass::Complete,
            },
        )
    }

    fn audit_refused(
        &self,
        token: &Pass<Audit>,
        _ctx: &UnitCtx,
        _refusal: &Refusal,
    ) -> SeatVerdict<Audit> {
        SeatVerdict::proceed(
            token,
            busbar_contract::caps::AuditFacts {
                op_class: Self::op_class(),
                finish: busbar_contract::FinishClass::Error,
            },
        )
    }

    fn encode(
        &self,
        token: &Pass<Encode>,
        _ctx: &UnitCtx,
        _outcome: &Outcome,
    ) -> SeatVerdict<Encode> {
        SeatVerdict::proceed(
            token,
            Frame {
                direction: busbar_contract::Direction::Outbound,
                stream: busbar_contract::StreamId(0),
                bytes: busbar_contract::SlabBytes::new(Arc::from(&b""[..])),
                meta: busbar_contract::FrameMeta::default(),
            },
        )
    }

    fn evidence(&self, _ctx: &UnitCtx) -> Evidence {
        Evidence::default()
    }
}

impl RouteAwait for DoorUnit {
    fn route_leg<'a>(
        &'a self,
        token: &'a Pass<Route>,
        _ctx: &'a UnitCtx,
        _destinations: &'a [VerifiedDestination],
    ) -> RouteLeg<'a> {
        Box::pin(async move { SeatVerdict::proceed(token, RoutePlan::default()) })
    }

    fn abandoned(&self, _ctx: &UnitCtx, _ended: Ended) {}

    fn screen<'a>(&'a self, _ctx: &'a UnitCtx) -> Screen<'a> {
        let screen = self.screen;
        Box::pin(async move {
            match screen {
                Some(reason) => Err(Refusal::new(reason)),
                None => Ok(()),
            }
        })
    }
}

/// A node bound to `book`, and the door's posting site over it (`root::serve` holds one per
/// process: `NodeEndPost::new(node())`).
fn door_node(book: &crate::root::durability::NodeBook) -> (Arc<Node>, NodeEndPost) {
    let node = Arc::new(Node::new());
    node.bind_book(Arc::clone(&book.durability));
    let post = NodeEndPost::new(Arc::clone(&node));
    (node, post)
}

/// ONE DOOR UNIT, through the node's borrowed drive, as `root::serve` drives it: a key from the
/// node's mint, the arrival it charged in, its late reading, the card history pinned at its door.
async fn drive_door(
    node: &Node,
    post: &NodeEndPost,
    unit: &DoorUnit,
    arrived: Arrived,
    late: Late,
    history: Option<crate::root::kernel::PinnedHistory>,
) -> (UnitKey, Option<Outcome>) {
    let key = node.mint();
    let outcome = node
        .drive_borrowed(
            key,
            arrived,
            &PrincipalId::new(PRINCIPAL),
            post,
            unit,
            late,
            history,
            None,
            DoorUnit::op_class(),
        )
        .await;
    (key, outcome)
}

/// A late reading that never arrives (a door unit whose money never opened).
fn no_late() -> Late {
    Box::new(|| None)
}

/// The door's late reading of `report`, as `root::serve`'s `report_of` hands it to the node.
fn late_of(report: Report) -> Late {
    Box::new(move || Some((report.usage, report.fee_count, report.lane)))
}

/// One door unit's END, as the loop seals it: the unit run through the kernel loop in `node`'s
/// table, its record kept on `post` (the borrowed drive's taps), the end handed back unposted.
/// What `plane_node.rs`'s `drive_to_end` did over the handed unit's wrapper, on the door's.
async fn drive_to_end(node: &Node, post: &NodeEndPost) -> Ended {
    let unit = DoorUnit::served();
    let key = node.mint();
    let call = node.kernel.next_call();
    let meter = Arc::new(AccrualMeter::new());
    let hold = busbar_kernel::inflight::arrival_hold(
        &node.kernel,
        &node.door,
        PrincipalId::new(PRINCIPAL),
        call,
    );
    let slot = node
        .inflight
        .insert(busbar_kernel::inflight::Enter {
            key,
            origin: OriginKind::Client,
            session: None,
            admin_listener: false,
            zero_hold_tick: false,
            arrival: hold,
            now: EPOCH * 1_000,
        })
        .expect("the uncapped table takes the unit");
    let ctx = UnitCtx {
        call,
        key,
        origin: OriginKind::Client,
        session: None,
        generation: busbar_kernel::registry::Generation::FIRST,
        admin_listener: false,
        kernel_verb_only: false,
    };
    let ended = busbar_kernel::teller::run_unit_async(
        &node.kernel,
        &unit,
        &ctx,
        busbar_kernel::teller::Run {
            cell: slot.cell(),
            parent: None,
            leases: slot.leases(),
            gauge: &node.gauge,
            canary: &node.canary,
            meter: &meter,
            taps: Some(post),
        },
        &unit,
    )
    .await;
    node.inflight.remove(key);
    ended
}

// PORT of `crates/busbar/src/root/tests/plane_node.rs::a_unit_arriving_at_a_window_boundary_bills_in_the_window_it_arrived_in`,
// onto the door path. The original read the plane's governance metering rows; what the NODE does
// with the arrival it is handed is where its one line lands, so that is asserted, window by window.
/// **A unit that arrives in the last millisecond of a window bills in THAT window.**
///
/// The arrival is placed one millisecond short of a day boundary, the one instant where two clock
/// reads disagree, and the whole unit is run from it through the node's borrowed drive: its hold,
/// its exit and its late line. The line is looked for in the window the unit arrived in, and the
/// next window is checked to be empty, because a charge that leaked forward would land there.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_unit_arriving_at_a_window_boundary_bills_in_the_window_it_arrived_in() {
    use busbar_kernel::governance::{budget_window, SECS_PER_DAY, WINDOW_DAY};
    declare_test_classes();
    // The last SECOND of the day EPOCH falls in, and the last MILLISECOND of that second: a past
    // day, so a figure taken from a fresh clock read lands visibly elsewhere.
    let last = (EPOCH / SECS_PER_DAY + 1) * SECS_PER_DAY - 1;
    let arrived = Arrived::at(last * 1_000 + 999, 0);
    assert_eq!(
        arrived.secs(),
        last,
        "the fixture really is on the last second of a window"
    );
    let window = budget_window(WINDOW_DAY, arrived.secs());
    let next = budget_window(WINDOW_DAY, arrived.secs() + 1);
    assert_ne!(
        window, next,
        "and one second later is a different window, which is what makes this a straddle"
    );

    let history = history_of(&[(0, 1.0)]);
    let pinned = history.clone();
    let book = crate::root::durability::node_book_over(Box::new(move || Some(pinned.clone())));
    let (node, post) = door_node(&book);
    let (_key, outcome) = drive_door(
        &node,
        &post,
        &DoorUnit::served(),
        arrived,
        late_of(report_of(1_000)),
        Some(history),
    )
    .await;
    assert!(outcome.is_some(), "the table took the unit and it ended");

    let rows = second_book_rows(&book);
    assert_eq!(rows.len(), 1, "one line for the one unit: {rows:?}");
    assert_eq!(
        rows[0].window, window,
        "the unit's line lands in the window it arrived in"
    );
    // 1,000 output tokens at 1 micro-unit each.
    assert_eq!(rows[0].settled, 1_000_000);
    let durability = book.durability.lock().expect("unpoisoned");
    let key = balance(&PrincipalId::new(PRINCIPAL));
    assert_eq!(
        durability.ledger.book().get(&key, window).settled,
        1_000_000,
        "the unit's figure is on the book in the window it arrived in"
    );
    let leaked = durability.ledger.book().get(&key, next);
    assert_eq!(
        (
            leaked.settled,
            leaked.open_holds,
            leaked.overdraft_carried_out
        ),
        (0, 0, 0),
        "and nothing leaked into the window the clock was about to roll into"
    );
}

// PORT of `crates/busbar/src/root/tests/plane_node.rs::the_exit_arm_puts_the_loops_posting_on_the_journal`,
// onto the door path: the unit is driven through the borrowed drive onto a bound book, and the
// posting its exit settled is read back off that book's journal.
/// **THE EXIT ARM, END TO END.** The reservation the door opened reaches the journal.
///
/// The loop's exit path is where a hold stops existing, and what it hands back is a POSTING that
/// has moved no balance and left no record until something settles it. This drives the REAL loop
/// through the node's borrowed drive, with no late reading, so the exit arm settles the posting it
/// sealed, and reads that posting back off the journal. The door opens the kernel's hold at zero,
/// so what this proves is not a price: the kernel's record of a unit having run reaches a durable
/// record.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_exit_arm_puts_the_loops_posting_on_the_journal() {
    use busbar_kernel::governance::{budget_window, WINDOW_DAY};
    let book = crate::root::durability::node_book();
    let (node, post) = door_node(&book);
    let (_key, outcome) = drive_door(
        &node,
        &post,
        &DoorUnit::served(),
        Arrived::at(EPOCH * 1_000, 0),
        no_late(),
        None,
    )
    .await;
    assert!(
        outcome.is_some_and(Outcome::is_completed),
        "the exit path settles the unit: {outcome:?}"
    );

    let durability = book.durability.lock().expect("unpoisoned");
    let Ok(Ok(chain)) = durability.journal.replay() else {
        panic!("the node's journal reads back and verifies");
    };
    let postings: Vec<_> = chain
        .iter()
        .filter_map(crate::root::durability::Posting::from_record)
        .collect();
    assert_eq!(postings.len(), 1, "one posting, one record: {postings:?}");
    assert_eq!(
        postings[0].kind,
        crate::root::durability::PostingKind::Settlement,
        "the exit's posting settles the unit's hold"
    );
    assert_eq!(
        postings[0].reserved, 0,
        "this plane's door opens the kernel's hold at zero; the spend is the governance ledger's"
    );
    assert_eq!(postings[0].overdraft, 0, "nothing to carry out");
    let window = budget_window(WINDOW_DAY, EPOCH);
    let figures = durability
        .ledger
        .book()
        .get(&balance(&PrincipalId::new(PRINCIPAL)), window);
    assert_eq!(figures.overdraft_carried_out, 0);
}

// PORT of `crates/busbar/src/root/tests/plane_node.rs::a_driven_planes_abandoned_end_posts_once_onto_the_nodes_book`.
// Each end is the loop's own, sealed over the borrowed drive's wrapper rather than the handed
// unit's; the posting site and every assertion are the original's.
/// A DRIVEN PLANE'S ABANDONED END POSTS ONCE, onto the node's book. The loop's sealed end is handed
/// to the root's posting site under the unit's key: posted once for a unit whose facts are open,
/// never for a unit that closed (returned) or was never opened, and never twice.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_driven_planes_abandoned_end_posts_once_onto_the_nodes_book() {
    use busbar_kernel::plane_driver::EndPost;
    let (node, book) = swept_node();
    let node = Arc::new(node);
    let posted = || {
        book.lock()
            .unwrap_or_else(|p| p.into_inner())
            .journal
            .replay()
            .expect("reads back")
            .expect("verifies")
            .len()
    };
    let site = NodeEndPost::new(Arc::clone(&node));
    let ctx = |key: u64| UnitCtx {
        call: busbar_contract::caps::CallId::UNBOUND,
        key: UnitKey::new(key),
        origin: OriginKind::Client,
        session: None,
        generation: busbar_kernel::registry::Generation::FIRST,
        admin_listener: false,
        kernel_verb_only: false,
    };
    let who = PrincipalId::new("acct:node");
    // Opened, then abandoned: posted once; a second post of the same key posts nothing.
    let ended = drive_to_end(&node, &site).await;
    site.open(
        UnitKey::new(41),
        who.clone(),
        Arrived::at(EPOCH * 1_000, 0),
        None,
    );
    // Counted around each post: driving a unit to its end writes its own records on the book.
    let before = posted();
    site.post(&ctx(41), ended);
    assert!(posted() > before, "the abandoned end is on the book");
    let ended = drive_to_end(&node, &site).await;
    let before = posted();
    site.post(&ctx(41), ended);
    assert_eq!(posted(), before, "an end posts at most once");
    // Opened then closed (the unit returned): the node's exit arm posts it, not this site.
    let ended = drive_to_end(&node, &site).await;
    site.open(UnitKey::new(42), who, Arrived::at(EPOCH * 1_000, 1), None);
    site.close(UnitKey::new(42));
    let before = posted();
    site.post(&ctx(42), ended);
    assert_eq!(posted(), before, "a returned unit's end is not this site's");
    assert_eq!(site.open_units(), 0, "every unit's facts closed");
}

// PORT of `crates/busbar/src/root/tests/plane_node.rs::a_driven_planes_abandoned_end_seals_one_audit_record`.
// Each end is the loop's own, sealed over the borrowed drive's wrapper rather than the handed
// unit's; the posting site and every assertion are the original's.
/// A DRIVEN PLANE'S ABANDONED END SEALS EXACTLY ONE AUDIT RECORD with its one line, from the facts
/// and pass its audit door handed back; an abandoned unit whose audit door never answered seals none.
/// RED: without the held pass the posting site seals no record.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_driven_planes_abandoned_end_seals_one_audit_record() {
    use busbar_kernel::plane_driver::EndPost;
    let (node, book) = swept_node();
    let node = Arc::new(node);
    let records = || {
        book.lock()
            .unwrap_or_else(|p| p.into_inner())
            .audit_records
            .len()
    };
    let site = NodeEndPost::new(Arc::clone(&node));
    let ctx = |key: u64| UnitCtx {
        call: busbar_contract::caps::CallId::UNBOUND,
        key: UnitKey::new(key),
        origin: OriginKind::Client,
        session: None,
        generation: busbar_kernel::registry::Generation::FIRST,
        admin_listener: false,
        kernel_verb_only: false,
    };
    let who = PrincipalId::new("acct:node");
    let facts = busbar_contract::caps::AuditFacts {
        op_class: busbar_contract::caps::OpClassId::new("call"),
        finish: busbar_contract::FinishClass::Complete,
    };
    // The audit door answered: one record, with the line.
    let ended = drive_to_end(&node, &site).await;
    site.open(
        UnitKey::new(51),
        who.clone(),
        Arrived::at(EPOCH * 1_000, 0),
        None,
    );
    site.audited(
        UnitKey::new(51),
        facts,
        busbar_kernel::test_support::tokens::pass(),
    );
    let before = records();
    site.post(&ctx(51), ended);
    assert_eq!(
        records(),
        before + 1,
        "exactly one audit record for the abandoned unit"
    );
    // The audit door never answered: the line is posted, and no record is minted for it.
    let ended = drive_to_end(&node, &site).await;
    site.open(UnitKey::new(52), who, Arrived::at(EPOCH * 1_000, 1), None);
    let before = records();
    site.post(&ctx(52), ended);
    assert_eq!(records(), before, "no pass, no record");
}

// PORT of `crates/busbar/src/root/tests/plane_node.rs::every_unit_the_node_answers_served_or_refused_seals_one_record_on_one_tamper_evident_chain`,
// onto the door path: the served unit and the refused one (a request its Decode cannot read, the
// original's unreadable body) are driven through the borrowed drive; the chain assertions are the
// original's.
/// AUDIT-CHAIN, THE NODE'S DOOR UNITS: every unit the node drives, served (a dispatched completion)
/// or refused (a request it cannot read), seals ONE record on the node's audit chain, the second
/// linked to the first; the chain walks clean, and a record altered after its seal (the served unit
/// re-told as refused) breaks the walk. RED: a loop whose audit door's pass is never handed back to
/// the node seals nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_unit_the_node_answers_served_or_refused_seals_one_record_on_one_tamper_evident_chain(
) {
    let book = crate::root::durability::node_book();
    let (node, post) = door_node(&book);

    let (_, served) = drive_door(
        &node,
        &post,
        &DoorUnit::served(),
        node.arrived(),
        no_late(),
        None,
    )
    .await;
    assert!(
        served.is_some_and(Outcome::is_completed),
        "the completion is served: {served:?}"
    );
    let (_, refused) = drive_door(
        &node,
        &post,
        &DoorUnit::refused_at_decode(),
        node.arrived(),
        no_late(),
        None,
    )
    .await;
    assert!(
        matches!(refused, Some(Outcome::Refused(..))),
        "the unreadable request is refused: {refused:?}"
    );
    assert_eq!(post.open_units(), 0, "both units' facts closed");

    let durability = book.durability.lock().expect("unpoisoned");
    let records = durability.audit_records.clone();
    assert_eq!(records.len(), 2, "one record per unit: {records:?}");
    let (served, refused) = (&records[0], &records[1]);
    assert_eq!(
        served.outcome.unit_end,
        busbar_contract::caps::Outcome::Completed,
        "the dispatch is chained as served"
    );
    assert!(
        matches!(
            refused.outcome.unit_end,
            busbar_contract::caps::Outcome::Refused(..)
        ),
        "the refusal is chained as one: {:?}",
        refused.outcome
    );
    assert_eq!(refused.seq, served.seq + 1, "contiguous");
    assert_eq!(
        refused.prev_hash, served.hash,
        "linked to the record before"
    );
    assert!(busbar_kernel_audit::AuditChain::verify_window(&records).is_ok());
    assert!(
        durability.retained_audit_findings().is_empty(),
        "the node's own verify finds nothing"
    );

    let mut forged = records.clone();
    forged[0].outcome.unit_end = refused.outcome.unit_end;
    assert!(
        busbar_kernel_audit::AuditChain::verify_window(&forged).is_err(),
        "a record altered after its seal breaks the chain"
    );
}

// PORT of `crates/busbar/src/root/tests/plane_node.rs::a_screened_veto_through_the_node_admits_nothing`,
// onto the door path: the unit screens itself out through the borrowed drive's wrapper. The
// original read "nothing admitted" off the plane's governance ledger; here it is read off the door
// seat itself, which the loop never reaches.
/// RED (SEAM-4j through the node): a unit whose route SCREENS it before the door (a gate-first
/// plane's veto) is screened through the node's own wrapper: the unit is refused at Approve's seat
/// with the screen's reason and the door never admits it. RED before: the node's wrapper answered
/// the default screen, the unit was admitted and served.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_screened_veto_through_the_node_admits_nothing() {
    let book = crate::root::durability::node_book();
    let (node, post) = door_node(&book);
    let unit = DoorUnit::screened_by(busbar_contract::caps::ReasonCode::HookVeto);
    let (_, outcome) = drive_door(&node, &post, &unit, node.arrived(), no_late(), None).await;
    assert_eq!(
        outcome,
        Some(Outcome::Refused(
            busbar_contract::caps::StepName::Approve,
            busbar_contract::caps::ReasonCode::HookVeto
        )),
        "refused at the screen, before the door"
    );
    assert!(
        !unit.reached_admit.load(Ordering::SeqCst),
        "a veto admits nothing: the door was never asked"
    );
}

// PORT of `crates/busbar/src/root/tests/plane_node.rs::a_full_journal_lane_refuses_a_new_unit_503_with_the_reason`,
// onto the door path. The book, the full lane and every assertion on the node are the original's;
// the 503 the handed path renders is that path's own answer, and the door's answer is the door's.
/// **A NODE WHOSE JOURNAL CANNOT REACH ITS STORE FAILS CLOSED** (ARCHITECT 2026-10-07 H3 ruling):
/// the book's journal is kept by the configured store, the store refuses and the lane to it is
/// full, so a new money-bearing unit is refused with the reason, before any step of it runs or
/// anything is held or journalled for it, and nothing the journal holds is dropped. A state 1.5.5
/// never reached (it kept no journal).
///
/// RED before the fix: the node admitted the unit and drove it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_journal_lane_refuses_a_new_unit_with_the_reason() {
    let slots = crate::root::store_double::RecordSlots::new();
    slots.refuse(true);
    let lane = crate::root::durability::JournalLane::with_capacity(slots.calls(), "test-store", 1)
        .expect("the lane starts");
    let book = Arc::new(std::sync::Mutex::new(
        crate::root::durability::build_on_store(
            &crate::root::durability::DurabilityConfig { data_dir: None },
            0,
            lane,
            Box::new(busbar_kernel_ledger::legacy::RecordingRows::new()),
            Box::new(|| None),
            None,
        )
        .expect("the store reads back"),
    ));
    let token = busbar_kernel::test_support::tokens::grant::<busbar_contract::caps::DurableWrite>();
    for _ in 0..3 {
        let _lost = book.lock().unwrap().journal.append(
            &token,
            busbar_contract::caps::StepName::Meter,
            &[busbar_kernel_wal::Entry::new(
                busbar_kernel_wal::RecordClass::Load,
                Vec::new(),
            )],
        );
    }
    let node = Arc::new(Node::new());
    node.bind_book(Arc::clone(&book));
    let post = NodeEndPost::new(Arc::clone(&node));
    let unit = DoorUnit::served();
    let (_, outcome) = drive_door(&node, &post, &unit, node.arrived(), no_late(), None).await;
    assert!(
        outcome.is_none(),
        "the node refuses the unit: the table never takes it"
    );
    assert!(
        !unit.reached_arrival.load(Ordering::SeqCst),
        "a refused unit is never driven"
    );
    assert_eq!(post.open_units(), 0, "nothing is held open for it");
    let why = node
        .journal_refusal()
        .expect("the node states why it refuses");
    assert!(
        why.contains("journal is full") && why.contains("`test-store`"),
        "the reason names the full journal and the store: {why}"
    );
    assert_eq!(
        book.lock().unwrap().journal.dropped_total(),
        0,
        "no record is dropped"
    );
}

/// A rerank's late reading on [`RERANK_LANE`]: `units` search units where `Some` (none reported
/// where `None`), and the one billable request a served rerank is.
fn rerank_report_on(units: Option<u64>) -> Report {
    Report {
        usage: busbar_contract::billing::Usage {
            usage_units: units
                .map(|units| (SEARCH_UNITS.to_string(), units))
                .into_iter()
                .collect(),
        },
        fee_count: 1,
        lane: RERANK_LANE.to_string(),
    }
}

/// ONE RERANK DOOR UNIT, through the borrowed drive onto a fresh book over `history`, its late
/// reading `report`: the second book's rows for it.
async fn serve_rerank(
    history: crate::root::kernel::PinnedHistory,
    report: Report,
) -> Vec<crate::root::durability::Posting> {
    declare_test_classes();
    let pinned = history.clone();
    let book = crate::root::durability::node_book_over(Box::new(move || Some(pinned.clone())));
    let (node, post) = door_node(&book);
    let (_key, outcome) = drive_door(
        &node,
        &post,
        &DoorUnit::served(),
        Arrived::at(EPOCH * 1_000, 0),
        late_of(report),
        Some(history),
    )
    .await;
    assert!(
        outcome.is_some_and(Outcome::is_completed),
        "the rerank was served: {outcome:?}"
    );
    second_book_rows(&book)
}

/// The search units the durable book's first row carries.
fn durable_units(rows: &[crate::root::durability::Posting]) -> Option<u64> {
    rows.first()
        .and_then(|row| row.counts.as_ref())
        .and_then(|counts| counts.classes.get(SEARCH_UNITS))
        .copied()
}

// PORT of `crates/busbar/src/root/tests/plane_node.rs::a_served_rerank_puts_identical_search_units_on_both_books`,
// onto the door path: the late reading the door hands the node carries the 50 search units, and
// the node's own late arm writes the unit's one line and seals its record. The governance side is
// the door's reading of the same unit (`governance_row`); the governance ledger the legacy walk
// filled is not the node's to fill.
/// **A SERVED RERANK PUTS IDENTICAL SEARCH UNITS ON BOTH BOOKS** (#71/#43, item 134): the door
/// unit's reading of 50 search units reaches the node's late arm, which settles the unit's ONE
/// line carrying them at the card pinned at its door, and seals the unit's one audit record whose
/// amount is that line's counts.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_served_rerank_puts_identical_search_units_on_both_books() {
    declare_test_classes();
    // 2,000 micro-units per search unit and a 3-unit fee, over the serving lane.
    let history = rerank_history_on(RERANK_LANE, 3, Some(2_000_000));
    let pinned = history.clone();
    let book = crate::root::durability::node_book_over(Box::new(move || Some(pinned.clone())));
    let (node, post) = door_node(&book);
    let report = rerank_report_on(Some(RERANK_UNITS));
    let governance = governance_row(&report);
    // NON-VACUITY: the governance row holds the search units, so an agreement below is an
    // agreement ON them.
    assert_eq!(
        governance.classes.get(SEARCH_UNITS),
        Some(&RERANK_UNITS),
        "the governance row holds the rerank's search units: {governance:?}"
    );
    let arrived = Arrived::at(EPOCH * 1_000, 0);
    let (key_n, outcome) = drive_door(
        &node,
        &post,
        &DoorUnit::served(),
        arrived,
        late_of(report),
        Some(history.clone()),
    )
    .await;
    assert!(
        outcome.is_some_and(Outcome::is_completed),
        "the rerank was served: {outcome:?}"
    );
    assert_eq!(post.open_units(), 0, "its facts closed at its end");

    // THE UNIT'S ONE FIXED AUDIT RECORD, sealed where its one line was written (the late arm): its
    // amount is the line's counts, and it is sealed under this boot's incarnation.
    {
        let durability = book.durability.lock().expect("unpoisoned");
        assert_eq!(
            durability.audit_records.len(),
            1,
            "one record per unit: {:?}",
            durability.audit_records
        );
        let record = &durability.audit_records[0];
        assert_eq!(record.what.unit_key, key_n);
        assert_eq!(record.what.incarnation, durability.incarnation);
        assert_eq!(
            record.outcome.unit_end,
            busbar_contract::caps::Outcome::Completed
        );
        assert!(
            record
                .usage
                .lines
                .iter()
                .any(|l| l.class.as_str() == SEARCH_UNITS && l.quantity == RERANK_UNITS),
            "the record's amount is the line's counts: {:?}",
            record.usage.lines
        );
        assert!(durability.retained_audit_findings().is_empty());
    }

    // THE SECOND BOOK: the late arm's row, and it is the unit's ONLY line (KERNEL<>PLUGINS step
    // 14): the exit wrote none, and the one line is a settlement carrying the counts.
    let rows = second_book_rows(&book);
    assert_eq!(
        rows.len(),
        1,
        "one line per unit: the exit writes none when the late arm writes it: {rows:?}"
    );
    assert_eq!(
        rows[0].kind,
        crate::root::durability::PostingKind::Settlement,
        "the one line settles the unit's reservation: {rows:?}"
    );
    assert_eq!(
        durable_units(&rows),
        Some(RERANK_UNITS),
        "the durable book's row carries the rerank's search units: {rows:?}"
    );
    every_cell_agrees("served rerank", &rows, &governance, &history, arrived.ms())
        .expect("both books hold the same search units and the same figure");
}

// PORT of `crates/busbar/src/root/tests/plane_node.rs::a_reranks_search_units_reach_the_price_on_both_books`,
// onto the door path: the node's half, every arm. The durable book's figures and its every-cell
// agreement are the original's, nano-unit for nano-unit; the cents the governance read derives
// (10 and 0, the silent card's refusal, billing off reading 0) are the governance read's, not the
// node's.
/// A RERANK'S SEARCH UNITS REACH THE PRICE, ON THE DURABLE BOOK (item 134; #42's three arms): a
/// card pricing `search_units` at 2,000 micro-units each settles 50 x and 1 x 2,000,000 nano-units
/// for 50 and 1 units; a present card silent about `search_units` REFUSES the line, naming the
/// class, never a silent 0; no card (billing off) keeps the counts with no figure. Every arm
/// agrees cell by cell with the unit's governance row.
///
/// RED: the search units dropped or priced as a flat request, a silent card read as 0, billing off
/// charging, or the two books disagreeing on any arm.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reranks_search_units_reach_the_price_on_both_books() {
    let at = EPOCH * 1_000;
    for units in [50_u64, 1] {
        let report = rerank_report_on(Some(units));
        let governance = governance_row(&report);
        let rows = serve_rerank(rerank_history_on(RERANK_LANE, 0, Some(2_000_000)), report).await;
        assert_eq!(
            rows.first().map(|row| row.settled),
            Some(i128::from(units) * 2_000_000),
            "{units} units: the durable book settles them at the card"
        );
        every_cell_agrees(
            "rerank, priced",
            &rows,
            &governance,
            &rerank_history_on(RERANK_LANE, 0, Some(2_000_000)),
            at,
        )
        .expect("both books price the rerank alike");
    }

    let silent = serve_rerank(
        rerank_history_on(RERANK_LANE, 0, None),
        rerank_report_on(Some(50)),
    )
    .await;
    assert!(
        silent
            .first()
            .and_then(|row| row.refusal.as_deref())
            .is_some_and(|why| why.contains(SEARCH_UNITS)),
        "the durable book refuses the class a present card is silent about: {silent:?}"
    );

    let absent = crate::root::kernel::PinnedHistory::for_test(
        Arc::new(busbar_kernel_ledger::cost::History::opening(
            crate::root::kernel::card_from_config(
                std::iter::empty::<(&str, busbar_contract::billing::RawTierRates)>(),
                0,
                false,
            ),
            0,
        )),
        busbar_kernel_ledger::cost::HistorySeq(0),
    );
    let report = rerank_report_on(Some(50));
    let governance = governance_row(&report);
    let off = serve_rerank(absent.clone(), report).await;
    assert_eq!(
        durable_units(&off),
        Some(50),
        "billing off still keeps the counts"
    );
    every_cell_agrees("rerank, billing off", &off, &governance, &absent, at)
        .expect("both books read the rerank at nothing with billing off");
}

// PORT of `crates/busbar/src/root/tests/plane_node.rs::a_same_dialect_rerank_puts_identical_search_units_on_both_books`,
// onto the door path: the node's half. Whether a dialect's relay keeps the far end's units is the
// plane's; what the node books from the reading it is handed is asserted here.
/// A RERANK'S SEARCH UNITS ARE BOOKED AS REPORTED (Q29, item 134): a door reading of 50 search
/// units leaves 50 on the durable book's row; a reading that bills none books none.
///
/// RED: a late arm that drops the open class, or books a count nobody reported.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_same_dialect_rerank_puts_identical_search_units_on_both_books() {
    let history = || rerank_history_on(RERANK_LANE, 3, Some(2_000_000));
    let billed = serve_rerank(history(), rerank_report_on(Some(RERANK_UNITS))).await;
    assert_eq!(
        durable_units(&billed),
        Some(RERANK_UNITS),
        "the durable book holds the rerank's search units"
    );
    let unbilled = serve_rerank(history(), rerank_report_on(None)).await;
    assert_eq!(durable_units(&unbilled), None, "no units, none booked");
}
