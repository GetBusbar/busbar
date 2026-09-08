//! Tests for `ledger_identity.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;

use busbar_caps::{Admit, AdmitToken};
use busbar_caps::{Hold, LedgerToken, Usage, UsageToken};
use busbar_caps::{KernelSeal, MeterClassId, PrincipalId, QuantitySource, UsageLine};
use busbar_unit_cost::{
    derive_spend_micros, price, CurrencyCode, History, LaneClass, Posting, RateCard,
    STANDARD_TIER_BP,
};
use busbar_unit_ledger::legacy::{LegacyRows, RecordingRows};
use busbar_unit_ledger::settle::Ledger;
use busbar_unit_ledger::totals::{BucketId, BucketScope, CapDimension, TotalsKey};

/// The day every synthetic settlement falls in. One day, because the identity is per row and a
/// second day would only widen the fixture without widening what is checked.
const DAY: u64 = 1_767_225_600;
/// The same instant in the milliseconds the history resolves at.
const DAY_MS: u64 = DAY * 1_000;
/// Halfway through it — the instant a mid-window entry becomes effective.
const MID_MS: u64 = DAY_MS + 12 * 60 * 60 * 1_000;
/// One settlement's instant: an hour apart, so the first eight fall before the mid-window entry
/// and the rest after it.
///
/// Spread rather than all at zero, and that is not decoration: with every posting at one instant
/// a lookup that ignored the instant entirely and always took the newest entry would answer
/// identically, and the whole claim of this module is that a line is priced at the card in force
/// when it was EARNED.
fn arrived_ms(i: usize) -> u64 {
    DAY_MS + (i as u64) * 60 * 60 * 1_000
}
/// The flat fee, in cents. Deliberately not zero: with no fee the count half of the identity is
/// `0 == 0` on every row and the test would pass with the fee line unimplemented.
const FEE_CENTS: i64 = 3;

/// The three lanes, each with a visibly different price so a row that took the wrong lane's
/// rate is a different number rather than the same one.
fn card() -> RateCard {
    RateCard::from_micro_rates(
        [
            (LaneClass::new("lane-a", "input"), 40.0),
            (LaneClass::new("lane-a", "output"), 90.0),
            (LaneClass::new("lane-b", "input"), 7.0),
            (LaneClass::new("lane-b", "output"), 13.0),
            (LaneClass::new("lane-c", "input"), 1.0),
            (LaneClass::new("lane-c", "output"), 2.0),
        ],
        FEE_CENTS,
    )
}

fn ledger_token() -> LedgerToken {
    LedgerToken::mint(&KernelSeal::acquire_for_kernel())
}

fn admit_token() -> AdmitToken<Admit> {
    AdmitToken::mint(&KernelSeal::acquire_for_kernel())
}

fn usage_token() -> UsageToken {
    UsageToken::mint(&KernelSeal::acquire_for_kernel())
}

fn lines(input: u64, output: u64) -> Vec<UsageLine> {
    [("input", input), ("output", output)]
        .into_iter()
        .map(|(class, quantity)| UsageLine {
            class: MeterClassId::new(class),
            quantity,
            source: QuantitySource::Count,
            estimated: false,
        })
        .collect()
}

fn totals_key(bucket: &str) -> TotalsKey {
    TotalsKey::new(
        BucketId::new(bucket),
        CapDimension::NanoUnits,
        BucketScope::All,
    )
}

/// One synthetic settlement: whose it is, which lane answered, what it used, and whether it
/// carried the flat fee.
struct Settlement {
    bucket: &'static str,
    lane: &'static str,
    provider: &'static str,
    input: u64,
    output: u64,
    billable: bool,
}

/// Sixteen settlements over three buckets, three lanes and two providers, with quantities
/// chosen so several rows carry a nano-unit remainder that only survives if the projection
/// happens once over the row (see the module doc). Two units are non-billable — a nested unit
/// and a tick — so the fee count is not simply the row's posting count.
fn settlements() -> Vec<Settlement> {
    let raw: &[(&'static str, &'static str, &'static str, u64, u64, bool)] = &[
        ("key-1", "lane-a", "prov-x", 11, 7, true),
        ("key-1", "lane-a", "prov-x", 3, 1, true),
        ("key-1", "lane-a", "prov-x", 1, 1, false),
        ("key-1", "lane-b", "prov-y", 11, 7, true),
        ("key-1", "lane-b", "prov-y", 250, 125, true),
        ("key-2", "lane-a", "prov-x", 9, 4, true),
        ("key-2", "lane-c", "prov-y", 1, 1, true),
        ("key-2", "lane-c", "prov-y", 1, 1, true),
        ("key-2", "lane-c", "prov-y", 1, 1, true),
        ("key-2", "lane-c", "prov-y", 1, 1, false),
        ("key-3", "lane-b", "prov-x", 40_000, 20_000, true),
        ("key-3", "lane-b", "prov-x", 17, 3, true),
        ("key-3", "lane-c", "prov-x", 0, 0, true),
        ("key-3", "lane-c", "prov-x", 5, 0, true),
        ("key-3", "lane-a", "prov-y", 2, 2, true),
        ("key-3", "lane-a", "prov-y", 6, 6, true),
    ];
    raw.iter()
        .map(
            |(bucket, lane, provider, input, output, billable)| Settlement {
                bucket,
                lane,
                provider,
                input: *input,
                output: *output,
                billable: *billable,
            },
        )
        .collect()
}

/// Drive every settlement through BOTH paths and return the two snapshots plus the rows the
/// dual write produced.
///
/// The two paths are genuinely two implementations of the same law and that is the whole value
/// of the test. The ledger side prices each unit with `price` — per-line amounts, the fee as a
/// line of its own, one tier divide over the sum — and stores the nano-units. The legacy side
/// runs the previous release's read-time derivation over the row's accumulated quantities, which
/// sums nano-units across the row and adds the fee afterwards. They are not the same code and
/// they do not have the same shape; the identity is the claim that they land on the same
/// number, and nothing but running both of them proves it.
fn drive(
    settlements: &[Settlement],
    drop_posting: Option<usize>,
) -> (
    LedgerSnapshot,
    LegacySnapshot,
    Vec<busbar_unit_ledger::legacy::LegacyPosting>,
) {
    // The card, as the migration seals it: a SINGLE-ENTRY history effective from instant zero,
    // so `card_at` resolves to that entry for every posting and the lookup is arithmetically
    // the pinned card it replaces.
    let history = History::opening(card(), 0);
    let view = history.current();
    let rows = RecordingRows::new();
    let mut ledger = Ledger::dual_writing(Box::new(rows.clone()) as Box<dyn LegacyRows>);
    let token = ledger_token();

    let mut ledger_snapshot = LedgerSnapshot::new();
    // The legacy side accumulates RAW quantities per row and derives money once, at the end,
    // exactly as the previous release's usage projection does.
    let mut legacy_units: BTreeMap<RowKey, (u64, u64, u64)> = BTreeMap::new();

    for (i, s) in settlements.iter().enumerate() {
        let row = RowKey::new(s.bucket, DAY, s.lane, s.provider);
        let usage = Usage::report(&usage_token(), lines(s.input, s.output))
            .expect("the usage report is within the line limit");
        let fee_count = u64::from(s.billable);
        let quantities = Posting::from_usage(
            s.lane,
            &usage,
            fee_count,
            STANDARD_TIER_BP,
            arrived_ms(i),
            i as u64,
        );
        let posting = price(&view, &quantities, CurrencyCode::USD)
            .expect("the opening entry covers instant zero and names USD");

        // The books move whatever the snapshot does: the red proof below drops a posting from
        // what the CHECK sees, not from what the ledger did, because the defect it stands in
        // for is a reconciliation that missed a posting and not a settlement that never
        // happened.
        let reserved = posting.priced_nanos.min(u128::from(u64::MAX)) as u64;
        ledger.record_draw(&totals_key(s.bucket), DAY, i128::from(reserved));
        ledger.record_hold_opened(&totals_key(s.bucket), DAY, reserved);
        ledger.record_slice_spent(&totals_key(s.bucket), DAY, i128::from(reserved));
        // The priced amount is what settles, and the report is what it was priced FROM: the
        // lines here are raw token counts and their sum is not money at all. The legacy row
        // accumulator below is the one place that still adds the raw quantities up, which is
        // exactly where the previous release added them.
        ledger.settle(
            &totals_key(s.bucket),
            DAY,
            Hold::open(&admit_token(), PrincipalId::new(s.bucket), reserved),
            posting.priced_nanos,
            &usage,
            &token,
        );

        if drop_posting != Some(i) {
            accumulate(&mut ledger_snapshot, row.clone(), &posting);
        }
        let e = legacy_units.entry(row).or_default();
        e.0 += s.input;
        e.1 += s.output;
        e.2 += fee_count;
    }

    let legacy_snapshot: LegacySnapshot = legacy_units
        .into_iter()
        .map(|(row, (input, output, billable))| {
            let l = super::tests::lines(input, output);
            let spend_micros = derive_spend_micros(
                view.card_at(0)
                    .expect("the opening entry covers instant zero")
                    .1,
                [(row.lane.as_str(), l.as_slice())].into_iter(),
                billable,
                true,
            );
            (
                row,
                LegacyRow {
                    spend_micros,
                    billable_requests: billable,
                },
            )
        })
        .collect();

    (ledger_snapshot, legacy_snapshot, rows.written())
}

/// GREEN: every row the dual write produced carries the figures its posting moved.
///
/// Counting the rows says only that something was written; it says nothing about what. A row
/// carrying zero, or carrying the reservation where the spend goes, would be a parity
/// obligation quietly unmet — and the previous release's readers, which are the whole reason
/// the dual write exists, would be reading a lie that reconciles. So every posting is checked
/// against the settlement it came from, field by field, and the reservations on each row are
/// checked against the same row's money on the ledger side.
#[test]
fn every_dual_written_row_carries_the_figures_its_posting_moved() {
    let s = settlements();
    let (ledger, _legacy, written) = drive(&s, None);
    assert_eq!(
        written.len(),
        s.len(),
        "the dual write must put every settlement onto the previous release's rows"
    );

    // The card, as the migration seals it: a SINGLE-ENTRY history effective from instant zero,
    // so `card_at` resolves to that entry for every posting and the lookup is arithmetically
    // the pinned card it replaces.
    let history = History::opening(card(), 0);
    let view = history.current();
    let mut reserved_per_row: BTreeMap<RowKey, u128> = BTreeMap::new();
    for (i, (posting, settlement)) in written.iter().zip(s.iter()).enumerate() {
        let usage = Usage::report(&usage_token(), lines(settlement.input, settlement.output))
            .expect("the usage report is within the line limit");
        let quantities = Posting::from_usage(
            settlement.lane,
            &usage,
            u64::from(settlement.billable),
            STANDARD_TIER_BP,
            arrived_ms(i),
            i as u64,
        );
        let priced = price(&view, &quantities, CurrencyCode::USD)
            .expect("the opening entry covers instant zero and names USD");
        let reserved = priced.priced_nanos.min(u128::from(u64::MAX)) as u64;

        assert_eq!(
            posting.principal, settlement.bucket,
            "posting {i}: principal"
        );
        assert_eq!(posting.bucket, settlement.bucket, "posting {i}: bucket");
        assert_eq!(posting.window_start, DAY, "posting {i}: window");
        assert_eq!(posting.reserved, reserved, "posting {i}: reservation");
        // What was posted is MONEY: the priced total of the usage the report carried, in the
        // nano-units the hold reserved in. A usage report is not money, so the quantity it
        // said was used is what the posting must NOT read as.
        assert_eq!(
            posting.settled, reserved,
            "posting {i}: the money the usage priced at"
        );
        assert_ne!(
            posting.settled,
            settlement.input + settlement.output,
            "posting {i}: the fixture must price a unit at something other than its own \
             quantity, or a quantity written where the money goes would reconcile"
        );
        assert_eq!(posting.overdraft, 0, "posting {i}: overdraft");

        let row = RowKey::new(settlement.bucket, DAY, settlement.lane, settlement.provider);
        *reserved_per_row.entry(row).or_default() += u128::from(reserved);
    }

    for (row, reserved) in reserved_per_row {
        assert_eq!(
            ledger[&row].priced_nanos, reserved,
            "the rows written for {row:?} do not add up to the money the ledger posted"
        );
    }
}

/// GREEN: sixteen settlements through both paths, and every row reconciles exactly.
#[test]
fn the_two_paths_agree_on_every_row() {
    let s = settlements();
    let (ledger, legacy, written) = drive(&s, None);

    assert_eq!(
        written.len(),
        s.len(),
        "the dual write must put every settlement onto the previous release's rows"
    );
    assert_eq!(
        ledger.len(),
        legacy.len(),
        "the two paths disagree about how many rows there are: {:?} against {:?}",
        ledger.keys().collect::<Vec<_>>(),
        legacy.keys().collect::<Vec<_>>()
    );
    assert!(ledger.len() >= 7, "the fixture must span several rows");

    let out = reconcile(&ledger, &legacy);
    assert!(
        out.is_empty(),
        "the books do not reconcile: {}",
        describe(&out)
    );

    // Not a vacuous green: at least one row has to have carried real money and a real fee, or
    // "every residual is zero" would be a statement about a table of zeros.
    let priced: usize = ledger.values().filter(|r| r.priced_nanos > 0).count();
    assert!(priced >= 6, "only {priced} rows priced at anything at all");
    let fees: u64 = ledger.values().map(|r| r.fee_count).sum();
    assert_eq!(fees, 14, "fourteen of the sixteen units are billable");
}

/// RED: drop ONE posting from what the check sees, and the residual names the row it went
/// missing from — by name, and by the amount of that one posting.
#[test]
fn a_dropped_posting_names_its_row_and_its_amount() {
    let s = settlements();
    // The fourth settlement: `key-1`/`lane-b`@`prov-y`, 11 in / 7 out, billable. Its row has a
    // second posting on it, so the row does not vanish — it comes up SHORT, which is the
    // failure a missed posting actually produces.
    let dropped = 3;
    let expected_row = RowKey::new(s[dropped].bucket, DAY, s[dropped].lane, s[dropped].provider);

    let (whole, legacy, _) = drive(&s, None);
    assert!(
        reconcile(&whole, &legacy).is_empty(),
        "the same fixture must be green before the posting is dropped"
    );

    let (short, legacy, _) = drive(&s, Some(dropped));
    let out = reconcile(&short, &legacy);

    assert_eq!(
        out.len(),
        1,
        "exactly the row the posting was dropped from must be named, got: {}",
        describe(&out)
    );
    assert_eq!(out[0].row, expected_row, "the wrong row was named");

    // The magnitude is the missing posting, and the sign says which side it is missing from:
    // the ledger accounted for LESS than the legacy row drew, so the residual is negative.
    let missing = i128::from(whole[&expected_row].micros() - short[&expected_row].micros());
    assert_eq!(
        out[0].spend.amount(),
        -missing,
        "the residual must be exactly the posting that went missing"
    );
    assert!(
        missing > 0,
        "the dropped posting must have been worth something"
    );

    // And the count side names it too: the dropped unit was billable, so the row's fee count is
    // one short of its billable requests.
    assert!(out[0].fees_disagree());
    assert_eq!(
        out[0].legacy_billable_requests - out[0].ledger_fee_count,
        1,
        "one billable unit went missing, so the counts are out by exactly one"
    );
}

/// RED, the other direction: a posting on a row the previous release never wrote. The walk is
/// over the union precisely so this cannot pass unnoticed.
#[test]
fn a_posting_the_legacy_rows_never_saw_is_reported() {
    let s = settlements();
    let (mut ledger, legacy, _) = drive(&s, None);
    assert!(reconcile(&ledger, &legacy).is_empty());

    let invented = RowKey::new("key-9", DAY, "lane-a", "prov-x");
    ledger.insert(
        invented.clone(),
        LedgerRow {
            priced_nanos: 5_000_000,
            fee_count: 1,
        },
    );

    let out = reconcile(&ledger, &legacy);
    assert_eq!(out.len(), 1, "{}", describe(&out));
    assert_eq!(out[0].row, invented);
    assert_eq!(
        out[0].spend.amount(),
        5_000,
        "five million nano-units is five thousand micro-units, accounted for against nothing"
    );
}

/// The fee count is checked on its own, so a row whose money happens to agree while its fee
/// count does not is still reported. The case is real: a fee charged against a unit that was
/// not a billable client request, with the money offset by an under-priced token line, would
/// balance on the money side alone.
#[test]
fn the_count_side_is_checked_even_when_the_money_agrees() {
    let row = RowKey::new("key-1", DAY, "lane-a", "prov-x");
    let ledger: LedgerSnapshot = [(
        row.clone(),
        LedgerRow {
            priced_nanos: 7_000_000,
            fee_count: 2,
        },
    )]
    .into_iter()
    .collect();
    let legacy: LegacySnapshot = [(
        row.clone(),
        LegacyRow {
            spend_micros: 7_000,
            billable_requests: 1,
        },
    )]
    .into_iter()
    .collect();

    let out = reconcile(&ledger, &legacy);
    assert_eq!(out.len(), 1);
    assert!(out[0].spend.holds(), "the money side agrees");
    assert!(out[0].fees_disagree(), "the count side does not");
    assert!(out[0].to_string().contains("fee(s) against"));
}

/// The single truncation, asserted rather than assumed. Eight postings that each fall short of
/// a micro-unit sum to something the row can see; projecting each one first would floor all
/// eight to nothing and report the whole row as missing.
#[test]
fn the_projection_happens_once_over_the_row() {
    let mut snapshot = LedgerSnapshot::new();
    let row = RowKey::new("key-1", DAY, "lane-a", "prov-x");
    // 900 nano-units is nine tenths of a micro-unit: zero on its own, seven on the sum of eight.
    for _ in 0..8 {
        let entry = snapshot.entry(row.clone()).or_default();
        entry.priced_nanos += 900;
    }
    assert_eq!(snapshot[&row].micros(), 7);
    assert_eq!(
        micros_of(900) * 8,
        0,
        "the per-posting projection is what this shape exists to avoid"
    );
}

// ── the identity over a history with more than one entry on it ───────────────────────────────

use busbar_unit_cost::{Author, CardEntryDraft, HistorySeq};
use busbar_unit_ledger::checkpoint::{ChainHead, Checkpoint};
use busbar_unit_ledger::recompute::{
    DerivedPrice, Divergence, PostingOrigin, PricedLine, SealedHistory,
};
use busbar_unit_ledger::totals::totals_as_of;

/// The mid-window card: every lane at ten times the opening card's rate, and the same fee.
///
/// Ten times rather than a nudge, so a line priced at the wrong entry is a figure nothing else
/// in the fixture could have produced.
fn later_card() -> RateCard {
    RateCard::from_micro_rates(
        [
            (LaneClass::new("lane-a", "input"), 400.0),
            (LaneClass::new("lane-a", "output"), 900.0),
            (LaneClass::new("lane-b", "input"), 70.0),
            (LaneClass::new("lane-b", "output"), 130.0),
            (LaneClass::new("lane-c", "input"), 10.0),
            (LaneClass::new("lane-c", "output"), 20.0),
        ],
        FEE_CENTS,
    )
}

/// A two-entry history: the opening card from instant zero, and the later card from mid-window.
///
/// Appended rather than substituted, which is the whole model: the opening entry is still there,
/// still covers every instant before the mid-window one, and still prices everything earned
/// under it. Nothing was rewritten.
fn two_entry_history() -> History {
    let mut history = History::opening(card(), 0);
    history.append(CardEntryDraft {
        effective_from: MID_MS,
        effective_until: None,
        card: later_card(),
        appended_at: MID_MS,
        author: Author::Config { policy_epoch: 1 },
    });
    history
}

/// The booked lines the fixture's settlements become, priced and cached AT THE HEAD of whatever
/// history is handed in.
///
/// Cached correctly on purpose: the tests that need a wrong cache corrupt one by hand and say
/// so, and a fixture that started out wrong would make "the caches agree" a claim about nothing.
fn booked(history: &History) -> Vec<BookedLine> {
    let view = history.current();
    let head = history.head().expect("the fixture history has an entry");
    settlements()
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let mut line = BookedLine {
                node: 1,
                node_seq: i as u64 + 1,
                key: totals_key(s.bucket),
                window_start: DAY,
                lane: s.lane.to_string(),
                lines: vec![
                    PricedLine {
                        class: MeterClassId::new("input"),
                        quantity: s.input,
                    },
                    PricedLine {
                        class: MeterClassId::new("output"),
                        quantity: s.output,
                    },
                ],
                fee_count: u64::from(s.billable),
                tier_bp: STANDARD_TIER_BP,
                arrived_ms: arrived_ms(i),
                currency: CurrencyCode::USD,
                cached: DerivedPrice::default(),
                origin: PostingOrigin::Client,
            };
            let priced = busbar_unit_ledger::recompute::price_line(&line, &view, line.tier_bp)
                .expect("every fixture lane is priced in USD at both entries");
            line.cached = DerivedPrice {
                history_seq: head,
                card_seq: priced.card_seq,
                pre_tier_nanos: i128::try_from(priced.pre_tier_nanos).expect("in range"),
                priced_nanos: i128::try_from(priced.priced_nanos).expect("in range"),
            };
            line
        })
        .collect()
}

/// The row one booked line belongs on, at the previous release's width.
fn row_of(line: &BookedLine) -> RowKey {
    let provider = match line.lane.as_str() {
        "lane-a" => "prov-x",
        "lane-b" => "prov-y",
        _ => "prov-z",
    };
    RowKey::new(
        line.key.bucket.as_str(),
        line.window_start,
        &line.lane,
        provider,
    )
}

/// GREEN, and the design's rule 6: on a SINGLE-ENTRY history the lookup at each line's own
/// instant is the previous release's derivation, to the unit.
///
/// The instants are spread across the day and the answer does not move, which is what "exact for
/// a single-entry history" means: the opening entry covers instant zero with no end, so every
/// instant a line can carry resolves to it and the arithmetic is the pinned card's.
#[test]
fn a_single_entry_history_prices_every_instant_exactly_as_the_previous_release_does() {
    let history = History::opening(card(), 0);
    let lines = booked(&history);
    assert!(
        lines
            .iter()
            .map(|l| l.arrived_ms)
            .collect::<BTreeSet<_>>()
            .len()
            > 1,
        "the fixture must span more than one instant, or the claim is about one instant"
    );

    let (ledger, unpriceable) = reprice(&history.current(), CurrencyCode::USD, &lines, row_of);
    assert!(unpriceable.is_empty(), "{unpriceable:?}");

    // The previous release's side: the row's accumulated quantities, derived once at the one
    // card, exactly as `derive_spend_micros` does it.
    let mut legacy_units: BTreeMap<RowKey, (u64, u64, u64)> = BTreeMap::new();
    for (line, s) in lines.iter().zip(settlements().iter()) {
        let e = legacy_units.entry(row_of(line)).or_default();
        e.0 += s.input;
        e.1 += s.output;
        e.2 += u64::from(s.billable);
    }
    let legacy: LegacySnapshot = legacy_units
        .into_iter()
        .map(|(row, (input, output, billable))| {
            let l = super::tests::lines(input, output);
            let spend_micros = derive_spend_micros(
                history
                    .current()
                    .card_at(0)
                    .expect("the opening entry covers instant zero")
                    .1,
                [(row.lane.as_str(), l.as_slice())].into_iter(),
                billable,
                true,
            );
            (
                row,
                LegacyRow {
                    spend_micros,
                    billable_requests: billable,
                },
            )
        })
        .collect();

    let out = reconcile(&ledger, &legacy);
    assert!(out.is_empty(), "{}", describe(&out));
    assert!(ledger.len() >= 7, "the fixture must span several rows");
    assert_eq!(
        total_fee_count(&ledger),
        14,
        "fourteen of the sixteen units are billable"
    );
}

/// RED for the same claim: append one mid-window entry and the previous release's derivation
/// stops agreeing, because it prices the whole day at one card and the lookup does not.
///
/// This is the registered breaking difference, asserted rather than described. It is also what
/// makes the green above a statement about the single-entry case specifically, instead of a test
/// that would pass whatever the history held.
#[test]
fn a_mid_window_entry_is_exactly_what_makes_the_legacy_derivation_diverge() {
    let one = History::opening(card(), 0);
    let two = two_entry_history();
    let lines = booked(&two);

    let (at_opening, _) = reprice(&one.current(), CurrencyCode::USD, &lines, row_of);
    let (at_head, _) = reprice(&two.current(), CurrencyCode::USD, &lines, row_of);

    assert_ne!(
        total_nanos(&at_opening),
        total_nanos(&at_head),
        "a mid-window entry that changed no figure would not be a rate-card change"
    );
    assert!(
        total_nanos(&at_head) > total_nanos(&at_opening),
        "the later card is ten times the opening one, so the head reads higher"
    );

    // And the lines before the mid-window entry did NOT move: only the ones earned after it did.
    // A lookup that priced the whole day at the head would move all of them, which is precisely
    // the behaviour being left behind.
    let early: Vec<&BookedLine> = lines.iter().filter(|l| l.arrived_ms < MID_MS).collect();
    let (early_at_opening, _) = reprice(
        &one.current(),
        CurrencyCode::USD,
        early.iter().copied(),
        row_of,
    );
    let (early_at_head, _) = reprice(
        &two.current(),
        CurrencyCode::USD,
        early.iter().copied(),
        row_of,
    );
    assert!(
        !early.is_empty(),
        "the fixture must have lines before the entry"
    );
    assert_eq!(
        total_nanos(&early_at_opening),
        total_nanos(&early_at_head),
        "a line earned before the entry is priced at the card it was earned under, at every \
         snapshot"
    );
}

/// GREEN over a multi-entry history: the identity's ledger side and the statement cut at the
/// same snapshot are the same money, and the fee counts agree.
///
/// Two walks that fold the same lookups onto different keys — the previous release's row width
/// on one side, the book's balance keys on the other — so a figure that landed on the wrong row
/// on either side moves one sum and not the other.
#[test]
fn the_identity_and_the_statement_at_one_snapshot_are_the_same_money() {
    let history = two_entry_history();
    let view = history.current();
    let lines = booked(&history);

    let (ledger, unpriceable) = reprice(&view, CurrencyCode::USD, &lines, row_of);
    assert!(unpriceable.is_empty(), "{unpriceable:?}");

    let statement = totals_as_of(&view, DAY, CurrencyCode::USD, lines.iter());
    assert!(statement.unpriceable.is_empty());
    assert_eq!(
        statement_residual(&ledger, &statement),
        0,
        "the identity accounted for {} and the statement holds {}",
        total_nanos(&ledger),
        statement.total_nanos()
    );

    // Not a statement about two empty tables.
    assert!(total_nanos(&ledger) > 0);
    assert!(ledger.len() >= 7);

    // The count half, which no card change can move.
    let statement_fees: u64 = statement.rows.values().map(|r| r.fee_count).sum();
    assert_eq!(total_fee_count(&ledger), statement_fees);
    assert_eq!(total_fee_count(&ledger), 14);
}

/// RED for the same claim: move one line's money onto another row and the residual names it.
#[test]
fn a_line_folded_onto_the_wrong_row_moves_one_sum_and_not_the_other() {
    let history = two_entry_history();
    let view = history.current();
    let lines = booked(&history);

    let statement = totals_as_of(&view, DAY, CurrencyCode::USD, lines.iter());
    let (mut ledger, _) = reprice(&view, CurrencyCode::USD, &lines, row_of);
    assert_eq!(statement_residual(&ledger, &statement), 0);

    // Drop one row from the identity's side entirely — the same shape as a fold that put its
    // lines somewhere the walk never looked.
    let dropped = ledger.keys().next().cloned().expect("the fixture has rows");
    let lost = ledger
        .remove(&dropped)
        .expect("the row was there")
        .priced_nanos;
    assert!(lost > 0, "the dropped row must have carried money");
    assert_eq!(
        statement_residual(&ledger, &statement),
        i128::try_from(lost).expect("in range"),
        "the residual is exactly the money that stopped being accounted for"
    );
}

/// The reconciliation walk NEVER reads a cache: corrupt every cached figure in the book and the
/// answer does not move by one nano-unit.
///
/// This is what makes the cache a cache. A walk that summed the stored figures would answer
/// differently depending on whether the recompute had got round to a line yet, and an invoice
/// whose total depended on that is not reproducible at all.
#[test]
fn the_walk_answers_from_the_quantities_and_never_from_the_cache() {
    let history = two_entry_history();
    let view = history.current();
    let honest = booked(&history);
    let (before, _) = reprice(&view, CurrencyCode::USD, &honest, row_of);

    let mut corrupted = honest.clone();
    for line in corrupted.iter_mut() {
        line.cached.priced_nanos = 999_999_999_999;
        line.cached.pre_tier_nanos = 888_888_888_888;
        line.cached.card_seq = HistorySeq(99);
    }
    let (after, _) = reprice(&view, CurrencyCode::USD, &corrupted, row_of);

    assert_eq!(before, after, "the cache is not on the reconciliation path");
    assert!(total_nanos(&before) > 0);

    // And the statement agrees, for the same reason.
    let statement = totals_as_of(&view, DAY, CurrencyCode::USD, corrupted.iter());
    assert_eq!(statement_residual(&after, &statement), 0);
}

/// A lane the card is silent about is REPORTED, and its row is not quietly short.
///
/// The read posture prices what it can — the flat fee is still charged and is still real money —
/// so the figure lands on its row and the line is listed beside it. A row that came up a lane
/// short with nothing saying why would report as a residual against the previous release and
/// send an operator looking through a day of postings for a defect that is a configuration hole.
#[test]
fn a_lane_the_card_is_silent_about_is_reported_beside_its_row() {
    let history = two_entry_history();
    let view = history.current();
    let mut lines = booked(&history);
    lines[0].lane = "lane-nobody-priced".to_string();

    let (ledger, unpriceable) = reprice(&view, CurrencyCode::USD, &lines, row_of);
    assert_eq!(unpriceable.len(), 1, "{unpriceable:?}");
    assert_eq!(unpriceable[0].node_seq, lines[0].node_seq);
    assert!(matches!(
        unpriceable[0].why,
        Divergence::LaneUnpriced { .. }
    ));
    // The fee is on the row, and only the fee: the tokens the card names no rate for price at
    // nothing, and that is what makes the hole visible as a figure as well as as a report.
    let row = ledger[&row_of(&lines[0])];
    assert_eq!(row.fee_count, 1);
    assert!(row.priced_nanos > 0, "the fee is still money");
}

/// A hole in the history is a refusal, never a zero: the line lands on NO row at all, and it is
/// listed.
///
/// Folding it in at nothing is how a gap in the history becomes free service that reconciles.
#[test]
fn an_instant_no_entry_covers_lands_on_no_row_and_is_listed() {
    // A history whose only entry opens AFTER the day the lines fall in.
    let mut history = History::new();
    history.append(CardEntryDraft {
        effective_from: MID_MS,
        effective_until: None,
        card: card(),
        appended_at: MID_MS,
        author: Author::Opening,
    });
    let view = history.current();
    let lines = booked(&two_entry_history());
    let early: Vec<&BookedLine> = lines.iter().filter(|l| l.arrived_ms < MID_MS).collect();
    assert!(!early.is_empty());

    let (ledger, unpriceable) = reprice(&view, CurrencyCode::USD, early.iter().copied(), row_of);
    assert_eq!(unpriceable.len(), early.len(), "{unpriceable:?}");
    assert!(unpriceable
        .iter()
        .all(|u| matches!(u.why, Divergence::NoCardInForce { .. })));
    assert!(
        ledger.is_empty(),
        "an instant no entry covers must not land on a row as a zero"
    );
}

/// A currency the reconciliation did not ask for is skipped, never summed.
#[test]
fn two_currencies_never_sum_into_one_reconciliation() {
    let history = two_entry_history();
    let view = history.current();
    let mut lines = booked(&history);
    let moved = lines[0].node_seq;
    lines[0].currency = CurrencyCode::new("JPY").expect("a valid alpha-3 code");

    let (usd, unpriceable) = reprice(&view, CurrencyCode::USD, &lines, row_of);
    assert!(
        unpriceable.is_empty(),
        "a skipped currency is not a refusal"
    );

    let (all_usd, _) = reprice(&view, CurrencyCode::USD, &booked(&history), row_of);
    assert!(
        total_nanos(&usd) < total_nanos(&all_usd),
        "line {moved} is denominated in another currency and must not be in this sum"
    );
}

// ── the recompute pass ───────────────────────────────────────────────────────────────────────

/// GREEN: every line's cached price is the lookup, so a pass over an untouched book finds
/// nothing and corrects nothing.
#[test]
fn a_book_whose_caches_are_the_lookup_reconciles_clean() {
    let history = two_entry_history();
    let archive = SealedHistory::new(history.clone());
    let mut lines = booked(&history);

    assert!(
        cache_findings(&lines, &archive).is_empty(),
        "the fixture's caches are the lookup's own answers"
    );

    let entry = boot_pass(Watermark::start(), &mut lines, &archive);
    assert!(entry.is_clean(), "{entry}");
    assert!(!entry.alarms());
    assert_eq!(entry.checked, 16);
    assert_eq!(entry.corrected, 0);
    assert_eq!(entry.history_seq, history.head());
    assert_eq!(entry.watermark.mark_for(1), Some(16));
}

/// RED, and the one that must alarm: a cached figure edited by hand under a head that has NOT
/// moved.
///
/// Nothing legitimate can have changed the answer, so the verdict is `Alarm` and not `Stale`.
/// Routing it through the quiet path an amendment uses would be exactly how somebody launders a
/// hand edit into a routine cache refresh.
#[test]
fn a_cache_edited_under_an_unmoved_head_alarms_and_is_corrected() {
    let history = two_entry_history();
    let archive = SealedHistory::new(history.clone());
    let mut lines = booked(&history);

    let honest = lines[4].cached.priced_nanos;
    lines[4].cached.priced_nanos = honest + 1_000_000;

    let findings = cache_findings(&lines, &archive);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].verdict, Verdict::Alarm);
    assert_eq!(findings[0].node_seq, lines[4].node_seq);
    assert!(matches!(findings[0].divergence, Divergence::Priced { .. }));

    let entry = on_demand_pass(Watermark::start(), &mut lines, &archive);
    assert!(entry.alarms(), "{entry}");
    assert_eq!(entry.alarming(), 1);
    assert_eq!(entry.stale(), 0);
    assert_eq!(entry.corrected, 1);
    // The LOOKUP wins: the cache is corrected back to it, and the quantities are untouched.
    assert_eq!(lines[4].cached.priced_nanos, honest);
    assert!(entry.to_string().contains("ALARMING"));
}

/// RED, the other verdict: an amendment moved the head, so a cache computed under the older
/// snapshot is STALE — corrected, journalled, and not an alarm.
///
/// The same correction as the case above and a different meaning, which is the whole reason the
/// two counts are separate fields.
#[test]
fn a_cache_behind_a_moved_head_is_stale_rather_than_alarming() {
    // The lines are settled under the single-entry history, so their caches are current as of
    // entry zero and their figures are the opening card's.
    let opening = History::opening(card(), 0);
    let mut lines = booked(&opening);
    let before: Vec<i128> = lines.iter().map(|l| l.cached.priced_nanos).collect();

    // Then the operator appends a mid-window entry. The head moves; nothing else does.
    let history = two_entry_history();
    let archive = SealedHistory::new(history.clone());

    let findings = cache_findings(&lines, &archive);
    assert!(!findings.is_empty(), "the later card moves the late lines");
    assert!(
        findings.iter().all(|f| f.verdict == Verdict::Stale),
        "a head that moved is consent for a cache to be behind: {findings:?}"
    );

    let entry = boot_pass(Watermark::start(), &mut lines, &archive);
    assert!(!entry.alarms(), "{entry}");
    assert_eq!(entry.alarming(), 0);
    assert!(entry.stale() > 0);
    assert!(entry.corrected > 0);
    assert!(entry.to_string().contains("stale"));

    // Corrected forward to the head, and the lines earned BEFORE the entry did not move.
    let mut repriced_upward = 0usize;
    for (i, line) in lines.iter().enumerate() {
        assert_eq!(line.cached.history_seq, history.head().expect("a head"));
        if line.arrived_ms < MID_MS {
            assert_eq!(
                line.cached.priced_nanos, before[i],
                "line {i} was earned before the entry and its price must not have moved"
            );
        } else {
            // A line with quantities reprices upward at the ten-times card; the fixture's
            // one zero-quantity line carries only the fee, which neither card changes, so it
            // reprices to the same figure. Both are the lookup's answer and neither may fall.
            assert!(
                line.cached.priced_nanos >= before[i],
                "line {i} priced lower at the later card"
            );
            if line.cached.priced_nanos > before[i] {
                repriced_upward += 1;
            }
        }
    }
    assert!(
        repriced_upward > 0,
        "the later card must actually have moved something"
    );
}

/// The boot pass and the on-demand pass are the SAME arithmetic, and each says which it was.
///
/// A boot pass that used a different rule from a tick's would be a second copy of the
/// arbitration, and a second copy of a money rule is how a figure comes to be judged one way in
/// one place and another way in another.
#[test]
fn the_trigger_is_recorded_and_is_never_an_input_to_the_arithmetic() {
    let history = two_entry_history();
    let archive = SealedHistory::new(history.clone());
    let mut a = booked(&History::opening(card(), 0));
    let mut b = a.clone();

    let boot = boot_pass(Watermark::start(), &mut a, &archive);
    let demand = on_demand_pass(Watermark::start(), &mut b, &archive);

    assert_eq!(boot.trigger, PassTrigger::Boot);
    assert_eq!(demand.trigger, PassTrigger::OnDemand);
    assert_ne!(boot.trigger, demand.trigger);
    assert_eq!(boot.findings, demand.findings);
    assert_eq!(boot.corrected, demand.corrected);
    assert_eq!(boot.checked, demand.checked);
    assert_eq!(boot.watermark, demand.watermark);
    assert_eq!(a, b, "the two passes leave the book in the same state");

    assert!(boot.to_string().contains("at boot"));
    assert!(demand.to_string().contains("on demand"));
}

/// The pass resumes from the watermark it was handed, per node.
///
/// A boot pass that started over would recheck a day of lines on every restart and reach the
/// head on none of them; one that reset to the head would check nothing at all.
#[test]
fn a_pass_resumes_from_the_watermark_it_was_handed() {
    let history = two_entry_history();
    let archive = SealedHistory::new(history);
    let mut lines = booked(&History::opening(card(), 0));

    let first = boot_pass(Watermark::from_pairs([(1u64, 10u64)]), &mut lines, &archive);
    assert_eq!(first.checked, 6, "ten of the sixteen are already behind it");

    // Handed the mark it left, the next pass has nothing to do — and the caches it corrected
    // stay corrected.
    let second = on_demand_pass(first.watermark.clone(), &mut lines, &archive);
    assert_eq!(second.checked, 0);
    assert_eq!(second.corrected, 0);
    assert!(second.is_clean());
    assert_eq!(second.watermark, first.watermark);
}

// ── a checkpoint is true of one history and no other ─────────────────────────────────────────

/// The totals a checkpoint fixture seals. One balance, one window, real figures.
fn sealed_totals() -> BTreeMap<(TotalsKey, u64), Totals> {
    [(
        (totals_key("key-1"), DAY),
        Totals {
            settled: 2_530_000_000,
            drawn: 2_530_000_000,
            ..Totals::zero()
        },
    )]
    .into_iter()
    .collect()
}

fn sealed_at(history_seq: HistorySeq) -> Checkpoint {
    Checkpoint::seal_as_of(
        7,
        1,
        DAY,
        vec![ChainHead {
            node: 1,
            node_seq: 16,
            hash: [0u8; 32],
        }],
        sealed_totals(),
        0,
        0,
        history_seq,
        None,
    )
    .expect("no signer, so no signature can fail")
}

/// GREEN: a checkpoint sealed as of a snapshot verifies at that snapshot — and at no other.
///
/// The figures are a materialised view of a lookup, so verifying them against a history that did
/// not produce them is not a check that passes or fails; it is a check about nothing.
#[test]
fn a_checkpoint_verifies_at_the_snapshot_it_was_sealed_as_of_and_at_no_other() {
    let checkpoint = sealed_at(HistorySeq(1));
    assert_eq!(checkpoint.history_seq, Some(HistorySeq(1)));
    assert!(verify_as_of(&checkpoint, HistorySeq(1)).is_ok());

    for asked in [HistorySeq::OPENING, HistorySeq(2), HistorySeq(99)] {
        let refusal = verify_as_of(&checkpoint, asked)
            .expect_err("a snapshot the checkpoint never named must be refused");
        assert_eq!(
            refusal,
            CheckpointRefusal::NotAsOf {
                sealed: HistorySeq(1),
                asked
            }
        );
        // The refusal names both numbers, because "it does not verify" sends an operator
        // looking and "it is true of entry 1, not 2" is an answer.
        assert!(refusal.to_string().contains('1'), "{refusal}");
    }
}

/// RED: the digest is still taken. A checkpoint whose figures were edited after the seal is
/// refused at its own snapshot.
#[test]
fn an_edited_checkpoint_body_is_refused_at_its_own_snapshot() {
    let mut checkpoint = sealed_at(HistorySeq(1));
    assert!(verify_as_of(&checkpoint, HistorySeq(1)).is_ok());

    let row = checkpoint
        .totals
        .get_mut(&(totals_key("key-1"), DAY))
        .expect("the fixture sealed one row");
    row.settled += 1;

    assert!(!checkpoint.body_hash_verifies());
    assert_eq!(
        verify_as_of(&checkpoint, HistorySeq(1)),
        Err(CheckpointRefusal::BodyEdited)
    );
}

/// A checkpoint sealed before the history existed names none. It still verifies by digest —
/// forever, under the encoding it was sealed with — and it is refused at every snapshot,
/// because it never claimed to be re-derivable at one.
#[test]
fn a_checkpoint_that_predates_the_history_is_refused_at_every_snapshot() {
    let checkpoint = Checkpoint::seal(
        7,
        1,
        DAY,
        vec![ChainHead {
            node: 1,
            node_seq: 16,
            hash: [0u8; 32],
        }],
        sealed_totals(),
        0,
        0,
        None,
    )
    .expect("no signer, so no signature can fail");

    assert_eq!(checkpoint.history_seq, None);
    assert!(
        checkpoint.body_hash_verifies(),
        "a sealed body is never rewritten, so it digests forever"
    );
    for asked in [HistorySeq::OPENING, HistorySeq(1), HistorySeq(2)] {
        assert_eq!(
            verify_as_of(&checkpoint, asked),
            Err(CheckpointRefusal::PredatesHistory { asked })
        );
    }
}

/// The snapshot is DIGESTED, not merely carried beside the figures: two checkpoints over the
/// same totals at different snapshots are different bodies.
///
/// A number that rode along outside the body could be edited without breaking the seal, which
/// would make "these totals, at that history" an assertion anybody could change.
#[test]
fn the_snapshot_a_checkpoint_names_is_part_of_the_body_it_seals() {
    let at_one = sealed_at(HistorySeq(1));
    let at_two = sealed_at(HistorySeq(2));
    assert_eq!(at_one.totals, at_two.totals);
    assert_ne!(
        at_one.body_hash, at_two.body_hash,
        "the snapshot must move the digest, or it is not sealed at all"
    );
}
