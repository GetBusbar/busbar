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
        let quantities = Posting::from_usage(s.lane, &usage, fee_count, STANDARD_TIER_BP, 0, 0);
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
        let _ = ledger.settle(
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
            let l = lines(input, output);
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
            0,
            0,
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
