// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The reconciliation identity: the ledger's postings against the previous release's rows.
//!
//! ## What it says
//!
//! For every row the previous release keeps — one per `(bucket, day, lane, provider)` — two figures
//! have to agree:
//!
//! ```text
//!   Σ ledger priced_amount, projected once to micro-units  ==  the row's spend_micros
//!   Σ ledger fee_count                                     ==  the row's billable_requests
//! ```
//!
//! The first is money and the second is a count, and they are checked separately because they fail
//! separately: a card edit moves the money and leaves the count alone, and a fee applied to a unit
//! that should not have carried one moves both but only the count says which.
//!
//! ## Why it belongs to the root and not to either unit
//!
//! The ledger unit knows what it posted and nothing about a usage row. The store adapter knows the
//! row shape and nothing about a posting. Neither may name the other — that is the whole point of
//! the unit split — so the one place entitled to hold both sides of the comparison is the thing
//! that built both, and that is here.
//!
//! The arithmetic itself is not here. `busbar_unit_ledger::identity::residual` is the pure function
//! — no clock, no store, no state, two snapshots in and a number out — and this module's job is to
//! supply those two snapshots in its terms. That division is deliberate: an auditor re-deriving the
//! identity from a pair of sealed checkpoints runs exactly the same function this does.
//!
//! ## The one truncation, and where it happens
//!
//! Postings accumulate in NANO-UNITS and are projected to micro-units ONCE per row, at comparison
//! time. Projecting each posting and summing the projections is a different number: eight postings
//! each half a micro-unit short of a boundary are eight floors of zero, where the single divide
//! over the sum is four. The previous release's read-time derivation sums nano-units across the
//! whole row and divides once, so the ledger side has to as well or the identity would report a
//! rounding convention as a discrepancy on every busy row.
//!
//! ## Why a residual and not a boolean
//!
//! Same reason the unit's own identity returns one. "The books do not balance" sends an operator
//! looking through a day's postings; "this row is out by the price of one output token" is a
//! starting point, and the sign says which side is missing it. So a discrepancy carries the row it
//! is about and the residual, and the display line names both.

use std::collections::{BTreeMap, BTreeSet};

use busbar_unit_cost::{micros_of, Posting};
use busbar_unit_ledger::identity::{residual, Residual};
use busbar_unit_ledger::totals::Totals;

/// Which of the previous release's rows a posting groups onto.
///
/// Four parts, because the previous release keeps its usage rows at exactly this width and the
/// identity is only worth checking at the width somebody could disagree at. Summing two lanes into
/// one row before comparing would let an over-priced lane and an under-priced lane cancel, and the
/// row a bill is queried at is the row the check has to hold at.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RowKey {
    /// Whose budget the usage was attributed to — the previous release's key id.
    pub bucket: String,
    /// The UTC-day bucket the row falls in, as a unix second.
    pub day: u64,
    /// The serving lane's configured model name — the lane the posting was priced against.
    pub lane: String,
    /// The serving lane's provider.
    pub provider: String,
}

impl RowKey {
    /// Name a row.
    pub fn new(
        bucket: impl Into<String>,
        day: u64,
        lane: impl Into<String>,
        provider: impl Into<String>,
    ) -> Self {
        RowKey {
            bucket: bucket.into(),
            day,
            lane: lane.into(),
            provider: provider.into(),
        }
    }
}

impl std::fmt::Display for RowKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}/{}@{} in the day opening at {}",
            self.bucket, self.lane, self.provider, self.day
        )
    }
}

/// What the ledger posted against one row.
///
/// Nano-units, not micro-units, and the reason is the module doc's single truncation: this figure
/// is a running sum and the projection happens once, over the sum, at comparison time.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LedgerRow {
    /// The summed `priced_amount` of every posting on this row, in nano-units, post-tier.
    pub priced_nanos: u128,
    /// The summed `fee_count` of those postings — one per billable client request, zero otherwise.
    pub fee_count: u64,
}

impl LedgerRow {
    /// The row's money in micro-units: one truncating divide over the summed nano-units.
    pub fn micros(&self) -> i64 {
        micros_of(self.priced_nanos)
    }
}

/// What the previous release's row carries for the same cell.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LegacyRow {
    /// The row's derived spend in micro-units, as the legacy usage projection reports it.
    pub spend_micros: i64,
    /// The row's billable request count — the base the flat fee is charged on.
    pub billable_requests: u64,
}

/// Everything the ledger posted, by row.
pub type LedgerSnapshot = BTreeMap<RowKey, LedgerRow>;

/// Everything the previous release's rows carry, by row.
pub type LegacySnapshot = BTreeMap<RowKey, LegacyRow>;

/// Add one posting to a ledger snapshot.
///
/// The one place a `Posting` becomes a row figure, so there is one answer to "which two numbers off
/// a posting does the identity read" rather than one per caller.
pub fn accumulate(snapshot: &mut LedgerSnapshot, row: RowKey, posting: &Posting) {
    let entry = snapshot.entry(row).or_default();
    entry.priced_nanos = entry.priced_nanos.saturating_add(posting.priced_amount());
    entry.fee_count = entry.fee_count.saturating_add(posting.fee_count());
}

/// The two snapshots of one row, in the terms the unit's identity function reads.
///
/// The mapping is one line and it is worth stating in full rather than leaving to a reader of the
/// call site. The identity asks *everything drawn — where is it now?*: `drawn` is what left the
/// store, and the accounted columns are the places it can be. Here the previous release's row IS
/// the drawn figure — it is the record of value taken — and the ledger's postings ARE where it
/// went, so they land in `settled`. Every other column is zero because this comparison has no other
/// place for value to be: a row is a closed statement about one day's completed postings, with no
/// holds still open on it and no transfers in or out.
///
/// `since` is zeros for the same reason: a row's figures are the row's own total, not a delta from
/// an earlier seal, so the snapshot before it is the one where nothing had happened.
pub fn as_totals(ledger: &LedgerRow, legacy: &LegacyRow) -> Totals {
    Totals {
        settled: i128::from(ledger.micros()),
        drawn: i128::from(legacy.spend_micros),
        ..Totals::zero()
    }
}

/// How far out one row is, on the money side.
pub fn row_residual(ledger: &LedgerRow, legacy: &LegacyRow) -> Residual {
    residual(&Totals::zero(), &as_totals(ledger, legacy))
}

/// One row where the two sides do not agree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discrepancy {
    /// Which row.
    pub row: RowKey,
    /// How far out the money is, and on which side.
    pub spend: Residual,
    /// What the ledger's postings charged fees for.
    pub ledger_fee_count: u64,
    /// What the previous release's row says was billable.
    pub legacy_billable_requests: u64,
}

impl Discrepancy {
    /// Whether the count side is the one that is wrong.
    pub fn fees_disagree(&self) -> bool {
        self.ledger_fee_count != self.legacy_billable_requests
    }
}

impl std::fmt::Display for Discrepancy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} does not reconcile: {}", self.row, self.spend)?;
        if self.fees_disagree() {
            write!(
                f,
                "; the ledger charged {} fee(s) against {} billable request(s)",
                self.ledger_fee_count, self.legacy_billable_requests
            )?;
        }
        Ok(())
    }
}

impl std::error::Error for Discrepancy {}

/// Check the identity over every row either side carries.
///
/// The previous release's rows name the domain — they are what an operator queries and what a
/// rollback reads — but the walk is over the UNION rather than over the legacy keys alone, and that
/// is not pedantry. A ledger row with no legacy row behind it is a posting the previous release
/// never saw: value the dual write lost, which is exactly the failure this check exists for, and
/// iterating the legacy keys only would step straight past it. Such a row is compared against a
/// zero legacy row, so it reports as a residual naming the whole posting rather than as silence.
///
/// Returns the rows that do not reconcile, in row order. An empty answer is the good one.
pub fn reconcile(ledger: &LedgerSnapshot, legacy: &LegacySnapshot) -> Vec<Discrepancy> {
    let rows: BTreeSet<&RowKey> = ledger.keys().chain(legacy.keys()).collect();
    let mut out = Vec::new();
    for row in rows {
        let l = ledger.get(row).copied().unwrap_or_default();
        let g = legacy.get(row).copied().unwrap_or_default();
        let spend = row_residual(&l, &g);
        if spend.holds() && l.fee_count == g.billable_requests {
            continue;
        }
        out.push(Discrepancy {
            row: row.clone(),
            spend,
            ledger_fee_count: l.fee_count,
            legacy_billable_requests: g.billable_requests,
        });
    }
    out
}

/// Whether the identity holds over every row.
pub fn holds(ledger: &LedgerSnapshot, legacy: &LegacySnapshot) -> bool {
    reconcile(ledger, legacy).is_empty()
}

/// Every discrepancy on one line, for a message.
pub fn describe(discrepancies: &[Discrepancy]) -> String {
    discrepancies
        .iter()
        .map(|d| d.to_string())
        .collect::<Vec<_>>()
        .join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;

    use busbar_caps::{Admit, AdmitToken};
    use busbar_caps::{Hold, LedgerToken, Usage, UsageToken};
    use busbar_caps::{KernelSeal, MeterClassId, PrincipalId, QuantitySource, UsageLine};
    use busbar_unit_cost::{
        derive_spend_micros, price, LaneClass, RateCard, RateCardVersion, STANDARD_TIER_BP,
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
            RateCardVersion::new("identity-test-1"),
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
        let card = card();
        let pinned = card.pin();
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
            let posting = price(&pinned, s.lane, &usage, fee_count, STANDARD_TIER_BP);

            // The books move whatever the snapshot does: the red proof below drops a posting from
            // what the CHECK sees, not from what the ledger did, because the defect it stands in
            // for is a reconciliation that missed a posting and not a settlement that never
            // happened.
            let reserved = posting.priced_amount().min(u128::from(u64::MAX)) as u64;
            ledger.record_draw(&totals_key(s.bucket), DAY, i128::from(reserved));
            ledger.record_hold_opened(&totals_key(s.bucket), DAY, reserved);
            ledger.record_slice_spent(&totals_key(s.bucket), DAY, i128::from(reserved));
            ledger.settle(
                &totals_key(s.bucket),
                DAY,
                Hold::open(&admit_token(), PrincipalId::new(s.bucket), reserved),
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
                    &card,
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
        let expected_row =
            RowKey::new(s[dropped].bucket, DAY, s[dropped].lane, s[dropped].provider);

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
}
