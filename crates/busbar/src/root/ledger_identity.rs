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
//!   Σ ledger priced_amount, projected once to micro-units  ==  the row's spend_micros × tier
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
//! ## The tier, and which side of the comparison carries it
//!
//! The two sides do not agree about the tier multiplier, and pretending they do is how a discount
//! group reports its discount as a discrepancy. The ledger side applies the tier when it PRICES —
//! `busbar_unit_cost::price` divides the summed pre-tier amount by the tier once and stores the
//! result — so a posting's `priced_amount` is already tiered. The previous release's read-time
//! derivation has no tier in it at all: `derive_spend_micros` sums quantity × rate and adds the flat
//! fee, and that is the whole of it. So the row's own figure is a PRE-TIER one, and comparing it
//! against a post-tier sum reports the multiplier itself as the residual — a group at 9000 bp comes
//! out ten per cent short on every row it has.
//!
//! Hence the row carries the tier it was charged at and the comparison projects the legacy figure
//! through it. The tier belongs on the legacy side and not on the ledger side because that is where
//! it is MISSING: the ledger's figure needs no adjustment, and adjusting it would be undoing work
//! the pricing already did correctly.
//!
//! ### What has to hold for that projection to be exact
//!
//! Two conditions, both properties of the card rather than of this module, and both worth naming
//! because the identity is exact only while they hold:
//!
//! - every posting's pre-tier amount is a whole number of MICRO-units, so the row's legacy figure
//!   loses nothing to its own projection before the tier is applied to it. Configured rates are
//!   micro-units per unit of quantity and the flat fee is CENTS lifted by `NANOS_PER_CENT`, so a
//!   sub-micro line amount can only come from a sub-micro configured rate;
//! - the tier divides each posting's pre-tier amount exactly, so the ledger's per-posting floors sum
//!   to the row's single one.
//!
//! Where either fails the two sides truncate on OPPOSITE sides of the tier — the ledger after it,
//! the legacy row before it — and the residual names a rounding convention rather than lost value.
//! The tests below pin both conditions rather than assuming them.
//!
//! ## Why a residual and not a boolean
//!
//! Same reason the unit's own identity returns one. "The books do not balance" sends an operator
//! looking through a day's postings; "this row is out by the price of one output token" is a
//! starting point, and the sign says which side is missing it. So a discrepancy carries the row it
//! is about and the residual, and the display line names both.

use std::collections::{BTreeMap, BTreeSet};

use busbar_unit_cost::{apply_tier, micros_of, Posting, STANDARD_TIER_BP};
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LegacyRow {
    /// The row's derived spend in micro-units, as the legacy usage projection reports it — PRE-TIER,
    /// because that projection has no tier in it. See the module doc.
    pub spend_micros: i64,
    /// The row's billable request count — the base the flat fee is charged on.
    pub billable_requests: u64,
    /// The tier multiplier, in basis points, the row's postings were charged at.
    ///
    /// The one field on this side that is not read off the row: a legacy row records what was used
    /// and what the rates made of it, never which tier the chain serving it was on. It is supplied
    /// by whoever builds the snapshot, from the same chain the pricing read it from, and it is a
    /// field rather than an argument so that a snapshot spanning two tiers cannot be built by
    /// forgetting which row is which.
    pub tier_bp: u32,
}

impl Default for LegacyRow {
    /// An absent row: no spend, no billable requests, and the NEUTRAL tier.
    ///
    /// Not `#[derive]`d, and the reason is the tier. A derived default is zero basis points, which
    /// multiplies every figure it is applied to by nothing — so a row built with
    /// `..Default::default()` would report its whole spend as unaccounted for, and the row
    /// `reconcile` invents for a posting the previous release never saw would compare against a
    /// figure the multiplier had already erased.
    fn default() -> Self {
        LegacyRow {
            spend_micros: 0,
            billable_requests: 0,
            tier_bp: STANDARD_TIER_BP,
        }
    }
}

impl LegacyRow {
    /// The row's money in the ledger's terms: the derived figure projected through the tier the
    /// postings were charged at.
    ///
    /// `apply_tier` is the unit's own multiplier and is used rather than reimplemented, so the ledger
    /// side and this side can never round the tier two different ways. It takes an unsigned amount,
    /// which is what a derived spend is; the sign is carried around it rather than through it so that
    /// a figure some future adjustment made negative scales by magnitude and keeps its sign, instead
    /// of wrapping into an enormous positive one.
    pub fn tiered_micros(&self) -> i128 {
        let magnitude = apply_tier(u128::from(self.spend_micros.unsigned_abs()), self.tier_bp);
        let magnitude = i128::try_from(magnitude).unwrap_or(i128::MAX);
        if self.spend_micros < 0 {
            -magnitude
        } else {
            magnitude
        }
    }
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
///
/// `drawn` is the legacy figure THROUGH THE TIER, never the raw one. The ledger's postings arrive
/// already tiered and the previous release's derivation never was, so the raw figure would report
/// the multiplier as the residual on every row of a group that is not at the neutral tier.
pub fn as_totals(ledger: &LedgerRow, legacy: &LegacyRow) -> Totals {
    Totals {
        settled: i128::from(ledger.micros()),
        drawn: legacy.tiered_micros(),
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
        derive_spend_micros, price, LaneClass, RateCard, RateCardVersion, NANOS_PER_MICRO,
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

    /// The tiers the fixture's buckets are charged at, one per bucket, because a tier is a property
    /// of the chain a request was admitted through and every row under one bucket shares it.
    ///
    /// Three distinct values on purpose: the neutral one, a DISCOUNT and a SURCHARGE. A fixture at
    /// the neutral tier alone proves nothing about the tier at all — `apply_tier` at ×1 is the
    /// identity function, so the whole projection could be missing and every row would still
    /// reconcile.
    const DISCOUNT_TIER_BP: u32 = 9_000;
    const SURCHARGE_TIER_BP: u32 = 15_000;

    /// The tier each bucket's chain is on.
    fn tier_of(bucket: &str) -> u32 {
        match bucket {
            "key-2" => DISCOUNT_TIER_BP,
            "key-3" => SURCHARGE_TIER_BP,
            _ => STANDARD_TIER_BP,
        }
    }

    /// The four lanes, each with a visibly different price so a row that took the wrong lane's
    /// rate is a different number rather than the same one.
    ///
    /// `lane-d` is priced in HUNDREDTHS of a micro-unit, and it is the reason the module's
    /// single-truncation rule is a claim about this fixture rather than about an imagined one: every
    /// other lane's rate is a whole micro-unit, so every amount it produces is a whole number of
    /// micro-units and no projection can lose anything. On `lane-d` a posting is a fraction of a
    /// micro-unit and only the sum over the row reaches one.
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
                (LaneClass::new("lane-d", "input"), 0.11),
                (LaneClass::new("lane-d", "output"), 0.37),
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

    /// Twenty-one settlements over four buckets, four lanes and two providers.
    ///
    /// `key-1` is on the neutral tier, `key-2` on a discount and `key-3` on a surcharge, so no row's
    /// money is the same number with the tier projection missing as with it present. `key-4` runs
    /// the sub-micro lane at the neutral tier, several postings to a row, so the row's figure is one
    /// a per-posting projection would floor away — the module's single-truncation rule, exercised
    /// rather than described.
    ///
    /// The discount and the surcharge stay on the whole-micro lanes, which is not an accident and is
    /// the module doc's second exactness condition standing up: a sub-micro amount under a tier
    /// truncates on opposite sides of the multiplier on the two paths, and a fixture that mixed them
    /// would be asserting a rounding convention.
    ///
    /// Three units are non-billable — a nested unit, a tick, and one on the sub-micro lane — so the
    /// fee count is not simply the row's posting count.
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
            ("key-4", "lane-d", "prov-x", 3, 2, true),
            ("key-4", "lane-d", "prov-x", 1, 1, true),
            ("key-4", "lane-d", "prov-x", 7, 0, false),
            ("key-4", "lane-d", "prov-y", 2, 1, true),
            ("key-4", "lane-d", "prov-y", 4, 5, true),
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
            // THE TIER THE CHAIN WAS ON, read from the bucket rather than pinned to the neutral
            // value: the ledger side is the side that applies it, and a fixture that only ever
            // priced at ×1 would leave the legacy side's projection unexercised.
            let posting = price(&pinned, s.lane, &usage, fee_count, tier_of(s.bucket));

            // The books move whatever the snapshot does: the red proof below drops a posting from
            // what the CHECK sees, not from what the ledger did, because the defect it stands in
            // for is a reconciliation that missed a posting and not a settlement that never
            // happened.
            let reserved = posting.priced_amount().min(u128::from(u64::MAX)) as u64;
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
                posting.priced_amount(),
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
                // The derivation is the previous release's and has no tier in it; the tier the row
                // was charged at rides beside the figure, which is the whole of the projection.
                let tier_bp = tier_of(row.bucket.as_str());
                (
                    row,
                    LegacyRow {
                        spend_micros,
                        billable_requests: billable,
                        tier_bp,
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

        let card = card();
        let pinned = card.pin();
        let mut reserved_per_row: BTreeMap<RowKey, u128> = BTreeMap::new();
        for (i, (posting, settlement)) in written.iter().zip(s.iter()).enumerate() {
            let usage = Usage::report(&usage_token(), lines(settlement.input, settlement.output))
                .expect("the usage report is within the line limit");
            let priced = price(
                &pinned,
                settlement.lane,
                &usage,
                u64::from(settlement.billable),
                tier_of(settlement.bucket),
            );
            let reserved = priced.priced_amount().min(u128::from(u64::MAX)) as u64;

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
        assert!(ledger.len() >= 9, "the fixture must span several rows");
        // AND SEVERAL TIERS, or the projection the identity now performs is the identity function
        // on every row it was checked over.
        let tiers: BTreeSet<u32> = legacy.values().map(|r| r.tier_bp).collect();
        assert_eq!(
            tiers,
            [STANDARD_TIER_BP, DISCOUNT_TIER_BP, SURCHARGE_TIER_BP]
                .into_iter()
                .collect::<BTreeSet<u32>>(),
            "the fixture must reconcile at a discount and a surcharge, not only at the neutral tier"
        );

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
        assert_eq!(fees, 18, "eighteen of the twenty-one units are billable");
    }

    /// THE TIER IS APPLIED, and the row that is not at the neutral tier says so.
    ///
    /// The plant this stands against is the projection going missing: `as_totals` reading the legacy
    /// figure raw. Every row of `key-1` would still reconcile, because ×1 is the identity function —
    /// so the check is made on the rows that are NOT at ×1, and it is made against a figure derived
    /// here rather than against the one the comparison uses.
    #[test]
    fn a_row_off_the_neutral_tier_reconciles_at_its_own_multiplier_and_not_at_one() {
        let s = settlements();
        let (ledger, legacy, _) = drive(&s, None);

        let mut checked = 0usize;
        for (row, g) in &legacy {
            if g.tier_bp == STANDARD_TIER_BP {
                continue;
            }
            let l = ledger[row];
            assert!(g.spend_micros > 0, "{row} priced at nothing");
            // Spelled out rather than taken from `tiered_micros`: the figure the comparison is
            // supposed to reach, computed the long way, from the multiplier the row was charged at.
            let expected =
                i128::from(g.spend_micros) * i128::from(g.tier_bp) / i128::from(STANDARD_TIER_BP);
            assert_eq!(
                i128::from(l.micros()),
                expected,
                "{row}: the ledger's tiered money is not the row's figure at the row's tier"
            );
            assert_ne!(
                i128::from(l.micros()),
                i128::from(g.spend_micros),
                "{row}: the untiered figure must be a DIFFERENT number, or this proves nothing"
            );
            checked += 1;
        }
        assert!(
            checked >= 4,
            "only {checked} rows were off the neutral tier; the fixture must carry several"
        );
    }

    /// THE FEE IS A WHOLE MICRO-UNIT, which is the condition the fee's two placements rely on.
    ///
    /// The fee enters the ledger's arithmetic PRE-truncation — as a priced line summed in before the
    /// single divide — and the previous release's arithmetic POST-truncation, added to an already
    /// projected figure. Those two land on the same number only while the fee's unit price is an
    /// exact multiple of the micro-unit, and it is, because the configured fee is CENTS and a cent
    /// is ten million nano-units. A fee grammar that grew a sub-cent scale would break the identity
    /// on every billable row, silently, and this is where it would be heard about first.
    #[test]
    fn the_fee_is_an_exact_number_of_micro_units_on_both_sides() {
        let card = card();
        assert!(
            card.per_request_fee_cents() > 0,
            "the fixture charges a fee"
        );
        assert_eq!(
            card.fee_unit_price_nanos() % NANOS_PER_MICRO,
            0,
            "a sub-micro fee would truncate on one side of the comparison and not the other"
        );

        // And the two placements, run: the fee summed in before the projection against the fee added
        // after it, over a row whose TOKEN amount is deliberately not a whole micro-unit.
        let pinned = card.pin();
        let usage = Usage::report(&usage_token(), lines(3, 2)).expect("within the line limit");
        let posting = price(&pinned, "lane-d", &usage, 1, STANDARD_TIER_BP);
        assert_ne!(
            posting.pre_tier_amount() % NANOS_PER_MICRO,
            0,
            "the sub-micro lane must leave a remainder, or the two placements cannot differ"
        );
        let l = lines(3, 2);
        let legacy = derive_spend_micros(&card, [("lane-d", l.as_slice())].into_iter(), 1, true);
        assert_eq!(
            i128::from(micros_of(posting.priced_amount())),
            i128::from(legacy),
            "the fee before the truncation and the fee after it are the same money"
        );
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
                tier_bp: STANDARD_TIER_BP,
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
