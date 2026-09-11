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

use busbar_unit_cost::{micros_of, Priced};
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
/// The one place a lookup's answer becomes a row figure, so there is one answer to "which two
/// numbers does the identity read" rather than one per caller.
///
/// It takes what the LOOKUP said rather than a stored posting, because under the dated history a
/// posting stores quantities and no money at all: the figure being accumulated is derived, at a
/// named snapshot, and taking it from anywhere else would be reading a cache.
pub fn accumulate(snapshot: &mut LedgerSnapshot, row: RowKey, priced: &Priced) {
    let entry = snapshot.entry(row).or_default();
    entry.priced_nanos = entry.priced_nanos.saturating_add(priced.priced_nanos);
    entry.fee_count = entry.fee_count.saturating_add(priced.transaction_count);
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
#[path = "tests/ledger_identity.rs"]
mod tests;
