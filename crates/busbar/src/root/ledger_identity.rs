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

use busbar_unit_cost::{micros_of, CurrencyCode, HistorySeq, HistoryView, Priced};
use busbar_unit_ledger::checkpoint::Checkpoint;
use busbar_unit_ledger::identity::{residual, Residual};
use busbar_unit_ledger::recompute::{
    price_line, recheck, recompute, Divergence, Finding, HistoryArchive, Posting as BookedLine,
    Verdict, Watermark,
};
use busbar_unit_ledger::totals::{Statement, Totals, Unpriced};

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
    entry.fee_count = entry.fee_count.saturating_add(priced.fee_count);
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

// ── the identity over a history of any length ────────────────────────────────────────────────────
//
// Everything above compares two snapshots. Everything below is how the ledger side of one is BUILT
// when the deployment's history has more than the migration's single entry on it — which is to say,
// by re-deriving every booked line through the lookup at the line's own instant, and never by
// reading the figure the line happens to be carrying.

/// The whole money side of a snapshot, in nano-units.
///
/// Before the single projection, deliberately: this is the figure a statement is compared against,
/// and comparing two figures that had each already been truncated would report the projection's own
/// convention as a difference.
pub fn total_nanos(snapshot: &LedgerSnapshot) -> u128 {
    snapshot
        .values()
        .fold(0u128, |sum, row| sum.saturating_add(row.priced_nanos))
}

/// The whole count side of a snapshot.
pub fn total_fee_count(snapshot: &LedgerSnapshot) -> u64 {
    snapshot
        .values()
        .fold(0u64, |sum, row| sum.saturating_add(row.fee_count))
}

/// Build the identity's ledger side from booked lines, priced by lookup AT EACH LINE'S OWN INSTANT.
///
/// The instant is the whole of it. A history with one entry resolves every instant to that entry,
/// so this is arithmetically the pinned card it replaces and the answer is the previous release's
/// to the byte. A history with more than one does not: a line earned before an entry was appended
/// resolves to the entry that was in force when it was earned, and a walk that priced the day at the
/// head would report every line before the newest entry at a rate nobody was charged.
///
/// It reads no cache. [`BookedLine::cached`] is a figure the node computed at settlement, correct
/// until an amendment makes it stale, and a reconciliation whose ledger side summed those figures
/// would be a reconciliation whose answer depended on whether the recompute had reached that line
/// yet. So the quantities go through the lookup again, every time, against the view the caller
/// named — which is why hand-corrupting every cached figure in a book leaves this answer untouched.
///
/// `row_of` is the caller's, because the row width the identity compares at is the previous
/// release's and not the ledger's: the ledger line knows its bucket, its window and its lane, and
/// the provider that completes the row is the composition root's to supply.
///
/// Lines in another currency are skipped rather than summed. Two currencies never sum, so a
/// reconciliation names exactly one.
///
/// Returns the snapshot and every line the lookup could not fully price. **A hole is never a zero.**
/// Two shapes of hole, and both are reported rather than absorbed:
///
/// - No entry of the snapshot covers the line's instant. There is no figure at all, so the line
///   lands on no row and is listed. Folding it in at nothing is how a gap in the history becomes
///   free service that reconciles.
/// - A present card names no rate for the line's lane. The read posture prices what it can — the
///   flat fee is still charged, and it is still real money — so the figure DOES land on its row,
///   and the line is listed beside it. A row that quietly came up a lane short would otherwise
///   report as a residual against the previous release with nothing saying why.
pub fn reprice<'a>(
    view: &HistoryView<'_>,
    currency: CurrencyCode,
    lines: impl IntoIterator<Item = &'a BookedLine>,
    row_of: impl Fn(&BookedLine) -> RowKey,
) -> (LedgerSnapshot, Vec<Unpriced>) {
    let mut snapshot = LedgerSnapshot::new();
    let mut unpriceable = Vec::new();
    for line in lines {
        if line.currency != currency {
            continue;
        }
        match price_line(line, view, line.tier_bp) {
            Ok(priced) => {
                if priced.lane_unpriced {
                    unpriceable.push(Unpriced {
                        node: line.node,
                        node_seq: line.node_seq,
                        why: Divergence::LaneUnpriced {
                            card_seq: priced.card_seq,
                            lane: line.lane.clone(),
                        },
                    });
                }
                accumulate(&mut snapshot, row_of(line), &priced);
            }
            Err(why) => unpriceable.push(Unpriced {
                node: line.node,
                node_seq: line.node_seq,
                why: busbar_unit_ledger::recompute::divergence_of(why),
            }),
        }
    }
    (snapshot, unpriceable)
}

/// How far the identity's ledger side is from a statement cut at the same snapshot, in nano-units.
///
/// Zero is the good one, and the sign says which side is carrying the difference: positive when the
/// statement holds more than the identity accounted for.
///
/// Two walks of the same law, and that is the point. The identity's side folds each line's lookup
/// onto the previous release's row width; the statement's side folds the same lookups onto the
/// book's balance keys. They partition the same lines differently, so a figure that landed on the
/// wrong row on either side moves one of the two sums and not the other — which no single walk
/// could tell apart from a correct one.
///
/// The comparison is in nano-units and before either projection, because the projection is a
/// property of a ROW and the two sides do not have the same rows.
pub fn statement_residual(snapshot: &LedgerSnapshot, statement: &Statement) -> i128 {
    let identity = i128::try_from(total_nanos(snapshot)).unwrap_or(i128::MAX);
    statement.total_nanos().saturating_sub(identity)
}

/// Every booked line whose cached price is not what the lookup says, with the verdict M3's rule
/// gives it.
///
/// It corrects nothing — it is the read a reconciliation report is made of, and a report that
/// repaired the thing it was reporting on would leave nothing to report. [`reconciliation_pass`] is
/// the one that writes back.
pub fn cache_findings(lines: &[BookedLine], archive: &dyn HistoryArchive) -> Vec<Finding> {
    let mut findings = Vec::new();
    for line in lines {
        let outcome = recheck(line, archive);
        for divergence in outcome.divergences {
            findings.push(Finding {
                node: line.node,
                node_seq: line.node_seq,
                divergence,
                verdict: outcome.verdict,
            });
        }
    }
    findings
}

// ── the recompute pass, at boot and on demand ────────────────────────────────────────────────────

/// Why a recompute pass ran.
///
/// On the journalled entry, because the two are not the same evidence. A boot pass says what a node
/// found when it came back — including whether anything moved while it was down — and an on-demand
/// pass says what an operator asked about at a moment they chose. An entry that did not say which
/// would let a node that only ever recomputed at boot look exactly like one that recomputes every
/// tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassTrigger {
    /// The node came up and repriced what it recovered, before it served anything.
    Boot,
    /// An operator, or a tick, asked for one.
    OnDemand,
}

impl std::fmt::Display for PassTrigger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            PassTrigger::Boot => "at boot",
            PassTrigger::OnDemand => "on demand",
        })
    }
}

/// One journalled reconciliation entry: what a pass repriced, and what it found.
///
/// The two finding counts are separate fields and not one total, and that is the whole of M3's rule
/// carried up to the root. A stale cache is what an amendment DOES: the head moved, the figure a
/// line was carrying is behind, and correcting it is routine. A divergence under a head that has not
/// moved cannot have a legitimate cause, so it is the hand edit the recompute exists to catch. One
/// count covering both would let a hundred amendments hide one of those.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconciliationEntry {
    /// Why the pass ran.
    pub trigger: PassTrigger,
    /// The history snapshot every line in it was repriced against. `None` for a node that has read
    /// no configuration yet.
    pub history_seq: Option<HistorySeq>,
    /// Where the watermark is now. Carried so it survives the restart — a watermark that reset at
    /// boot would check nothing on a node that restarts often.
    pub watermark: Watermark,
    /// How many lines the pass looked at.
    pub checked: usize,
    /// How many caches it corrected in place.
    pub corrected: usize,
    /// Everything it disagreed with, stale and alarming alike, in the order it found them.
    pub findings: Vec<Finding>,
}

impl ReconciliationEntry {
    /// How many findings are an amendment catching up.
    pub fn stale(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.verdict == Verdict::Stale)
            .count()
    }

    /// How many are somebody's hand.
    pub fn alarming(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.verdict == Verdict::Alarm)
            .count()
    }

    /// Whether this entry needs an operator, as opposed to a journal line.
    ///
    /// A pass full of stale caches after an amendment is not an alarm; a single one under an unmoved
    /// head is. Routing the second through the first's quiet path would be the way to launder one.
    pub fn alarms(&self) -> bool {
        self.alarming() > 0
    }

    /// Whether every line checked out.
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }
}

impl std::fmt::Display for ReconciliationEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "recompute {} at ", self.trigger)?;
        match self.history_seq {
            Some(seq) => write!(f, "history entry {seq}")?,
            None => f.write_str("no history at all")?,
        }
        write!(
            f,
            ": {} line(s) checked, {} cache(s) corrected, {} stale, {} ALARMING; watermark {}",
            self.checked,
            self.corrected,
            self.stale(),
            self.alarming(),
            self.watermark
        )
    }
}

/// Run a recompute pass over recovered lines and return the entry the journal carries.
///
/// The same act at boot and on demand, and that is deliberate: a boot pass that used a different
/// rule from a tick's would be a second copy of the arbitration, and a second copy of a money rule
/// is how a figure comes to be judged one way in one place and another way in another. The trigger
/// is a fact recorded ABOUT the pass, never an input to it.
///
/// The lines are taken by mutable reference because the cache is the one field a pass writes back,
/// and it writes back only the cache. Every quantity, instant and sequence number on a booked line
/// is left exactly as it was: a booked line is never rewritten.
pub fn reconciliation_pass(
    trigger: PassTrigger,
    watermark: Watermark,
    lines: &mut [BookedLine],
    archive: &dyn HistoryArchive,
) -> ReconciliationEntry {
    let pass = recompute(watermark, lines, archive);
    ReconciliationEntry {
        trigger,
        history_seq: pass.history_seq,
        watermark: pass.watermark,
        checked: pass.checked,
        corrected: pass.corrected,
        findings: pass.findings,
    }
}

/// The pass a node runs before it serves anything, over the lines it recovered.
///
/// From the watermark the last reconciliation entry carried, not from the beginning: the whole point
/// of persisting a mark is that a node which restarts often still gets round to every line, and a
/// boot pass that started over would recheck a day of lines on every restart and reach the head on
/// none of them.
pub fn boot_pass(
    watermark: Watermark,
    lines: &mut [BookedLine],
    archive: &dyn HistoryArchive,
) -> ReconciliationEntry {
    reconciliation_pass(PassTrigger::Boot, watermark, lines, archive)
}

/// The pass an operator, or a tick, asks for.
pub fn on_demand_pass(
    watermark: Watermark,
    lines: &mut [BookedLine],
    archive: &dyn HistoryArchive,
) -> ReconciliationEntry {
    reconciliation_pass(PassTrigger::OnDemand, watermark, lines, archive)
}

// ── a checkpoint is true of one history and no other ─────────────────────────────────────────────

/// Why a checkpoint did not verify at the snapshot it was asked about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointRefusal {
    /// The digest does not match the body. The figures were edited after the seal.
    BodyEdited,
    /// The checkpoint was sealed as of a different history snapshot than the one asked about.
    NotAsOf {
        /// The snapshot it was sealed at.
        sealed: HistorySeq,
        /// The snapshot it was asked about.
        asked: HistorySeq,
    },
    /// The checkpoint names no history at all — it was sealed before there was one.
    PredatesHistory {
        /// The snapshot it was asked about.
        asked: HistorySeq,
    },
}

impl std::fmt::Display for CheckpointRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckpointRefusal::BodyEdited => {
                f.write_str("the sealed body does not digest to the hash it carries")
            }
            CheckpointRefusal::NotAsOf { sealed, asked } => write!(
                f,
                "the checkpoint's figures are true of history entry {sealed}, not {asked}"
            ),
            CheckpointRefusal::PredatesHistory { asked } => write!(
                f,
                "the checkpoint names no history snapshot, so it says nothing about entry {asked}"
            ),
        }
    }
}

impl std::error::Error for CheckpointRefusal {}

/// Verify a checkpoint AT the history snapshot its figures are claimed to be true of — and at no
/// other.
///
/// A checkpoint's totals are a materialised view of a lookup, so on their own they say what the
/// figures were without saying what they were true OF. Verifying a set of figures against a history
/// that did not produce them is not a check that passes or fails: it is a check about nothing. So
/// the snapshot has to match before the digest is worth taking, and a caller that asks about the
/// wrong one is refused rather than answered.
///
/// A checkpoint sealed before the history existed names none, and it is refused at every snapshot
/// while still verifying by digest — which is the point of [`Checkpoint::body_hash_verifies`] being
/// a separate question. Such a checkpoint stays valid forever under the encoding it was sealed with;
/// what it cannot do is claim to be re-derivable at a snapshot it never named. A sealed body is
/// never rewritten, including by an amendment, which is expressed forward as an adjusting entry
/// precisely so that it does not have to be.
pub fn verify_as_of(checkpoint: &Checkpoint, at: HistorySeq) -> Result<(), CheckpointRefusal> {
    match checkpoint.history_seq {
        None => Err(CheckpointRefusal::PredatesHistory { asked: at }),
        Some(sealed) if sealed != at => Err(CheckpointRefusal::NotAsOf { sealed, asked: at }),
        Some(_) if !checkpoint.body_hash_verifies() => Err(CheckpointRefusal::BodyEdited),
        Some(_) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
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

        let (ledger, unpriceable) =
            reprice(&view, CurrencyCode::USD, early.iter().copied(), row_of);
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
}
