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
#[path = "tests/ledger_identity.rs"]
mod tests;
