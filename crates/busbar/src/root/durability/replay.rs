// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The book rebuild: replaying the journal's chain back into a ledger, and the reconciliation that
//! compares what the chain rebuilds against what the book holds.
//!
//! Split out of `durability.rs` (structure-lint) — a private child module reached only through the
//! parent, so nothing outside `durability` names it directly; the parent brings its items into
//! scope and re-exports the two that are part of the module's public surface, [`Recoverable`] and
//! [`JournalDisagreement`], so no caller's path changes.

use super::*;

/// A reservation's movement on the book: drawn into the slice and spent out of it into the hold.
pub(super) fn apply_opened(
    ledger: &mut Ledger,
    key: &TotalsKey,
    window: WindowStart,
    reserved: u64,
) {
    let amount = i128::from(reserved);
    ledger.record_draw(key, window, amount);
    ledger.record_slice_spent(key, window, amount);
    ledger.record_hold_opened(key, window, reserved);
}

/// A hold the replay found open, with the reservation it derived for it.
struct OpenHold {
    hold: HoldOpened,
    reserved: u64,
    /// Whether a dispatch record for the unit was durable.
    dispatched: bool,
    /// The unit's last durable accrual checkpoint: its counts and their epoch.
    checkpoint: Option<(UnitCounts, u64)>,
}

/// A hold a predecessor left open, with what the chain says happened to its unit before the crash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recoverable {
    /// The hold.
    pub hold: HoldOpened,
    /// Whether a dispatch record for the unit was durable: something left the node.
    pub dispatched: bool,
    /// The unit's last durable accrual checkpoint — counts and their epoch — if it made one.
    pub checkpoint: Option<(UnitCounts, u64)>,
}

/// What replaying a chain into a book left over.
pub(super) struct Replayed {
    /// Holds opened and closed by no posting of the same unit, in chain order.
    pub(super) open: Vec<Recoverable>,
    /// Idempotency claims taken, not voided, whose unit no hold record ever names, in chain order.
    pub(super) unheld_claims: Vec<ClaimTaken>,
    /// The highest incarnation any record carried; 0 on a chain with none.
    pub(super) incarnation: u64,
    /// Records that look like this build's money records and could not be read.
    pub(super) unreadable: Vec<String>,
    /// Counts rows whose pricing refused, in chain order.
    pub(super) refused: Vec<Posting>,
    /// Every posting read, with the figures the replay derived for it, in chain order — kept only
    /// when the caller asked to read the chain back.
    pub(super) read: Vec<Posting>,
    /// The counted lines the read-time totals price, in chain order (H6): the same set the live
    /// book appended as each posting was journalled.
    pub(super) counted: Vec<CountedLine>,
    /// The balances a figure with no counts behind it moved: a record of the figures era.
    pub(super) uncounted: std::collections::BTreeSet<(TotalsKey, WindowStart)>,
}

impl Replayed {
    /// What a chain that could not be read at all leaves: nothing to rebuild from.
    pub(super) fn nothing() -> Self {
        Replayed {
            open: Vec::new(),
            unheld_claims: Vec::new(),
            incarnation: 0,
            unreadable: Vec::new(),
            refused: Vec::new(),
            read: Vec::new(),
            counted: Vec::new(),
            uncounted: std::collections::BTreeSet::new(),
        }
    }
}

/// REBUILD A BOOK FROM THE CHAIN, in chain order: every hold opened, every settlement posted — each
/// figure DERIVED from the record's counts at its epoch against `history` (#71, #79).
///
/// Reads every `Transaction` record, not only the migration marker. Audit records share the class
/// and are passed over; a posting the chain cannot place on a balance is named rather than
/// silently skipped. A record of the era that carried figures is read as written.
///
/// A settlement closes the hold its unit opened, and releases what that hold reserved; what it
/// settled is its counts priced, and what nothing reserved is carried out — the settlement's own
/// arithmetic, restated over derived figures. A counts row whose pricing refuses is kept as a
/// refused row, and moves no figure (#42).
pub(super) fn replay_into(
    ledger: &mut Ledger,
    records: &[JournalRecord],
    history: Option<&HistoryView<'_>>,
    keep: bool,
) -> Replayed {
    let mut replay = Replayer::new(history, keep);
    for record in records {
        replay.step(ledger, record);
    }
    replay.finish()
}

/// THE CHAIN REPLAYED ONE RECORD AT A TIME into a ledger, with what the replay leaves over: the
/// walk [`replay_into`] runs whole and [`super::Durability::each_held_checkpoint`] pauses at each
/// held checkpoint's record, so both derive every figure through the one body below.
pub(super) struct Replayer<'v, 'h> {
    history: Option<&'v HistoryView<'h>>,
    keep: bool,
    open: Vec<OpenHold>,
    held_units: std::collections::BTreeSet<(u64, TotalsKey, WindowStart, u64)>,
    claims: Vec<ClaimTaken>,
    incarnation: u64,
    unreadable: Vec<String>,
    refused: Vec<Posting>,
    read: Vec<Posting>,
    counted: Vec<CountedLine>,
    uncounted: std::collections::BTreeSet<(TotalsKey, WindowStart)>,
}

impl<'v, 'h> Replayer<'v, 'h> {
    /// A replay at its start, deriving through `history`; `keep` keeps every posting read.
    pub(super) fn new(history: Option<&'v HistoryView<'h>>, keep: bool) -> Self {
        Replayer {
            history,
            keep,
            open: Vec::new(),
            held_units: std::collections::BTreeSet::new(),
            claims: Vec::new(),
            incarnation: 0,
            unreadable: Vec::new(),
            refused: Vec::new(),
            read: Vec::new(),
            counted: Vec::new(),
            uncounted: std::collections::BTreeSet::new(),
        }
    }

    /// Replay one record into `ledger`. A record of another class than a transaction moves nothing.
    pub(super) fn step(&mut self, ledger: &mut Ledger, record: &JournalRecord) {
        if record.class != RecordClass::Transaction {
            return;
        }
        if let Some(hold) = HoldOpened::from_record(record) {
            self.incarnation = self.incarnation.max(hold.incarnation);
            let reserved = hold.reserved(self.history);
            apply_opened(ledger, &hold.key, hold.window, reserved);
            self.held_units.insert(hold.unit());
            self.open.push(OpenHold {
                hold,
                reserved,
                dispatched: false,
                checkpoint: None,
            });
        } else if let Some(mark) = UnitMark::from_record(record) {
            self.incarnation = self.incarnation.max(mark.incarnation);
            // A mark names the unit whose hold it marks; one for a unit whose hold is closed, or
            // was never opened, marks nothing a recovery could act on.
            if let Some(held) = self
                .open
                .iter_mut()
                .find(|held| held.hold.unit() == mark.unit())
            {
                match mark.mark {
                    Mark::Dispatched => held.dispatched = true,
                    Mark::Accrued { counts, arrived_ms } => {
                        held.checkpoint = Some((counts, arrived_ms));
                    }
                }
            }
        } else if let Some(claim) = ClaimRecord::from_record(record) {
            self.incarnation = self.incarnation.max(claim.taken.incarnation);
            if claim.voided {
                self.claims.retain(|taken| *taken != claim.taken);
            } else {
                self.claims.push(claim.taken);
            }
        } else if let Some(mut posting) = Posting::from_record(record) {
            self.incarnation = self.incarnation.max(posting.incarnation);
            // What the read-time totals keep of it, by the rule the live book applies (H6), read
            // off the record as written — before any figure is derived onto it.
            booked_of(&posting, record.node_seq).keep(&mut self.counted, &mut self.uncounted);
            if posting.kind == PostingKind::Carry {
                if self.keep {
                    self.read.push(posting);
                }
                return;
            }
            // The hold this posting closes, if it closes one: a settlement of the same unit, or the
            // counts row a hold whose counts priced to nothing closes with (`close_counted`).
            let unit = (
                posting.incarnation,
                posting.key.clone(),
                posting.window,
                posting.mono,
            );
            let closes = matches!(posting.kind, PostingKind::Settlement | PostingKind::Counted)
                .then(|| self.open.iter().position(|held| held.hold.unit() == unit))
                .flatten()
                .map(|at| self.open.remove(at).reserved);
            let figures = match posting.era {
                RecordEra::Figures => figures_as_written(&posting),
                RecordEra::Counts => derived_figures(&posting, closes, self.history),
            };
            match figures {
                Ok(Some(figures)) => {
                    ledger.replay_post(&posting.key, posting.window, &posting.principal, figures);
                    if self.keep {
                        posting.reserved = i128::from(figures.reserved);
                        posting.settled = i128::from(figures.settled);
                        posting.overdraft = i128::from(figures.overdraft());
                        self.read.push(posting);
                    }
                }
                // A counts row that priced to nothing moves nothing.
                Ok(None) => {
                    if self.keep {
                        self.read.push(posting);
                    }
                }
                Err(Negative) => self.unreadable.push(format!(
                    "node {} record {}: a posting with a negative figure",
                    record.node, record.node_seq
                )),
                Err(Refused(why)) => {
                    // The fact is kept and every read over its balance refuses. A settlement that
                    // closed a hold still hands its reservation back: what it consumed has no
                    // figure, and the reservation is not a charge.
                    if let Some(reserved) = closes {
                        ledger.replay_post(
                            &posting.key,
                            posting.window,
                            &posting.principal,
                            Figures {
                                reserved,
                                ..Figures::default()
                            },
                        );
                    }
                    posting.refusal = Some(why);
                    if self.keep {
                        self.read.push(posting.clone());
                    }
                    self.refused.push(posting);
                }
            }
        } else if looks_like_a_posting(record) {
            self.unreadable.push(format!(
                "node {} record {}: a posting this build cannot place on a balance",
                record.node, record.node_seq
            ));
        }
    }

    /// What the replay left over.
    pub(super) fn finish(self) -> Replayed {
        Replayed {
            open: self
                .open
                .into_iter()
                .map(|held| Recoverable {
                    hold: held.hold,
                    dispatched: held.dispatched,
                    checkpoint: held.checkpoint,
                })
                .collect(),
            unheld_claims: self
                .claims
                .into_iter()
                .filter(|claim| !self.held_units.contains(&claim.unit()))
                .collect(),
            incarnation: self.incarnation,
            unreadable: self.unreadable,
            refused: self.refused,
            read: self.read,
            counted: self.counted,
            uncounted: self.uncounted,
        }
    }
}

/// Why a posting read back moves no figure.
enum Unplaced {
    /// A figures-era record holding a negative figure.
    Negative,
    /// A counts-era record whose counts the card refuses to price, and why.
    Refused(String),
}
use Unplaced::{Negative, Refused};

/// How many billable requests a posting is: its counts' fee count, and none on a record that
/// carries no counts.
fn fee_count_of(posting: &Posting) -> u64 {
    posting.counts.as_ref().map_or(0, |counts| counts.fee_count)
}

/// The three figures a figures-era record holds, as written. `None` for a counts row, which
/// moved no balance when it was written.
fn figures_as_written(posting: &Posting) -> Result<Option<Figures>, Unplaced> {
    if posting.kind == PostingKind::Counted {
        return match &posting.refusal {
            Some(why) => Err(Refused(why.clone())),
            None => Ok(None),
        };
    }
    // The overdraft a figures-era record wrote is still read, so a negative one is still unplaced;
    // the book carries the one the ledger reckons from the other two (`Figures::overdraft`).
    match (
        u64::try_from(posting.reserved),
        u64::try_from(posting.settled),
        u64::try_from(posting.overdraft),
    ) {
        (Ok(reserved), Ok(settled), Ok(_)) => Ok(Some(Figures {
            reserved,
            settled,
            fee_count: fee_count_of(posting),
        })),
        _ => Err(Negative),
    }
}

/// The three figures a counts-era record DERIVES: the reservation of the hold it closes, its counts
/// priced at their epoch, and the part nothing reserved. `None` for a counts row that priced to
/// nothing.
fn derived_figures(
    posting: &Posting,
    closes: Option<u64>,
    history: Option<&HistoryView<'_>>,
) -> Result<Option<Figures>, Unplaced> {
    let reserved = closes.unwrap_or(0);
    // A line refused because its plane reported a class nobody declared stays refused: the
    // declaration is a fact about the unit when it was written, and no card — present, absent or
    // amended — can price a class that was never declared.
    if posting.flags.contains(PostingFlags::UNDECLARED) {
        return Err(Refused(format!(
            "{}({:?})",
            super::UNDECLARED_CLASS,
            posting
                .counts
                .as_ref()
                .map(|counts| counts.classes.keys().collect::<Vec<_>>())
                .unwrap_or_default()
        )));
    }
    let settled = match &posting.counts {
        None => 0,
        Some(counts) => price_counts(history, counts, posting.arrived_ms)
            .and_then(|nanos| u64::try_from(nanos).map_err(|_| MoneyError::Overflow))
            .map_err(|refused| Refused(format!("{refused:?}")))?,
    };
    // A counts row that priced to nothing moves nothing, unless it closes a hold: then it hands
    // that hold's reservation back, as the live book did when it closed it.
    if posting.kind == PostingKind::Counted && settled == 0 && closes.is_none() {
        return Ok(None);
    }
    Ok(Some(Figures {
        reserved,
        settled,
        fee_count: fee_count_of(posting),
    }))
}

/// A posting of the figures era without the tail: a balance display, a window and three figures and
/// a version, and nothing else — or a counts-era record this build cannot parse. An audit record
/// never has either shape: it opens with two digests.
fn looks_like_a_posting(record: &JournalRecord) -> bool {
    let mut body = BodyReader::new(&record.body);
    let Some(first) = body.text() else {
        return false;
    };
    if first == POSTING_COUNTS || first == HOLD_OPENED_COUNTS {
        return true;
    }
    first.contains('/')
        && body.num().is_some()
        && body.figure().is_some()
        && body.figure().is_some()
        && body.figure().is_some()
        && body.num().is_some()
}

/// Whether two readings of one balance moved it the same way. `settled` is read together with
/// `unreconciled`: a posting the log has not confirmed moves between those two, not out of the book.
pub(super) fn same_movement(journal: &Totals, book: &Totals) -> bool {
    journal.drawn == book.drawn
        && journal.open_holds == book.open_holds
        && journal.open_slice_remainders == book.open_slice_remainders
        && journal.overdraft_carried_out == book.overdraft_carried_out
        && journal.settled.saturating_add(journal.unreconciled)
            == book.settled.saturating_add(book.unreconciled)
}

/// Something the restart reconciliation found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalDisagreement {
    /// The chain, or a money record on it, could not be read.
    Unreadable(String),
    /// A balance the book and the chain disagree about.
    Balance {
        /// Which balance.
        key: TotalsKey,
        /// Which window.
        window: WindowStart,
        /// What the chain rebuilds it to. Boxed, as the book's reading beside it is: a finding is
        /// rare and a full set of figures is wide.
        journal: Box<Totals>,
        /// What the book holds.
        book: Box<Totals>,
    },
    /// The refused counts rows the node holds are not the ones its chain holds.
    RefusedRows {
        /// How many the chain rebuilds.
        journal: usize,
        /// How many the node holds.
        book: usize,
    },
    /// Journal bytes were set aside at boot: a whole record altered after it was written, or damage
    /// with acknowledged records behind it. The text names the segment, the offset and the records.
    Quarantined(String),
    /// A unit whose hold was left OPEN at boot because a quarantined record names it (or because a
    /// quarantined record could not be read at all, so no open hold can be cleared of it). Recovery
    /// would have settled it at its checkpoint — a zero line for a unit that may have settled — so
    /// it is left for the operator, never settled on a guess.
    OpenQuarantined {
        /// Which balance.
        key: TotalsKey,
        /// Which window.
        window: WindowStart,
        /// The unit's monotonic reading, which with the balance and window names it.
        mono: u64,
    },
    /// A signed rate correction on the chain whose base entry the rebuilt dated history does not
    /// hold (#79). It is not rebuilt: its window prices at the card the rebuilt history holds, and
    /// this finding is the operator's notice that a signed correction is not in force.
    CorrectionRefused(crate::root::kernel::CorrectionRefused),
}

impl std::fmt::Display for JournalDisagreement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JournalDisagreement::Unreadable(why) => f.write_str(why),
            JournalDisagreement::Quarantined(what) => write!(f, "journal quarantine: {what}"),
            JournalDisagreement::CorrectionRefused(refused) => write!(f, "{refused}"),
            JournalDisagreement::OpenQuarantined { key, window, mono } => write!(
                f,
                "{key} in the window opening at {window}: unit {mono} is left OPEN-QUARANTINED — a \
                 quarantined journal record names it, so it is not settled at its checkpoint"
            ),
            JournalDisagreement::RefusedRows { journal, book } => write!(
                f,
                "the journal rebuilds {journal} refused counts row(s), the node holds {book}"
            ),
            JournalDisagreement::Balance {
                key,
                window,
                journal,
                book,
            } => write!(
                f,
                "{key} in the window opening at {window}: the journal rebuilds settled {} / held {} \
                 / drawn {}, the book holds settled {} / held {} / drawn {}",
                journal.settled.saturating_add(journal.unreconciled),
                journal.open_holds,
                journal.drawn,
                book.settled.saturating_add(book.unreconciled),
                book.open_holds,
                book.drawn
            ),
        }
    }
}
