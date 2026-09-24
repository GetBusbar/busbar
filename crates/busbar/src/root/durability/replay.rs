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
    let mut open: Vec<OpenHold> = Vec::new();
    let mut held_units: std::collections::BTreeSet<(u64, TotalsKey, WindowStart, u64)> =
        std::collections::BTreeSet::new();
    let mut claims: Vec<ClaimTaken> = Vec::new();
    let mut incarnation = 0;
    let mut unreadable = Vec::new();
    let mut refused = Vec::new();
    let mut read = Vec::new();
    for record in records
        .iter()
        .filter(|r| r.class == RecordClass::Transaction)
    {
        if let Some(hold) = HoldOpened::from_record(record) {
            incarnation = incarnation.max(hold.incarnation);
            let reserved = hold.reserved(history);
            apply_opened(ledger, &hold.key, hold.window, reserved);
            held_units.insert(hold.unit());
            open.push(OpenHold {
                hold,
                reserved,
                dispatched: false,
                checkpoint: None,
            });
        } else if let Some(mark) = UnitMark::from_record(record) {
            incarnation = incarnation.max(mark.incarnation);
            // A mark names the unit whose hold it marks; one for a unit whose hold is closed, or
            // was never opened, marks nothing a recovery could act on.
            if let Some(held) = open.iter_mut().find(|held| held.hold.unit() == mark.unit()) {
                match mark.mark {
                    Mark::Dispatched => held.dispatched = true,
                    Mark::Accrued { counts, arrived_ms } => {
                        held.checkpoint = Some((counts, arrived_ms));
                    }
                }
            }
        } else if let Some(claim) = ClaimRecord::from_record(record) {
            incarnation = incarnation.max(claim.taken.incarnation);
            if claim.voided {
                claims.retain(|taken| *taken != claim.taken);
            } else {
                claims.push(claim.taken);
            }
        } else if let Some(mut posting) = Posting::from_record(record) {
            incarnation = incarnation.max(posting.incarnation);
            if posting.kind == PostingKind::Carry {
                if keep {
                    read.push(posting);
                }
                continue;
            }
            // The hold this posting closes, if it closes one: a settlement of the same unit.
            let unit = (
                posting.incarnation,
                posting.key.clone(),
                posting.window,
                posting.mono,
            );
            let closes = (posting.kind == PostingKind::Settlement)
                .then(|| open.iter().position(|held| held.hold.unit() == unit))
                .flatten()
                .map(|at| open.remove(at).reserved);
            let figures = match posting.era {
                RecordEra::Figures => figures_as_written(&posting),
                RecordEra::Counts => derived_figures(&posting, closes.unwrap_or(0), history),
            };
            match figures {
                Ok(Some(figures)) => {
                    ledger.replay_post(&posting.key, posting.window, &posting.principal, figures);
                    if keep {
                        posting.reserved = i128::from(figures.reserved);
                        posting.settled = i128::from(figures.settled);
                        posting.overdraft = i128::from(figures.overdraft);
                        read.push(posting);
                    }
                }
                // A counts row that priced to nothing moves nothing.
                Ok(None) => {
                    if keep {
                        read.push(posting);
                    }
                }
                Err(Negative) => unreadable.push(format!(
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
                    if keep {
                        read.push(posting.clone());
                    }
                    refused.push(posting);
                }
            }
        } else if looks_like_a_posting(record) {
            unreadable.push(format!(
                "node {} record {}: a posting this build cannot place on a balance",
                record.node, record.node_seq
            ));
        }
    }
    Replayed {
        open: open
            .into_iter()
            .map(|held| Recoverable {
                hold: held.hold,
                dispatched: held.dispatched,
                checkpoint: held.checkpoint,
            })
            .collect(),
        unheld_claims: claims
            .into_iter()
            .filter(|claim| !held_units.contains(&claim.unit()))
            .collect(),
        incarnation,
        unreadable,
        refused,
        read,
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
    match (
        u64::try_from(posting.reserved),
        u64::try_from(posting.settled),
        u64::try_from(posting.overdraft),
    ) {
        (Ok(reserved), Ok(settled), Ok(overdraft)) => Ok(Some(Figures {
            reserved,
            settled,
            overdraft,
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
    reserved: u64,
    history: Option<&HistoryView<'_>>,
) -> Result<Option<Figures>, Unplaced> {
    let settled = match &posting.counts {
        None => 0,
        Some(counts) => price_counts(history, counts, posting.arrived_ms)
            .and_then(|nanos| u64::try_from(nanos).map_err(|_| MoneyError::Overflow))
            .map_err(|refused| Refused(format!("{refused:?}")))?,
    };
    if posting.kind == PostingKind::Counted && settled == 0 {
        return Ok(None);
    }
    Ok(Some(Figures {
        reserved,
        settled,
        overdraft: settled.saturating_sub(reserved),
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
}

impl std::fmt::Display for JournalDisagreement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JournalDisagreement::Unreadable(why) => f.write_str(why),
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
