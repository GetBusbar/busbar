// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Settlement: a hold plus a usage report becomes a posting, and the books move.
//!
//! ## The one act that closes a unit
//!
//! [`Ledger::settle`] takes the hold BY VALUE. That is not a style choice — it is the whole
//! mechanism by which a hold is settled at most once. A settled hold does not exist any more, so
//! there is no second one to settle, and no amount of care at the call sites is required to make
//! that true. The token is the other half: a posting cannot be built by anything that is not the
//! ledger unit at the moment it is being asked to settle.
//!
//! ## What settling does to the books
//!
//! Two figures move together, and they have to: what was reserved leaves the open-holds column, and
//! what was actually used enters the settled column. Doing one without the other is exactly the
//! shape of imbalance the identity exists to catch, so they are one function and not two.
//!
//! ## ONE GUARD POLICY FOR THIS FILE: EVERY BOOK OPERATOR SATURATES
//!
//! Every arithmetic operator in this file that moves a money column is `saturating_*`. Not some of
//! them, and not "the ones that can overflow" — all of them, because which ones can overflow is a
//! fact about today's callers and the policy has to survive tomorrow's.
//!
//! This file used to hold two policies at once, which is the defect this states away.
//! TWENTY-THREE operators moved a money column with a bare `-=`, `+=` or `-` (counted off the
//! diff, not estimated; a twenty-fourth moved a posting COUNT), and the repricing fold thirty
//! lines below them used `saturating_add` — so the crate's own guarded and unguarded arithmetic
//! sat in one file with nothing to say which was intended. A reader could take either as the house
//! rule. The money sweep that found this counted FOUR of them.
//!
//! SATURATING RATHER THAN CHECKED, for two reasons and they are not the same reason. First, it is
//! what the rest of this crate already does (`totals.rs`, the fold at the bottom of this file,
//! `cost::nanos_sum`), and one policy per file is worth more than the marginally better policy
//! applied to half of it. Second, `post` returns a `Settlement`, not a `Result`, and every caller
//! of it is a settlement that has ALREADY HAPPENED — the value was delivered, the hold is consumed
//! by value, and there is no arm left that could decline. A `checked_` here would have to either
//! unwrap (a panic on the money path) or silently drop the movement (a lost posting), and both are
//! worse than pinning at the ceiling.
//!
//! WHAT SATURATION BUYS, in the numbers it was measured at: `figures.settled += settled` with a
//! bare `+=` panics on overflow in a debug build and WRAPS in a release one, and the wrap is the
//! dangerous half because it is silent. A book holding `i128::MAX - 9.2e18` that settles one more
//! `u64::MAX` posting reads back `-170141183460469231722463931679029329921` — a NEGATIVE settled
//! column on a fully-drawn book — and `Totals::headroom` then reports
//! `+170141183460469231722463931679029329921` of room on it. Pinned at `i128::MAX` instead, the
//! column stays at the ceiling and the headroom stays exhausted. An over-the-top book that reads as
//! over-the-top is a wrong number somebody chases; one that reads as headroom is a wrong number
//! that admits requests.
//!
//! ## The dual write is a hook, not a branch
//!
//! The previous release keeps its own rows, and they must keep being written so that everything
//! reading them sees no change. That is an integrator's binding, not this crate's business, so it
//! is a trait: the ledger tells it what was posted, and what happens next is somebody else's
//! decision. A crate that knew the shape of those rows would be a crate that has to change every
//! time they do.

use std::collections::BTreeMap;

use crate::cost::{HistorySeq, HistoryView};
use busbar_contract::caps::{Grant, Hold, Posted, Usage, WriteMoney};

use crate::legacy::{LegacyPosting, LegacyRows};
use crate::recompute::{price_line, Posting, PricedLine};
use crate::totals::{Book, TotalsKey, WindowStart};

/// An internal record of value delivered with no reservation behind it.
///
/// It is the ledger's own note, not an answer to anybody: the unit that produced it has already run
/// and already posted, and nothing reads this to decide whether it may. What it is for is the two
/// things that cannot be re-derived once the posting is written — WHICH principal ran past what the
/// window could back, and by how much — so the carry into the next window's admissible budget is a
/// figure with a provenance rather than a difference somebody noticed.
///
/// Produced only where the reservation could not be grown to cover the spend. A unit that topped up
/// produces none, which is what makes the presence of one meaningful.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Overdraft {
    /// Whose spend it was.
    pub principal: String,
    /// Which balance carries it.
    pub key: TotalsKey,
    /// Which window it was delivered in.
    pub window: WindowStart,
    /// How much of the posting nothing reserved.
    pub amount: i128,
}

/// What one settlement moved and what it left behind.
#[derive(Debug)]
pub struct Settlement {
    /// The posting. One per hold, because settling consumed the hold.
    pub posted: Posted,
    /// The residual: reserved, never used, and handed back to the slice it was drawn from.
    pub released: i128,
    /// The ledger's note, where the unit ran past everything that could be reserved for it.
    pub overdraft: Option<Overdraft>,
}

/// The ledger unit: the book it keeps, and the previous release's rows it also feeds.
pub struct Ledger {
    book: Book,
    legacy: Option<Box<dyn LegacyRows>>,
}

impl std::fmt::Debug for Ledger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ledger")
            .field("balances", &self.book.len())
            .field("dual_writing", &self.legacy.is_some())
            .finish()
    }
}

impl Default for Ledger {
    fn default() -> Self {
        Ledger::new()
    }
}

impl Ledger {
    /// A ledger with empty books and no dual write.
    pub fn new() -> Self {
        Ledger {
            book: Book::new(),
            legacy: None,
        }
    }

    /// A ledger that also writes onto the previous release's rows.
    pub fn dual_writing(legacy: Box<dyn LegacyRows>) -> Self {
        Ledger {
            book: Book::new(),
            legacy: Some(legacy),
        }
    }

    /// Whether this ledger also writes onto the previous release's rows.
    ///
    /// Read-only, and here so the composition root can assert at boot that the dual write is on.
    /// It is a release requirement rather than a deployment choice — the reconciliation identity
    /// and rollback both depend on it — and the failure mode is silent: a ledger built with
    /// [`Ledger::new`] where [`Ledger::dual_writing`] was meant keeps its own books correctly and
    /// leaves the previous release unable to read anything this one wrote. Nothing observable goes
    /// wrong until somebody tries to roll back.
    #[must_use]
    pub fn is_dual_writing(&self) -> bool {
        self.legacy.is_some()
    }

    /// The books.
    pub fn book(&self) -> &Book {
        &self.book
    }

    /// The books, to be adjusted directly by whatever owns draws, releases and corrections.
    pub fn book_mut(&mut self) -> &mut Book {
        &mut self.book
    }

    /// Settle a hold against what the unit's usage priced at, and move the books.
    ///
    /// The token is required by the capability itself, so this function cannot be reached by
    /// anything that is not the ledger unit mid-settlement. The hold is consumed.
    ///
    /// `priced_nanos` is the money figure, in the unit the reservation is written in; `usage` is
    /// the report it was priced from. See [`busbar_contract::caps::Posted::settle`] for why those are two
    /// arguments and not one.
    pub fn settle(
        &mut self,
        key: &TotalsKey,
        window: WindowStart,
        hold: Hold,
        priced_nanos: u128,
        usage: &Usage,
        token: &Grant<WriteMoney>,
    ) -> Posted {
        self.settle_recording(key, window, hold, priced_nanos, usage, token)
            .posted
    }

    /// Settle, and hand back what the settlement left behind as well as the posting.
    ///
    /// The same act as [`Ledger::settle`] — one function, so the two can never move the books
    /// differently — reporting the residual it released and the overdraft it noted. The composition
    /// root wants both: they are the two facts a posting record cannot carry on its own.
    pub fn settle_recording(
        &mut self,
        key: &TotalsKey,
        window: WindowStart,
        hold: Hold,
        priced_nanos: u128,
        usage: &Usage,
        token: &Grant<WriteMoney>,
    ) -> Settlement {
        let posted = Posted::settle(hold, priced_nanos, usage, token);
        self.post(key, window, posted)
    }

    /// Move the books for a posting that is already built, and note what it left behind.
    ///
    /// The other way in, for the one caller that cannot hand over a hold: the loop's exit path owns
    /// the hold and consumes it there, so what reaches the composition root is the posting. Both
    /// doors move the same three figures through this one function, because a second copy of that
    /// arithmetic is a second answer to the identity.
    pub fn post(&mut self, key: &TotalsKey, window: WindowStart, posted: Posted) -> Settlement {
        let (released, overdraft) = self.move_books(
            key,
            window,
            posted.principal().as_str(),
            posted.reserved(),
            posted.settled(),
            posted.overdraft(),
        );
        Settlement {
            overdraft: (overdraft > 0).then(|| Overdraft {
                principal: posted.principal().as_str().to_string(),
                key: key.clone(),
                window,
                amount: overdraft,
            }),
            released,
            posted,
        }
    }

    /// Move the books for a posting read back off the journal, exactly as [`Ledger::post`] moved
    /// them when it was made.
    ///
    /// The restart half of the one book-moving function. A node that restarts rebuilds its book by
    /// replaying the postings its journal holds, and a replay that moved the figures by a second
    /// copy of the arithmetic would be a second answer to the identity — so both doors go through
    /// the same private function, and the dual write is fed on replay exactly as it was fed live,
    /// because the rows the reconciliation reads are the rows the postings made. Returns the residual
    /// released, as [`Settlement::released`] reports it.
    ///
    /// No token: nothing is being SETTLED here. The settlement happened, under a token, in the
    /// incarnation that wrote the record; this only restores what it did to the figures.
    pub fn replay_post(
        &mut self,
        key: &TotalsKey,
        window: WindowStart,
        principal: &str,
        reserved: u64,
        settled: u64,
        overdraft: u64,
    ) -> i128 {
        self.move_books(key, window, principal, reserved, settled, overdraft)
            .0
    }

    /// THE ONE BOOK-MOVING ARITHMETIC, for a live posting and a replayed one alike.
    ///
    /// Returns what was released and what was carried as overdraft.
    fn move_books(
        &mut self,
        key: &TotalsKey,
        window: WindowStart,
        principal: &str,
        reserved: u64,
        settled: u64,
        overdraft: u64,
    ) -> (i128, i128) {
        let legacy_reserved = reserved;
        let legacy_settled = settled;
        let legacy_overdraft = overdraft;
        let reserved = i128::from(reserved);
        let settled = i128::from(settled);
        let overdraft = i128::from(overdraft);
        let released = reserved.saturating_sub(settled).max(0);

        let figures = self.book.entry(key.clone(), window);
        // Three figures move together, and they have to. What was reserved stops being held; what
        // was used starts being settled; and whatever was reserved and NOT used goes back to the
        // slice it came out of, because it is still drawn and has to be somewhere. Spending more
        // than was reserved is the overdraft, and that is the one part of the amount that was never
        // drawn — which is exactly why the identity subtracts it.
        figures.open_holds = figures.open_holds.saturating_sub(reserved);
        figures.settled = figures.settled.saturating_add(settled);
        figures.open_slice_remainders = figures.open_slice_remainders.saturating_add(released);
        figures.overdraft_carried_out = figures.overdraft_carried_out.saturating_add(overdraft);

        if let Some(rows) = self.legacy.as_mut() {
            // Best effort by design: the previous release's rows are a parity obligation, not the
            // system of record, and failing a settlement because a legacy row would not write would
            // be a behavioural change in the direction nobody wants.
            let _ = rows.write(&LegacyPosting {
                principal: principal.to_string(),
                bucket: key.bucket.as_str().to_string(),
                window_start: window,
                reserved: legacy_reserved,
                settled: legacy_settled,
                overdraft: legacy_overdraft,
            });
        }
        (released, overdraft)
    }

    /// Open a hold's reservation in the books. Called when the door says yes.
    pub fn record_hold_opened(&mut self, key: &TotalsKey, window: WindowStart, reserved: u64) {
        let figures = self.book.entry(key.clone(), window);
        figures.open_holds = figures.open_holds.saturating_add(i128::from(reserved));
    }

    /// Record a draw from the store.
    pub fn record_draw(&mut self, key: &TotalsKey, window: WindowStart, amount: i128) {
        let figures = self.book.entry(key.clone(), window);
        figures.drawn = figures.drawn.saturating_add(amount);
        figures.open_slice_remainders = figures.open_slice_remainders.saturating_add(amount);
    }

    /// Record a slice being spent out of its remainder into a hold.
    pub fn record_slice_spent(&mut self, key: &TotalsKey, window: WindowStart, amount: i128) {
        let figures = self.book.entry(key.clone(), window);
        figures.open_slice_remainders = figures.open_slice_remainders.saturating_sub(amount);
    }

    /// Record a release back to the store.
    pub fn record_release(&mut self, key: &TotalsKey, window: WindowStart, amount: i128) {
        let figures = self.book.entry(key.clone(), window);
        figures.released = figures.released.saturating_add(amount);
        figures.drawn = figures.drawn.saturating_sub(amount);
        figures.open_slice_remainders = figures.open_slice_remainders.saturating_sub(amount);
    }

    /// Record a correction that reverses part of what was settled.
    ///
    /// A pure ledger reversal: the amount leaves the settled column and appears in the adjustments
    /// column, so the value is still accounted for and the identity does not move. `amount` is
    /// positive to give value back to the payer, negative to take more.
    pub fn record_adjustment(&mut self, key: &TotalsKey, window: WindowStart, amount: i128) {
        let figures = self.book.entry(key.clone(), window);
        figures.adjustments = figures.adjustments.saturating_add(amount);
        figures.settled = figures.settled.saturating_sub(amount);
    }

    /// Move value from one window to another, both sides at once.
    ///
    /// Both sides, in one call, because a transfer recorded on only one side is precisely the
    /// imbalance the identity would report — and reporting it would be right, but the defect would
    /// be here rather than wherever the alarm pointed. The value itself moves between the two
    /// windows' slice remainders; the transfer column is what keeps each window's own identity
    /// closed while it does.
    pub fn record_cross_window_transfer(
        &mut self,
        key: &TotalsKey,
        from_window: WindowStart,
        to_window: WindowStart,
        amount: i128,
    ) {
        let out = self.book.entry(key.clone(), from_window);
        out.open_slice_remainders = out.open_slice_remainders.saturating_sub(amount);
        out.cross_window_transfers = out.cross_window_transfers.saturating_add(amount);
        let into = self.book.entry(key.clone(), to_window);
        into.open_slice_remainders = into.open_slice_remainders.saturating_add(amount);
        into.cross_window_transfers = into.cross_window_transfers.saturating_sub(amount);
    }

    /// Record that an amount already posted has not yet been agreed with by the recompute.
    ///
    /// It moves out of the settled column and into the unreconciled one rather than being added
    /// beside it, so the value is counted once. When the recompute agrees, the caller moves it back
    /// with a negative amount.
    ///
    /// Decided rule (ARCHITECTURE.md §4.2): "an unreconciled amount is a MOVE out of settled, never
    /// a parallel tally" — booking it is `unreconciled += A; settled -= A` on the same figure, so
    /// the identity closes with no special case and nothing is reported as settled that the store
    /// has not confirmed.
    pub fn record_unreconciled(&mut self, key: &TotalsKey, window: WindowStart, amount: i128) {
        let figures = self.book.entry(key.clone(), window);
        figures.unreconciled = figures.unreconciled.saturating_add(amount);
        figures.settled = figures.settled.saturating_sub(amount);
    }

    /// Book one adjusting entry: **the only way a history amendment moves money.**
    ///
    /// A booked line is never rewritten, so `settled` does not move — not by a nano-unit, not on
    /// the line the amendment repriced and not on any other. What moves is the delta, and it moves
    /// on two columns at once:
    ///
    /// - `adjustments`, which is the cell the identity already carries, so no term is added to it
    ///   and nothing that reads a residual has to learn a new name;
    /// - `drawn`, by the same figure, because a bill that went up by `delta` is `delta` more value
    ///   that has to have come out of the store, and a bill that went down is that much handed back.
    ///
    /// Both sides of the identity therefore move by exactly the same amount and the residual is
    /// unchanged: zero before the amendment, zero after it. That is the whole reason an amendment
    /// is expressed FORWARD as an adjusting entry rather than backward as an edit — a window sealed
    /// into a signed checkpoint cannot be rewritten, and it does not have to be.
    pub fn record_repricing(&mut self, entry: &Repricing) {
        let figures = self.book.entry(entry.key.clone(), entry.window);
        figures.adjustments = figures.adjustments.saturating_add(entry.delta);
        figures.drawn = figures.drawn.saturating_add(entry.delta);
    }
}

/// One adjusting entry: what a history amendment did to one balance in one window.
///
/// It is the permanent record of a correction, and it is never collapsed into the lines it
/// describes. Both figures are on it — what the balance was under the old history and what it is
/// under the new — so the original bill and the correction are both readable forever, which is the
/// property that makes an invoice sent last month reproducible this month.
///
/// **Per `(window, balance)` rather than per line, deliberately.** A day's lines for one principal
/// are one line on an invoice, and the correction has to be legible beside that line. Per-line
/// records would be correct and unreadable, and would multiply the journal by the traffic rate
/// rather than by the number of balances. [`Repricing::postings`] carries how many lines the entry
/// covers, so the granularity it summarises is stated rather than assumed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repricing {
    /// Which balance.
    pub key: TotalsKey,
    /// Which window.
    pub window: WindowStart,
    /// The history head BEFORE the amendment.
    pub from_seq: HistorySeq,
    /// The history head AFTER it.
    pub to_seq: HistorySeq,
    /// The entry the lines resolved to under `from_seq`.
    pub old_card_seq: HistorySeq,
    /// The entry they resolve to under `to_seq`. An amendment does not delete what it corrects; it
    /// out-ranks it, which is why both numbers are worth keeping.
    pub new_card_seq: HistorySeq,
    /// The quantities, summed over the lines the entry covers, per class.
    pub quantities: Vec<PricedLine>,
    /// The request fees those lines carry between them.
    pub fee_count: u64,
    /// What the balance came to under the old history.
    pub old_nanos: i128,
    /// What it comes to under the new one.
    pub new_nanos: i128,
    /// `new_nanos - old_nanos`: **the only figure that moves a balance.** Positive when the
    /// amendment raised the bill.
    pub delta: i128,
    /// Who signed the amendment.
    pub operator_fingerprint: String,
    /// The hash of the reason they gave. The reason is free text and is hashed into the record
    /// rather than being the record.
    pub reason_hash: [u8; 32],
    /// How many lines the entry covers.
    pub postings: u64,
}

/// Work out the adjusting entries an amendment owes, without moving anything.
///
/// The affected set is DERIVED rather than declared: a line is affected when the entry it resolves
/// to under `after` is not the entry it resolved to under `before`. That is the same set as "every
/// line whose instant falls in the amended interval", computed from the histories themselves, so a
/// caller cannot name an interval and an affected set that disagree.
///
/// It reads no clock, no store and no configuration, and it moves nothing. The caller signs the
/// entries, journals them, and only then hands each to [`Ledger::record_repricing`] — which is what
/// lets an amendment be refused after its effects are known and before any of them have happened.
///
/// Balances whose figure did not move produce no entry: an amendment that repriced a window nobody
/// used is a history append and nothing else, and emitting a zero-delta record for it would put
/// noise in the one journal an auditor reads line by line.
pub fn adjusting_entries<'a>(
    before: &HistoryView<'_>,
    after: &HistoryView<'_>,
    operator_fingerprint: &str,
    reason_hash: [u8; 32],
    lines: impl IntoIterator<Item = &'a Posting>,
) -> Vec<Repricing> {
    // Grouped in key order, because the entries are journalled and signed and a batch whose order
    // depended on a hash map's iteration would verify on the node that made it and nowhere else.
    let mut groups: BTreeMap<(TotalsKey, WindowStart), Repricing> = BTreeMap::new();
    for line in lines {
        let (Ok(old), Ok(new)) = (
            price_line(line, before, line.tier_bp),
            price_line(line, after, line.tier_bp),
        ) else {
            // A line that cannot be priced under one of the two histories is not something an
            // adjusting entry can describe: there is no old figure or no new one to state. It is a
            // finding for the recompute, which reports holes as refusals rather than as zeros.
            continue;
        };
        if old.card_seq == new.card_seq {
            continue;
        }
        let entry = groups
            .entry((line.key.clone(), line.window_start))
            .or_insert_with(|| Repricing {
                key: line.key.clone(),
                window: line.window_start,
                from_seq: before.seq(),
                to_seq: after.seq(),
                old_card_seq: old.card_seq,
                new_card_seq: new.card_seq,
                quantities: Vec::new(),
                fee_count: 0,
                old_nanos: 0,
                new_nanos: 0,
                delta: 0,
                operator_fingerprint: operator_fingerprint.to_string(),
                reason_hash,
                postings: 0,
            });
        for line in &line.lines {
            match entry
                .quantities
                .iter_mut()
                .find(|held| held.class == line.class)
            {
                Some(held) => held.quantity = held.quantity.saturating_add(line.quantity),
                None => entry.quantities.push(line.clone()),
            }
        }
        entry.fee_count = entry.fee_count.saturating_add(old.fee_count);
        entry.old_nanos = entry
            .old_nanos
            .saturating_add(i128::try_from(old.priced_nanos).unwrap_or(i128::MAX));
        entry.new_nanos = entry
            .new_nanos
            .saturating_add(i128::try_from(new.priced_nanos).unwrap_or(i128::MAX));
        entry.postings = entry.postings.saturating_add(1);
    }
    groups
        .into_values()
        .filter_map(|mut entry| {
            entry.delta = entry.new_nanos.saturating_sub(entry.old_nanos);
            // Class order, because the entry is journalled and signed and a batch whose field order
            // came out of an insertion sequence would digest differently on two nodes that saw the
            // same lines in a different order.
            entry.quantities.sort_by_key(|q| q.class);
            (entry.delta != 0).then_some(entry)
        })
        .collect()
}
