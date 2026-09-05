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
//! ## The dual write is a hook, not a branch
//!
//! The previous release keeps its own rows, and they must keep being written so that everything
//! reading them sees no change. That is an integrator's binding, not this crate's business, so it
//! is a trait: the ledger tells it what was posted, and what happens next is somebody else's
//! decision. A crate that knew the shape of those rows would be a crate that has to change every
//! time they do.

use busbar_caps::{Hold, LedgerToken, Posted, Usage};

use crate::legacy::{LegacyPosting, LegacyRows};
use crate::totals::{Book, TotalsKey, WindowStart};

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

    /// The books.
    pub fn book(&self) -> &Book {
        &self.book
    }

    /// The books, to be adjusted directly by whatever owns draws, releases and corrections.
    pub fn book_mut(&mut self) -> &mut Book {
        &mut self.book
    }

    /// Settle a hold against what the unit used, and move the books.
    ///
    /// The token is required by the capability itself, so this function cannot be reached by
    /// anything that is not the ledger unit mid-settlement. The hold is consumed.
    pub fn settle(
        &mut self,
        key: &TotalsKey,
        window: WindowStart,
        hold: Hold,
        usage: &Usage,
        token: &LedgerToken,
    ) -> Posted {
        let reserved = i128::from(hold.reserved());
        let posted = Posted::settle(hold, usage, token);
        let settled = i128::from(posted.settled());
        let overdraft = i128::from(posted.overdraft());

        let figures = self.book.entry(key.clone(), window);
        // Three figures move together, and they have to. What was reserved stops being held; what
        // was used starts being settled; and whatever was reserved and NOT used goes back to the
        // slice it came out of, because it is still drawn and has to be somewhere. Spending more
        // than was reserved is the overdraft, and that is the one part of the amount that was never
        // drawn — which is exactly why the identity subtracts it.
        figures.open_holds -= reserved;
        figures.settled += settled;
        figures.open_slice_remainders += (reserved - settled).max(0);
        figures.overdraft_carried_out += overdraft;

        if let Some(rows) = self.legacy.as_mut() {
            // Best effort by design: the previous release's rows are a parity obligation, not the
            // system of record, and failing a settlement because a legacy row would not write would
            // be a behavioural change in the direction nobody wants.
            let _ = rows.write(&LegacyPosting {
                principal: posted.principal().as_str().to_string(),
                bucket: key.bucket.as_str().to_string(),
                window_start: window,
                reserved: posted.reserved(),
                settled: posted.settled(),
                overdraft: posted.overdraft(),
            });
        }
        posted
    }

    /// Open a hold's reservation in the books. Called when the door says yes.
    pub fn record_hold_opened(&mut self, key: &TotalsKey, window: WindowStart, reserved: u64) {
        self.book.entry(key.clone(), window).open_holds += i128::from(reserved);
    }

    /// Record a draw from the store.
    pub fn record_draw(&mut self, key: &TotalsKey, window: WindowStart, amount: i128) {
        let figures = self.book.entry(key.clone(), window);
        figures.drawn += amount;
        figures.open_slice_remainders += amount;
    }

    /// Record a slice being spent out of its remainder into a hold.
    pub fn record_slice_spent(&mut self, key: &TotalsKey, window: WindowStart, amount: i128) {
        self.book.entry(key.clone(), window).open_slice_remainders -= amount;
    }

    /// Record a release back to the store.
    pub fn record_release(&mut self, key: &TotalsKey, window: WindowStart, amount: i128) {
        let figures = self.book.entry(key.clone(), window);
        figures.released += amount;
        figures.drawn -= amount;
        figures.open_slice_remainders -= amount;
    }

    /// Record a correction that reverses part of what was settled.
    ///
    /// A pure ledger reversal: the amount leaves the settled column and appears in the adjustments
    /// column, so the value is still accounted for and the identity does not move. `amount` is
    /// positive to give value back to the payer, negative to take more.
    pub fn record_adjustment(&mut self, key: &TotalsKey, window: WindowStart, amount: i128) {
        let figures = self.book.entry(key.clone(), window);
        figures.adjustments += amount;
        figures.settled -= amount;
    }

    /// Record a correction inside the open window that also gives headroom back to the store.
    ///
    /// The reversal first, then the release. Only the open window may do this: a closed window's
    /// budget has already been reported, so handing headroom back to it would change a figure
    /// somebody has already read.
    pub fn record_adjustment_releasing(
        &mut self,
        key: &TotalsKey,
        window: WindowStart,
        amount: i128,
    ) {
        self.record_adjustment(key, window, amount);
        self.record_release(key, window, amount);
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
        out.open_slice_remainders -= amount;
        out.cross_window_transfers += amount;
        let into = self.book.entry(key.clone(), to_window);
        into.open_slice_remainders += amount;
        into.cross_window_transfers -= amount;
    }

    /// Record that an amount already posted has not yet been agreed with by the recompute.
    ///
    /// It moves out of the settled column and into the unreconciled one rather than being added
    /// beside it, so the value is counted once. When the recompute agrees, the caller moves it back
    /// with a negative amount.
    ///
    /// contract: the architecture names "Σ unreconciled" as one of the sealed figures and as a term
    /// of the identity, but does not say whether an unreconciled amount is also counted as settled.
    /// Treating it as a MOVE keeps the identity closed with no special case; treating it as a
    /// parallel tally would need the identity to subtract it somewhere. The integrator should
    /// confirm which reading the reporting surfaces expect.
    pub fn record_unreconciled(&mut self, key: &TotalsKey, window: WindowStart, amount: i128) {
        let figures = self.book.entry(key.clone(), window);
        figures.unreconciled += amount;
        figures.settled -= amount;
    }
}
