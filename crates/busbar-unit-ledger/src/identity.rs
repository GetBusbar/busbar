// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The one identity, as a pure function.
//!
//! ## What it says
//!
//! For one bucket, in one dimension, at one scope, in one window, measured as a CHANGE since the
//! last sealed checkpoint:
//!
//! ```text
//!   Δ settlements
//! + Δ open holds
//! + Δ open-slice remainders
//! + Δ unreconciled
//! + Δ adjustments
//! − Δ overdraft carried
//! ± Δ cross-window transfers
//! = Δ drawn from the store
//! ```
//!
//! Everything taken out of the store is somewhere: posted, held, sitting in a slice, waiting on the
//! recompute, corrected away, carried as overdraft, or moved to another window. Money that is drawn
//! and in none of those places has been lost, and money in one of those places that was never drawn
//! has been invented. The identity is what makes both of those an alarm instead of a surprise at
//! the end of a billing period.
//!
//! ## Why it is a function of two totals and nothing else
//!
//! Because it has to be checkable by something that was not there when the postings happened. This
//! function reads two snapshots and returns a number; it has no clock, no store, no configuration
//! and no state. That is what lets an auditor re-derive it from a pair of sealed checkpoints, and
//! what lets a test throw random postings at it without a fixture.
//!
//! ## The residual, not a boolean
//!
//! It returns HOW FAR OUT the books are, not whether they balance. A verifier that answers only
//! "no" tells an operator that something is wrong and nothing else, which in practice means it gets
//! run once and then ignored. A residual is a starting point: its sign says which side the missing
//! value is on, and its magnitude is often recognisably one posting.

use crate::totals::{Totals, TotalsKey, WindowStart};

/// The identity's answer for one balance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Residual {
    /// The left-hand side: everything the drawn value should be sitting in.
    pub accounted: i128,
    /// The right-hand side: what was actually taken out of the store.
    pub drawn: i128,
}

impl Residual {
    /// How far out the books are. Zero is the only good answer.
    pub fn amount(self) -> i128 {
        self.accounted - self.drawn
    }

    /// Whether the identity holds.
    pub fn holds(self) -> bool {
        self.amount() == 0
    }
}

impl std::fmt::Display for Residual {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "accounted {} against drawn {} (residual {})",
            self.accounted,
            self.drawn,
            self.amount()
        )
    }
}

/// The identity, as a delta between two snapshots of one balance.
///
/// `since` is the last sealed checkpoint's figures for this key; `now` is the figures as they
/// stand. A key that was not in the last checkpoint is measured from zeros, which is right: it had
/// nothing then.
pub fn residual(since: &Totals, now: &Totals) -> Residual {
    let accounted = (now.settled - since.settled)
        + (now.open_holds - since.open_holds)
        + (now.open_slice_remainders - since.open_slice_remainders)
        + (now.unreconciled - since.unreconciled)
        + (now.adjustments - since.adjustments)
        - (now.overdraft_carried() - since.overdraft_carried())
        + (now.cross_window_transfers - since.cross_window_transfers);
    let drawn = now.drawn - since.drawn;
    Residual { accounted, drawn }
}

/// Whether the identity holds for one balance.
pub fn holds(since: &Totals, now: &Totals) -> bool {
    residual(since, now).holds()
}

/// A balance that does not satisfy the identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Imbalance {
    /// Which balance.
    pub key: TotalsKey,
    /// Which window.
    pub window: WindowStart,
    /// By how much, and on which side.
    pub residual: Residual,
}

impl std::fmt::Display for Imbalance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} in the window opening at {} does not balance: {}",
            self.key, self.window, self.residual
        )
    }
}

impl std::error::Error for Imbalance {}

/// A closed window that is still moving.
///
/// A window that has closed must show a delta of zero after its last transfer. A non-zero delta on
/// a closed window means value is being posted into a period that is already reported, which is a
/// different defect from a window that simply does not balance — hence a different answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosedWindowMoved {
    /// Which balance.
    pub key: TotalsKey,
    /// Which window.
    pub window: WindowStart,
    /// How much it moved by.
    pub moved: i128,
}

impl std::fmt::Display for ClosedWindowMoved {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} in the closed window opening at {} moved by {} after its last transfer",
            self.key, self.window, self.moved
        )
    }
}

impl std::error::Error for ClosedWindowMoved {}

/// Whether a closed window has stopped moving.
///
/// Everything that can change in a closed window is a transfer out of it; once the transfers are
/// accounted for, every other figure must be where it was at the last checkpoint.
pub fn closed_window_is_settled(since: &Totals, now: &Totals) -> Result<(), i128> {
    let moved = (now.settled - since.settled)
        + (now.open_holds - since.open_holds)
        + (now.open_slice_remainders - since.open_slice_remainders)
        + (now.adjustments - since.adjustments)
        + (now.cross_window_transfers - since.cross_window_transfers)
        - (now.drawn - since.drawn);
    if moved == 0 {
        Ok(())
    } else {
        Err(moved)
    }
}

/// An attribution bucket's identity: everything accrued was posted, and nothing else happened.
///
/// An attribution bucket never refuses and never draws, so the general identity degenerates: what
/// was accrued is what was settled.
pub fn attribution_holds(accrued: i128, settled: i128) -> bool {
    accrued == settled
}
