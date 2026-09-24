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
//!
//! ## ONE GUARD POLICY FOR THIS FILE: NO BOOK OPERATOR WRAPS
//!
//! `totals.rs` and `settle.rs` both announce that every operator moving a money column saturates.
//! This file is the one that READS those columns to decide whether the books balance, and it was
//! the one that still summed eight `i128`s with a bare `+`/`-` — so the imbalance detector was the
//! only place in the crate a broken book could wrap. Measured: `settled = i128::MAX`,
//! `open_holds = i128::MAX`, `open_slice_remainders = 2` sums to exactly 2^128, which a release
//! build wraps to ZERO — against zero drawn, a residual of zero, and the most broken book the type
//! can hold verified CLEAN. (A debug build panicked on the same figures, on the verification path.)
//!
//! CHECKED rather than saturating here, and the reason is specific to a comparison: two sides that
//! both saturate meet at the same bound and "balance". So a sum that does not fit is not pinned —
//! it is an UNREPRESENTABLE book, and it reads as out by the most the type can say
//! ([`Residual::unrepresentable`]), which can never hold.

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
    /// The answer for a book whose figures do not fit the type: out by the most it can say.
    ///
    /// Not a pinned sum. Pinning both sides would let them meet at the same bound and read as
    /// balanced, so an overflow is reported as the widest residual there is, which never holds.
    pub const fn unrepresentable() -> Self {
        Residual {
            accounted: i128::MAX,
            drawn: i128::MIN,
        }
    }

    /// How far out the books are. Zero is the only good answer.
    ///
    /// Saturating: a residual wider than the type is still a residual, never a wrap back to zero.
    pub fn amount(self) -> i128 {
        self.accounted.saturating_sub(self.drawn)
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
///
/// Every step is checked (see the module note): a book whose delta cannot be summed in 128 bits is
/// [`Residual::unrepresentable`], never a wrapped figure that happens to read as balanced.
pub fn residual(since: &Totals, now: &Totals) -> Residual {
    let delta = |now: i128, since: i128| now.checked_sub(since);
    let accounted = (|| {
        delta(now.settled, since.settled)?
            .checked_add(delta(now.open_holds, since.open_holds)?)?
            .checked_add(delta(
                now.open_slice_remainders,
                since.open_slice_remainders,
            )?)?
            .checked_add(delta(now.unreconciled, since.unreconciled)?)?
            .checked_add(delta(now.adjustments, since.adjustments)?)?
            .checked_sub(delta(now.overdraft_carried(), since.overdraft_carried())?)?
            .checked_add(delta(
                now.cross_window_transfers,
                since.cross_window_transfers,
            )?)
    })();
    match (accounted, delta(now.drawn, since.drawn)) {
        (Some(accounted), Some(drawn)) => Residual { accounted, drawn },
        _ => Residual::unrepresentable(),
    }
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

/// Whether a closed window has stopped moving, and by how much it has not.
///
/// Everything that can change in a closed window is a transfer out of it; once the transfers are
/// accounted for, every other figure must be where it was at the last checkpoint.
///
/// It reads the columns [`residual`] reads, for the reason that module note gives: a second sum over
/// a hand-picked subset is a second definition of "the books balance", and the one that used to be
/// here had drifted — it omitted `unreconciled` and the carried overdraft, so a reconciliation that
/// moved value between the settled and unreconciled columns was reported as a window still moving,
/// while a posting that landed in `unreconciled` alone moved the window invisibly.
///
/// But it is NOT the residual. The residual is the difference between the two sides, and this
/// question is about the sides themselves. A late posting into a reported window that draws 200 and
/// settles 200 has a residual of zero — the books balance, and would balance in an open window — and
/// it is precisely the thing a closed window must not do. So each side is compared against where the
/// checkpoint left it, and the window is settled only when NEITHER has moved.
///
/// The amount returned is what moved: the accounted side when that is what moved, and otherwise the
/// drawn side, so the figure an alarm carries is the one an operator can go looking for.
pub fn closed_window_is_settled(since: &Totals, now: &Totals) -> Result<(), i128> {
    let moved = residual(since, now);
    if moved.accounted != 0 {
        Err(moved.accounted)
    } else if moved.drawn != 0 {
        Err(moved.drawn)
    } else {
        Ok(())
    }
}

/// An attribution bucket's identity: everything accrued was posted, and nothing else happened.
///
/// An attribution bucket never refuses and never draws, so the general identity degenerates: what
/// was accrued is what was settled.
pub fn attribution_holds(accrued: i128, settled: i128) -> bool {
    accrued == settled
}
