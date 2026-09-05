// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The two-sided canary: the count that says nothing went missing.
//!
//! The type system can say a hold is taken from its cell at most once. It cannot say a hold was
//! taken at ALL, or that every unit that got through the door had one. That is an arithmetic
//! property over a whole run, so it is checked as arithmetic, on both sides at once:
//!
//! > drafts accepted == holds opened + accruals into a parent == settlements
//!
//! Two-sided means neither side is trusted alone. Counting only settlements would miss a unit that
//! never opened a hold; counting only holds would miss one that never settled. The kernel keeps one
//! of these per cell and the proof battery asserts it balances at the end of every run.

use std::sync::atomic::{AtomicU64, Ordering};

/// The four counts, and what they must add up to.
///
/// Every method is a plain increment, so a hot path can carry one; the check is done at the end.
#[derive(Debug, Default)]
pub struct Canary {
    drafts: AtomicU64,
    holds: AtomicU64,
    accruals: AtomicU64,
    settlements: AtomicU64,
}

/// The way the counts failed to balance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanaryBreak {
    /// Drafts the door accepted.
    pub drafts: u64,
    /// Holds opened.
    pub holds: u64,
    /// Accruals into some parent's hold.
    pub accruals: u64,
    /// Settlements written, late ones included.
    pub settlements: u64,
}

impl std::fmt::Display for CanaryBreak {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "canary broken: {} drafts, {} holds + {} accruals, {} settlements",
            self.drafts, self.holds, self.accruals, self.settlements
        )
    }
}

impl std::error::Error for CanaryBreak {}

impl Canary {
    /// A fresh set of counts.
    pub fn new() -> Self {
        Canary::default()
    }

    /// A draft got through the door.
    pub fn draft_accepted(&self) {
        self.drafts.fetch_add(1, Ordering::Relaxed);
    }

    /// A hold was opened.
    pub fn hold_opened(&self) {
        self.holds.fetch_add(1, Ordering::Relaxed);
    }

    /// A spend went into a parent's hold instead of opening one.
    pub fn accrual_taken(&self) {
        self.accruals.fetch_add(1, Ordering::Relaxed);
    }

    /// A settlement was written — a late accrual's own posting counts here too.
    pub fn settled(&self) {
        self.settlements.fetch_add(1, Ordering::Relaxed);
    }

    /// The counts as they stand.
    pub fn counts(&self) -> CanaryBreak {
        CanaryBreak {
            drafts: self.drafts.load(Ordering::Relaxed),
            holds: self.holds.load(Ordering::Relaxed),
            accruals: self.accruals.load(Ordering::Relaxed),
            settlements: self.settlements.load(Ordering::Relaxed),
        }
    }

    /// Check both sides. Call it when the run is quiet — mid-flight units are legitimately counted
    /// on one side and not yet the other.
    pub fn balanced(&self) -> Result<(), CanaryBreak> {
        let c = self.counts();
        let opened = c.holds.saturating_add(c.accruals);
        if c.drafts == opened && opened == c.settlements {
            Ok(())
        } else {
            Err(c)
        }
    }
}
