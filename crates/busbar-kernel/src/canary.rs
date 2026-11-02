// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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
    pub fn new() -> Self {
        Canary::default()
    }

    pub fn draft_accepted(&self) {
        self.drafts.fetch_add(1, Ordering::Relaxed);
    }

    pub fn hold_opened(&self) {
        self.holds.fetch_add(1, Ordering::Relaxed);
    }

    pub fn accrual_taken(&self) {
        self.accruals.fetch_add(1, Ordering::Relaxed);
    }

    pub fn settled(&self) {
        self.settlements.fetch_add(1, Ordering::Relaxed);
    }

    pub fn counts(&self) -> CanaryBreak {
        CanaryBreak {
            drafts: self.drafts.load(Ordering::Relaxed),
            holds: self.holds.load(Ordering::Relaxed),
            accruals: self.accruals.load(Ordering::Relaxed),
            settlements: self.settlements.load(Ordering::Relaxed),
        }
    }

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
