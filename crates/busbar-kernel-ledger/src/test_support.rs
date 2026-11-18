// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Ledger fixtures for tests in this crate and its dependents (`test-support`). Never in a shipped
//! build.

use busbar_contract::caps::Usage;

use crate::cost::{whole, LedgerEntry, Posting, Priced, Quantity};

impl LedgerEntry {
    /// Add one class's count from a whole-unit integer — the shape both books hold today.
    pub fn with_whole(mut self, class: impl Into<String>, count: u64) -> LedgerEntry {
        self.counts.insert(class.into(), whole(count));
        self
    }

    /// Set the tier multiplier in basis points.
    pub fn with_tier(mut self, tier_bp: u32) -> LedgerEntry {
        self.tier_bp = tier_bp;
        self
    }
}

impl Posting {
    /// Build a posting from a usage report: the quantities, the lane and the instant.
    pub fn from_usage(
        lane: impl Into<String>,
        usage: &Usage,
        fee_count: u64,
        tier_bp: u32,
        arrived_ms: u64,
        arrived_mono: u64,
    ) -> Self {
        Posting {
            lane: busbar_contract::kept::Text::from(std::sync::Arc::<str>::from(lane.into())),
            quantities: usage
                .lines()
                .iter()
                .map(|l| Quantity {
                    class: l.class.as_str(),
                    amount: l.quantity,
                })
                .collect(),
            fee_count,
            tier_bp,
            arrived_ms,
            arrived_mono,
            estimated: usage.is_estimated(),
        }
    }
}

impl Priced {
    /// Every class the card was present for but silent about. The flat fee is never among them.
    pub fn unpriced_classes(&self) -> Vec<&str> {
        self.lines
            .iter()
            .filter(|l| l.unpriced)
            .map(|l| l.class)
            .collect()
    }
}
