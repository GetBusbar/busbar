// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The metering fold: raw per-cell consumption, kept for observability and never for enforcement.
//!
//! This is deliberately separate from the settlement above. A metering cell is a running total of
//! what a key consumed against a model in a window; nothing enforces against it, so it is a plain
//! accumulation with two properties that matter — a response ALWAYS counts its request, even when
//! it consumed nothing, and coalescing several responses into one write must carry the real count
//! rather than inventing a single increment.

use std::collections::BTreeMap;

use busbar_caps::Usage;

/// One metering cell's running totals.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MeterCounts {
    /// How many responses landed in this cell.
    pub requests: u64,
    /// How much of each class they consumed, by class name so the order is stable everywhere.
    pub quantities: BTreeMap<String, u64>,
}

impl MeterCounts {
    /// Fold one delivered response into the cell.
    ///
    /// A response with NO usage at all — a flat-fee operation — still counts its request. Consumers
    /// count requests per model even when nothing else bills, and dropping the request because the
    /// quantities were empty would make the two disagree.
    pub fn accrue_response(&mut self, usage: Option<&Usage>) {
        self.requests = self.requests.saturating_add(1);
        if let Some(usage) = usage {
            for line in usage.lines() {
                let entry = self
                    .quantities
                    .entry(line.class.as_str().to_string())
                    .or_insert(0);
                *entry = entry.saturating_add(line.quantity);
            }
        }
    }

    /// Merge another cell's totals into this one — a saturating add, never an overwrite.
    ///
    /// This is what makes a failed write safe to retry: the counts go back into whatever
    /// accumulated meanwhile, so the next attempt carries the full amount exactly once.
    pub fn merge(&mut self, other: &MeterCounts) {
        self.requests = self.requests.saturating_add(other.requests);
        for (class, quantity) in &other.quantities {
            let entry = self.quantities.entry(class.clone()).or_insert(0);
            *entry = entry.saturating_add(*quantity);
        }
    }

    /// Whether this cell carries nothing at all. A genuinely empty cell is skipped rather than
    /// written: an empty row is not a fact about anything.
    pub fn is_empty(&self) -> bool {
        self.requests == 0 && self.quantities.values().all(|q| *q == 0)
    }

    /// How much of one class this cell has accumulated.
    pub fn quantity(&self, class: &str) -> u64 {
        self.quantities.get(class).copied().unwrap_or(0)
    }
}
