// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What an enforced key may still spend — the arithmetic, and only the arithmetic.
//!
//! ## Why this is here and not on the key
//!
//! Owner ruling 13:0x (6): the enforced key's one shape is the auth unit's resolved key, and the
//! money-carrying fields the legacy key held move to the cost and ledger VIEWS. The census
//! (`docs/design/1.6.0-virtualkey-reader-table.md`) found that the legacy key held no budget field,
//! no rate reference and no price — its whole money content was the NAME of the pot it charges
//! through. So there is nothing to move except that name, and it splits: the ledger owns the row it
//! names, and this owns every figure derived from it.
//!
//! Ruling 13:0x (5) says the rest: "admission reads `spent` from the ledger and
//! `budget_remaining_cents` from unit-cost; no arithmetic outside unit-cost". This is that
//! function, and it is the only place it is written down as a policy rather than performed.
//!
//! ## What this view is NOT
//!
//! It is not a door. Nothing here refuses anything; it answers two questions and the caller decides.
//! It holds no clock, so it cannot know which window it is in — the caller resolves the window,
//! reads the cell, and hands over a figure. And it holds no cells, so it cannot accumulate: every
//! answer is a pure function of the arguments, which is what lets an auditor re-derive one by hand.
//!
//! ## The parity that matters
//!
//! The door performs the identical comparison inline, over its own bucket chain, because a unit
//! never calls another unit and the admission crate cannot reach this one. Two copies of one
//! comparison with nothing checking that they agree is how a request comes to be judged at one
//! figure and billed at another — so the crate's existing dev-dependency on the admission unit,
//! which exists for exactly this reason on the rate side, pins them equal on this side too.

use crate::project::cents_of;

/// The budget standing of one row, as of one reading of it.
///
/// Constructed per question rather than held: the cap comes from the policy epoch the request was
/// pinned to, and a view that outlived that epoch would answer against a cap the request was never
/// judged under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyBudgetView {
    /// The ledger row this standing is about — the id the ledger unit named. Carried so an answer
    /// can be attributed to the row it came from; never parsed, and never used to derive a figure.
    bucket: String,
    /// The spend ceiling on that row, in cents. `None` is uncapped, which is the ordinary posture
    /// for a deployment with no budget limit and NOT a missing value.
    cap_cents: Option<i64>,
}

impl KeyBudgetView {
    /// A row with a spend ceiling.
    #[must_use]
    pub fn capped(bucket: impl Into<String>, cap_cents: i64) -> Self {
        KeyBudgetView {
            bucket: bucket.into(),
            cap_cents: Some(cap_cents),
        }
    }

    /// A row with no spend ceiling. Authed and unlimited is a real posture: a key bound to no group
    /// has access and no budget, and saying so explicitly is what keeps it from reading as an
    /// absent cap somebody forgot to configure.
    #[must_use]
    pub fn uncapped(bucket: impl Into<String>) -> Self {
        KeyBudgetView {
            bucket: bucket.into(),
            cap_cents: None,
        }
    }

    /// The ledger row this view is about.
    #[must_use]
    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    /// The ceiling, in cents. `None` is uncapped.
    #[must_use]
    pub fn cap_cents(&self) -> Option<i64> {
        self.cap_cents
    }

    /// What has been spent on this row, in whole cents.
    ///
    /// ONE truncation, at the very end, and it is the projection the rest of the crate already
    /// uses. Nano-units accumulate across every lane FIRST and divide to cents ONCE, because two
    /// lanes each contributing half a cent make a whole cent and a per-lane floor would drop both.
    #[must_use]
    pub fn spent_cents(&self, spent_nanos: u128) -> i64 {
        cents_of(spent_nanos)
    }

    /// What is left on this row, in cents. `None` is uncapped — no figure, rather than a very large
    /// one, because a caller that treated a large number as a limit would eventually meet it.
    ///
    /// Floored at zero: a row already over its cap has nothing left, not a negative allowance that
    /// a later credit could be netted against. Saturating, because the subtraction of an
    /// out-of-range spend from a cap must pin rather than wrap — a wrap lands positive and reads as
    /// unlimited headroom on a row that is exhausted.
    #[must_use]
    pub fn remaining_cents(&self, spent_nanos: u128) -> Option<i64> {
        self.cap_cents
            .map(|cap| cap.saturating_sub(self.spent_cents(spent_nanos)).max(0))
    }

    /// Whether admitting one more request would put this row over its cap.
    ///
    /// The shipped comparison, operator for operator: `derived >= cap` (already at or past the
    /// ceiling) OR `derived + fee > cap` (the flat fee this request would add takes it past). The
    /// two clauses are NOT redundant and neither may be dropped. The first is `>=` and the second
    /// is `>`, which is the shipped asymmetry: a row exactly AT its cap is blocked, and a row that
    /// a zero fee leaves exactly AT its cap is not. An uncapped row is never over.
    ///
    /// `fee_lookahead_cents` is the flat per-request fee, which is EVIDENCE that a billable request
    /// is about to happen rather than an estimate of what it will cost; the usage it consumes is
    /// priced afterwards, at settlement, against the card pinned when its hold opened.
    #[must_use]
    pub fn would_exceed(&self, spent_nanos: u128, fee_lookahead_cents: i64) -> bool {
        let Some(cap) = self.cap_cents else {
            return false;
        };
        let derived = self.spent_cents(spent_nanos);
        derived >= cap || derived.saturating_add(fee_lookahead_cents) > cap
    }
}
