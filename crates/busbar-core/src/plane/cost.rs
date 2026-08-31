// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `plane::cost` — the neutral, protocol-blind itemized cost breakdown a plane settles through the
//! engine ledger.
//!
//! # Why this is neutral
//!
//! Core prices nothing and interprets no label. A plane (the LLM plane, an MCP plane, a future
//! protocol) computes what a unit of work cost and reports it as a [`CostBreakdown`]: a `total`
//! plus a list of labeled [`CostComponent`]s. The labels — `"Prompt"`, `"Cache write"`,
//! `"Output"`, or whatever a future protocol invents — are OPAQUE plugin strings; core records and
//! surfaces them (in response headers, next to the total) without knowing that "Cache write" is an
//! LLM concept. The same ledger and header machinery reports a future protocol's own labels
//! unchanged.
//!
//! # The one thing core DOES enforce
//!
//! **The parts add up.** [`CostBreakdown::new`] is the only constructor, and it rejects a breakdown
//! whose top-level components do not sum to `total`. That guarantee is checkable with zero protocol
//! knowledge, and it is the whole reason a caller can trust the split it reads back: `Prompt +
//! cache write + output = total`, always. Accuracy is a structural invariant here, not a
//! best-effort — a `CostBreakdown` that violates it cannot be constructed.
//!
//! # Nesting (containment)
//!
//! A component may name a `parent` — a containing component's label — for reporting a sub-cost that
//! is ALREADY included in its parent (e.g. reasoning is inside output, so it nests under `"Output"`
//! rather than adding a fourth top-level line). Nested children do NOT add to `total`; only the
//! top-level lines (those with no parent) sum to it. Each parent's direct children are additionally
//! required not to exceed the parent — a child cannot cost more than the line that contains it.

use std::collections::BTreeSet;
use std::fmt;

/// Exact money in **nanodollars** (1e-9 USD), the same integer unit the engine's per-token pricing
/// already settles in (`cost::RateNanos`/`cost_nanos`). Integer so accounting is lossless — a
/// caller's `0.0078345` USD is exactly `7_834_500` nanodollars, with no float drift on the way to
/// the ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
pub struct CostAmount(pub u128);

impl CostAmount {
    /// The zero amount.
    pub const ZERO: CostAmount = CostAmount(0);

    /// Nanodollars as a raw integer.
    #[inline]
    pub fn nanodollars(self) -> u128 {
        self.0
    }
}

impl std::ops::Add for CostAmount {
    type Output = CostAmount;
    #[inline]
    fn add(self, rhs: CostAmount) -> CostAmount {
        CostAmount(self.0 + rhs.0)
    }
}

impl std::iter::Sum for CostAmount {
    fn sum<I: Iterator<Item = CostAmount>>(iter: I) -> CostAmount {
        CostAmount(iter.map(|c| c.0).sum())
    }
}

/// One labeled line of a [`CostBreakdown`].
///
/// `label` is an OPAQUE plugin string (core never branches on it). `parent`, when set, names the
/// label of a component that CONTAINS this one for nested reporting — the child's amount is already
/// part of its parent's amount and does not add to the total.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CostComponent {
    /// The plane's own name for this cost line. Surfaced verbatim; never interpreted by core.
    pub label: String,
    /// What this line cost, in nanodollars.
    pub amount: CostAmount,
    /// The label of the containing component, if this line is a sub-cost of another (e.g. reasoning
    /// nested under output). `None` for a top-level line that contributes to `total`.
    pub parent: Option<String>,
}

impl CostComponent {
    /// A top-level component (contributes to the total).
    pub fn top(label: impl Into<String>, amount: CostAmount) -> CostComponent {
        CostComponent {
            label: label.into(),
            amount,
            parent: None,
        }
    }

    /// A nested component contained within `parent` (does NOT contribute to the total).
    pub fn nested(
        label: impl Into<String>,
        amount: CostAmount,
        parent: impl Into<String>,
    ) -> CostComponent {
        CostComponent {
            label: label.into(),
            amount,
            parent: Some(parent.into()),
        }
    }
}

/// Why a [`CostBreakdown`] was rejected. Every variant is a violation of "the parts add up" or of
/// the containment rule — the invariants that make the reported split trustworthy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CostError {
    /// A component carried a zero amount. Breakdowns are sparse by construction — a line that cost
    /// nothing is omitted, not reported as zero (this is why "cache write" appears only when
    /// nonzero).
    ZeroComponent { label: String },
    /// Two components shared a label. Labels are the key a consumer reports and accumulates by, so
    /// they must be unique within a breakdown.
    DuplicateLabel { label: String },
    /// A component named a `parent` label that is not itself a component of this breakdown.
    UnknownParent { label: String, parent: String },
    /// The top-level components (those with no parent) do not sum to `total`. This is the
    /// "parts add up" guarantee failing.
    TopLevelSumMismatch { total: u128, top_level_sum: u128 },
    /// A parent's direct children sum to more than the parent — a sub-cost cannot exceed the line
    /// that contains it.
    ChildrenExceedParent {
        parent: String,
        parent_amount: u128,
        children_sum: u128,
    },
}

impl fmt::Display for CostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CostError::ZeroComponent { label } => {
                write!(
                    f,
                    "cost component {label:?} is zero (omit it; breakdowns are sparse)"
                )
            }
            CostError::DuplicateLabel { label } => {
                write!(f, "duplicate cost component label {label:?}")
            }
            CostError::UnknownParent { label, parent } => {
                write!(
                    f,
                    "cost component {label:?} names unknown parent {parent:?}"
                )
            }
            CostError::TopLevelSumMismatch {
                total,
                top_level_sum,
            } => write!(
                f,
                "cost components do not add up: top-level sum {top_level_sum} != total {total}"
            ),
            CostError::ChildrenExceedParent {
                parent,
                parent_amount,
                children_sum,
            } => write!(
                f,
                "children of {parent:?} sum to {children_sum} > parent {parent_amount}"
            ),
        }
    }
}

impl std::error::Error for CostError {}

/// An itemized, protocol-blind cost: a `total` and the labeled components that make it up.
///
/// Constructed ONLY through [`CostBreakdown::new`], which enforces every invariant, so a value of
/// this type is always well-formed: nonzero unique-labeled components, valid parent references,
/// top-level lines that sum to `total`, and children that do not exceed their parent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CostBreakdown {
    total: CostAmount,
    components: Vec<CostComponent>,
}

impl CostBreakdown {
    /// Build a breakdown, enforcing the invariants. Returns [`CostError`] if the parts do not add
    /// up (or any other rule is violated), so an ill-formed breakdown can never reach the ledger.
    pub fn new(
        total: CostAmount,
        components: Vec<CostComponent>,
    ) -> Result<CostBreakdown, CostError> {
        let mut labels: BTreeSet<&str> = BTreeSet::new();
        for c in &components {
            if c.amount == CostAmount::ZERO {
                return Err(CostError::ZeroComponent {
                    label: c.label.clone(),
                });
            }
            if !labels.insert(c.label.as_str()) {
                return Err(CostError::DuplicateLabel {
                    label: c.label.clone(),
                });
            }
        }

        // Every named parent must exist as a component.
        for c in &components {
            if let Some(p) = &c.parent {
                if !labels.contains(p.as_str()) {
                    return Err(CostError::UnknownParent {
                        label: c.label.clone(),
                        parent: p.clone(),
                    });
                }
            }
        }

        // Top-level lines (no parent) must sum to total.
        let top_level_sum: u128 = components
            .iter()
            .filter(|c| c.parent.is_none())
            .map(|c| c.amount.0)
            .sum();
        if top_level_sum != total.0 {
            return Err(CostError::TopLevelSumMismatch {
                total: total.0,
                top_level_sum,
            });
        }

        // Each parent's direct children must not exceed it (containment).
        for parent in &components {
            let children_sum: u128 = components
                .iter()
                .filter(|c| c.parent.as_deref() == Some(parent.label.as_str()))
                .map(|c| c.amount.0)
                .sum();
            if children_sum > parent.amount.0 {
                return Err(CostError::ChildrenExceedParent {
                    parent: parent.label.clone(),
                    parent_amount: parent.amount.0,
                    children_sum,
                });
            }
        }

        Ok(CostBreakdown { total, components })
    }

    /// The total charge (equals the sum of the top-level components, by construction).
    pub fn total(&self) -> CostAmount {
        self.total
    }

    /// All components, top-level and nested, in the order supplied.
    pub fn components(&self) -> &[CostComponent] {
        &self.components
    }

    /// Just the top-level components — the lines that sum to [`Self::total`] and are the natural
    /// header split.
    pub fn top_level(&self) -> impl Iterator<Item = &CostComponent> {
        self.components.iter().filter(|c| c.parent.is_none())
    }
}

/// A coarse pre-admission magnitude: a number and the NAME of what is counted (`"tokens"`, `"bytes"`,
/// `"tasks"`, …), for a HARD pre-admission budget cap via over-reservation. The plane fills it from
/// its own [`crate::ir::facts`] projection; core reserves against it without knowing the unit's origin
/// (owner ruling Q5 — accuracy comes from the exact *settlement*, not this coarse estimate).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Magnitude {
    /// What is being counted — an opaque plugin word, never interpreted by core.
    pub unit: &'static str,
    /// How much of it, for the over-estimate.
    pub amount: u64,
    /// The caller's declared cap on `amount`, if any (a request asking for more is refused up front).
    pub caller_cap: Option<u64>,
}

/// The outcome of finalizing a [`CostHold`]: the exact amount to ledger, and the refund owed back to
/// the budget cell the reserve was taken from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settlement {
    /// The true charge — the sum of the plugin's exact [`CostBreakdown`] settlements. This is what the
    /// ledger records; it is NEVER a core estimate.
    pub ledgered_total: CostAmount,
    /// `reserved − settled`, saturating at zero: the unspent reserve to return to the budget cell. Zero
    /// when the exact charge met or exceeded the (coarse) reserve.
    pub refund: CostAmount,
}

/// A cost reserve held across a request: reserve a coarse over-estimate at admit for a hard budget
/// cap, settle the EXACT itemized charge as it becomes known, and reconcile the refund at the end.
///
/// This type owns the correctness of the *amounts* — the reserve total, the exact settled sum, the
/// once-only flat fee, and the refund — but NOT the ledger: the caller applies `reserved` to its
/// budget cell at [`CostHold::reserve`] and the [`Settlement`] at [`CostHold::finalize`]. Pinning the
/// hold to a `(bucket, window)` so the refund lands where it was reserved is the caller's key choice;
/// this value carries no clock and no cell.
///
/// **Accuracy invariant:** the ledgered charge is the sum of the exact `settle_partial`s, never
/// the coarse reserve. **No double-count:** the flat per-request fee is folded into `reserved` once
/// and never re-added on settle.
#[derive(Debug)]
pub struct CostHold {
    reserved: CostAmount,
    settled: CostAmount,
}

impl CostHold {
    /// Open a hold reserving a coarse `estimate` plus the once-only flat per-request `fee`. The caller
    /// debits `reserved()` from the budget cell now; the unspent part comes back at [`Self::finalize`].
    pub fn reserve(estimate: CostAmount, fee: CostAmount) -> CostHold {
        CostHold {
            reserved: estimate + fee,
            settled: CostAmount::ZERO,
        }
    }

    /// The amount debited from the budget cell at admit (estimate + flat fee).
    pub fn reserved(&self) -> CostAmount {
        self.reserved
    }

    /// Record an EXACT increment the plugin computed (a streamed frame's cost, or the final usage).
    /// Repeatable; the running sum is the true charge. Core does not derive it — the plugin supplies
    /// the itemized [`CostBreakdown`] and its `total` is what accrues.
    pub fn settle_partial(&mut self, exact: &CostBreakdown) {
        self.settled = self.settled + exact.total();
    }

    /// Reconcile: the exact total to ledger, and the refund (`reserved − settled`, saturating). An
    /// over-settle (exact charge above the coarse reserve — the estimate was low) ledgers the true
    /// amount and refunds zero, never a negative.
    pub fn finalize(self) -> Settlement {
        let refund = CostAmount(self.reserved.0.saturating_sub(self.settled.0));
        Settlement {
            ledgered_total: self.settled,
            refund,
        }
    }
}

#[cfg(test)]
#[path = "tests/cost_tests.rs"]
mod cost_tests;
