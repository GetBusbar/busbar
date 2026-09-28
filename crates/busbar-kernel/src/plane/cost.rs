// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `plane::cost` — the neutral, protocol-blind itemized cost breakdown a plane settles through the
//! engine ledger.
//!
//! # Why this is neutral
//!
//! Core prices nothing and interprets no label. Any registered plane computes what a unit of work
//! cost and reports it as a [`CostBreakdown`]: a `total` plus a list of labeled
//! [`CostComponent`]s. The labels — `"Prompt"`, `"Cache write"`, `"Output"`, or whatever a plane
//! invents — are OPAQUE plugin strings; core records and surfaces them (in response headers, next
//! to the total) without knowing that any one of them is a concept specific to some plane's own
//! protocol. The same ledger and header machinery reports any plane's own labels unchanged.
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
        // Saturating, matching the fail-closed money-path discipline (`finalize` uses
        // saturating_sub, `derive_spend_cents` saturating_add). A hostile/buggy plugin
        // breakdown or a long run of partial settles must NOT wrap the accumulator to ~0
        // (silent under-settlement in release, debug panic) — it caps at the ceiling instead.
        CostAmount(self.0.saturating_add(rhs.0))
    }
}

impl std::iter::Sum for CostAmount {
    fn sum<I: Iterator<Item = CostAmount>>(iter: I) -> CostAmount {
        // Saturating fold — see the `Add` impl above; a summed sequence cannot wrap to under-charge.
        iter.fold(CostAmount(0), |acc, c| acc + c)
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
    /// A sum the invariant checks — the top-level lines, or one parent's direct children — does not
    /// fit a `u128`. The breakdown is ill-formed and is REFUSED: a sum that wrapped (release) could
    /// otherwise land exactly on `total` and validate a breakdown whose parts do not add up, and a
    /// sum that saturated could hide the same lie at the ceiling.
    SumOverflow {
        /// `None` for the top-level sum; `Some(parent)` for one parent's children.
        parent: Option<String>,
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
            CostError::SumOverflow { parent: None } => {
                f.write_str("cost components' top-level sum overflows the amount type")
            }
            CostError::SumOverflow {
                parent: Some(parent),
            } => write!(f, "children of {parent:?} sum past the amount type's range"),
        }
    }
}

impl std::error::Error for CostError {}

/// The invariant checks' one summation: exact, or `None` when the true sum does not fit a `u128`.
fn checked_sum(mut amounts: impl Iterator<Item = u128>) -> Option<u128> {
    amounts.try_fold(0u128, u128::checked_add)
}

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
        //
        // CHECKED, never the raw `Sum`: `u128`'s own `Sum` panics on overflow in a debug build and
        // WRAPS in a release one, and a wrapped sum can land exactly on `total` — validating a
        // hostile or buggy plugin's breakdown whose parts do not add up, the one invariant this
        // type exists to guarantee. The saturating `Sum` on `CostAmount` above is the wrong tool
        // too: a sum pinned at the ceiling equals a `total` of `u128::MAX` just as falsely. A sum
        // that does not fit is an ill-formed breakdown, and it is refused.
        let top_level_sum = checked_sum(
            components
                .iter()
                .filter(|c| c.parent.is_none())
                .map(|c| c.amount.0),
        )
        .ok_or(CostError::SumOverflow { parent: None })?;
        if top_level_sum != total.0 {
            return Err(CostError::TopLevelSumMismatch {
                total: total.0,
                top_level_sum,
            });
        }

        // Each parent's direct children must not exceed it (containment).
        for parent in &components {
            let children_sum = checked_sum(
                components
                    .iter()
                    .filter(|c| c.parent.as_deref() == Some(parent.label.as_str()))
                    .map(|c| c.amount.0),
            )
            .ok_or_else(|| CostError::SumOverflow {
                parent: Some(parent.label.clone()),
            })?;
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

#[cfg(test)]
#[path = "tests/cost_tests.rs"]
mod cost_tests;
