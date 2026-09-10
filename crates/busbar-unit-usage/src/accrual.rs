// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE ONE FOLD from a delivered unit's name-keyed report to the record the books settle
//! against**, and the whole of what an accrual is entitled to decide about it.
//!
//! # Why it is here and not at each accrual site
//!
//! A delivered unit's consumption arrives as a `class -> quantity` map. Every book that settles
//! against it has to turn that map into lines, and the turn is not a formality: it decides which
//! classes survive, in what order they are written down, and what evidence each line claims to rest
//! on. Written once per book, those three decisions drift, and two books that disagree about which
//! classes survive are two different amounts for one request that nothing can reconcile.
//!
//! That is not hypothetical. Two copies of this walk existed on the llm path, they hard-coded the
//! same four token class names, and they did not agree with the book beside them: the previous
//! release's budget cell folds the report WHOLE (`GovState::record_usage` skips only the zeros),
//! and the record builder walked a fixed list of four and dropped everything else.
//!
//! # The two models of a billable class, which is the actual divergence
//!
//! The previous release's book is keyed by an OPEN `String`: any name an operator or an upstream
//! puts in the map is a billable class the moment it is accrued. The record this crate produces is
//! keyed by [`MeterClassId`], which is a `&'static str` — **a class must be DECLARED, in a plane's
//! own const meter-class table, before a line can exist for it at all.**
//!
//! Those are not two spellings of one book. They are two answers to "what is a billable class", and
//! the compiler is the one that says so: there is no expression that mints a `MeterClassId` from a
//! name read out of a map at runtime. So the fold cannot simply be widened to keep everything, and
//! it must not silently drop what it cannot keep — a quantity that is not written down cannot be
//! disputed, re-derived or invoiced, and it is the one direction a money defect must never go.
//!
//! What it does instead is HAND BACK what it could not hold, by name and quantity, so the caller
//! settles what is declared and can see — and refuse, alarm on, or declare — what is not. Nothing
//! is lost quietly.
//!
//! # The three rules
//!
//! 1. **A zero-quantity line is not a fact about anything**, so it is not written down. The books on
//!    either side of this fold already skip zeros.
//! 2. **The declared classes come first, in the caller's declared order** — so the line sequence is
//!    a property of this function and of the table the caller declares, and never of a map's
//!    collation.
//! 3. **Every class the report carries that no caller declared comes back as
//!    [`Folded::undeclared`]**, at its quantity, in the report's own order.
//!
//! # What this crate does not name
//!
//! No class name and no unit of measure appears here. The declared table is the CALLER's, because
//! which classes a deployment meters is a fact about the planes it hosts and about its rate card,
//! and a unit that named four of them would be a unit that had to be edited to meter a fifth. The
//! only vocabulary this fold carries is the provenance the caller states per class, which is
//! `busbar-contract`'s and travels on the line into the ledger's own digest.

use std::collections::BTreeMap;

use busbar_caps::{MeterClassId, QuantitySource, Usage, UsageError, UsageLine, UsageToken};

/// One declared class and the evidence a line for it rests on.
///
/// The provenance is stated per class rather than per report because it is per class in fact: a
/// figure a destination reported at a locator and a figure the node counted for itself are
/// different evidence, they are argued from differently in a dispute, and the ledger seals which one
/// it was into its digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalClass {
    /// The declared class, spelled exactly as the rate card is written against.
    pub class: MeterClassId,
    /// What a line for this class rests on.
    pub source: QuantitySource,
    /// Whether a figure for this class is the node's own floor rather than one a destination stood
    /// behind. The mark travels onto the line and from there onto the posting.
    pub estimated: bool,
}

impl CanonicalClass {
    /// Name one declared class and its evidence. Counted, not estimated — the ordinary case, where
    /// the figure came off the destination's own answer.
    #[must_use]
    pub fn counted(class: MeterClassId) -> Self {
        CanonicalClass {
            class,
            source: QuantitySource::Count,
            estimated: false,
        }
    }

    /// Name one declared class, its evidence and whether that evidence is a floor.
    #[must_use]
    pub fn new(class: MeterClassId, source: QuantitySource, estimated: bool) -> Self {
        CanonicalClass {
            class,
            source,
            estimated,
        }
    }
}

/// The fold's whole answer: what the record holds, and what it could not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Folded {
    /// The record the books settle against.
    pub usage: Usage,
    /// Every class the report carried that no caller declared, at the quantity reported.
    ///
    /// **NOT A DIAGNOSTIC, AND NOT EMPTY MEANS SOMETHING WENT UNBILLED.** The previous release's
    /// budget cell accrues these; this record cannot represent them. A caller that ignores this
    /// field is a caller whose two books disagree by exactly its contents.
    pub undeclared: BTreeMap<String, u64>,
}

impl Folded {
    /// Whether everything the report carried made it into the record.
    #[must_use]
    pub fn whole(&self) -> bool {
        self.undeclared.is_empty()
    }
}

/// Fold a delivered unit's name-keyed report into the usage record the books settle against.
///
/// The declared classes in `declared` are written first, in that order, at the provenance each one
/// states. Every remaining class the report carries comes back in [`Folded::undeclared`] rather than
/// on a line, because a line needs a declared class and this fold does not invent declarations.
///
/// A report with nothing in it produces a record with no lines, which is not an error: it is what a
/// unit that reported nothing consumed, and it still prices whatever a flat fee costs.
pub fn report_from_units(
    token: &UsageToken,
    units: &BTreeMap<String, u64>,
    declared: &[CanonicalClass],
) -> Result<Folded, UsageError> {
    let mut lines: Vec<UsageLine> = Vec::with_capacity(units.len());
    for entry in declared {
        // A declared class the report does not carry is not a zero line; it is a class this unit did
        // not consume, and the two are the same statement only to a reader that never looks.
        let quantity = units.get(entry.class.as_str()).copied().unwrap_or(0);
        if quantity == 0 {
            continue;
        }
        lines.push(UsageLine {
            class: entry.class,
            quantity,
            source: entry.source.clone(),
            estimated: entry.estimated,
        });
    }
    let undeclared = units
        .iter()
        .filter(|(class, quantity)| {
            **quantity > 0 && !declared.iter().any(|e| e.class.as_str() == class.as_str())
        })
        .map(|(class, quantity)| (class.clone(), *quantity))
        .collect();
    Ok(Folded {
        usage: Usage::report(token, lines)?,
        undeclared,
    })
}
