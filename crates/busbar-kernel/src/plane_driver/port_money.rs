// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Money, usage and audit for a plane session over the port (IF §12.4, §12.20; PLANE-DRIVER.md slice 4).
//!
//! The session task ([`super::port_session`]) decodes `PlaneOut::{Usage, Expect, Attempt, Audit}` and keeps the
//! cumulative USAGE per (class, source) in a [`SessionUsage`]. This module turns that set into the unit's counts
//! ([`unit_counts`]: `UnitCount`s at the plane's class indexes, fractional quantities in micro-units, the three
//! sources the ledger knows) and drives the existing money seam with them ([`PortMoney`]): a checkpoint asks the
//! budget, and the session's end posts exactly what the §12.4 cancel table ([`super::usage::bill`]) says.
//! Audit rows go to the audit chain under the request's verified principal ([`PortMoney::audit`]).
//!
//! `PlanePort::end`'s answer feeds the final counts here before the unit is settled; the settlement itself
//! (`PlaneMoney::settle_end_as`) stays with the unit's owner, exactly as it did with the old driver.

use std::sync::Arc;

use busbar_contract::abi::plane::UnitCount;
use busbar_contract::caps::{PrincipalId, ReasonCode};
use busbar_contract::measurement::{UNITS_ESTIMATED, UNITS_FLOOR, UNITS_REPORTED};
use busbar_contract::plane::codes::{CANCEL_ABORTED, CANCEL_FAILED, CANCEL_OK_PARTIAL};
use busbar_contract::vocab::{OUTCOME_APPLIED, OUTCOME_DEGRADED, OUTCOME_REJECTED};
use busbar_plugin_abi::plane::{
    AUDIT_APPLIED, AUDIT_DEGRADED, AUDIT_REJECTED, SRC_ESTIMATED, SRC_FLOOR, SRC_REPORTED,
};

use super::cancel::{CancelBill, Checkpoint, MoneySeam};
use super::usage::{bill, scaled, Bill, Ending, Reported, SessionUsage};
use super::AuditSink;
use crate::diagnostics::{PLANE_USAGE_ROUNDED, PLANE_USAGE_UNDECLARED};
use crate::teller::UnitCtx;

/// The audit action of a USAGE class the plane never declared (diagnostic [`PLANE_USAGE_UNDECLARED`], §12.20).
pub const ACTION_UNDECLARED: &str = "plane_usage_undeclared";

/// The audit action of a USAGE quantity rounded past micro-units (diagnostic [`PLANE_USAGE_ROUNDED`]).
pub const ACTION_ROUNDED: &str = "plane_usage_rounded";

/// One AUDIT row (§12.20): `verdict` is AUDIT_APPLIED, AUDIT_REJECTED or AUDIT_DEGRADED (checked at decode).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRow {
    pub verdict: u32,
    pub action: Box<str>,
    pub resource: Box<str>,
}

/// The audit outcome word of an AUDIT verdict.
fn outcome_of(verdict: u32) -> Option<&'static str> {
    match verdict {
        AUDIT_APPLIED => Some(OUTCOME_APPLIED),
        AUDIT_REJECTED => Some(OUTCOME_REJECTED),
        AUDIT_DEGRADED => Some(OUTCOME_DEGRADED),
        _ => None,
    }
}

/// Why [`write_audit`] wrote nothing: the row's verdict or action is not one the chain takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RowRefused;

/// Writes one row to `sink` under `principal` (`None` = anonymous). Err when the verdict or action is not one the
/// chain takes.
pub fn write_audit(
    sink: &dyn AuditSink,
    row: &AuditRow,
    principal: Option<&str>,
) -> Result<(), RowRefused> {
    let outcome = outcome_of(row.verdict).ok_or(RowRefused)?;
    if row.action.is_empty() {
        return Err(RowRefused);
    }
    let anonymous = PrincipalId::anonymous();
    sink.record(
        &row.action,
        &row.resource,
        outcome,
        principal.unwrap_or_else(|| anonymous.as_str()),
    );
    Ok(())
}

/// A session's usage as the unit's counts.
#[derive(Debug, Default)]
pub struct Counted {
    pub counts: Vec<UnitCount>,
    /// Classes the plane never declared: dropped and audited (C-USAGE).
    pub dropped: Vec<Box<str>>,
    /// Classes whose scale > 6 was rounded half-even: audited.
    pub rounded: Vec<Box<str>>,
}

const fn units_source(source: u32) -> Option<u32> {
    match source {
        SRC_REPORTED => Some(UNITS_REPORTED),
        SRC_ESTIMATED => Some(UNITS_ESTIMATED),
        SRC_FLOOR => Some(UNITS_FLOOR),
        _ => None,
    }
}

/// The kept USAGE as `UnitCount`s in first-answered order. `classes` is the unit's billable class list: a count's
/// `class` is the index of its class there. A class absent from it is dropped (and named); a quantity that does
/// not fit the ledger's range is dropped the same way.
#[must_use]
pub fn unit_counts(usage: &SessionUsage, classes: &[String]) -> Counted {
    counts_of(usage.last().iter(), classes)
}

/// [`unit_counts`] over any selection of the kept values (the cancel table's).
#[must_use]
fn counts_of<'r>(values: impl Iterator<Item = &'r Reported>, classes: &[String]) -> Counted {
    let mut counted = Counted::default();
    for r in values {
        let Some(index) = classes.iter().position(|c| **c == *r.class) else {
            if !counted.dropped.contains(&r.class) {
                counted.dropped.push(r.class.clone());
            }
            continue;
        };
        let (Some((quantity, rounded)), Some(source)) =
            (scaled(r.amount, r.scale), units_source(r.source))
        else {
            continue;
        };
        if rounded && !counted.rounded.contains(&r.class) {
            counted.rounded.push(r.class.clone());
        }
        let Ok(index) = u32::try_from(index) else {
            continue;
        };
        match UnitCount::from_count(index, source, quantity) {
            Ok(count) => counted.counts.push(count),
            Err(_) => {
                if !counted.dropped.contains(&r.class) {
                    counted.dropped.push(r.class.clone());
                }
            }
        }
    }
    counted
}

/// One plane instance's money for a session: the seam the unit's counts go to, the class list they index, and
/// the audit chain.
#[derive(Clone)]
pub struct PortMoney {
    seam: Arc<dyn MoneySeam>,
    classes: Arc<[String]>,
    audit: Arc<dyn AuditSink>,
}

impl PortMoney {
    #[must_use]
    pub fn new(
        seam: Arc<dyn MoneySeam>,
        classes: Arc<[String]>,
        audit: Arc<dyn AuditSink>,
    ) -> Self {
        Self {
            seam,
            classes,
            audit,
        }
    }

    fn counted<'r>(
        &self,
        values: impl Iterator<Item = &'r Reported>,
        ctx: &UnitCtx,
        principal: Option<&str>,
    ) -> Counted {
        let counted = counts_of(values, &self.classes);
        for (action, classes) in [
            (ACTION_UNDECLARED, &counted.dropped),
            (ACTION_ROUNDED, &counted.rounded),
        ] {
            for class in classes {
                if action == ACTION_UNDECLARED {
                    crate::diagnostics::diag_warn!(
                        PLANE_USAGE_UNDECLARED,
                        unit = ctx.key.get(),
                        class = %class,
                        "a plane reported usage for a class it never declared: dropped"
                    );
                } else {
                    crate::diagnostics::diag_debug!(
                        PLANE_USAGE_ROUNDED,
                        unit = ctx.key.get(),
                        class = %class,
                        "a plane reported usage past micro-units: rounded half-even"
                    );
                }
                let resource = format!("unit:{} class:{class}", ctx.key.get());
                let anonymous = PrincipalId::anonymous();
                self.audit.record(
                    action,
                    &resource,
                    OUTCOME_DEGRADED,
                    principal.unwrap_or_else(|| anonymous.as_str()),
                );
            }
        }
        counted
    }

    /// The member that served the unit: its money lane and the provider it was sent to. The
    /// unit's counts are priced, ledgered and metered under that lane from here on.
    pub fn served(&self, ctx: &UnitCtx, lane: &str, provider: &str) {
        self.seam.served(ctx, lane, provider);
    }

    /// A running unit's cumulative usage: the budget decides whether the stream goes on.
    pub fn checkpoint(
        &self,
        ctx: &UnitCtx,
        usage: &SessionUsage,
        principal: Option<&str>,
    ) -> Checkpoint {
        let counted = self.counted(usage.last().iter(), ctx, principal);
        self.seam.checkpoint(ctx, &counted.counts)
    }

    /// The session's end: the cancel table decides what is posted (§12.4); rule 4, the budget refund, is the
    /// unit owner's own act and is never folded in here.
    pub fn ended(
        &self,
        ctx: &UnitCtx,
        ending: Ending,
        usage: &SessionUsage,
        principal: Option<&str>,
    ) {
        match (bill(ending, usage), ending) {
            (Bill::Usage(values), Ending::End) => {
                let counted = self.counted(values.into_iter(), ctx, principal);
                // The final cumulative counts; a budget that dries after the end has nothing left to cut.
                let _ = self.seam.checkpoint(ctx, &counted.counts);
                self.seam.finished(ctx);
            }
            (Bill::Estimate | Bill::Nothing, Ending::End) => self.seam.finished(ctx),
            (
                billed,
                Ending::Cancel {
                    cause,
                    far_end_answered,
                    streamed,
                },
            ) => {
                let (disposition, billed) = match billed {
                    Bill::Usage(values) => {
                        let counted = self.counted(values.into_iter(), ctx, principal);
                        let lines: Vec<_> = counted
                            .counts
                            .iter()
                            .filter_map(|u| u.count().ok().map(|c| (u.class, c)))
                            .collect();
                        (CANCEL_OK_PARTIAL, lines)
                    }
                    Bill::Estimate | Bill::Nothing => (CANCEL_ABORTED, Vec::new()),
                };
                self.seam.cancelled(
                    ctx,
                    &CancelBill {
                        cause,
                        disposition,
                        far_end_answered,
                        streamed,
                        billed,
                        unread: None,
                    },
                );
            }
            (_, Ending::Failed) => self.seam.cancelled(
                ctx,
                &CancelBill {
                    cause: ReasonCode::PlanePanic,
                    disposition: CANCEL_FAILED,
                    far_end_answered: false,
                    streamed: false,
                    billed: Vec::new(),
                    unread: None,
                },
            ),
        }
    }

    /// One AUDIT row, under the request's verified principal (`None` = anonymous).
    pub fn audit(&self, row: &AuditRow, principal: Option<&str>) -> Result<(), RowRefused> {
        write_audit(&*self.audit, row, principal)
    }
}

#[cfg(test)]
#[path = "tests/port_money_tests.rs"]
mod tests;
