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

use std::fmt::Write as _;
use std::sync::Arc;

use busbar_contract::abi::plane::UnitCount;
use busbar_contract::caps::{PrincipalId, ReasonCode};
use busbar_contract::measurement::{UNITS_ESTIMATED, UNITS_FLOOR, UNITS_REPORTED};
use busbar_contract::plane::codes::{CANCEL_ABORTED, CANCEL_OK_PARTIAL};
use busbar_contract::vocab::{OUTCOME_APPLIED, OUTCOME_DEGRADED, OUTCOME_REJECTED};
use busbar_plugin_abi::plane::{
    AUDIT_APPLIED, AUDIT_DEGRADED, AUDIT_REJECTED, SRC_ESTIMATED, SRC_FLOOR, SRC_REPORTED,
};

use super::cancel::{CancelBill, Checkpoint, MoneySeam};
use super::usage::{bill, scaled, Bill, Ending, Reported, SessionUsage, UsageInvalid};
use super::AuditSink;
use crate::diagnostics::{PLANE_USAGE_ROUNDED, PLANE_USAGE_UNDECLARED, PLANE_USAGE_UNREAD};
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

/// What a `plane-usage-unread` row states: the final report the money could not price, or why the session
/// refused the report.
enum Unread<'a> {
    Stated(&'a SessionUsage),
    Refused(UsageInvalid),
}

/// A USAGE source's word in an audit row.
const fn source_name(source: u32) -> &'static str {
    match source {
        SRC_REPORTED => "reported",
        SRC_ESTIMATED => "estimated",
        SRC_FLOOR => "floor",
        _ => "unknown",
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

    /// A running session's usage as it is accepted (P087B): the money takes each accepted report as it comes,
    /// so the last report it accepted is what bills when a later one cannot be priced or never comes. Quiet:
    /// a dropped or rounded class is audited once, at the session's end.
    pub fn running(&self, ctx: &UnitCtx, usage: &SessionUsage) -> Checkpoint {
        self.seam
            .checkpoint(ctx, &counts_of(usage.last().iter(), &self.classes).counts)
    }

    /// The unit's far end is being dialled: the unit has run.
    pub fn dialled(&self, ctx: &UnitCtx) {
        self.seam.dialled(ctx);
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
        self.ended_taken(ctx, ending, usage, None, principal);
    }

    /// [`Self::ended`], where `taken` is the money's answer to the session's last running checkpoint when it
    /// was taken of exactly `usage` ([`Self::running`]); `None` asks the money now.
    ///
    /// An `End` or a `Failed` session bills exactly the usage it accepted, once, at its owner's settlement
    /// (P087B): its bill's values reach the money as its final checkpoint and the unit is finished. A final
    /// report the money cannot price (`Unpriced`) is not billed, neither as 0 nor at an invented price: the
    /// money keeps the last report it accepted, the unit is left unread and audited
    /// ([`Self::unread`]).
    pub fn ended_taken(
        &self,
        ctx: &UnitCtx,
        ending: Ending,
        usage: &SessionUsage,
        taken: Option<Checkpoint>,
        principal: Option<&str>,
    ) {
        match (bill(ending, usage), ending) {
            (Bill::Usage(values), Ending::End | Ending::Failed) => {
                let counted = self.counted(values.into_iter(), ctx, principal);
                // The final cumulative counts; a budget that dries after the end has nothing left to cut.
                let verdict = taken.unwrap_or_else(|| self.seam.checkpoint(ctx, &counted.counts));
                if verdict == Checkpoint::Unpriced {
                    self.unread(ctx, Unread::Stated(usage), principal);
                }
                self.seam.finished(ctx);
            }
            (Bill::Estimate | Bill::Nothing, Ending::End | Ending::Failed) => {
                self.seam.finished(ctx);
            }
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
        }
    }

    /// The session refused a USAGE the plane stated (`why`): that report is never billed; it is audited
    /// `plane-usage-unread` and the unit is left unread (P087B, old K0b).
    pub fn refused(&self, ctx: &UnitCtx, why: UsageInvalid, principal: Option<&str>) {
        self.unread(ctx, Unread::Refused(why), principal);
    }

    /// `BUSBAR-5046`: the provider's final stated usage was not accepted. The unit is told (once: its terminal
    /// record carries the reason and it bills only the usage accepted before), and one `plane-usage-unread`
    /// row names the unit, its lane, the reason and the raw stated counts (or why the report was refused).
    fn unread(&self, ctx: &UnitCtx, what: Unread<'_>, principal: Option<&str>) {
        let reason = ReasonCode::Unpriced;
        if !self.seam.unread(ctx, reason) {
            return;
        }
        let lane = self.seam.lane(ctx).unwrap_or_default();
        let mut resource = format!(
            "unit:{} lane:{lane} reason:{}",
            ctx.key.get(),
            reason.as_str()
        );
        match what {
            Unread::Stated(usage) => {
                resource.push_str(" stated:");
                for (at, r) in usage.last().iter().enumerate() {
                    if at > 0 {
                        resource.push(',');
                    }
                    let _ = write!(resource, "{}={}", r.class, r.amount);
                    if r.scale != 0 {
                        let _ = write!(resource, "e-{}", r.scale);
                    }
                    resource.push('/');
                    resource.push_str(source_name(r.source));
                }
            }
            Unread::Refused(why) => {
                resource.push_str(" refused:");
                resource.push_str(match why {
                    UsageInvalid::Class => "class",
                    UsageInvalid::Scale => "scale",
                    UsageInvalid::Source => "source",
                });
            }
        }
        let anonymous = PrincipalId::anonymous();
        self.audit.record(
            PLANE_USAGE_UNREAD.slug,
            &resource,
            OUTCOME_DEGRADED,
            principal.unwrap_or_else(|| anonymous.as_str()),
        );
        crate::diagnostics::diag_warn!(
            PLANE_USAGE_UNREAD,
            unit = ctx.key.get(),
            reason = reason.as_str(),
            "provider usage not read: the unit bills only the usage accepted before its final report"
        );
    }

    /// One AUDIT row, under the request's verified principal (`None` = anonymous).
    pub fn audit(&self, row: &AuditRow, principal: Option<&str>) -> Result<(), RowRefused> {
        write_audit(&*self.audit, row, principal)
    }
}

#[cfg(test)]
#[path = "tests/port_money_tests.rs"]
mod tests;
