// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A request a plane serves over the port is a billed unit (IF §12.4; PLANE-DRIVER.md slice 4's "no production
//! owner" gap). [`PortBilling`] is that owner: the process's plane money ([`PlaneMoney`]), the governance book
//! and the unit-key allocator. [`PortBilling::open`] admits one request through its caller key's budget chain
//! and opens it as a unit, handing back the [`Unit`] `PortDriver::serve` runs the session's books against
//! ([`PortMoney`] checkpoints and posts the cancel table's end through the existing money seam);
//! [`PortBilling::settle`] closes it when the answer is out.
//!
//! The same shape as the old driver's admission with what a port session does not know yet left out, each a
//! stated simplification (the smallest design consistent with the old behaviour; PLANE-DRIVER.md):
//! the unit is admitted before the session runs, so there is no EXPECT estimate (admission charges the request
//! fee and takes its concurrency hold; usage is settled from what the plane reports); its pool and lane are the
//! plane-qualified instance name (the serving member's lane is not known until the egress walk is ported); and
//! the instance names no fee units, so no flat-fee refund rule applies.
//!
//! Configured native routing instead uses [`PortBilling::allocate`] before the retained task
//! resolves its route, then [`PortBilling::admit_existing`] with the resulting checked receipt.
//! The allocation and monetary insertion keep the same unit; attempt selection never re-admits it.

use std::sync::Arc;

use busbar_contract::caps::{CallId, OriginKind};
use busbar_contract::records::VirtualKey;
use busbar_contract::UnitKey;

use super::money::{FeeRefund, PlaneMoney, UnitEnd, UnitMoney};
use super::port::Unit;
use super::port_money::PortMoney;
use super::request_admission::{AdmittedRequest, CommittingRequest};
use super::AuditSink;
use super::{NativeAdmissionError, ParentMoney};
use crate::config::groups::ExhaustionMode;
use crate::cost::CostModel;
use crate::door::UnitKeyMint;
use crate::governance::{GovState, LimitBlocked, PLANE_LANE_SEP};
use crate::registry::Generation;
use crate::teller::UnitCtx;

/// What admitting one request needs.
pub struct Admit<'a> {
    /// The plane instance's configured name: the plane the unit's pool and lane are qualified by.
    pub instance: &'a str,
    /// The instance's declared usage classes, in its Statement's order: a count's class indexes them.
    pub classes: Arc<[String]>,
    /// The resolved caller key (the balance and the budget chain).
    pub key: Arc<VirtualKey>,
    /// The generation's cost model the request was admitted under.
    pub cost: Arc<CostModel>,
    /// The in-flight exhaustion mode: the root always supplies `FinishUnit`.
    pub mode: ExhaustionMode,
    /// The arrival epoch, seconds.
    pub arrived: u64,
}

/// The process's billing of plane requests served over ports.
#[derive(Clone)]
pub struct PortBilling {
    money: Arc<PlaneMoney>,
    gov: Arc<GovState>,
    keys: Arc<UnitKeyMint>,
    audit: Arc<dyn AuditSink>,
    /// Where a unit's end user goes (`records.user`, ADMIN-API-1.6 §3.5); `None` keeps none.
    journal: Option<Arc<dyn super::HookJournal>>,
}

impl std::fmt::Debug for PortBilling {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PortBilling").finish_non_exhaustive()
    }
}

impl PortBilling {
    pub fn admission_rollback(
        &self,
        request: &AdmittedRequest,
    ) -> Result<super::AdmissionRollback, NativeAdmissionError> {
        self.money.admission_rollback(request)
    }

    pub fn settle_admitted(
        &self,
        request: &AdmittedRequest,
        end: UnitEnd,
    ) -> Result<bool, NativeAdmissionError> {
        self.money.settle_admitted(request, end)
    }

    pub fn admit_existing_selected(
        &self,
        request: CommittingRequest,
        declaration: super::port_session::RequestDeclaration,
        generation: Generation,
        attempt_limit: std::num::NonZeroU32,
        fee: FeeRefund,
        mode: ExhaustionMode,
    ) -> Result<super::NativeRequestMoney, NativeAdmissionError> {
        self.money.admit_existing_selected(
            request,
            declaration,
            generation,
            attempt_limit,
            fee,
            mode,
        )
    }

    #[must_use]
    pub fn new(
        money: Arc<PlaneMoney>,
        gov: Arc<GovState>,
        keys: Arc<UnitKeyMint>,
        audit: Arc<dyn AuditSink>,
    ) -> Self {
        Self {
            money,
            gov,
            keys,
            audit,
            journal: None,
        }
    }

    /// The node's journal, told the end user a plane projects for each unit it opens.
    #[must_use]
    pub fn with_journal(mut self, journal: Arc<dyn super::HookJournal>) -> Self {
        self.journal = Some(journal);
        self
    }

    /// Allocate the real unit before route resolution. This creates no monetary Open, charge
    /// or grant. Root registers this same key in the checked pre-admission invocation phase.
    #[must_use]
    pub fn allocate(&self, classes: Arc<[String]>) -> Unit {
        self.unit(self.keys.mint(), classes)
    }

    /// Attach books to the DATA allocation's original registered unit without minting another.
    pub fn allocated_data(
        &self,
        allocation: &crate::auth::native_data::NativeDataAllocation,
        classes: Arc<[String]>,
    ) -> Result<Unit, NativeAdmissionError> {
        let context = allocation.context();
        if !context.is_live() || context.principal().is_none() {
            return Err(NativeAdmissionError::NotLive);
        }
        let generation = context
            .generation()
            .routing_generation()
            .ok_or(NativeAdmissionError::NotLive)?;
        let mut unit = self.unit(UnitKey::new(context.unit()), classes);
        unit.ctx.generation = generation;
        Ok(unit)
    }

    pub fn admit_existing(
        &self,
        request: CommittingRequest,
        classes: Arc<[String]>,
        fee: FeeRefund,
        mode: ExhaustionMode,
    ) -> Result<AdmittedRequest, NativeAdmissionError> {
        self.money.admit_existing(request, classes, fee, mode)
    }

    pub fn admit_existing_child(
        &self,
        request: CommittingRequest,
        parent: &ParentMoney,
        classes: Arc<[String]>,
        fee: FeeRefund,
    ) -> Result<AdmittedRequest, NativeAdmissionError> {
        self.money
            .admit_existing_child(request, parent, classes, fee)
    }

    /// Admits the request and opens it as a unit. A refusal (`LimitBlocked`) opened nothing and charged nothing.
    pub fn open(&self, admit: Admit<'_>) -> Result<Unit, LimitBlocked> {
        let Admit {
            instance,
            classes,
            key,
            cost,
            mode,
            arrived,
        } = admit;
        let pool = format!("{instance}{PLANE_LANE_SEP}");
        let grant = self.gov.try_admit(&cost, &key, &pool, arrived)?;
        let unit = self.keys.mint();
        let charge = grant.charge().clone();
        self.money.open_admitted(
            unit,
            UnitMoney {
                key,
                cost,
                lane: pool.clone(),
                pool,
                classes: Arc::clone(&classes),
                arrived,
                mode,
                fee: FeeRefund::PlaneFeeUnits(Arc::from(Vec::new())),
                charge,
            },
            Arc::new(grant),
        );
        Ok(self.unit(unit, classes))
    }

    fn unit(&self, unit: UnitKey, classes: Arc<[String]>) -> Unit {
        Unit {
            money: PortMoney::new(
                Arc::clone(&self.money) as Arc<dyn super::cancel::MoneySeam>,
                classes,
                Arc::clone(&self.audit),
            ),
            ctx: UnitCtx {
                call: CallId::UNBOUND,
                key: unit,
                origin: OriginKind::Client,
                session: None,
                generation: Generation::FIRST,
                admin_listener: false,
                kernel_verb_only: false,
            },
            journal: self.journal.clone(),
        }
    }

    /// Open an ordinary child under its live parent's actual admission and rate era. The
    /// money book checks the complete verified key and parent provenance before sharing its
    /// fee participation and governor hold. A missing, ended or foreign parent opens nothing.
    pub fn child(
        &self,
        parent: UnitKey,
        key: &VirtualKey,
        instance: &str,
        classes: Arc<[String]>,
    ) -> Result<Unit, busbar_contract::caps::ReasonCode> {
        let admitted = self.money.parent_money(parent, key)?;
        let child = self.keys.mint();
        self.money.open_child(
            &admitted,
            child,
            format!("{instance}{PLANE_LANE_SEP}"),
            Arc::clone(&classes),
            FeeRefund::PlaneFeeUnits(Arc::from([])),
        )?;
        Ok(Unit {
            money: PortMoney::new(
                Arc::clone(&self.money) as Arc<dyn super::cancel::MoneySeam>,
                classes,
                Arc::clone(&self.audit),
            ),
            ctx: UnitCtx {
                call: CallId::UNBOUND,
                key: child,
                origin: OriginKind::Nested { parent },
                session: None,
                generation: Generation::FIRST,
                admin_listener: false,
                kernel_verb_only: false,
            },
            journal: self.journal.clone(),
        })
    }

    /// Closes the unit once its answer is out: what the books left open is billed at `end`, the hold released.
    /// A second settlement of the same unit finds nothing open and does nothing.
    pub fn settle(&self, unit: UnitKey, end: UnitEnd) {
        self.money.settle_end_as(unit, end);
    }
}

/// The unit's end for a request answered `caller_status`. `ran` = the session ran; a request that was refused
/// before it (admission, or the plane's own refusal) spent nothing, so its end releases the request count.
#[must_use]
pub fn end_of(caller_status: u32, ran: bool) -> UnitEnd {
    UnitEnd {
        caller_status,
        cut: false,
        refused_unspent: !ran,
    }
}

#[cfg(test)]
#[path = "tests/port_billing_tests.rs"]
mod tests;
