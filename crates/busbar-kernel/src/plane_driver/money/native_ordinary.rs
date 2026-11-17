// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The original funded ordinary terminal slot survives startup rollback and caller loss.

use super::{
    locked, FeeAccount, FeeRefund, NativeAdmissionError, PlaneMoney, UnitEnd, UnitMoney, UsageFold,
};
use crate::governance::unit_checkpoint::{OrdinaryTerminalCompletion, OrdinaryTerminalReservation};
use crate::plane_driver::request_admission::{AdmittedRequest, CommittingRequest};
use busbar_contract::storage::StorageCredit;
use std::alloc::Layout;
use std::sync::{Arc, Mutex};

pub struct NativeOrdinaryTerminalSlot {
    context: crate::host_services::InvocationContext,
    pub(super) state: Mutex<OrdinaryState>,
    _credit: StorageCredit,
}

pub(super) struct OrdinaryState {
    pub(super) admitting: bool,
    pub(super) request: Option<AdmittedRequest>,
    pub(super) intent: Option<UnitEnd>,
    reservation: OrdinaryTerminalReservation,
    terminal: Option<OrdinaryTerminalOwner>,
}

struct OrdinaryTerminalOwner {
    completion: OrdinaryTerminalCompletion,
    money: Arc<UnitMoney>,
    usage: Arc<UsageFold>,
    provider: Option<String>,
    fee: Arc<FeeAccount>,
}

impl NativeOrdinaryTerminalSlot {
    pub(crate) fn reserve(
        allocation: &crate::auth::native_data::NativeDataAllocation,
    ) -> Result<Arc<Self>, NativeAdmissionError> {
        let source = allocation.request().storage();
        let credit = source
            .try_reserve(Layout::new::<Self>().size())
            .map_err(|_| NativeAdmissionError::Declaration)?;
        let reservation =
            OrdinaryTerminalReservation::reserve(&source).map_err(NativeAdmissionError::Custody)?;
        Ok(Arc::new(Self {
            context: allocation.context().clone(),
            state: Mutex::new(OrdinaryState {
                admitting: false,
                request: None,
                intent: None,
                reservation,
                terminal: None,
            }),
            _credit: credit,
        }))
    }

    pub(super) fn accepts(&self, request: &CommittingRequest) -> bool {
        self.context.same_unit(request.context())
    }

    /// Drop records intent only. It cannot take Open, release a fee, or retire registration.
    pub(super) fn startup_cancelled(&self, request: &AdmittedRequest) {
        let mut state = locked(&self.state);
        if state
            .request
            .as_ref()
            .is_some_and(|held| held.same_admission(request))
            && state.intent.is_none()
            && state.terminal.is_none()
        {
            state.intent = Some(UnitEnd {
                caller_status: 500,
                cut: false,
                refused_unspent: true,
            });
        }
    }

    pub fn request_terminal(
        &self,
        request: &AdmittedRequest,
        end: UnitEnd,
    ) -> Result<(), NativeAdmissionError> {
        let mut state = locked(&self.state);
        if !state
            .request
            .as_ref()
            .is_some_and(|held| held.same_admission(request))
        {
            return Err(NativeAdmissionError::NotLive);
        }
        if state.intent.is_none() {
            state.intent = Some(end);
        }
        Ok(())
    }

    /// The same original checkpoint receipt; fee-debt Applied remains a separate requirement.
    pub fn checkpoint_confirmed(&self, money: &PlaneMoney) -> Result<bool, NativeAdmissionError> {
        let state = locked(&self.state);
        match &state.terminal {
            Some(owner) => owner
                .completion
                .is_confirmed(&money.gov)
                .map_err(NativeAdmissionError::Custody),
            None => Ok(false),
        }
    }
}

impl PlaneMoney {
    /// Transfer only the elected original intent. The Node keeps its slot installed while
    /// lending this call; no Node lock is held across legacy EndPost checkpoint facts.
    pub fn drive_ordinary_terminal(
        &self,
        slot: &Arc<NativeOrdinaryTerminalSlot>,
    ) -> Result<bool, NativeAdmissionError> {
        let mut state = locked(&slot.state);
        if state.terminal.is_some() {
            return Ok(true);
        }
        let Some(end) = state.intent else {
            return Ok(false);
        };
        let request = state
            .request
            .as_ref()
            .ok_or(NativeAdmissionError::NotLive)?;
        let key = request.unit();
        let mut all = self.shard(key);
        let open = all.get_mut(&key).ok_or(NativeAdmissionError::NotLive)?;
        let grant = open.grant.as_ref().ok_or(NativeAdmissionError::NotLive)?;
        if !request.matches_money_identity(&self.book, &open.identity, grant)
            || !request.matches_governance(&self.gov)
            || open.native.is_some()
            || !open
                .ordinary_terminal
                .as_ref()
                .is_some_and(|original| Arc::ptr_eq(original, slot))
        {
            return Err(NativeAdmissionError::NotLive);
        }
        let usage = open.usage_fold();
        let snapshot = self
            .checkpoint_snapshot(
                key,
                open,
                usage.counts(),
                (200..=299).contains(&end.caller_status),
            )
            .ok_or(NativeAdmissionError::Declaration)?;
        let completion = self
            .gov
            .finish_ordinary_checkpoint(snapshot, &state.reservation)
            .map_err(NativeAdmissionError::Custody)?;
        let refundable = open.money.fee.refunds(end.caller_status, &open.last);
        // Preserve original report and fee observer before removing Open. The observer is not
        // another participant and cannot hold children open or issue another refund.
        state.terminal = Some(OrdinaryTerminalOwner {
            completion,
            money: open.money.clone(),
            usage,
            provider: open.provider.take(),
            fee: open.fee.account.clone(),
        });
        let mut removed = all
            .remove(&key)
            .expect("verified original Open under shard lock");
        removed.fee.refundable = refundable;
        drop(all);
        drop(state);
        if end.refused_unspent
            && !removed.ledgered
            && removed.last.iter().all(|unit| unit.amount == 0)
        {
            self.gov.release_request(&removed.money.charge);
        }
        drop(removed);
        Ok(true)
    }
}
