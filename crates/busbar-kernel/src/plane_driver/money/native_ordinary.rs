// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The original funded ordinary terminal slot survives startup rollback and caller loss.

use super::{locked, FeeAccount, NativeAdmissionError, PlaneMoney, UnitEnd, UnitMoney, UsageFold};
use crate::governance::unit_checkpoint::{OrdinaryTerminalCompletion, OrdinaryTerminalReservation};
use crate::plane_driver::request_admission::{AdmittedRequest, CommittingRequest};
use busbar_contract::storage::StorageCredit;
use std::alloc::Layout;
use std::sync::{Arc, Mutex};

pub struct NativeOrdinaryTerminalSlot {
    context: crate::host_services::InvocationContext,
    // The original request source that funds this slot's dependent fee observer.
    source: busbar_contract::storage::StorageSource,
    pub(super) state: Mutex<OrdinaryState>,
    _credit: StorageCredit,
}

pub(super) struct OrdinaryState {
    pub(super) request: Option<AdmittedRequest>,
    // The original fee observer, installed with the admission so captures before the terminal
    // transfer still reach it.
    pub(super) fee: Option<Arc<crate::governance::fee_debt::FeeDebtObserver>>,
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
    pub fn reserve(
        context: &crate::host_services::InvocationContext,
        source: &busbar_contract::storage::StorageSource,
    ) -> Result<Arc<Self>, NativeAdmissionError> {
        let credit = source
            .try_reserve(Layout::new::<Self>().size())
            .map_err(|_| NativeAdmissionError::Declaration)?;
        let reservation =
            OrdinaryTerminalReservation::reserve(source).map_err(NativeAdmissionError::Custody)?;
        Ok(Arc::new(Self {
            context: context.clone(),
            source: source.clone(),
            state: Mutex::new(OrdinaryState {
                request: None,
                intent: None,
                fee: None,
                reservation,
                terminal: None,
            }),
            _credit: credit,
        }))
    }

    /// The exact admitted request this slot owns, for the Node's terminal callers.
    pub fn admitted(&self) -> Option<AdmittedRequest> {
        locked(&self.state).request.clone()
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
            self.gov.release_request_observed(
                &removed.money.charge,
                removed.fee.account.observer.as_deref(),
            );
        }
        drop(removed);
        Ok(true)
    }
}

impl OrdinaryState {
    pub(super) fn has_terminal(&self) -> bool {
        self.terminal.is_some()
    }
}

impl NativeOrdinaryTerminalSlot {
    /// The original transferred money report: the serving lane, recipe attribution and the
    /// exact usage fold captured from the verified Open. None until the single transfer.
    /// Root borrows it for audit inputs; it is not a receipt and creates no bill.
    pub fn ordinary_usage(&self) -> Option<super::UsageView> {
        let state = locked(&self.state);
        let owner = state.terminal.as_ref()?;
        let (_, pool) = busbar_kernel_ledger::cost::split_plane_lane(&owner.money.pool);
        Some(super::UsageView::Legacy {
            lane: owner.money.lane.clone(),
            attribution: busbar_kernel_audit::attribution(
                owner.money.key.group.as_deref().unwrap_or_default(),
                pool,
                owner.provider.as_deref().unwrap_or_default(),
            ),
            usage: Arc::clone(&owner.usage),
        })
    }

    /// The original Open's meter classes, for naming the folded usage lines.
    pub fn ordinary_classes(&self) -> Option<Arc<[String]>> {
        let state = locked(&self.state);
        state
            .terminal
            .as_ref()
            .map(|owner| Arc::clone(&owner.money.classes))
    }
}

impl NativeOrdinaryTerminalSlot {
    /// Whether the whole original fee target set has its FEE-DEBT r1 receipt: the original
    /// parent/child fee decision completed AND every target is Applied or honestly
    /// CancelledBeforeSend. Hot FeeAccount completion alone is never sufficient.
    pub fn fee_join_complete(&self) -> bool {
        matches!(
            self.fee_status(),
            Some(crate::governance::fee_debt::FeeDebtStatus::Complete(_))
        )
    }

    /// The typed original fee receipt; None before the single transfer or without an observer.
    pub fn fee_status(&self) -> Option<crate::governance::fee_debt::FeeDebtStatus> {
        let state = locked(&self.state);
        let owner = state.terminal.as_ref()?;
        let observer = state.fee.as_ref()?;
        if locked(&owner.fee.state).completed.is_none() {
            return Some(crate::governance::fee_debt::FeeDebtStatus::Pending);
        }
        Some(observer.status())
    }

    /// Offer one original flush capture to this slot's observer (Node association callback).
    pub fn offer_fee_capture(&self, capture: &Arc<crate::governance::fee_debt::FeeCapture>) {
        let observer = locked(&self.state).fee.clone();
        if let Some(observer) = observer {
            observer.offer(capture);
        }
    }

    pub(super) fn source(&self) -> &busbar_contract::storage::StorageSource {
        &self.source
    }
}
