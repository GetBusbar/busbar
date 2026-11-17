// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The retained request's one monetary callback, after read-only route resolution.

use std::sync::{Arc, Mutex, OnceLock};

use super::port::Unit;
use super::port_serve::{Books, UnitBooks};
use super::port_session::{RequestDeclaration, SessionError};
use super::port_upstream::{Members, Wants};
use super::request_admission::{
    AdmittedRequest, RequestAllocation, RequestPoolReceipt, RequestRoutes,
};
use crate::host_services::InvocationContext;
use crate::refusal::ClientRefusal;

pub struct AdmittedUnit {
    pub request: AdmittedRequest,
    pub unit: Unit,
    pub selected: Option<super::NativeRequestMoney>,
    rollback: Mutex<Option<super::AdmissionRollback>>,
}

impl AdmittedUnit {
    pub fn selected(
        unit: Unit,
        money: super::NativeRequestMoney,
        rollback: super::AdmissionRollback,
    ) -> Result<Self, super::NativeAdmissionError> {
        let request = money.request().clone();
        if unit.ctx.key != request.unit() || !rollback.accepts(&request) {
            return Err(super::NativeAdmissionError::Declaration);
        }
        Ok(Self {
            request,
            unit,
            selected: Some(money),
            rollback: Mutex::new(Some(rollback)),
        })
    }
    /// Keep exact money rollback armed until the same Task has accepted all admission proofs.
    pub fn ordinary(
        request: AdmittedRequest,
        unit: Unit,
        rollback: super::AdmissionRollback,
    ) -> Result<Self, super::NativeAdmissionError> {
        if unit.ctx.key != request.unit() || !rollback.accepts(&request) {
            return Err(super::NativeAdmissionError::Declaration);
        }
        Ok(Self {
            request,
            unit,
            selected: None,
            rollback: Mutex::new(Some(rollback)),
        })
    }
}

enum Commit {
    Ordinary(Box<dyn FnOnce(RequestPoolReceipt) -> Result<AdmittedUnit, ClientRefusal> + Send>),
    Selected(
        Box<
            dyn FnOnce(
                    RequestPoolReceipt,
                    RequestDeclaration,
                ) -> Result<AdmittedUnit, ClientRefusal>
                + Send,
        >,
    ),
}

/// Root owns the exact allocation and callback. Neither plugin facts nor a numeric unit can construct it.
pub struct Pending {
    context: InvocationContext,
    routes: Arc<RequestRoutes>,
    allocation: Mutex<Option<RequestAllocation>>,
    commit: Mutex<Option<Commit>>,
    admitted: OnceLock<AdmittedUnit>,
    journal: Option<Arc<dyn super::HookJournal>>,
    channel_budget: Option<crate::channels::budget::UnitBudget>,
    route: Option<super::route_identity::OriginalPlaneRoute>,
    current_rates: Option<crate::state::SelectedRateAdmission>,
}

impl Pending {
    pub fn new(
        allocation: RequestAllocation,
        routes: Arc<RequestRoutes>,
        journal: Option<Arc<dyn super::HookJournal>>,
        commit: impl FnOnce(RequestPoolReceipt) -> Result<AdmittedUnit, ClientRefusal> + Send + 'static,
    ) -> Self {
        Self {
            context: allocation.context().clone(),
            routes,
            allocation: Mutex::new(Some(allocation)),
            commit: Mutex::new(Some(Commit::Ordinary(Box::new(commit)))),
            admitted: OnceLock::new(),
            journal,
            channel_budget: None,
            route: None,
            current_rates: None,
        }
    }

    /// The selected initial binder must install its actual native checkpoint before phase commit.
    pub fn new_selected(
        allocation: RequestAllocation,
        routes: Arc<RequestRoutes>,
        journal: Option<Arc<dyn super::HookJournal>>,
        commit: impl FnOnce(RequestPoolReceipt, RequestDeclaration) -> Result<AdmittedUnit, ClientRefusal>
            + Send
            + 'static,
    ) -> Self {
        Self {
            context: allocation.context().clone(),
            routes,
            allocation: Mutex::new(Some(allocation)),
            commit: Mutex::new(Some(Commit::Selected(Box::new(commit)))),
            admitted: OnceLock::new(),
            journal,
            channel_budget: None,
            route: None,
            current_rates: None,
        }
    }

    pub fn context(&self) -> &InvocationContext {
        &self.context
    }
    pub fn with_channel_budget(mut self, budget: crate::channels::budget::UnitBudget) -> Self {
        self.channel_budget = Some(budget);
        self
    }
    pub fn channel_budget(&self) -> Option<&crate::channels::budget::UnitBudget> {
        self.channel_budget.as_ref()
    }
    pub fn with_route(mut self, route: super::route_identity::OriginalPlaneRoute) -> Self {
        self.route = Some(route);
        self
    }
    pub fn original_route(&self) -> Option<&super::route_identity::OriginalPlaneRoute> {
        self.route.as_ref()
    }
    pub fn with_current_rates(mut self, rates: crate::state::SelectedRateAdmission) -> Self {
        self.current_rates = Some(rates);
        self
    }
    pub(crate) fn current_rates(&self) -> Option<&crate::state::SelectedRateAdmission> {
        self.current_rates.as_ref()
    }
    pub fn journal(&self) -> Option<Arc<dyn super::HookJournal>> {
        self.journal.clone()
    }
    pub fn admitted(&self) -> Option<&AdmittedUnit> {
        self.admitted.get()
    }
    pub(crate) fn accept_admission(&self) -> Result<(), SessionError> {
        let admitted = self.admitted.get().ok_or(SessionError::NotDriven)?;
        let mut held = admitted.rollback.lock().unwrap();
        let rollback = held.as_ref().ok_or(SessionError::NotDriven)?;
        if !admitted.request.is_live() || !rollback.accepts(&admitted.request) {
            return Err(SessionError::NotDriven);
        }
        held.take()
            .expect("checked original rollback owner")
            .commit();
        Ok(())
    }
    pub(crate) fn routes(&self) -> Arc<RequestRoutes> {
        self.routes.clone()
    }

    pub(crate) fn admit(
        &self,
        members: Option<&mut dyn Members>,
        wants: Option<&Wants>,
        declaration: RequestDeclaration,
    ) -> Result<(), SessionError> {
        if !declaration.context().same_unit(&self.context) || !declaration.context().is_live() {
            return Err(SessionError::NotDriven);
        }
        let commit = self
            .commit
            .lock()
            .unwrap()
            .take()
            .ok_or(SessionError::NotDriven)?;
        let selected_required = declaration.selected();
        if selected_required && declaration.original_route().is_none() {
            return Err(SessionError::NotDriven);
        }
        if declaration.selected() && matches!(&commit, Commit::Ordinary(_)) {
            return Err(SessionError::NotDriven);
        }
        let allocation = self
            .allocation
            .lock()
            .unwrap()
            .take()
            .ok_or(SessionError::NotDriven)?;
        let mut members = members;
        let receipt = match wants {
            Some(wants) => {
                let members = members.as_deref_mut().ok_or(SessionError::NotDriven)?;
                let walk = members.request_walk().ok_or(SessionError::NotDriven)?;
                let receipt = allocation
                    .forward(&self.routes, walk, wants.model.as_deref())
                    .map_err(|_| SessionError::NotDriven)?;
                if !members.select_request(&receipt, wants) {
                    return Err(SessionError::NotDriven);
                }
                receipt
            }
            None => allocation
                .local(&self.routes)
                .map_err(|_| SessionError::NotDriven)?,
        };
        let admitted = match commit {
            Commit::Ordinary(commit) => commit(receipt),
            Commit::Selected(commit) => commit(receipt, declaration),
        }
        .map_err(SessionError::AdmissionRefused)?;
        if !admitted.request.context().same_unit(&self.context)
            || admitted.unit.ctx.key != admitted.request.unit()
            || !admitted.request.is_live()
            || (selected_required && admitted.selected.is_none())
            || admitted.selected.as_ref().is_some_and(|money| {
                !money
                    .request()
                    .context()
                    .same_unit(admitted.request.context())
                    || !money.request().is_live()
                    || money.request().unit() != admitted.request.unit()
            })
        {
            return Err(SessionError::NotDriven);
        }
        self.admitted
            .set(admitted)
            .map_err(|_| SessionError::NotDriven)?;
        if let Some(members) = members.filter(|_| wants.is_some()) {
            if !members.admit_request(&self.admitted.get().unwrap().request) {
                return Err(SessionError::NotDriven);
            }
        }
        Ok(())
    }

    fn books(&self) -> Option<UnitBooks<'_>> {
        let admitted = self.admitted.get()?;
        Some(
            UnitBooks::new(
                &admitted.unit.money,
                &admitted.unit.ctx,
                Some(&admitted.request.key().id),
            )
            .with_journal(admitted.unit.journal.as_deref()),
        )
    }
}

impl Books for Pending {
    fn ended(&self, ending: super::usage::Ending, usage: &super::usage::SessionUsage) {
        if let Some(money) = self.admitted.get().and_then(|unit| unit.selected.as_ref()) {
            if let Err(error) = money.work_ended(ending) {
                tracing::warn!(?error, "selected work ending remains in original custody");
            }
        } else if let Some(books) = self.books() {
            books.ended(ending, usage);
        }
        if let Some(admitted) = self.admitted.get() {
            admitted.request.context().retire();
        }
    }
    fn audit(&self, row: &super::port_money::AuditRow) {
        if let Some(books) = self.books() {
            books.audit(row);
        }
    }
    fn end_user(&self, user: &str) {
        if let Some(books) = self.books() {
            books.end_user(user);
        }
    }
}
