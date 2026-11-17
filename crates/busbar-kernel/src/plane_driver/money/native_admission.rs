// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Checked installation of the one native request admission into its existing allocation.

use super::*;
use crate::governance::{LimitBlocked, PLANE_LANE_SEP};
use crate::plane_driver::request_admission::{AdmissionError, AdmittedRequest, CommittingRequest};

#[derive(Debug)]
pub enum NativeAdmissionError {
    NotLive,
    Occupied,
    MissingChain,
    Blocked(LimitBlocked),
    Phase(AdmissionError),
    Parent(ReasonCode),
    Declaration,
    SelectedTerminalRequired,
    Custody(busbar_contract::records::RecordStoreError),
}

impl From<ReasonCode> for NativeAdmissionError {
    fn from(reason: ReasonCode) -> Self {
        Self::Parent(reason)
    }
}

/// Owns an ordinary callback's admission until physical startup and Pending validation succeed.
/// The factory checks the actual book/Open/grant; no caller-supplied cleanup closure is accepted.
pub struct AdmissionRollback {
    money: Arc<PlaneMoney>,
    request: Option<AdmittedRequest>,
    selected: Option<Arc<super::native_terminal::TerminalSlot>>,
}

impl AdmissionRollback {
    pub fn accepts(&self, request: &AdmittedRequest) -> bool {
        let Some(held) = &self.request else {
            return false;
        };
        if held.unit() != request.unit() {
            return false;
        }
        let all = self.money.shard(held.unit());
        let Some(open) = all.get(&held.unit()) else {
            return false;
        };
        let Some(grant) = &open.grant else {
            return false;
        };
        held.matches_money_identity(&self.money.book, &open.identity, grant)
            && request.matches_money_identity(&self.money.book, &open.identity, grant)
            && request.matches_governance(&self.money.gov)
    }

    /// Transfer ongoing settlement responsibility to the existing retained response owner.
    pub fn commit(mut self) {
        self.request.take();
    }
}

impl Drop for AdmissionRollback {
    fn drop(&mut self) {
        if let Some(request) = self.request.take() {
            if let Some(slot) = &self.selected {
                if let Err(error) = self.money.abort_selected_startup(&request, slot) {
                    // Refusal leaves the exact Open and checkpoint owner intact. Surface the
                    // failure to the existing response confirmation rather than losing facts.
                    slot.publish(Err(format!(
                        "selected startup terminal transfer refused: {error:?}"
                    )));
                }
            } else {
                let _ = self.money.settle_admitted(
                    &request,
                    UnitEnd {
                        caller_status: 500,
                        cut: false,
                        refused_unspent: true,
                    },
                );
            }
            request.context().retire();
        }
    }
}

/// Until installation commits, only this owner refunds the newly acquired admission.
/// It is never a fee participant, and it cannot refund an existing Open's charge.
struct PendingAdmission {
    gov: Arc<GovState>,
    admission: Option<(Arc<UnitMoney>, Arc<AdmitGrant>)>,
}

impl PendingAdmission {
    fn new(gov: Arc<GovState>, mut money: UnitMoney, grant: AdmitGrant) -> Self {
        money.charge = grant.charge().clone();
        Self {
            gov,
            admission: Some((Arc::new(money), Arc::new(grant))),
        }
    }

    fn facts(&self) -> &(Arc<UnitMoney>, Arc<AdmitGrant>) {
        self.admission.as_ref().expect("uncommitted admission")
    }

    fn commit(&mut self) {
        self.admission.take();
    }
}

impl Drop for PendingAdmission {
    fn drop(&mut self) {
        if let Some((_, grant)) = &self.admission {
            self.gov.refund_charge(grant.charge());
            self.gov.release_request(grant.charge());
        }
        // The final grant reference then releases the actual concurrency and shutdown hold.
    }
}

impl PlaneMoney {
    pub fn admission_rollback(
        self: &Arc<Self>,
        request: &AdmittedRequest,
    ) -> Result<AdmissionRollback, NativeAdmissionError> {
        let all = self.shard(request.unit());
        let open = all
            .get(&request.unit())
            .ok_or(NativeAdmissionError::NotLive)?;
        let grant = open.grant.as_ref().ok_or(NativeAdmissionError::NotLive)?;
        if !request.matches_money_identity(&self.book, &open.identity, grant)
            || !request.matches_governance(&self.gov)
            || open.finished
            || open.ledgered
            || open.abandoned
            || open.last.iter().any(|count| count.amount != 0)
        {
            return Err(NativeAdmissionError::NotLive);
        }
        let selected = if let Some(native) = &open.native {
            let parts = native
                .checkpoint()
                .partitions
                .as_ref()
                .ok_or(NativeAdmissionError::Declaration)?;
            if parts.disposition
                != crate::governance::unit_checkpoint::partitions::Disposition::Running
                || !parts.attempts.is_empty()
                || parts.session.is_some()
                || parts.far_end_answered
                || parts.caller_bytes_committed
                || parts.final_target.is_some()
            {
                return Err(NativeAdmissionError::SelectedTerminalRequired);
            }
            Some(native.terminal.clone())
        } else {
            None
        };
        Ok(AdmissionRollback {
            money: self.clone(),
            request: Some(request.clone()),
            selected,
        })
    }

    /// Bind the retained Task's declaration before the admitted phase can expose host effects.
    /// Routing supplies its actual captured generation and complete reachable attempt ceiling;
    /// neither value substitutes for the checked allocation or the original monetary grant.
    pub fn admit_existing_selected(
        self: &Arc<Self>,
        request: CommittingRequest,
        declaration: super::super::port_session::RequestDeclaration,
        routing_generation: crate::registry::Generation,
        attempt_limit: std::num::NonZeroU32,
        fee: FeeRefund,
        mode: ExhaustionMode,
    ) -> Result<native_attempt::NativeRequestMoney, NativeAdmissionError> {
        use crate::governance::unit_checkpoint::{
            partitions::{Disposition, PartitionedUsageV1, SessionOrigin, MAX_PREPARATIONS},
            SelectedActivationError,
        };
        if !request.is_live()
            || !request.context().same_unit(declaration.context())
            || !declaration.context().is_live()
            || request.context().generation().routing_generation() != Some(routing_generation)
        {
            return Err(NativeAdmissionError::NotLive);
        }
        if !request.accepts_governance(&self.gov) {
            return Err(NativeAdmissionError::Phase(AdmissionError::Principal));
        }
        if !declaration.selected() || attempt_limit.get() as usize > MAX_PREPARATIONS {
            return Err(NativeAdmissionError::Declaration);
        }
        let declared = declaration.declaration();
        let classes: Arc<[String]> = declaration
            .classes()
            .iter()
            .map(|class| class.class.to_string())
            .collect();
        let declared_classes = classes.iter().cloned().collect();
        let attempt_classes = classes
            .iter()
            .filter(|class| declared.is_attempt_class(class))
            .cloned()
            .collect();
        let physical_classes = declared.physical_classes().map(str::to_owned).collect();
        let instance = request.context().instance().to_owned();
        let lane = format!("{instance}{PLANE_LANE_SEP}");
        let plan = request
            .cost()
            .plan_chain(request.key())
            .ok_or(NativeAdmissionError::MissingChain)?;
        let money = UnitMoney {
            key: request.key().clone(),
            cost: request.cost().clone(),
            pool: request.pool().to_owned(),
            lane: lane.clone(),
            classes,
            arrived: request.arrived(),
            mode,
            fee,
            charge: Default::default(),
        };
        let grant = self
            .gov
            .try_admit_planned(
                &money.cost,
                &money.key,
                &money.pool,
                money.arrived,
                Some(&plan),
            )
            .map_err(NativeAdmissionError::Blocked)?;
        let key = request.unit();
        let pending = PendingAdmission::new(self.gov.clone(), money, grant);
        self.install_native_pending_with(key, pending, |open| {
            let parts = PartitionedUsageV1 {
                version: 1,
                request_pool: open.money.pool.clone(),
                routing_generation: routing_generation.get(),
                attempt_limit: attempt_limit.get(),
                declared_classes,
                attempt_classes,
                physical_classes,
                session_origin: SessionOrigin {
                    instance,
                    lane,
                    provider: None,
                },
                fee: open.fee.selected_fee().0,
                session: None,
                attempts: Vec::new(),
                far_end_answered: false,
                caller_bytes_committed: false,
                disposition: Disposition::Running,
                final_target: None,
            };
            let snapshot = self
                .selected_checkpoint_snapshot(key, open, parts)
                .map_err(NativeAdmissionError::Custody)?;
            self.gov
                .activate_selected_checkpoint(snapshot, |accepted| {
                    open.native =
                        Some(native_attempt::NativeMoney::admitted(accepted, declaration));
                    let admitted = request
                        .admitted(
                            open.money.clone(),
                            open.grant
                                .as_ref()
                                .expect("new admission holds its grant")
                                .clone(),
                            self.gov.clone(),
                            self.book.clone(),
                            open.identity.clone(),
                        )
                        .map_err(NativeAdmissionError::Phase)?;
                    Ok(native_attempt::NativeRequestMoney {
                        terminal: open
                            .native
                            .as_ref()
                            .expect("selected checkpoint installed")
                            .terminal
                            .clone(),
                        money: self.clone(),
                        request: admitted,
                    })
                })
                .map_err(|error| match error {
                    SelectedActivationError::Custody(error) => NativeAdmissionError::Custody(error),
                    SelectedActivationError::Publish(error) => error,
                })
        })
    }

    /// Activate a child's own checked route while retaining its actual parent's monetary
    /// scope, grant and fee participation. This path never acquires another admission.
    pub fn admit_existing_child(
        &self,
        request: CommittingRequest,
        parent: &ParentMoney,
        classes: Arc<[String]>,
        fee: FeeRefund,
    ) -> Result<AdmittedRequest, NativeAdmissionError> {
        if !request.is_live() {
            return Err(NativeAdmissionError::NotLive);
        }
        if !request.accepts_governance(&self.gov) {
            return Err(NativeAdmissionError::Phase(AdmissionError::Principal));
        }
        let unit = request.unit();
        let lane = format!("{}{PLANE_LANE_SEP}", request.context().instance());
        self.install_child_with(
            parent,
            unit,
            lane,
            classes,
            fee,
            |money, grant, identity| {
                request
                    .admitted_child(
                        parent,
                        money,
                        grant,
                        self.gov.clone(),
                        self.book.clone(),
                        identity,
                    )
                    .map_err(NativeAdmissionError::Phase)
            },
        )
    }

    /// Complete the actual pre-money allocation. `begin` already won its one-shot phase before
    /// this method can acquire a grant; no numeric key or copied route metadata enters here.
    pub fn admit_existing(
        &self,
        request: CommittingRequest,
        classes: Arc<[String]>,
        fee: FeeRefund,
        mode: ExhaustionMode,
    ) -> Result<AdmittedRequest, NativeAdmissionError> {
        if !request.is_live() {
            return Err(NativeAdmissionError::NotLive);
        }
        if !request.accepts_governance(&self.gov) {
            return Err(NativeAdmissionError::Phase(AdmissionError::Principal));
        }
        let plan = request
            .cost()
            .plan_chain(request.key())
            .ok_or(NativeAdmissionError::MissingChain)?;
        let money = UnitMoney {
            key: request.key().clone(),
            cost: request.cost().clone(),
            pool: request.pool().to_owned(),
            lane: format!("{}{PLANE_LANE_SEP}", request.context().instance()),
            classes,
            arrived: request.arrived(),
            mode,
            fee,
            charge: Default::default(),
        };
        let grant = self
            .gov
            .try_admit_planned(
                &money.cost,
                &money.key,
                &money.pool,
                money.arrived,
                Some(&plan),
            )
            .map_err(NativeAdmissionError::Blocked)?;
        let pending = PendingAdmission::new(self.gov.clone(), money, grant);
        let key = request.unit();
        self.install_native_pending(key, pending, |money, grant, identity| {
            request
                .admitted(money, grant, self.gov.clone(), self.book.clone(), identity)
                .map_err(NativeAdmissionError::Phase)
        })
    }

    // The sole production caller above supplies the typed phase transition. Keeping this
    // transaction private prevents a scalar-only path from opening native money authority.
    fn install_native_pending<R>(
        &self,
        key: UnitKey,
        pending: PendingAdmission,
        activate: impl FnOnce(
            Arc<UnitMoney>,
            Arc<AdmitGrant>,
            Arc<()>,
        ) -> Result<R, NativeAdmissionError>,
    ) -> Result<R, NativeAdmissionError> {
        self.install_native_pending_with(key, pending, |open| {
            activate(
                open.money.clone(),
                open.grant
                    .as_ref()
                    .expect("new admission holds its grant")
                    .clone(),
                open.identity.clone(),
            )
        })
    }

    fn install_native_pending_with<R>(
        &self,
        key: UnitKey,
        mut pending: PendingAdmission,
        activate: impl FnOnce(&mut Open) -> Result<R, NativeAdmissionError>,
    ) -> Result<R, NativeAdmissionError> {
        if !Arc::ptr_eq(&self.gov, &pending.gov) {
            return Err(NativeAdmissionError::NotLive);
        }
        let checkpoint_audit = self.post.checkpoint_facts(key);
        let mut removed = None;
        let result = {
            let mut all = self.shard(key);
            if all.contains_key(&key) {
                Err(NativeAdmissionError::Occupied)
            } else {
                let (money, grant) = pending.facts();
                let account = Arc::new(FeeAccount {
                    gov: self.gov.clone(),
                    money: money.clone(),
                    state: Mutex::new(FeeState {
                        children: 0,
                        parent_refund: None,
                        child_incurred: false,
                        completed: None,
                    }),
                });
                let open = Open::new(
                    money.clone(),
                    Some(grant.clone()),
                    FeeParticipation {
                        account,
                        owner: true,
                        // Rollback is owned by PendingAdmission until activation succeeds.
                        refundable: false,
                    },
                    checkpoint_audit,
                );
                all.insert(key, open);
                match activate(all.get_mut(&key).expect("inserted under the same lock")) {
                    Ok(receipt) => {
                        pending.commit();
                        Ok(receipt)
                    }
                    Err(error) => {
                        // The shard stayed locked since the vacant check: this is exactly our
                        // new Open. Its fee participant cannot itself refund the charge.
                        removed = all.remove(&key);
                        Err(error)
                    }
                }
            }
        };
        // No governor refund, concurrency release or participant drop under a money shard.
        drop(removed);
        drop(pending);
        result
    }
}

#[cfg(test)]
#[path = "native_admission_tests.rs"]
mod tests;
