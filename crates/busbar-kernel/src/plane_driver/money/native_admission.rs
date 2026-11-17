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
        mut pending: PendingAdmission,
        activate: impl FnOnce(
            Arc<UnitMoney>,
            Arc<AdmitGrant>,
            Arc<()>,
        ) -> Result<R, NativeAdmissionError>,
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
                let identity = open.identity.clone();
                all.insert(key, open);
                match activate(money.clone(), grant.clone(), identity) {
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
