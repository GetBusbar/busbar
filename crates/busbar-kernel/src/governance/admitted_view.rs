// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Read ordinary request budgets from the actual admitted monetary authority.
use super::GovState;
use crate::plane_driver::request_admission::AdmittedRequest;

pub struct AdmittedView {
    pub budgets: Vec<busbar_contract::hooks::BudgetBucketState>,
    /// Ordinary original-chain headroom, not the selected-resource governor's current policy.
    pub rate_headroom: Option<f64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionViewUnavailable {
    Stale,
    ForeignGovernor,
    MissingChain,
    WrongChain,
}

impl GovState {
    /// No key/pool/time overrides: all identity and window facts come from the same admission.
    /// The shared synchronous observation cache has the same custody limits as `budget_state`.
    pub fn admitted_view(
        &self,
        request: &AdmittedRequest,
    ) -> Result<AdmittedView, AdmissionViewUnavailable> {
        if !request.is_live() {
            return Err(AdmissionViewUnavailable::Stale);
        }
        if !request.matches_governance(self) {
            return Err(AdmissionViewUnavailable::ForeignGovernor);
        }
        let plan = request
            .charge()
            .chain()
            .ok_or(AdmissionViewUnavailable::MissingChain)?;
        let chain = request
            .cost()
            .admitted_chain(request.key(), plan)
            .ok_or(AdmissionViewUnavailable::WrongChain)?;
        let (_, pool) = busbar_kernel_ledger::cost::split_plane_lane(request.pool());
        let buckets = || {
            chain
                .iter()
                .copied()
                .filter(|bucket| bucket.applies_to_pool(pool))
        };
        let mut budgets =
            self.ordinary_budget_state_buckets(request.cost(), buckets(), request.arrived());
        self.apply_observation_liability(&mut budgets);
        let rate_headroom = self.rate_headroom_on(buckets(), request.arrived());
        // A record can be retired during a synchronous cache read; do not publish its view then.
        if !request.is_live() {
            return Err(AdmissionViewUnavailable::Stale);
        }
        Ok(AdmittedView {
            budgets,
            rate_headroom,
        })
    }
}

#[cfg(test)]
#[path = "tests/admitted_view_tests.rs"]
mod tests;
