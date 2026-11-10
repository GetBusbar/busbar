// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Host custody for cross-request accounting. Plugins never construct a charging binding.
use super::*;
use crate::persistence::observations::{
    Binding, BoundScope, BudgetBinding, ObservationStore, PrincipalBinding, RatedSubject, Receipt,
};
use busbar_contract::abi::sdk::plane::observation::{Observation, ScopeId};
use busbar_kernel_ledger::cost::{ClassPrice, NANOS_PER_CENT};

/// Operator-approved accounting policy for one configured upstream binding.
/// The root supplies this only after routing has verified the selected destination.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservationPolicy {
    pub instance: String,
    pub destination: String,
    pub serving_subject: String,
    pub accounting_namespace: String,
    /// Eligible declared classes, excluding gateway admission/fee counts.
    pub classes: Vec<u32>,
    /// Additional approved accounting lanes. Index zero always remains the serving lane.
    pub rated_subjects: Vec<String>,
    /// Conservative liability retained until an explicitly closed final scope.
    pub reserve_nanos: u128,
    pub ordered_revisions: bool,
}

#[derive(Debug)]
pub enum ObservationRuntimeError {
    Unauthorized,
    Unpriced,
    AlreadyBound,
    LegacyOverlap,
    Store(crate::persistence::observations::Error),
}
impl From<crate::persistence::observations::Error> for ObservationRuntimeError {
    fn from(error: crate::persistence::observations::Error) -> Self {
        Self::Store(error)
    }
}

/// Stable, collision-free identity for a dated enforcement cell.
pub(crate) fn budget_id(bucket: &str, window: u64) -> String {
    // JSON array framing distinguishes arbitrary bucket strings and window boundaries.
    serde_json::to_string(&(bucket, window)).expect("strings and integers serialize")
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum PendingKind {
    Create,
    Submit,
    Close,
}
#[derive(Clone, Copy)]
pub(super) struct PendingObservation {
    kind: PendingKind,
    operation: crate::persistence::facade::PendingId,
    scope: ScopeId,
}

impl PlaneMoney {
    fn observation_error(
        &self,
        unit: UnitKey,
        kind: PendingKind,
        error: crate::persistence::observations::Error,
    ) -> ObservationRuntimeError {
        if let crate::persistence::observations::Error::Pending { operation, scope } = &error {
            if let Some(open) = self.shard(unit).get_mut(&unit) {
                open.observation_pending = Some(PendingObservation {
                    kind,
                    operation: *operation,
                    scope: *scope,
                });
            }
        }
        ObservationRuntimeError::Store(error)
    }
    async fn resume_observation(
        &self,
        unit: UnitKey,
        kind: PendingKind,
    ) -> Result<Option<ScopeId>, ObservationRuntimeError> {
        let pending = self
            .shard(unit)
            .get(&unit)
            .and_then(|open| open.observation_pending);
        let Some(pending) = pending else {
            return Ok(None);
        };
        if pending.kind != kind {
            return Err(ObservationRuntimeError::AlreadyBound);
        }
        let result = self
            .observation_store()?
            .retry(pending.operation, pending.scope)
            .await
            .map_err(|_| {
                // A failed reconciliation read cannot turn an already unknown commit
                // into a definitive refusal or authorize another paid create.
                ObservationRuntimeError::Store(crate::persistence::observations::Error::Pending {
                    operation: pending.operation,
                    scope: pending.scope,
                })
            })?;
        if let Some(open) = self.shard(unit).get_mut(&unit) {
            open.observation_pending = None;
        }
        if result {
            Ok(Some(pending.scope))
        } else {
            Err(ObservationRuntimeError::Unpriced)
        }
    }
    async fn refresh_observation_views(&self, unit: UnitKey) {
        let Some(bound) = self
            .shard(unit)
            .get(&unit)
            .and_then(|o| o.observation.clone())
        else {
            return;
        };
        let Ok(store) = self.observation_store() else {
            return;
        };
        let Ok(binding) = store.binding(&bound).await else {
            return;
        };
        for budget in binding.budgets {
            let Ok((id, window)) = serde_json::from_str::<(String, u64)>(&budget.id) else {
                continue;
            };
            let total = store.budget(&budget.id).await.unwrap_or_else(|_| {
                crate::persistence::observations::BudgetTotal {
                    spent_nanos: u128::MAX,
                    ..Default::default()
                }
            });
            self.gov.cache_observation_total(&id, window, total);
        }
    }

    fn observation_store(&self) -> Result<ObservationStore, ObservationRuntimeError> {
        let store = self
            .gov
            .core_store_handle()
            .map_err(|_| ObservationRuntimeError::Unauthorized)?;
        Ok(ObservationStore::open(store)?)
    }

    fn observation_identity(
        &self,
        unit: UnitKey,
        policy: &ObservationPolicy,
    ) -> Result<(Arc<UnitMoney>, PrincipalBinding), ObservationRuntimeError> {
        let all = self.shard(unit);
        let open = all
            .get(&unit)
            .ok_or(ObservationRuntimeError::Unauthorized)?;
        if open.finished
            || open.ledgered
            || open.abandoned
            || open.grant.is_none()
            || policy.instance.is_empty()
            || policy.destination.is_empty()
            || policy.accounting_namespace.is_empty()
        {
            return Err(ObservationRuntimeError::Unauthorized);
        }
        let money = open.money.clone();
        let identity = PrincipalBinding {
            principal: money.key.id.clone(),
            instance: policy.instance.clone(),
            destination: policy.destination.clone(),
            accounting_namespace: policy.accounting_namespace.clone(),
        };
        Ok((money, identity))
    }

    /// Freeze the admitted caller, budget chain, declared classes and original tariff.
    /// This entry point is host-only; the wire accepts neither policy nor prices.
    pub async fn issue_observation_scope(
        &self,
        unit: UnitKey,
        policy: &ObservationPolicy,
    ) -> Result<ScopeId, ObservationRuntimeError> {
        let (money, principal) = self.observation_identity(unit, policy)?;
        if let Some(scope) = self.observation_scope(unit) {
            return Ok(scope);
        }
        if let Some(scope) = self.resume_observation(unit, PendingKind::Create).await? {
            let store = self.observation_store()?;
            let bound = store.bind_scope(scope, principal).await?;
            let binding = store.binding(&bound).await?;
            self.install_observation_scope(unit, bound, &binding)?;
            self.refresh_observation_views(unit).await;
            return Ok(scope);
        }
        if policy.reserve_nanos == 0
            || policy.classes.is_empty()
            || policy.classes.len() > 64
            || policy.rated_subjects.len() > 15
        {
            return Err(ObservationRuntimeError::Unpriced);
        }
        {
            let all = self.shard(unit);
            if all.get(&unit).is_none_or(|o| o.observation.is_some()) {
                return Err(ObservationRuntimeError::AlreadyBound);
            }
        }
        let mut classes = BTreeMap::new();
        for &class in &policy.classes {
            let name = money
                .classes
                .get(class as usize)
                .ok_or(ObservationRuntimeError::Unpriced)?;
            if money.fee.is_fee(class) || classes.insert(class, name.clone()).is_some() {
                return Err(ObservationRuntimeError::Unpriced);
            }
        }
        let mut subjects = Vec::new();
        for lane in std::iter::once(&policy.serving_subject).chain(policy.rated_subjects.iter()) {
            if subjects.iter().any(|s: &RatedSubject| &s.name == lane) {
                return Err(ObservationRuntimeError::Unpriced);
            }
            let pricing = money.cost.card().lane_pricing(lane);
            // An absent card cannot silently make an expensive leaf free.
            if !pricing.card.pricing_enabled() {
                return Err(ObservationRuntimeError::Unpriced);
            }
            let mut rates_nanos = BTreeMap::new();
            for (&class, name) in &classes {
                let ClassPrice::Nanos(rate) = pricing.class_price(name) else {
                    return Err(ObservationRuntimeError::Unpriced);
                };
                rates_nanos.insert(class, rate);
            }
            subjects.push(RatedSubject {
                name: lane.clone(),
                rates_nanos,
            });
        }
        let (_, pool) = busbar_kernel_ledger::cost::split_plane_lane(&money.pool);
        let chain = money
            .cost
            .chain_for(&money.key)
            .map_err(|_| ObservationRuntimeError::Unpriced)?;
        let ordinary = self
            .gov
            .budget_state(&money.cost, &money.key, money.arrived);
        let mut budgets = Vec::new();
        for bucket in chain.iter().filter(|b| b.applies_to_pool(pool)) {
            let window = crate::governance::budget_window(bucket.window, money.arrived);
            let spent = ordinary
                .iter()
                .find(|b| b.bucket_id == bucket.bucket_id)
                .ok_or(ObservationRuntimeError::Unpriced)?
                .spend_micros_at_current_rate;
            let limit = match bucket.budget_cap {
                Some(cap) => u128::try_from(cap)
                    .map_err(|_| ObservationRuntimeError::Unpriced)?
                    .checked_mul(NANOS_PER_CENT)
                    .ok_or(ObservationRuntimeError::Unpriced)?
                    .saturating_sub(
                        u128::try_from(spent)
                            .map_err(|_| ObservationRuntimeError::Unpriced)?
                            .saturating_mul(NANOS_PER_MICRO),
                    ),
                None => u128::MAX,
            };
            budgets.push(BudgetBinding {
                id: budget_id(bucket.bucket_id, window),
                limit_nanos: limit,
                reserve_nanos: policy.reserve_nanos,
            });
        }
        let binding = Binding {
            principal: principal.principal.clone(),
            group: money.key.group.clone().unwrap_or_default(),
            instance: principal.instance.clone(),
            destination: principal.destination.clone(),
            accounting_namespace: principal.accounting_namespace.clone(),
            serving_subject: policy.serving_subject.clone(),
            rate_time: money.arrived,
            subjects,
            budgets,
            ordered_revisions: policy.ordered_revisions,
            classes,
        };
        let store = self.observation_store()?;
        {
            let mut all = self.shard(unit);
            let open = all
                .get_mut(&unit)
                .ok_or(ObservationRuntimeError::Unauthorized)?;
            if open.observation_started {
                return Err(ObservationRuntimeError::AlreadyBound);
            }
            if open.last.iter().any(|u| {
                units_bill(u.source) && u.amount != 0 && binding.classes.contains_key(&u.class)
            }) {
                return Err(ObservationRuntimeError::LegacyOverlap);
            }
            // Claim before the first await: uncertain reservation creation must never trigger
            // a second scope (or a second paid operation) on a repeated plugin poll.
            open.observation_started = true;
            open.observation_classes.extend(binding.classes.keys());
        }
        let scope = store
            .create_scope(binding)
            .await
            .map_err(|e| self.observation_error(unit, PendingKind::Create, e))?;
        let bound = store.bind_scope(scope, principal).await?;
        let binding = store.binding(&bound).await?;
        self.install_observation_scope(unit, bound, &binding)?;
        self.refresh_observation_views(unit).await;
        Ok(scope)
    }

    /// Reattach only through a newly admitted host identity. Unknown IDs stay unattributed.
    /// The original tariff, date and subjects are read from durable custody, never refreshed.
    pub async fn attach_observation_scope(
        &self,
        unit: UnitKey,
        policy: &ObservationPolicy,
        scope: ScopeId,
    ) -> Result<(), ObservationRuntimeError> {
        let (_, principal) = self.observation_identity(unit, policy)?;
        let store = self.observation_store()?;
        let bound = store.bind_scope(scope, principal).await?;
        let binding = store.binding(&bound).await?;
        self.install_observation_scope(unit, bound, &binding)?;
        self.refresh_observation_views(unit).await;
        Ok(())
    }

    fn install_observation_scope(
        &self,
        unit: UnitKey,
        bound: BoundScope,
        binding: &Binding,
    ) -> Result<(), ObservationRuntimeError> {
        let mut all = self.shard(unit);
        let open = all
            .get_mut(&unit)
            .ok_or(ObservationRuntimeError::Unauthorized)?;
        if open.observation.is_some() {
            return Err(ObservationRuntimeError::AlreadyBound);
        }
        for (&class, name) in &binding.classes {
            if open.money.classes.get(class as usize) != Some(name) || open.money.fee.is_fee(class)
            {
                return Err(ObservationRuntimeError::Unpriced);
            }
            if open
                .last
                .iter()
                .any(|u| u.class == class && units_bill(u.source) && u.amount != 0)
            {
                return Err(ObservationRuntimeError::LegacyOverlap);
            }
        }
        open.observation_classes.extend(binding.classes.keys());
        open.observation = Some(Arc::new(bound));
        Ok(())
    }

    pub fn observation_scope(&self, unit: UnitKey) -> Option<ScopeId> {
        self.shard(unit)
            .get(&unit)?
            .observation
            .as_ref()
            .map(|b| b.id())
    }

    pub fn observations_supported(&self) -> bool {
        self.observation_store().is_ok()
    }

    /// Acknowledge only the store's atomic event+journal+budget+dated-count commit.
    /// Cancellation drops transient attachment but never releases durable liability.
    pub async fn submit_observation(
        &self,
        unit: UnitKey,
        observation: &Observation,
        observed_at: u64,
    ) -> Result<Receipt, ObservationRuntimeError> {
        let bound = self
            .shard(unit)
            .get(&unit)
            .and_then(|o| o.observation.clone())
            .ok_or(ObservationRuntimeError::Unauthorized)?;
        self.resume_observation(unit, PendingKind::Submit).await?;
        let receipt = self
            .observation_store()?
            .submit(&bound, observation, observed_at)
            .await
            .map_err(|e| self.observation_error(unit, PendingKind::Submit, e))?;
        self.refresh_observation_views(unit).await;
        Ok(receipt)
    }

    /// The host invokes this only after it knows no new economic component can arrive.
    pub async fn close_observation_scope(
        &self,
        unit: UnitKey,
    ) -> Result<(), ObservationRuntimeError> {
        let bound = self
            .shard(unit)
            .get(&unit)
            .and_then(|o| o.observation.clone())
            .ok_or(ObservationRuntimeError::Unauthorized)?;
        self.resume_observation(unit, PendingKind::Close).await?;
        self.observation_store()?
            .close_scope(&bound)
            .await
            .map_err(|e| self.observation_error(unit, PendingKind::Close, e))?;
        self.refresh_observation_views(unit).await;
        Ok(())
    }
}
