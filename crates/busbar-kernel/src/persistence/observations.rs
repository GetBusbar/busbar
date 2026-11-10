// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Durable usage observation settlement. Each transaction changes the component,
//! immutable signed-difference journal and authoritative aggregates together.
//! Consequently there is no additive outbox replay gap or process-local seen set.
//! Scope reservations and final tombstones have no automatic expiry. Reconciliation
//! may close a known-complete scope; timeouts alone never manufacture zero liability.

use super::{
    commit::SubmitResult,
    facade::{CoreStore, PendingId},
};
use busbar_contract::{
    abi::sdk::plane::observation::{Observation, ScopeId, State},
    persistence::{
        Address, Candidate, Decision, Durability, ExpectedValue, Mutation, NamespaceId, Predicate,
        PreparedCandidate, Read, ReadResult, CANDIDATE_VERSION,
    },
    Count, Secret,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Arc};

const NS: NamespaceId = NamespaceId(*b"busbar.usage.v1\0");
const MAX_COMPONENTS: usize = 64;
const MAX_SCOPES_PER_PRINCIPAL: u64 = 10_000;
const MAX_REVISIONS_PER_SCOPE: usize = 4096;

/// Immutable authenticated host identity. Never constructed from plugin output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrincipalBinding {
    pub principal: String,
    pub instance: String,
    pub destination: String,
    pub accounting_namespace: String,
}
/// An operator-approved tariff snapshot, pinned at the original accounting time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RatedSubject {
    pub name: String,
    /// Nano currency units per whole declared usage unit. Missing rates refuse settlement.
    pub rates_nanos: BTreeMap<u32, u64>,
}
/// Host-resolved bucket including its original budget window. No plugin can supply it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetBinding {
    pub id: String,
    pub limit_nanos: u128,
    pub reserve_nanos: u128,
}
/// All authority and accounting facts fixed before a paid operation is accepted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Binding {
    pub principal: String,
    /// Group at original admission, retained through later key regrouping.
    pub group: String,
    pub instance: String,
    pub destination: String,
    pub accounting_namespace: String,
    pub serving_subject: String,
    pub rate_time: u64,
    /// Index zero must name the serving subject; other entries only choose tariffs.
    pub subjects: Vec<RatedSubject>,
    pub budgets: Vec<BudgetBinding>,
    /// Set only for a trusted adapter that authenticates the upstream revision order.
    pub ordered_revisions: bool,
    /// Immutable class index/name map from the admitting plane declaration.
    pub classes: BTreeMap<u32, String>,
}
impl Binding {
    fn identity(&self) -> PrincipalBinding {
        PrincipalBinding {
            principal: self.principal.clone(),
            instance: self.instance.clone(),
            destination: self.destination.clone(),
            accounting_namespace: self.accounting_namespace.clone(),
        }
    }
    fn validate(&self) -> Result<(), Error> {
        let names = [
            &self.principal,
            &self.instance,
            &self.destination,
            &self.accounting_namespace,
            &self.serving_subject,
        ];
        if names.iter().any(|v| v.is_empty() || v.len() > 1024)
            || self.subjects.is_empty()
            || self.classes.len() > 64
            || self.subjects.len() > 64
            || self.subjects[0].name != self.serving_subject
            || self.budgets.is_empty()
            || self.budgets.len() > 64
        {
            return Err(Error::Invalid);
        }
        let mut seen = std::collections::BTreeSet::new();
        for b in &self.budgets {
            if b.id.is_empty()
                || b.id.len() > 4096
                || !seen.insert(&b.id)
                || b.reserve_nanos > b.limit_nanos
            {
                return Err(Error::Invalid);
            }
        }
        if self
            .subjects
            .iter()
            .map(|s| &s.name)
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != self.subjects.len()
        {
            return Err(Error::Invalid);
        }
        if self.subjects.iter().any(|s| {
            s.name.is_empty()
                || s.name.len() > 1024
                || s.rates_nanos.len() > 64
                || s.rates_nanos.keys().any(|c| !self.classes.contains_key(c))
        }) {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}
/// Authoritative totals read on admission; failure to read is never interpreted as zero.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetTotal {
    pub spent_nanos: u128,
    pub reserved_nanos: u128,
    /// Raw declared classes only; derived family parents are projected by governance.
    #[serde(default)]
    pub units: BTreeMap<String, BTreeMap<String, Count>>,
}
impl BudgetTotal {
    pub fn liability_nanos(&self) -> Result<u128, Error> {
        self.spent_nanos
            .checked_add(self.reserved_nanos)
            .ok_or(Error::Overflow)
    }
}
/// Dated raw totals distinguish original serving and approved rated subjects.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatedTotal {
    pub counts: BTreeMap<u32, Count>,
    pub spent_nanos: u128,
}
/// Read-time raw metering projection, retaining both original serving and rated subjects.
/// Requests and gateway fees remain exclusively in ordinary request accounting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatedRecord {
    pub principal: String,
    pub group: String,
    pub instance: String,
    pub destination: String,
    pub accounting_namespace: String,
    pub serving_subject: String,
    pub rated_subject: String,
    pub rate_time: u64,
    pub classes: BTreeMap<u32, String>,
    pub rates_nanos: BTreeMap<u32, u64>,
    pub counts: BTreeMap<u32, Count>,
    pub spent_nanos: u128,
}
impl DatedRecord {
    fn empty(binding: &Binding, subject: &RatedSubject) -> Self {
        Self {
            principal: binding.principal.clone(),
            group: binding.group.clone(),
            instance: binding.instance.clone(),
            destination: binding.destination.clone(),
            accounting_namespace: binding.accounting_namespace.clone(),
            serving_subject: binding.serving_subject.clone(),
            rated_subject: subject.name.clone(),
            rate_time: binding.rate_time,
            classes: binding.classes.clone(),
            rates_nanos: subject.rates_nanos.clone(),
            counts: BTreeMap::new(),
            spent_nanos: 0,
        }
    }
}
/// One accepted transition and its signed economic difference, retained indefinitely.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalEntry {
    pub settlement_id: [u8; 16],
    pub scope: ScopeId,
    pub observation: Observation,
    pub accounting_time: u64,
    pub observed_at: u64,
    pub serving_subject: String,
    pub rated_subject: String,
    pub counts_delta: BTreeMap<u32, Count>,
    pub nanos_delta: i128,
    pub quarantined: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScopeRow {
    binding: Binding,
    event_key: Option<Vec<u8>>,
    components: Vec<Vec<u8>>,
    closed: bool,
    reservation_held: bool,
    revisions: usize,
}
/// Persisted reconciliation facts; unknown creates have no event and retain liability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeStatus {
    pub event_key: Option<Vec<u8>>,
    pub components: Vec<Vec<u8>>,
    pub closed: bool,
    pub reservation_held: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WorkRow {
    scope: ScopeId,
    pending: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ComponentRow {
    observation: Observation,
    settlement_id: [u8; 16],
    nanos: u128,
    quarantined: bool,
}
/// Reattached host authority; cannot be forged by constructing a public struct.
#[derive(Debug, Clone)]
pub struct BoundScope {
    id: ScopeId,
    identity: PrincipalBinding,
}
impl BoundScope {
    pub fn id(&self) -> ScopeId {
        self.id
    }
}
pub use busbar_contract::abi::sdk::plane::observation::Receipt;
/// Content-free failures; an unknown outcome retains its original operation.
#[derive(Debug)]
pub enum Error {
    UnsupportedStore,
    Invalid,
    Unauthorized,
    Unattributed,
    Closed,
    Unpriced,
    Budget,
    Overflow,
    Corrupt,
    Contended,
    Pending {
        operation: PendingId,
        scope: ScopeId,
    },
    Store(super::facade::AccessError),
    Backend(busbar_contract::persistence::Failure),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "usage observation: {self:?}")
    }
}
impl std::error::Error for Error {}
impl From<super::facade::AccessError> for Error {
    fn from(e: super::facade::AccessError) -> Self {
        Self::Store(e)
    }
}
impl From<busbar_contract::persistence::Failure> for Error {
    fn from(e: busbar_contract::persistence::Failure) -> Self {
        Self::Backend(e)
    }
}

#[derive(Clone)]
pub struct ObservationStore {
    store: Arc<CoreStore>,
}
impl ObservationStore {
    /// Only admitted atomic durable Store instances can offer this capability.
    pub fn open(store: Arc<CoreStore>) -> Result<Self, Error> {
        if store.info().durability == Durability::Ephemeral {
            return Err(Error::UnsupportedStore);
        }
        Ok(Self { store })
    }
    pub fn supports(store: &CoreStore) -> bool {
        store.info().durability != Durability::Ephemeral
    }
    /// Reserve all relevant budgets before permitting the paid create. Retain a Pending
    /// error's scope for recovery; never issue a second paid create after an uncertain send.
    pub async fn create_scope(&self, binding: Binding) -> Result<ScopeId, Error> {
        binding.validate()?;
        let mut scope = [0; 32];
        getrandom::fill(&mut scope).map_err(|_| Error::Invalid)?;
        if scope == [0; 32] {
            return Err(Error::Invalid);
        }
        for _ in 0..=self.store.limits().conflict_retries {
            let mut addresses = vec![address(b's', &scope)];
            addresses.extend(
                binding
                    .budgets
                    .iter()
                    .map(|b| address(b'b', b.id.as_bytes())),
            );
            addresses.push(address(b'q', binding.principal.as_bytes()));
            let quota_index = addresses.len() - 1;
            addresses.push(address(b'a', &[]));
            let values = self.read(&addresses).await?;
            let quota: u64 = decode_default(&values[quota_index])?;
            if values
                .last()
                .and_then(Option::as_ref)
                .is_some_and(|v| v.expose(&crate::seal::lend()).as_slice() != b"1")
            {
                return Err(Error::Corrupt);
            }
            if quota >= MAX_SCOPES_PER_PRINCIPAL {
                return Err(Error::Budget);
            }
            if values[0].is_some() {
                return Err(Error::Corrupt);
            }
            let mut changes = vec![(
                addresses[0].clone(),
                encode(&ScopeRow {
                    binding: binding.clone(),
                    event_key: None,
                    components: vec![],
                    closed: false,
                    reservation_held: true,
                    revisions: 0,
                })?,
            )];
            for (i, b) in binding.budgets.iter().enumerate() {
                let mut total: BudgetTotal = decode_default(&values[i + 1])?;
                total.reserved_nanos = total
                    .reserved_nanos
                    .checked_add(b.reserve_nanos)
                    .ok_or(Error::Overflow)?;
                if total.liability_nanos()? > b.limit_nanos {
                    return Err(Error::Budget);
                }
                changes.push((addresses[i + 1].clone(), encode(&total)?));
            }
            changes.push((
                work_address(&binding, scope),
                encode(&WorkRow {
                    scope,
                    pending: true,
                })?,
            ));
            changes.push((addresses[quota_index].clone(), encode(&(quota + 1))?));
            changes.push((address(b'a', &[]), Secret::new(b"1".to_vec())));
            if self.commit(scope, addresses, values, changes, None).await? {
                return Ok(scope);
            }
        }
        Err(Error::Contended)
    }
    /// The authenticated host supplies all four original ownership coordinates.
    /// An unknown external identifier cannot create or import a charging scope.
    pub async fn bind_scope(
        &self,
        id: ScopeId,
        identity: PrincipalBinding,
    ) -> Result<BoundScope, Error> {
        let row = self.scope(id).await?;
        if row.binding.identity() != identity {
            return Err(Error::Unauthorized);
        }
        Ok(BoundScope { id, identity })
    }
    pub async fn binding(&self, scope: &BoundScope) -> Result<Binding, Error> {
        Ok(self.authorized(scope).await?.binding)
    }
    async fn scope(&self, id: ScopeId) -> Result<ScopeRow, Error> {
        let values = self.read(&[address(b's', &id)]).await?;
        values[0]
            .as_ref()
            .map(decode)
            .transpose()?
            .ok_or(Error::Unattributed)
    }
    async fn authorized(&self, scope: &BoundScope) -> Result<ScopeRow, Error> {
        let row = self.scope(scope.id).await?;
        if row.binding.identity() != scope.identity {
            return Err(Error::Unauthorized);
        }
        Ok(row)
    }
    /// Sticky global activation proof, read fresh on every admission. Its first
    /// publication is atomic with scope reservation; never cache an absent marker.
    pub async fn has_accounting(&self) -> Result<bool, Error> {
        match &self.read(&[address(b'a', &[])]).await?[0] {
            None => Ok(false),
            Some(v) if v.expose(&crate::seal::lend()).as_slice() == b"1" => Ok(true),
            Some(_) => Err(Error::Corrupt),
        }
    }
    /// Read coherent authoritative totals; no unhydrated process cache participates.
    pub async fn budget(&self, id: &str) -> Result<BudgetTotal, Error> {
        decode_default(&self.read(&[address(b'b', id.as_bytes())]).await?[0])
    }
    /// Read original-rate-time raw metering totals for one approved subject.
    pub async fn dated_total(&self, scope: &BoundScope, subject: u32) -> Result<DatedTotal, Error> {
        let row = self.authorized(scope).await?;
        let rated = row
            .binding
            .subjects
            .get(subject as usize)
            .ok_or(Error::Unauthorized)?;
        let value = self
            .read(&[dated_address(&row.binding, &rated.name)?])
            .await?;
        let record: Option<DatedRecord> = value[0].as_ref().map(decode).transpose()?;
        Ok(record.map_or_else(DatedTotal::default, |r| DatedTotal {
            counts: r.counts,
            spent_nanos: r.spent_nanos,
        }))
    }
    /// Atomically settle totals and raw dated aggregates. Accepted charges are never
    /// discarded because a run failed, was cancelled, or exceeded its estimate.
    pub async fn submit(
        &self,
        scope: &BoundScope,
        observation: &Observation,
        observed_at: u64,
    ) -> Result<Receipt, Error> {
        observation.validate().map_err(|_| Error::Invalid)?;
        if observation.scope != scope.id {
            return Err(Error::Unauthorized);
        }
        for _ in 0..=self.store.limits().conflict_retries {
            let initial = self.authorized(scope).await?;
            let binding = &initial.binding;
            let subject = binding
                .subjects
                .get(observation.rated_subject as usize)
                .ok_or(Error::Unauthorized)?;
            let nanos = price(subject, &observation.counts)?;
            let component = component_address(scope.id, &observation.component_key)?;
            let owner = event_address(binding, &observation.event_key)?;
            let dated = dated_address(binding, &subject.name)?;
            let mut addresses = vec![
                address(b's', &scope.id),
                component.clone(),
                owner.clone(),
                dated.clone(),
            ];
            addresses.extend(
                binding
                    .budgets
                    .iter()
                    .map(|b| address(b'b', b.id.as_bytes())),
            );
            let intent_address = address(
                b'r',
                &Sha256::digest(observation.encode().map_err(|_| Error::Invalid)?),
            );
            addresses.push(intent_address.clone());
            let values = self.read(&addresses).await?;
            if let Some(value) = values.last().and_then(Option::as_ref) {
                let mut receipt: Receipt = decode(value)?;
                receipt.duplicate = true;
                return Ok(receipt);
            }
            let mut row: ScopeRow = decode(values[0].as_ref().ok_or(Error::Unattributed)?)?;
            if row.binding != *binding {
                return Err(Error::Corrupt);
            }
            if let Some(existing) = &row.event_key {
                if existing != &observation.event_key {
                    return Err(Error::Unauthorized);
                }
            }
            if let Some(held) = values[2].as_ref() {
                if held.expose(&crate::seal::lend()).as_slice() != scope.id {
                    return Err(Error::Unauthorized);
                }
            }
            let previous: Option<ComponentRow> = values[1].as_ref().map(decode).transpose()?;
            if row.closed && previous.is_none() {
                return Err(Error::Closed);
            }
            if previous
                .as_ref()
                .is_some_and(|p| p.observation.rated_subject != observation.rated_subject)
            {
                return Err(Error::Unauthorized);
            }
            if let Some(p) = &previous {
                if p.observation.state == State::Final && observation.state == State::Provisional {
                    return Ok(Receipt {
                        settlement_id: p.settlement_id,
                        duplicate: true,
                        quarantined: p.quarantined,
                    });
                }
                if p.observation.state == State::Final
                    && observation.state == State::Final
                    && p.observation.counts == observation.counts
                {
                    let advances = binding.ordered_revisions
                        && matches!((&p.observation.revision,&observation.revision),(Some(old),Some(new)) if new.order>old.order && new.identity!=old.identity);
                    if !advances {
                        return Ok(Receipt {
                            settlement_id: p.settlement_id,
                            duplicate: true,
                            quarantined: p.quarantined,
                        });
                    }
                }
                if p.observation == *observation {
                    return Ok(Receipt {
                        settlement_id: p.settlement_id,
                        duplicate: true,
                        quarantined: p.quarantined,
                    });
                }
            }
            let quarantine = previous.as_ref().is_some_and(|p| {
                if p.observation.state != State::Final {
                    return false;
                }
                if observation.state != State::Final || !binding.ordered_revisions {
                    return true;
                }
                match (&p.observation.revision, &observation.revision) {
                    (Some(old), Some(new)) => {
                        new.order <= old.order || new.identity == old.identity
                    }
                    _ => true,
                }
            });
            if previous.is_none() {
                if row.components.len() >= MAX_COMPONENTS {
                    return Err(Error::Budget);
                }
                row.components.push(observation.component_key.clone());
            }
            if row.revisions >= MAX_REVISIONS_PER_SCOPE {
                return Err(Error::Budget);
            }
            row.revisions += 1;
            let restore_reservation = quarantine && !row.reservation_held;
            if restore_reservation {
                row.reservation_held = true;
            }
            row.event_key = Some(observation.event_key.clone());
            let old_counts = previous
                .as_ref()
                .filter(|p| p.observation.state == State::Final)
                .map(|p| &p.observation.counts);
            let empty = BTreeMap::new();
            let next_counts = if observation.state == State::Final && !quarantine {
                &observation.counts
            } else {
                old_counts.unwrap_or(&empty)
            };
            let difference = count_difference(old_counts.unwrap_or(&empty), next_counts)?;
            let old_nanos = previous
                .as_ref()
                .filter(|p| p.observation.state == State::Final)
                .map_or(0, |p| p.nanos);
            let next_nanos = if observation.state == State::Final && !quarantine {
                nanos
            } else {
                old_nanos
            };
            let delta = i128::try_from(next_nanos)
                .map_err(|_| Error::Overflow)?
                .checked_sub(i128::try_from(old_nanos).map_err(|_| Error::Overflow)?)
                .ok_or(Error::Overflow)?;
            let id = self.store.next_id()?;
            let journal = JournalEntry {
                settlement_id: id.operation,
                scope: scope.id,
                observation: observation.clone(),
                accounting_time: binding.rate_time,
                observed_at,
                serving_subject: binding.serving_subject.clone(),
                rated_subject: subject.name.clone(),
                counts_delta: difference.clone(),
                nanos_delta: delta,
                quarantined: quarantine,
            };
            let mut changes = vec![
                (addresses[0].clone(), encode(&row)?),
                (owner, Secret::new(scope.id.to_vec())),
                (journal_address(scope.id, id.operation), encode(&journal)?),
            ];
            if restore_reservation {
                changes.push((
                    work_address(binding, scope.id),
                    encode(&WorkRow {
                        scope: scope.id,
                        pending: true,
                    })?,
                ));
            }
            if !quarantine {
                changes.push((
                    component,
                    encode(&ComponentRow {
                        observation: observation.clone(),
                        settlement_id: id.operation,
                        nanos: next_nanos,
                        quarantined: false,
                    })?,
                ));
            }
            if quarantine {
                let mut retained = previous.ok_or(Error::Corrupt)?;
                retained.quarantined = true;
                changes.push((
                    component_address(scope.id, &observation.component_key)?,
                    encode(&retained)?,
                ));
            }
            let mut total: DatedRecord = values[3]
                .as_ref()
                .map(decode)
                .transpose()?
                .unwrap_or_else(|| DatedRecord::empty(binding, subject));
            for (class, amount) in &difference {
                let next = total
                    .counts
                    .get(class)
                    .copied()
                    .unwrap_or_default()
                    .micros()
                    .checked_add(amount.micros())
                    .ok_or(Error::Overflow)?;
                if next < 0 {
                    return Err(Error::Corrupt);
                }
                total.counts.insert(*class, Count::from_micros(next));
            }
            total.spent_nanos = apply_delta(total.spent_nanos, delta)?;
            changes.push((dated, encode(&total)?));
            for (i, _) in binding.budgets.iter().enumerate() {
                let mut total: BudgetTotal = decode_default(&values[i + 4])?;
                if restore_reservation {
                    total.reserved_nanos = total
                        .reserved_nanos
                        .checked_add(binding.budgets[i].reserve_nanos)
                        .ok_or(Error::Overflow)?;
                }
                total.spent_nanos = apply_delta(total.spent_nanos, delta)?;
                for (class, amount) in &difference {
                    let name = binding.classes.get(class).ok_or(Error::Corrupt)?;
                    let units = total.units.entry(subject.name.clone()).or_default();
                    let previous = units.get(name).copied().unwrap_or_default();
                    let next = previous
                        .micros()
                        .checked_add(amount.micros())
                        .ok_or(Error::Overflow)?;
                    if next < 0 {
                        return Err(Error::Corrupt);
                    }
                    units.insert(name.clone(), Count::from_micros(next));
                }
                changes.push((addresses[i + 4].clone(), encode(&total)?));
            }
            changes.push((
                intent_address,
                encode(&Receipt {
                    settlement_id: id.operation,
                    duplicate: false,
                    quarantined: quarantine,
                })?,
            ));
            if self
                .commit(scope.id, addresses, values, changes, Some(id))
                .await?
            {
                return Ok(Receipt {
                    settlement_id: id.operation,
                    duplicate: false,
                    quarantined: quarantine,
                });
            }
        }
        Err(Error::Contended)
    }
    /// Explicit reconciliation of a known-complete run. Empty/uncertain attempts and
    /// provisional components keep their reservation; deadlines do not release them.
    pub async fn close_scope(&self, scope: &BoundScope) -> Result<(), Error> {
        for _ in 0..=self.store.limits().conflict_retries {
            let initial = self.authorized(scope).await?;
            if !initial.reservation_held {
                return Ok(());
            }
            if initial.components.is_empty() {
                return Err(Error::Invalid);
            }
            let mut addresses = vec![address(b's', &scope.id)];
            for c in &initial.components {
                addresses.push(component_address(scope.id, c)?);
            }
            addresses.extend(
                initial
                    .binding
                    .budgets
                    .iter()
                    .map(|b| address(b'b', b.id.as_bytes())),
            );
            let values = self.read(&addresses).await?;
            let mut row: ScopeRow = decode(values[0].as_ref().ok_or(Error::Unattributed)?)?;
            if row.components != initial.components || !row.reservation_held {
                continue;
            }
            for value in values.iter().skip(1).take(row.components.len()) {
                let component: ComponentRow = decode(value.as_ref().ok_or(Error::Corrupt)?)?;
                if component.observation.state != State::Final || component.quarantined {
                    return Err(Error::Invalid);
                }
            }
            row.closed = true;
            row.reservation_held = false;
            let mut changes = vec![(addresses[0].clone(), encode(&row)?)];
            changes.push((
                work_address(&row.binding, scope.id),
                encode(&WorkRow {
                    scope: scope.id,
                    pending: false,
                })?,
            ));
            let start = 1 + row.components.len();
            for (i, b) in row.binding.budgets.iter().enumerate() {
                let mut total: BudgetTotal = decode_default(&values[start + i])?;
                total.reserved_nanos = total
                    .reserved_nanos
                    .checked_sub(b.reserve_nanos)
                    .ok_or(Error::Corrupt)?;
                changes.push((addresses[start + i].clone(), encode(&total)?));
            }
            if self
                .commit(scope.id, addresses, values, changes, None)
                .await?
            {
                return Ok(());
            }
        }
        Err(Error::Contended)
    }
    /// Read-time export from authoritative metering, never an additive ordinary-ledger
    /// replay. The caller supplies its existing authenticated report filters. Scan
    /// generation changes or an unreadable accounting shard fail the entire read.
    pub async fn dated_records(&self) -> Result<Vec<DatedRecord>, Error> {
        let rows = self.store.scan(NS, vec![b'd'], None).await?;
        rows.rows.iter().map(|(_, value)| decode(value)).collect()
    }
    /// A daily report seeks only that original UTC-day index, rather than scanning
    /// lifetime history. The argument is an existing `governance::metering_bucket`.
    pub async fn dated_records_for_day(&self, bucket: u64) -> Result<Vec<DatedRecord>, Error> {
        if crate::governance::metering_bucket(bucket) != bucket {
            return Err(Error::Invalid);
        }
        let mut prefix = vec![b'd'];
        prefix.extend_from_slice(&bucket.to_be_bytes());
        let rows = self.store.scan(NS, prefix, None).await?;
        rows.rows.iter().map(|(_, value)| decode(value)).collect()
    }
    /// Recover durable unresolved work for an authenticated principal. The scope quota
    /// bounds this index; every returned scope is reauthorized before use.
    pub async fn pending_scopes(&self, identity: &PrincipalBinding) -> Result<Vec<ScopeId>, Error> {
        let mut prefix = vec![b'w'];
        prefix.extend_from_slice(&Sha256::digest(identity.principal.as_bytes()));
        let rows = self.store.scan(NS, prefix, None).await?;
        let mut result = Vec::new();
        for (_, value) in rows.rows {
            let work: WorkRow = decode(&value)?;
            if work.pending {
                let row = self.scope(work.scope).await?;
                if row.binding.identity() == *identity && row.reservation_held {
                    result.push(work.scope);
                }
            }
        }
        Ok(result)
    }
    pub async fn status(&self, scope: &BoundScope) -> Result<ScopeStatus, Error> {
        let row = self.authorized(scope).await?;
        Ok(ScopeStatus {
            event_key: row.event_key,
            components: row.components,
            closed: row.closed,
            reservation_held: row.reservation_held,
        })
    }
    /// Exact operation replay after a lost response; authoritative rows already include
    /// the charge if it committed. No aggregate delta is emitted a second time.
    pub async fn retry(&self, operation: PendingId, scope: ScopeId) -> Result<bool, Error> {
        self.verdict(scope, self.store.retry(operation).await?)
    }
    /// Bounded-per-crossing recovery/export of retained journal and tombstones. A stale
    /// generation is an error; callers retry, never publish a partial reconstruction.
    pub async fn journal(&self, scope: &BoundScope) -> Result<Vec<JournalEntry>, Error> {
        self.authorized(scope).await?;
        let mut prefix = vec![b'j'];
        prefix.extend_from_slice(&scope.id);
        let rows = self.store.scan(NS, prefix, None).await?;
        rows.rows.iter().map(|(_, v)| decode(v)).collect()
    }
    async fn read(&self, addresses: &[Address]) -> Result<Vec<Option<Secret<Vec<u8>>>>, Error> {
        let ReadResult::Values {
            observed_at,
            values,
        } = self
            .store
            .backend()
            .read(Arc::new(Read {
                dataset: self.store.info().dataset,
                addresses: addresses.to_vec(),
                time: None,
            }))
            .await?
        else {
            return Err(Error::Corrupt);
        };
        if values.len() != addresses.len()
            || observed_at.authority != self.store.info().clock_authority
        {
            return Err(Error::Corrupt);
        }
        Ok(values)
    }
    async fn commit(
        &self,
        scope: ScopeId,
        addresses: Vec<Address>,
        values: Vec<Option<Secret<Vec<u8>>>>,
        changes: Vec<(Address, Secret<Vec<u8>>)>,
        id: Option<busbar_contract::persistence::AttemptId>,
    ) -> Result<bool, Error> {
        let id = match id {
            Some(id) => id,
            None => self.store.next_id()?,
        };
        let candidate = PreparedCandidate::new(Candidate {
            id,
            codec: CANDIDATE_VERSION,
            predicates: addresses
                .into_iter()
                .zip(values)
                .map(|(address, value)| Predicate {
                    address,
                    expected: value.map_or(ExpectedValue::Absent, ExpectedValue::Exact),
                })
                .collect(),
            mutations: changes
                .into_iter()
                .map(|(address, value)| Mutation::Put { address, value })
                .collect(),
            time: None,
            result: Secret::new(scope.to_vec()),
        })
        .map_err(|_| Error::Invalid)?;
        self.verdict(scope, self.store.submit(candidate).await?)
    }
    fn verdict(
        &self,
        scope: ScopeId,
        submission: super::facade::Submission,
    ) -> Result<bool, Error> {
        match submission.result {
            SubmitResult::Decided(decision) => match decision.as_ref() {
                Decision::Applied(_) => Ok(true),
                Decision::ConditionConflict => Ok(false),
                Decision::ExpiredUnknown => Err(Error::Pending {
                    operation: submission.id,
                    scope,
                }),
                _ => Err(Error::Corrupt),
            },
            SubmitResult::NoEffect(e) => Err(Error::Backend(e)),
            _ => Err(Error::Pending {
                operation: submission.id,
                scope,
            }),
        }
    }
}
fn address(kind: u8, key: &[u8]) -> Address {
    let mut bytes = vec![kind];
    bytes.extend_from_slice(key);
    Address {
        namespace: NS.0,
        key: bytes,
    }
}
fn framed(parts: &[&[u8]]) -> Vec<u8> {
    let mut b = vec![];
    for part in parts {
        b.extend_from_slice(&(part.len() as u64).to_be_bytes());
        b.extend_from_slice(part);
    }
    b
}
fn component_address(scope: ScopeId, component: &[u8]) -> Result<Address, Error> {
    Ok(address(b'c', &framed(&[&scope, component])))
}
fn event_address(binding: &Binding, event: &[u8]) -> Result<Address, Error> {
    let key = framed(&[
        binding.instance.as_bytes(),
        binding.destination.as_bytes(),
        binding.accounting_namespace.as_bytes(),
        event,
    ]);
    Ok(address(b'e', &Sha256::digest(key)))
}
fn dated_address(binding: &Binding, rated: &str) -> Result<Address, Error> {
    let subject = binding
        .subjects
        .iter()
        .find(|s| s.name == rated)
        .ok_or(Error::Unauthorized)?;
    let tariff = serde_json::to_vec(&(&binding.group, &binding.classes, &subject.rates_nanos))
        .map_err(|_| Error::Invalid)?;
    let digest = Sha256::digest(framed(&[
        binding.principal.as_bytes(),
        binding.instance.as_bytes(),
        binding.destination.as_bytes(),
        binding.accounting_namespace.as_bytes(),
        binding.serving_subject.as_bytes(),
        rated.as_bytes(),
        &binding.rate_time.to_be_bytes(),
        &tariff,
    ]));
    let mut key = crate::governance::metering_bucket(binding.rate_time)
        .to_be_bytes()
        .to_vec();
    key.extend_from_slice(&digest);
    Ok(address(b'd', &key))
}
fn work_address(binding: &Binding, scope: ScopeId) -> Address {
    let mut key = Sha256::digest(binding.principal.as_bytes()).to_vec();
    key.extend_from_slice(&scope);
    address(b'w', &key)
}
fn journal_address(scope: ScopeId, id: [u8; 16]) -> Address {
    let mut key = scope.to_vec();
    key.extend_from_slice(&id);
    address(b'j', &key)
}
fn encode<T: Serialize>(v: &T) -> Result<Secret<Vec<u8>>, Error> {
    serde_json::to_vec(v)
        .map(Secret::new)
        .map_err(|_| Error::Invalid)
}
fn decode<T: serde::de::DeserializeOwned>(v: &Secret<Vec<u8>>) -> Result<T, Error> {
    serde_json::from_slice(v.expose(&crate::seal::lend())).map_err(|_| Error::Corrupt)
}
fn decode_default<T: serde::de::DeserializeOwned + Default>(
    v: &Option<Secret<Vec<u8>>>,
) -> Result<T, Error> {
    v.as_ref()
        .map(decode)
        .transpose()
        .map(Option::unwrap_or_default)
}
fn count_difference(
    old: &BTreeMap<u32, Count>,
    next: &BTreeMap<u32, Count>,
) -> Result<BTreeMap<u32, Count>, Error> {
    let mut result = BTreeMap::new();
    for class in old.keys().chain(next.keys()) {
        let delta = next
            .get(class)
            .copied()
            .unwrap_or_default()
            .micros()
            .checked_sub(old.get(class).copied().unwrap_or_default().micros())
            .ok_or(Error::Overflow)?;
        result.insert(*class, Count::from_micros(delta));
    }
    Ok(result)
}
fn apply_delta(total: u128, delta: i128) -> Result<u128, Error> {
    if delta >= 0 {
        total.checked_add(delta as u128).ok_or(Error::Overflow)
    } else {
        total
            .checked_sub(delta.unsigned_abs())
            .ok_or(Error::Corrupt)
    }
}
fn price(subject: &RatedSubject, counts: &BTreeMap<u32, Count>) -> Result<u128, Error> {
    let mut sum = 0u128;
    for (class, count) in counts {
        let rate = subject.rates_nanos.get(class).ok_or(Error::Unpriced)?;
        let micro = u128::try_from(count.micros()).map_err(|_| Error::Invalid)?;
        let product = micro
            .checked_mul(u128::from(*rate))
            .ok_or(Error::Overflow)?;
        sum = sum.checked_add(product).ok_or(Error::Overflow)?;
    }
    // Same canonical projection as ordinary accounting: sum exact class products,
    // then truncate once to nano currency units, never round each class separately.
    let sum = sum / 1_000_000;
    i128::try_from(sum).map_err(|_| Error::Overflow)?;
    Ok(sum)
}

#[cfg(test)]
#[path = "observations_tests.rs"]
mod tests;
