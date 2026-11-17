// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One checked native allocation, retained walk and monetary admission.
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

use busbar_contract::records::VirtualKey;
use busbar_contract::UnitKey;

use super::money::UnitMoney;
use super::port_egress::SeatPool;
use super::provider_catalog::{CatalogPlan, RouteKind};
use crate::cost::CostModel;
use crate::governance::{AdmitGrant, GovState, PLANE_LANE_SEP};
use crate::host_services::InvocationContext;

#[path = "request_registration.rs"]
mod registration;
use registration::SelectedCommand;
#[path = "request_current.rs"]
mod current;

const REGISTERED: u8 = 0;
const RESOLVING: u8 = 1;
const READY: u8 = 2;
const COMMITTING: u8 = 3;
const ADMITTED: u8 = 4;
const ENDED: u8 = 5;

/// Shared only by the actual registered record and its checked invocation clones.
pub(crate) struct AdmissionPhase(AtomicU8);
impl AdmissionPhase {
    pub(crate) fn pending() -> Self {
        Self(AtomicU8::new(REGISTERED))
    }
    pub(crate) fn admitted() -> Self {
        Self(AtomicU8::new(ADMITTED))
    }
    pub(crate) fn effects_allowed(&self) -> bool {
        self.0.load(Ordering::Acquire) == ADMITTED
    }
    pub(crate) fn end(&self) {
        self.0.store(ENDED, Ordering::Release);
    }
    fn change(&self, from: u8, to: u8) -> Result<(), AdmissionError> {
        self.0
            .compare_exchange(from, to, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| AdmissionError::Phase)
    }
    fn at(&self, phase: u8) -> bool {
        self.0.load(Ordering::Acquire) == phase
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionError {
    Phase,
    Stale,
    Principal,
    Route,
    Scope,
    Money,
}

/// Operator domain is distinct from the internal walk key and the pricing lane.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequestDomain {
    NamedPool(String),
    DirectModel(String),
    Registration(String),
    Local,
}

/// Immutable route metadata from root's selected generation. It grants no unit authority.
pub struct RequestRoutes {
    identity: Arc<()>,
    instance: String,
    scope_kind: Option<Arc<str>>,
    catalog: Option<Arc<CatalogPlan>>,
    registration: Option<Arc<SeatPool>>,
    registrations: Option<Arc<crate::upstreams::ConfiguredUpstreams>>,
}
impl RequestRoutes {
    pub fn new(
        instance: &str,
        scope_kind: Option<Arc<str>>,
        catalog: Option<Arc<CatalogPlan>>,
        registration: Option<Arc<SeatPool>>,
    ) -> Result<Self, AdmissionError> {
        if instance.is_empty()
            || instance.chars().any(char::is_control)
            || catalog.as_ref().is_some_and(|p| p.instance != instance)
            || registration
                .as_ref()
                .is_some_and(|r| r.pool != instance || !r.pools.contains_key(&r.pool))
        {
            return Err(AdmissionError::Route);
        }
        if let (Some(catalog), Some(registration)) = (&catalog, &registration) {
            if catalog.select(&registration.pool).is_some() {
                return Err(AdmissionError::Route);
            }
        }
        Ok(Self {
            identity: Arc::new(()),
            instance: instance.into(),
            scope_kind,
            catalog,
            registration,
            registrations: None,
        })
    }

    // These resolved producers describe ordinary pool/direct scope. A descriptor requiring
    // member-granted semantics needs its typed producer before root can assemble this path.
    fn member_grants(&self, key: &VirtualKey) -> BTreeMap<String, Vec<String>> {
        let allowed = |name: &str| {
            self.scope_kind
                .as_ref()
                .is_none_or(|kind| key.scope_allowed(kind, name))
        };
        let mut grants = BTreeMap::new();
        if let Some(catalog) = &self.catalog {
            for (walk, pool) in catalog.pools() {
                let name = match &pool.kind {
                    RouteKind::NamedPool(name) | RouteKind::DirectModel(name) => name,
                };
                if !allowed(name) {
                    continue;
                }
                let members: Vec<_> = pool
                    .config
                    .members
                    .iter()
                    .map(|member| format!("{}{PLANE_LANE_SEP}{}", self.instance, member.name()))
                    .collect();
                if !members.is_empty() {
                    grants.insert(walk.clone(), members);
                }
            }
        }
        if let Some(registration) = &self.registration {
            if allowed(&registration.pool) {
                let members: Vec<_> = registration
                    .members
                    .iter()
                    .map(|member| format!("{}{PLANE_LANE_SEP}{}", self.instance, member.upstream))
                    .collect();
                if !members.is_empty() {
                    grants.insert(registration.pool.clone(), members);
                }
            }
        }
        grants
    }
    fn resolve(&self, selector: Option<&str>) -> Result<(RequestDomain, String), AdmissionError> {
        if let Some(name) = selector {
            if let Some(catalog) = &self.catalog {
                if let Some(walk) = catalog.select(name) {
                    let pool = catalog.pools().get(walk).ok_or(AdmissionError::Route)?;
                    let domain = match &pool.kind {
                        RouteKind::NamedPool(p) => RequestDomain::NamedPool(p.clone()),
                        RouteKind::DirectModel(m) => RequestDomain::DirectModel(m.clone()),
                    };
                    return Ok((domain, walk.into()));
                }
            }
            if let Some(registration) = &self.registration {
                if name == registration.pool {
                    return Ok((
                        RequestDomain::Registration(name.into()),
                        registration.pool.clone(),
                    ));
                }
            }
            return Err(AdmissionError::Route);
        }
        // An absent selector can choose the explicitly configured registration default only.
        let registration = self.registration.as_ref().ok_or(AdmissionError::Route)?;
        Ok((
            RequestDomain::Registration(registration.pool.clone()),
            registration.pool.clone(),
        ))
    }
}

/// The runtime retains this with the actual FarEnd/Pass pair. It is never made from a UnitKey.
#[derive(Clone)]
pub struct RequestWalk {
    context: InvocationContext,
    identity: Arc<()>,
}
impl RequestWalk {
    pub(in crate::plane_driver) fn new(
        context: &InvocationContext,
    ) -> Result<Self, AdmissionError> {
        if !context.is_live() {
            return Err(AdmissionError::Stale);
        }
        Ok(Self {
            context: context.clone(),
            identity: Arc::new(()),
        })
    }
    pub fn accepts(&self, context: &InvocationContext) -> bool {
        self.context.same_unit(context) && self.context.is_live()
    }
}

/// Linear ownership of the one registered pre-money invocation.
pub struct RequestAllocation {
    context: InvocationContext,
    key: Arc<VirtualKey>,
    cost: Arc<CostModel>,
    arrived: u64,
    armed: bool,
}
impl RequestAllocation {
    pub fn new(
        context: InvocationContext,
        cost: Arc<CostModel>,
        arrived: u64,
    ) -> Result<Self, AdmissionError> {
        if !context.is_live() {
            return Err(AdmissionError::Stale);
        }
        let key = context
            .principal()
            .cloned()
            .ok_or(AdmissionError::Principal)?;
        context.admission_phase().change(REGISTERED, RESOLVING)?;
        Ok(Self {
            context,
            key,
            cost,
            arrived,
            armed: true,
        })
    }
    pub fn context(&self) -> &InvocationContext {
        &self.context
    }
    pub fn forward(
        self,
        routes: &RequestRoutes,
        walk: &RequestWalk,
        selector: Option<&str>,
    ) -> Result<RequestPoolReceipt, AdmissionError> {
        if !walk.accepts(&self.context) {
            return Err(AdmissionError::Stale);
        }
        let (domain, key) = routes.resolve(selector)?;
        self.resolve(routes, domain, Some((walk.clone(), key)))
    }
    pub fn local(self, routes: &RequestRoutes) -> Result<RequestPoolReceipt, AdmissionError> {
        self.resolve(routes, RequestDomain::Local, None)
    }
    fn resolve(
        mut self,
        routes: &RequestRoutes,
        domain: RequestDomain,
        walk: Option<(RequestWalk, String)>,
    ) -> Result<RequestPoolReceipt, AdmissionError> {
        if !self.context.is_live() || self.context.instance() != routes.instance {
            return Err(AdmissionError::Stale);
        }
        let name = match &domain {
            RequestDomain::NamedPool(n)
            | RequestDomain::DirectModel(n)
            | RequestDomain::Registration(n) => n.as_str(),
            RequestDomain::Local => "",
        };
        let grants = if let Some((_, walk_key)) = &walk {
            let grants = routes.member_grants(&self.key);
            if !grants.contains_key(walk_key) {
                return Err(AdmissionError::Scope);
            }
            grants
        } else {
            BTreeMap::new()
        };
        let pool = format!("{}{PLANE_LANE_SEP}{name}", routes.instance);
        self.context.admission_phase().change(RESOLVING, READY)?;
        self.armed = false;
        Ok(RequestPoolReceipt {
            context: self.context.clone(),
            key: self.key.clone(),
            routes: routes.identity.clone(),
            grants: Arc::new(grants),
            cost: self.cost.clone(),
            arrived: self.arrived,
            pool,
            domain,
            walk,
            command: None,
            armed: true,
        })
    }
}
impl Drop for RequestAllocation {
    fn drop(&mut self) {
        if self.armed {
            self.context.admission_phase().end();
        }
    }
}

/// Route resolution on the live allocation, consumed before acquiring any monetary grant.
pub struct RequestPoolReceipt {
    context: InvocationContext,
    key: Arc<VirtualKey>,
    routes: Arc<()>,
    grants: Arc<BTreeMap<String, Vec<String>>>,
    cost: Arc<CostModel>,
    arrived: u64,
    pool: String,
    domain: RequestDomain,
    walk: Option<(RequestWalk, String)>,
    command: Option<SelectedCommand>,
    armed: bool,
}
impl RequestPoolReceipt {
    pub fn pool(&self) -> &str {
        &self.pool
    }
    pub fn domain(&self) -> &RequestDomain {
        &self.domain
    }
    pub fn member_grants(&self) -> &BTreeMap<String, Vec<String>> {
        &self.grants
    }
    pub fn walk_key(&self) -> Option<&str> {
        self.walk.as_ref().map(|(_, key)| key.as_str())
    }
    pub fn begin(mut self) -> Result<CommittingRequest, AdmissionError> {
        if !self.context.is_live() {
            return Err(AdmissionError::Stale);
        }
        self.context.admission_phase().change(READY, COMMITTING)?;
        self.armed = false;
        Ok(CommittingRequest {
            route: self,
            armed: true,
        })
    }
}
impl Drop for RequestPoolReceipt {
    fn drop(&mut self) {
        if self.armed {
            self.context.admission_phase().end();
        }
    }
}

/// The sole winner may acquire and install a grant. Drop keeps host effects closed.
pub struct CommittingRequest {
    route: RequestPoolReceipt,
    armed: bool,
}
impl CommittingRequest {
    pub fn context(&self) -> &InvocationContext {
        &self.route.context
    }
    pub fn key(&self) -> &Arc<VirtualKey> {
        &self.route.key
    }
    pub fn cost(&self) -> &Arc<CostModel> {
        &self.route.cost
    }
    pub fn pool(&self) -> &str {
        &self.route.pool
    }
    pub fn arrived(&self) -> u64 {
        self.route.arrived
    }
    pub fn unit(&self) -> UnitKey {
        UnitKey::new(self.route.context.unit())
    }
    pub fn is_live(&self) -> bool {
        self.context().is_live() && self.context().admission_phase().at(COMMITTING)
    }
    pub(in crate::plane_driver) fn accepts_governance(&self, governance: &GovState) -> bool {
        self.context().signed_authority().is_none_or(|proof| {
            proof.belongs_to(governance) && Arc::ptr_eq(proof.original_key(), self.key())
        })
    }
    pub(in crate::plane_driver) fn admitted(
        self,
        money: Arc<UnitMoney>,
        grant: Arc<AdmitGrant>,
        governance: Arc<GovState>,
        book: Arc<()>,
        open: Arc<()>,
    ) -> Result<AdmittedRequest, AdmissionError> {
        if !self.is_live() {
            return Err(AdmissionError::Stale);
        }
        if !Arc::ptr_eq(&money.key, self.key())
            || !Arc::ptr_eq(&money.cost, self.cost())
            || money.pool != self.pool()
            || money.arrived != self.arrived()
            || money.charge != *grant.charge()
            || money.charge.chain().is_none()
        {
            return Err(AdmissionError::Money);
        }
        self.finish(money, grant, governance, book, open)
    }

    /// The money owner calls this only while its existing live-parent/child transaction is held.
    /// The child's routing domain cannot replace the parent's monetary scope or create a grant.
    pub(in crate::plane_driver) fn admitted_child(
        self,
        parent: &super::money::ParentMoney,
        money: Arc<UnitMoney>,
        grant: Arc<AdmitGrant>,
        governance: Arc<GovState>,
        book: Arc<()>,
        open: Arc<()>,
    ) -> Result<AdmittedRequest, AdmissionError> {
        if !self.is_live() {
            return Err(AdmissionError::Stale);
        }
        if money.key.as_ref() != self.key().as_ref()
            || !Arc::ptr_eq(&money.cost, self.cost())
            || !parent.matches_child_money(&money, &grant)
        {
            return Err(AdmissionError::Money);
        }
        self.finish(money, grant, governance, book, open)
    }

    fn finish(
        mut self,
        money: Arc<UnitMoney>,
        grant: Arc<AdmitGrant>,
        governance: Arc<GovState>,
        book: Arc<()>,
        open: Arc<()>,
    ) -> Result<AdmittedRequest, AdmissionError> {
        if !self.accepts_governance(&governance) {
            return Err(AdmissionError::Principal);
        }
        self.context()
            .admission_phase()
            .change(COMMITTING, ADMITTED)?;
        self.armed = false;
        Ok(AdmittedRequest {
            context: self.context().clone(),
            routes: self.route.routes.clone(),
            grants: self.route.grants.clone(),
            domain: self.route.domain.clone(),
            walk: self.route.walk.clone(),
            command: self.route.command.clone(),
            money,
            grant,
            governance,
            book,
            open,
        })
    }
}
impl Drop for CommittingRequest {
    fn drop(&mut self) {
        if self.armed {
            self.context().admission_phase().end();
        }
    }
}

/// Retains the actual installed Open, captured grant and checked invocation; clones share authority.
#[derive(Clone)]
pub struct AdmittedRequest {
    context: InvocationContext,
    routes: Arc<()>,
    grants: Arc<BTreeMap<String, Vec<String>>>,
    domain: RequestDomain,
    walk: Option<(RequestWalk, String)>,
    command: Option<SelectedCommand>,
    money: Arc<UnitMoney>,
    grant: Arc<AdmitGrant>,
    governance: Arc<GovState>,
    book: Arc<()>,
    open: Arc<()>,
}
impl AdmittedRequest {
    /// Same original monetary and invocation ownership, including after effects retire.
    /// This comparison grants no new admission and cannot be satisfied by a reused unit number.
    pub fn same_admission(&self, other: &Self) -> bool {
        self.context.same_unit(&other.context)
            && Arc::ptr_eq(&self.book, &other.book)
            && Arc::ptr_eq(&self.open, &other.open)
            && Arc::ptr_eq(&self.grant, &other.grant)
            && Arc::ptr_eq(&self.governance, &other.governance)
            && Arc::ptr_eq(&self.money, &other.money)
            && Arc::ptr_eq(&self.routes, &other.routes)
            && match (self.registered_command(), other.registered_command()) {
                (Some(a), Some(b)) => Arc::ptr_eq(a, b),
                (None, None) => true,
                _ => false,
            }
    }

    /// The original signed verification of this exact registered request, never a key lookup.
    pub fn signed_authority(
        &self,
    ) -> Option<&crate::governance::current_credential::VerifiedKeyAuthority> {
        self.is_live()
            .then(|| self.context.signed_authority())
            .flatten()
            .map(Arc::as_ref)
    }
    pub fn context(&self) -> &InvocationContext {
        &self.context
    }
    pub fn unit(&self) -> UnitKey {
        UnitKey::new(self.context.unit())
    }
    pub fn key(&self) -> &Arc<VirtualKey> {
        &self.money.key
    }
    pub fn cost(&self) -> &Arc<CostModel> {
        &self.money.cost
    }
    pub fn pool(&self) -> &str {
        &self.money.pool
    }
    pub fn arrived(&self) -> u64 {
        self.money.arrived
    }
    pub fn domain(&self) -> &RequestDomain {
        &self.domain
    }
    pub fn member_grants(&self) -> &BTreeMap<String, Vec<String>> {
        &self.grants
    }
    pub fn charge(&self) -> &crate::governance::FeeCharge {
        &self.money.charge
    }
    pub(crate) fn matches_governance(&self, governance: &GovState) -> bool {
        std::ptr::eq(self.governance.as_ref(), governance)
    }
    pub fn is_live(&self) -> bool {
        self.context.is_live() && self.context.effects_allowed()
    }
    pub fn accepts_walk(&self, walk: &RequestWalk) -> bool {
        self.is_live()
            && self.walk.as_ref().is_some_and(|(held, _)| {
                Arc::ptr_eq(&held.identity, &walk.identity) && walk.accepts(&self.context)
            })
    }
    pub fn walk_key(&self) -> Option<&str> {
        self.walk.as_ref().map(|(_, key)| key.as_str())
    }
    /// A later FORWARD may only reuse the same frozen route; Local never acquires a route later.
    pub fn accepts_route(&self, routes: &RequestRoutes, selector: Option<&str>) -> bool {
        self.is_live()
            && Arc::ptr_eq(&self.routes, &routes.identity)
            && routes.resolve(selector).is_ok_and(|(domain, walk)| {
                domain == self.domain && self.walk_key() == Some(walk.as_str())
            })
    }
    pub(in crate::plane_driver) fn matches_money(
        &self,
        book: &Arc<()>,
        open: &Arc<()>,
        grant: &Arc<AdmitGrant>,
    ) -> bool {
        self.is_live() && self.matches_money_identity(book, open, grant)
    }
    /// Terminal cleanup only: retirement closes effects but does not erase the original Open.
    pub(in crate::plane_driver) fn matches_money_identity(
        &self,
        book: &Arc<()>,
        open: &Arc<()>,
        grant: &Arc<AdmitGrant>,
    ) -> bool {
        Arc::ptr_eq(&self.book, book)
            && Arc::ptr_eq(&self.open, open)
            && Arc::ptr_eq(&self.grant, grant)
    }
}

#[cfg(test)]
#[path = "tests/request_admission_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/request_credential_tests.rs"]
mod credential_tests;
#[cfg(test)]
#[path = "tests/request_registration_support.rs"]
mod registration_support;
#[cfg(test)]
pub(crate) use registration_support::CommandAdmissionFixture;

#[cfg(test)]
#[path = "tests/request_current_tests.rs"]
mod current_tests;
