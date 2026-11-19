// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One checked native allocation, retained walk and monetary admission.
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

use busbar_contract::kept::Text;
use busbar_contract::records::VirtualKey;
use busbar_contract::UnitKey;

use super::money::UnitMoney;
use super::port_egress::SeatPool;
use super::provider_catalog::{CatalogPlan, RouteKind};
use crate::cost::CostModel;
use crate::governance::{AdmitGrant, GovState, PLANE_LANE_SEP};
use crate::host_services::InvocationContext;
use crate::resource_admission::SelectedResources;

#[path = "request_registration.rs"]
mod registration;
use registration::SelectedCommand;
#[path = "request_section_pools.rs"]
mod sections;
pub use sections::SectionPool;
#[path = "request_current.rs"]
mod current;

const REGISTERED: u8 = 0;
const RESOLVING: u8 = 1;
const READY: u8 = 2;
const COMMITTING: u8 = 3;
const ADMITTED: u8 = 4;
const ENDED: u8 = 5;
/// A verified request on a route that opens no unit: its route's hooks are heard, as a billed
/// request's are between its walk and its money, and it never leaves this phase but to end. No
/// transition starts here, so no money can be asked and no effect allowed under it.
const UNBILLED: u8 = 6;

/// Shared only by the actual registered record and its checked invocation clones.
pub(crate) struct AdmissionPhase(AtomicU8);
impl AdmissionPhase {
    pub(crate) fn pending() -> Self {
        Self(AtomicU8::new(REGISTERED))
    }
    pub(crate) fn admitted() -> Self {
        Self(AtomicU8::new(ADMITTED))
    }
    /// A verified request that opens no unit (`UNBILLED`).
    pub(crate) fn unbilled() -> Self {
        Self(AtomicU8::new(UNBILLED))
    }
    /// The request opens no unit and never will.
    pub(crate) fn opens_no_unit(&self) -> bool {
        self.at(UNBILLED)
    }
    pub(crate) fn effects_allowed(&self) -> bool {
        self.0.load(Ordering::Acquire) == ADMITTED
    }
    /// The request's walk is resolved (the key's grant of it is judged) and its money has not
    /// been asked: where a hook that may refuse is heard. A request that opens no unit stands
    /// there for its whole life: it is verified, and there is no money to ask.
    pub(crate) fn before_money(&self) -> bool {
        let phase = self.0.load(Ordering::Acquire);
        phase == READY || phase == UNBILLED
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

/// The members a unit may reach, walk by walk, by their qualified names
/// (`<instance><sep><member>`). A walk the key reaches whole shares the routes' own member list,
/// made once with the generation; a narrowed walk holds its own shorter list. Either way a name
/// is shared text: a grant spells no name and copies none.
pub type MemberGrants = BTreeMap<Text, Arc<[Text]>>;

/// One walk's key and its members' qualified names, in configured order.
type WalkLanes = (Text, Arc<[Text]>);

/// A configured name as shared text: made once, as the routes are built.
fn shared(name: &str) -> Text {
    Text::from(Arc::<str>::from(name))
}

/// `members` of `instance` by their qualified names, in order: made once, as the routes are built.
fn lanes_of<'m>(instance: &str, members: impl Iterator<Item = &'m str>) -> Arc<[Text]> {
    members
        .map(|member| shared(&format!("{instance}{PLANE_LANE_SEP}{member}")))
        .collect()
}

/// `lanes` less the ones `keep` drops, in order. When none is dropped it is the routes' own
/// list, shared: an unnarrowed grant builds nothing.
fn granted(lanes: &Arc<[Text]>, keep: impl Fn(usize, &Text) -> bool) -> Arc<[Text]> {
    if lanes.iter().enumerate().all(|(at, lane)| keep(at, lane)) {
        return Arc::clone(lanes);
    }
    lanes
        .iter()
        .enumerate()
        .filter(|(at, lane)| keep(*at, lane))
        .map(|(_, lane)| lane.clone())
        .collect()
}

/// Immutable route metadata from root's selected generation. It grants no unit authority.
pub struct RequestRoutes {
    identity: Arc<()>,
    instance: String,
    scope_kind: Option<Arc<str>>,
    catalog: Option<Arc<CatalogPlan>>,
    registration: Option<Arc<SeatPool>>,
    registrations: Option<Arc<crate::upstreams::ConfiguredUpstreams>>,
    section_pools: BTreeMap<String, SectionPool>,
    /// The catalog's walks, in `catalog.pools()` order, each with its members' qualified names.
    catalog_lanes: Vec<WalkLanes>,
    /// The registration pool with its members' qualified names.
    registration_lanes: Option<WalkLanes>,
    /// The section pools, in `section_pools` order, each with its members' qualified names
    /// (index for index with the pool's `members`).
    section_lanes: Vec<WalkLanes>,
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
                .is_some_and(|r| r.pool != instance || !r.pools.contains_key(r.pool.as_str()))
        {
            return Err(AdmissionError::Route);
        }
        if let (Some(catalog), Some(registration)) = (&catalog, &registration) {
            if catalog.select(&registration.pool).is_some() {
                return Err(AdmissionError::Route);
            }
        }
        let catalog_lanes = catalog.as_ref().map_or_else(Vec::new, |plan| {
            plan.pools()
                .iter()
                .map(|(walk, pool)| {
                    let members = pool.config.members.iter().map(|member| member.name());
                    (shared(walk), lanes_of(instance, members))
                })
                .collect()
        });
        let registration_lanes = registration.as_ref().map(|seat| {
            let members = seat.members.iter().map(|member| &*member.upstream);
            (shared(&seat.pool), lanes_of(instance, members))
        });
        Ok(Self {
            identity: Arc::new(()),
            instance: instance.into(),
            scope_kind,
            catalog,
            registration,
            registrations: None,
            section_pools: BTreeMap::new(),
            catalog_lanes,
            registration_lanes,
            section_lanes: Vec::new(),
        })
    }

    /// Whether `key` may use the operator domain `name` (K2). A declared kind checks the
    /// key's grant of that kind. With no declared kind, a keyed unit is admitted only by an
    /// unrestricted key or by its own non-empty authorized selection, which then narrows
    /// the walk to the selected tuples; `None` never means allow.
    /// The admission walk and the current-key re-check both use this one rule.
    fn scope_admits(
        &self,
        key: &VirtualKey,
        selection: Option<&SelectedResources>,
        name: &str,
    ) -> bool {
        match selection {
            Some(selected) => {
                selected.scope_allowed(key)
                    && self
                        .scope_kind
                        .as_ref()
                        .is_none_or(|kind| key.scope_allowed(kind, name))
            }
            None => self.key_admits(key, name),
        }
    }

    /// The key's own grant of `name` in this seat's declared kind. With no declared kind,
    /// only an unrestricted key holds it.
    fn key_admits(&self, key: &VirtualKey, name: &str) -> bool {
        match &self.scope_kind {
            Some(kind) => key.scope_allowed(kind, name),
            None => key.allowed_scopes.is_none(),
        }
    }

    // Catalog and registration walks are ordinary pool/direct scope. Member-granted pools are
    // the section pools, granted per member in `section_grants` (#108, R5).
    fn member_grants(
        &self,
        key: &VirtualKey,
        selection: Option<&SelectedResources>,
    ) -> MemberGrants {
        let allowed = |name: &str| self.scope_admits(key, selection, name);
        let selected = |walk: &str, member: &str| {
            selection.is_none_or(|selected| selected.grants_member(walk, member))
        };
        let mut grants = MemberGrants::new();
        if let Some(catalog) = &self.catalog {
            // `catalog_lanes` was read off this same immutable catalog, walk for walk.
            for (pool, (walk, lanes)) in catalog.pools().values().zip(&self.catalog_lanes) {
                let name = match &pool.kind {
                    RouteKind::NamedPool(name) | RouteKind::DirectModel(name) => name,
                };
                if !allowed(name) {
                    continue;
                }
                let members = granted(lanes, |_, lane| selected(walk.as_str(), lane.as_str()));
                if !members.is_empty() {
                    grants.insert(walk.clone(), members);
                }
            }
        }
        if let (Some(registration), Some((pool, lanes))) =
            (&self.registration, &self.registration_lanes)
        {
            if allowed(&registration.pool) {
                let members = granted(lanes, |_, lane| selected(pool.as_str(), lane.as_str()));
                if !members.is_empty() {
                    grants.insert(pool.clone(), members);
                }
            }
        }
        self.section_grants(key, selection, &mut grants);
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
            if self.section_pools.contains_key(name) {
                return Ok((RequestDomain::NamedPool(name.into()), name.into()));
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
    selection: Option<Arc<SelectedResources>>,
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
            selection: None,
            armed: true,
        })
    }
    pub fn context(&self) -> &InvocationContext {
        &self.context
    }
    /// Bind this native unit's authorized resource selection: its walk grants become the
    /// selected tuples' own targets, and a registration outside them is refused (K2).
    pub fn with_selection(mut self, selected: Arc<SelectedResources>) -> Self {
        self.selection = Some(selected);
        self
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
            let grants = routes.member_grants(&self.key, self.selection.as_deref());
            if !grants.contains_key(walk_key.as_str()) {
                return Err(AdmissionError::Scope);
            }
            grants
        } else {
            MemberGrants::new()
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
            selection: self.selection.clone(),
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
    grants: Arc<MemberGrants>,
    cost: Arc<CostModel>,
    arrived: u64,
    pool: String,
    domain: RequestDomain,
    walk: Option<(RequestWalk, String)>,
    command: Option<SelectedCommand>,
    selection: Option<Arc<SelectedResources>>,
    armed: bool,
}
impl RequestPoolReceipt {
    pub fn pool(&self) -> &str {
        &self.pool
    }
    pub fn domain(&self) -> &RequestDomain {
        &self.domain
    }
    pub fn member_grants(&self) -> &MemberGrants {
        &self.grants
    }
    /// The receipt's grants, shared: a unit route that confines its walk to them holds this
    /// same map, never a copy.
    pub fn shared_member_grants(&self) -> &Arc<MemberGrants> {
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
            selection: self.route.selection.clone(),
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
    grants: Arc<MemberGrants>,
    domain: RequestDomain,
    walk: Option<(RequestWalk, String)>,
    command: Option<SelectedCommand>,
    selection: Option<Arc<SelectedResources>>,
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
    pub fn member_grants(&self) -> &MemberGrants {
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
