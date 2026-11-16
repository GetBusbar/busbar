// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use busbar_contract::abi::plane::{
    UnitCount, ROUTE_DIRECT, ROUTE_LOCAL, ROUTE_POOL, ROUTE_SCOPE, ROUTE_SCOPE_LOCAL,
    ROUTE_SCOPE_SEPARATOR,
};
use busbar_contract::caps::{
    Admittance, Authenticated, Consumption, Dial, Grant, OpClassId, Outcome, PrincipalId,
    QuantitySource, ReasonCode, Refusal, UsageLine, VerifiedDestination,
};
use busbar_contract::records::VirtualKey;
use busbar_contract::MeterClassId;
use busbar_kernel::config::groups::ExhaustionMode;
use busbar_kernel::governance::{AdmitGrant, LimitBlocked, PLANE_LANE_SEP};
#[cfg(test)]
use busbar_kernel::plane_driver::ParentMoney;
use busbar_kernel::plane_driver::{DriverSteps, FeeRefund, PlaneMoney, UnitMoney};
use busbar_kernel::slice::GroupLeaseSlip;
use busbar_kernel::state::App;
use busbar_kernel::teller::UnitCtx;

use crate::root::linked::node::Resolve;

// The off-path half (pool tables, sections, routes, bindings, rules, credential renewal).
pub(crate) use crate::root::off_path::door_steps::*;

/// THE POOLS A DOOR PLANE'S UNITS ROUTE OVER, read off its section
/// once per generation: the section's entries (its `models` map's keys in a model-serving section,
/// else every top-level key but the reserved ones) and its
/// reserved `pools` sub-key (each named pool's member entries). An arrival names an entry name
/// (`ArriveOut::pool`); nothing here parses it, it is only looked up.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DoorPools {
    pub(crate) entries: Vec<String>,
    pub(crate) pools: BTreeMap<String, Vec<String>>,
    /// Each pool's `on_exhausted: { fallback_pool }`, where it names one.
    pub(crate) fallbacks: BTreeMap<String, String>,
    /// The pools whose members the plane admits each on its own grant (`member_granted`): the
    /// pool's name is no grant of its own.
    pub(crate) member_granted: std::collections::BTreeSet<String>,
    /// Each entry's reserved `timeout:`, in milliseconds (`busbar_contract::section::ENTRY_TIMEOUT_KEY`),
    /// a tool-server registration that writes none at the core's default: its member's attempt bound.
    pub(crate) timeouts: BTreeMap<String, u64>,
    /// Each pool's members' tiers, in member order (`0` where a member states none).
    pub(crate) tiers: BTreeMap<String, Vec<u32>>,
    /// Each pool's `breaker:` block, where its `pools:` entry states one ([`POOL_BREAKER_KEY`]):
    /// the same block, read the same way, as a top-level pool's (BUSBAR-1.6.0.md THE DESIGN
    /// §1: "Any plugin gets all functionality").
    pub(crate) breakers: BTreeMap<String, busbar_kernel::config::BreakerCfg>,
    /// The section's entries, indexed: what a direct route names is looked up here.
    pub(crate) entry_set: std::collections::BTreeSet<String>,
    /// Each entry's member-granted pool: the first such pool, in name order, that lists it.
    pub(crate) member_pools: BTreeMap<String, String>,
}

pub type Routed = (String, Vec<String>);

impl DoorPools {
    #[must_use]
    pub fn breaker(&self, pool: &str) -> Option<&busbar_kernel::config::BreakerCfg> {
        self.breakers.get(pool)
    }

    #[must_use]
    pub fn timeout_ms(&self, entry: &str) -> Option<u64> {
        self.timeouts.get(entry).copied()
    }

    #[must_use]
    pub fn resolve(&self, class: u8, named: Option<&[u8]>) -> Option<Routed> {
        busbar_contract::stage_probe::tick(busbar_contract::stage_probe::Derive::EntryResolve);
        let name = std::str::from_utf8(named?).ok()?;
        match class {
            ROUTE_POOL => self
                .pools
                .get(name)
                .map(|members| (name.to_owned(), members.clone())),
            ROUTE_DIRECT => self
                .entry_set
                .get(name)
                .map(|e| (String::new(), vec![e.clone()])),
            _ => None,
        }
    }

    pub fn entries(&self) -> &[String] {
        &self.entries
    }

    #[must_use]
    pub fn pools(&self) -> &BTreeMap<String, Vec<String>> {
        &self.pools
    }

    #[must_use]
    pub fn tier(&self, pool: &str, index: usize) -> u32 {
        self.tiers
            .get(pool)
            .and_then(|t| t.get(index))
            .copied()
            .unwrap_or(0)
    }

    #[must_use]
    pub(crate) fn member_pool(&self, entry: &str) -> Option<&str> {
        self.member_pools.get(entry).map(String::as_str)
    }

    #[must_use]
    pub fn fallback(&self, pool: &str) -> Option<&str> {
        self.fallbacks.get(pool).map(String::as_str)
    }
}

pub(crate) const POOL_BREAKER_KEY: &str = "breaker";

impl DoorPools {
    #[must_use]
    pub fn granted(
        &self,
        kind: Option<&str>,
        key: Option<&VirtualKey>,
        class: u8,
        named: Option<&[u8]>,
    ) -> bool {
        self.granted_known(kind, key, class, named, None)
    }

    /// [`DoorPools::granted`], given verify's answer for a `ROUTE_DIRECT` name (`entry_known`:
    /// whether it is one of this section's entries, SP-V1); `None` re-scans the entries.
    fn granted_known(
        &self,
        kind: Option<&str>,
        key: Option<&VirtualKey>,
        class: u8,
        named: Option<&[u8]>,
        entry_known: Option<bool>,
    ) -> bool {
        let Some(key) = key else {
            return true;
        };
        let Some(kind) = kind else {
            return true;
        };
        let Some(name) = named.and_then(|n| std::str::from_utf8(n).ok()) else {
            return true;
        };

        if class == ROUTE_POOL && self.member_granted.contains(name) {
            return true;
        }

        if class == ROUTE_DIRECT && !entry_known.unwrap_or_else(|| self.has_entry(name)) {
            return true;
        }
        let fallback = (class == ROUTE_POOL)
            .then(|| self.fallbacks.get(name))
            .flatten();
        std::iter::once(name)
            .chain(fallback.map(String::as_str))
            .all(|granted| key.scope_allowed(kind, granted))
    }
}

impl DoorPools {
    /// Whether `name` is one of this section's entries: an entry-index lookup (SP-V1 counts it).
    fn has_entry(&self, name: &str) -> bool {
        busbar_contract::stage_probe::tick(busbar_contract::stage_probe::Derive::EntryResolve);
        self.entry_set.contains(name)
    }

    #[must_use]
    pub(crate) fn granted_to(
        &self,
        kind: Option<&str>,
        key: Option<&VirtualKey>,
        (class, named): (u8, Option<&[u8]>),
        counterparty: Option<&[u8]>,
        entry_known: Option<bool>,
    ) -> bool {
        if !self.granted_known(kind, key, class, named, entry_known) {
            return false;
        }
        let (Some(kind), Some(key)) = (kind, key) else {
            return true;
        };
        let Some(pool) = named.and_then(|n| std::str::from_utf8(n).ok()) else {
            return true;
        };
        if class != ROUTE_POOL || !self.member_granted.contains(pool) {
            return true;
        }
        let member = counterparty
            .and_then(|c| std::str::from_utf8(c).ok())
            .filter(|c| {
                self.pools
                    .get(pool)
                    .is_some_and(|m| m.iter().any(|m| m == c))
            });
        member.is_none_or(|member| key.scope_allowed(kind, member))
    }
}

#[must_use]
pub fn plane_lane(plane: &str, entry: &str) -> String {
    if plane.is_empty() {
        return entry.to_string();
    }
    format!("{plane}{PLANE_LANE_SEP}{entry}")
}

/// The lane a unit's money opens under: the first member's lane on its plane. A routed unit with
/// no member is refused, never laned `""` (no rate card prices `""`, so every read of a row under it
/// refuses). An unrouted unit keeps the empty lane.
fn opened_lane(plane: &str, routed: Option<&Routed>) -> Result<String, Refusal> {
    match routed {
        None => Ok(String::new()),
        Some((_, members)) => members
            .first()
            .map(|m| plane_lane(plane, m))
            .ok_or_else(|| Refusal::new(ReasonCode::Unpriced)),
    }
}

#[must_use]
pub(crate) fn egress_pool(plane: &str, routed: &Routed) -> String {
    match routed {
        (label, _) if !label.is_empty() => label.clone(),
        (_, members) => members
            .first()
            .map(|m| plane_lane(plane, m))
            .unwrap_or_default(),
    }
}

struct DoorPoolView<'a> {
    pools: &'a DoorPools,
    key: Option<&'a VirtualKey>,
    app: &'a App,
}

impl busbar_kernel::door::PoolView for DoorPoolView<'_> {
    fn has_key(&self) -> bool {
        self.key.is_some()
    }

    fn key_is_scoped(&self) -> bool {
        self.key.is_some_and(|k| k.allowed_scopes.is_some())
    }

    fn pool_allowed(&self, pool: &str) -> bool {
        self.key.is_none_or(|k| k.scope_allowed("pool", pool))
    }

    fn on_exhausted_fallback(&self, pool: &str) -> Option<String> {
        self.pools.fallback(pool).map(str::to_owned)
    }

    fn is_configured(&self, name: &str) -> bool {
        self.pools.pools().contains_key(name) || self.pools.has_entry(name)
    }

    fn is_unpriced(&self, name: &str) -> bool {
        self.app.cost.model_unpriced(name)
    }
}

/// How a unit is admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// A keyed unit: admitted and charged on the governance book, its money opened.
    Keyed,
    /// No key, on a claim that takes no credential (`CLAIM_OPEN`): admitted with nothing held and
    /// no money; it never reaches a billed path.
    Anonymous,
    /// No key on a claim that takes a credential: never admitted (fail closed).
    Refused,
}

#[must_use]
pub fn admission(key: Option<&Arc<VirtualKey>>, open: bool) -> Admission {
    match (key, open) {
        (Some(_), _) => Admission::Keyed,
        (None, true) => Admission::Anonymous,
        (None, false) => Admission::Refused,
    }
}

fn refusal_for(blocked: &LimitBlocked) -> Refusal {
    let waited = |refusal: Refusal, retry_after: &Option<u64>| match retry_after
        .and_then(|s| u32::try_from(s).ok())
    {
        Some(secs) => refusal.retry_after(secs),
        None => refusal,
    };
    match blocked {
        LimitBlocked::Disabled(_) => Refusal::new(ReasonCode::GroupFrozen),
        LimitBlocked::MissingGroup(_) => Refusal::new(ReasonCode::OverBudget),
        // SHUTDOWN-HANG F4a: "retry on another instance", so no Retry-After.
        LimitBlocked::Draining => Refusal::new(ReasonCode::Drain),
        LimitBlocked::CustodyFull { .. } => {
            Refusal::new(ReasonCode::DurabilityUnavailable).retry_after(1)
        }
        LimitBlocked::Limit {
            metric: "budget",
            retry_after,
            ..
        } => waited(Refusal::new(ReasonCode::OverBudget), retry_after),
        LimitBlocked::Limit { retry_after, .. } => {
            waited(Refusal::new(ReasonCode::RateLimited), retry_after)
        }
    }
}

/// WHAT A SERVED PLANE STATES THE KERNEL SERVES ITS UNITS BY, read off its Statement tail at bind.
#[derive(Debug, Clone)]
pub struct DoorFacts {
    /// The plane's key: the card its lanes are priced on, and the qualifier of every lane it routes.
    pub plane: busbar_kernel::plane_driver::dispatch::LaneQualifier,
    /// The grant kind that admits its traffic (its tail's first scope kind); `None` = it states none.
    pub scope_kind: Option<String>,
    /// Host-sealed catalog entries and their declared secondary grant kind.
    pub secondary_scopes: BTreeMap<String, String>,
    /// Its billable classes, in its tail's order: a unit count's class indexes them.
    pub classes: Arc<[String]>,
    /// The validated plane recipe: billable-class index and default expected units.
    pub route_cost: Vec<(u32, f64)>,
    /// The same classes as the meter's class ids.
    pub meter_classes: Arc<[MeterClassId]>,
    /// Its fee units, as indices into [`Self::classes`].
    pub fee_units: Arc<[u32]>,
    /// Its `audit_kind`: what a unit refused before its decode is audited under.
    pub audit_kind: OpClassId,
    /// Each need's response-head rule, in Statement need order: what of a far end's head reaches
    /// the plane on that need.
    pub keeps: Vec<busbar_kernel::plane_driver::ResponseKeep>,
    /// The plane's dialect names, by the index `arrive` answers, and each provider's dialect: an
    /// attempt whose far end speaks another dialect than the caller's is counted as a translation
    /// (`busbar_translations_total`), as the previous release counted it, and a usage-tap fault
    /// an answer carries is counted under the unit's dialect. Empty = none counted.
    pub translations: (Arc<[String]>, Arc<BTreeMap<String, String>>),
    /// The plane's dialect names, by the index `arrive` answers: the `ingress` its units' request
    /// span records.
    pub dialects: Arc<[String]>,
    /// The plane's declared breaker fact (`declares.breaker`): whether a transient
    /// failure below the trip threshold benches a member's cell. `None`: it declares none, and
    /// every cell keeps the host's default.
    pub bench_below_trip_threshold: Option<bool>,
    /// Its declared counter lane words (`PlaneTail::metric_lanes`): beside its entry names, the
    /// words its attempts may state as their `lane` label ([`label_bound`]).
    pub metric_lanes: Vec<String>,
    /// Its stated stream ceiling, seconds (its tail's `stream_ceiling_secs`): the deadline of a
    /// unit whose `arrive` states `ROUTE_STREAM`, from the moment its route is known. `0` = none.
    pub stream_ceiling_secs: u64,
}

impl DoorFacts {
    pub(super) fn scope_candidate_granted(
        &self,
        pools: &DoorPools,
        key: Option<&VirtualKey>,
        class: u8,
        explicit: bool,
        entry: &str,
    ) -> bool {
        (class == ROUTE_SCOPE_LOCAL && explicit && self.secondary_scopes.contains_key(entry))
            || pools.granted(
                self.scope_kind.as_deref(),
                key,
                ROUTE_DIRECT,
                Some(entry.as_bytes()),
            )
    }
}

/// The budget inputs one unit's admission reads (SINGLE-PATH SP-AD1): built once by
/// `prepare_admission` for the unit's routed pool and consumed by its charge's first admission.
/// A downgrade re-route builds its own for the new pool.
struct BudgetPlan {
    /// Its expected units, by class name.
    units: BTreeMap<String, busbar_contract::Count>,
    /// The pool it is charged through.
    pool: String,
    /// Its key's budget chain; `None` when a group the key names is missing.
    chain: Option<busbar_kernel::cost::ChainPlan>,
}

/// What one unit carries between its steps.
#[derive(Default)]
struct DoorUnit {
    op: Option<OpClassId>,
    /// What its `arrive` named, once decode ran: the route class and the entry.
    named: Option<(u8, Option<Vec<u8>>)>,
    /// What its `arrive` expected it to do (its admission estimate).
    expected: Vec<UnitCount>,
    /// Its operation is performed at most once (`ROUTE_ONCE`).
    once: bool,
    /// The plane answers it itself as an admitted call (`ROUTE_COUNTED`): a keyed one is charged.
    counted: bool,
    /// Its caller asked for the answer streamed (`ROUTE_STREAM`).
    stream: bool,
    /// The walk's affinity position its `arrive`'s sticky key names.
    affinity: Option<u64>,
    routed: Option<Routed>,
    /// A `ROUTE_DIRECT` unit's named entry as verify resolved it: whether it is one of the
    /// section's entries. Approve judges the grant over it rather than re-scanning (SP-V1).
    entry_known: Option<bool>,
    /// The governance book's grant: its in-flight holds, released when the unit's steps drop.
    grant: Option<Arc<AdmitGrant>>,
    /// Its budget inputs, built at `prepare_admission` and taken by its charge.
    budget: Option<BudgetPlan>,
    charged_unit: Option<busbar_contract::caps::UnitKey>,
    /// Whether the unit's money facts were opened (it was charged).
    charged: bool,
    /// The words of the refusal one of its steps raised, where it has its own (its Retry-After
    /// seconds; its message).
    refused: (Option<u32>, Option<String>),
    /// The key the unit's record was written under on the host's unit records, once authenticate
    /// passed; it is struck when these steps drop.
    recorded: Option<u64>,
    /// A `ROUTE_SCOPE` unit several entries reach: those entries, named in its refusal's words.
    reachable: Vec<String>,
    /// The pool a budget `on_exhaust: downgrade` re-admitted the unit through, where one did: its
    /// charge landed there and its walk routes there.
    downgraded: Option<String>,
    /// How its answer went, as the driver told it before the audit seat: a byte reached the
    /// caller, and the far end cut the answer after its head ([`DriverSteps::answered`]).
    answered: (bool, bool),
    /// A `ROUTE_SCOPE_LOCAL` unit's one entry, its scope resolved at verify: the plane answers it
    /// there, with no route walked.
    resolved: Option<String>,
    /// A `ROUTE_SCOPE` or `ROUTE_SCOPE_LOCAL` unit's one entry, its scope resolved at verify: the
    /// entry its gate-first hooks bind over ([`DriverSteps::scope_entry`]).
    scope_entry: Option<String>,
    /// The counterparty its `arrive` stated among its trust facts: the entry it is addressed to.
    counterparty: Option<Vec<u8>>,
}

pub struct DoorSteps<'s> {
    facts: &'s DoorFacts,
    pools: &'s DoorPools,
    lanes: Resolve,
    app: Arc<App>,
    money: Option<&'s PlaneMoney>,
    principal: PrincipalId,
    key: Option<Arc<VirtualKey>>,

    open: bool,

    arrived: u64,

    records: Option<Arc<busbar_kernel::host_units::UnitRecords>>,

    depth: u32,

    credential: Option<busbar_kernel::auth::CallerCredential>,

    ticket: Option<Vec<u8>>,

    host_ticket_admission: Option<busbar_kernel::host_services::HostTicketAdmission>,
    ticket_node: Option<Arc<()>>,
    ticket_instance: Option<Arc<()>>,
    ticket_lineage: Mutex<Option<busbar_kernel::plane_driver::ReservedRequestLineage>>,
    parent: Option<&'s busbar_contract::caps::HoldCell>,
    #[cfg(test)]
    parent_admission: Option<&'s ParentAdmission<'s>>,
    child_constraints: Option<busbar_kernel::hook_child::Constraints>,
    unit: Mutex<DoorUnit>,
}

impl std::fmt::Debug for DoorSteps<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DoorSteps")
            .field("plane", &self.facts.plane)
            .field("principal", &self.principal)
            .finish_non_exhaustive()
    }
}

/// Who a unit is, as the data door saw it arrive.
#[derive(Debug, Clone)]
pub struct DoorCaller {
    /// The principal the unit is billed to (THE DESIGN §7, Attribution).
    pub principal: PrincipalId,
    /// The caller's governance key, when the auth gate resolved one.
    pub key: Option<Arc<VirtualKey>>,
    /// The claim it arrived on takes no inbound credential.
    pub open: bool,
    /// Its arrival epoch, seconds.
    pub arrived: u64,
    /// The host's unit records the unit's principal is written on while it runs.
    pub records: Option<Arc<busbar_kernel::host_units::UnitRecords>>,
    /// How deep the unit is nested (`0` for a unit a caller sent), written on its record.
    pub depth: u32,
    /// The caller's verified credential, lent on the unit's record while it runs: a passthrough
    /// member's auth call made inside the unit (the plane's own fetches included) is lent it.
    pub credential: Option<busbar_kernel::auth::CallerCredential>,
    /// The record of the ticket the auth gate spent admitting the caller (row 132); `None` when a
    /// key admitted it.
    pub ticket: Option<Vec<u8>>,
}

/// Host-owned proof of the actual live parent cell and its retained monetary admission. No
/// production path opens one yet (only `under_admission`'s tests do), so it is test-only.
#[cfg(test)]
pub(crate) struct ParentAdmission<'a> {
    cell: &'a busbar_contract::caps::HoldCell,
    money: &'a PlaneMoney,
    token: ParentMoney,
}

impl<'s> DoorSteps<'s> {
    #[must_use]
    pub fn new(
        facts: &'s DoorFacts,
        pools: &'s DoorPools,
        lanes: Resolve,
        app: Arc<App>,
        money: Option<&'s PlaneMoney>,
        caller: DoorCaller,
    ) -> Self {
        DoorSteps {
            facts,
            pools,
            lanes,
            app,
            money,
            principal: caller.principal,
            key: caller.key,
            open: caller.open,
            arrived: caller.arrived,
            records: caller.records,
            depth: caller.depth,
            credential: caller.credential,
            ticket: caller.ticket,
            host_ticket_admission: None,
            ticket_node: None,
            ticket_instance: None,
            ticket_lineage: Mutex::new(None),
            parent: None,
            #[cfg(test)]
            parent_admission: None,
            child_constraints: None,
            unit: Mutex::new(DoorUnit::default()),
        }
    }

    pub(crate) fn with_ticket_admission(
        mut self,
        ticket: Option<busbar_kernel::host_services::HostTicketAdmission>,
        node: Arc<()>,
        instance: Arc<()>,
    ) -> Self {
        self.host_ticket_admission = ticket;
        self.ticket_node = Some(node);
        self.ticket_instance = Some(instance);
        self
    }

    #[must_use]
    pub fn under(mut self, parent: &'s busbar_contract::caps::HoldCell) -> Self {
        self.parent = Some(parent);
        self
    }

    pub(crate) fn with_child_constraints(
        mut self,
        constraints: Option<busbar_kernel::hook_child::Constraints>,
    ) -> Self {
        self.child_constraints = constraints;
        self
    }

    pub(crate) fn child_member(&self) -> Option<String> {
        self.child_constraints
            .as_ref()
            .map(|c| c.grant.target_binding.clone())
    }

    fn child_live(&self) -> Result<(), Refusal> {
        if let Some(c) = &self.child_constraints {
            // DoorNests already binds the grant to the matched configured instance.
            // The declared plane pricing key here may be shared by several instances.
            if self.key.is_none()
                || self.money.is_none()
                || self.app.governance.is_none()
                || !self.pools.entries().contains(&c.grant.target_binding)
                || c.cancellation.is_cancelled()
                || busbar_core_connector::framer::instant_of(busbar_core_connector::framer::now_ns())
                    >= c.deadline
            {
                return Err(Refusal::new(ReasonCode::ScopeDenied));
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn parent_admission<'a>(
        &'a self,
        ctx: &UnitCtx,
        cell: &'a busbar_contract::caps::HoldCell,
        admit: &Grant<Admittance>,
    ) -> Result<ParentAdmission<'a>, Refusal> {
        if !admit.bound_to(ctx.call) || !cell.admitted_for(admit, &self.principal) {
            return Err(Refusal::new(ReasonCode::Replayed));
        }
        let key = self
            .key
            .as_ref()
            .ok_or_else(|| Refusal::new(ReasonCode::Unauthenticated))?;
        let money = self
            .money
            .ok_or_else(|| Refusal::new(ReasonCode::Unpriced))?;
        {
            let unit = self.lock();
            if !unit.charged || unit.charged_unit != Some(ctx.key) || unit.grant.is_none() {
                return Err(Refusal::new(ReasonCode::Unpriced));
            }
        }
        let token = money.parent_money(ctx.key, key).map_err(Refusal::new)?;
        Ok(ParentAdmission { cell, money, token })
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn under_admission(mut self, parent: &'s ParentAdmission<'s>) -> Self {
        self.parent = Some(parent.cell);
        self.parent_admission = Some(parent);
        self
    }

    #[cfg(test)]
    fn parented(&self) -> bool {
        self.parent_admission.is_some()
    }

    #[cfg(not(test))]
    fn parented(&self) -> bool {
        false
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, DoorUnit> {
        self.unit
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn routed(&self) -> Option<Routed> {
        self.lock().routed.clone()
    }

    /// Read the unit's route in place (SP-V1): no copy of its label and members.
    pub(crate) fn with_routed<R>(&self, read: impl FnOnce(&Routed) -> R) -> Option<R> {
        self.lock().routed.as_ref().map(read)
    }

    #[must_use]
    pub(crate) fn connection_required(&self) -> bool {
        self.app.upstream_creds() == busbar_contract::config::UpstreamCreds::Connection
    }

    pub fn once(&self) -> bool {
        self.lock().once
    }

    #[must_use]
    pub fn streamed(&self) -> bool {
        self.lock().stream
    }

    #[must_use]
    pub fn affinity(&self) -> Option<u64> {
        self.lock().affinity
    }

    #[must_use]
    pub(crate) fn lane_prefix(&self) -> &str {
        self.facts.plane.lane_prefix()
    }

    pub(crate) fn route_cost(&self, lane: &str) -> busbar_contract::SignalBag {
        use busbar_contract::signal::route_cost::{append, Term};
        let mut bag = busbar_contract::SignalBag::new();
        append(
            &mut bag,
            self.facts
                .route_cost
                .iter()
                .map(|&(class, expected_units)| {
                    let class = self
                        .facts
                        .classes
                        .get(class as usize)
                        .map(String::as_str)
                        .unwrap_or_default();
                    let price_per_unit = self.app.cost.routing_price(lane, class);
                    Term {
                        class,
                        price_per_unit,
                        expected_units,
                    }
                }),
        );
        bag
    }

    #[must_use]
    pub(crate) fn charged(&self) -> bool {
        self.lock().charged
    }

    #[must_use]
    pub(crate) fn downgraded(&self) -> Option<String> {
        self.lock().downgraded.clone()
    }

    #[must_use]
    pub(crate) fn stream_cut(&self) -> bool {
        let u = self.lock();
        u.answered.1 && u.stream
    }

    fn downgrade_reaches(&self, key: &VirtualKey, to: &str, visited: &[String]) -> bool {
        let pools = self.pools.pools();
        if visited.iter().any(|v| v == to)
            || visited.len() >= pools.len()
            || !pools.contains_key(to)
        {
            return false;
        }
        // Only a configured pool names a fallback, so the chain reaches every distinct name within
        // `pools.len() + 1` steps before it ends or comes back round; a pool it comes back to was
        // already judged, and judging it again gives the same answer. No visited list is kept.
        let mut at = Some(to);
        for _ in 0..=pools.len() {
            let Some(pool) = at else {
                break;
            };
            if !self.pools.granted(
                self.facts.scope_kind.as_deref(),
                Some(key),
                ROUTE_POOL,
                Some(pool.as_bytes()),
            ) {
                return false;
            }
            at = self.pools.fallback(pool);
        }
        true
    }

    fn charged_pool(&self, label: &str) -> String {
        plane_lane(self.facts.plane.lane_prefix(), label)
    }

    fn expected_units(
        &self,
        expected: &[UnitCount],
    ) -> Result<BTreeMap<String, busbar_contract::Count>, Refusal> {
        busbar_contract::stage_probe::tick(busbar_contract::stage_probe::Derive::BudgetUnits);
        let mut units = BTreeMap::new();
        for u in expected {
            if let Some(name) = self.facts.classes.get(u.class as usize) {
                let n = units
                    .entry(name.clone())
                    .or_insert(busbar_contract::Count::ZERO);
                *n = n
                    .checked_add(u.count().map_err(|_| Refusal::new(ReasonCode::Unpriced))?)
                    .map_err(|_| Refusal::new(ReasonCode::Unpriced))?;
            }
        }
        Ok(units)
    }

    fn charge(&self, ctx: &UnitCtx, key: &Arc<VirtualKey>) -> Result<bool, Refusal> {
        let (Some(gov), Some(money)) = (self.app.governance.as_ref(), self.money) else {
            return Ok(false);
        };
        let (routed, planned) = {
            let mut u = self.lock();
            (u.routed.clone(), u.budget.take())
        };
        let (units, mut planned) = match planned {
            Some(BudgetPlan { units, pool, chain }) => (units, Some((pool, chain))),
            None => (self.expected_units(&self.lock().expected)?, None),
        };

        let mut routed = routed;
        let mut visited: Vec<String> = Vec::new();
        let (grant, pool, lane) = loop {
            // Before governance admits: a refusal here has charged no request and no fee, on the
            // first pool and on every downgrade target.
            let lane = opened_lane(self.facts.plane.lane_prefix(), routed.as_ref())?;
            // The first admission reads the plan `prepare_admission` built; a downgrade
            // re-route builds the pool for its new pool, and its admission resolves the chain
            // itself.
            let (pool, chain) = match planned.take() {
                Some(plan) => plan,
                None => {
                    let label = routed.as_ref().map_or("", |(label, _)| label.as_str());
                    (self.charged_pool(label), None)
                }
            };
            if let Some(c) = &self.child_constraints {
                let lane = plane_lane(self.facts.plane.lane_prefix(), &c.grant.target_binding);
                let fee =
                    u128::try_from(self.app.cost.request_fee_on(self.facts.plane.lane_prefix()))
                        .ok()
                        .and_then(|n| n.checked_mul(busbar_kernel_ledger::cost::NANOS_PER_CENT));
                let estimate = self
                    .app
                    .cost
                    .price_counts_nanos(&lane, &units)
                    .zip(fee)
                    .and_then(|(usage, fee)| usage.checked_add(fee));
                if !estimate.is_some_and(|n| n <= u128::from(c.grant.max_budget_micros) * 1_000) {
                    return Err(Refusal::new(ReasonCode::Unpriced));
                }
            }
            match gov.try_admit_planned(&self.app.cost, key, &pool, self.arrived, chain.as_ref()) {
                Ok(grant) => break (grant, pool, lane),
                Err(LimitBlocked::Limit {
                    downgrade_to: Some(to),
                    ..
                }) if self.child_constraints.is_none()
                    && self.downgrade_reaches(key, &to, &visited) =>
                {
                    routed = self.pools.resolve(ROUTE_POOL, Some(to.as_bytes()));
                    visited.push(to);
                }
                Err(blocked) => {
                    if self.facts.plane.lane_prefix().is_empty() {
                        self.lock().refused.1 =
                            Some(busbar_kernel::ingress::limit_refusal("", &blocked).2);
                    }
                    return Err(refusal_for(&blocked));
                }
            }
        };
        if let Some(to) = visited.last() {
            let mut u = self.lock();
            u.routed = routed;
            u.downgraded = Some(to.clone());
        }
        let grant = Arc::new(grant);
        money.open_admitted(
            ctx.key,
            UnitMoney {
                key: Arc::clone(key),
                cost: Arc::clone(&self.app.cost),
                pool,

                lane,
                classes: Arc::clone(&self.facts.classes),
                arrived: self.arrived,
                mode: ExhaustionMode::FinishUnit,

                fee: FeeRefund::PlaneFeeUnits(Arc::clone(&self.facts.fee_units)),
                charge: grant.charge().clone(),
            },
            Arc::clone(&grant),
        );
        if let Some(c) = &self.child_constraints {
            money
                .limit_unit_spend(ctx.key, c.grant.max_budget_micros)
                .map_err(Refusal::new)?;
        }
        let mut u = self.lock();
        u.grant = Some(grant);
        u.charged_unit = Some(ctx.key);
        u.charged = true;
        Ok(true)
    }
}

impl Drop for DoorSteps<'_> {
    fn drop(&mut self) {
        let recorded = self.lock().recorded.take();
        if let (Some(records), Some(unit)) = (self.records.as_ref(), recorded) {
            records.ended(unit);
        }
    }
}

fn facts(
    op: OpClassId,
    outcome: &Outcome,
    streamed: bool,
    cut: bool,
) -> busbar_contract::AuditFacts {
    use busbar_contract::FinishClass;
    let finish = match outcome {
        Outcome::Completed if cut && streamed => FinishClass::Partial,

        Outcome::Completed if cut => FinishClass::Error,
        Outcome::Completed => FinishClass::Complete,
        Outcome::Aborted(_) if streamed => FinishClass::Partial,
        _ => FinishClass::Error,
    };
    busbar_contract::AuditFacts {
        op_class: op,
        finish,
    }
}

impl DriverSteps for DoorSteps<'_> {
    fn arrival(&self, _ctx: &UnitCtx) -> Result<busbar_contract::ArrivalRecord, Refusal> {
        Ok(busbar_contract::ArrivalRecord {
            source: String::new(),
            port: 0,
            alpn: None,
            sni: None,
            peer_cert: None,
            transport_chain: Vec::new(),
        })
    }

    fn authenticate(&self, ctx: &UnitCtx) -> Result<Authenticated, Refusal> {
        match admission(self.key.as_ref(), self.open) {
            Admission::Refused => Err(Refusal::new(ReasonCode::Unauthenticated)),
            Admission::Keyed | Admission::Anonymous => {
                if let Some(records) = &self.records {
                    records.admitted(
                        ctx.key.get(),
                        busbar_kernel::host_units::UnitRecord {
                            principal: self.key.clone(),
                            depth: self.depth,
                        },
                    );
                    if let Some(credential) = &self.credential {
                        records.lend(ctx.key.get(), credential.clone());
                    }

                    records.ticketed(ctx.key.get(), self.ticket.clone());
                    self.lock().recorded = Some(ctx.key.get());
                }
                Ok(Authenticated::Principal(self.principal.clone()))
            }
        }
    }

    fn verify(
        &self,
        trust: &Grant<Dial>,
        _ctx: &UnitCtx,
        _principal: &PrincipalId,
    ) -> Result<Vec<VerifiedDestination>, Refusal> {
        let named_scope = match &self.lock().named {
            Some((class @ (ROUTE_SCOPE | ROUTE_SCOPE_LOCAL), candidates)) => {
                Some((*class, candidates.clone()))
            }
            _ => None,
        };
        if let Some((class, candidates)) = named_scope {
            // The arrival's candidate list is read in place: whether it lists an entry is a walk
            // of its separated words, never a copy of them.
            let candidates = candidates.as_deref().map(String::from_utf8_lossy);
            let listed = |entry: &str| {
                candidates.as_deref().map(|c| {
                    c.split(ROUTE_SCOPE_SEPARATOR)
                        .filter(|e| !e.is_empty())
                        .any(|e| e == entry)
                })
            };
            let reachable: Vec<String> = self
                .pools
                .entries()
                .iter()
                .filter(|entry| listed(entry.as_str()).is_none_or(|l| l))
                .filter(|entry| {
                    self.child_constraints
                        .as_ref()
                        .is_none_or(|c| **entry == c.grant.target_binding)
                })
                .filter(|entry| {
                    self.facts.scope_candidate_granted(
                        self.pools,
                        self.key.as_deref(),
                        class,
                        listed(entry.as_str()).is_some_and(|l| l),
                        entry,
                    )
                })
                .cloned()
                .collect();
            let mut u = self.lock();
            match reachable.as_slice() {
                [one] if class == ROUTE_SCOPE_LOCAL => {
                    u.resolved = Some(one.clone());
                    u.scope_entry = Some(one.clone());
                }

                [one] => {
                    u.scope_entry = Some(one.clone());
                    u.named = Some(match self.pools.member_pool(one) {
                        Some(pool) => (ROUTE_POOL, Some(pool.as_bytes().to_vec())),
                        None => (ROUTE_DIRECT, Some(one.as_bytes().to_vec())),
                    });
                }
                [] => {}
                _ => u.reachable = reachable,
            }
        }

        let (named, local_entry) = {
            let u = self.lock();
            let local_entry = u
                .named
                .as_ref()
                .is_some_and(|(class, _)| *class == ROUTE_SCOPE_LOCAL)
                .then(|| u.resolved.clone())
                .flatten();
            (u.named.clone(), local_entry)
        };

        if self.facts.plane.lane_prefix().is_empty() {
            if let Some(name) = named
                .as_ref()
                .and_then(|(_, n)| n.as_deref())
                .and_then(|n| std::str::from_utf8(n).ok())
            {
                let view = DoorPoolView {
                    pools: self.pools,
                    key: self.key.as_deref(),
                    app: &self.app,
                };
                if let Err(refusal) = busbar_kernel::door::destination_guard(&view, name) {
                    self.lock().refused.1 = Some(refusal.message());
                    return Err(Refusal::new(refusal.reason()));
                }
            }
        }
        let direct = named
            .as_ref()
            .is_some_and(|(class, _)| *class == ROUTE_DIRECT);
        let mut routed = named.and_then(|(class, n)| self.pools.resolve(class, n.as_deref()));
        let entry_known = direct.then_some(routed.is_some());
        self.child_live()?;
        if let Some(c) = &self.child_constraints {
            if let Some((_, members)) = &mut routed {
                members.retain(|member| member == &c.grant.target_binding);
                if members.is_empty() {
                    return Err(Refusal::new(ReasonCode::ScopeDenied));
                }
            } else if local_entry.as_ref() != Some(&c.grant.target_binding) {
                return Err(Refusal::new(ReasonCode::ScopeDenied));
            }
        }

        let sealed: Vec<VerifiedDestination> = routed
            .iter()
            .flat_map(|(_, members)| members)
            .chain(local_entry.iter())
            .filter_map(|member| (self.lanes)(&plane_lane(self.facts.plane.lane_prefix(), member)))
            .map(|lane| VerifiedDestination::seal(trust, lane))
            .collect();
        let mut u = self.lock();
        u.routed = routed;
        u.entry_known = entry_known;
        drop(u);
        Ok(sealed)
    }

    fn approve(
        &self,
        _ctx: &UnitCtx,
        _principal: &PrincipalId,
        _destinations: &[VerifiedDestination],
    ) -> Result<busbar_contract::ScopeFacts, Refusal> {
        // One guard for the whole judgement: the unit's words are read in place, not copied out.
        let u = self.lock();
        let (class, named) = u
            .named
            .as_ref()
            .map_or((ROUTE_POOL, None), |(class, named)| {
                (*class, named.as_deref())
            });
        let counterparty = u.counterparty.as_deref();
        let selected = u.resolved.as_deref();
        let entry_known = u.entry_known;
        if class == ROUTE_SCOPE_LOCAL
            && named.is_some()
            && selected.is_some_and(|entry| {
                self.facts.secondary_scopes.get(entry).is_some_and(|kind| {
                    self.key
                        .as_ref()
                        .is_some_and(|key| !key.scope_allowed(kind, entry))
                })
            })
        {
            return Err(Refusal::new(ReasonCode::ScopeDenied));
        }

        if class == ROUTE_SCOPE_LOCAL
            && counterparty.is_some_and(|counterparty| {
                !self.pools.granted(
                    self.facts.scope_kind.as_deref(),
                    self.key.as_deref(),
                    ROUTE_DIRECT,
                    Some(counterparty),
                )
            })
        {
            return Err(Refusal::new(ReasonCode::ScopeDenied));
        }

        if class == ROUTE_SCOPE
            || class == ROUTE_SCOPE_LOCAL
            || self.pools.granted_to(
                self.facts.scope_kind.as_deref(),
                self.key.as_deref(),
                (class, named),
                counterparty,
                entry_known,
            )
        {
            Ok(busbar_contract::ScopeFacts::default())
        } else {
            Err(Refusal::new(ReasonCode::ScopeDenied))
        }
    }

    async fn prepare_admission(
        &self,
        _ctx: &UnitCtx,
        _principal: &PrincipalId,
        _destinations: &[VerifiedDestination],
    ) -> Result<(), Refusal> {
        self.child_live()?;
        // These paths consume an existing host reservation, or perform a free local
        // operation. They do not acquire a second budget admission here.
        if self.host_ticket_admission.is_some() || self.parented() {
            return Ok(());
        }
        let (Some(gov), Some(key)) = (self.app.governance.as_ref(), self.key.as_ref()) else {
            return Ok(());
        };
        let (routed, units) = {
            let unit = self.lock();
            let local = unit
                .named
                .as_ref()
                .is_some_and(|(route, _)| *route == ROUTE_LOCAL || *route == ROUTE_SCOPE_LOCAL);
            if local
                && !unit.counted
                && unit.expected.is_empty()
                && self.child_constraints.is_none()
            {
                return Ok(());
            }
            (unit.routed.clone(), self.expected_units(&unit.expected)?)
        };
        let pool = self.charged_pool(routed.as_ref().map_or("", |(label, _)| label));
        let chain = self.app.cost.plan_chain(key);
        gov.check_observation_admission_on(
            &self.app.cost,
            key,
            chain.as_ref(),
            &pool,
            self.arrived,
        )
        .await
        .map_err(|blocked| refusal_for(&blocked))?;
        // The observation check read the routed pool only; a downgrade at the charge re-admits
        // through its new pool without a second observation read, as before.
        self.lock().budget = Some(BudgetPlan { units, pool, chain });
        Ok(())
    }

    fn admit(
        &self,
        admit: &Grant<Admittance>,
        ctx: &UnitCtx,
        principal: &PrincipalId,
        _destinations: &[VerifiedDestination],
        _leases: &GroupLeaseSlip,
    ) -> Result<busbar_contract::caps::Admission, Refusal> {
        self.child_live()?;
        if self.child_constraints.is_some()
            && (self.host_ticket_admission.is_some() || self.parented())
        {
            return Err(Refusal::new(ReasonCode::Unpriced));
        }
        let (local, counted, estimated) = {
            let u = self.lock();
            let local = u
                .named
                .as_ref()
                .is_some_and(|(class, _)| *class == ROUTE_LOCAL || *class == ROUTE_SCOPE_LOCAL);
            (local, local && u.counted, !u.expected.is_empty())
        };

        let unrouted_scope = {
            let u = self.lock();
            u.named.as_ref().is_some_and(|(class, _)| {
                *class == ROUTE_SCOPE || (*class == ROUTE_SCOPE_LOCAL && u.resolved.is_none())
            })
        };
        if unrouted_scope && !matches!(admission(self.key.as_ref(), self.open), Admission::Refused)
        {
            return Err(Refusal::new(ReasonCode::NoDestination));
        }
        if matches!(admission(self.key.as_ref(), self.open), Admission::Refused) {
            return Err(Refusal::new(ReasonCode::Unauthenticated));
        }
        if !local && self.lock().routed.is_none() {
            return Err(Refusal::new(ReasonCode::NoDestination));
        }

        if let Some(holder) = &self.host_ticket_admission {
            let spent = holder
                .take()
                .ok_or_else(|| Refusal::new(ReasonCode::Replayed))?;
            let money = self
                .money
                .ok_or_else(|| Refusal::new(ReasonCode::Unpriced))?;
            let key = self
                .key
                .as_ref()
                .ok_or_else(|| Refusal::new(ReasonCode::Unauthenticated))?;
            let gov = self
                .app
                .governance
                .as_ref()
                .ok_or_else(|| Refusal::new(ReasonCode::Unpriced))?;
            let node = self
                .ticket_node
                .as_ref()
                .ok_or_else(|| Refusal::new(ReasonCode::Unpriced))?;
            let instance = self
                .ticket_instance
                .as_ref()
                .ok_or_else(|| Refusal::new(ReasonCode::Unpriced))?;
            let lane = opened_lane(self.facts.plane.lane_prefix(), self.lock().routed.as_ref())?;
            match spent.adopt(
                money,
                ctx,
                admit,
                principal,
                key,
                lane,
                Arc::clone(&self.facts.classes),
                FeeRefund::PlaneFeeUnits(Arc::clone(&self.facts.fee_units)),
                node,
                instance,
                &gov.core_store_handle()
                    .map_err(|_| Refusal::new(ReasonCode::Unpriced))?,
            ) {
                Ok(lineage) => {
                    {
                        let mut unit = self.lock();
                        unit.charged = true;
                        unit.charged_unit = Some(ctx.key);
                    }
                    *self
                        .ticket_lineage
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(lineage);
                    return Ok(busbar_kernel::door::admitted_at_zero(
                        admit,
                        principal.clone(),
                    ));
                }
                Err(returned) => {
                    let (reason, reservation) = returned.into_parts();
                    drop(reservation);
                    return Err(Refusal::new(reason));
                }
            }
        }
        #[cfg(test)]
        if let (Some(parent), Some(key)) = (self.parent_admission, self.key.as_ref()) {
            if !admit.bound_to(ctx.call) {
                return Err(Refusal::new(ReasonCode::Replayed));
            }
            if !self
                .money
                .is_some_and(|money| std::ptr::eq(money, parent.money))
            {
                return Err(Refusal::new(ReasonCode::Unpriced));
            }
            parent
                .money
                .validate_parent(&parent.token, key)
                .map_err(Refusal::new)?;
            let lane = opened_lane(self.facts.plane.lane_prefix(), self.lock().routed.as_ref())?;
            let prepared = parent.cell.accrue_child_after(principal, admit, || {
                parent.money.open_child(
                    &parent.token,
                    ctx.key,
                    lane,
                    Arc::clone(&self.facts.classes),
                    FeeRefund::PlaneFeeUnits(Arc::clone(&self.facts.fee_units)),
                )
            });
            match prepared {
                Ok(accrual) => {
                    let mut unit = self.lock();
                    unit.charged = true;
                    unit.charged_unit = Some(ctx.key);
                    return Ok(busbar_contract::caps::Admission::Accrual(accrual));
                }
                Err(busbar_contract::caps::AccrualPrepareError::Prepare(reason)) => {
                    return Err(Refusal::new(reason));
                }
                Err(busbar_contract::caps::AccrualPrepareError::Parent(_)) => {}
            }
        }
        match admission(self.key.as_ref(), self.open) {
            Admission::Refused => return Err(Refusal::new(ReasonCode::Unauthenticated)),
            Admission::Keyed
                if !local || counted || estimated || self.child_constraints.is_some() =>
            {
                if let Some(key) = self.key.clone() {
                    if let Err(refusal) = self.charge(ctx, &key) {
                        self.lock().refused.0 = refusal.retry_after_secs();
                        return Err(refusal);
                    }
                }
            }
            Admission::Keyed | Admission::Anonymous => {}
        }

        if !self.parented() {
            if let Some(cell) = self.parent {
                if let Ok(accrual) = cell.accrue_child(principal, admit) {
                    return Ok(busbar_contract::caps::Admission::Accrual(accrual));
                }
            }
        }
        Ok(busbar_kernel::door::admitted_at_zero(
            admit,
            principal.clone(),
        ))
    }

    fn take_reserved_request_lineage(
        &self,
        _ctx: &UnitCtx,
    ) -> Option<busbar_kernel::plane_driver::ReservedRequestLineage> {
        self.ticket_lineage
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }

    fn at_parent_exit(
        &self,
        ctx: &UnitCtx,
        _accrual: &busbar_contract::caps::HoldAccrual,
    ) -> Result<(), Refusal> {
        #[cfg(test)]
        if let (Some(parent), Some(key)) = (self.parent_admission, self.key.as_ref()) {
            return parent
                .money
                .validate_child(&parent.token, ctx.key, key)
                .map_err(Refusal::new);
        }
        let key = self
            .key
            .as_ref()
            .ok_or_else(|| Refusal::new(ReasonCode::Unauthenticated))?;
        let actual_grant = self.lock().grant.clone();
        if let (Some(money), Some(grant)) = (self.money, actual_grant.as_ref()) {
            if money.validate_admitted(ctx.key, key, grant).is_ok() {
                return Ok(());
            }
        }
        self.charge(ctx, key).map(|_| ())
    }

    fn meter(
        &self,
        usage: &Grant<Consumption>,
        ctx: &UnitCtx,
        _provisional: &Outcome,
        _destinations: &[VerifiedDestination],
    ) -> Result<busbar_contract::caps::Usage, Refusal> {
        // The unit's one usage fold (SP-M1): the gate refuses on it here, and the late accrual's
        // report and the settlement carry it while the counts have not moved since.
        let fold = self.money.and_then(|m| m.usage_fold(ctx.key));
        let mut lines: Vec<UsageLine> = Vec::new();
        for (class, sum) in fold.iter().flat_map(|fold| fold.by_class()) {
            if self.facts.fee_units.contains(&class) {
                continue;
            }
            let quantity = sum.ok_or_else(|| Refusal::new(ReasonCode::Unpriced))?;
            if quantity.is_zero() {
                continue;
            }
            if let Some(class) = self.facts.meter_classes.get(class as usize) {
                lines.push(UsageLine {
                    class: *class,
                    quantity,

                    source: QuantitySource::Count,
                    estimated: false,
                });
            }
        }
        busbar_contract::caps::Usage::report(usage, lines)
            .map_err(|_| Refusal::new(ReasonCode::Unpriced))
    }

    fn audit(&self, _ctx: &UnitCtx, outcome: &Outcome) -> busbar_contract::AuditFacts {
        let (op, (streamed, cut)) = {
            let u = self.lock();
            (u.op.unwrap_or(self.facts.audit_kind), u.answered)
        };
        facts(op, outcome, streamed, cut)
    }

    fn audit_refused(&self, _ctx: &UnitCtx, refusal: &Refusal) -> busbar_contract::AuditFacts {
        let op = self.lock().op.unwrap_or(self.facts.audit_kind);
        let step = refusal
            .step()
            .unwrap_or(busbar_contract::caps::StepName::Admit);
        facts(op, &Outcome::Refused(step, refusal.reason()), false, false)
    }

    fn pool_holds(&self, pool: &[u8], member: &str) -> bool {
        std::str::from_utf8(pool)
            .ok()
            .and_then(|pool| self.pools.pools().get(pool))
            .is_some_and(|members| members.iter().any(|m| m == member))
    }

    fn decoded(&self, ctx: &UnitCtx, op: OpClassId, route: u8, pool: Option<&[u8]>) {
        if let Some(money) = self.money {
            money.checkpoint_decoded(ctx.key, op);
        }
        let mut u = self.lock();
        u.op = Some(op);
        u.named = Some((route, pool.map(<[u8]>::to_vec)));
        u.entry_known = None;
    }

    fn request_span(
        &self,
        _ctx: &UnitCtx,
        decoded: &busbar_kernel::plane_driver::Decoded,
        op: OpClassId,
    ) -> Option<(tracing::Span, u64)> {
        let request_id = self.app.next_request_id();

        let span = tracing::span!(
            target: "busbar::proxy::engine",
            busbar_kernel::observability::HOTPATH_LEVEL,
            "forward",
            pool = tracing::field::Empty,
            ingress = tracing::field::Empty,
            op = %op,
            request_id = tracing::field::Empty
        );
        // A disabled span records nothing: compute none of its fields (no lock, no allocation).
        if !span.is_disabled() {
            let named = decoded.pool.as_deref().map(String::from_utf8_lossy);
            {
                // The downgrade target is read in place under the unit's lock, never copied out.
                let unit = self.lock();
                if let Some(pool) = unit.downgraded.as_deref().or(named.as_deref()) {
                    span.record("pool", tracing::field::display(pool));
                }
            }
            if let Some(ingress) = self.facts.dialects.get(decoded.dialect as usize) {
                span.record("ingress", tracing::field::display(ingress));
            }
            span.record("request_id", request_id);
        }
        Some((span, request_id))
    }

    fn expected(&self, _ctx: &UnitCtx, units: &[UnitCount]) {
        self.lock().expected = units.to_vec();
    }

    fn summary(
        &self,
        _ctx: &UnitCtx,
        dialect: Option<u32>,
    ) -> busbar_kernel::plane_driver::UnitSummary {
        let u = self.lock();
        let pool = u.downgraded.clone().or_else(|| {
            u.named
                .as_ref()
                .and_then(|(_, pool)| pool.as_deref())
                .map(|p| String::from_utf8_lossy(p).into_owned())
        });
        let governance = match (&u.downgraded, u.charged, &self.key) {
            _ if self.app.governance.is_none() => "off",
            (Some(_), _, _) => "downgraded",
            (None, true, _) => "admitted",
            (None, false, None) => "no_key",
            (None, false, Some(_)) => "not_admitted",
        };
        busbar_kernel::plane_driver::UnitSummary {
            ingress: dialect
                .and_then(|d| self.facts.dialects.get(d as usize))
                .cloned(),
            pool,
            key_id: self.key.as_ref().map(|k| k.id.clone()),
            governance,
            downgraded_to: u.downgraded.clone(),
        }
    }

    fn refused_words(&self) -> (Option<u32>, Option<String>) {
        self.lock().refused.clone()
    }

    fn attempting(&self, _ctx: &UnitCtx, dialect: u32, provider: &str) {
        let (names, providers) = &self.facts.translations;
        if let (Some(from), Some(to)) = (names.get(dialect as usize), providers.get(provider)) {
            if from != to {
                busbar_kernel::telemetry::translation(from, to);
            }
        }
    }

    fn answered(&self, _ctx: &UnitCtx, streamed: bool, cut: bool) {
        self.lock().answered = (streamed, cut);
    }

    fn usage_tap_fault(&self, _ctx: &UnitCtx, dialect: u32, reason: &'static str) {
        if let Some(protocol) = self.facts.translations.0.get(dialect as usize) {
            busbar_kernel::snapshot::usage_tap_fault(protocol, reason);
        }
    }

    fn refusal_words(&self, reason: ReasonCode) -> Option<Vec<u8>> {
        let u = self.lock();
        let scoped = u
            .named
            .as_ref()
            .is_some_and(|(class, _)| *class == ROUTE_SCOPE || *class == ROUTE_SCOPE_LOCAL);
        (reason == ReasonCode::NoDestination && scoped)
            .then(|| u.reachable.join(ROUTE_SCOPE_SEPARATOR).into_bytes())
    }

    fn counterparty(&self, _ctx: &UnitCtx, counterparty: &[u8]) {
        self.lock().counterparty = Some(counterparty.to_vec());
    }

    fn resolved(&self, _ctx: &UnitCtx) -> Option<Vec<u8>> {
        self.lock().resolved.clone().map(String::into_bytes)
    }

    fn scope_entry(&self) -> Option<Vec<u8>> {
        self.lock().scope_entry.clone().map(String::into_bytes)
    }

    fn route_flags(&self, _ctx: &UnitCtx, flags: u8) {
        let mut u = self.lock();
        u.once = flags & busbar_contract::abi::plane::ROUTE_ONCE != 0;
        u.counted = flags & busbar_contract::abi::plane::ROUTE_COUNTED != 0;
        u.stream = flags & busbar_contract::abi::plane::ROUTE_STREAM != 0;
    }

    fn affinity(&self, _ctx: &UnitCtx, hash: u64) {
        self.lock().affinity = Some(hash);
    }
}

pub(crate) struct EndpointStripped(pub(crate) Arc<dyn busbar_contract::auth_calls::OutboundAuth>);

impl busbar_contract::auth_calls::OutboundAuth for EndpointStripped {
    fn open_outbound(
        &self,
        style: &str,
        credential: &[u8],
        settings: &serde_json::Value,
    ) -> Result<u64, String> {
        let stripped = endpoint_userinfo(settings).map(|(stripped, _)| stripped);
        self.0
            .open_outbound(style, credential, stripped.as_ref().unwrap_or(settings))
    }

    fn fields_now(
        &self,
        handle: u64,
        request: &busbar_contract::auth_calls::FieldsRequest,
    ) -> Option<busbar_contract::auth_calls::Fields> {
        self.0.fields_now(handle, request)
    }

    fn fields(
        &self,
        handle: u64,
        request: busbar_contract::auth_calls::FieldsRequest,
        deadline_ns: u64,
    ) -> Box<dyn busbar_contract::auth_calls::Fielding> {
        self.0.fields(handle, request, deadline_ns)
    }

    fn ready(&self, handle: u64) -> bool {
        self.0.ready(handle)
    }
}

pub(crate) fn presenting(
    conns: crate::root::loader::dispatch::ConnTable,
    userinfo: &crate::root::userinfo::UserinfoBasic,
) -> crate::root::loader::dispatch::ConnTable {
    use crate::root::loader::dispatch::ConnTable;
    match conns {
        ConnTable::Host(inner) => {
            ConnTable::Host(crate::root::connector::admit(Arc::new(PresentingConns {
                inner: Arc::clone(inner.table()),
                userinfo: userinfo.clone(),
            })))
        }
        other => other,
    }
}

struct PresentingConns {
    inner: Arc<dyn busbar_contract::conn::DeclaredConns>,
    userinfo: crate::root::userinfo::UserinfoBasic,
}

impl busbar_contract::conn::Conns for PresentingConns {
    fn open(
        &self,
        caller: busbar_contract::conn::InstanceId,
        need: busbar_contract::conn::NeedId,
        desc: &busbar_contract::conn::OpenDesc<'_>,
    ) -> Result<busbar_contract::conn::ConnId, busbar_contract::conn::ConnError> {
        self.open_with_security(caller, need, desc, false)
    }

    fn open_with_security(
        &self,
        caller: busbar_contract::conn::InstanceId,
        need: busbar_contract::conn::NeedId,
        desc: &busbar_contract::conn::OpenDesc<'_>,
        require_secure: bool,
    ) -> Result<busbar_contract::conn::ConnId, busbar_contract::conn::ConnError> {
        let target = busbar_kernel_egress::trust::net::strip_userinfo(desc.target);
        let led = self.userinfo.leading(desc.fields);
        let fields = led.as_deref().unwrap_or(desc.fields);
        self.inner.open_with_security(
            caller,
            need,
            &busbar_contract::conn::OpenDesc {
                target: &target,
                fields,
                ..desc.clone()
            },
            require_secure,
        )
    }

    fn write(
        &self,
        caller: busbar_contract::conn::InstanceId,
        conn: busbar_contract::conn::ConnId,
        bytes: &[u8],
        end: bool,
        text: bool,
    ) -> Result<usize, busbar_contract::conn::ConnError> {
        self.inner.write(caller, conn, bytes, end, text)
    }

    fn read(
        &self,
        caller: busbar_contract::conn::InstanceId,
        conn: busbar_contract::conn::ConnId,
        ticket: busbar_contract::conn::Ticket,
        buf: &mut [u8],
    ) -> Result<busbar_contract::conn::Piece, busbar_contract::conn::ConnError> {
        self.inner.read(caller, conn, ticket, buf)
    }

    fn wait(
        &self,
        caller: busbar_contract::conn::InstanceId,
        set: &[busbar_contract::conn::ConnId],
        ticket: busbar_contract::conn::Ticket,
    ) -> Result<usize, busbar_contract::conn::ConnError> {
        self.inner.wait(caller, set, ticket)
    }

    fn facts(
        &self,
        caller: busbar_contract::conn::InstanceId,
        conn: busbar_contract::conn::ConnId,
    ) -> Result<busbar_contract::transport::ConnFacts, busbar_contract::conn::ConnError> {
        self.inner.facts(caller, conn)
    }

    fn close(
        &self,
        caller: busbar_contract::conn::InstanceId,
        conn: busbar_contract::conn::ConnId,
    ) -> Result<(), busbar_contract::conn::ConnError> {
        self.inner.close(caller, conn)
    }
}

impl busbar_contract::conn::DeclaredConns for PresentingConns {
    fn landed(
        &self,
        caller: busbar_contract::conn::InstanceId,
        conn: busbar_contract::conn::ConnId,
        ticket: busbar_contract::conn::Ticket,
    ) -> Result<(), busbar_contract::conn::ConnError> {
        self.inner.landed(caller, conn, ticket)
    }

    fn prepare_request(
        &self,
        caller: busbar_contract::conn::InstanceId,
        need: busbar_contract::conn::NeedId,
        desc: &busbar_contract::conn::OpenDesc<'_>,
        dial_timeout_ms: u64,
    ) -> Result<busbar_contract::conn::ConnId, busbar_contract::conn::ConnError> {
        let target = busbar_kernel_egress::trust::net::strip_userinfo(desc.target);
        self.inner.prepare_request(
            caller,
            need,
            &busbar_contract::conn::OpenDesc {
                target: &target,
                ..desc.clone()
            },
            dial_timeout_ms,
        )
    }

    fn commit_request(
        &self,
        caller: busbar_contract::conn::InstanceId,
        conn: busbar_contract::conn::ConnId,
        desc: &busbar_contract::conn::OpenDesc<'_>,
        require_secure: bool,
    ) -> Result<(), busbar_contract::conn::ConnError> {
        let target = busbar_kernel_egress::trust::net::strip_userinfo(desc.target);
        let led = self.userinfo.leading(desc.fields);
        let fields = led.as_deref().unwrap_or(desc.fields);
        self.inner.commit_request(
            caller,
            conn,
            &busbar_contract::conn::OpenDesc {
                target: &target,
                fields,
                ..desc.clone()
            },
            require_secure,
        )
    }

    fn open_request(
        &self,
        caller: busbar_contract::conn::InstanceId,
        need: busbar_contract::conn::NeedId,
        desc: &busbar_contract::conn::OpenDesc<'_>,
        require_secure: bool,
        dial_timeout_ms: u64,
    ) -> Result<busbar_contract::conn::ConnId, busbar_contract::conn::ConnError> {
        let target = busbar_kernel_egress::trust::net::strip_userinfo(desc.target);
        let led = self.userinfo.leading(desc.fields);
        let fields = led.as_deref().unwrap_or(desc.fields);
        self.inner.open_request(
            caller,
            need,
            &busbar_contract::conn::OpenDesc {
                target: &target,
                fields,
                ..desc.clone()
            },
            require_secure,
            dial_timeout_ms,
        )
    }

    fn declare(
        &self,
        owner: busbar_contract::conn::InstanceId,
        need: busbar_contract::conn::NeedId,
        spec: &busbar_contract::abi::mechanism::rendering::ReadNeed,
        target: Option<&str>,
        trust: Option<&str>,
    ) -> Result<(), busbar_contract::conn::ConnError> {
        self.inner.declare(owner, need, spec, target, trust)
    }

    fn declared(
        &self,
        owner: busbar_contract::conn::InstanceId,
        need: busbar_contract::conn::NeedId,
    ) -> Option<Result<(), busbar_contract::conn::ConnError>> {
        self.inner.declared(owner, need)
    }

    fn upgrade_secure(
        &self,
        caller: busbar_contract::conn::InstanceId,
        conn: busbar_contract::conn::ConnId,
        name: Option<&str>,
        trust: Option<&str>,
        verify_off: bool,
        ticket: busbar_contract::conn::Ticket,
    ) -> Result<(), busbar_contract::conn::ConnError> {
        self.inner
            .upgrade_secure(caller, conn, name, trust, verify_off, ticket)
    }

    fn framed(
        &self,
        owner: busbar_contract::conn::InstanceId,
        need: busbar_contract::conn::NeedId,
    ) -> bool {
        self.inner.framed(owner, need)
    }

    fn serves_scheme(&self, transport: &str) -> bool {
        self.inner.serves_scheme(transport)
    }

    fn declare_program(
        &self,
        owner: busbar_contract::conn::InstanceId,
        need: busbar_contract::conn::NeedId,
        spec: &busbar_contract::abi::mechanism::rendering::ReadNeed,
        program: &busbar_contract::conn::Program,
    ) -> Result<(), busbar_contract::conn::ConnError> {
        self.inner.declare_program(owner, need, spec, program)
    }

    fn cause(
        &self,
        owner: busbar_contract::conn::InstanceId,
        conn: busbar_contract::conn::ConnId,
    ) -> Option<busbar_contract::conn::ConnCause> {
        self.inner.cause(owner, conn)
    }

    fn hold_authority(&self, owner: busbar_contract::conn::InstanceId) {
        self.inner.hold_authority(owner);
    }

    fn request_head(
        &self,
        owner: busbar_contract::conn::InstanceId,
        need: busbar_contract::conn::NeedId,
        target: &str,
        timeout_ms: u64,
    ) -> Result<busbar_contract::conn::HeadDefaults, busbar_contract::conn::ConnError> {
        let target = busbar_kernel_egress::trust::net::strip_userinfo(target);
        self.inner.request_head(owner, need, &target, timeout_ms)
    }

    fn bind_auth(
        &self,
        owner: busbar_contract::conn::InstanceId,
        need: busbar_contract::conn::NeedId,
        member: &str,
        origin: &str,
        binding: busbar_contract::conn::ConnAuth,
    ) {
        self.inner.bind_auth(owner, need, member, origin, binding);
    }

    fn auth_of(
        &self,
        owner: busbar_contract::conn::InstanceId,
        need: busbar_contract::conn::NeedId,
        member: &str,
        target: &str,
    ) -> Option<busbar_contract::conn::ConnAuth> {
        self.inner.auth_of(owner, need, member, target)
    }

    fn declare_member_programs(
        &self,
        owner: busbar_contract::conn::InstanceId,
        need: busbar_contract::conn::NeedId,
        spec: &busbar_contract::abi::mechanism::rendering::ReadNeed,
        programs: &[(String, busbar_contract::conn::Program)],
    ) -> Result<(), busbar_contract::conn::ConnError> {
        self.inner
            .declare_member_programs(owner, need, spec, programs)
    }

    fn forget(&self, owner: busbar_contract::conn::InstanceId) {
        self.inner.forget(owner);
    }
}

pub(crate) struct MainLogSink(
    pub(crate) Arc<dyn crate::root::loader::dispatch::EnvelopeSink>,
    pub(crate) busbar_kernel::diagnostics::Catalogue,
);

impl MainLogSink {
    fn named(text: &str) -> (&str, Option<&str>, Option<&str>, Option<&str>) {
        let split = |t: &'_ str, name: &str| -> (usize, Option<usize>) {
            t.find(name)
                .map_or((t.len(), None), |at| (at, Some(at + name.len())))
        };
        let (end, from) = split(text, " error=");
        let error = from.map(|f| &text[f..]);
        let rest = &text[..end];
        let (end, from) = split(rest, " header=");
        let header = from.map(|f| &rest[f..]);
        let rest = &rest[..end];
        let (end, from) = split(rest, " protocol=");
        let protocol = from.map(|f| &rest[f..]);
        (&rest[..end], protocol, header, error)
    }

    fn write(&self, d: &crate::root::loader::dispatch::Diagnostic<'_>) {
        use busbar_contract::diagnostic::Severity;
        use tracing::Level;
        let text = String::from_utf8_lossy(d.text);
        let (message, protocol, header, error) = Self::named(&text);
        let code = std::str::from_utf8(d.name)
            .ok()
            .and_then(|n| n.strip_prefix("BUSBAR-"))
            .and_then(|n| n.parse::<u16>().ok())
            .and_then(|n| self.1.by_code(n));
        let level = match (code.map(|c| c.severity), d.severity) {
            (Some(Severity::BenignRecurring), _) => Level::DEBUG,
            (Some(Severity::Fatal), _) | (_, 2..) => Level::ERROR,
            (_, 1) => Level::WARN,
            _ => Level::INFO,
        };
        let diag = code.map(|c| tracing::field::display(c.banner()));
        let error = error.map(tracing::field::display);
        macro_rules! line {
            ($level:expr) => {
                tracing::event!($level, diag, protocol, header, error, "{message}")
            };
        }
        match level {
            Level::DEBUG => line!(Level::DEBUG),
            Level::INFO => line!(Level::INFO),
            Level::WARN => line!(Level::WARN),
            _ => line!(Level::ERROR),
        }
    }
}

impl crate::root::loader::dispatch::EnvelopeSink for MainLogSink {
    fn metric(&self, m: crate::root::loader::dispatch::Metric<'_>) {
        self.0.metric(m);
    }

    fn diag(&self, d: crate::root::loader::dispatch::Diagnostic<'_>) {
        use busbar_contract::abi::mechanism::call::{DIAG_LOG, DIAG_LOG_DROPPED};
        if d.id != DIAG_LOG && d.id != DIAG_LOG_DROPPED {
            self.write(&d);
        }
        self.0.diag(d);
    }

    fn dropped(&self, why: crate::root::loader::dispatch::Dropped) {
        self.0.dropped(why);
    }
}

impl PerHop {
    /// The handle a hop at `now` presents: none once what is held is past its lease or was dropped.
    /// No lock, no resolution and no report on the hop path (the refresher reports the lapse).
    fn handle_at(&self, now: std::time::Instant) -> Option<u64> {
        let held = self.held.load();
        let held = held.as_ref()?;
        (now < held.expires_at).then_some(held.handle)
    }
}

impl busbar_contract::auth_calls::PerRequestHandle for PerHop {
    fn handle_now(&self) -> Option<u64> {
        self.handle_at(busbar_core_connector::framer::instant_of(
            busbar_core_connector::framer::now_ns(),
        ))
    }
}

/// The composition root's rules that read only the resolved config: no I/O, no loaded plugin
/// state. Boot/apply (`Rules::check`) and `--validate` both run exactly this, so they agree.
pub(crate) fn offline_root_rules(cfg: &busbar_kernel::config::RootCfg) -> Result<(), Vec<String>> {
    kernel_sections(cfg).map_err(|e| vec![e])?;
    if let Some(url) = cfg.public_url.as_deref() {
        busbar_core_admin::config::validate_public_url(url, &cfg.blocked_metadata_hosts)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests/door_steps.rs"]
pub(crate) mod tests;

#[cfg(test)]
#[path = "tests/usage_fold.rs"]
mod usage_fold_tests;

#[cfg(all(test, linked_axis_transport_door, linked_section_agents))]
#[path = "tests/registration_pin.rs"]
mod registration_pin_tests;
