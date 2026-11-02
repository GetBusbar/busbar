// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use busbar_contract::abi::plane::{
    units_bill, UnitCount, ROUTE_DIRECT, ROUTE_LOCAL, ROUTE_POOL, ROUTE_SCOPE, ROUTE_SCOPE_LOCAL,
    ROUTE_SCOPE_SEPARATOR,
};
use busbar_contract::caps::{
    Admittance, Authenticated, Consumption, Dial, Grant, OpClassId, Outcome, PrincipalId,
    QuantitySource, ReasonCode, Refusal, UsageLine, VerifiedDestination,
};
use busbar_contract::records::VirtualKey;
use busbar_contract::section::{
    MODEL_PROTOCOL_KEYS, MODEL_PROVIDER_KEY, POOL_MEMBERS_KEY, POOL_MEMBER_NAME_KEY,
    POOL_MEMBER_TIER_KEY, RESERVED_MODELS_KEY, RESERVED_POOLS_KEY, RESERVED_SECTION_KEYS,
    RESERVED_WORK_KEY,
};
use busbar_contract::MeterClassId;
use busbar_kernel::config::groups::ExhaustionMode;
use busbar_kernel::governance::{AdmitGrant, LimitBlocked, PLANE_LANE_SEP};
use busbar_kernel::plane_driver::{DriverSteps, FeeRefund, PlaneMoney, UnitMoney};
use busbar_kernel::slice::GroupLeaseSlip;
use busbar_kernel::state::App;
use busbar_kernel::teller::UnitCtx;

use crate::root::linked::node::Resolve;

/// THE POOLS A DOOR PLANE'S UNITS ROUTE OVER, read off its section
/// once per generation: the section's entries (its `models` map's keys in a model-serving section,
/// else every top-level key but the reserved ones) and its
/// reserved `pools` sub-key (each named pool's member entries). An arrival names an entry name
/// (`ArriveOut::pool`); nothing here parses it, it is only looked up.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DoorPools {
    entries: Vec<String>,
    pools: BTreeMap<String, Vec<String>>,
    /// Each pool's `on_exhausted: { fallback_pool }`, where it names one.
    fallbacks: BTreeMap<String, String>,
    /// The pools whose members the plane admits each on its own grant (`member_granted`): the
    /// pool's name is no grant of its own.
    member_granted: std::collections::BTreeSet<String>,
    /// Each entry's reserved `timeout:`, in milliseconds (`busbar_contract::section::ENTRY_TIMEOUT_KEY`),
    /// a tool-server registration that writes none at the core's default: its member's attempt bound.
    timeouts: BTreeMap<String, u64>,
    /// Each pool's members' tiers, in member order (`0` where a member states none).
    tiers: BTreeMap<String, Vec<u32>>,
    /// Each pool's `breaker:` block, where its `pools:` entry states one ([`POOL_BREAKER_KEY`]):
    /// the same block, read the same way, as a top-level pool's (BUSBAR-1.6.0.md THE DESIGN
    /// §1: "Any plugin gets all functionality").
    breakers: BTreeMap<String, busbar_kernel::config::BreakerCfg>,
}

pub type Routed = (String, Vec<String>);

impl DoorPools {
    pub fn of(section: &serde_yaml::Value, declared: &str) -> Result<Self, String> {
        let Some(map) = section.as_mapping() else {
            return Ok(Self::default());
        };
        let key = |k: &serde_yaml::Value| k.as_str().map(str::to_owned);

        let models = map
            .get(RESERVED_MODELS_KEY)
            .and_then(serde_yaml::Value::as_mapping);
        let entries: Vec<String> = match models {
            Some(models) => models.keys().filter_map(key).collect(),
            None => map
                .keys()
                .filter_map(key)
                .filter(|k| {
                    k != RESERVED_POOLS_KEY
                        && k != RESERVED_WORK_KEY
                        && !RESERVED_SECTION_KEYS.contains(&k.as_str())
                })
                .collect(),
        };
        let mut pools: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut tiers: BTreeMap<String, Vec<u32>> = BTreeMap::new();
        for (name, pool) in map
            .get(RESERVED_POOLS_KEY)
            .and_then(serde_yaml::Value::as_mapping)
            .into_iter()
            .flatten()
        {
            let Some(name) = key(name) else {
                continue;
            };
            let listed = members(pool).map_err(|e| format!("pool '{name}': {e}"))?;
            pools.insert(
                name.clone(),
                listed.iter().map(|(m, _)| m.clone()).collect(),
            );
            tiers.insert(name, listed.into_iter().map(|(_, t)| t).collect());
        }
        let fallbacks = map
            .get(RESERVED_POOLS_KEY)
            .and_then(serde_yaml::Value::as_mapping)
            .map(|pools| {
                pools
                    .iter()
                    .filter_map(|(name, pool)| {
                        let fallback = pool
                            .get(ON_EXHAUSTED_KEY)?
                            .get(FALLBACK_POOL_KEY)?
                            .as_str()?;
                        Some((key(name)?, fallback.to_owned()))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let member_granted = map
            .get(RESERVED_POOLS_KEY)
            .and_then(serde_yaml::Value::as_mapping)
            .map(|pools| {
                pools
                    .iter()
                    .filter(|(_, pool)| {
                        pool.get(busbar_contract::section::POOL_MEMBER_GRANTED_KEY)
                            .and_then(serde_yaml::Value::as_bool)
                            .unwrap_or(false)
                    })
                    .filter_map(|(name, _)| key(name))
                    .collect()
            })
            .unwrap_or_default();

        let breakers = map
            .get(RESERVED_POOLS_KEY)
            .and_then(serde_yaml::Value::as_mapping)
            .map(|pools| {
                pools
                    .iter()
                    .filter_map(|(name, pool)| {
                        let block = pool.get(POOL_BREAKER_KEY)?.clone();
                        Some((key(name)?, serde_yaml::from_value(block).ok()?))
                    })
                    .collect()
            })
            .unwrap_or_default();

        let registration_default = busbar_contract::section::default_entry_timeout_ms(declared);
        let timeouts = entries
            .iter()
            .filter_map(|entry| {
                let written = models
                    .unwrap_or(map)
                    .get(entry.as_str())
                    .and_then(|e| e.get(busbar_contract::section::ENTRY_TIMEOUT_KEY))
                    .and_then(serde_yaml::Value::as_str)
                    .and_then(|t| busbar_contract::section::entry_timeout_ms(t).ok());
                let ms = match (written, models) {
                    (Some(ms), _) => ms,
                    (None, None) => registration_default?,
                    (None, Some(_)) => return None,
                };
                Some((entry.clone(), ms))
            })
            .collect();
        Ok(DoorPools {
            entries,
            pools,
            fallbacks,
            member_granted,
            timeouts,
            tiers,
            breakers,
        })
    }

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
        let name = std::str::from_utf8(named?).ok()?;
        match class {
            ROUTE_POOL => self
                .pools
                .get(name)
                .map(|members| (name.to_owned(), members.clone())),
            ROUTE_DIRECT => self
                .entries
                .iter()
                .find(|e| *e == name)
                .map(|e| (String::new(), vec![e.clone()])),
            _ => None,
        }
    }

    #[must_use]
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
    pub fn member_pool(&self, entry: &str) -> Option<&str> {
        self.pools
            .iter()
            .filter(|(name, _)| self.member_granted.contains(*name))
            .find(|(_, members)| members.iter().any(|m| m == entry))
            .map(|(name, _)| name.as_str())
    }

    #[must_use]
    pub fn fallback(&self, pool: &str) -> Option<&str> {
        self.fallbacks.get(pool).map(String::as_str)
    }
}

const ON_EXHAUSTED_KEY: &str = "on_exhausted";
const FALLBACK_POOL_KEY: &str = "fallback_pool";

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

        if class == ROUTE_DIRECT && !self.entries.iter().any(|e| e == name) {
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
    #[must_use]
    pub fn granted_to(
        &self,
        kind: Option<&str>,
        key: Option<&VirtualKey>,
        (class, named): (u8, Option<&[u8]>),
        counterparty: Option<&[u8]>,
    ) -> bool {
        if !self.granted(kind, key, class, named) {
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

fn members(pool: &serde_yaml::Value) -> Result<Vec<(String, u32)>, String> {
    let Some(list) = pool
        .get(POOL_MEMBERS_KEY)
        .and_then(serde_yaml::Value::as_sequence)
    else {
        return Ok(Vec::new());
    };
    let mut out = Vec::with_capacity(list.len());
    for m in list {
        if let Some(name) = m.as_str() {
            out.push((name.to_owned(), 0));
            continue;
        }
        let Some(name) = m
            .get(POOL_MEMBER_NAME_KEY)
            .and_then(serde_yaml::Value::as_str)
        else {
            continue;
        };
        let Some(written) = m.get(POOL_MEMBER_TIER_KEY) else {
            out.push((name.to_owned(), 0));
            continue;
        };
        let tier = written
            .as_u64()
            .and_then(|t| u32::try_from(t).ok())
            .ok_or_else(|| {
                format!("member '{name}' has tier {written:?}, which is no unsigned integer that fits u32")
            })?;
        out.push((name.to_owned(), tier));
    }
    Ok(out)
}

#[must_use]
pub fn plane_lane(plane: &str, entry: &str) -> String {
    if plane.is_empty() {
        return entry.to_string();
    }
    format!("{plane}{PLANE_LANE_SEP}{entry}")
}

#[must_use]
pub fn egress_pool(plane: &str, routed: &Routed) -> String {
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
        self.pools.pools().contains_key(name) || self.pools.entries().iter().any(|e| e == name)
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

fn exhaustion_of(app: &App, key: &VirtualKey) -> ExhaustionMode {
    let mut limits = Vec::new();
    let mut seen = Vec::new();
    let mut at = key.group.clone();
    while let Some(name) = at {
        if seen.contains(&name) {
            break;
        }
        let Some(group) = app.groups_registry.get(&name) else {
            break;
        };
        limits.extend(group.limits.iter());
        at = group.parent.clone();
        seen.push(name);
    }
    ExhaustionMode::governing(limits)
}

/// WHAT A SERVED PLANE STATES THE KERNEL SERVES ITS UNITS BY, read off its Statement tail at bind.
#[derive(Debug, Clone)]
pub struct DoorFacts {
    /// The plane's key: the card its lanes are priced on, and the qualifier of every lane it routes.
    pub plane: String,
    /// The grant kind that admits its traffic (its tail's first scope kind); `None` = it states none.
    pub scope_kind: Option<String>,
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
    /// The governance book's grant: its in-flight holds, released when the unit's steps drop.
    grant: Option<AdmitGrant>,
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

    credential: Option<busbar_contract::redacted::Secret<Vec<u8>>>,

    ticket: Option<Vec<u8>>,

    parent: Option<&'s busbar_contract::caps::HoldCell>,
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
    pub credential: Option<busbar_contract::redacted::Secret<Vec<u8>>>,
    /// The record of the ticket the auth gate spent admitting the caller (row 132); `None` when a
    /// key admitted it.
    pub ticket: Option<Vec<u8>>,
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
            parent: None,
            unit: Mutex::new(DoorUnit::default()),
        }
    }

    #[must_use]
    pub fn under(mut self, parent: &'s busbar_contract::caps::HoldCell) -> Self {
        self.parent = Some(parent);
        self
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, DoorUnit> {
        self.unit
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[must_use]
    pub fn routed(&self) -> Option<Routed> {
        self.lock().routed.clone()
    }

    #[must_use]
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
    pub fn plane(&self) -> &str {
        &self.facts.plane
    }

    pub fn route_cost(&self, lane: &str) -> busbar_contract::SignalBag {
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
    pub fn charged(&self) -> bool {
        self.lock().charged
    }

    #[must_use]
    pub fn downgraded(&self) -> Option<String> {
        self.lock().downgraded.clone()
    }

    #[must_use]
    pub fn stream_cut(&self) -> bool {
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
        let mut seen: Vec<&str> = Vec::new();
        let mut at = Some(to);
        while let Some(pool) = at {
            if seen.contains(&pool) {
                break;
            }
            if !self.pools.granted(
                self.facts.scope_kind.as_deref(),
                Some(key),
                ROUTE_POOL,
                Some(pool.as_bytes()),
            ) {
                return false;
            }
            seen.push(pool);
            at = self.pools.fallback(pool);
        }
        true
    }

    fn charged_pool(&self, label: &str) -> String {
        plane_lane(&self.facts.plane, label)
    }

    fn expected_units(&self, expected: &[UnitCount]) -> BTreeMap<String, u64> {
        let mut units = BTreeMap::new();
        for u in expected {
            if let Some(name) = self.facts.classes.get(u.class as usize) {
                let n = units.entry(name.clone()).or_insert(0u64);
                *n = n.saturating_add(u.amount);
            }
        }
        units
    }

    fn charge(&self, ctx: &UnitCtx, key: &Arc<VirtualKey>) -> Result<bool, Refusal> {
        let (Some(gov), Some(money)) = (self.app.governance.as_ref(), self.money) else {
            return Ok(false);
        };
        let (routed, expected) = {
            let u = self.lock();
            (u.routed.clone(), u.expected.clone())
        };
        let units = self.expected_units(&expected);
        let lanes_of = |routed: &Option<Routed>| -> Vec<String> {
            routed
                .iter()
                .flat_map(|(_, members)| members)
                .map(|m| plane_lane(&self.facts.plane, m))
                .collect()
        };

        let mut routed = routed;
        let mut visited: Vec<String> = Vec::new();
        let (grant, pool, lanes) = loop {
            let label = routed.as_ref().map_or("", |(label, _)| label.as_str());
            let pool = self.charged_pool(label);
            let lanes = lanes_of(&routed);
            let models: Vec<&str> = lanes.iter().map(String::as_str).collect();
            match gov.try_admit_estimated(&self.app.cost, key, &pool, self.arrived, &models, &units)
            {
                Ok(grant) => break (grant, pool, lanes),
                Err(LimitBlocked::Limit {
                    downgrade_to: Some(to),
                    ..
                }) if self.downgrade_reaches(key, &to, &visited) => {
                    routed = self.pools.resolve(ROUTE_POOL, Some(to.as_bytes()));
                    visited.push(to);
                }
                Err(blocked) => {
                    if self.facts.plane.is_empty() {
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
        money.open(
            ctx.key,
            UnitMoney {
                key: Arc::clone(key),
                cost: Arc::clone(&self.app.cost),
                pool,

                lane: lanes.first().cloned().unwrap_or_default(),
                classes: Arc::clone(&self.facts.classes),
                arrived: self.arrived,
                mode: exhaustion_of(&self.app, key),

                fee: FeeRefund::PlaneFeeUnits(Arc::clone(&self.facts.fee_units)),
                charge: grant.charge().clone(),
            },
        );
        let mut u = self.lock();
        u.grant = Some(grant);
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
            let candidates: Option<Vec<String>> = candidates.map(|c| {
                String::from_utf8_lossy(&c)
                    .split(ROUTE_SCOPE_SEPARATOR)
                    .filter(|e| !e.is_empty())
                    .map(str::to_string)
                    .collect()
            });
            let reachable: Vec<String> = self
                .pools
                .entries()
                .iter()
                .filter(|entry| candidates.as_ref().is_none_or(|c| c.contains(entry)))
                .filter(|entry| {
                    self.pools.granted(
                        self.facts.scope_kind.as_deref(),
                        self.key.as_deref(),
                        ROUTE_DIRECT,
                        Some(entry.as_bytes()),
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

        let named = self.lock().named.clone();

        if self.facts.plane.is_empty() {
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
        let routed = named.and_then(|(class, n)| self.pools.resolve(class, n.as_deref()));
        let sealed: Vec<VerifiedDestination> = routed
            .iter()
            .flat_map(|(_, members)| members)
            .filter_map(|member| (self.lanes)(&plane_lane(&self.facts.plane, member)))
            .map(|lane| VerifiedDestination::seal(trust, lane))
            .collect();
        self.lock().routed = routed;
        Ok(sealed)
    }

    fn approve(
        &self,
        _ctx: &UnitCtx,
        _principal: &PrincipalId,
        _destinations: &[VerifiedDestination],
    ) -> Result<busbar_contract::ScopeFacts, Refusal> {
        let (class, named) = self.lock().named.clone().unwrap_or((ROUTE_POOL, None));
        let counterparty = self.lock().counterparty.clone();

        if class == ROUTE_SCOPE
            || class == ROUTE_SCOPE_LOCAL
            || self.pools.granted_to(
                self.facts.scope_kind.as_deref(),
                self.key.as_deref(),
                (class, named.as_deref()),
                counterparty.as_deref(),
            )
        {
            Ok(busbar_contract::ScopeFacts::default())
        } else {
            Err(Refusal::new(ReasonCode::ScopeDenied))
        }
    }

    fn admit(
        &self,
        admit: &Grant<Admittance>,
        ctx: &UnitCtx,
        principal: &PrincipalId,
        _destinations: &[VerifiedDestination],
        _leases: &GroupLeaseSlip,
    ) -> Result<busbar_contract::caps::Admission, Refusal> {
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
        match admission(self.key.as_ref(), self.open) {
            Admission::Refused => return Err(Refusal::new(ReasonCode::Unauthenticated)),
            Admission::Keyed if !local || counted || estimated => {
                if let Some(key) = self.key.clone() {
                    if let Err(refusal) = self.charge(ctx, &key) {
                        self.lock().refused.0 = refusal.retry_after_secs();
                        return Err(refusal);
                    }
                }
            }
            Admission::Keyed | Admission::Anonymous => {}
        }

        if !local && self.lock().routed.is_none() {
            return Err(Refusal::new(ReasonCode::NoDestination));
        }

        if let Some(cell) = self.parent {
            if let Ok(accrual) = cell.accrue_child(principal, admit) {
                return Ok(busbar_contract::caps::Admission::Accrual(accrual));
            }
        }
        Ok(busbar_kernel::door::admitted_at_zero(
            admit,
            principal.clone(),
        ))
    }

    fn meter(
        &self,
        usage: &Grant<Consumption>,
        ctx: &UnitCtx,
        _provisional: &Outcome,
        _destinations: &[VerifiedDestination],
    ) -> Result<busbar_contract::caps::Usage, Refusal> {
        let last = self
            .money
            .map(|m| m.last_counts(ctx.key))
            .unwrap_or_default();
        let mut by_class: BTreeMap<u32, u64> = BTreeMap::new();
        for u in last.iter().filter(|u| units_bill(u.source)) {
            if self.facts.fee_units.contains(&u.class) {
                continue;
            }
            let n = by_class.entry(u.class).or_insert(0);
            match n.checked_add(u.amount) {
                Some(sum) => *n = sum,
                None => return Err(Refusal::new(ReasonCode::Unpriced)),
            }
        }
        let lines: Vec<UsageLine> = by_class
            .into_iter()
            .filter(|(_, quantity)| *quantity > 0)
            .filter_map(|(class, quantity)| {
                let class = *self.facts.meter_classes.get(class as usize)?;
                Some(UsageLine {
                    class,
                    quantity,

                    source: QuantitySource::Count,
                    estimated: false,
                })
            })
            .collect();
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

    fn decoded(&self, _ctx: &UnitCtx, op: OpClassId, route: u8, pool: Option<&[u8]>) {
        let mut u = self.lock();
        u.op = Some(op);
        u.named = Some((route, pool.map(<[u8]>::to_vec)));
    }

    fn request_span(
        &self,
        _ctx: &UnitCtx,
        decoded: &busbar_kernel::plane_driver::Decoded,
        op: OpClassId,
    ) -> Option<(tracing::Span, u64)> {
        let request_id = self.app.next_request_id();
        let pool = self.downgraded().or_else(|| {
            decoded
                .pool
                .as_deref()
                .map(|p| String::from_utf8_lossy(p).into_owned())
        });
        let ingress = self.facts.dialects.get(decoded.dialect as usize);

        let span = tracing::span!(
            target: "busbar::proxy::engine",
            busbar_kernel::observability::HOTPATH_LEVEL,
            "forward",
            pool = tracing::field::Empty,
            ingress = tracing::field::Empty,
            op = %op,
            request_id = tracing::field::Empty
        );
        if let Some(pool) = pool.as_deref() {
            span.record("pool", tracing::field::display(pool));
        }
        if let Some(ingress) = ingress {
            span.record("ingress", tracing::field::display(ingress));
        }
        span.record("request_id", request_id);
        Some((span, request_id))
    }

    fn expected(&self, _ctx: &UnitCtx, units: &[UnitCount]) {
        self.lock().expected = units.to_vec();
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

#[must_use]
pub fn door_facts(
    plane: &str,
    scope_kinds: &[&str],
    classes: &[&'static str],
    fee_units: &[&str],
    audit_kind: &'static str,
    keeps: Vec<busbar_kernel::plane_driver::ResponseKeep>,
) -> DoorFacts {
    let index: HashMap<&str, u32> = classes.iter().zip(0u32..).map(|(c, i)| (*c, i)).collect();
    DoorFacts {
        plane: plane.to_string(),
        scope_kind: scope_kinds.first().map(|k| (*k).to_string()),
        classes: classes.iter().map(|c| (*c).to_string()).collect(),
        route_cost: Vec::new(),
        meter_classes: classes.iter().map(|c| MeterClassId::new(c)).collect(),
        fee_units: fee_units
            .iter()
            .filter_map(|f| index.get(f).copied())
            .collect(),
        audit_kind: OpClassId::new(audit_kind),
        keeps,
        translations: (Arc::from(Vec::new()), Arc::default()),
        dialects: Arc::from(Vec::new()),
        bench_below_trip_threshold: None,
        metric_lanes: Vec::new(),
        stream_ceiling_secs: 0,
    }
}

#[must_use]
pub fn label_bound(
    plane: &str,
    pools: &DoorPools,
    vocabulary: &[String],
) -> crate::root::egress_ports::LabelBound {
    let mut bound = crate::root::egress_ports::LabelBound::new(vocabulary.iter().cloned());
    for label in pools.pools().keys() {
        let mut labels = Vec::new();
        let mut entries = Vec::new();
        let mut at = Some(label.as_str());
        while let Some(pool) = at.filter(|p| !labels.iter().any(|l: &String| l == p)) {
            labels.push(pool.to_string());
            entries.extend(pools.pools().get(pool).into_iter().flatten().cloned());
            at = pools.fallback(pool);
        }
        bound = bound.reaching(label, labels, entries);
    }
    for entry in pools.entries() {
        bound = bound.reaching(&plane_lane(plane, entry), [], [entry.clone()]);
    }
    bound
}

#[allow(clippy::too_many_arguments)]
pub fn compose_egress(
    facts: &DoorFacts,
    pools: &DoorPools,
    caller: busbar_contract::conn::InstanceId,
    conns: Arc<dyn busbar_contract::conn::PollConns>,
    routes: &BTreeMap<String, busbar_kernel::plane_driver::MemberRoute>,
    journal: Arc<dyn busbar_kernel_egress::ports::Journal>,
    clock: Arc<dyn busbar_kernel_egress::ports::Clock>,
    stream_ceiling_secs: u64,
) -> Result<busbar_kernel::plane_driver::Egress, String> {
    use busbar_kernel_egress::{Member, OnExhausted, Pool};
    let mut members: BTreeMap<String, Member> = BTreeMap::new();
    let mut sealed = HashMap::new();
    let mut names = Vec::new();
    for (entry, id) in pools.entries().iter().zip(0u64..) {
        let Some(route) = routes.get(entry) else {
            continue;
        };

        let mut route = route.clone();
        let keep_of = |need: busbar_contract::conn::NeedId| {
            facts
                .keeps
                .get(need.0 as usize)
                .cloned()
                .unwrap_or_default()
        };
        route.keep = keep_of(route.need);
        for (need, keep) in &mut route.rides {
            *keep = keep_of(*need);
        }

        for (need, base_url) in ridden(&route) {
            conns
                .anchor(caller, need, &route.provider, &base_url, &route.anchors)
                .map_err(|e| {
                    format!("member '{entry}': its trust anchors could not be sealed: {e}")
                })?;

            conns
                .seal_reach(
                    caller,
                    need,
                    &route.provider,
                    &base_url,
                    route.anchors.private_reach,
                )
                .map_err(|e| {
                    format!("member '{entry}': its private reach could not be sealed: {e}")
                })?;
        }
        let destination = busbar_contract::dest::DestinationId::new(id);
        let name = plane_lane(&facts.plane, entry);

        let mut member = Member::new(destination, name.clone(), 1);
        member.attempt_timeout_ms = pools.timeout_ms(entry);
        members.insert(entry.clone(), member);
        sealed.insert(destination, route);
        names.push((destination, name));
    }
    let mut built: HashMap<String, Pool> = HashMap::new();
    for (label, entries) in pools.pools() {
        let list = entries
            .iter()
            .enumerate()
            .map(|(index, e)| {
                let mut member = members.get(e).cloned().ok_or_else(|| {
                    format!("pool '{label}' names entry '{e}', which has no sealed route")
                })?;
                member.tier = pools.tier(label, index);
                Ok(member)
            })
            .collect::<Result<Vec<_>, String>>()?;
        let mut pool = Pool::new(label.clone(), list);
        if let Some(fallback) = pools.fallback(label) {
            pool.on_exhausted = OnExhausted::FallbackPool(fallback.to_string());
        }
        built.insert(label.clone(), pool);
    }
    for member in members.values() {
        built.insert(
            member.name.clone(),
            Pool::new(member.name.clone(), vec![member.clone()]),
        );
    }

    let cell = |pool: Option<&str>| {
        let mut cfg = busbar_kernel::store::pool_breaker_cfg(pool.and_then(|p| pools.breaker(p)));
        if let Some(bench) = facts.bench_below_trip_threshold {
            cfg.bench_below_trip_threshold = bench;
        }
        cfg
    };
    let policy = built.keys().fold(
        crate::root::adapters::BreakerPolicy::new().with_default_cell(cell(None)),
        |policy, pool| policy.with_pool(pool.as_str(), cell(Some(pool.as_str()))),
    );

    let (hard_down_cooldown_secs, max_honored_retry_after_secs) =
        busbar_kernel::config::limits::installed().map_or(
            (
                busbar_kernel::config::limits::DEFAULT_HARD_DOWN_COOLDOWN_SECS,
                busbar_kernel::config::limits::DEFAULT_MAX_HONORED_RETRY_AFTER_SECS,
            ),
            |l| (l.hard_down_cooldown_secs, l.max_honored_retry_after_secs),
        );
    let unit = busbar_kernel_breaker::BreakerUnit::new()
        .with_limits(hard_down_cooldown_secs, max_honored_retry_after_secs);
    Ok(busbar_kernel::plane_driver::Egress {
        caller,
        conns,
        breaker: busbar_kernel::plane_driver::fixed_breaker(Arc::new(
            crate::root::adapters::BreakerAdapter::new(unit, policy),
        )),
        capacity: Arc::new(crate::root::egress_ports::MemberPermits::new(Vec::new())),
        clock,
        journal,
        telemetry: Arc::new(
            crate::root::egress_ports::WalkTelemetry::new(names).bounded(label_bound(
                &facts.plane,
                pools,
                &facts.metric_lanes,
            )),
        ),
        pools: built,
        routes: sealed,
        stream_ceiling_secs,
        stated_ceiling_secs: facts.stream_ceiling_secs,
        error_body_max: busbar_kernel::config::limits::installed().map_or(
            busbar_kernel::plane_driver::DEFAULT_ERROR_BODY_MAX,
            |limits| limits.upstream_error_body_max_bytes,
        ),
    })
}

/// WHAT A DOOR PLANE IS SEALED OVER, for ONE configuration generation (spec Part 1 line 569: one
/// validated `{section: value}` object per `open`/`refresh`): the kernel-owned sections it reads
/// ([`kernel_sections`]), the providers its members are reached through ([`provider_routes`]) and
/// the model-serving pools' bounds ([`crate::root::model_egress::ModelPools`]). Projected from each
/// resolved configuration as it is built (the root's install record,
/// `busbar_kernel::preflight::RootInstall::config_projection`), and read back when that generation
/// is swapped in.
#[derive(Debug)]
pub struct DoorConfig {
    /// Candidate-owned physical handlers, constructed by its root rules before publication.
    pub listener_routes: std::sync::OnceLock<crate::root::serve::PreparedListeners>,
    /// Effective physical listener settings of this candidate, before publication.
    pub listeners: Result<crate::root::boot::ListenerNeeds, String>,
    /// Effective root binds, independent of the boot catalog used by the early projection.
    pub root_binds: Result<Vec<crate::root::loader::boot::InboundBind>, String>,
    /// The ordered configured data auth positions, resolved against this candidate's opened auths.
    pub data_chain: Vec<String>,
    /// The kernel-owned sections, and beside them every plane section the configuration carries RAW
    /// (a door plane's other owned sections among them: a config apply hands a plane its owned
    /// sections from here, as boot hands them from the document's sections).
    pub sections: BTreeMap<&'static str, serde_yaml::Value>,
    /// The providers, by name.
    pub providers: BTreeMap<String, ProviderRoute>,
    /// The model-serving pools' bounds.
    pub model_pools: crate::root::model_egress::ModelPools,
}

#[must_use]
pub fn door_config(cfg: &busbar_kernel::config::RootCfg) -> Arc<dyn std::any::Any + Send + Sync> {
    let mut sections = kernel_sections(cfg);
    for (key, value) in raw_sections(cfg) {
        sections.entry(key).or_insert(value);
    }
    Arc::new(DoorConfig {
        listener_routes: std::sync::OnceLock::new(),
        listeners: crate::root::boot::configured_listener_needs(cfg, &sections),
        root_binds: crate::root::boot::configured_root_binds(cfg),
        data_chain: cfg
            .auth
            .as_ref()
            .map(|auth| auth.chain.iter().map(|entry| entry.name.clone()).collect())
            .unwrap_or_default(),
        sections,
        providers: provider_routes(
            &cfg.providers,
            &busbar_kernel::config_validate::MetadataPosture::global(cfg),
        ),
        model_pools: crate::root::model_egress::ModelPools::of(cfg),
    })
}

pub fn listener_needs(
    cfg: &busbar_kernel::config::RootCfg,
) -> Result<crate::root::boot::ListenerNeeds, String> {
    let mut sections = kernel_sections(cfg);
    for (key, value) in raw_sections(cfg) {
        sections.entry(key).or_insert(value);
    }
    crate::root::boot::configured_listener_needs(cfg, &sections)
}

fn raw_sections(cfg: &busbar_kernel::config::RootCfg) -> BTreeMap<&'static str, serde_yaml::Value> {
    cfg.endpoint_resources
        .values()
        .filter_map(|r| r.downcast_ref::<(&'static str, serde_yaml::Value)>())
        .filter(|(_, v)| !v.is_null())
        .map(|(k, v)| (*k, v.clone()))
        .collect()
}

pub fn owned_anchor_refusal(at: &str, written: &str) -> Result<(), String> {
    busbar_core_connector::tls::client::operator_ca_config(written.as_bytes())
        .map(|_| ())
        .map_err(|_| {
            format!(
                "`{at}` is not a usable trust anchor: it must be one or more PEM certificates the \
                 TLS stack takes as a trust anchor"
            )
        })
}

pub fn owned_anchors_refusal<P: AsRef<str>>(
    paths: &[P],
    sections: &BTreeMap<&'static str, serde_yaml::Value>,
) -> Result<(), String> {
    for path in paths {
        let Some(at) = busbar_contract::section::owned_path(path.as_ref()) else {
            continue;
        };
        let mut segments = at.split('.');
        let written = segments
            .next()
            .and_then(|section| sections.get(section))
            .and_then(|v| segments.try_fold(v, |v, key| v.get(key)))
            .and_then(serde_yaml::Value::as_str)
            .filter(|t| !t.is_empty());
        if let Some(written) = written {
            owned_anchor_refusal(at, written)?;
        }
    }
    Ok(())
}

/// THE COMPOSITION ROOT'S RULES OF A CONFIGURATION (`busbar_kernel::appbuild::RootRules`): what
/// the build judges every configuration by before any part of it is built, at boot and at every
/// apply, rebuild or dry run, through the `App` each generation keeps them in. Today, the owned
/// trust anchors the composed door planes name (`owned.<section>.<key>`): each, as a
/// configuration writes it, judged by [`owned_anchor_refusal`], the rule the boot judges it by, so a
/// configuration whose anchor the boot would refuse never goes live through an apply, and the
/// running generation (its declared trust among it) is untouched. They also hold the deployment's
/// one destination guard, which hears each committed configuration's destinations through them.
#[derive(Default)]
pub struct Rules {
    listeners: std::sync::OnceLock<Arc<crate::root::serve::ListenerPlan>>,
    /// The owned trust anchors the composed door planes name, held as each plane is composed.
    owned_anchors: Mutex<Vec<&'static str>>,
    /// The declaring sections of the door planes the boot bound but did not open (their section
    /// absent from the boot configuration), held once the boot composed its planes
    /// ([`Rules::hold_unopened`]). A door plane is opened once, at boot, so a configuration that
    /// writes one of these is restart-to-apply ([`Rules::planes_awaiting_restart`]).
    unopened: Mutex<Vec<&'static str>>,
    /// The deployment's one destination guard (`root::connector::dest_judge`), told each committed
    /// configuration's destinations ([`Rules::hearing`]). `None`: no guard hears a commit.
    guard: Option<Arc<dyn busbar_kernel::host_services::DestJudge>>,
    /// The discovered plane doors the boot's configuration did not use, so the boot never loaded
    /// them (Law 7), held from the boot plan ([`Rules::hold_unloaded`]). A running process cannot
    /// take a first section of one: an apply or reload that writes one is refused
    /// ([`unloaded_plane_refusal`]).
    unloaded: Mutex<Vec<crate::root::loader::boot::Candidate>>,
}

impl std::fmt::Debug for Rules {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rules")
            .field("owned_anchors", &self.owned_anchors)
            .field("unopened", &self.unopened)
            .field("guard", &self.guard.is_some())
            .finish()
    }
}

impl Rules {
    pub fn hold_listeners(
        &self,
        listeners: Arc<crate::root::serve::ListenerPlan>,
    ) -> Result<(), String> {
        self.listeners
            .set(listeners)
            .map_err(|_| "listener topology was already installed".into())
    }

    #[must_use]
    pub fn hearing(guard: Arc<dyn busbar_kernel::host_services::DestJudge>) -> Self {
        Self {
            guard: Some(guard),
            ..Self::default()
        }
    }

    pub fn hold_owned_anchors(&self, paths: &[&'static str]) {
        let mut held = self
            .owned_anchors
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for path in paths
            .iter()
            .filter(|p| busbar_contract::section::owned_path(p).is_some())
        {
            if !held.contains(path) {
                held.push(path);
            }
        }
    }

    pub fn hold_unloaded(&self, candidates: Vec<crate::root::loader::boot::Candidate>) {
        self.unloaded
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend(candidates);
    }

    pub fn hold_unopened(&self, sections: impl IntoIterator<Item = &'static str>) {
        let mut held = self
            .unopened
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for section in sections {
            if !held.contains(&section) {
                held.push(section);
            }
        }
    }
}

pub(crate) fn writes_plane(section: &str, cfg: &busbar_kernel::config::RootCfg) -> bool {
    cfg.plane_sections.contains(section)
}

#[must_use]
pub fn unloaded_doors() -> Vec<crate::root::loader::boot::Candidate> {
    let bound = crate::root::boot::door_planes();
    crate::root::boot::DOOR_CANDIDATES
        .get()
        .map_or(&[][..], Vec::as_slice)
        .iter()
        .filter(|c| c.kind == busbar_contract::abi::mechanism::KindCode::Plane)
        .filter(|c| !bound.iter().any(|(instance, _)| *instance == c.name))
        .cloned()
        .collect()
}

#[must_use]
pub fn unloaded_plane_refusal(
    unloaded: &[crate::root::loader::boot::Candidate],
    keys: &[&str],
) -> Option<String> {
    let uses = crate::root::loader::boot::Uses {
        roots: keys.iter().map(|k| (*k).to_string()).collect(),
        ..Default::default()
    };
    unloaded.iter().find_map(|c| {
        crate::root::loader::boot::plane_use(&uses, c).map(|section| {
            format!(
                "`{section}:` is the section of the `{plane}` plane, which this process did not \
                 load because its configuration did not use it at start; a first `{section}:` \
                 cannot take effect on a running process, so the change was refused and nothing \
                 was changed: write it in the config file and restart.",
                plane = c.name
            )
        })
    })
}

impl busbar_kernel::appbuild::RootRules for Rules {
    fn check_built(&self, app: &App) -> Result<(), String> {
        match self.listeners.get() {
            Some(listeners) => listeners.check(app),
            None => Ok(()),
        }
    }

    fn mounted_plugin_paths(&self, app: &App) -> Option<std::collections::HashSet<String>> {
        self.listeners.get()?.mounted_plugin_paths(app)
    }
    fn unloaded_plane_refusal(&self, keys: &[&str]) -> Option<String> {
        unloaded_plane_refusal(
            &self
                .unloaded
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            keys,
        )
    }

    fn planes_awaiting_restart(&self, cfg: &busbar_kernel::config::RootCfg) -> Vec<&'static str> {
        let mut out: Vec<&'static str> = self
            .unopened
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .copied()
            .filter(|section| writes_plane(section, cfg))
            .collect();
        out.sort_unstable();
        out
    }

    fn check(&self, cfg: &busbar_kernel::config::RootCfg) -> Result<(), String> {
        let anchors = self
            .owned_anchors
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if anchors.is_empty() {
            return Ok(());
        }
        owned_anchors_refusal(&anchors, &raw_sections(cfg))
    }

    fn destinations_applied(&self, destinations: &busbar_kernel::config::Destinations) {
        if let Some(guard) = &self.guard {
            guard.destinations_applied(destinations);
        }
    }
}

#[must_use]
pub fn kernel_sections(
    cfg: &busbar_kernel::config::RootCfg,
) -> BTreeMap<&'static str, serde_yaml::Value> {
    use serde_json::{json, Map, Value};
    fn opt(m: &mut Map<String, Value>, key: &str, v: Option<Value>) {
        if let Some(v) = v {
            m.insert(key.to_string(), v);
        }
    }
    let mut out = BTreeMap::new();
    let mut providers = Map::new();
    for (name, p) in &cfg.providers {
        let mut m = p.table.clone();
        opt(&mut m, "path", p.path.as_ref().map(|v| json!(v)));
        opt(&mut m, "path_base", p.path_base.as_ref().map(|v| json!(v)));
        opt(
            &mut m,
            "auth",
            p.auth.as_ref().map(style_word).map(|v| json!(v)),
        );
        providers.insert(name.clone(), Value::Object(m));
    }
    let mut models = Map::new();
    for (name, model) in &cfg.models {
        let mut m = Map::new();
        m.insert(MODEL_PROVIDER_KEY.into(), json!(model.provider));
        opt(
            &mut m,
            "upstream_model",
            model.upstream_model.as_ref().map(|v| json!(v)),
        );
        opt(
            &mut m,
            "default_max_tokens",
            model.default_max_tokens.map(|v| json!(v)),
        );
        opt(&mut m, "reasoning", model.reasoning.map(|v| json!(v)));
        opt(
            &mut m,
            "prompt_caching",
            model.prompt_caching.map(|v| json!(v)),
        );

        opt(
            &mut m,
            MODEL_PROTOCOL_KEYS[0],
            model.protocol.as_ref().map(|v| json!(v)),
        );
        models.insert(name.clone(), Value::Object(m));
    }
    let mut pools = Map::new();
    for (name, pool) in &cfg.pools {
        let members: Vec<Value> = pool
            .members
            .iter()
            .map(|member| {
                let mut m = Map::new();
                m.insert("model".into(), json!(member.model));
                opt(&mut m, "reasoning", member.reasoning.map(|v| json!(v)));
                opt(&mut m, "context_max", member.context_max.map(|v| json!(v)));
                Value::Object(m)
            })
            .collect();
        let mut p = Map::new();
        p.insert(POOL_MEMBERS_KEY.into(), Value::Array(members));
        if let Some(busbar_kernel::config::pools::OnExhaustedCfg::FallbackPool(fallback)) =
            &pool.on_exhausted
        {
            p.insert(
                ON_EXHAUSTED_KEY.into(),
                json!({ FALLBACK_POOL_KEY: fallback }),
            );
        }

        if let Some(header) = pool.affinity.as_ref().and_then(|a| a.header_name.as_ref()) {
            p.insert("affinity".into(), json!({ "header_name": header }));
        }
        pools.insert(name.clone(), Value::Object(p));
    }

    let limits = json!({
        "default_max_tokens": cfg.limits.default_max_tokens,
        "request_body_max_bytes": cfg.limits.request_body_max_bytes,
        "datagram_line_memory_bytes": cfg.limits.datagram_line_memory_bytes,
        "reasoning_effort_budgets": {
            "minimal": cfg.limits.reasoning_effort_budgets.minimal,
            "low": cfg.limits.reasoning_effort_budgets.low,
            "medium": cfg.limits.reasoning_effort_budgets.medium,
            "high": cfg.limits.reasoning_effort_budgets.high,
        },
    });
    let yaml = |v: Value| serde_yaml::to_value(v).unwrap_or(serde_yaml::Value::Null);
    if !providers.is_empty() {
        out.insert(
            busbar_contract::plugin::Kind::Transport.root(),
            yaml(Value::Object(providers)),
        );
    }

    let required = |key: &'static str| {
        busbar_kernel::plane_driver::registry::plane_decls()
            .iter()
            .any(|d| d.required_config_sections.contains(&key))
    };
    if !models.is_empty() || !pools.is_empty() || required(RESERVED_MODELS_KEY) {
        out.insert(RESERVED_MODELS_KEY, yaml(Value::Object(models)));
        out.insert(RESERVED_POOLS_KEY, yaml(Value::Object(pools)));
    }
    out.insert("limits", yaml(limits));
    out
}

/// ONE `providers:` ENTRY as a door plane's member reaches it (THE DESIGN §6 step 2; #50, #51): the
/// `base_url` it dials, its default `protocol` and `error_map` (the dialect fields its plane is handed
/// at open), its credential reference, the `auth:` style it states (`None` = its plane's dialect
/// default) and the parameters that style is opened with.
#[derive(Debug, Clone)]
pub struct ProviderRoute {
    /// `base_url`, as the operator (or the catalog) spelled it, less any `user:pass@`: 1.5.5 dialled,
    /// sent and signed the host after it (v1.5.5 `crates/busbar/src/proxy/egress.rs:18`; row 74, F25),
    /// so the member's route, its sealed reach, its binding and every dial read that host alone.
    pub base_url: String,
    /// The basic credential that userinfo spelled, read at configuration time and held by the root:
    /// the member's binding is led by it as 1.5.5 sent it ([`crate::root::userinfo::lead_with`]);
    /// the kernel holds the binding's handle, never these bytes.
    pub userinfo: Option<crate::root::userinfo::UserinfoBasic>,
    /// The default wire protocol (#51).
    pub protocol: String,
    /// The `error_map`, catalog-merged; empty = none stated.
    pub error_map: BTreeMap<String, String>,
    /// `api_key`, a reference; resolved once, at the seal.
    pub credential: busbar_contract::secret_ref::SecretRef,
    /// `auth:`, the style it overrides its plane's dialect default with.
    pub style: Option<String>,
    /// The style's parameters (`token_url`, `scope`, `subject`, where stated).
    pub params: StyleParams,
    /// The metadata posture its credential's own token endpoint is judged under at the seal
    /// (`token_uri`, [`StyleParams::token_uri`]).
    pub metadata: busbar_kernel::config_validate::MetadataPosture,
}

/// THE PARAMETERS A PROVIDER'S `auth:` STYLE IS OPENED WITH, typed: the three keys a provider states
/// (`token_url`, `scope`, `subject`), each present only where the operator wrote it, and the one its
/// credential states (`token_uri`, a `jwt-bearer` service account's token endpoint), filled at the
/// seal once the credential resolves. The JSON object the auth plugin's `open_outbound` reads is
/// built from them at the call, never carried as a bag.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StyleParams {
    /// `token_url`, where stated.
    pub token_url: Option<String>,
    /// `token_uri`, the service-account token endpoint: the target
    /// of the serving plugin's `settings.token_uri` need, subject
    /// to the auth-mint endpoint destination policy.
    pub token_uri: Option<String>,
    /// `scope`, where stated.
    pub scope: Option<String>,
    /// `subject`, where stated.
    pub subject: Option<String>,
}

impl StyleParams {
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        let mut object = serde_json::Map::new();
        for (key, value) in [
            ("token_url", &self.token_url),
            ("token_uri", &self.token_uri),
            ("scope", &self.scope),
            ("subject", &self.subject),
        ] {
            if let Some(v) = value {
                object.insert(key.to_string(), serde_json::Value::String(v.clone()));
            }
        }
        serde_json::Value::Object(object)
    }
}

fn style_word(auth: &busbar_kernel::config::ProviderAuth) -> &str {
    auth.as_str()
}

#[must_use]
pub fn declared_styles() -> Vec<busbar_contract::auth_calls::DeclaredStyle> {
    use crate::root::loader::dispatch::kinds::auth::{rendered_facts, stated_facts};
    let linked = crate::LINKED
        .auths
        .iter()
        .filter_map(|(_, _, door)| stated_facts(*door).ok())
        .flat_map(|facts| facts.styles);
    let dropped = crate::root::boot::dropped_registry()
        .map_or(&[][..], |r| r.loadable())
        .iter()
        .filter(|r| r.manifest.kind == "auth")
        .filter_map(|r| r.manifest.stated_rendering().ok().flatten())
        .filter_map(|stated| rendered_facts(&stated).ok())
        .flat_map(|facts| facts.styles);
    busbar_contract::auth_calls::listed_styles(linked.chain(dropped).map(|s| {
        busbar_contract::auth_calls::DeclaredStyle {
            name: s.name,
            flags: s.flags,
        }
    }))
}

struct RouteFacts<'a> {
    provider: &'a busbar_kernel::config::ResolvedProvider,
    protocol: String,
    error_map: BTreeMap<String, String>,
}

impl<'a> RouteFacts<'a> {
    fn of(provider: &'a busbar_kernel::config::ResolvedProvider) -> Self {
        Self {
            provider,
            protocol: provider.dialect().to_string(),
            error_map: provider
                .error_map()
                .map(|(code, class)| (code.to_string(), class.to_string()))
                .collect(),
        }
    }
}

impl std::ops::Deref for RouteFacts<'_> {
    type Target = busbar_kernel::config::ResolvedProvider;
    fn deref(&self) -> &Self::Target {
        self.provider
    }
}

#[must_use]
pub fn provider_routes(
    providers: &HashMap<String, busbar_kernel::config::ResolvedProvider>,
    security: &busbar_kernel::config_validate::MetadataPosture,
) -> BTreeMap<String, ProviderRoute> {
    providers
        .iter()
        .map(|(name, p)| (name, RouteFacts::of(p)))
        .map(|(name, p)| {
            (
                name.clone(),
                ProviderRoute {
                    base_url: busbar_kernel_egress::trust::net::strip_userinfo(&p.base_url)
                        .into_owned(),
                    userinfo: crate::root::userinfo::UserinfoBasic::of(&p.base_url),
                    protocol: p.protocol.clone(),
                    error_map: p
                        .error_map
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect(),
                    credential: p.api_key.clone(),
                    style: p.auth.as_ref().map(|a| style_word(a).to_string()),
                    params: StyleParams {
                        token_url: p.token_url.clone(),
                        token_uri: None,
                        scope: p.scope.clone(),
                        subject: p.subject.clone(),
                    },
                    metadata: security.for_provider(&p),
                },
            )
        })
        .collect()
}

#[must_use]
pub fn dialect_facts(
    section: &serde_yaml::Value,
    providers: &BTreeMap<String, ProviderRoute>,
) -> Vec<busbar_contract::plane_calls::DialectFacts> {
    busbar_contract::plane_calls::dialect_facts(section, |name| {
        providers
            .get(name)
            .map(|p| (p.protocol.clone(), p.error_map.clone()))
    })
}

type Serving = (
    Arc<dyn busbar_contract::auth_calls::OutboundAuth>,
    crate::root::loader::dispatch::kinds::auth::OutboundStyle,
);

pub struct OutboundAuths {
    dispatcher: Arc<crate::root::loader::dispatch::Dispatcher>,
    linked: Vec<busbar_kernel::preflight::LinkedAuth>,
    dropped: Option<&'static crate::root::loader::PluginRegistry>,
    conns: crate::root::loader::dispatch::ConnTable,

    catalogue: busbar_kernel::diagnostics::Catalogue,

    linked_facts: std::sync::OnceLock<Vec<AuthRowFacts>>,

    dropped_facts: std::sync::OnceLock<Vec<AuthRowFacts>>,

    opened: crate::root::loader::open_once::OpenOnce<
        String,
        crate::root::loader::dispatch::auth_outbound::OutboundInstance,
    >,

    #[cfg(test)]
    bound: Mutex<Vec<String>>,
}

struct AuthRowFacts {
    name: String,
    door: AuthRowDoor,
    styles: Vec<crate::root::loader::dispatch::kinds::auth::OutboundStyle>,
    per_binding: bool,
}

/// Where an auth row's door is: the build's linked row, or the plugins directory's loadable row,
/// by index.
#[derive(Clone, Copy)]
enum AuthRowDoor {
    Linked(usize),
    Dropped(usize),
}

impl std::fmt::Debug for OutboundAuths {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboundAuths")
            .field(
                "linked",
                &self.linked.iter().map(|(n, _, _)| *n).collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

impl OutboundAuths {
    #[must_use]
    pub fn new(
        dispatcher: Arc<crate::root::loader::dispatch::Dispatcher>,
        linked: &[busbar_kernel::preflight::LinkedAuth],
        dropped: Option<&'static crate::root::loader::PluginRegistry>,
        conns: crate::root::loader::dispatch::ConnTable,
        catalogue: busbar_kernel::diagnostics::Catalogue,
    ) -> Self {
        Self {
            dispatcher,
            linked: linked.to_vec(),
            dropped,
            conns,
            catalogue,
            linked_facts: std::sync::OnceLock::new(),
            dropped_facts: std::sync::OnceLock::new(),
            opened: crate::root::loader::open_once::OpenOnce::new(),
            #[cfg(test)]
            bound: Mutex::default(),
        }
    }

    fn bind_with(
        &self,
        name: &str,
        conns: crate::root::loader::dispatch::ConnTable,
    ) -> crate::root::loader::dispatch::Bind {
        use crate::root::loader::dispatch::{EnvelopeSink, NoSink};
        let sink: Arc<dyn EnvelopeSink> = crate::root::boot::plugin_logs()
            .sink(
                name,
                busbar_contract::abi::mechanism::KindCode::Auth,
                Arc::new(NoSink),
            )
            .map_or_else(
                |_| Arc::new(NoSink) as Arc<dyn EnvelopeSink>,
                |s| Arc::new(s) as Arc<dyn EnvelopeSink>,
            );
        let sink: Arc<dyn EnvelopeSink> = Arc::new(MainLogSink(sink, self.catalogue));
        crate::root::loader::dispatch::Bind {
            instance: Arc::from(name),
            max_inflight_cap: 64,
            sink,
            dispatcher: self.dispatcher.adopter(),
            conns,
        }
    }

    fn load(
        &self,
        name: &str,
        door: AuthRowDoor,
    ) -> Option<
        crate::root::loader::dispatch::Plugin<crate::root::loader::dispatch::kinds::auth::Auth>,
    > {
        self.load_with(name, door, self.conns.clone())
    }

    fn load_with(
        &self,
        name: &str,
        door: AuthRowDoor,
        conns: crate::root::loader::dispatch::ConnTable,
    ) -> Option<
        crate::root::loader::dispatch::Plugin<crate::root::loader::dispatch::kinds::auth::Auth>,
    > {
        use crate::root::loader::dispatch::kinds::auth::Auth;
        use crate::root::loader::dispatch::{load_dropped_bytes, load_linked, LinkedRow};
        #[cfg(test)]
        self.bound
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(name.to_string());
        match door {
            AuthRowDoor::Linked(i) => {
                let (_, _, door) = self.linked.get(i)?;
                LinkedRow::of(*door)
                    .and_then(|row| load_linked::<Auth>(&row, self.bind_with(name, conns)))
                    .ok()
            }
            AuthRowDoor::Dropped(i) => {
                let row = self.dropped?.loadable().get(i)?;
                let Ok(Some(stated)) = row.manifest.stated_rendering() else {
                    return None;
                };
                load_dropped_bytes::<Auth>(
                    &row.lib_bytes,
                    name,
                    &stated,
                    self.bind_with(name, conns),
                )
                .ok()
            }
        }
    }

    #[must_use]
    pub fn style_flags(&self, style: &str) -> Option<u32> {
        self.stating(style)
            .next()
            .and_then(|row| row.styles.iter().find(|s| s.name == style))
            .map(|s| s.flags)
    }

    fn stating<'a>(&'a self, style: &'a str) -> impl Iterator<Item = &'a AuthRowFacts> + 'a {
        self.linked_facts()
            .iter()
            .chain(std::iter::once_with(move || self.dropped_facts()).flatten())
            .filter(move |row| row.styles.iter().any(|s| s.name == style))
    }

    fn linked_facts(&self) -> &[AuthRowFacts] {
        use crate::root::loader::dispatch::kinds::auth::stated_facts;
        use crate::root::loader::dispatch::LinkedRow;
        self.linked_facts.get_or_init(|| {
            self.linked
                .iter()
                .enumerate()
                .filter_map(|(i, (name, _, door))| {
                    let styles = stated_facts(*door).ok()?.styles;
                    let per_binding = LinkedRow::of(*door)
                        .ok()
                        .and_then(|row| {
                            busbar_contract::abi::mechanism::rendering::read(&row.statement).ok()
                        })
                        .is_some_and(|r| r.needs.iter().any(|n| !n.target_from.is_empty()));
                    Some(AuthRowFacts {
                        name: (*name).to_string(),
                        door: AuthRowDoor::Linked(i),
                        styles,
                        per_binding,
                    })
                })
                .collect()
        })
    }

    fn dropped_facts(&self) -> &[AuthRowFacts] {
        use crate::root::loader::dispatch::kinds::auth::rendered_facts;
        self.dropped_facts.get_or_init(|| {
            self.dropped
                .map_or(&[][..], |r| r.loadable())
                .iter()
                .enumerate()
                .filter(|(_, r)| r.manifest.kind == "auth")
                .filter_map(|(i, r)| {
                    let stated = r.manifest.stated_rendering().ok().flatten()?;
                    let styles = rendered_facts(&stated).ok()?.styles;
                    let per_binding = busbar_contract::abi::mechanism::rendering::read(&stated)
                        .is_ok_and(|r| r.needs.iter().any(|n| !n.target_from.is_empty()));
                    Some(AuthRowFacts {
                        name: r.manifest.name.clone(),
                        door: AuthRowDoor::Dropped(i),
                        styles,
                        per_binding,
                    })
                })
                .collect()
        })
    }

    pub fn serving(
        &self,
        style: &str,
        settings: &serde_json::Value,
    ) -> Result<Option<Serving>, String> {
        use crate::root::loader::dispatch::auth_outbound::OutboundInstance;

        let endpoint = endpoint_userinfo(settings);
        let (stated, userinfo) = match &endpoint {
            Some((stripped, userinfo)) => (stripped, userinfo.clone()),
            None => (settings, None),
        };
        for row in self.stating(style) {
            let Some(decl) = row.styles.iter().find(|s| s.name == style).cloned() else {
                continue;
            };
            let open_with = if row.per_binding {
                serde_json::to_vec(stated).map_err(|e| e.to_string())?
            } else {
                b"{}".to_vec()
            };

            let key = if row.per_binding {
                let written = serde_json::to_vec(settings).map_err(|e| e.to_string())?;
                let presenting = userinfo
                    .as_ref()
                    .and_then(|u| u.leading(&[]))
                    .and_then(|led| led.first().map(|(_, value)| value.to_vec()))
                    .map(|value| String::from_utf8_lossy(&value).into_owned())
                    .unwrap_or_default();
                format!(
                    "{}\0{}\0{presenting}",
                    row.name,
                    String::from_utf8_lossy(&written)
                )
            } else {
                row.name.clone()
            };
            let instance = match self.opened.get(&key) {
                Some(instance) => instance,
                None => {
                    let loaded = match &userinfo {
                        Some(userinfo) if row.per_binding => self.load_with(
                            &row.name,
                            row.door,
                            presenting(self.conns.clone(), userinfo),
                        ),
                        _ => self.load(&row.name, row.door),
                    };
                    let Some(plugin) = loaded else {
                        continue;
                    };
                    let (instance, installed) = self.opened.get_or_open(&key, || {
                        OutboundInstance::open_with(
                            plugin,
                            Arc::clone(&self.dispatcher),
                            0,
                            &open_with,
                        )
                    })?;

                    if installed {
                        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                            runtime.spawn(Arc::clone(&instance).ticks());
                        }
                    }
                    instance
                }
            };
            let auth = instance as Arc<dyn busbar_contract::auth_calls::OutboundAuth>;
            let auth = if endpoint.is_some() {
                Arc::new(EndpointStripped(auth))
                    as Arc<dyn busbar_contract::auth_calls::OutboundAuth>
            } else {
                auth
            };
            return Ok(Some((auth, decl)));
        }
        Ok(None)
    }
}

const TOKEN_ENDPOINT_SETTINGS: [&str; 2] = ["token_url", "token_uri"];

fn endpoint_userinfo(
    settings: &serde_json::Value,
) -> Option<(
    serde_json::Value,
    Option<crate::root::userinfo::UserinfoBasic>,
)> {
    let mut stripped_settings: Option<serde_json::Value> = None;
    let mut userinfo = None;
    for key in TOKEN_ENDPOINT_SETTINGS {
        let Some(written) = settings.get(key).and_then(serde_json::Value::as_str) else {
            continue;
        };
        let std::borrow::Cow::Owned(stripped) =
            busbar_kernel_egress::trust::net::strip_userinfo(written)
        else {
            continue;
        };
        userinfo = userinfo.or_else(|| crate::root::userinfo::UserinfoBasic::of(written));
        stripped_settings.get_or_insert_with(|| settings.clone())[key] =
            serde_json::Value::String(stripped);
    }
    stripped_settings.map(|stripped| (stripped, userinfo))
}

struct EndpointStripped(Arc<dyn busbar_contract::auth_calls::OutboundAuth>);

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

fn presenting(
    conns: crate::root::loader::dispatch::ConnTable,
    userinfo: &crate::root::userinfo::UserinfoBasic,
) -> crate::root::loader::dispatch::ConnTable {
    use crate::root::loader::dispatch::ConnTable;
    match conns {
        ConnTable::Host(inner) => ConnTable::Host(Arc::new(PresentingConns {
            inner,
            userinfo: userinfo.clone(),
        })),
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
    ) -> busbar_contract::conn::HeadDefaults {
        let target = busbar_kernel_egress::trust::net::strip_userinfo(target);
        self.inner.request_head(owner, need, &target)
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

impl OutboundAuths {
    pub fn check(
        &self,
        style: &str,
        credential: &[u8],
        settings: &serde_json::Value,
    ) -> Result<Vec<String>, String> {
        use crate::root::loader::dispatch::auth_outbound::OutboundInstance;
        use crate::root::loader::dispatch::ConnTable;
        for row in self.stating(style) {
            let Some(plugin) = self.load_with(&row.name, row.door, ConnTable::Probe) else {
                continue;
            };
            let bytes = serde_json::to_vec(settings).map_err(|e| e.to_string())?;
            let instance =
                OutboundInstance::open_with(plugin, Arc::clone(&self.dispatcher), 0, &bytes)?;
            return Ok(
                match instance.open_outbound_raw(style, credential, settings) {
                    Ok(_) => Vec::new(),
                    Err((_, why)) => why
                        .lines()
                        .filter_map(|l| l.strip_prefix("credential: "))
                        .map(str::to_string)
                        .collect(),
                },
            );
        }
        Ok(Vec::new())
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

pub fn process_auths() -> Arc<OutboundAuths> {
    static AUTHS: std::sync::OnceLock<Arc<OutboundAuths>> = std::sync::OnceLock::new();
    Arc::clone(AUTHS.get_or_init(|| {
        Arc::new(OutboundAuths::new(
            crate::root::dispatch::dispatcher(),
            crate::LINKED.auths,
            crate::root::boot::dropped_registry(),
            crate::root::loader::dispatch::ConnTable::Host(
                Arc::clone(crate::root::connector::the())
                    as Arc<dyn busbar_contract::conn::DeclaredConns>,
            ),
            crate::root::linked::catalogue(),
        ))
    }))
}

pub struct DoorReach<'a> {
    pub providers: &'a BTreeMap<String, ProviderRoute>,

    pub secrets: Arc<dyn busbar_contract::secret::SecretResolve>,

    pub auths: Arc<OutboundAuths>,

    pub conns: Arc<dyn busbar_contract::conn::PollConns>,

    pub stream_ceiling_secs: u64,

    pub catalog: Option<&'a std::collections::HashMap<String, busbar_contract::config::ModelCfg>>,

    pub models: Option<&'a crate::root::model_egress::ModelServing>,

    pub upgrades: Vec<&'static str>,
}

impl std::fmt::Debug for DoorReach<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DoorReach")
            .field("provider_names", &self.providers.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

fn member_entry<'s>(section: &'s serde_yaml::Value, entry: &str) -> Option<&'s serde_yaml::Value> {
    section.get(RESERVED_MODELS_KEY)?.get(entry)
}

fn entry_text<'s>(entry: &'s serde_yaml::Value, key: &str) -> Option<&'s str> {
    entry.get(key).and_then(serde_yaml::Value::as_str)
}

fn origin_of(url: &str) -> &str {
    let after = url.find("://").map_or(0, |at| at + 3);
    url[after..].find('/').map_or(url, |at| &url[..after + at])
}

const PASSTHROUGH: &str = "passthrough";

const PASSTHROUGH_STYLE: &str = "bearer";

const TOKEN_EXCHANGE_STYLE: &str = "oauth-token-exchange";

fn token_exchange_binding(
    entry: &str,
    registration: &serde_yaml::Value,
    reach: &DoorReach<'_>,
    scope: &busbar_contract::config_time::ConfigScope,
) -> Result<Option<busbar_kernel::plane_driver::AuthBinding>, String> {
    use busbar_contract::section::{
        AUDIENCE_KEY, DEFAULT_SUBJECT_TOKEN_TYPE, SUBJECT_TOKEN_KEY, SUBJECT_TOKEN_TYPE_KEY,
        TOKEN_EXCHANGE_KEY, TOKEN_URL_KEY,
    };
    let Some(block) = registration.get(TOKEN_EXCHANGE_KEY) else {
        return Ok(None);
    };
    let subject: busbar_contract::secret_ref::SecretRef = block
        .get(SUBJECT_TOKEN_KEY)
        .cloned()
        .ok_or_else(|| format!("member '{entry}': its token exchange states no subject token"))
        .and_then(|v| {
            serde_yaml::from_value(v)
                .map_err(|e| format!("member '{entry}': its subject token reference: {e}"))
        })?;
    let credential = reach
        .secrets
        .resolve_at_config(&subject, scope)
        .map_err(|e| {
            format!("member '{entry}': busbar's own subject token for it cannot resolve: {e}")
        })?;
    let mut settings = serde_json::Map::new();
    for (key, value) in [
        ("token_url", entry_text(block, TOKEN_URL_KEY)),
        (
            "subject_token_type",
            Some(entry_text(block, SUBJECT_TOKEN_TYPE_KEY).unwrap_or(DEFAULT_SUBJECT_TOKEN_TYPE)),
        ),
        ("resource", entry_text(registration, AUDIENCE_KEY)),
    ] {
        if let Some(v) = value {
            settings.insert(key.to_string(), serde_json::Value::String(v.to_string()));
        }
    }
    let settings = serde_json::Value::Object(settings);
    let (auth, decl) = reach
        .auths
        .serving(TOKEN_EXCHANGE_STYLE, &settings)?
        .ok_or_else(|| {
            format!(
                "member '{entry}': no linked or dropped-in auth plugin serves the style \
                 '{TOKEN_EXCHANGE_STYLE}' a token-exchange registration is bound under"
            )
        })?;
    let handle = auth
        .open_outbound(
            TOKEN_EXCHANGE_STYLE,
            credential.expose(&busbar_kernel::seal::lend()),
            &settings,
        )
        .map_err(|e| format!("member '{entry}' {e}"))?;
    Ok(Some(busbar_kernel::plane_driver::AuthBinding {
        auth,
        handle,
        style_flags: decl.flags,
        points: busbar_contract::abi::auth::AuthPoints(decl.points),
        passthrough: false,
        per_request: None,
    }))
}

fn upstream_credential_binding(
    member_name: &str,
    registration: &serde_yaml::Value,
    reach: &DoorReach<'_>,
    scope: &busbar_contract::config_time::ConfigScope,
) -> Result<Option<busbar_kernel::plane_driver::AuthBinding>, String> {
    Ok(
        upstream_credential(member_name, registration, reach, scope)?.map(|(binding, per)| {
            refresher::keep(&per);
            binding
        }),
    )
}

fn upstream_credential(
    member_name: &str,
    registration: &serde_yaml::Value,
    reach: &DoorReach<'_>,
    scope: &busbar_contract::config_time::ConfigScope,
) -> Result<Option<(busbar_kernel::plane_driver::AuthBinding, Arc<PerHop>)>, String> {
    use busbar_contract::section::{
        CREDENTIAL_LEASE_TTL_KEY, CREDENTIAL_PLACEMENT_KEY, CREDENTIAL_SECRET_KEY,
        PLACEMENT_BEARER, PLACEMENT_HEADER_KEY, UPSTREAM_CREDENTIAL_KEY,
    };

    const BEARER_STYLE: &str = "bearer";

    const HEADER_STYLE: &str = "api-key";
    let Some(block) = registration.get(UPSTREAM_CREDENTIAL_KEY) else {
        return Ok(None);
    };
    let secret: busbar_contract::secret_ref::SecretRef = block
        .get(CREDENTIAL_SECRET_KEY)
        .cloned()
        .ok_or_else(|| {
            format!(
                "member '{member_name}': its `{UPSTREAM_CREDENTIAL_KEY}` states no \
                 `{CREDENTIAL_SECRET_KEY}`"
            )
        })
        .and_then(|v| {
            serde_yaml::from_value(v).map_err(|_| {
                format!(
                    "member '{member_name}': its \
                     `{UPSTREAM_CREDENTIAL_KEY}.{CREDENTIAL_SECRET_KEY}` is not a secret \
                     reference (the value is not echoed): use {{ env: <VAR> }}, \
                     {{ file: <path> }} or {{ module: <secret-module>, settings: {{…}} }}"
                )
            })
        })?;
    let (style, header) = match block.get(CREDENTIAL_PLACEMENT_KEY) {
        None => (BEARER_STYLE, None),
        Some(p) if p.as_str() == Some(PLACEMENT_BEARER) => (BEARER_STYLE, None),
        Some(p) => match p
            .get(PLACEMENT_HEADER_KEY)
            .and_then(serde_yaml::Value::as_str)
        {
            Some(header) if !header.is_empty() => (HEADER_STYLE, Some(header.to_string())),
            _ => {
                return Err(format!(
                    "member '{member_name}': its upstream credential's placement is neither \
                     `{PLACEMENT_BEARER}` nor `{{{PLACEMENT_HEADER_KEY}: <name>}}`"
                ))
            }
        },
    };

    let minted = std::time::Instant::now();
    let lease = block
        .get(CREDENTIAL_LEASE_TTL_KEY)
        .and_then(serde_yaml::Value::as_u64)
        .filter(|ms| *ms > 0)
        .map(std::time::Duration::from_millis)
        .filter(|lease| minted.checked_add(*lease).is_some())
        .ok_or_else(|| {
            format!(
                "member '{member_name}': its \
                 `{UPSTREAM_CREDENTIAL_KEY}.{CREDENTIAL_LEASE_TTL_KEY}` is not a lease in \
                 milliseconds greater than zero"
            )
        })?;
    let settings = placement_settings(header.as_deref());

    let credential = reach
        .secrets
        .resolve_string_at_config(&secret, scope)
        .map_err(|e| {
            format!(
                "member '{member_name}': busbar's own upstream credential for it cannot \
                 resolve: {e}"
            )
        })?
        .into_bytes();
    let (auth, decl) = reach.auths.serving(style, &settings)?.ok_or_else(|| {
        format!(
            "member '{member_name}': no linked or dropped-in auth plugin serves the style \
             '{style}' its upstream credential is presented under"
        )
    })?;

    let seal = busbar_kernel::seal::lend();
    let handle = auth
        .open_outbound(style, credential.expose(&seal), &settings)
        .map_err(|e| format!("member '{member_name}' {e}"))?;

    let per = Arc::new(PerHop {
        secret,
        secrets: Arc::clone(&reach.secrets),
        auth: Arc::clone(&auth),
        style,
        header,
        lease,
        held: arc_swap::ArcSwapOption::from_pointee(Held {
            digest: busbar_contract::abi::sdk::digest::sha256(credential.expose(&seal)),
            handle,
            expires_at: minted + lease,
        }),
        refreshing: Mutex::new(()),
        lapsed: std::sync::atomic::AtomicBool::new(false),
    });
    drop(credential);
    Ok(Some((
        busbar_kernel::plane_driver::AuthBinding {
            auth,
            handle,
            style_flags: decl.flags,
            points: busbar_contract::abi::auth::AuthPoints(decl.points),
            passthrough: false,
            per_request: Some(
                Arc::clone(&per) as Arc<dyn busbar_contract::auth_calls::PerRequestHandle>
            ),
        },
        per,
    )))
}

fn placement_settings(header: Option<&str>) -> serde_json::Value {
    header.map_or_else(
        || serde_json::json!({}),
        |name| serde_json::json!({ busbar_contract::section::PLACEMENT_HEADER_KEY: name }),
    )
}

struct Held {
    digest: [u8; 32],
    handle: u64,
    expires_at: std::time::Instant,
}

fn renew_every(lease: std::time::Duration) -> std::time::Duration {
    (lease / 2).max(std::time::Duration::from_millis(1))
}

struct PerHop {
    secret: busbar_contract::secret_ref::SecretRef,
    secrets: Arc<dyn busbar_contract::secret::SecretResolve>,
    auth: Arc<dyn busbar_contract::auth_calls::OutboundAuth>,
    style: &'static str,
    header: Option<String>,

    lease: std::time::Duration,
    held: arc_swap::ArcSwapOption<Held>,

    refreshing: Mutex<()>,

    lapsed: std::sync::atomic::AtomicBool,
}

impl PerHop {
    fn refresh(&self, scope: &busbar_contract::config_time::ConfigScope) {
        let _one = self
            .refreshing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let expires_at = std::time::Instant::now() + self.lease;
        let Ok(value) = self.secrets.resolve_string_at_config(&self.secret, scope) else {
            self.held.store(None);
            return;
        };
        let value = value.into_bytes();

        let seal = busbar_kernel::seal::lend();
        let digest = busbar_contract::abi::sdk::digest::sha256(value.expose(&seal));
        let unchanged = self.held.load().as_ref().and_then(|held| {
            busbar_contract::redacted::constant_time_eq(&held.digest, &digest)
                .then_some(held.handle)
        });
        if let Some(handle) = unchanged {
            self.held.store(Some(Arc::new(Held {
                digest,
                handle,
                expires_at,
            })));
            self.lapsed
                .store(false, std::sync::atomic::Ordering::Relaxed);
            return;
        }
        let opened = self.auth.open_outbound(
            self.style,
            value.expose(&seal),
            &placement_settings(self.header.as_deref()),
        );
        drop(value);
        self.held.store(opened.ok().map(|handle| {
            Arc::new(Held {
                digest,
                handle,
                expires_at,
            })
        }));
        self.lapsed
            .store(false, std::sync::atomic::Ordering::Relaxed);
    }
}

impl std::fmt::Debug for PerHop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let handle = self.held.load().as_ref().map(|held| held.handle);
        f.debug_struct("PerHop")
            .field("secret", &"<redacted; refreshed once per lease>")
            .field("style", &self.style)
            .field("carried_in", &self.header)
            .field("lease", &self.lease)
            .field("handle", &handle)
            .finish_non_exhaustive()
    }
}

impl PerHop {
    fn handle_at(&self, now: std::time::Instant) -> Option<u64> {
        let held = self.held.load();
        let held = held.as_ref()?;
        if now < held.expires_at {
            return Some(held.handle);
        }
        if !self.lapsed.swap(true, std::sync::atomic::Ordering::Relaxed) {
            tracing::warn!(
                style = self.style,
                header = self.header.as_deref(),
                lease_ms = u64::try_from(self.lease.as_millis()).unwrap_or(u64::MAX),
                "an upstream credential's lease ran out before a refresh renewed it: each hop on \
                 it is refused (credential_unavailable) until one does"
            );
        }
        None
    }
}

impl busbar_contract::auth_calls::PerRequestHandle for PerHop {
    fn handle_now(&self) -> Option<u64> {
        self.handle_at(std::time::Instant::now())
    }
}

mod refresher {
    use super::PerHop;
    use std::sync::{Arc, Condvar, Mutex, Once, Weak};
    use std::time::Instant;

    struct Kept {
        per: Weak<PerHop>,
        due: Instant,
    }

    struct Book {
        kept: Mutex<Vec<Kept>>,
        woken: Condvar,
    }

    static BOOK: Book = Book {
        kept: Mutex::new(Vec::new()),
        woken: Condvar::new(),
    };

    fn kept_book() -> &'static Book {
        static STARTED: Once = Once::new();
        STARTED.call_once(|| {
            std::thread::Builder::new()
                .name("busbar-cred-refresh".into())
                .spawn(|| run(&BOOK))
                .unwrap_or_else(|e| {
                    eprintln!("busbar: the credential refresher did not start: {e}");
                    std::process::exit(2);
                });
        });
        &BOOK
    }

    pub(super) fn keep(per: &Arc<PerHop>) {
        let book = kept_book();
        book.kept
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(Kept {
                per: Arc::downgrade(per),
                due: Instant::now() + super::renew_every(per.lease),
            });
        book.woken.notify_one();
    }

    fn run(book: &'static Book) {
        let mut kept = book
            .kept
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            let now = Instant::now();
            kept.retain(|k| k.per.strong_count() > 0);
            let mut due = Vec::new();
            for k in kept.iter_mut().filter(|k| k.due <= now) {
                if let Some(per) = k.per.upgrade() {
                    k.due = now + super::renew_every(per.lease);
                    due.push(per);
                }
            }
            if !due.is_empty() {
                drop(kept);

                let scope = busbar_contract::config_time::ConfigScope::config_time();
                for per in due {
                    per.refresh(&scope);
                }
                kept = book
                    .kept
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                continue;
            }
            let next = kept.iter().map(|k| k.due).min();
            kept = match next {
                Some(at) => {
                    book.woken
                        .wait_timeout(kept, at.saturating_duration_since(now))
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .0
                }
                None => book
                    .woken
                    .wait(kept)
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
            };
        }
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn refresh_all() {
        let live: Vec<Arc<PerHop>> = kept_book()
            .kept
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter_map(|k| k.per.upgrade())
            .collect();
        let scope = busbar_contract::config_time::ConfigScope::config_time();
        for per in live {
            per.refresh(&scope);
        }
    }
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn refresh_credentials() {
    refresher::refresh_all();
}

pub fn bind_member_fetches(
    served: &crate::root::loader::dispatch::kinds::plane::ServedFacts,
    routes: &BTreeMap<String, busbar_kernel::plane_driver::MemberRoute>,
    instance: busbar_contract::conn::InstanceId,
    table: &dyn busbar_contract::conn::DeclaredConns,
    units: &Arc<busbar_kernel::host_units::UnitRecords>,
) {
    let targeted = member_target_needs(served);
    for (member, route) in routes {
        let Some(binding) = &route.auth else {
            continue;
        };

        for (need, base_url) in ridden(route) {
            if !targeted.iter().any(|(n, _)| *n == need) {
                continue;
            }
            table.bind_auth(
                instance,
                need,
                member,
                busbar_contract::conn::origin_of(&base_url),
                busbar_contract::conn::ConnAuth {
                    auth: Arc::clone(&binding.auth),
                    handle: binding.handle,
                    style_flags: binding.style_flags,
                    points: binding.points,
                    passthrough: binding.passthrough,
                    per_request: binding.per_request.clone(),
                    lender: Some(
                        Arc::clone(units) as Arc<dyn busbar_contract::conn::LendCredential>
                    ),
                },
            );
        }
    }
}

fn member_target_needs(
    served: &crate::root::loader::dispatch::kinds::plane::ServedFacts,
) -> Vec<(busbar_contract::conn::NeedId, &'static str)> {
    served
        .need_targets
        .iter()
        .copied()
        .enumerate()
        .filter_map(|(at, path)| {
            let key = busbar_contract::section::member_target(path)?;
            Some((busbar_contract::conn::NeedId(u32::try_from(at).ok()?), key))
        })
        .collect()
}

fn ridden(
    route: &busbar_kernel::plane_driver::MemberRoute,
) -> Vec<(busbar_contract::conn::NeedId, String)> {
    std::iter::once(route.need)
        .chain(route.rides.iter().map(|(need, _)| *need))
        .filter_map(|need| {
            let ride = route.ride(need.0.checked_add(1)?)?;
            Some((ride.need, ride.base_url.to_string()))
        })
        .collect()
}

pub fn member_routes(
    section: &serde_yaml::Value,
    pools: &DoorPools,
    served: &crate::root::loader::dispatch::kinds::plane::ServedFacts,
    reach: &DoorReach<'_>,
    scope: &busbar_contract::config_time::ConfigScope,
) -> Result<BTreeMap<String, busbar_kernel::plane_driver::MemberRoute>, String> {
    use busbar_contract::abi::mechanism::rendering::{ReadBlob, ReadNeed};
    use busbar_kernel::plane_driver::{resolve_member_needs, AuthBinding, MemberAuth, MemberRoute};
    struct Resolved<'p> {
        entry: String,
        name: String,
        provider: &'p ProviderRoute,
        style: String,

        params: &'static [u8],
    }
    let mut resolved = Vec::new();
    let mut registered = BTreeMap::new();

    let member_targets = member_target_needs(served);
    let member_target = member_targets.first().copied();

    let member_program = served
        .need_targets
        .iter()
        .position(|path| busbar_contract::section::member_program(path))
        .and_then(|at| u32::try_from(at).ok())
        .map(busbar_contract::conn::NeedId);
    let mut programs = BTreeMap::new();
    for entry in pools.entries() {
        let Some(member) = member_entry(section, entry) else {
            let registration = section.get(entry.as_str());
            if let Some((need, key)) = member_target {
                if let Some((registration, target)) = registration
                    .and_then(|r| entry_text(r, key).filter(|t| !t.is_empty()).map(|t| (r, t)))
                {
                    let anchors =
                        registration_anchors(entry, registration, need, served, &*reach.secrets)?;
                    let base_url = origin_of(target).to_string();

                    let mut rides = Vec::new();
                    let mut spelled = Vec::new();
                    for (other, key) in member_targets.iter().skip(1) {
                        let Some(at) = entry_text(registration, key).filter(|t| !t.is_empty())
                        else {
                            continue;
                        };
                        rides.push(*other);
                        if origin_of(at) != base_url {
                            spelled.push((*other, origin_of(at).to_string()));
                        }
                    }
                    registered.insert(entry.clone(), (need, base_url, anchors, rides, spelled));
                    continue;
                }
            }

            if let Some(need) = member_program {
                if registration
                    .and_then(|r| entry_text(r, busbar_contract::conn::PROGRAM_KEYS[0]))
                    .is_some()
                {
                    programs.insert(entry.clone(), need);
                }
            }
            continue;
        };
        let name = entry_text(member, MODEL_PROVIDER_KEY)
            .ok_or_else(|| format!("member '{entry}' names no provider"))?;
        let provider = reach.providers.get(name).ok_or_else(|| {
            format!("member '{entry}' names provider '{name}', which is not configured")
        })?;
        let dialect = MODEL_PROTOCOL_KEYS
            .iter()
            .find_map(|k| entry_text(member, k))
            .unwrap_or(&provider.protocol);
        let default_of = |dialect: &str| {
            let at = served.dialects.iter().position(|d| *d == dialect)?;
            let at = u32::try_from(at).ok()?;
            served
                .dialect_auth
                .iter()
                .find(|(d, _, _)| *d == at)
                .map(|(_, style, params)| ((*style).to_string(), *params))
        };

        let default = default_of(dialect).or_else(|| default_of(&provider.protocol));

        let (style, params) = match (&provider.style, default) {
            (Some(style), _) => (Some(style.clone()), &[][..]),
            (None, Some((style, params))) => (Some(style), params),
            (None, None) => (None, &[][..]),
        };
        let style = style.ok_or_else(|| {
            format!(
                "member '{entry}': provider '{name}' states no `auth:` and its plane declares no \
                 default style for the dialect '{dialect}'"
            )
        })?;
        resolved.push(Resolved {
            entry: entry.clone(),
            name: name.to_string(),
            provider,
            style,
            params,
        });
    }
    let needs: Vec<ReadNeed> = served
        .need_auths
        .iter()
        .zip(served.need_transports.iter().chain(std::iter::repeat(&"")))
        .map(|((direction, auth), transport)| ReadNeed {
            direction: *direction,
            egress_class: 0,
            transport: (*transport).to_string(),
            auth: (*auth).to_string(),
            target_from: String::new(),
            trust_from: String::new(),
            details: ReadBlob {
                fmt: 0,
                flags: 0,
                bytes: Vec::new(),
            },
            timeout_ms: 0,

            keep_mode: busbar_contract::abi::host::conn::connector::KEEP_NAMED,
            keep_response_headers: Vec::new(),
            deny_response_headers: Vec::new(),
        })
        .collect();
    let members: Vec<MemberAuth<'_>> = resolved
        .iter()
        .map(|r| MemberAuth {
            member: &r.entry,
            auth: &r.style,
        })
        .collect();
    let dialled = resolve_member_needs(&needs, &members).map_err(|e| e.to_string())?;
    let mut routes = BTreeMap::new();

    let section_default = section
        .get(busbar_contract::section::UPSTREAM_CREDENTIALS_KEY)
        .and_then(serde_yaml::Value::as_str);
    for (entry, (need, base_url, anchors, rides, spelled)) in registered {
        let mode = section
            .get(entry.as_str())
            .and_then(|r| entry_text(r, busbar_contract::section::UPSTREAM_CREDENTIALS_KEY))
            .or(section_default);
        let auth = if mode == Some(PASSTHROUGH) {
            let (auth, decl) = reach
                .auths
                .serving(PASSTHROUGH_STYLE, &serde_json::json!({}))?
                .ok_or_else(|| {
                    format!(
                        "member '{entry}': no linked or dropped-in auth plugin serves the style \
                         '{PASSTHROUGH_STYLE}' a passthrough registration presents the caller's \
                         credential under"
                    )
                })?;
            let handle = auth
                .open_outbound(PASSTHROUGH_STYLE, &[], &serde_json::json!({}))
                .map_err(|e| format!("member '{entry}' {e}"))?;
            Some(AuthBinding {
                auth,
                handle,
                style_flags: decl.flags,
                points: busbar_contract::abi::auth::AuthPoints(decl.points),
                passthrough: true,
                per_request: None,
            })
        } else {
            match section.get(entry.as_str()) {
                Some(registration) => {
                    match token_exchange_binding(&entry, registration, reach, scope)? {
                        Some(binding) => Some(binding),
                        None => upstream_credential_binding(&entry, registration, reach, scope)?,
                    }
                }
                None => None,
            }
        };
        routes.insert(
            entry.clone(),
            MemberRoute {
                rides: rides
                    .into_iter()
                    .map(|n| (n, busbar_kernel::plane_driver::ResponseKeep::default()))
                    .collect(),
                need,
                base_url,
                auth,
                provider: entry,
                keep: busbar_kernel::plane_driver::ResponseKeep::default(),
                anchors,
                spelled,
            },
        );
    }

    for (entry, need) in programs {
        routes.insert(
            entry.clone(),
            MemberRoute {
                rides: Vec::new(),
                need,
                base_url: entry.clone(),
                auth: None,
                provider: entry,
                keep: busbar_kernel::plane_driver::ResponseKeep::default(),
                anchors: busbar_contract::transport::trust::Anchors::default(),
                spelled: Vec::new(),
            },
        );
    }
    for r in resolved {
        let credential = if r.provider.credential.is_none() {
            busbar_kernel::config::secret::Held::default()
        } else {
            reach
                .secrets
                .resolve_at_config(&r.provider.credential, scope)
                .map_err(|e| format!("provider '{}' credential: {e}", r.name))?
        };

        let from_credential = reach.auths.style_flags(&r.style).is_some_and(|flags| {
            flags & busbar_contract::abi::auth::STYLE_ENDPOINT_FROM_CREDENTIAL != 0
        });
        let seal = busbar_kernel::seal::lend();
        let credential = if from_credential {
            busbar_contract::redacted::Secret::new(
                busbar_kernel::config_validate::service_account_json(
                    credential.expose(&seal).clone(),
                    |file| {
                        reach
                            .secrets
                            .resolve_at_config(file, scope)
                            .map(|held| held.expose(&seal).clone())
                    },
                )
                .map_err(|e| format!("provider '{}' ({} auth): {e}", r.name, r.style))?,
            )
        } else {
            credential
        };
        let credential = credential.expose(&seal);
        let settings =
            sealed_params(&r.name, &r.style, from_credential, r.provider, credential)?.to_json();
        let (auth, decl) = reach.auths.serving(&r.style, &settings)?.ok_or_else(|| {
            format!(
                "member '{}': no linked or dropped-in auth plugin serves the style '{}'",
                r.entry, r.style
            )
        })?;
        let settings = sealed_settings(r.params, &r.provider.base_url, &settings)
            .map_err(|e| format!("member '{}': {e}", r.entry))?;
        let handle = auth
            .open_outbound(&r.style, credential, &settings)
            .map_err(|e| format!("provider '{}' {e}", r.name))?;

        let bound = dialled
            .get(&r.entry)
            .filter(|b| !b.is_empty())
            .ok_or_else(|| format!("member '{}' dials no need", r.entry))?;
        let need = bound[0];
        let rides = bound[1..]
            .iter()
            .map(|n| (*n, busbar_kernel::plane_driver::ResponseKeep::default()))
            .collect();

        let spelled = bound
            .iter()
            .filter_map(|n| {
                let transport = served.need_transports.get(n.0 as usize)?;
                let url = spelled_for(&r.provider.base_url, transport, &reach.upgrades)?;
                Some((*n, url))
            })
            .collect();
        routes.insert(
            r.entry,
            MemberRoute {
                need,
                base_url: r.provider.base_url.clone(),

                auth: Some(AuthBinding {
                    auth: crate::root::userinfo::lead_with(auth, r.provider.userinfo.clone()),
                    handle,
                    style_flags: decl.flags,
                    points: busbar_contract::abi::auth::AuthPoints(decl.points),
                    passthrough: false,
                    per_request: None,
                }),
                provider: r.name,
                keep: busbar_kernel::plane_driver::ResponseKeep::default(),
                rides,
                anchors: busbar_contract::transport::trust::Anchors::default(),
                spelled,
            },
        );
    }
    Ok(routes)
}

pub fn sealed_settings(
    params: &[u8],
    base_url: &str,
    provider: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    if params.is_empty() {
        return Ok(provider.clone());
    }
    let serde_json::Value::Object(mut sealed) = serde_json::from_slice(params)
        .map_err(|e| format!("its dialect's auth parameters are not JSON: {e}"))?
    else {
        return Err("its dialect's auth parameters are not a JSON object".to_string());
    };
    let mut unread: Vec<(String, serde_json::Value)> = Vec::new();
    for (key, value) in &mut sealed {
        let Some(directive) = value.get("host_label_after") else {
            continue;
        };
        let labels: Vec<&str> = directive
            .as_array()
            .map(|a| a.iter().filter_map(serde_json::Value::as_str).collect())
            .unwrap_or_default();
        let default = value
            .get("default")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("its dialect's auth parameter `{key}` names no default"))?
            .to_string();
        let resolved = match host_label(base_url_host(base_url), &labels) {
            Some(label) => label.to_string(),
            None => {
                if let Some(words) = value.get("unread").filter(|w| w.is_string()) {
                    unread.push((format!("{key}_unread"), words.clone()));
                }
                default
            }
        };
        *value = serde_json::Value::String(resolved);
    }
    sealed.extend(unread);
    if let serde_json::Value::Object(own) = provider {
        for (key, value) in own {
            sealed.insert(key.clone(), value.clone());
        }
    }
    Ok(serde_json::Value::Object(sealed))
}

fn base_url_host(base_url: &str) -> &str {
    busbar_contract::net::url_authority(base_url)
        .host_port
        .split(':')
        .next()
        .unwrap_or("")
}

fn host_label<'h>(host: &'h str, after: &[&str]) -> Option<&'h str> {
    let shaped = |label: &str| {
        let parts: Vec<&str> = label.split('-').collect();
        let Some((last, leading)) = parts.split_last() else {
            return false;
        };
        parts.len() >= 3
            && parts.iter().all(|p| !p.is_empty())
            && last.bytes().all(|b| b.is_ascii_digit())
            && leading
                .iter()
                .all(|p| p.bytes().all(|b| b.is_ascii_alphabetic()))
    };
    let labels: Vec<&str> = host.split('.').collect();
    labels.iter().enumerate().find_map(|(i, label)| {
        if !after.contains(label) {
            return None;
        }
        labels.get(i + 1).copied().filter(|next| shaped(next))
    })
}

fn sealed_params(
    name: &str,
    style: &str,
    from_credential: bool,
    provider: &ProviderRoute,
    credential: &[u8],
) -> Result<StyleParams, String> {
    let mut params = provider.params.clone();
    if !from_credential || credential.is_empty() {
        return Ok(params);
    }
    let Ok(text) = std::str::from_utf8(credential) else {
        return Ok(params);
    };
    let Ok(token_uri) = busbar_kernel::config_validate::service_account_token_uri(text) else {
        return Ok(params);
    };
    busbar_kernel::config_validate::vet_token_uri(&token_uri, &provider.metadata)
        .map_err(|e| format!("provider '{name}' ({style} auth): {e}"))?;
    params.token_uri = Some(token_uri);
    Ok(params)
}

#[must_use]
pub fn spelled_for(base_url: &str, transport: &str, upgrades: &[&str]) -> Option<String> {
    if !upgrades.contains(&transport) {
        return None;
    }
    if let Some(rest) = base_url.strip_prefix("https://") {
        Some(format!("{transport}s://{rest}"))
    } else {
        base_url
            .strip_prefix("http://")
            .map(|rest| format!("{transport}://{rest}"))
    }
}

fn registration_anchors(
    entry: &str,
    registration: &serde_yaml::Value,
    need: busbar_contract::conn::NeedId,
    served: &crate::root::loader::dispatch::kinds::plane::ServedFacts,
    secrets: &dyn busbar_contract::secret::SecretResolve,
) -> Result<busbar_contract::transport::trust::Anchors, String> {
    let at = format!("`{}.{entry}`", served.section);
    let pin = busbar_kernel::trust::section::parse_entry(&at, registration, &served.trust_keys)?
        .pin
        .filter(|p| p.peer_key)
        .and_then(|p| p.key)
        .map(|written| {
            busbar_contract::transport::trust::canonical_key_pin(&written)
                .map_err(|_| peer_key_pin_refusal(&at, &served.trust_keys))
        })
        .transpose()?;

    let private_reach =
        busbar_kernel::trust::section::private_reach(registration, &served.trust_keys);
    let identity_at = served
        .need_trust
        .get(need.0 as usize)
        .and_then(|path| busbar_contract::section::member_target(path));
    let client_identity = match identity_at
        .and_then(|key| Some((key, registration.get(key).filter(|v| !v.is_null())?)))
    {
        None => None,
        Some((key, identity)) => {
            let reference = |half: &str| {
                identity
                    .get(half)
                    .cloned()
                    .ok_or_else(|| format!("member '{entry}': `{key}.{half}:` is required"))
                    .and_then(|v| {
                        serde_yaml::from_value::<busbar_contract::secret_ref::SecretRef>(v)
                            .map_err(|e| format!("member '{entry}': `{key}.{half}:` {e}"))
                    })
            };
            let (cert, private) = (reference("cert")?, reference("key")?);
            Some(
                busbar_core_connector::tls::client_identity(secrets, &cert, &private)
                    .map_err(|e| format!("member '{entry}': `{key}`: {e}"))?,
            )
        }
    };
    Ok(busbar_contract::transport::trust::Anchors {
        key_pin: pin,
        client_identity,
        private_reach,
    })
}

fn peer_key_pin_refusal(at: &str, keys: &[busbar_contract::plane::TrustKeyDecl]) -> String {
    let k = keys
        .iter()
        .find(|k| k.role == busbar_contract::plane::TrustRole::Pin)
        .map_or("pin", |k| k.key);
    format!(
        "{at}: `{k}.key:` is not a key pin. Write `sha256/<base64>`: the standard, padded base64 \
         of the 32-byte SHA-256 digest of the far end's certificate SubjectPublicKeyInfo (the \
         plain `<base64>` of the same digest is also accepted)."
    )
}

#[cfg(test)]
#[path = "tests/door_steps.rs"]
pub(crate) mod tests;

#[cfg(all(test, linked_axis_transport_door, linked_section_agents))]
#[path = "tests/registration_pin.rs"]
mod registration_pin_tests;
