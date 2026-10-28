// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE KERNEL STEPS OF A UNIT SERVED THROUGH A PLANE'S DOOR (SERVE-WIRE step 33, the serving slice;
//! `BUSBAR-1.6.0.md` Part 3 §12 "One unit, step by step", THE DESIGN §7): the steps the kernel
//! answers around the plane's own seats (decode, route and encode are the plane driver's), one
//! [`DoorSteps`] per unit. Generic over the plane's tail: it names no plane.
//!
//! | step | here |
//! |---|---|
//! | arrival | proceeds: the data listener's gates ran before the data door |
//! | authenticate | the auth gate's verdict (the unit's principal); a unit with no key on a claim that takes a credential is refused (ARCHITECT P3 (a)) |
//! | verify | the route the plane's `arrive` named, resolved against its section ([`DoorPools`], ARCHITECT Q-SW6/Q-FL3), a `ROUTE_SCOPE` unit to the one entry the principal's grant reaches among the plane's candidates (Q-DEL-A2A-SELECT, -SCOPE-TRUST); each member sealed under its (plane key, entry); a `ROUTE_SCOPE_LOCAL` unit resolved the same way and sealed nothing, the plane told its one entry |
//! | approve | the caller's grant of the plane's scope kind over the route as named, then its fallback pool |
//! | admit | a unit its plane answers itself (`ROUTE_LOCAL`, `ROUTE_SCOPE_LOCAL` once resolved) is admitted with no walk and nothing held or charged, unless the plane counts it as an admitted call (`ROUTE_COUNTED`) or states expected units: then a keyed one is charged on the plane's pool as below; `$`: a keyed unit is admitted and charged by the governance book's one check-then-charge (`GovState::try_admit_estimated`, the plane's expected units the estimate), its money facts opened on the money steps (`PlaneMoney::open`); a route its section does not hold is refused after the charge (1.5.5's order); an anonymous unit on an open claim is admitted with nothing held and no money |
//! | meter | the plane's last far-end-reported counts, as the unit's usage lines (an estimate never bills) |
//! | audit | the record's facts: the decoded operation class and how the unit finished |
//!
//! The money steps (`busbar_kernel::plane_driver::PlaneMoney`) ledger the unit at its end: the
//! kernel writes what the plane reported, priced at read time against the card in force (money is a
//! view: `money = f(ledger, ratecard)`).

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use busbar_contract::abi::plane::{
    units_bill, UnitCount, ROUTE_DIRECT, ROUTE_LOCAL, ROUTE_POOL, ROUTE_SCOPE, ROUTE_SCOPE_LOCAL,
    ROUTE_SCOPE_SEPARATOR,
};
use busbar_contract::caps::{
    Admit, Admittance, Approve, Arrival, Audit, Authenticate, Authenticated, Consumption, Decode,
    Dial, Encode, Grant, Meter, OpClassId, Outcome, Pass, PrincipalId, QuantitySource, ReasonCode,
    Refusal, Route, SeatVerdict, UsageLine, VerifiedDestination, Verify,
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
use busbar_kernel::teller::{Evidence, UnitCtx, Units};

use crate::root::linked::node::Resolve;

// ── the pools ────────────────────────────────────────────────────────────────────────────────────

/// THE POOLS A DOOR PLANE'S UNITS ROUTE OVER (ARCHITECT Q-SW6, 2026-10-02), read off its section
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
    /// Each entry's reserved `timeout:`, in milliseconds, where it writes one
    /// (`busbar_contract::section::ENTRY_TIMEOUT_KEY`): its member's attempt bound.
    timeouts: BTreeMap<String, u64>,
    /// Each pool's members' tiers, in member order (`0` where a member states none).
    tiers: BTreeMap<String, Vec<u32>>,
    /// Each pool's `breaker:` block, where its `pools:` entry states one ([`POOL_BREAKER_KEY`]):
    /// the same block, read the same way, as a top-level pool's (BUSBAR-1.6.0.md THE DESIGN
    /// §1: "Any plugin gets all functionality").
    breakers: BTreeMap<String, busbar_kernel::config::BreakerCfg>,
}

/// A resolved route: its pool label (empty for a direct route) and its member entries.
pub type Routed = (String, Vec<String>);

impl DoorPools {
    /// The pools `section` states. REFUSED where a member written `{name, tier}` carries a tier
    /// that is no unsigned integer that fits `u32` (a member that writes no tier states none, tier
    /// `0`): the tier is core-owned
    /// ([`crate::root::serve::pools_into`] writes each member's declared index), so a bad one is a
    /// core bug, and defaulting it to `0` would route that member at the top tier in silence.
    pub fn of(section: &serde_yaml::Value) -> Result<Self, String> {
        let Some(map) = section.as_mapping() else {
            return Ok(Self::default());
        };
        let key = |k: &serde_yaml::Value| k.as_str().map(str::to_owned);
        // A model-serving section's entries are its `models` map's; any other section's are its own
        // top-level registrations.
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
        // THE POOL'S `breaker:` BLOCK, carried here by `serve::pools_into` from the pool's
        // `<verb>.pools` entry (already held to `config_validate`'s Rule 6), never handed to the plane.
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
        // THE ENTRY'S ATTEMPT BOUND (ARCHITECT timeout ruling; R2-G "per-member ... timeout"): its
        // reserved `timeout:`, read the one way the kernel judged it at load, for every plane alike.
        let timeouts = entries
            .iter()
            .filter_map(|entry| {
                let written = models
                    .unwrap_or(map)
                    .get(entry.as_str())?
                    .get(busbar_contract::section::ENTRY_TIMEOUT_KEY)?
                    .as_str()?;
                let ms = busbar_contract::section::entry_timeout_ms(written).ok()?;
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

    /// The `breaker:` block `pool` states, where it states one; `None` = the defaults.
    #[must_use]
    pub fn breaker(&self, pool: &str) -> Option<&busbar_kernel::config::BreakerCfg> {
        self.breakers.get(pool)
    }

    /// The attempt bound of `entry`'s member, milliseconds: its reserved `timeout:`; `None` = the
    /// walk's own budget bounds it.
    #[must_use]
    pub fn timeout_ms(&self, entry: &str) -> Option<u64> {
        self.timeouts.get(entry).copied()
    }

    /// The route an arrival named (ARCHITECT Q-SW6 amended by Q-FL3): a POOL route walks the named
    /// pool's members under its label; a DIRECT route walks the named entry alone under 1.5.5's
    /// empty pool label. `None` = none named, an unknown name or class.
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

    /// Every entry the section states, in its order.
    #[must_use]
    pub fn entries(&self) -> &[String] {
        &self.entries
    }

    /// Every named pool and its member entries.
    #[must_use]
    pub fn pools(&self) -> &BTreeMap<String, Vec<String>> {
        &self.pools
    }

    /// The tier of `pool`'s member at `index` (the core-owned per-member `tier`), `0` where it
    /// states none.
    #[must_use]
    pub fn tier(&self, pool: &str, index: usize) -> u32 {
        self.tiers
            .get(pool)
            .and_then(|t| t.get(index))
            .copied()
            .unwrap_or(0)
    }

    /// The first pool (in name order) whose members are each admitted on their own grant
    /// (`member_granted`) that names `entry` among its members: the pool a unit naming `entry`
    /// routes over.
    #[must_use]
    pub fn member_pool(&self, entry: &str) -> Option<&str> {
        self.pools
            .iter()
            .filter(|(name, _)| self.member_granted.contains(*name))
            .find(|(_, members)| members.iter().any(|m| m == entry))
            .map(|(name, _)| name.as_str())
    }

    /// The pool `pool` spills into when its members are spent, where its section names one.
    #[must_use]
    pub fn fallback(&self, pool: &str) -> Option<&str> {
        self.fallbacks.get(pool).map(String::as_str)
    }
}

/// A pool's reserved `on_exhausted:` key, and the pool its structured form falls back to (the pools
/// grammar's own words, `busbar_kernel::config::pools::OnExhaustedCfg`).
const ON_EXHAUSTED_KEY: &str = "on_exhausted";
const FALLBACK_POOL_KEY: &str = "fallback_pool";

/// A pool's `breaker:` key, in the pools grammar's own word (`busbar_kernel::config::PoolCfg`'s
/// `breaker`): the core-owned block `serve::pools_into` carries onto a door section's pool and
/// `serve::plane_settings` strikes before the plane is handed its section.
pub(crate) const POOL_BREAKER_KEY: &str = "breaker";

impl DoorPools {
    /// WHETHER THE CALLER'S GRANT ADMITS THE ROUTE AS NAMED, judged before its destination (1.5.5's
    /// order: the pool's grant, then its fallback pool's; an unknown pool is refused by its grant
    /// first, and only then by its absence). A direct route's grant names its entry; a direct
    /// route to an entry the section does not hold is absent before its grant. Ungoverned
    /// (`key` is `None`): nothing to enforce. A plane that states no scope kind has no resource a
    /// grant names, so it scopes nothing. None named: nothing to judge here (the route's absence
    /// refuses it).
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
        // A pool of members each admitted on its own grant: the plane judges the member.
        if class == ROUTE_POOL && self.member_granted.contains(name) {
            return true;
        }
        // A DIRECT route to an entry the section does not hold has no scope to be granted on: it
        // is absent before any grant is judged, and its absence refuses it (predev's inbound
        // authorization, whose grant list for an unknown id is empty). A pool keeps 1.5.5's order
        // above: its grant, then its absence.
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
    /// [`DoorPools::granted`], and for a POOL route over a pool whose members are each admitted on
    /// their own grant: the caller's grant on the member the unit is ADDRESSED to, its stated trust
    /// `counterparty`, where that names a member of the pool, before anything is charged (QP2,
    /// coordinator 2026-10-07: the grant on the addressed member, judged before the charge as
    /// predev's admission judged it). A counterparty that names no member of the pool leaves the
    /// members to the plane, as before.
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

/// A pool's member entries: its `members` list, each an entry name or a member naming one, with the
/// member's tier. A member that WRITES NO TIER, a bare name or an object naming its entry
/// (`{name}`, `busbar_contract::section::POOL_MEMBER_NAME_KEY`), states none: tier `0`, the
/// unordered pool, as the section read it before the refusal (the reserved `tier` sub-key is
/// optional, `BUSBAR-1.6.0.md` l.552-554). A member that WRITES a `tier`, as
/// [`crate::root::serve::pools_into`] does for every member it lays, must write an unsigned integer
/// that fits `u32`: anything else is refused, never read as `0`.
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

/// THE KEY A DOOR PLANE'S ENTRY IS PRICED, METERED AND ROUTED UNDER (ARCHITECT Q-FL3: "keys the
/// kernel's state by (plane key, model entry)"; #42/#47 one card per plane): `"<plane>\u{1f}<entry>"`.
/// The plane that owns the flat card (the empty plane key: 1.5.5's `rate_card:` and its lanes,
/// `busbar_kernel_ledger::cost::split_plane_lane`) keys its entries bare, as 1.5.5 did.
#[must_use]
pub fn plane_lane(plane: &str, entry: &str) -> String {
    if plane.is_empty() {
        return entry.to_string();
    }
    format!("{plane}{PLANE_LANE_SEP}{entry}")
}

/// THE EGRESS POOL a resolved route walks: a pool route's own label; a direct route's (plane key,
/// entry), its one member's own cell (a direct route runs under 1.5.5's empty pool label in its
/// money rows, and its breaker cell is its entry's).
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

/// The pools and key the destination guard reads, for the plane serving the `pools` map.
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

// ── admission ────────────────────────────────────────────────────────────────────────────────────

/// HOW A UNIT IS ADMITTED (ARCHITECT P3 (a), 2026-10-02).
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

/// AN ANONYMOUS UNIT NEVER REACHES A BILLED PATH (ARCHITECT P3 (a)): with no key it is admitted only
/// on an open claim, and then as anonymous; every other unkeyed unit is refused; a keyed unit is the
/// only one admitted onto the book.
#[must_use]
pub fn admission(key: Option<&Arc<VirtualKey>>, open: bool) -> Admission {
    match (key, open) {
        (Some(_), _) => Admission::Keyed,
        (None, true) => Admission::Anonymous,
        (None, false) => Admission::Refused,
    }
}

/// A blocked admission, as the refusal the plane renders: the rule the budget unit's own door
/// applies (`busbar_kernel_budget`'s `refusal_for`): a frozen group is frozen; a spend cap and a
/// principal bound to a group this node does not have are over budget; every count cap (requests,
/// tokens of any tier, the in-flight gauge) is a rate limit. A rolling window's wait rides along.
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

/// The budget mode a unit of `key` runs under: any governing limit in its group chain that cuts
/// (`on_exhaustion: cut-stream`) cuts; otherwise the unit finishes (THE DESIGN §7, Budgets).
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

// ── the steps ────────────────────────────────────────────────────────────────────────────────────

/// WHAT A SERVED PLANE STATES THE KERNEL SERVES ITS UNITS BY, read off its Statement tail at bind.
#[derive(Debug, Clone)]
pub struct DoorFacts {
    /// The plane's key: the card its lanes are priced on, and the qualifier of every lane it routes.
    pub plane: String,
    /// The grant kind that admits its traffic (its tail's first scope kind); `None` = it states none.
    pub scope_kind: Option<String>,
    /// Its billable classes, in its tail's order: a unit count's class indexes them.
    pub classes: Arc<[String]>,
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
    /// span records (status row 173).
    pub dialects: Arc<[String]>,
    /// The plane's declared breaker fact (`declares.breaker`, ARCHITECT Q4): whether a transient
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

/// ONE UNIT'S KERNEL STEPS (see the module doc), lent to the plane driver for the unit's life.
pub struct DoorSteps<'s> {
    facts: &'s DoorFacts,
    pools: &'s DoorPools,
    lanes: Resolve,
    app: Arc<App>,
    money: Option<&'s PlaneMoney>,
    principal: PrincipalId,
    key: Option<Arc<VirtualKey>>,
    /// The claim takes no inbound credential (`CLAIM_OPEN`).
    open: bool,
    /// The unit's arrival epoch, seconds: the window every charge and refund of it lands in.
    arrived: u64,
    /// The host's unit records: a host service the plane calls inside the unit's crossings
    /// (`entitlement.check`) answers for the principal recorded here.
    records: Option<Arc<busbar_kernel::host_units::UnitRecords>>,
    /// How deep the unit is nested.
    depth: u32,
    /// The caller's verified credential, lent on the unit's record at authenticate.
    credential: Option<busbar_contract::redacted::Secret<Vec<u8>>>,
    /// A nested unit's parent's hold cell: its door accrues against the parent's admission.
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
}

impl<'s> DoorSteps<'s> {
    /// The steps of one unit of the plane `facts` states, routing over `pools`, sealing each member
    /// on the lane `lanes` names its (plane key, entry) by, admitted against the generation `app`,
    /// its money on `money` (`None` = this composition moves no money).
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
            parent: None,
            unit: Mutex::new(DoorUnit::default()),
        }
    }

    /// The same steps for a NESTED unit (`unit.nest`, THE DESIGN §11.12 unit row): a child of the
    /// unit whose hold cell is `parent`, so its door accrues against the parent's admission (an
    /// accrual of nothing at admission; its reported units are its own line, at its end, under the
    /// same principal) rather than opening a reservation of its own.
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

    /// The route the unit resolved to at verify: its pool label and member entries.
    #[must_use]
    pub fn routed(&self) -> Option<Routed> {
        self.lock().routed.clone()
    }

    /// Whether the unit's operation is performed at most once (its `arrive`'s `ROUTE_ONCE`).
    #[must_use]
    pub fn once(&self) -> bool {
        self.lock().once
    }

    /// Whether the unit's caller asked for its answer streamed (its `arrive`'s `ROUTE_STREAM`).
    #[must_use]
    pub fn streamed(&self) -> bool {
        self.lock().stream
    }

    /// The walk's affinity position the unit's `arrive` named, where it stated a sticky key.
    #[must_use]
    pub fn affinity(&self) -> Option<u64> {
        self.lock().affinity
    }

    /// The key of the plane the unit is of.
    #[must_use]
    pub fn plane(&self) -> &str {
        &self.facts.plane
    }

    /// Whether the unit was charged (its money facts opened).
    #[must_use]
    pub fn charged(&self) -> bool {
        self.lock().charged
    }

    /// The pool a budget `on_exhaust: downgrade` re-admitted the unit through, where one did: the
    /// pool its charge landed on, its walk routes over and its request is counted under (1.5.5's
    /// `ingress::dispatch`: "dispatch through the pool the charge actually landed on").
    #[must_use]
    pub fn downgraded(&self) -> Option<String> {
        self.lock().downgraded.clone()
    }

    /// Whether the unit's far end CUT its STREAMED answer after its head, as the driver told the
    /// steps at the unit's audit ([`DriverSteps::answered`]): the caller asked for the answer
    /// streamed (`ROUTE_STREAM`), and its connection failed, or its send's deadline passed, before
    /// the answer completed. A whole (non-stream) answer cut by its far end is not one. Neither
    /// changes the bill: the unit bills what its plane ledgered (owner ruling 2026-10-20).
    #[must_use]
    pub fn stream_cut(&self) -> bool {
        let u = self.lock();
        u.answered.1 && u.stream
    }

    /// WHETHER A BUDGET DOWNGRADE MAY SEND THE UNIT TO `to` (1.5.5's `admit_check` guard, hop by
    /// hop): `to` is a pool of this section not yet visited, the visited set is smaller than the
    /// pool count, and the caller's grant reaches `to` and every pool its `on_exhausted` fallback
    /// chain spills into (a downgrade never routes a key into a pool it may not use).
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

    /// The pool a unit's charge and refund land on: the plane's own (#47 per-plane fees), the
    /// route's label qualified by the plane's key (a direct route's label is 1.5.5's empty one).
    fn charged_pool(&self, label: &str) -> String {
        plane_lane(&self.facts.plane, label)
    }

    /// The expected counts under the plane's class names (an estimate's figures, never billed).
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

    /// THE `$` DOOR for a keyed unit: the governance book's one check-then-charge over the route as
    /// named, its expected units the estimate (`admission: estimate`) priced at the highest of the
    /// sealed members; on a pass, its money facts open on the money steps. `Ok(false)` when this
    /// composition keeps no governance book (nothing is charged, nothing is refunded).
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
        // BUDGET DOWNGRADE (1.5.5 `ingress::admit_check`): a budget block whose limit declared
        // `on_exhaust: downgrade` re-admits through its `downgrade_to` pool instead of refusing. The
        // chain may cascade; the visited set bounds it, and every hop re-judges the caller's grant.
        // The charge lands on the EFFECTIVE pool and the unit's walk routes there.
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
                    // The plane serving the `pools` map answers a blocked admission in the
                    // previous release's words (`busbar_kernel::ingress::limit_refusal`).
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
                // The first member until one answers; the money steps take the serving member's
                // own key when its answer commits (`MoneySeam::served`).
                lane: lanes.first().cloned().unwrap_or_default(),
                classes: Arc::clone(&self.facts.classes),
                arrived: self.arrived,
                mode: exhaustion_of(&self.app, key),
                // THE PLANE'S REPORT IS THE ONE FEE DECIDER (owner #77, money-B1): every plane's
                // fee is its reported fee units (#47); the plane serving the `pools` map reports
                // its per-request unit exactly where 1.5.5 kept its flat fee.
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
    /// The unit ended (returned, or its future was dropped): its record leaves the host's unit
    /// records.
    fn drop(&mut self) {
        let recorded = self.lock().recorded.take();
        if let (Some(records), Some(unit)) = (self.records.as_ref(), recorded) {
            records.ended(unit);
        }
    }
}

/// The record's facts for a unit of these steps: its op class and its FINISH, new in 1.6.0 (v1.5.5
/// wrote no per-request audit record, so there is no parity to match). ARCHITECT ruling
/// 2026-10-15: `Complete` for a whole answer; `Partial` for a unit the far end CUT after its head
/// (ruling (a) completes it, its transient cleared) or one the node ended after a byte of its reply
/// reached the caller (the caller dropped it, a `cut-stream` budget cut): a cut is not a refusal
/// (#77(7), #62), what arrived arrived; `Error` for a refused or failed unit, for one ended before
/// the first byte of a success answer, and for a cut answered with an error (a buffered answer
/// cut mid-body is the caller's 502). `streamed` and `cut` are the driver's facts
/// ([`DriverSteps::answered`]).
fn facts(
    op: OpClassId,
    outcome: &Outcome,
    streamed: bool,
    cut: bool,
) -> busbar_contract::AuditFacts {
    use busbar_contract::FinishClass;
    let finish = match outcome {
        // A cut after the first byte of a success answer: what arrived, arrived.
        Outcome::Completed if cut && streamed => FinishClass::Partial,
        // A cut the caller was answered with an error for (a buffered answer's 502).
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

    /// THE UNIT'S REQUEST SPAN, `forward`, as the previous release opened it around its dispatch
    /// (v1.5.5 `proxy/engine/mod.rs:120-152`): at the hot-path level, with the pool the charge
    /// landed on (a budget downgrade's, else the one the unit named), the dialect it was read in,
    /// its operation class and a correlation id off the process's one counter, stamped once per
    /// dispatched unit as 1.5.5 stamped one per dispatched request (status row 173).
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
        // A stream the far end cut bills what its plane ledgered, as any other: the cut is a fact
        // of the unit's end, never a reason to drop its usage (owner ruling 2026-10-20).
        self.lock().answered = (streamed, cut);
    }

    fn usage_tap_fault(&self, _ctx: &UnitCtx, dialect: u32, reason: &'static str) {
        // The unit's dialect is the ingress protocol its tap read the body as (row 155).
        if let Some(protocol) = self.facts.translations.0.get(dialect as usize) {
            busbar_kernel::handlers::usage_tap_fault(protocol, reason);
        }
    }

    fn refusal_words(&self, reason: ReasonCode) -> Option<Vec<u8>> {
        // A unit routed by scope that no one entry reached: the entries that reached it (none, or
        // several), so the plane words which (abi/plane `ROUTE_SCOPE`).
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

impl Units for DoorSteps<'_> {
    fn arrival(&self, token: &Pass<Arrival>, _ctx: &UnitCtx) -> SeatVerdict<Arrival> {
        SeatVerdict::proceed(
            token,
            busbar_contract::ArrivalRecord {
                source: String::new(),
                port: 0,
                alpn: None,
                sni: None,
                peer_cert: None,
                transport_chain: Vec::new(),
            },
        )
    }

    fn decode(&self, token: &Pass<Decode>, _ctx: &UnitCtx) -> SeatVerdict<Decode> {
        // The plane driver's own seat (`arrive`): never reached through these steps.
        SeatVerdict::refuse(token, Refusal::new(ReasonCode::HandoffMismatch))
    }

    fn authenticate(&self, token: &Pass<Authenticate>, ctx: &UnitCtx) -> SeatVerdict<Authenticate> {
        match admission(self.key.as_ref(), self.open) {
            Admission::Refused => {
                SeatVerdict::refuse(token, Refusal::new(ReasonCode::Unauthenticated))
            }
            Admission::Keyed | Admission::Anonymous => {
                // The unit's verified principal, on the host's unit records for its life: a host
                // service called inside its crossings answers for it.
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
                    self.lock().recorded = Some(ctx.key.get());
                }
                SeatVerdict::proceed(token, Authenticated::Principal(self.principal.clone()))
            }
        }
    }

    fn verify(
        &self,
        token: &Pass<Verify>,
        trust: &Grant<Dial>,
        _ctx: &UnitCtx,
        _principal: &PrincipalId,
    ) -> SeatVerdict<Verify> {
        // A UNIT ROUTED BY SCOPE (ROUTE_SCOPE, the ARCHITECT scope-select ruling: scope seals the
        // destinations): the one entry the principal's grant of the plane's scope kind reaches is
        // its route, directly; zero or several seal nothing and it is refused at admission, the
        // several named in its refusal's words.
        let named_scope = match &self.lock().named {
            Some((class @ (ROUTE_SCOPE | ROUTE_SCOPE_LOCAL), candidates)) => {
                Some((*class, candidates.clone()))
            }
            _ => None,
        };
        if let Some((class, candidates)) = named_scope {
            // The plane's candidates (the entries that would serve the unit, ARCHITECT
            // Q-DEL-A2A-SCOPE-TRUST); none named = every entry.
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
                // A UNIT THE PLANE ANSWERS AT THE ONE ENTRY (ROUTE_SCOPE_LOCAL, COORDINATOR ruling
                // 2026-10-07): resolved as a scope's, and routed nowhere (no pool, no breaker, no
                // egress), as predev answered its local verbs at the agent `select` chose before
                // any pool was read (receive.rs:1257-1279, :1559-1593, before `pool_of` :1839).
                [one] if class == ROUTE_SCOPE_LOCAL => {
                    u.resolved = Some(one.clone());
                    u.scope_entry = Some(one.clone());
                }
                // The one entry, routed as an addressed unit naming it is: over the pool of
                // members each admitted on their own grant that it is a member of, else directly
                // (predev's unaddressed request reached the same pool walk as an addressed one,
                // receive.rs:1262-1268 converging at :1839 and :1916).
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
        // An unknown route seals nothing and is refused at admission, after its grant was judged
        // (1.5.5's order); the empty set is an answer at this step.
        let named = self.lock().named.clone();
        // THE PLANE SERVING THE `pools` MAP judges the route as named with the previous release's
        // destination guard (`busbar_kernel::door::destination_guard`): the key's pool grant, its
        // fallback pools' grants, then a rate card's coverage of the name, refused in 1.5.5's words.
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
                    return SeatVerdict::refuse(token, Refusal::new(refusal.reason()));
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
        SeatVerdict::proceed(token, sealed)
    }

    fn approve(
        &self,
        token: &Pass<Approve>,
        _ctx: &UnitCtx,
        _principal: &PrincipalId,
        _destinations: &[VerifiedDestination],
    ) -> SeatVerdict<Approve> {
        let (class, named) = self.lock().named.clone().unwrap_or((ROUTE_POOL, None));
        let counterparty = self.lock().counterparty.clone();
        // A unit routed by scope that no one entry reached names its candidates, not a route: the
        // grant was the resolution itself, and admission refuses it (no destination).
        if class == ROUTE_SCOPE
            || class == ROUTE_SCOPE_LOCAL
            || self.pools.granted_to(
                self.facts.scope_kind.as_deref(),
                self.key.as_deref(),
                (class, named.as_deref()),
                counterparty.as_deref(),
            )
        {
            SeatVerdict::proceed(token, busbar_contract::ScopeFacts::default())
        } else {
            SeatVerdict::refuse(token, Refusal::new(ReasonCode::ScopeDenied))
        }
    }

    fn admit(
        &self,
        token: &Pass<Admit>,
        admit: &Grant<Admittance>,
        ctx: &UnitCtx,
        principal: &PrincipalId,
        _destinations: &[VerifiedDestination],
        _leases: &GroupLeaseSlip,
    ) -> SeatVerdict<Admit> {
        // A UNIT THE PLANE ANSWERS ITSELF (ROUTE_LOCAL, ARCHITECT Q-L3B-LOCAL): admitted with no
        // route walk; only far-end-reported units bill (§7), so it holds and charges nothing, and
        // is audited as every unit is.
        // A local unit whose plane EXPECTS units (its admission estimate) is charged as any keyed
        // unit is: the plane's own round, on the caller's budget (the served engine charged busbar's
        // own ask round before it was asked; 05e053183a). So is one the plane answers
        // AS AN ADMITTED CALL (ROUTE_COUNTED): a keyed one passes the one check-then-charge on the
        // plane's pool, counting its request (R2, 1.5.5's rule), and keeps only the fee units the
        // plane reports.
        let (local, counted, estimated) = {
            let u = self.lock();
            let local = u
                .named
                .as_ref()
                .is_some_and(|(class, _)| *class == ROUTE_LOCAL || *class == ROUTE_SCOPE_LOCAL);
            (local, local && u.counted, !u.expected.is_empty())
        };
        // A UNIT ROUTED BY SCOPE that no one entry reached (the scope-select ruling): refused before
        // anything is charged, as 1.5.5 chose the agent before its admission.
        let unrouted_scope = {
            let u = self.lock();
            u.named.as_ref().is_some_and(|(class, _)| {
                *class == ROUTE_SCOPE || (*class == ROUTE_SCOPE_LOCAL && u.resolved.is_none())
            })
        };
        if unrouted_scope && !matches!(admission(self.key.as_ref(), self.open), Admission::Refused)
        {
            return SeatVerdict::refuse(token, Refusal::new(ReasonCode::NoDestination));
        }
        match admission(self.key.as_ref(), self.open) {
            Admission::Refused => {
                return SeatVerdict::refuse(token, Refusal::new(ReasonCode::Unauthenticated))
            }
            Admission::Keyed if !local || counted || estimated => {
                if let Some(key) = self.key.clone() {
                    if let Err(refusal) = self.charge(ctx, &key) {
                        self.lock().refused.0 = refusal.retry_after_secs();
                        return SeatVerdict::refuse(token, refusal);
                    }
                }
            }
            Admission::Keyed | Admission::Anonymous => {}
        }
        // A route its section does not hold: refused here, after its grant and its charge (1.5.5's
        // order); the charge is refunded at the unit's end.
        if !local && self.lock().routed.is_none() {
            return SeatVerdict::refuse(token, Refusal::new(ReasonCode::NoDestination));
        }
        // The door reserves nothing: the unit's hold opens at zero and the money steps ledger what
        // the plane reported, at its end. A NESTED unit accrues against its parent's admission
        // instead (zero at admission, ARCHITECT H3): one admission chain, its posting into the
        // parent's hold. A parent that already exited, or any refusal of the accrual, leaves the
        // child its own zero hold: it posts on its own.
        if let Some(cell) = self.parent {
            if let Ok(accrual) = cell.accrue_child(principal, admit) {
                return SeatVerdict::proceed(
                    token,
                    busbar_contract::caps::Admission::Accrual(accrual),
                );
            }
        }
        SeatVerdict::proceed(
            token,
            busbar_kernel::door::admitted_at_zero(admit, principal.clone()),
        )
    }

    fn route(
        &self,
        token: &Pass<Route>,
        _ctx: &UnitCtx,
        _destinations: &[VerifiedDestination],
    ) -> SeatVerdict<Route> {
        // The plane driver's own seat (the route pump): never reached through these steps.
        SeatVerdict::refuse(token, Refusal::new(ReasonCode::HandoffMismatch))
    }

    fn meter(
        &self,
        token: &Pass<Meter>,
        usage: &Grant<Consumption>,
        ctx: &UnitCtx,
        _provisional: &Outcome,
        _destinations: &[VerifiedDestination],
    ) -> SeatVerdict<Meter> {
        // What the unit consumed: the plane's last far-end-reported cumulative counts (an estimate
        // never bills; a fee unit says whether the fee was incurred and is no usage), one line per
        // class, summed with checked addition. Nothing here names a rate.
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
                None => return SeatVerdict::refuse(token, Refusal::new(ReasonCode::Unpriced)),
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
                    // The figure the plane reported, written as it was told.
                    source: QuantitySource::Count,
                    estimated: false,
                })
            })
            .collect();
        match busbar_contract::caps::Usage::report(usage, lines) {
            Ok(report) => SeatVerdict::proceed(token, report),
            Err(_) => SeatVerdict::refuse(token, Refusal::new(ReasonCode::Unpriced)),
        }
    }

    fn audit(&self, token: &Pass<Audit>, _ctx: &UnitCtx, outcome: &Outcome) -> SeatVerdict<Audit> {
        let (op, (streamed, cut)) = {
            let u = self.lock();
            (u.op.unwrap_or(self.facts.audit_kind), u.answered)
        };
        SeatVerdict::proceed(token, facts(op, outcome, streamed, cut))
    }

    fn audit_refused(
        &self,
        token: &Pass<Audit>,
        _ctx: &UnitCtx,
        refusal: &Refusal,
    ) -> SeatVerdict<Audit> {
        let op = self.lock().op.unwrap_or(self.facts.audit_kind);
        let step = refusal
            .step()
            .unwrap_or(busbar_contract::caps::StepName::Admit);
        SeatVerdict::proceed(
            token,
            facts(op, &Outcome::Refused(step, refusal.reason()), false, false),
        )
    }

    fn encode(
        &self,
        token: &Pass<Encode>,
        _ctx: &UnitCtx,
        _outcome: &Outcome,
    ) -> SeatVerdict<Encode> {
        // The plane driver's own seat (the plane renders): never reached through these steps.
        SeatVerdict::refuse(token, Refusal::new(ReasonCode::HandoffMismatch))
    }

    fn evidence(&self, _ctx: &UnitCtx) -> Evidence {
        Evidence::default()
    }
}

/// THE DOOR FACTS of a plane bound through its door: its key, its first scope kind, and its tail's
/// billable classes and fee units (a fee unit that is no billable class is not one: the tail check
/// holds `fee_units ⊆ billable_classes`).
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

/// THE BOUND ON A PLANE'S STATED COUNTER LABELS over its section's `pools`
/// ([`crate::root::egress_ports::LabelBound`]): for each pool the walk keys by name — a named
/// pool's label, and each entry's own pool (`plane_lane(plane, entry)`, a direct route's) — the
/// configured pool labels and entry names that walk can reach (a named pool's members, then its
/// fallback pool's, and so on), and the plane's declared lane words `vocabulary`.
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

// ── the egress ───────────────────────────────────────────────────────────────────────────────────

/// THE EGRESS OF ONE DOOR PLANE, sealed for a generation (`BUSBAR-1.6.0.md` Part 3 §12 "The route
/// pump": the route step is the kernel's existing egress walk; Part 4 Axis 3 / THE DESIGN §5: the
/// host owns the allow-list, pin, breaker and meter valves, and the wire is the connector's): the
/// plane instance `caller`'s connection table `conns` (the connector its needs were declared on),
/// one member per entry `routes` seals (each named by its (plane key, entry), Q-FL3), a pool per
/// named pool of its section (its members, its fallback pool) and a pool per entry its direct
/// routes walk, the breaker under every pool's default ladder, the members' permits, the node's
/// counters, `journal` (the write-ahead dispatch record, `$`, ARCHITECT P3 (c)) and `clock`, the
/// walk's clock the plane was composed on (the node's, [`crate::root::egress_ports::NodeClock`]).
///
/// # Errors
///
/// A named pool whose member entry has no sealed route: the load is refused, naming both.
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
        // What of the far end's head crosses is the dialled need's own declared rule.
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
        // THE MEMBER'S TRUST ANCHORS, SEALED INTO THE CONNECTOR (the transport pin, ARCHITECT 2026-10-03): every connection
        // to the member, the walk's and the plane's own, is held to them by the connector itself,
        // on EVERY need the member rides (its own and each beside it, at the base each dials),
        // kept under the member's name, so a registration sharing its authority presents its own
        // client identity and never this one's.
        for (need, base_url) in ridden(&route) {
            conns
                .anchor(caller, need, &route.provider, &base_url, &route.anchors)
                .map_err(|e| {
                    format!("member '{entry}': its trust anchors could not be sealed: {e}")
                })?;
            // THE REGISTRATION'S PRIVATE REACH, sealed for this registration alone (SEAM-4k): the
            // member route's dials name it, and no other registration at the same authority holds it.
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
        // The member's attempt bound is its entry's `timeout:` (ARCHITECT timeout ruling): every
        // attempt the walk makes to it, alone or in a pool, is held to it.
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
    // Every cell of this plane's members under its pool's ladder: the pool's own `breaker:` block
    // where its `pools:` entry states one, lowered by the kernel's one lowering exactly as the
    // top-level pools are (`BreakerPolicy::from_pools`), else the default ladder (BUSBAR-1.6.0.md
    // THE DESIGN §1: "Any plugin gets all functionality"); with the plane's declared breaker fact
    // where it states one (ARCHITECT Q4). A pool with no block — every pool of a default config —
    // reads exactly the ladder it always did.
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
    // The process-wide `limits.hard_down_cooldown_secs` / `limits.max_honored_retry_after_secs`,
    // as published for the generation this egress is sealed for (boot's commit, or the swap that
    // refreshes the door planes onto a new generation): the same two limits the lane store's
    // cells run under (THE DESIGN §1). Unpublished (a test process), the defaults — the values
    // every default deployment runs under.
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
        breaker: Arc::new(crate::root::adapters::BreakerAdapter::new(
            Arc::new(unit),
            policy,
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
        floor: busbar_kernel_egress::WeightedFloor::new(),
        pools: built,
        routes: sealed,
        stream_ceiling_secs,
        stated_ceiling_secs: facts.stream_ceiling_secs,
        error_body_max: busbar_kernel::plane_driver::DEFAULT_ERROR_BODY_MAX,
    })
}

// ── one configuration generation, as the door planes are sealed over it ─────────────────────────

/// WHAT A DOOR PLANE IS SEALED OVER, for ONE configuration generation (spec Part 1 line 569: one
/// validated `{section: value}` object per `open`/`refresh`): the kernel-owned sections it reads
/// ([`kernel_sections`]), the providers its members are reached through ([`provider_routes`]) and
/// the model-serving pools' bounds ([`crate::root::model_egress::ModelPools`]). Projected from each
/// resolved configuration as it is built (the root's install record,
/// `busbar_kernel::preflight::RootInstall::config_projection`), and read back when that generation
/// is swapped in.
#[derive(Debug)]
pub struct DoorConfig {
    /// The kernel-owned sections, and beside them every plane section the configuration carries RAW
    /// (a door plane's other owned sections among them: a config apply hands a plane its owned
    /// sections from here, as boot hands them from the document's sections).
    pub sections: BTreeMap<&'static str, serde_yaml::Value>,
    /// The providers, by name.
    pub providers: BTreeMap<String, ProviderRoute>,
    /// The model-serving pools' bounds.
    pub model_pools: crate::root::model_egress::ModelPools,
}

/// The [`DoorConfig`] of `cfg` (the root's `ConfigProjection`).
#[must_use]
pub fn door_config(cfg: &busbar_kernel::config::RootCfg) -> Arc<dyn std::any::Any + Send + Sync> {
    let mut sections = kernel_sections(cfg);
    for (key, value) in raw_sections(cfg) {
        sections.entry(key).or_insert(value);
    }
    Arc::new(DoorConfig {
        sections,
        providers: provider_routes(
            &cfg.providers,
            &busbar_kernel::config_validate::MetadataPosture::global(cfg),
        ),
        model_pools: crate::root::model_egress::ModelPools::of(cfg),
    })
}

/// EVERY PLANE SECTION `cfg` CARRIES RAW, by section key, as written: each is its plane's resource
/// (`RootCfg::endpoint_resources`, `(section, value)`), a plane's other owned sections among them.
fn raw_sections(cfg: &busbar_kernel::config::RootCfg) -> BTreeMap<&'static str, serde_yaml::Value> {
    cfg.endpoint_resources
        .values()
        .filter_map(|r| r.downcast_ref::<(&'static str, serde_yaml::Value)>())
        .filter(|(_, v)| !v.is_null())
        .map(|(k, v)| (*k, v.clone()))
        .collect()
}

// ── the owned trust anchors: one rule, at boot and before an apply's swap ───────────────────────

/// THE ONE RULE an owned trust anchor the operator wrote is judged by, at boot and before an
/// apply's swap alike: it is one or more PEM certificates the TLS stack takes as trust anchors (the
/// connector's own reading of it, `tls::client::operator_ca_config`). An anchor the operator did
/// not write is no refusal: an owned section is optional.
///
/// # Errors
///
/// The refusal, naming `at` (`<section>.<key>`).
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

/// Judge every owned trust anchor among `paths` (need `trust_from` paths; any other is skipped)
/// that `sections` (the configuration's sections, by key) writes, by [`owned_anchor_refusal`].
///
/// # Errors
///
/// The first written anchor that is no trust anchor, named.
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
    /// The rules of a boot whose destination guard is `guard`: it re-reads its metadata lists at
    /// every configuration commit, the boot's own build included, as 1.5.5 re-read them at every
    /// reload.
    #[must_use]
    pub fn hearing(guard: Arc<dyn busbar_kernel::host_services::DestJudge>) -> Self {
        Self {
            guard: Some(guard),
            ..Self::default()
        }
    }

    /// Hold the owned trust anchors among a door plane's need `trust_from` paths (`paths`).
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

    /// Hold the discovered plane doors the boot did not load (`candidates`): each one the boot's
    /// configuration used by no section of its ([`unloaded_doors`]).
    pub fn hold_unloaded(&self, candidates: Vec<crate::root::loader::boot::Candidate>) {
        self.unloaded
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend(candidates);
    }

    /// Hold the declaring sections of the door planes the boot left unopened (`sections`): each a
    /// plane bound through its door whose section the boot configuration did not write.
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

/// Does `cfg` write the plane whose declaring section is `section` (Law 7, BUSBAR-1.6.0.md l.547:
/// a plane loads iff its verb is present)? The declaring section selects; an owned, consumed or
/// required section does not on its own.
pub(crate) fn writes_plane(section: &str, cfg: &busbar_kernel::config::RootCfg) -> bool {
    cfg.plane_sections.contains(section)
}

/// THE DISCOVERED PLANE DOORS THE BOOT DID NOT LOAD: every plane door discovered (linked or dropped
/// in) that [`crate::root::boot::load_door_planes`] did not bind, because the boot's configuration
/// uses it by no section (`used_planes`, Law 7). Read once the door planes are loaded.
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

/// THE REFUSAL OF A FIRST SECTION OF AN UNLOADED PLANE (u67 BLOCK 2 item 2, ruled (iv)): the first
/// of `unloaded` that a document whose root keys are `keys` uses (`plane_use`, the boot's own
/// selection), named with the section that uses it. A plane is loaded only at start, when config
/// uses it (Law 7, BUSBAR-1.6.0.md l.547), so its first section cannot take effect on a running
/// process: the change is refused whole and nothing is changed (§6 item 8, l.980-982).
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

// ── the kernel-owned sections a door plane reads ────────────────────────────────────────────────

/// THE KERNEL-OWNED SECTIONS A DOOR PLANE MAY READ, as the configuration validated and resolved
/// them (spec Part 1 §4: "A plane's settings reach it as ONE validated JSON object `{section:
/// value}` per open/refresh, reserved keys and secrets stripped"; "A plane receives, at open, the
/// dialect fields of the providers it references and resolves model -> dialect itself"): `providers`
/// (catalog-merged, each provider's dialect fields: no `base_url`, no credential reference, no
/// health or token endpoint), `models`, `pools` (each pool's members and its fallback pool) and
/// `limits` (the output-cap default, the effort budgets and the translation cap,
/// `request_body_max_bytes`). The previous release kept these in the
/// kernel; they are the root's to hand a door plane whose Statement names them. `pools` is present
/// whenever `models` is: a deployment with models and no pools routes to its models directly.
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
        // The provider's dialect keys are its table, as written and catalog-merged (row 155 B1b:
        // the root names none of them); beside them the two destination facts a dialect composes
        // its request path from and the auth style a dialect's default yields to.
        let mut m = p.table.clone();
        opt(&mut m, "path", p.path.as_ref().map(|v| json!(v)));
        opt(&mut m, "path_base", p.path_base.as_ref().map(|v| json!(v)));
        opt(&mut m, "auth", p.auth.map(style_word).map(|v| json!(v)));
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
        // The model's dialect override (#51), for the plane to resolve and judge.
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
        // The header a pool's session affinity reads (1.5.5's `affinity.header_name`): the plane
        // reads the caller's key from it, and the kernel routes on that key (ARCHITECT Q1).
        if let Some(header) = pool.affinity.as_ref().and_then(|a| a.header_name.as_ref()) {
            p.insert("affinity".into(), json!({ "header_name": header }));
        }
        pools.insert(name.clone(), Value::Object(p));
    }
    // The translation cap (row 155): the operator's one knob for the inbound body limit and the
    // egress translate cap, handed so the plane enforces the kernel's value from its own settings.
    let limits = json!({
        "default_max_tokens": cfg.limits.default_max_tokens,
        "request_body_max_bytes": cfg.limits.request_body_max_bytes,
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
    // A WRITTEN consumed|required key counts, even an empty one (ARCHITECT row-82 ruling): a
    // section some registered plane requires is written in every document that parsed (the pre-pass
    // refuses one that omits it, `busbar_kernel::config::prepass`), so it is handed as written. The
    // previous release accepted `models: {}` and answered from its catch-all (v1.5.5
    // crates/busbar/src/config/mod.rs:2626-2632; ingress/dispatch.rs:292-319).
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

// ── the members' routes (THE DESIGN §6 steps 2-3) ──────────────────────────────────────────────

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
    /// `token_uri`, the service account's token endpoint (ARCHITECT 2026-10-04 parity ruling, THE
    /// DESIGN §5 `loopback-allowed`: "auth mint endpoints (`token_url`, `token_uri`)"): the target
    /// of the serving plugin's `settings.token_uri` need, judged as 1.5.5 judged it.
    pub token_uri: Option<String>,
    /// `scope`, where stated.
    pub scope: Option<String>,
    /// `subject`, where stated.
    pub subject: Option<String>,
}

impl StyleParams {
    /// The one JSON object `open_outbound` reads: the stated keys, in this order, and no others.
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

/// The `auth:` spelling of a provider's style override, as config writes it.
fn style_word(auth: busbar_kernel::config::ProviderAuth) -> &'static str {
    use busbar_kernel::config::ProviderAuth as Style;
    match auth {
        Style::Bearer => "bearer",
        Style::ApiKey => "api-key",
        Style::JwtBearer => "jwt-bearer",
        Style::OAuthClientCredentials => "oauth-client-credentials",
    }
}

/// TRANSITIONAL (row 155 B1b; drains at B1c, where the plane states the default auth style its
/// dialect implies per provider and the root reads that style, never the dialect): one resolved
/// provider as [`provider_routes`] reads it, its kernel-owned keys through the provider itself and
/// the two dialect facts [`ProviderRoute`] still carries read off its table.
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

/// THE DEPLOYMENT'S PROVIDERS as door planes' members reach them, by name (the catalog-merged
/// `providers:` the configuration resolved), each under its metadata posture in the deployment's
/// `security` (its own allow-overrides, then the global ones).
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
                    style: p.auth.map(|a| style_word(a).to_string()),
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

/// THE DIALECT FACTS OF THE PROVIDERS `section` REFERENCES, read off `providers` through the one
/// builder the probe's open uses too ([`busbar_contract::plane_calls::dialect_facts`]).
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

/// One auth plugin serving a style: its instance, opened for its outbound styles, and the style as
/// its tail states it.
type Serving = (
    Arc<dyn busbar_contract::auth_calls::OutboundAuth>,
    crate::root::loader::dispatch::kinds::auth::OutboundStyle,
);

/// THE AUTH PLUGINS A MEMBER'S STYLE MAY BE SERVED BY (THE DESIGN §6 step 3: the auth plugin that
/// serves the style opens the binding): the build's linked `auths` rows, then the plugins
/// directory's `kind: auth` rows (compiled-in = dropped-in), each loaded through the loader's one
/// load on the process's dispatcher, its declared needs on the process's connection table (THE
/// DESIGN §5: an auth plugin that mints reaches its token endpoint through its own need). The first
/// whose tail states the style serves it. Its instance is opened once and serves every binding of
/// every style it states; a plugin whose needs take their target from its settings (`target_from`)
/// is opened once per binding's settings instead, so each need is declared pinned to that binding's
/// endpoint (PB-100). Every instance opened runs its tick schedule on its driver ticket (§6.5: a
/// minted credential refreshes ahead of expiry on `tick`).
pub struct OutboundAuths {
    dispatcher: Arc<crate::root::loader::dispatch::Dispatcher>,
    linked: Vec<busbar_kernel::preflight::LinkedAuth>,
    dropped: Option<&'static crate::root::loader::PluginRegistry>,
    conns: crate::root::loader::dispatch::ConnTable,
    /// Each linked row's outbound facts, READ off its door's `'static` Statement at the first
    /// serving: no row is bound to read them (Law 7; ARCHITECT ruling 2026-10-20: reading a row's
    /// static declaration, its kind tail included, is reading, not loading).
    linked_facts: std::sync::OnceLock<Vec<AuthRowFacts>>,
    /// Each dropped-in row's outbound facts, READ off its SIGNED MANIFEST's Statement rendering at
    /// the first serving no linked row answers: no row is bound or opened to read them (ARCHITECT
    /// ruling 2026-10-20, audit root#7 / loader#9: the rendering carries the whole kind tail, and
    /// admitting the row compares its door's Statement with it).
    dropped_facts: std::sync::OnceLock<Vec<AuthRowFacts>>,
    /// The opened instances, by key: opened OUTSIDE the map's lock (THE DESIGN §11.13 M1: the
    /// plugin's validate and open crossings never run under a host lock).
    opened: crate::root::loader::open_once::OpenOnce<
        String,
        crate::root::loader::dispatch::auth_outbound::OutboundInstance,
    >,
    /// TEST PROBE: every row [`Self::load_with`] was asked to bind, by name, in order (Law 7: an
    /// auth row no configured style selects is never bound).
    #[cfg(test)]
    bound: Mutex<Vec<String>>,
}

/// One auth row's outbound facts: where its door is, the styles its Statement states, and whether
/// its needs take their target from its settings (one instance per binding's settings).
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
    /// The auth rows `linked` (the build's) and `dropped` (the plugins directory's), loaded on
    /// `dispatcher`, their needs declared on `conns`: `ConnTable::Host`, the process's connector;
    /// or, stated by the caller, `ConnTable::NoNeeds`: no need is granted, a row that declares one
    /// will not load and is passed over, and a style that mints mints nothing.
    #[must_use]
    pub fn new(
        dispatcher: Arc<crate::root::loader::dispatch::Dispatcher>,
        linked: &[busbar_kernel::preflight::LinkedAuth],
        dropped: Option<&'static crate::root::loader::PluginRegistry>,
        conns: crate::root::loader::dispatch::ConnTable,
    ) -> Self {
        Self {
            dispatcher,
            linked: linked.to_vec(),
            dropped,
            conns,
            linked_facts: std::sync::OnceLock::new(),
            dropped_facts: std::sync::OnceLock::new(),
            opened: crate::root::loader::open_once::OpenOnce::new(),
            #[cfg(test)]
            bound: Mutex::default(),
        }
    }

    /// The bind one auth row is loaded under: its needs on the connection table, its diagnostics
    /// (a mint that failed and will retry, a credential it could not present) in its own log file
    /// under the configured `plugins.logs` (THE DESIGN #85) AND, each declared one, in the main log
    /// in the line 1.5.5 wrote there ([`MainLogSink`]). Its needs are declared on `conns`
    /// (`ConnTable::NoNeeds`: no need is granted).
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
        let sink: Arc<dyn EnvelopeSink> = Arc::new(MainLogSink(sink));
        crate::root::loader::dispatch::Bind {
            instance: Arc::from(name),
            max_inflight_cap: 64,
            sink,
            dispatcher: self.dispatcher.adopter(),
            conns,
        }
    }

    /// One auth row's door, loaded (bound) afresh. `None` when it will not load (its own open names
    /// why where it is configured).
    fn load(
        &self,
        name: &str,
        door: AuthRowDoor,
    ) -> Option<
        crate::root::loader::dispatch::Plugin<crate::root::loader::dispatch::kinds::auth::Auth>,
    > {
        self.load_with(name, door, self.conns.clone())
    }

    /// [`Self::load`] with the needs declared on `conns` (`ConnTable::NoNeeds`: no need is granted,
    /// so a row that declares one will not load).
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

    /// The rows stating the outbound `style`, in the order a serving tries them: the linked rows
    /// whose Statement states it, then (read only once no linked row served it) the dropped-in rows
    /// stating it.
    fn stating<'a>(&'a self, style: &'a str) -> impl Iterator<Item = &'a AuthRowFacts> + 'a {
        self.linked_facts()
            .iter()
            .chain(std::iter::once_with(move || self.dropped_facts()).flatten())
            .filter(move |row| row.styles.iter().any(|s| s.name == style))
    }

    /// Every linked row's outbound facts, read once off its door's `'static` Statement: the styles
    /// its auth tail states, and whether a need of its takes its target from its settings
    /// (`target_from`: one instance per binding's settings). No row is bound. A row whose
    /// Statement a bind refuses states nothing here.
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

    /// Every dropped-in row's outbound facts, read once off its signed manifest's Statement
    /// rendering: the styles its auth tail states, and whether a need of its takes its target from
    /// its settings. No row is bound or opened. A row whose rendering a bind refuses states nothing
    /// here.
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

    /// The auth plugin serving `style` for a binding under `settings`, its instance opened (once
    /// per plugin, or once per binding's settings for a plugin whose needs take their target from
    /// them) and its tick schedule running; `None` when no row states it. Only the serving row is
    /// bound, and only when its instance is not open yet; its open runs with no lock held.
    ///
    /// # Errors
    ///
    /// The serving plugin would not open for its outbound styles.
    pub fn serving(
        &self,
        style: &str,
        settings: &serde_json::Value,
    ) -> Result<Option<Serving>, String> {
        use crate::root::loader::dispatch::auth_outbound::OutboundInstance;
        // A token endpoint spelled `user:pass@` (row 74, F25): the plugin is opened over, and its
        // binding handed, the stripped endpoint, and the userinfo rides its mint as 1.5.5 sent it
        // ([`endpoint_userinfo`]).
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
            // Keyed on the settings as written, so two bindings whose endpoints differ only in
            // their userinfo never share an instance (each one's mint presents its own).
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
                    // ITS TICK SCHEDULE, once per instance, on the runtime the composition runs on.
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

/// The settings keys a minting style's token endpoint is written under: the configured
/// `token_url` (`oauth-client-credentials`) and the service account's `token_uri` (`jwt-bearer`).
const TOKEN_ENDPOINT_SETTINGS: [&str; 2] = ["token_url", "token_uri"];

/// A TOKEN ENDPOINT SPELLED `user:pass@`, AS 1.5.5 REACHED IT (row 74, F25). 1.5.5 POSTed the client
/// credentials with reqwest to `token_url` as written (v1.5.5
/// `oauth_client_credentials.rs:119-126` in its egress-auth tree, `.post(&self.token_url)
/// .form(..)`), and reqwest 0.12.28's builder took the userinfo out of the URL and sent it FIRST as
/// `authorization: Basic base64(user:pass)` (`src/async_impl/request.rs:169-182`,
/// `extract_authority` `:581-605`, `util::basic_auth` `src/util.rs:4-25`); the form named no
/// `authorization`, so it always rode. `jwt-bearer` POSTed its signed assertion to the service
/// account's `token_uri` the same way (v1.5.5 `crates/busbar/src/egress_auth/jwt_bearer.rs:175-181`,
/// `.post(&self.token_uri).form(..)`), so the same rule holds for it. Here the endpoint the plugin
/// is handed in its settings is the stripped one,
/// so its need is pinned to, and its mint dials, the host after the `@` and the userinfo is in no
/// plugin's settings, log or error; the Basic value rides the mint's open from the host side
/// ([`presenting`]). `None` when the settings name no endpoint, or one with no userinfo.
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

/// A served binding whose endpoint was stripped: its `open_outbound` is handed the stripped
/// settings too, whatever its caller wrote ([`endpoint_userinfo`]); every other call is the
/// instance's own.
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

/// The connection table one binding's minting instance declares its needs on and opens its mint
/// through: the process's table, with the endpoint's Basic value FIRST on every open whose fields
/// name no `authorization` (1.5.5's order and condition, see [`endpoint_userinfo`]) and any
/// userinfo left in the open's target taken out. A table that grants no need stays as it is.
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

/// See [`presenting`]: every call but `open` is the inner table's own.
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
        let target = busbar_kernel_egress::trust::net::strip_userinfo(desc.target);
        let led = self.userinfo.leading(desc.fields);
        let fields = led.as_deref().unwrap_or(desc.fields);
        self.inner.open(
            caller,
            need,
            &busbar_contract::conn::OpenDesc {
                target: &target,
                fields,
                ..*desc
            },
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
    /// CHECK, NEVER DIAL: `credential` bound under `settings` on a FRESH instance of the plugin
    /// serving `style`, loaded as a CHECK bind (`ConnTable::Probe`: a need it declares is not
    /// declared and it is handed no table, so it reaches nothing), and the refusals it names for the
    /// credential itself — its `credential:` lines, their text. Empty when it accepts the credential
    /// or no row states the style. A `ConnTable::NoNeeds` bind would REFUSE every plugin that
    /// declares a need (a token endpoint), so the styles that mint would be passed over and their
    /// malformed credentials pass `--validate` that boot refuses (oracle BOOT-035).
    ///
    /// # Errors
    ///
    /// The serving plugin would not open for its outbound styles.
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

/// AN AUTH ROW'S DECLARED DIAGNOSTICS, WRITTEN TO THE MAIN LOG IN 1.5.5'S LINE (ARCHITECT D1
/// 2026-10-05, LOG LINES; THE DESIGN #85).
///
/// 1.5.5 wrote a credential it could not present, and a mint that failed, to the main log; the auth
/// plugin that now holds the credential reports the same condition as a DECLARED diagnostic on the
/// #85 envelope of the call that met it, and this sink writes it there again, word for word, before
/// the row's own log file keeps it too. A plugin's free log records ([`DIAG_LOG`]) stay in its own
/// file only.
///
/// The line: the text up to its first named value is the message; the named values follow as
/// ` name=value`, in 1.5.5's order — `protocol`, `header`, then `error` (which runs to the end) —
/// and are written as the fields 1.5.5 wrote them (`protocol` and `header` as text, `error` as
/// display). A declared id that is a code of the host's catalog (`BUSBAR-NNNN`) is written as the
/// `diag` field, at the level the catalog's severity sets (benign-recurring: debug); any other at
/// the plugin's own severity.
///
/// [`DIAG_LOG`]: busbar_contract::abi::mechanism::call::DIAG_LOG
pub(crate) struct MainLogSink(pub(crate) Arc<dyn crate::root::loader::dispatch::EnvelopeSink>);

impl MainLogSink {
    /// `text` split into its message and the named values 1.5.5's line carried.
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

    /// Write one declared diagnostic to the main log.
    fn write(d: &crate::root::loader::dispatch::Diagnostic<'_>) {
        use busbar_contract::diagnostic::Severity;
        use tracing::Level;
        let text = String::from_utf8_lossy(d.text);
        let (message, protocol, header, error) = Self::named(&text);
        let code = std::str::from_utf8(d.name)
            .ok()
            .and_then(|n| n.strip_prefix("BUSBAR-"))
            .and_then(|n| n.parse::<u16>().ok())
            .and_then(busbar_kernel::diagnostics::by_code);
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
            Self::write(&d);
        }
        self.0.diag(d);
    }

    fn dropped(&self, why: crate::root::loader::dispatch::Dropped) {
        self.0.dropped(why);
    }
}

/// THE PROCESS'S OUTBOUND AUTH INSTANCES: the build's linked `auths` rows, then the plugins
/// directory's, on the process's dispatcher, their needs declared on the process's one connector.
/// One set per process, so a style is served by one opened instance (and one tick schedule)
/// whichever plane's member, or whichever configuration generation, binds it. Read only once the
/// connector is booted (the first read pins the connector, `root::connector::the`).
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
        ))
    }))
}

/// WHAT A DOOR PLANE'S MEMBERS ARE REACHED THROUGH, for the process (THE DESIGN §6 steps 2-3, §5):
/// the deployment's providers, the secret seam their credentials resolve through, the auth plugins
/// that serve a style, the connector the planes' needs were declared on, and the client-level
/// ceiling a streamed answer is bounded by.
pub struct DoorReach<'a> {
    /// The providers, by name ([`provider_routes`]).
    pub providers: &'a BTreeMap<String, ProviderRoute>,
    /// The secret seam (shared: a binding refreshed once per lease holds it for its generation).
    pub secrets: Arc<dyn busbar_contract::secret::SecretResolve>,
    /// The auth plugins.
    pub auths: Arc<OutboundAuths>,
    /// The process's connector.
    pub conns: Arc<dyn busbar_contract::conn::PollConns>,
    /// Whole seconds.
    pub stream_ceiling_secs: u64,
    /// The top-level models catalog a section's `session.model` names an entry of
    /// (`root::serve::catalog_routes`, ARCHITECT Q-L5B-ROUTE); `None` = the section's own table.
    pub catalog: Option<&'a std::collections::HashMap<String, busbar_contract::config::ModelCfg>>,
    /// The model-serving pools the plane serving the `pools` map walks
    /// ([`crate::root::model_egress`]); `None` where none is composed.
    pub models: Option<&'a crate::root::model_egress::ModelServing>,
    /// The claims, linked or dropped in, that open at an upgrade
    /// (`crate::root::serve::upgrade_carriers`): a need over one dials its member's base URL in its
    /// own scheme ([`spelled_for`]).
    pub upgrades: Vec<&'static str>,
}

impl std::fmt::Debug for DoorReach<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DoorReach")
            .field("provider_names", &self.providers.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

/// A member's entry in its plane's section: the uniform model-serving map's (#49), else nothing.
fn member_entry<'s>(section: &'s serde_yaml::Value, entry: &str) -> Option<&'s serde_yaml::Value> {
    section.get(RESERVED_MODELS_KEY)?.get(entry)
}

/// The text `key` of a member's entry.
fn entry_text<'s>(entry: &'s serde_yaml::Value, key: &str) -> Option<&'s str> {
    entry.get(key).and_then(serde_yaml::Value::as_str)
}

/// The origin (`scheme://authority`) of a member's URL: what its route is sealed at, the plane
/// spelling the path of every request it sends (a target is a path, joined onto the base).
fn origin_of(url: &str) -> &str {
    let after = url.find("://").map_or(0, |at| at + 3);
    url[after..].find('/').map_or(url, |at| &url[..after + at])
}

/// The reserved `upstream_credentials:` value that lends the caller's credential.
const PASSTHROUGH: &str = "passthrough";

/// The style a passthrough registration presents the caller's credential under: the bearer
/// scheme, as the previous release forwarded it.
const PASSTHROUGH_STYLE: &str = "bearer";

/// The style a `token_exchange:` registration is bound under (ARCHITECT round 5 Q-L3B-EXCHANGE (B)):
/// RFC 8693, busbar's own subject token exchanged per call for the caller's down-scope.
const TOKEN_EXCHANGE_STYLE: &str = "oauth-token-exchange";

/// THE `token_exchange:` BINDING of the registration `registration` (`entry`): its block's
/// `token_url`, `subject_token` (a secret reference, resolved here: busbar's own credential, the
/// binding's) and `subject_token_type`, and the registration's `aud:` as the RFC 8707 `resource`,
/// opened by the auth plugin serving [`TOKEN_EXCHANGE_STYLE`]. `None` when the registration states
/// no exchange.
///
/// # Errors
///
/// The subject token does not resolve, or no auth plugin serves or will bind the style: the load
/// is refused, naming the member.
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
        .open_outbound(TOKEN_EXCHANGE_STYLE, &credential, &settings)
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

/// THE `upstream_credential:` BINDING of the registration `registration` (the member
/// `member_name`): busbar's own credential for the member, its `secret` reference resolved here
/// (the plane validates the block and never resolves it: `BUSBAR-1.6.0.md` Part 3 section 4,
/// "credentials are auth objects, never a host-minted header"), opened by the auth plugin serving
/// the style its `placement` names: `bearer` (absent = it) presents `authorization: Bearer
/// <secret>`, `{header: <name>}` presents the secret verbatim in that header (the `api-key` style
/// over that header). The kernel presents it on every request to the member through the auth
/// kind's per-request call, which reads the binding's current handle and nothing else; the
/// credential is re-resolved OFF the request path, by the host's refresher once per lease
/// (`lease_ttl_ms`, [`refresher`]; ARCHITECT ruling on #787, THE DESIGN §11: no blocking, plugin
/// memory valid to its next refresh generation). `None` when the registration states no such
/// block.
///
/// # Errors
///
/// The block is malformed, its secret does not resolve, or no auth plugin serves or will bind the
/// style: the load is refused, naming the member.
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

/// [`upstream_credential_binding`]'s binding and the [`PerHop`] it presents through, opened over
/// the value resolved now and kept by nothing: the caller hands it to the [`refresher`] (or, in a
/// cell, refreshes it by hand).
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
    /// The style a `bearer` placement is bound under.
    const BEARER_STYLE: &str = "bearer";
    /// The style a `{header: <name>}` placement is bound under: the named header, verbatim.
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
            // The decoder's own error is NOT carried: its input is where an operator pastes the
            // secret itself, and a decoder names what it could not read (a flow map `{sk-...}` is
            // an "unknown field" quoting it). The refusal names the binding and the shapes.
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
    // THE LEASE: how long one resolution of the credential may be presented, and so how often
    // the refresher re-resolves it (the grammar's `lease_ttl_ms`, greater than zero).
    let lease = block
        .get(CREDENTIAL_LEASE_TTL_KEY)
        .and_then(serde_yaml::Value::as_u64)
        .filter(|ms| *ms > 0)
        .map(std::time::Duration::from_millis)
        .ok_or_else(|| {
            format!(
                "member '{member_name}': its \
                 `{UPSTREAM_CREDENTIAL_KEY}.{CREDENTIAL_LEASE_TTL_KEY}` is not a lease in \
                 milliseconds greater than zero"
            )
        })?;
    let settings = placement_settings(header.as_deref());
    let credential = busbar_contract::redacted::Secret::new(
        reach
            .secrets
            .resolve_string_at_config(&secret, scope)
            .map_err(|e| {
                format!(
                    "member '{member_name}': busbar's own upstream credential for it cannot \
                     resolve: {e}"
                )
            })?
            .into_bytes(),
    );
    let (auth, decl) = reach.auths.serving(style, &settings)?.ok_or_else(|| {
        format!(
            "member '{member_name}': no linked or dropped-in auth plugin serves the style \
             '{style}' its upstream credential is presented under"
        )
    })?;
    // Revealed under the kernel's seal (Part 2 #54): to open the binding, and for its digest.
    let seal = busbar_kernel::seal::lend();
    let handle = auth
        .open_outbound(style, credential.expose(&seal), &settings)
        .map_err(|e| format!("member '{member_name}' {e}"))?;
    // The binding holds the reference and the digest of the value its handle was opened with,
    // never the value.
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
        }),
        refreshing: Mutex::new(()),
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

/// THE OUTBOUND SETTINGS an `upstream_credential:` placement opens its style under: none for
/// `bearer`, `{header: <name>}` for a named header. Built from the typed placement each time a
/// binding opens, so no binding holds a settings bag.
fn placement_settings(header: Option<&str>) -> serde_json::Value {
    header.map_or_else(
        || serde_json::json!({}),
        |name| serde_json::json!({ busbar_contract::section::PLACEMENT_HEADER_KEY: name }),
    )
}

/// What a [`PerHop`] presents now: the handle its auth instance opened, and the SHA-256 of the
/// value it was opened with (the value itself is never kept).
struct Held {
    digest: [u8; 32],
    handle: u64,
}

/// A REGISTRATION'S OWN CREDENTIAL, REFRESHED OFF THE REQUEST PATH (`upstream_credential:`): the
/// reference, the secret seam it resolves through, the auth instance, the style it is bound under,
/// the header a named-header placement names and its lease, and, in one swap cell, what it
/// presents now ([`Held`]; empty = refused). A hop only LOADS the cell ([`PerHop::handle_now`]):
/// no resolution, no open, no lock (ARCHITECT ruling on #787: a secret resolution blocks its
/// thread up to its deadline, `busbar_contract::secret::SecretCalls`, and is never made on the
/// request path). [`PerHop::refresh`] re-resolves the value, re-opens the binding only when its
/// digest changed (handles grow by rotations, never by hops), and swaps the cell whole, so a hop
/// sees the old handle or the new one; a value that no longer resolves or binds EMPTIES the cell,
/// so every hop after it is refused, never served a stale credential.
struct PerHop {
    secret: busbar_contract::secret_ref::SecretRef,
    secrets: Arc<dyn busbar_contract::secret::SecretResolve>,
    auth: Arc<dyn busbar_contract::auth_calls::OutboundAuth>,
    style: &'static str,
    header: Option<String>,
    /// The lease: how often the [`refresher`] re-resolves the credential.
    lease: std::time::Duration,
    held: arc_swap::ArcSwapOption<Held>,
    /// Taken by [`PerHop::refresh`] alone, so two refreshes never open the same rotation twice;
    /// no hop ever waits on it.
    refreshing: Mutex<()>,
}

impl PerHop {
    /// RE-RESOLVE the credential and swap what the binding presents: the same value keeps its
    /// handle; a changed one is opened (outside every lock a hop could wait on) and swapped in
    /// whole; one that no longer resolves, or whose new value will not bind, empties the cell (fail
    /// closed). Off the request path only: the binding's build, and the [`refresher`]'s own thread,
    /// each holding the config-time proof (THE DESIGN §11.11 R4: a refresh is config time).
    fn refresh(&self, scope: &busbar_contract::config_time::ConfigScope) {
        let _one = self
            .refreshing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Ok(value) = self.secrets.resolve_string_at_config(&self.secret, scope) else {
            self.held.store(None);
            return;
        };
        let value = busbar_contract::redacted::Secret::new(value.into_bytes());
        // Revealed under the kernel's seal (Part 2 #54): for its digest, and to open a rotation.
        let seal = busbar_kernel::seal::lend();
        let digest = busbar_contract::abi::sdk::digest::sha256(value.expose(&seal));
        if self
            .held
            .load()
            .as_ref()
            .is_some_and(|held| busbar_contract::redacted::constant_time_eq(&held.digest, &digest))
        {
            return;
        }
        let opened = self.auth.open_outbound(
            self.style,
            value.expose(&seal),
            &placement_settings(self.header.as_deref()),
        );
        drop(value);
        self.held
            .store(opened.ok().map(|handle| Arc::new(Held { digest, handle })));
    }
}

/// A `PerHop` NAMES NO CREDENTIAL in a debug line: it holds the reference and a digest, never the
/// value, and renders neither (a derived `Debug` over a reference to a literal or a digest would put
/// the one in a log line and a guessing oracle for the other in it).
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

impl busbar_contract::auth_calls::PerRequestHandle for PerHop {
    fn handle_now(&self) -> Option<u64> {
        self.held.load().as_ref().map(|held| held.handle)
    }
}

/// THE HOST'S CREDENTIAL REFRESHER: one thread of its own (never a runtime worker, never a
/// dispatcher worker's crossing) that re-resolves each live [`PerHop`] once per its lease. It keeps
/// each binding WEAKLY, so a binding its generation dropped (a config apply builds the next
/// generation's bindings, and the last request on the old one lets it go) is forgotten at its next
/// due time, never refreshed again.
mod refresher {
    use super::PerHop;
    use std::sync::{Arc, Condvar, Mutex, Once, Weak};
    use std::time::Instant;

    /// One kept binding and when it is next due.
    struct Kept {
        per: Weak<PerHop>,
        due: Instant,
    }

    /// The kept bindings, and the signal a new one wakes the thread with.
    struct Book {
        kept: Mutex<Vec<Kept>>,
        woken: Condvar,
    }

    /// The process's one book.
    static BOOK: Book = Book {
        kept: Mutex::new(Vec::new()),
        woken: Condvar::new(),
    };

    /// The process's one book, its thread started the first time it is reached.
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

    /// Keep `per`, first due one lease from now (its build has just resolved it).
    pub(super) fn keep(per: &Arc<PerHop>) {
        let book = kept_book();
        book.kept
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(Kept {
                per: Arc::downgrade(per),
                due: Instant::now() + per.lease,
            });
        book.woken.notify_one();
    }

    /// The thread: refresh every binding that is due, forget every one dropped, sleep to the next
    /// due time (or a new binding). The book's lock is never held across a refresh.
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
                    k.due = now + per.lease;
                    due.push(per);
                }
            }
            if !due.is_empty() {
                drop(kept);
                // THE REFRESHER'S TICK IS CONFIG TIME (BUSBAR-1.6.0.md l.1468, R4: "boot, config
                // apply, refresh"): the proof is minted here, once per tick, and handed down.
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

    /// Refresh every live kept binding NOW, on the calling thread (a cell that rotates or removes
    /// a served credential, then asserts what the first hop after the refresh presents).
    #[cfg(test)]
    #[allow(dead_code)] // reached only by a door plane's own root cells, which a build may not link
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

/// [`refresher`]'s refresh of every live served credential, for the door planes' own root cells.
#[cfg(test)]
#[allow(dead_code)] // reached only by a door plane's own root cells, which a build may not link
pub(crate) fn refresh_credentials() {
    refresher::refresh_all();
}

/// THE DOOR'S OWN REQUESTS TO ITS REGISTRATION MEMBERS carry each member's binding (round 4 (d):
/// "admin connect + verify-on-call fetches use the same binding"): every registration member's
/// route with an auth binding (`routes`, on the plane's member-target need `served` states) is held
/// on the plane's connection table `table`, its passthrough credential lent from the unit records
/// `units` by the unit the request is made inside. The connector keys a binding by (`instance`,
/// need, member, target origin); a request naming no member gets no binding. So two registrations
/// at one origin each present their own, and one with no binding presents none (predev `creds.rs`
/// `Lease::header_for`, `LeaseError::WrongAgent`).
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
        // EVERY member-target need the member rides carries its binding: the plane's own requests
        // on any of them present what the walk's do.
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

/// THE MEMBER-TARGET NEEDS a plane states (`settings.*.<key>`,
/// `busbar_contract::section::member_target`), in its Statement's order, each with the
/// registration key its target is read from.
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

/// EVERY NEED A MEMBER ROUTE RIDES, its own first, each with the base URL it dials
/// (`MemberRoute::ride`).
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

/// THE MEMBERS' ROUTES of one door plane (THE DESIGN §6 steps 2-3, sealed at its composition):
/// each entry of its section's model-serving map, by the provider it names (#49), is reached at
/// that provider's `base_url`, under the style the provider's `auth:` states, else the plane's
/// default for the member's dialect (its entry's `protocol`/`dialect` override, else the
/// provider's protocol, #51; `dialect_auth`), on the outbound need that style names
/// ([`busbar_kernel::plane_driver::resolve_member_needs`]), its credential bound by the auth plugin
/// serving the style (`open_outbound`; the plugin keeps the binding, the route keeps the handle).
///
/// # Errors
///
/// A member whose provider is not configured, whose style is stated nowhere, whose style no need
/// (or more than one) names, whose credential does not resolve, or whose style no auth plugin
/// serves or will bind: the load is refused, naming the member.
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
        /// The dialect default style's parameters, when the style is that default.
        params: &'static [u8],
    }
    let mut resolved = Vec::new();
    let mut registered = BTreeMap::new();
    // A REGISTRATION MEMBER (ARCHITECT Q-L3B-ROUTES): where the plane's need states a member-target
    // path, an entry the section registers is reached at its own target, read off the registration;
    // on EVERY member-target need the plane states (the providers' rides, ARCHITECT Q-L5B-NEEDS):
    // the first as its own, each other one riding beside it at the target it names.
    let member_targets = member_target_needs(served);
    let member_target = member_targets.first().copied();
    // A PROGRAM MEMBER (ARCHITECT round 5 Q-L3B-STDIO-UPSTREAM (A)): where the plane's need states
    // the member-program path, an entry whose registration names a program is reached at its own
    // long-lived program, which the connector keeps per member (the loader declared each one from
    // the instance's settings); its route's base is the member's own name, the open's target.
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
                    // Each other member-target need the registration names a target for rides
                    // beside its own, held to the same anchors; one whose target is another
                    // origin dials that origin.
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
            // A PROGRAM MEMBER (the program-upstream ruling (A)): a registration that names a program is
            // reached at its own long-lived child, the connector keeps it per member.
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
        // A member whose own protocol states no default style (one its plane serves over another
        // dialect's envelope) rides its provider's protocol's default: the credential is the
        // provider's.
        let default = default_of(dialect).or_else(|| default_of(&provider.protocol));
        // The provider's own `auth:` binds its style alone; the dialect's default carries its
        // declared parameters (Q-L6-AUTHPARAMS).
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
    // Each registration member: reached at its own target on the member-target need, its metering
    // rows naming the registration; its auth binding is the registration's own (ARCHITECT round 4
    // Q-SURFACES (d)): `upstream_credentials: passthrough` (the entry's, else the section's reserved
    // default) lends the caller's verified credential to the member's one outbound auth call
    // (MODE_PASSTHROUGH; a caller who presented none presents nothing), a `token_exchange:` block
    // binds the RFC 8693 exchange style (round 5 Q-L3B-EXCHANGE (B)), any other sends none of the
    // providers' credentials.
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
            // A `token_exchange:` registration (ARCHITECT round 5 Q-L3B-EXCHANGE (B)): busbar's own
            // subject token, exchanged per call for the caller's down-scope the plane states; else
            // an `upstream_credential:` registration: busbar's own credential, presented per request.
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
    // Each program member: no auth binding (no credential rides a pipe), its metering rows naming
    // the registration.
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
            Vec::new()
        } else {
            reach
                .secrets
                .resolve_at_config(&r.provider.credential, scope)
                .map_err(|e| format!("provider '{}' credential: {e}", r.name))?
        };
        // A service-account credential naming its key file is read here, at configuration time,
        // through the secret kind's file source: the serving plugin is handed the JSON and opens no
        // file (Q128 audit ruling (a)).
        let credential = if r.style == SERVICE_ACCOUNT_STYLE {
            busbar_kernel::config_validate::service_account_json(credential, |file| {
                reach.secrets.resolve_at_config(file, scope)
            })
            .map_err(|e| format!("provider '{}' (jwt-bearer auth): {e}", r.name))?
        } else {
            credential
        };
        let settings = sealed_params(&r.name, &r.style, r.provider, &credential)?.to_json();
        let (auth, decl) = reach.auths.serving(&r.style, &settings)?.ok_or_else(|| {
            format!(
                "member '{}': no linked or dropped-in auth plugin serves the style '{}'",
                r.entry, r.style
            )
        })?;
        let settings = sealed_settings(r.params, &r.provider.base_url, &settings)
            .map_err(|e| format!("member '{}': {e}", r.entry))?;
        let handle = auth
            .open_outbound(&r.style, &credential, &settings)
            .map_err(|e| format!("provider '{}' {e}", r.name))?;
        // EVERY need its style names is bound (ARCHITECT Q-L5B-NEEDS): the first is its own, the
        // rest ride beside it, each opened when a far request names it.
        let bound = dialled
            .get(&r.entry)
            .filter(|b| !b.is_empty())
            .ok_or_else(|| format!("member '{}' dials no need", r.entry))?;
        let need = bound[0];
        let rides = bound[1..]
            .iter()
            .map(|n| (*n, busbar_kernel::plane_driver::ResponseKeep::default()))
            .collect();
        // A bound need over a framer composed over the base URL's carrier dials the base URL in
        // that framer's own scheme.
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
                // The provider URL's basic credential leads the binding's answers (row 74): the
                // kernel is handed the binding, never the bytes.
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

/// THE SETTINGS A MEMBER'S BINDING IS OPENED WITH (ARCHITECT RULING 2026-10-03, Q-L6-AUTHPARAMS;
/// ruling 2026-09-28: the kernel resolves the dialect's declared parameters at seal into
/// `OpenOutboundIn::settings`): the dialect's `params` object, each value written
/// `{"host_label_after": [labels], "default": word, "unread": warning}` resolved from the provider's
/// `base_url` host ([`host_label`]; `default` when no label reads, its `unread` warning then handed
/// on as `<key>_unread` for the binding to log with each use), then the provider's own settings
/// over it.
///
/// # Errors
///
/// Parameters that are not a JSON object, or a host directive that is malformed.
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
                // The operator warning the dialect states for a host its rule cannot read, handed
                // to the binding as `<key>_unread`: the plugin logs it where 1.5.5 did, with each
                // use of the default.
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

/// The host of `base_url`, the one the request dials: its authority read by the one split
/// ([`busbar_contract::net::url_authority`]), before its port.
fn base_url_host(base_url: &str) -> &str {
    busbar_contract::net::url_authority(base_url)
        .host_port
        .split(':')
        .next()
        .unwrap_or("")
}

/// The dotted label of `host` right after the first of `after`, when it reads as a dashed name
/// ending in a number (three parts or more, every part before the last alphabetic, the last all
/// digits: the shape the dialect's own rule accepted, 1.5.5's region derivation).
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

/// The `auth:` style whose credential names its own token endpoint: a service account's
/// `token_uri` (RFC 7523; `jwt-bearer`, 1.5.5's `egress_auth/jwt_bearer.rs`).
const SERVICE_ACCOUNT_STYLE: &str = "jwt-bearer";

/// THE PARAMETERS PROVIDER `name`'s STYLE IS OPENED WITH AT THE SEAL: those it states, and, for
/// a service-account credential, its `token_uri` — the target of the serving plugin's mint need —
/// judged under the provider's metadata posture with 1.5.5's check and words (v1.5.5 `main.rs`:
/// `provider '<p>' (jwt-bearer auth): <why>`). A credential that is no service account to read
/// fills nothing: the serving plugin refuses it in its own words at `open_outbound`.
///
/// # Errors
///
/// The service account's `token_uri` breaks 1.5.5's rule.
fn sealed_params(
    name: &str,
    style: &str,
    provider: &ProviderRoute,
    credential: &[u8],
) -> Result<StyleParams, String> {
    let mut params = provider.params.clone();
    if style != SERVICE_ACCOUNT_STYLE || credential.is_empty() {
        return Ok(params);
    }
    let Ok(text) = std::str::from_utf8(credential) else {
        return Ok(params);
    };
    let Ok(token_uri) = busbar_kernel::config_validate::service_account_token_uri(text) else {
        return Ok(params);
    };
    busbar_kernel::config_validate::vet_token_uri(&token_uri, &provider.metadata)
        .map_err(|e| format!("provider '{name}' (jwt-bearer auth): {e}"))?;
    params.token_uri = Some(token_uri);
    Ok(params)
}

/// THE BASE URL A NEED'S FRAMER READS: a need over `transport`, a claim that opens at an upgrade of
/// the connection the operator's `base_url` names (`upgrades`: the linked claims that open at an
/// upgrade, `crate::root::serve::upgrade_carriers`), dials the same authority and path under the
/// framer's own scheme, its secured form for a secured base (`http://h` -> `<key>://h`,
/// `https://h` -> `<key>s://h`, the pairing every upgrade-over-HTTP scheme keeps, RFC 6455 section
/// 3). `None` when the need dials the base URL as written.
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

/// THE TRUST ANCHORS OF ONE REGISTRATION MEMBER (ARCHITECT 2026-10-03, THE TRANSPORT PIN: "the connector enforces pins itself"): its pin's key, where the plane declares the pin's
/// mechanism pins the far end's key (`PinMechanismDecl::peer_key`), and busbar's client identity,
/// where the member-target need's `trust_from` names a member path (`settings.*.<key>`) and the
/// registration writes it (`{cert, key}`, secret references, resolved here once), and its PRIVATE
/// REACH where the plane declares that key (`abi::plane::TRUST_PRIVATE_REACH`: the member's need,
/// alone, may dial a private address at the member's own target). The connector holds every
/// connection to the member to them ([`compose_egress`] seals them).
///
/// # Errors
///
/// The registration's pin breaks its rule, or its client identity does not resolve or parse:
/// the load is refused, naming the member.
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
    // THE REGISTRATION'S PRIVATE REACH (`abi::plane::TRUST_PRIVATE_REACH`, SEAM-4f): sealed beside
    // its pin, honoured by the connector's one guard for this member's need alone.
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

/// THE REFUSAL OF A PEER-KEY PIN THAT NAMES NO DIGEST, at the registration `at`
/// (`` `<section>.<name>` ``): the field, and the form it takes. The value is not echoed: what was
/// pasted there may not be a public key digest at all.
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

// A registration's anchors read here, sealed on the in-tree connector over this build's linked
// wires and dialled over real TLS: the build links a wire to dial over, and the plane door whose
// section's registrations seal a peer-key pin and a client identity.
#[cfg(all(test, linked_axis_transport_door, linked_section_agents))]
#[path = "tests/registration_pin.rs"]
mod registration_pin_tests;
