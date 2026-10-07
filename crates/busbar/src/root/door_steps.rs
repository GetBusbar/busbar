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
//! | verify | the route the plane's `arrive` named, resolved against its section ([`DoorPools`], ARCHITECT Q-SW6/Q-FL3), a `ROUTE_SCOPE` unit to the one entry the principal's grant reaches among the plane's candidates (Q-DEL-A2A-SELECT, -SCOPE-TRUST); each member sealed under its (plane key, entry) |
//! | approve | the caller's grant of the plane's scope kind over the route as named, then its fallback pool |
//! | admit | a unit its plane answers itself (`ROUTE_LOCAL`) is admitted with no walk and nothing held or charged; `$`: a keyed unit is admitted and charged by the governance book's one check-then-charge (`GovState::try_admit_estimated`, the plane's expected units the estimate), its money facts opened on the money steps (`PlaneMoney::open`); a route its section does not hold is refused after the charge (1.5.5's order); an anonymous unit on an open claim is admitted with nothing held and no money |
//! | meter | the plane's last far-end-reported counts, as the unit's usage lines (an estimate never bills) |
//! | audit | the record's facts: the decoded operation class and how the unit finished |
//!
//! The money steps (`busbar_kernel::plane_driver::PlaneMoney`) ledger the unit at its end: the
//! kernel writes what the plane reported, priced at read time against the card in force (money is a
//! view: `money = f(ledger, ratecard)`).

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use busbar_contract::abi::plane::{
    units_bill, UnitCount, ROUTE_DIRECT, ROUTE_LOCAL, ROUTE_POOL, ROUTE_SCOPE,
    ROUTE_SCOPE_SEPARATOR,
};
use busbar_contract::caps::{
    Admit, Admittance, Approve, Arrival, Audit, Authenticate, Authenticated, Consumption, Decode,
    Dial, Encode, Grant, Meter, OpClassId, Outcome, Pass, PrincipalId, QuantitySource, ReasonCode,
    Refusal, Route, SeatVerdict, UsageLine, VerifiedDestination, Verify,
};
use busbar_contract::records::VirtualKey;
use busbar_contract::section::{
    MODEL_PROTOCOL_KEYS, MODEL_PROVIDER_KEY, POOL_MEMBERS_KEY, RESERVED_MODELS_KEY,
    RESERVED_POOLS_KEY, RESERVED_SECTION_KEYS, RESERVED_WORK_KEY,
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
}

/// A resolved route: its pool label (empty for a direct route) and its member entries.
pub type Routed = (String, Vec<String>);

impl DoorPools {
    /// The pools `section` states.
    #[must_use]
    pub fn of(section: &serde_yaml::Value) -> Self {
        let Some(map) = section.as_mapping() else {
            return Self::default();
        };
        let key = |k: &serde_yaml::Value| k.as_str().map(str::to_owned);
        // A model-serving section's entries are its `models` map's; any other section's are its own
        // top-level registrations.
        let entries = match map
            .get(RESERVED_MODELS_KEY)
            .and_then(serde_yaml::Value::as_mapping)
        {
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
        let pools = map
            .get(RESERVED_POOLS_KEY)
            .and_then(serde_yaml::Value::as_mapping)
            .map(|pools| {
                pools
                    .iter()
                    .filter_map(|(name, pool)| Some((key(name)?, members(pool))))
                    .collect()
            })
            .unwrap_or_default();
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
        DoorPools {
            entries,
            pools,
            fallbacks,
            member_granted,
        }
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

impl DoorPools {
    /// WHETHER THE CALLER'S GRANT ADMITS THE ROUTE AS NAMED, judged before its destination (1.5.5's
    /// order: the pool's grant, then its fallback pool's; an unknown pool is refused by its grant
    /// first, and only then by its absence). A direct route's grant names its entry. Ungoverned
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
        let fallback = (class == ROUTE_POOL)
            .then(|| self.fallbacks.get(name))
            .flatten();
        std::iter::once(name)
            .chain(fallback.map(String::as_str))
            .all(|granted| key.scope_allowed(kind, granted))
    }
}

/// A pool's member entries: its `members` list, each an entry name or a member naming one.
fn members(pool: &serde_yaml::Value) -> Vec<String> {
    pool.get(POOL_MEMBERS_KEY)
        .and_then(serde_yaml::Value::as_sequence)
        .map(|list| {
            list.iter()
                .filter_map(|m| {
                    m.as_str()
                        .or_else(|| m.get("name").and_then(serde_yaml::Value::as_str))
                        .map(str::to_owned)
                })
                .collect()
        })
        .unwrap_or_default()
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
    /// (`busbar_translations_total`), as the previous release counted it. Empty = none counted.
    pub translations: (Arc<[String]>, Arc<BTreeMap<String, String>>),
    /// The plane's declared breaker fact (`declares.breaker`, ARCHITECT Q4): whether a transient
    /// failure below the trip threshold benches a member's cell. `None`: it declares none, and
    /// every cell keeps the host's default.
    pub bench_below_trip_threshold: Option<bool>,
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
    /// The end its plane reported for a reply the far end cut (abi/plane `PIECE_CUT`); `None`
    /// when the unit's outcome decides.
    reported: Option<busbar_contract::FinishClass>,
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
    credential: Option<busbar_contract::redacted::Redacted<Vec<u8>>>,
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
    pub credential: Option<busbar_contract::redacted::Redacted<Vec<u8>>>,
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
    pub fn wants_stream(&self) -> bool {
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
    ///
    /// A BUDGET BLOCK THAT DOWNGRADES re-admits the unit on its `downgrade_to` pool through the
    /// kernel's one walk (`busbar_kernel::ingress::admit_downgrading`; v1.5.5
    /// `ingress/mod.rs:169-225` `admit_check`), each hop's pool judged by the key's grants as the
    /// route as named was; the unit is then served by the pool it was charged on, as 1.5.5
    /// dispatched through the effective pool (v1.5.5 `ingress/dispatch.rs:206`).
    fn charge(&self, ctx: &UnitCtx, key: &Arc<VirtualKey>) -> Result<bool, Refusal> {
        let (Some(gov), Some(money)) = (self.app.governance.as_ref(), self.money) else {
            return Ok(false);
        };
        let (routed, expected) = {
            let u = self.lock();
            (u.routed.clone(), u.expected.clone())
        };
        let label = routed.as_ref().map_or("", |(label, _)| label.as_str());
        // The lanes a pool's members are sealed on: the route as named (`label`) reads its own
        // routed members, a pool a downgrade reaches its resolved ones.
        let lanes_of = |at: &str| -> Vec<String> {
            let lanes = |members: &[String]| -> Vec<String> {
                members
                    .iter()
                    .map(|m| plane_lane(&self.facts.plane, m))
                    .collect()
            };
            if at == label {
                routed
                    .as_ref()
                    .map_or_else(Vec::new, |(_, m)| lanes(m.as_slice()))
            } else {
                self.pools
                    .resolve(ROUTE_POOL, Some(at.as_bytes()))
                    .map_or_else(Vec::new, |(_, m)| lanes(m.as_slice()))
            }
        };
        // The route as named, read once: the pool it is charged on and its lanes, which the first
        // admission and (with no downgrade) the money facts share.
        let named = (self.charged_pool(label), lanes_of(label));
        let units = self.expected_units(&expected);
        let view = DoorPoolView {
            pools: self.pools,
            key: Some(key.as_ref()),
            app: &self.app,
        };
        let configured = self.pools.pools();
        let (grant, effective) = busbar_kernel::ingress::admit_downgrading(
            &key.id,
            label,
            configured.len(),
            |to| configured.contains_key(to),
            // A downgrade pool is judged as the route as named was: the grant `approve` reads, and
            // for the plane serving the `pools` map the destination guard `verify` reads.
            |to| {
                self.pools.granted(
                    self.facts.scope_kind.as_deref(),
                    Some(key.as_ref()),
                    ROUTE_POOL,
                    Some(to.as_bytes()),
                ) && (!self.facts.plane.is_empty() || busbar_kernel::door::may_reach(&view, to))
            },
            |at| {
                let admit = |pool: &str, lanes: &[String]| {
                    let models: Vec<&str> = lanes.iter().map(String::as_str).collect();
                    gov.try_admit_estimated(
                        &self.app.cost,
                        key,
                        pool,
                        self.arrived,
                        &models,
                        &units,
                    )
                };
                if at == label {
                    admit(named.0.as_str(), named.1.as_slice())
                } else {
                    admit(self.charged_pool(at).as_str(), lanes_of(at).as_slice())
                }
            },
        )
        .map_err(|blocked| {
            // The plane serving the `pools` map answers a blocked admission in the previous
            // release's words (`busbar_kernel::ingress::limit_refusal`).
            if self.facts.plane.is_empty() {
                self.lock().refused.1 = Some(busbar_kernel::ingress::limit_refusal("", &blocked).2);
            }
            refusal_for(&blocked)
        })?;
        if let Some(to) = &effective {
            self.lock().routed = self.pools.resolve(ROUTE_POOL, Some(to.as_bytes()));
        }
        let (pool, lanes) = match effective.as_deref() {
            Some(at) if at != label => (self.charged_pool(at), lanes_of(at)),
            _ => named,
        };
        money.open(
            ctx.key,
            UnitMoney {
                key: Arc::clone(key),
                cost: Arc::clone(&self.app.cost),
                pool,
                // The first member until one answers; the money steps take the serving member's
                // own key when its answer commits (`MoneySeam::served`).
                model: lanes.into_iter().next().unwrap_or_default(),
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

/// The record's facts for a unit of these steps: a completed unit seals the end its plane
/// reported where it reported one (a reply the far end cut: `Partial`, or `Error` when nothing of
/// it reached the caller), `Complete` where it did not; any other outcome seals `Error`.
fn facts(
    op: OpClassId,
    outcome: &Outcome,
    reported: Option<busbar_contract::FinishClass>,
) -> busbar_contract::AuditFacts {
    let completed = outcome.is_completed();
    busbar_kernel::door::admitted_facts(op, reported.filter(|_| completed), completed)
}

impl DriverSteps for DoorSteps<'_> {
    fn decoded(&self, _ctx: &UnitCtx, op: OpClassId, route: u8, pool: Option<&[u8]>) {
        let mut u = self.lock();
        u.op = Some(op);
        u.named = Some((route, pool.map(<[u8]>::to_vec)));
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

    fn refusal_words(&self, reason: ReasonCode) -> Option<Vec<u8>> {
        // A unit routed by scope that no one entry reached: the entries that reached it (none, or
        // several), so the plane words which (abi/plane `ROUTE_SCOPE`).
        let u = self.lock();
        let scoped = u
            .named
            .as_ref()
            .is_some_and(|(class, _)| *class == ROUTE_SCOPE);
        (reason == ReasonCode::NoDestination && scoped)
            .then(|| u.reachable.join(ROUTE_SCOPE_SEPARATOR).into_bytes())
    }

    fn route_flags(&self, _ctx: &UnitCtx, flags: u8) {
        let mut u = self.lock();
        u.once = flags & busbar_contract::abi::plane::ROUTE_ONCE != 0;
        u.stream = flags & busbar_contract::abi::plane::ROUTE_STREAM != 0;
    }

    fn affinity(&self, _ctx: &UnitCtx, hash: u64) {
        self.lock().affinity = Some(hash);
    }

    fn reported_finish(&self, _ctx: &UnitCtx, finish: busbar_contract::FinishClass) {
        self.lock().reported = Some(finish);
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
        // A UNIT ROUTED BY SCOPE (ROUTE_SCOPE, ARCHITECT Q-DEL-A2A-SELECT: scope seals the
        // destinations): the one entry the principal's grant of the plane's scope kind reaches is
        // its route, directly; zero or several seal nothing and it is refused at admission, the
        // several named in its refusal's words.
        let named_scope = match &self.lock().named {
            Some((ROUTE_SCOPE, candidates)) => Some(candidates.clone()),
            _ => None,
        };
        if let Some(candidates) = named_scope {
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
                [one] => u.named = Some((ROUTE_DIRECT, Some(one.as_bytes().to_vec()))),
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
        // A unit routed by scope that no one entry reached names its candidates, not a route: the
        // grant was the resolution itself, and admission refuses it (no destination).
        if class == ROUTE_SCOPE
            || self.pools.granted(
                self.facts.scope_kind.as_deref(),
                self.key.as_deref(),
                class,
                named.as_deref(),
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
        let local = self
            .lock()
            .named
            .as_ref()
            .is_some_and(|(class, _)| *class == ROUTE_LOCAL);
        // A UNIT ROUTED BY SCOPE that no one entry reached (Q-DEL-A2A-SELECT): refused before
        // anything is charged, as 1.5.5 chose the agent before its admission.
        let unrouted_scope = self
            .lock()
            .named
            .as_ref()
            .is_some_and(|(class, _)| *class == ROUTE_SCOPE);
        if unrouted_scope && !matches!(admission(self.key.as_ref(), self.open), Admission::Refused)
        {
            return SeatVerdict::refuse(token, Refusal::new(ReasonCode::NoDestination));
        }
        match admission(self.key.as_ref(), self.open) {
            Admission::Refused => {
                return SeatVerdict::refuse(token, Refusal::new(ReasonCode::Unauthenticated))
            }
            Admission::Keyed if !local => {
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
            if let Ok(accrual) = cell.accrue_child(principal, 0, admit) {
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
        let (op, reported) = {
            let u = self.lock();
            (u.op.unwrap_or(self.facts.audit_kind), u.reported)
        };
        SeatVerdict::proceed(token, facts(op, outcome, reported))
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
            facts(op, &Outcome::Refused(step, refusal.reason()), None),
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
        bench_below_trip_threshold: None,
    }
}

// ── the egress ───────────────────────────────────────────────────────────────────────────────────

/// THE EGRESS OF ONE DOOR PLANE, sealed for a generation (`BUSBAR-1.6.0.md` Part 3 §12 "The route
/// pump": the route step is the kernel's existing egress walk; Part 4 Axis 3 / THE DESIGN §5: the
/// host owns the allow-list, pin, breaker and meter valves, and the wire is the connector's): the
/// plane instance `caller`'s connection table `conns` (the connector its needs were declared on),
/// one member per entry `routes` seals (each named by its (plane key, entry), Q-FL3), a pool per
/// named pool of its section (its members, its fallback pool) and a pool per entry its direct
/// routes walk, the breaker under every pool's default ladder, the members' permits, the node's
/// clock and counters, and `journal` (the write-ahead dispatch record, `$`, ARCHITECT P3 (c)).
///
/// # Errors
///
/// A named pool whose member entry has no sealed route: the load is refused, naming both.
pub fn compose_egress(
    facts: &DoorFacts,
    pools: &DoorPools,
    caller: busbar_contract::conn::InstanceId,
    conns: Arc<dyn busbar_contract::conn::PollConns>,
    routes: &BTreeMap<String, busbar_kernel::plane_driver::MemberRoute>,
    journal: Arc<dyn busbar_kernel_egress::ports::Journal>,
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
        // to the member, the walk's and the plane's own, is held to them by the connector itself.
        conns
            .anchor(caller, route.need, &route.base_url, &route.anchors)
            .map_err(|e| format!("member '{entry}': its trust anchors could not be sealed: {e}"))?;
        // THE REGISTRATION'S PRIVATE REACH, sealed for this registration alone (SEAM-4k): the
        // member route's dials name it, and no other registration at the same authority holds it.
        conns
            .seal_reach(
                caller,
                route.need,
                &route.provider,
                &route.base_url,
                route.anchors.private_reach,
            )
            .map_err(|e| format!("member '{entry}': its private reach could not be sealed: {e}"))?;
        let destination = busbar_contract::dest::DestinationId::new(id);
        let name = plane_lane(&facts.plane, entry);
        members.insert(entry.clone(), Member::new(destination, name.clone(), 1));
        sealed.insert(destination, route);
        names.push((destination, name));
    }
    let mut built: HashMap<String, Pool> = HashMap::new();
    for (label, entries) in pools.pools() {
        let list = entries
            .iter()
            .map(|e| {
                members.get(e).cloned().ok_or_else(|| {
                    format!("pool '{label}' names entry '{e}', which has no sealed route")
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
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
    // Every cell of this plane's members under the default ladder, with the plane's declared
    // breaker fact where it states one (ARCHITECT Q4); where it states none, the default holds.
    let cell = || {
        let mut cfg = busbar_kernel::store::pool_breaker_cfg(None);
        if let Some(bench) = facts.bench_below_trip_threshold {
            cfg.bench_below_trip_threshold = bench;
        }
        cfg
    };
    let policy = built.keys().fold(
        crate::root::adapters::BreakerPolicy::new().with_default_cell(cell()),
        |policy, pool| policy.with_pool(pool.as_str(), cell()),
    );
    Ok(busbar_kernel::plane_driver::Egress {
        caller,
        conns,
        breaker: Arc::new(crate::root::adapters::BreakerAdapter::with_policy(policy)),
        capacity: Arc::new(crate::root::egress_ports::MemberPermits::new(Vec::new())),
        clock: Arc::new(crate::root::egress_ports::NodeClock::new()),
        journal,
        telemetry: Arc::new(crate::root::egress_ports::WalkTelemetry::new(names)),
        floor: busbar_kernel_egress::WeightedFloor::new(),
        pools: built,
        routes: sealed,
        stream_ceiling_secs,
        error_body_max: busbar_kernel::plane_driver::DEFAULT_ERROR_BODY_MAX,
    })
}

// ── one configuration generation, as the door planes are sealed over it ─────────────────────────

/// WHAT A DOOR PLANE IS SEALED OVER, for ONE configuration generation (spec Part 1 line 569: one
/// validated `{section: value}` object per `open`/`refresh`): the kernel-owned sections it reads
/// ([`kernel_sections`]), the providers its members are reached through ([`provider_routes`]) and
/// the model-serving pools' bounds ([`crate::root::model_egress::ModelPools`]). Projected from each
/// resolved configuration as it is built (`busbar_kernel::appbuild::set_config_projection`), and
/// read back when that generation is swapped in.
#[derive(Debug)]
pub struct DoorConfig {
    /// The kernel-owned sections.
    pub sections: BTreeMap<&'static str, serde_yaml::Value>,
    /// The providers, by name.
    pub providers: BTreeMap<String, ProviderRoute>,
    /// The model-serving pools' bounds.
    pub model_pools: crate::root::model_egress::ModelPools,
}

/// The [`DoorConfig`] of `cfg` (the root's `ConfigProjection`).
#[must_use]
pub fn door_config(cfg: &busbar_kernel::config::RootCfg) -> Arc<dyn std::any::Any + Send + Sync> {
    Arc::new(DoorConfig {
        sections: kernel_sections(cfg),
        providers: provider_routes(&cfg.providers),
        model_pools: crate::root::model_egress::ModelPools::of(cfg),
    })
}

// ── the kernel-owned sections a door plane reads ────────────────────────────────────────────────

/// THE KERNEL-OWNED SECTIONS A DOOR PLANE MAY READ, as the configuration validated and resolved
/// them (spec Part 1 §4: "A plane's settings reach it as ONE validated JSON object `{section:
/// value}` per open/refresh, reserved keys and secrets stripped"; "A plane receives, at open, the
/// dialect fields of the providers it references and resolves model -> dialect itself"): `providers`
/// (catalog-merged, each provider's dialect fields: no `base_url`, no credential reference, no
/// health or token endpoint), `models`, `pools` (each pool's members and its fallback pool) and
/// `limits` (the output-cap default and the effort budgets). The previous release kept these in the
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
    fn output_key(k: busbar_kernel::ir::lane_caps::MaxOutputKeyCfg) -> &'static str {
        use busbar_kernel::ir::lane_caps::MaxOutputKeyCfg;
        match k {
            MaxOutputKeyCfg::MaxTokens => "max_tokens",
            MaxOutputKeyCfg::MaxCompletionTokens => "max_completion_tokens",
        }
    }
    let mut out = BTreeMap::new();
    let mut providers = Map::new();
    for (name, p) in &cfg.providers {
        let mut m = Map::new();
        m.insert("protocol".into(), json!(p.protocol));
        opt(&mut m, "path", p.path.as_ref().map(|v| json!(v)));
        opt(&mut m, "path_base", p.path_base.as_ref().map(|v| json!(v)));
        opt(
            &mut m,
            "organization",
            p.organization.as_ref().map(|v| json!(v)),
        );
        opt(&mut m, "project", p.project.as_ref().map(|v| json!(v)));
        m.insert("error_map".into(), json!(p.error_map));
        opt(&mut m, "auth", p.auth.map(style_word).map(|v| json!(v)));
        opt(
            &mut m,
            "max_output_key",
            p.max_output_key.map(output_key).map(|v| json!(v)),
        );
        opt(
            &mut m,
            "anthropic_adaptive_thinking",
            p.anthropic_adaptive_thinking.map(|v| json!(v)),
        );
        opt(
            &mut m,
            "native_structured_output",
            p.native_structured_output.map(|v| json!(v)),
        );
        let rules: Vec<Value> = p
            .model_capabilities
            .iter()
            .map(|r| {
                let mut c = Map::new();
                c.insert("models".into(), json!(r.models));
                opt(
                    &mut c,
                    "max_output_key",
                    r.max_output_key.map(output_key).map(|v| json!(v)),
                );
                opt(
                    &mut c,
                    "anthropic_adaptive_thinking",
                    r.anthropic_adaptive_thinking.map(|v| json!(v)),
                );
                opt(
                    &mut c,
                    "native_structured_output",
                    r.native_structured_output.map(|v| json!(v)),
                );
                opt(&mut c, "reasoning_none", r.reasoning_none.map(|v| json!(v)));
                opt(
                    &mut c,
                    "thinking_always_on",
                    r.thinking_always_on.map(|v| json!(v)),
                );
                Value::Object(c)
            })
            .collect();
        if !rules.is_empty() {
            m.insert("model_capabilities".into(), Value::Array(rules));
        }
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
    let limits = json!({
        "default_max_tokens": cfg.limits.default_max_tokens,
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
    if !models.is_empty() || !pools.is_empty() {
        out.insert(RESERVED_MODELS_KEY, yaml(Value::Object(models)));
        out.insert(RESERVED_POOLS_KEY, yaml(Value::Object(pools)));
    }
    out.insert("limits", yaml(limits));
    out
}

// ── the members' routes (THE DESIGN §6 steps 2-3) ──────────────────────────────────────────────

/// ONE `providers:` ENTRY as a door plane's member reaches it (THE DESIGN §6 step 2; #50, #51): the
/// `base_url` it dials, its default `protocol`, its credential reference, the `auth:` style it
/// states (`None` = its plane's dialect default) and the parameters that style is opened with.
#[derive(Debug, Clone)]
pub struct ProviderRoute {
    /// `base_url`, as the operator (or the catalog) spelled it.
    pub base_url: String,
    /// The default wire protocol (#51).
    pub protocol: String,
    /// `api_key`, a reference; resolved once, at the seal.
    pub credential: busbar_contract::secret_ref::SecretRef,
    /// `auth:`, the style it overrides its plane's dialect default with.
    pub style: Option<String>,
    /// The style's parameters (`token_url`, `scope`, `subject`, where stated).
    pub params: StyleParams,
}

/// THE PARAMETERS A PROVIDER'S `auth:` STYLE IS OPENED WITH, typed: the three keys a provider states
/// (`token_url`, `scope`, `subject`), each present only where the operator wrote it. The JSON object
/// the auth plugin's `open_outbound` reads is built from them at the call, never carried as a bag.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StyleParams {
    /// `token_url`, where stated.
    pub token_url: Option<String>,
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
    use busbar_kernel::config::ProviderAuth;
    match auth {
        ProviderAuth::Bearer => "bearer",
        ProviderAuth::ApiKey => "api-key",
        ProviderAuth::JwtBearer => "jwt-bearer",
        ProviderAuth::OAuthClientCredentials => "oauth-client-credentials",
    }
}

/// THE DEPLOYMENT'S PROVIDERS as door planes' members reach them, by name (the catalog-merged
/// `providers:` the configuration resolved).
#[must_use]
pub fn provider_routes(
    providers: &HashMap<String, busbar_kernel::config::ProviderCfg>,
) -> BTreeMap<String, ProviderRoute> {
    providers
        .iter()
        .map(|(name, p)| {
            (
                name.clone(),
                ProviderRoute {
                    base_url: p.base_url.clone(),
                    protocol: p.protocol.clone(),
                    credential: p.api_key.clone(),
                    style: p.auth.map(|a| style_word(a).to_string()),
                    params: StyleParams {
                        token_url: p.token_url.clone(),
                        scope: p.scope.clone(),
                        subject: p.subject.clone(),
                    },
                },
            )
        })
        .collect()
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
    opened:
        Mutex<HashMap<String, Arc<crate::root::loader::dispatch::auth_outbound::OutboundInstance>>>,
}

impl std::fmt::Debug for OutboundAuths {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboundAuths")
            .field(
                "linked",
                &self.linked.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
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
            opened: Mutex::new(HashMap::new()),
        }
    }

    /// The bind one auth row is loaded under: its needs on the connection table, its diagnostics
    /// (a mint that failed and will retry) in its own log file under the configured `plugins.logs`
    /// (THE DESIGN #85).
    fn bind(&self, name: &str) -> crate::root::loader::dispatch::Bind {
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
        crate::root::loader::dispatch::Bind {
            instance: Arc::from(name),
            max_inflight_cap: 64,
            sink,
            dispatcher: self.dispatcher.adopter(),
            conns: self.conns.clone(),
        }
    }

    /// Every auth row's loaded door, linked first, then dropped in. A row that will not load is
    /// passed over (its own open names why where it is configured).
    fn rows(
        &self,
    ) -> Vec<(
        String,
        crate::root::loader::dispatch::Plugin<crate::root::loader::dispatch::kinds::auth::Auth>,
    )> {
        use crate::root::loader::dispatch::kinds::auth::Auth;
        use crate::root::loader::dispatch::{load_dropped_bytes, load_linked, LinkedRow};
        let mut rows = Vec::new();
        for (name, door) in &self.linked {
            if let Ok(plugin) =
                LinkedRow::of(*door).and_then(|row| load_linked::<Auth>(&row, self.bind(name)))
            {
                rows.push(((*name).to_string(), plugin));
            }
        }
        let dropped = self.dropped.map_or(&[][..], |r| r.loadable());
        for row in dropped.iter().filter(|r| r.manifest.kind == "auth") {
            let name = &row.manifest.name;
            let Ok(Some(stated)) = row.manifest.stated_rendering() else {
                continue;
            };
            if let Ok(plugin) =
                load_dropped_bytes::<Auth>(&row.lib_bytes, name, &stated, self.bind(name))
            {
                rows.push((name.clone(), plugin));
            }
        }
        rows
    }

    /// The auth plugin serving `style` for a binding under `settings`, its instance opened (once
    /// per plugin, or once per binding's settings for a plugin whose needs take their target from
    /// them) and its tick schedule running; `None` when no row states it.
    ///
    /// # Errors
    ///
    /// The serving plugin would not open for its outbound styles.
    pub fn serving(
        &self,
        style: &str,
        settings: &serde_json::Value,
    ) -> Result<Option<Serving>, String> {
        use crate::root::loader::dispatch::auth_outbound::{outbound_style, OutboundInstance};
        for (name, plugin) in self.rows() {
            let Some(decl) = outbound_style(&plugin, style) else {
                continue;
            };
            let per_binding = plugin.targets_from_settings();
            let settings = if per_binding {
                serde_json::to_vec(settings).map_err(|e| e.to_string())?
            } else {
                b"{}".to_vec()
            };
            let key = if per_binding {
                format!("{name}\0{}", String::from_utf8_lossy(&settings))
            } else {
                name
            };
            let mut opened = self.opened.lock().unwrap_or_else(|p| p.into_inner());
            let instance = match opened.get(&key) {
                Some(instance) => Arc::clone(instance),
                None => {
                    let instance = Arc::new(OutboundInstance::open_with(
                        plugin,
                        Arc::clone(&self.dispatcher),
                        0,
                        &settings,
                    )?);
                    // ITS TICK SCHEDULE, on the runtime the composition runs on.
                    if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                        runtime.spawn(Arc::clone(&instance).ticks());
                    }
                    opened.insert(key, Arc::clone(&instance));
                    instance
                }
            };
            return Ok(Some((
                instance as Arc<dyn busbar_contract::auth_calls::OutboundAuth>,
                decl,
            )));
        }
        Ok(None)
    }
}

/// WHAT A DOOR PLANE'S MEMBERS ARE REACHED THROUGH, for the process (THE DESIGN §6 steps 2-3, §5):
/// the deployment's providers, the secret seam their credentials resolve through, the auth plugins
/// that serve a style, the connector the planes' needs were declared on, and the client-level
/// ceiling a streamed answer is bounded by.
pub struct DoorReach<'a> {
    /// The providers, by name ([`provider_routes`]).
    pub providers: &'a BTreeMap<String, ProviderRoute>,
    /// The secret seam.
    pub secrets: &'a dyn busbar_contract::secret::SecretResolve,
    /// The auth plugins.
    pub auths: Arc<OutboundAuths>,
    /// The process's connector.
    pub conns: Arc<dyn busbar_contract::conn::PollConns>,
    /// Whole seconds.
    pub stream_ceiling_secs: u64,
    /// The model-serving pools the plane serving the `pools` map walks
    /// ([`crate::root::model_egress`]); `None` where none is composed.
    pub models: Option<&'a crate::root::model_egress::ModelServing>,
    /// The linked wires composed over the data carrier (`crate::root::serve::upgrade_carriers`):
    /// a need over one dials its member's base URL in its own scheme ([`spelled_for`]).
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
    let credential = reach.secrets.resolve(&subject).map_err(|e| {
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
    }))
}

/// THE DOOR'S OWN REQUESTS TO ITS REGISTRATION MEMBERS carry each member's binding (ARCHITECT
/// round 5 Q-L3B-DOOR-EXCHANGE; round 4 (d): "admin connect + verify-on-call fetches use the same
/// binding"): every registration member's route with an auth binding (`routes`, on the plane's
/// member-target need `served` states) is held on the plane's connection table `table` per
/// (`instance`, need, target origin), its passthrough credential lent from the unit records
/// `units` by the unit the request is made inside.
pub fn bind_member_fetches(
    served: &crate::root::loader::dispatch::kinds::plane::ServedFacts,
    routes: &BTreeMap<String, busbar_kernel::plane_driver::MemberRoute>,
    instance: busbar_contract::conn::InstanceId,
    table: &dyn busbar_contract::conn::DeclaredConns,
    units: &Arc<busbar_kernel::host_units::UnitRecords>,
) {
    let Some(need) = served
        .need_targets
        .iter()
        .enumerate()
        .find_map(|(at, path)| {
            busbar_contract::section::member_target(path)?;
            Some(busbar_contract::conn::NeedId(u32::try_from(at).ok()?))
        })
    else {
        return;
    };
    for route in routes.values().filter(|r| r.need == need) {
        let Some(binding) = &route.auth else {
            continue;
        };
        table.bind_auth(
            instance,
            need,
            busbar_contract::conn::origin_of(&route.base_url),
            busbar_contract::conn::ConnAuth {
                auth: Arc::clone(&binding.auth),
                handle: binding.handle,
                style_flags: binding.style_flags,
                points: binding.points,
                passthrough: binding.passthrough,
                lender: Some(Arc::clone(units) as Arc<dyn busbar_contract::conn::LendCredential>),
            },
        );
    }
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
    // path, an entry the section registers is reached at its own target, read off the registration.
    let member_target = served
        .need_targets
        .iter()
        .enumerate()
        .find_map(|(at, path)| {
            let key = busbar_contract::section::member_target(path)?;
            Some((busbar_contract::conn::NeedId(u32::try_from(at).ok()?), key))
        });
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
                        registration_anchors(entry, registration, need, served, reach.secrets)?;
                    registered.insert(
                        entry.clone(),
                        (need, origin_of(target).to_string(), anchors),
                    );
                    continue;
                }
            }
            // A PROGRAM MEMBER (Q-L3B-STDIO-UPSTREAM (A)): a registration that names a program is
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
        let default = served
            .dialects
            .iter()
            .position(|d| *d == dialect)
            .and_then(|at| {
                let at = u32::try_from(at).ok()?;
                served
                    .dialect_auth
                    .iter()
                    .find(|(d, _, _)| *d == at)
                    .map(|(_, style, params)| ((*style).to_string(), *params))
            });
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
    for (entry, (need, base_url, anchors)) in registered {
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
            })
        } else {
            // A `token_exchange:` registration (ARCHITECT round 5 Q-L3B-EXCHANGE (B)): busbar's own
            // subject token, exchanged per call for the caller's down-scope the plane states.
            match section.get(entry.as_str()) {
                Some(registration) => token_exchange_binding(&entry, registration, reach)?,
                None => None,
            }
        };
        routes.insert(
            entry.clone(),
            MemberRoute {
                rides: Vec::new(),
                need,
                base_url,
                auth,
                provider: entry,
                keep: busbar_kernel::plane_driver::ResponseKeep::default(),
                anchors,
                spelled: Vec::new(),
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
                .resolve(&r.provider.credential)
                .map_err(|e| format!("provider '{}' credential: {e}", r.name))?
        };
        let settings = r.provider.params.to_json();
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
                auth: Some(AuthBinding {
                    auth,
                    handle,
                    style_flags: decl.flags,
                    points: busbar_contract::abi::auth::AuthPoints(decl.points),
                    passthrough: false,
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

/// The host of `base_url`: after its scheme, before its port, path, query or fragment.
fn base_url_host(base_url: &str) -> &str {
    let rest = base_url.split_once("://").map_or(base_url, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority.rsplit_once('@').map_or(authority, |(_, a)| a);
    authority.split(':').next().unwrap_or("")
}

/// The dotted label of `host` right after the first of `after`, when it reads as a dashed name
/// ending in a number (three parts or more, every part before the last alphabetic, the last all
/// digits: the shape the dialect's own rule accepted, 1.5.5 `derive_sigv4_region`).
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

/// THE BASE URL A NEED'S FRAMER READS: a need over `transport`, a framer composed over the
/// carrier the operator's `base_url` names (`upgrades`: the linked wires composing over the data
/// carrier, `crate::root::serve::upgrade_carriers`), dials the same authority and path under the
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
        .and_then(|p| p.key);
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

#[cfg(test)]
#[path = "tests/door_steps.rs"]
mod tests;
