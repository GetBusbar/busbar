// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The trust unit's test fixtures the moved verify-step tests drive through, carried from
//! `busbar-kernel-egress`'s `trust/tests/mod.rs` and `trust/tests/destination_tests.rs`.

use busbar_kernel_egress::trust::destination::{DestinationFacts, KindFacts};
use busbar_kernel_egress::trust::guard::PoolView;
use busbar_kernel_egress::trust::lane::{BreakerView, LaneTable, Unavailable};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

/// A pool table stated as data: who may use what, and what falls over to what.
pub(crate) struct Pools {
    pub(crate) has_key: bool,
    /// `None` means the key names no restriction and admits every pool. An explicit empty list is
    /// the empty set and denies every pool.
    pub(crate) allowed: Option<Vec<String>>,
    pub(crate) fallbacks: HashMap<String, String>,
    pub(crate) configured: HashSet<String>,
    pub(crate) pricing: bool,
    pub(crate) unpriced: HashSet<String>,
}

impl Default for Pools {
    fn default() -> Self {
        Pools {
            has_key: true,
            allowed: None,
            fallbacks: HashMap::new(),
            configured: HashSet::new(),
            pricing: false,
            unpriced: HashSet::new(),
        }
    }
}

impl Pools {
    pub(crate) fn allowing(pools: &[&str]) -> Self {
        Pools {
            allowed: Some(pools.iter().map(|p| (*p).to_string()).collect()),
            ..Pools::default()
        }
    }

    /// A card is present, and it does not price these names.
    pub(crate) fn with_card_missing(names: &[&str]) -> Self {
        Pools {
            pricing: true,
            unpriced: names.iter().map(|n| (*n).to_string()).collect(),
            ..Pools::default()
        }
    }

    pub(crate) fn falls_back(mut self, from: &str, to: &str) -> Self {
        self.fallbacks.insert(from.to_string(), to.to_string());
        self
    }
}

impl PoolView for Pools {
    fn key_scopes(&self) -> Option<&[String]> {
        self.allowed.as_deref()
    }
    fn pool_allowed(&self, pool: &str) -> bool {
        match &self.allowed {
            None => true,
            Some(list) => list.iter().any(|p| p == pool),
        }
    }
    fn on_exhausted_fallback(&self, pool: &str) -> Option<String> {
        self.fallbacks.get(pool).cloned()
    }
    fn is_configured(&self, name: &str) -> bool {
        self.configured.contains(name)
    }
    fn pricing_enabled(&self) -> bool {
        self.pricing
    }
    fn is_unpriced(&self, name: &str) -> bool {
        self.unpriced.contains(name)
    }
    fn has_key(&self) -> bool {
        self.has_key
    }
}

/// A lane table and breaker stated as data, plus a record of what was actually admitted — the only
/// way to tell "excluded before the walk" from "ordered last and attempted".
pub(crate) struct Lanes {
    pub(crate) dead: HashSet<usize>,
    pub(crate) exhausted: HashSet<usize>,
    pub(crate) open_breaker: HashSet<usize>,
    pub(crate) at_capacity: HashSet<usize>,
    /// Every lane the admission was actually called for, in call order.
    pub(crate) admissions: RefCell<Vec<usize>>,
    /// Every lane the readiness peek was called for, in call order.
    pub(crate) peeks: RefCell<Vec<usize>>,
}

impl Default for Lanes {
    fn default() -> Self {
        Lanes {
            dead: HashSet::new(),
            exhausted: HashSet::new(),
            open_breaker: HashSet::new(),
            at_capacity: HashSet::new(),
            admissions: RefCell::new(Vec::new()),
            peeks: RefCell::new(Vec::new()),
        }
    }
}

impl Lanes {
    pub(crate) fn with(f: impl FnOnce(&mut Lanes)) -> Self {
        let mut l = Lanes::default();
        f(&mut l);
        l
    }
}

impl LaneTable for Lanes {
    fn lane_admissible(&self, lane: usize) -> bool {
        !self.dead.contains(&lane) && !self.exhausted.contains(&lane)
    }
}

impl BreakerView for Lanes {
    fn ready(&self, _pool: &str, lane: usize, _now: u64) -> bool {
        self.peeks.borrow_mut().push(lane);
        !self.open_breaker.contains(&lane)
    }
    fn try_admit(&self, _pool: &str, lane: usize, _now: u64) -> Result<(), Unavailable> {
        self.admissions.borrow_mut().push(lane);
        if self.dead.contains(&lane) {
            return Err(Unavailable::Dead);
        }
        if self.exhausted.contains(&lane) {
            return Err(Unavailable::BudgetExhausted);
        }
        if self.open_breaker.contains(&lane) {
            return Err(Unavailable::BreakerOpen);
        }
        if self.at_capacity.contains(&lane) {
            return Err(Unavailable::AtCapacity);
        }
        Ok(())
    }
}

/// A resolver that answers every name with one address, so a test can say what a name resolves to
/// without a live one. The address is the whole point of the fake: the hazards the network guard
/// exists for are all about WHAT a name answers with.
pub(crate) struct Answering(pub(crate) &'static str);

impl busbar_kernel_egress::trust::net::Resolver for Answering {
    fn resolve(&self, _host: &str) -> Result<Vec<std::net::IpAddr>, String> {
        Ok(vec![self.0.parse().expect("a fixture address")])
    }
}

/// A breaker with nothing open, for the tests that are about a kind's OTHER conjuncts.
///
/// The breaker's own arm has its own tests beside the walk's; a test about the transport key should
/// not have to say anything about a circuit.
pub(crate) struct AllAdmitted;

impl busbar_kernel_egress::trust::lane::BreakerView for AllAdmitted {
    fn ready(&self, _pool: &str, _lane: usize, _now: u64) -> bool {
        true
    }
    fn try_admit(
        &self,
        _pool: &str,
        _lane: usize,
        _now: u64,
    ) -> Result<(), busbar_kernel_egress::trust::lane::Unavailable> {
        Ok(())
    }
}

/// Facts that say yes to everything, so a test can turn exactly one answer off and see it land.
pub(crate) struct AllYes {
    /// What every name this fake is asked about resolves to. `None` scripts no resolver at all and
    /// the plain `net_guard` answer stands; `Some` runs the REAL guard over the real address, which
    /// is what makes a test about the metadata address a test about the guard rather than a test
    /// about a boolean somebody set.
    pub(crate) resolves_to: Option<&'static str>,
    pub(crate) net_guard: bool,
    pub(crate) price_within_max: bool,
    /// Where in the lane table this fake's one lane sits. The mapping is all an implementer of the
    /// breaker predicate does; the question itself belongs to the query.
    pub(crate) lane_index: usize,
    pub(crate) allow_listed: bool,
    pub(crate) transport_key: bool,
    pub(crate) lane_permitted: bool,
    pub(crate) session_upstream: bool,
    pub(crate) session_principal: bool,
    pub(crate) client_selector: bool,
    pub(crate) await_deadline: bool,
    pub(crate) verb_scope: bool,
    pub(crate) nested: bool,
    pub(crate) record: bool,
    pub(crate) peer_lease: bool,
    pub(crate) upgrade: bool,
}

impl Default for AllYes {
    fn default() -> Self {
        AllYes {
            resolves_to: None,
            net_guard: true,
            price_within_max: true,
            lane_index: 0,
            allow_listed: true,
            transport_key: true,
            lane_permitted: true,
            session_upstream: true,
            session_principal: true,
            client_selector: true,
            await_deadline: true,
            verb_scope: true,
            nested: true,
            record: true,
            peer_lease: true,
            upgrade: true,
        }
    }
}

impl KindFacts for AllYes {
    fn net_guard_passes(&self, dest: &DestinationFacts) -> bool {
        let Some(address) = self.resolves_to else {
            return self.net_guard;
        };
        !matches!(
            busbar_kernel_egress::trust::net::check_destination_facts(
                dest,
                &[],
                &Answering(address),
                busbar_kernel_egress::trust::net::GuardPolicy::default(),
                &busbar_kernel_egress::trust::net::Denylist::default(),
            ),
            Err(
                busbar_kernel_egress::trust::net::NetworkRefusal::MetadataDenied(_)
                    | busbar_kernel_egress::trust::net::NetworkRefusal::Guard(_)
            )
        )
    }

    fn allow_listed(&self, _d: &DestinationFacts) -> bool {
        self.allow_listed
    }
    fn transport_key_resolves(&self, _d: &DestinationFacts) -> bool {
        self.transport_key
    }
    fn lane_permitted_for_op_class(&self, _lane: &str) -> bool {
        self.lane_permitted
    }
    fn session_upstream_ok(&self) -> bool {
        self.session_upstream
    }
    fn session_principal_matches(&self) -> bool {
        self.session_principal
    }
    fn client_selector_ok(&self) -> bool {
        self.client_selector
    }
    fn await_deadline_ok(&self) -> bool {
        self.await_deadline
    }
    fn verb_scope_held(&self) -> bool {
        self.verb_scope
    }
    fn nested_plane_ok(&self) -> bool {
        self.nested
    }
    fn plane_record_ok(&self) -> bool {
        self.record
    }
    fn peer_lease_live(&self) -> bool {
        self.peer_lease
    }
    fn upgrade_ok(&self) -> bool {
        self.upgrade
    }
    fn unit_price_within_max(&self, _d: &DestinationFacts) -> bool {
        self.price_within_max
    }
    fn breaker_admits(
        &self,
        dest: &DestinationFacts,
        at: &busbar_kernel_egress::trust::lane::BreakerQuery<'_>,
    ) -> bool {
        match dest.lane() {
            Some(_) => at.admits_lane(self.lane_index),
            // Nothing priced on a lane has a lane for the breaker to have an opinion about.
            None => true,
        }
    }
}

/// One destination of each kind, filled in with whatever its arm needs.
///
/// The kind is what these tests are about; the payload is the contract's shape and every field
/// here is a placeholder for it. A lane-bearing kind gets the one lane the fixtures share.
pub(crate) mod kinds {
    use super::DestinationFacts;

    const LANE: busbar_contract::caps::LaneId = busbar_contract::caps::LaneId::new("lane-a");

    pub(crate) fn upstream() -> DestinationFacts {
        DestinationFacts::Upstream {
            transport: "wire",
            address: busbar_contract::transport::dest::UpstreamAddress::socket("upstream.example"),
            lane: LANE,
        }
    }

    pub(crate) fn kernel_verb() -> DestinationFacts {
        DestinationFacts::KernelVerb { verb: "status" }
    }

    pub(crate) fn nested_plane() -> DestinationFacts {
        DestinationFacts::NestedPlane {
            op: busbar_contract::OpClassId::new("call"),
        }
    }
}
