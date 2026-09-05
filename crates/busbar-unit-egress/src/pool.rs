// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The pool: the set of members a route may be sent to, per transport and destination, and the
//! settings the walk over them reads.
//!
//! The design gives this unit the pool per `(transport, destination)`. That is what is here: the
//! membership, each member's weight and its own overrides, the walk's deadline and hop count, the
//! per-pool member blocklist, and what to do when the walk finds nowhere to send. Nothing here
//! decides anything — the deciding is in the walk, the order and the terminals, each of which
//! reads these values and none of which invents one.

use crate::ports::DestinationId;

/// The walk's deadline when the pool names none. Whole seconds, and the deadline is checked before
/// every attempt including a streaming one.
pub const DEFAULT_FAILOVER_DEADLINE_SECS: u64 = 120;

/// How many further members the walk may try after the first when the pool names no cap. The walk
/// runs this many PLUS ONE attempts: the cap counts hops, and the first attempt is not a hop.
pub const DEFAULT_FAILOVER_CAP: usize = 3;

/// One member of a pool.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    /// Which destination of the verified set this is.
    pub destination: DestinationId,
    /// The operator's name for it — the name a blocklist and a diagnostic say.
    pub name: String,
    /// Its share of the weighted order. Zero means drain: the operator is bleeding this member off
    /// before decommissioning it, so no path may select it — not the weighted walk, not a ranked
    /// preference, and not the sticky fast path.
    pub weight: u32,
    /// The member's own cap on time to response headers, overriding the destination's.
    pub attempt_timeout_ms: Option<u64>,
    /// The largest request this member accepts, where it declares one. The walk reads it only to
    /// exclude the members that share or undercut a limit that has just refused a request.
    pub context_max: Option<u64>,
    /// The lane this member is priced on, as the trust unit sealed it.
    pub lane: Option<busbar_contract::LaneId>,
}

impl Member {
    /// A member with only the two things every member has.
    #[must_use]
    pub fn new(destination: DestinationId, name: impl Into<String>, weight: u32) -> Self {
        Self {
            destination,
            name: name.into(),
            weight,
            attempt_timeout_ms: None,
            context_max: None,
            lane: None,
        }
    }
}

/// What the walk over one pool is bounded by.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failover {
    /// The whole walk's deadline, in seconds from the request's start.
    pub timeout_secs: u64,
    /// How many hops after the first the walk may take.
    pub max_hops: usize,
    /// Member names this pool will never select, primary or failover. They are removed from the
    /// membership rather than marked as already-tried: a consumer reading the tried set could not
    /// otherwise tell a blocklisted member from one this request has burned through, and the
    /// terminals read the membership directly.
    pub exclusions: Vec<String>,
}

impl Default for Failover {
    fn default() -> Self {
        Self {
            timeout_secs: DEFAULT_FAILOVER_DEADLINE_SECS,
            max_hops: DEFAULT_FAILOVER_CAP,
            exclusions: Vec::new(),
        }
    }
}

/// What to do when the walk finds nowhere to send.
///
/// These four are the design's terminals. The default is the shed, and it is the default in the
/// absence of the key rather than a spelling an operator writes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum OnExhausted {
    /// Refuse, with the wait the pool's own members justify.
    #[default]
    Status503,
    /// Spill into another pool, re-applying every restriction, with a visited guard.
    FallbackPool(String),
    /// The one documented breaker bypass: send to the member with the soonest cooldown even though
    /// it is suppressed, owning no probe.
    LeastBad,
    /// Wait a bounded time for a permit to free, then re-ask the same admission every path asks.
    Queue {
        /// The longest the wait may be, in milliseconds. The actual wait is the lesser of this and
        /// what is left of the walk's deadline.
        max_ms: u64,
    },
}

/// One pool: its membership and the settings the walk over it reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pool {
    /// The pool's name. This is the breaker cell key every attempt in this walk records against,
    /// and the empty name is the default cell a direct route uses.
    pub name: String,
    /// The members, in the operator's configured order.
    pub members: Vec<Member>,
    /// What bounds the walk.
    pub failover: Failover,
    /// What to do when the walk finds nowhere to send.
    pub on_exhausted: OnExhausted,
}

impl Pool {
    /// A pool of these members with every default.
    #[must_use]
    pub fn new(name: impl Into<String>, members: Vec<Member>) -> Self {
        Self {
            name: name.into(),
            members,
            failover: Failover::default(),
            on_exhausted: OnExhausted::default(),
        }
    }

    /// This pool's membership with its own blocklist applied.
    ///
    /// The blocklist is applied here, once, before the walk starts and before any terminal reads
    /// the membership — which is what stops a blocklisted member being reached by the least-bad
    /// terminal or counted into a shed's retry hint.
    #[must_use]
    pub fn admissible_members(&self) -> Vec<Member> {
        if self.failover.exclusions.is_empty() {
            return self.members.clone();
        }
        self.members
            .iter()
            .filter(|m| !self.failover.exclusions.contains(&m.name))
            .cloned()
            .collect()
    }

    /// Where a member sits in this pool's membership, by destination.
    #[must_use]
    pub fn position_of(&self, destination: DestinationId) -> Option<usize> {
        self.members
            .iter()
            .position(|m| m.destination == destination)
    }
}

/// Every pool this node has, and the spill targets between them.
///
/// A spill target is a pool of its own, which is why a spill re-applies the target's own blocklist
/// and its own restrictions: the two memberships are independent, and the primary pool's blocklist
/// says nothing about the pool a request spills into.
#[derive(Clone, Debug, Default)]
pub struct PoolTable {
    pools: Vec<Pool>,
}

impl PoolTable {
    /// An empty table.
    #[must_use]
    pub fn new() -> Self {
        Self { pools: Vec::new() }
    }

    /// Add a pool, replacing any pool of the same name.
    pub fn insert(&mut self, pool: Pool) {
        match self.pools.iter_mut().find(|p| p.name == pool.name) {
            Some(existing) => *existing = pool,
            None => self.pools.push(pool),
        }
    }

    /// One pool by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Pool> {
        self.pools.iter().find(|p| p.name == name)
    }

    /// How many pools.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pools.len()
    }

    /// Whether there are none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pools.is_empty()
    }
}
