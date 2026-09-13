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

use busbar_contract::CandidateIdx;

use crate::ports::DestinationId;

/// HOW MANY CANDIDATES A BINDING ADMITS — the ROUTE step's pick posture as binding data.
///
/// A pick over a set has always had two honest postures and only one of them was ever written
/// down. `Any` is the one every pool has: several members can serve this work, choosing between
/// them is the pick's job, and which one it chose is not something the caller needed to be asked
/// about. `One` is the other: the binding declares that exactly one of its candidates may serve a
/// request, and a set that offers two has not narrowed to an answer — it has produced an ambiguity,
/// and quietly taking the first of them would send a caller's work somewhere the caller did not
/// choose with no way to tell it happened.
///
/// It lives with [`Failover`], the binding it is a field of: the posture is a property of what was
/// bound, not of the request that arrived, and no plane reads it — only this unit's own pick does,
/// so it is unit-internal and never plugin-visible contract surface.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Arity {
    /// Any one of the fitting candidates may serve. The pick chooses among them.
    #[default]
    Any,
    /// Exactly one candidate may fit. More than one is an ambiguity, not a choice.
    One,
}

/// What [`decide_arity`] found about a fitting set.
///
/// The arms are deliberately not a `Result`: three of the four are ordinary and only one of them
/// is a refusal. `NoCandidate` is NOT a new refusal — it is the no-candidate answer every pick
/// already had, named here so the caller can see that arity did not invent it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArityVerdict {
    /// The binding admits any of them; the pick's own ordering decides, exactly as before.
    ChooseAmong,
    /// The binding admits one and exactly one fits.
    TheOne(CandidateIdx),
    /// The binding admits one and these fit. The refusal NAMES them: an operator shown "ambiguous"
    /// with no list has been told that something is wrong and not what.
    Ambiguous(Vec<CandidateIdx>),
    /// Nothing fits. The caller's existing no-candidate refusal, unchanged.
    NoCandidate,
}

/// THE ARITY DECISION, WRITTEN ONCE.
///
/// The pick asks this one question of its own fitting set, so it is answered here — once, beside
/// the binding both the walk and the wait terminal read — rather than open-coded at each call,
/// where the second copy is the one that drifts. It is pure, it allocates only on the ambiguity
/// arm, and it names no amount, no budget and no price: an ambiguity is a refusal about a SET, and
/// a refused request is unpriced.
#[must_use]
pub fn decide_arity(arity: Arity, fitting: &[CandidateIdx]) -> ArityVerdict {
    match (arity, fitting) {
        (Arity::Any, _) => ArityVerdict::ChooseAmong,
        (Arity::One, []) => ArityVerdict::NoCandidate,
        (Arity::One, [only]) => ArityVerdict::TheOne(*only),
        (Arity::One, many) => ArityVerdict::Ambiguous(many.to_vec()),
    }
}

/// The candidates a binding could not choose between, or empty when the fitting set is a choice
/// (`Any`, or a `One` set of exactly zero or one). The pick calls this over its own fitting set,
/// so [`decide_arity`] is consulted from the pick site while its candidate-index plumbing stays
/// here. The ids come back in the fitting order, for the AUDIT step.
#[must_use]
pub fn ambiguous(arity: Arity, fitting: &[DestinationId]) -> Vec<DestinationId> {
    let idxs: Vec<CandidateIdx> = (0..fitting.len())
        .map(|i| CandidateIdx(u16::try_from(i).unwrap_or(u16::MAX)))
        .collect();
    match decide_arity(arity, &idxs) {
        ArityVerdict::Ambiguous(candidates) => {
            candidates.iter().map(|c| fitting[c.0 as usize]).collect()
        }
        _ => Vec::new(),
    }
}

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
    /// How many of the fitting candidates this binding admits — the ROUTE step's pick posture as
    /// contract data. `Any` (the default) is every pool that has ever shipped: several members may
    /// serve and choosing between them is the pick's own job. `One` is the other honest posture —
    /// the binding declares that exactly one candidate may serve, so a fitting set of more than one
    /// is an ambiguity the walk refuses rather than a choice it makes quietly. It is data on the
    /// binding, not a flag on the request, because the posture is a property of what was bound.
    pub arity: Arity,
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
            arity: Arity::Any,
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
    ///
    /// A pool that blocklists nobody — the common case, and the one every hop of every walk pays
    /// for — has nothing to filter, so it borrows its own membership rather than copying it. Only a
    /// pool that actually excludes somebody builds a membership of its own. The answer derefs to
    /// `&[Member]` either way, so a caller reads it exactly as it read the copy.
    #[must_use]
    pub fn admissible_members(&self) -> std::borrow::Cow<'_, [Member]> {
        if self.failover.exclusions.is_empty() {
            return std::borrow::Cow::Borrowed(&self.members);
        }
        std::borrow::Cow::Owned(
            self.members
                .iter()
                .filter(|m| !self.failover.exclusions.contains(&m.name))
                .cloned()
                .collect(),
        )
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
