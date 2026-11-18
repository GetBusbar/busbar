// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The pool: the set of members a route may be sent to, per transport and destination, and the

use crate::ports::DestinationId;
use crate::select::WeightedFloor;
use std::sync::atomic::{AtomicI64, Ordering};

/// The walk's deadline when the pool names none. Whole seconds, and the deadline is checked before
pub const DEFAULT_FAILOVER_DEADLINE_SECS: u64 = 120;

/// How many further members the walk may try after the first when the pool names no cap. The walk
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
    /// Its TIER (the core-owned per-member `tier` key, `BUSBAR-1.6.0.md` l.4196 (b), l.4202, R2-G
    /// l.4285): the pick takes the lowest tier among the members that could take the request, and
    /// the weighted order turns only among those; a higher tier is reached only when every lower
    /// one is unhealthy, drained or already tried. Every member of a pool that states no tier is at
    /// `0`, so the weighted order is the pool's whole order.
    pub tier: u32,
    /// The member's own cap on time to response headers, overriding the destination's.
    pub attempt_timeout_ms: Option<u64>,
    /// The largest request this member accepts, where it declares one. The walk reads it only to
    /// exclude the members that share or undercut a limit that has just refused a request.
    pub context_max: Option<u64>,
    /// The lane this member is priced on, as the verify step sealed it.
    pub lane: Option<busbar_contract::LaneId>,
    /// Through this pool the member is reached with the caller's own credential (the pool's
    /// `upstream_credentials: passthrough`): its auth call is lent the caller's verified
    /// credential, and nothing else is presented when the caller presented none.
    pub passthrough: bool,
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
    /// The members, in the operator's configured order, blocklisted ones included.
    pub members: Vec<Member>,
    /// What bounds the walk. Private: its blocklist decides `admissible`, so it is set through
    /// [`Pool::set_failover`] alone.
    pub(crate) failover: Failover,
    /// What to do when the walk finds nowhere to send.
    pub on_exhausted: OnExhausted,
    /// The weighted floor's rotation memory over this pool's members.
    pub floor: WeightedFloor,
    /// `members` less the blocklist, in the same order. `None` when the blocklist names no member of
    /// this pool: then `members` is the admissible list and nothing is held twice.
    pub(crate) admissible: Option<Vec<Member>>,
    /// The pool's waiters now.
    pub queued: QueueDepth,
}

/// How many requests are parked in this pool's wait terminal now. It belongs to the pool, as
/// its rotation memory does: a change looks no pool name up.
#[derive(Debug, Default)]
pub struct QueueDepth(AtomicI64);

/// A copy of a pool is a copy of its configuration; the depth starts at zero.
impl Clone for QueueDepth {
    fn clone(&self) -> Self {
        Self::default()
    }
}

/// The depth is not part of what a pool is: two pools configured alike are equal.
impl PartialEq for QueueDepth {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl Eq for QueueDepth {}

impl QueueDepth {
    /// One waiter more (`1`) or fewer (`-1`): the depth after the change, never below zero.
    pub(crate) fn change(&self, delta: i64) -> i64 {
        let step = |depth: i64| depth.saturating_add(delta).max(0);
        match self
            .0
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |depth| {
                Some(step(depth))
            }) {
            Ok(before) | Err(before) => step(before),
        }
    }
}

impl Pool {
    /// This pool's membership with its own blocklist applied, in the configured order.
    #[must_use]
    #[inline]
    pub fn admissible_members(&self) -> &[Member] {
        self.admissible.as_deref().unwrap_or(&self.members)
    }

    /// What bounds the walk.
    #[must_use]
    #[inline]
    pub fn failover(&self) -> &Failover {
        &self.failover
    }
}
