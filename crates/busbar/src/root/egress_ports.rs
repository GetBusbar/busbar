// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EGRESS WALK'S PRODUCTION PORTS (ARCHITECT Q-SW8, 2026-10-02; SERVE-WIRE P2b): the clock, the
//! members' concurrency permits and the walk's counters, as the composition root binds them for a
//! plane served through its door (`busbar_kernel::plane_driver::Egress`). Each is node-local runtime
//! state that outlives a request; none moves money. (The write-ahead dispatch record, the walk's
//! fourth port, writes onto the money book's journal, so it is composed with the money steps.)
//!
//! A destination here is a member as the generation's seal numbered it: one number per member
//! across every pool of the plane, so a permit and a label key on it alone.

use std::collections::{BTreeSet, HashMap};
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use busbar_kernel_egress::ports::{
    BoxFut, Capacity, Clock, DestinationId, Permit, PermitHandle, StatedLabels, Telemetry,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

// ── the clock ────────────────────────────────────────────────────────────────────────────────────

/// THE NODE'S CLOCK, as the walk reads it: the wall clock's whole seconds for every deadline, a
/// monotonic millisecond reading from the clock's own start for the waits, and the runtime's timer
/// for its one sleep.
#[derive(Debug, Clone, Copy)]
pub struct NodeClock {
    origin: Instant,
}

impl NodeClock {
    /// A clock whose monotonic reading starts now.
    #[must_use]
    pub fn new() -> Self {
        NodeClock {
            origin: Instant::now(),
        }
    }
}

impl Default for NodeClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for NodeClock {
    fn now_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }

    fn now_millis(&self) -> u128 {
        self.origin.elapsed().as_millis()
    }

    fn now_micros(&self) -> u128 {
        self.origin.elapsed().as_micros()
    }

    fn sleep(&self, ms: u64) -> BoxFut<'_, ()> {
        Box::pin(tokio::time::sleep(std::time::Duration::from_millis(ms)))
    }
}

// ── the permits ──────────────────────────────────────────────────────────────────────────────────

/// THE MEMBERS' CONCURRENCY PERMITS: a member with a `max_concurrent` holds that many slots, handed
/// out first come, first served (a freed slot goes to the longest waiter, once); a member with none
/// is never at capacity.
#[derive(Debug, Default)]
pub struct MemberPermits {
    limits: HashMap<DestinationId, Arc<Semaphore>>,
}

/// One slot, freed when the attempt that holds it drops it.
#[derive(Debug)]
struct Slot {
    destination: DestinationId,
    /// `None` for a member with no limit.
    _held: Option<OwnedSemaphorePermit>,
}

impl PermitHandle for Slot {
    fn destination(&self) -> DestinationId {
        self.destination
    }
}

impl MemberPermits {
    /// The permits of members whose `max_concurrent` is stated, `(member, slots)`; every other
    /// member is unlimited.
    #[must_use]
    pub fn new(limits: impl IntoIterator<Item = (DestinationId, usize)>) -> Self {
        MemberPermits {
            limits: limits
                .into_iter()
                .map(|(d, n)| (d, Arc::new(Semaphore::new(n))))
                .collect(),
        }
    }

    /// The free slots of `destination`; `None` for a member with no limit.
    #[must_use]
    pub fn available(&self, destination: DestinationId) -> Option<usize> {
        self.limits.get(&destination).map(|s| s.available_permits())
    }

    fn slot(destination: DestinationId, held: Option<OwnedSemaphorePermit>) -> Permit {
        Permit::new(Box::new(Slot {
            destination,
            _held: held,
        }))
    }
}

impl Capacity for MemberPermits {
    fn try_acquire(&self, destination: DestinationId) -> Option<Permit> {
        match self.limits.get(&destination) {
            None => Some(Self::slot(destination, None)),
            Some(slots) => Arc::clone(slots)
                .try_acquire_owned()
                .ok()
                .map(|held| Self::slot(destination, Some(held))),
        }
    }

    fn acquire_any<'a>(
        &'a self,
        destinations: &'a [DestinationId],
    ) -> BoxFut<'a, Option<(DestinationId, Permit)>> {
        if let Some(free) = destinations.iter().find(|d| !self.limits.contains_key(d)) {
            let free = *free;
            return Box::pin(std::future::ready(Some((free, Self::slot(free, None)))));
        }
        type Wait = std::pin::Pin<
            Box<
                dyn Future<Output = Result<OwnedSemaphorePermit, tokio::sync::AcquireError>> + Send,
            >,
        >;
        let mut waits: Vec<(DestinationId, Wait)> = destinations
            .iter()
            .filter_map(|d| {
                let slots = Arc::clone(self.limits.get(d)?);
                Some((*d, Box::pin(slots.acquire_owned()) as Wait))
            })
            .collect();
        Box::pin(std::future::poll_fn(move |cx| {
            let mut i = 0;
            while i < waits.len() {
                match waits[i].1.as_mut().poll(cx) {
                    Poll::Ready(Ok(held)) => {
                        let d = waits[i].0;
                        return Poll::Ready(Some((d, Self::slot(d, Some(held)))));
                    }
                    // A closed queue frees nothing, ever: it leaves the race.
                    Poll::Ready(Err(_)) => {
                        drop(waits.swap_remove(i));
                    }
                    Poll::Pending => i += 1,
                }
            }
            if waits.is_empty() {
                Poll::Ready(None)
            } else {
                Poll::Pending
            }
        }))
    }
}

// ── the counters ─────────────────────────────────────────────────────────────────────────────────

/// THE WALK'S COUNTERS, on the node's metric families: every attempt, classified failure and fresh
/// trip under its pool and its member's configured name (the lane label), every failover under its
/// pool, and each pool's live wait-terminal depth.
#[derive(Debug, Default)]
pub struct WalkTelemetry {
    names: HashMap<DestinationId, String>,
    depths: Mutex<HashMap<String, i64>>,
    bound: LabelBound,
}

/// THE WORDS A PLANE MAY STATE AS ITS ATTEMPTS' COUNTER LABELS (`OnPieceOut::metric_pool` /
/// `metric_lane`), bounded so no plane can mint a series per distinct string: per walk pool, the
/// `pool` words (the configured pool labels and the entry names the walk over it can reach) and
/// the `lane` words (those entry names), and the plane's declared lane vocabulary beside them
/// (`PlaneTail::metric_lanes`). Empty: nothing stated is taken.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LabelBound {
    reach: HashMap<String, (BTreeSet<String>, BTreeSet<String>)>,
    vocabulary: BTreeSet<String>,
}

impl LabelBound {
    /// A bound over `vocabulary`, the plane's declared lane words, and no walk pool yet.
    #[must_use]
    pub fn new(vocabulary: impl IntoIterator<Item = String>) -> Self {
        LabelBound {
            reach: HashMap::new(),
            vocabulary: vocabulary.into_iter().collect(),
        }
    }

    /// What the walk over the pool named `walked` can reach: `pool_words` its `pool` label may
    /// state, `entries` its `lane` label may state (and its `pool` label too).
    #[must_use]
    pub fn reaching(
        mut self,
        walked: &str,
        pool_words: impl IntoIterator<Item = String>,
        entries: impl IntoIterator<Item = String>,
    ) -> Self {
        let entries: BTreeSet<String> = entries.into_iter().collect();
        let pools = pool_words
            .into_iter()
            .chain(entries.iter().cloned())
            .collect();
        self.reach.insert(walked.to_string(), (pools, entries));
        self
    }

    /// The `(pool, lane)` labels of one emission over the walk pool `walked` whose own labels are
    /// `own`: each label the plane `stated` within the bound, its own otherwise; `true` when the
    /// plane stated a word outside it.
    #[must_use]
    pub fn labels(
        &self,
        walked: &str,
        own: (&str, &str),
        stated: Option<&StatedLabels>,
    ) -> (String, String, bool) {
        let Some(stated) = stated else {
            return (own.0.to_string(), own.1.to_string(), false);
        };
        let reach = self.reach.get(walked);
        let mut refused = false;
        let mut take = |word: &Option<String>, ok: &dyn Fn(&str) -> bool, own: &str| match word {
            Some(w) if ok(w) => w.clone(),
            Some(_) => {
                refused = true;
                own.to_string()
            }
            None => own.to_string(),
        };
        let pool = take(
            &stated.pool,
            &|w| reach.is_some_and(|(pools, _)| pools.contains(w)),
            own.0,
        );
        let lane = take(
            &stated.lane,
            &|w| {
                reach.is_some_and(|(_, entries)| entries.contains(w)) || self.vocabulary.contains(w)
            },
            own.1,
        );
        (pool, lane, refused)
    }
}

impl WalkTelemetry {
    /// Counters labelling each member by its configured name, `(member, name)`.
    #[must_use]
    pub fn new(names: impl IntoIterator<Item = (DestinationId, String)>) -> Self {
        WalkTelemetry {
            names: names.into_iter().collect(),
            depths: Mutex::new(HashMap::new()),
            bound: LabelBound::default(),
        }
    }

    /// The same counters, taking the labels a plane states within `bound`.
    #[must_use]
    pub fn bounded(mut self, bound: LabelBound) -> Self {
        self.bound = bound;
        self
    }

    /// The `(pool, lane)` labels one emission over the walk pool `pool` for `destination` carries:
    /// the plane's `stated` labels within the bound, the walk's own otherwise; a stated word outside
    /// it is counted refused (`busbar_plugin_label_refused_total`).
    #[must_use]
    pub fn labels(
        &self,
        pool: &str,
        destination: DestinationId,
        stated: Option<&StatedLabels>,
    ) -> (String, String) {
        let (pool, lane, refused) = self
            .bound
            .labels(pool, (pool, self.lane(destination)), stated);
        if refused {
            busbar_kernel::telemetry::plugin_label_refused();
        }
        (pool, lane)
    }

    /// A member's lane label: its configured name; empty for a member the seal did not name.
    #[must_use]
    pub fn lane(&self, destination: DestinationId) -> &str {
        self.names.get(&destination).map_or("", String::as_str)
    }

    /// The wait-terminal depth of `pool`, as the gauge last reads it.
    #[must_use]
    pub fn depth(&self, pool: &str) -> i64 {
        self.depths
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(pool)
            .copied()
            .unwrap_or(0)
    }
}

impl Telemetry for WalkTelemetry {
    fn upstream_attempt(&self, pool: &str, destination: DestinationId) {
        busbar_kernel::telemetry::upstream_attempt_on(pool, self.lane(destination));
    }

    fn upstream_failure(&self, pool: &str, destination: DestinationId, disposition: &'static str) {
        busbar_kernel::telemetry::upstream_failure_on(pool, self.lane(destination), disposition);
    }

    fn upstream_attempt_stated(
        &self,
        pool: &str,
        destination: DestinationId,
        stated: Option<&StatedLabels>,
    ) {
        let (pool, lane) = self.labels(pool, destination, stated);
        busbar_kernel::telemetry::upstream_attempt_on(&pool, &lane);
    }

    fn upstream_failure_stated(
        &self,
        pool: &str,
        destination: DestinationId,
        disposition: &'static str,
        stated: Option<&StatedLabels>,
    ) {
        let (pool, lane) = self.labels(pool, destination, stated);
        busbar_kernel::telemetry::upstream_failure_on(&pool, &lane, disposition);
    }

    fn failover(&self, pool: &str, reason: &'static str) {
        busbar_kernel::telemetry::failover_on(pool, reason);
    }

    fn breaker_trip(&self, pool: &str, destination: DestinationId) {
        busbar_kernel::telemetry::breaker_trip_on(pool, self.lane(destination));
    }

    fn queued(&self, pool: &str, delta: i64) {
        let depth = {
            let mut depths = self
                .depths
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let depth = depths.entry(pool.to_string()).or_insert(0);
            *depth = depth.saturating_add(delta).max(0);
            *depth
        };
        busbar_kernel::telemetry::pool_queued_on(pool, depth);
    }
}

#[cfg(test)]
#[path = "tests/egress_ports.rs"]
mod tests;
