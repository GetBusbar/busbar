// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::BTreeSet;
use std::future::Future;
use std::sync::Arc;
use std::task::Poll;

use foldhash::HashMap;

use busbar_kernel_egress::ports::{
    BoxFut, Capacity, DestinationId, Permit, PermitHandle, StatedLabels, Telemetry,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// How the node's one host clock sleeps: the runtime's timer, until an absolute `Instant` (GROUP-time 3.2).
/// The root builds the clock with it once: `HostClock::system(tokio_sleep)`.
pub fn tokio_sleep(at: std::time::Instant) -> busbar_contract::clock::Sleep {
    Box::pin(tokio::time::sleep_until(tokio::time::Instant::from_std(at)))
}

/// THE MEMBERS' CONCURRENCY PERMITS: a member with a `max_concurrent` holds that many slots, handed
/// out first come, first served (a freed slot goes to the longest waiter, once); a member with none
/// is never at capacity.
#[derive(Debug, Default)]
pub struct MemberPermits {
    pub(crate) limits: HashMap<DestinationId, Arc<Semaphore>>,
}

/// A pending slot acquisition of a wait-for-any.
pub(crate) type Wait = std::pin::Pin<
    Box<dyn Future<Output = Result<OwnedSemaphorePermit, tokio::sync::AcquireError>> + Send>,
>;

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
        let mut waits = self.waits(destinations);
        Box::pin(std::future::poll_fn(move |cx| {
            let mut i = 0;
            while i < waits.len() {
                match waits[i].1.as_mut().poll(cx) {
                    Poll::Ready(Ok(held)) => {
                        let d = waits[i].0;
                        return Poll::Ready(Some((d, Self::slot(d, Some(held)))));
                    }

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

/// THE WALK'S COUNTERS, on the node's metric families: every attempt, classified failure and fresh
/// trip under its pool and its member's configured name (the lane label), every failover under its
/// pool, and each pool's live wait-terminal depth.
#[derive(Debug, Default)]
pub struct WalkTelemetry {
    pub(crate) names: HashMap<DestinationId, String>,
    pub(crate) bound: LabelBound,
}

/// THE WORDS A PLANE MAY STATE AS ITS ATTEMPTS' COUNTER LABELS (`OnPieceOut::metric_pool` /
/// `metric_lane`), bounded so no plane can mint a series per distinct string: per walk pool, the
/// `pool` words (the configured pool labels and the entry names the walk over it can reach) and
/// the `lane` words (those entry names), and the plane's declared lane vocabulary beside them
/// (`PlaneTail::metric_lanes`). Empty: nothing stated is taken.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LabelBound {
    pub(crate) reach: HashMap<String, (BTreeSet<String>, BTreeSet<String>)>,
    pub(crate) vocabulary: BTreeSet<String>,
}

impl LabelBound {
    #[must_use]
    pub fn labels<'a>(
        &self,
        walked: &str,
        own: (&'a str, &'a str),
        stated: Option<&'a StatedLabels>,
    ) -> (&'a str, &'a str, bool) {
        let Some(stated) = stated else {
            return (own.0, own.1, false);
        };
        let reach = self.reach.get(walked);
        let mut refused = false;
        let mut take =
            |word: &'a Option<String>, ok: &dyn Fn(&str) -> bool, own: &'a str| match word {
                Some(w) if ok(w) => w.as_str(),
                Some(_) => {
                    refused = true;
                    own
                }
                None => own,
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
    #[must_use]
    pub fn labels<'a>(
        &'a self,
        pool: &'a str,
        destination: DestinationId,
        stated: Option<&'a StatedLabels>,
    ) -> (&'a str, &'a str) {
        let (pool, lane, refused) = self
            .bound
            .labels(pool, (pool, self.lane(destination)), stated);
        if refused {
            busbar_kernel::telemetry::plugin_label_refused();
        }
        (pool, lane)
    }

    #[must_use]
    pub fn lane(&self, destination: DestinationId) -> &str {
        self.names.get(&destination).map_or("", String::as_str)
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
        busbar_kernel::telemetry::upstream_attempt_on(pool, lane);
    }

    fn upstream_failure_stated(
        &self,
        pool: &str,
        destination: DestinationId,
        disposition: &'static str,
        stated: Option<&StatedLabels>,
    ) {
        let (pool, lane) = self.labels(pool, destination, stated);
        busbar_kernel::telemetry::upstream_failure_on(pool, lane, disposition);
    }

    fn failover(&self, pool: &str, reason: &'static str) {
        busbar_kernel::telemetry::failover_on(pool, reason);
    }

    fn breaker_trip(&self, pool: &str, destination: DestinationId) {
        busbar_kernel::telemetry::breaker_trip_on(pool, self.lane(destination));
    }

    fn queued(&self, pool: &str, _delta: i64, depth: i64) {
        busbar_kernel::telemetry::pool_queued_on(pool, depth);
    }
}

#[cfg(test)]
#[path = "tests/egress_ports.rs"]
mod tests;
