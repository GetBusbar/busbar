// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The durable push queue behind plane PUSH intents (IF §12.9).
//!
//! Layout. One host-private scope per (stamp name, configured instance name), schema [`PUSHES`]; one row per
//! queued push, keyed by a CoreStore operation id (unique, never the runtime instance id). A row's stored
//! value is `1 ‖ expires_at (u64 BE, UNIX s) ‖ next_at (u64 BE, UNIX s) ‖ attempt (u32 BE) ‖ recs`, `recs` the
//! PUSH tail as the plane wrote it (nested H_METHOD, PUSH_URL, PAIR*, BODY), copied and owned by core.
//!
//! Delivery. [`StorePushQueue::deliver_due`] runs from the owner's tick with the live instance of that name as
//! Caller and hands each due row to a [`PushSink`]: the connector's fetch, whose guard judges every new
//! connection (§12.1), so a URL accepted at set time that later resolves internal is refused at delivery.
//! A failed attempt asks `RetryPolicy(PlanePush)`; Stop or a passed `ttl_s` drops the row and names it for the
//! audit. [`StorePushQueue::forget`] drops every row of an instance name no longer configured.

use std::sync::Arc;

use busbar_plugin_abi::host_side::caller::{BoxFut, Caller};

use crate::persistence::facade::CoreStore;
use crate::plugin_records::RecordsDenied;
use crate::retry::{PortError, RetryPolicy};

/// Plane PUSH intents. Durable (CoreStore, rows keyed by (who.plugin, who.name), never the runtime id),
/// at-least-once, deliveries through the connector's fetch with the live instance of that name as Caller
/// (the connector's guard judges every new connection, §12.1), retries via RetryPolicy(PlanePush), dropped and audited after ttl_s or when no
/// instance of that name is configured. The plane learns nothing back (it may record its own bookkeeping).
/// Round 16: a plane that must refuse a bad callback **when the client sets it** (plane-a2a's push config) asks
/// first with the JUDGE intent (§8.6, §12.1 `PlaneJudge`) and refuses in its own protocol; the delivery-time judge
/// here still applies to every attempt (DNS can change between the two).
pub trait PushQueue: Send + Sync + 'static {
    fn enqueue<'a>(
        &'a self,
        who: &'a Caller<'_>,
        ttl_s: u64,
        recs: &'a [u8],
    ) -> BoxFut<'a, Result<(), RecordsDenied>>;
}

/// The queued pushes.
pub const PUSHES: &str = "busbar.plane-push.v1";

/// The largest PUSH tail core queues.
pub const MAX_PUSH: usize = crate::plugin_records::MAX_VALUE;

/// The longest a push is kept (the record horizon, §12.5).
pub const MAX_PUSH_TTL_S: u64 = crate::plugin_records::MAX_TTL_S;

/// The most rows one [`StorePushQueue::deliver_due`] round attempts.
pub const ROUND: usize = 64;

/// One delivery attempt: the connector's fetch under the live instance's Caller and the connector's guard.
pub trait PushSink: Send + Sync {
    fn deliver<'a>(
        &'a self,
        who: &'a Caller<'_>,
        recs: &'a [u8],
    ) -> BoxFut<'a, Result<(), PortError>>;
}

/// Why a row left the queue undelivered (the caller audits `plane_push_dropped` with it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dropped {
    /// `ttl_s` passed.
    Expired,
    /// `RetryPolicy(PlanePush)` answered Stop.
    GaveUp,
    /// No instance of that name is configured any more.
    Unconfigured,
}

/// One delivery round's facts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Round {
    pub delivered: u32,
    pub retried: u32,
    pub dropped: Vec<Dropped>,
}

/// The push queue over CoreStore. One per process, shared (`Arc`) by the plane adapter and the tick.
pub struct StorePushQueue {
    store: Arc<CoreStore>,
    clock: fn() -> u64,
    policy: Arc<dyn RetryPolicy>,
}

impl StorePushQueue {
    #[must_use]
    pub fn new(store: Arc<CoreStore>, policy: Arc<dyn RetryPolicy>) -> Self {
        Self::with_clock(store, policy, crate::store::now)
    }

    /// `clock` answers UNIX seconds.
    #[must_use]
    pub fn with_clock(
        store: Arc<CoreStore>,
        policy: Arc<dyn RetryPolicy>,
        clock: fn() -> u64,
    ) -> Self {
        Self {
            store,
            clock,
            policy,
        }
    }

    /// Attempt every row of `who` that is due, at most [`ROUND`].
    pub async fn deliver_due(
        &self,
        who: &Caller<'_>,
        sink: &dyn PushSink,
    ) -> Result<Round, RecordsDenied> {
        let _ = (who, sink, &self.store, self.clock, &self.policy);
        todo!()
    }

    /// The instance name is no longer configured: every row of it is dropped. Answers how many.
    pub async fn forget(&self, who: &Caller<'_>) -> Result<u32, RecordsDenied> {
        let _ = who;
        todo!()
    }

    /// Rows queued for `who`.
    pub async fn queued(&self, who: &Caller<'_>) -> Result<u32, RecordsDenied> {
        let _ = who;
        todo!()
    }
}

impl PushQueue for StorePushQueue {
    fn enqueue<'a>(
        &'a self,
        who: &'a Caller<'_>,
        ttl_s: u64,
        recs: &'a [u8],
    ) -> BoxFut<'a, Result<(), RecordsDenied>> {
        let _ = (who, ttl_s, recs);
        todo!()
    }
}

#[cfg(test)]
mod tests;
