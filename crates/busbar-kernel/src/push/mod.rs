// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The durable push queue behind plane PUSH intents (IF §12.9).
//!
//! Layout. One host-private scope per (stamp name, configured instance name), schema `PUSHES`; one row per
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

use busbar_contract::Secret;

use crate::persistence::facade::CoreStore;
use crate::persistence::scoped::{Expected, Mutation, Predicate, Request, ScopedStore};
use crate::plugin_records::store::{denied, expiry, label, live, operation, InDoubt};
use crate::plugin_records::RecordsDenied;
use crate::retry::{PortError, Retry, RetryPolicy, RetrySite};

mod fetch;
pub use fetch::ConnectorPushSink;

/// The queued pushes.
pub(crate) const PUSHES: &str = "busbar.plane-push.v1";

/// The largest PUSH tail core queues.
pub const MAX_PUSH: usize = crate::plugin_records::MAX_VALUE;

/// The longest a push is kept (the record horizon, §12.5).
pub(crate) const MAX_PUSH_TTL_S: u64 = crate::plugin_records::MAX_TTL_S;

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
    in_doubt: InDoubt,
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
            in_doubt: InDoubt::new(Arc::clone(&store)),
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
        self.deliver_round(who, sink).await
    }

    /// The instance name is no longer configured: every row of it is dropped. Answers how many.
    pub async fn forget(&self, who: &Caller<'_>) -> Result<u32, RecordsDenied> {
        self.forget_all(who).await
    }

    /// Rows queued for `who`.
    pub async fn queued(&self, who: &Caller<'_>) -> Result<u32, RecordsDenied> {
        Ok(u32::try_from(self.rows(who).await?.len()).unwrap_or(u32::MAX))
    }
}

impl StorePushQueue {
    /// Queue one plane PUSH (arch lints section 3.1: the one queue is this concrete type). Durable (CoreStore,
    /// rows keyed by (who.plugin, who.name), never the runtime id), at-least-once, delivered through the
    /// connector's fetch with the live instance of that name as Caller (the connector's guard judges every new
    /// connection, section 12.1), retried via RetryPolicy(PlanePush), dropped and audited after ttl_s or when no
    /// instance of that name is configured. The plane learns nothing back. Round 16: a plane that must refuse a
    /// bad callback when the client sets it asks first with the JUDGE intent (section 8.6, 12.1 `PlaneJudge`);
    /// the delivery-time judge still applies to every attempt (DNS can change between the two).
    pub fn enqueue<'a>(
        &'a self,
        who: &'a Caller<'_>,
        ttl_s: u64,
        recs: &'a [u8],
    ) -> BoxFut<'a, Result<(), RecordsDenied>> {
        Box::pin(self.enqueue_one(who, ttl_s, recs))
    }
}

/// One stored row, decoded.
struct Row {
    key: Vec<u8>,
    raw: Secret<Vec<u8>>,
    expires_at: u64,
    next_at: u64,
    attempt: u32,
    recs: Vec<u8>,
}

/// The stored form: `1 ‖ expires_at ‖ next_at ‖ attempt ‖ recs` (module docs).
fn envelope(expires_at: u64, next_at: u64, attempt: u32, recs: &[u8]) -> Secret<Vec<u8>> {
    let mut out = Vec::with_capacity(21 + recs.len());
    out.push(1);
    out.extend_from_slice(&expires_at.to_be_bytes());
    out.extend_from_slice(&next_at.to_be_bytes());
    out.extend_from_slice(&attempt.to_be_bytes());
    out.extend_from_slice(recs);
    Secret::new(out)
}

fn decode(key: Vec<u8>, raw: Secret<Vec<u8>>) -> Option<Row> {
    let (expires_at, next_at, attempt, recs) = {
        let seal = crate::seal::lend();
        let bytes = raw.expose(&seal);
        let (&version, rest) = bytes.split_first()?;
        if version != 1 || rest.len() < 20 {
            return None;
        }
        (
            u64::from_be_bytes(rest[..8].try_into().ok()?),
            u64::from_be_bytes(rest[8..16].try_into().ok()?),
            u32::from_be_bytes(rest[16..20].try_into().ok()?),
            rest[20..].to_vec(),
        )
    };
    Some(Row {
        key,
        raw,
        expires_at,
        next_at,
        attempt,
        recs,
    })
}

impl StorePushQueue {
    fn scoped(&self, who: &Caller<'_>) -> Result<ScopedStore, RecordsDenied> {
        ScopedStore::host_private(Arc::clone(&self.store), &label(who), [PUSHES.to_string()])
            .and_then(|records| self.in_doubt.bind(records))
            .map_err(denied)
    }

    async fn enqueue_one(
        &self,
        who: &Caller<'_>,
        ttl_s: u64,
        recs: &[u8],
    ) -> Result<(), RecordsDenied> {
        if recs.is_empty() {
            return Err(RecordsDenied::Invalid);
        }
        if recs.len() > MAX_PUSH {
            return Err(RecordsDenied::TooLarge);
        }
        let records = self.scoped(who)?;
        self.in_doubt.settle_one().await;
        let now = (self.clock)();
        let ttl = if ttl_s == 0 { MAX_PUSH_TTL_S } else { ttl_s };
        let key = self
            .store
            .next_id()
            .map_err(|_| RecordsDenied::Unavailable)?
            .operation;
        let first = records
            .put(PUSHES, &key, envelope(expiry(now, ttl), now, 0, recs))
            .await;
        if self.in_doubt.decided(&records, first).await? {
            Ok(())
        } else {
            Err(RecordsDenied::Unavailable)
        }
    }

    /// Every row of `who`'s scope, decoded; rows this owner never wrote are left alone.
    async fn rows(&self, who: &Caller<'_>) -> Result<Vec<Row>, RecordsDenied> {
        let records = self.scoped(who)?;
        let mut out = Vec::new();
        let mut cursor = None;
        loop {
            let page = records
                .page(PUSHES, &[], cursor.as_ref())
                .await
                .map_err(denied)?;
            out.extend(
                page.rows
                    .into_iter()
                    .filter_map(|(key, raw)| decode(key, raw)),
            );
            match page.next {
                Some(next) => cursor = Some(next),
                None => return Ok(out),
            }
        }
    }

    /// Delete `row` under an exact predicate: true = this call removed it.
    async fn remove(&self, records: &ScopedStore, row: &Row) -> Result<bool, RecordsDenied> {
        let request = records
            .prepare_delete_exact(PUSHES, &row.key, row.raw.clone())
            .await
            .map_err(denied)?;
        let first = records.conditional_native(&request).await;
        self.in_doubt.decided(records, first).await
    }

    async fn deliver_round(
        &self,
        who: &Caller<'_>,
        sink: &dyn PushSink,
    ) -> Result<Round, RecordsDenied> {
        let records = self.scoped(who)?;
        self.in_doubt.settle_one().await;
        let now = (self.clock)();
        let mut round = Round::default();
        let mut handled = 0;
        for row in self.rows(who).await? {
            if handled == ROUND {
                break;
            }
            if !live(row.expires_at, now) {
                handled += 1;
                if self.remove(&records, &row).await? {
                    round.dropped.push(Dropped::Expired);
                }
                continue;
            }
            if row.next_at > now {
                continue;
            }
            handled += 1;
            match sink.deliver(who, &row.recs).await {
                Ok(()) => {
                    if self.remove(&records, &row).await? {
                        round.delivered += 1;
                    }
                }
                Err(err) => {
                    let attempt = row.attempt.saturating_add(1);
                    match self.policy.next(RetrySite::PlanePush, attempt, &err) {
                        Retry::Stop => {
                            if self.remove(&records, &row).await? {
                                round.dropped.push(Dropped::GaveUp);
                            }
                        }
                        Retry::After(wait) => {
                            let secs = wait.as_secs() + u64::from(wait.subsec_nanos() > 0);
                            let value = envelope(
                                row.expires_at,
                                now.saturating_add(secs),
                                attempt,
                                &row.recs,
                            );
                            // A removal or another worker may have settled this row while the
                            // connector was in flight. Retry only the version we delivered.
                            let request = Request {
                                op: operation(&self.store).await?,
                                predicates: vec![Predicate {
                                    schema: PUSHES.into(),
                                    key: row.key.clone(),
                                    expected: Expected::Exact(row.raw.clone()),
                                }],
                                mutations: vec![Mutation::Put {
                                    schema: PUSHES.into(),
                                    key: row.key.clone(),
                                    value,
                                }],
                            };
                            let first = records.conditional_native(&request).await;
                            if self.in_doubt.decided(&records, first).await? {
                                round.retried += 1;
                            }
                        }
                    }
                }
            }
        }
        Ok(round)
    }

    async fn forget_all(&self, who: &Caller<'_>) -> Result<u32, RecordsDenied> {
        let records = self.scoped(who)?;
        let mut dropped = 0;
        for row in self.rows(who).await? {
            let first = records.delete(PUSHES, &row.key).await;
            if self.in_doubt.decided(&records, first).await? {
                dropped += 1;
            }
        }
        Ok(dropped)
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod fetch_tests;
