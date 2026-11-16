// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! [`StoreRecords`]: the plugin-records namespace over the configured store, through CoreStore (IF §12.5).
//! W1-K5 red: the API and the key layout; every operation is held as `todo!()`.

use core::future::Future;
use std::sync::Arc;

use busbar_plugin_abi::host_side::caller::Caller;

use crate::persistence::facade::CoreStore;

use super::{ChainRead, CommitOp, CommitOutcome, PluginRecords, RecordsDenied, Scope};

/// Plain records.
pub(super) const RECORDS: &str = "busbar.plugin-records.v1";
/// Host chains: one head row and one row per entry (chain.rs).
pub(super) const CHAINS: &str = "busbar.plugin-chains.v1";

/// The plugin-records namespace over CoreStore. One per process, shared (`Arc`) by every consumer.
pub struct StoreRecords {
    store: Arc<CoreStore>,
    clock: fn() -> u64,
}

impl StoreRecords {
    /// Records over `store`, timed by the wall clock.
    #[must_use]
    pub fn new(store: Arc<CoreStore>) -> Self {
        Self::with_clock(store, crate::store::now)
    }

    /// Records over `store`; `clock` answers UNIX seconds (TTLs are judged against it).
    #[must_use]
    pub fn with_clock(store: Arc<CoreStore>, clock: fn() -> u64) -> Self {
        Self { store, clock }
    }

    /// Drive the parked in-doubt writes once more; answers how many are still parked.
    pub async fn settle(&self) -> usize {
        let _ = self.clock;
        todo!("W1-K5")
    }

    /// Delete expired records of `who`'s namespace (every scope), at most one batch.
    pub async fn sweep_expired(&self, who: &Caller<'_>) -> Result<u32, RecordsDenied> {
        let _ = who;
        todo!("W1-K5")
    }

    #[cfg(test)]
    pub(super) fn store_for_tests(&self) -> &Arc<CoreStore> {
        &self.store
    }
}

impl PluginRecords for StoreRecords {
    fn get(
        &self,
        who: &Caller<'_>,
        scope: Scope,
        key: &[u8],
        sink: &mut (dyn FnMut(&[u8]) + Send),
    ) -> impl Future<Output = Result<bool, RecordsDenied>> + Send {
        let _ = (who, scope, key, sink);
        async move { held::<Result<bool, RecordsDenied>>() }
    }

    fn put(
        &self,
        who: &Caller<'_>,
        scope: Scope,
        key: &[u8],
        value: &[u8],
        ttl_s: u64,
    ) -> impl Future<Output = Result<(), RecordsDenied>> + Send {
        let _ = (who, scope, key, value, ttl_s);
        async move { held::<Result<(), RecordsDenied>>() }
    }

    fn claim(
        &self,
        who: &Caller<'_>,
        scope: Scope,
        key: &[u8],
        value: &[u8],
        ttl_s: u64,
    ) -> impl Future<Output = Result<bool, RecordsDenied>> + Send {
        let _ = (who, scope, key, value, ttl_s);
        async move { held::<Result<bool, RecordsDenied>>() }
    }

    fn del(
        &self,
        who: &Caller<'_>,
        scope: Scope,
        key: &[u8],
    ) -> impl Future<Output = Result<(), RecordsDenied>> + Send {
        let _ = (who, scope, key);
        async move { held::<Result<(), RecordsDenied>>() }
    }

    fn list(
        &self,
        who: &Caller<'_>,
        scope: Scope,
        prefix: &[u8],
        limit: u32,
        sink: &mut (dyn FnMut(&[u8], &[u8]) + Send),
    ) -> impl Future<Output = Result<u32, RecordsDenied>> + Send {
        let _ = (who, scope, prefix, limit, sink);
        async move { held::<Result<u32, RecordsDenied>>() }
    }

    fn commit(
        &self,
        who: &Caller<'_>,
        scope: Scope,
        ops: &[CommitOp<'_>],
    ) -> impl Future<Output = Result<CommitOutcome, RecordsDenied>> + Send {
        let _ = (who, scope, ops);
        async move { held::<Result<CommitOutcome, RecordsDenied>>() }
    }

    fn append(
        &self,
        who: &Caller<'_>,
        scope: Scope,
        chain: &[u8],
        entry: &[u8],
    ) -> impl Future<Output = Result<u64, RecordsDenied>> + Send {
        let _ = (who, scope, chain, entry);
        async move { held::<Result<u64, RecordsDenied>>() }
    }

    fn chain(
        &self,
        who: &Caller<'_>,
        scope: Scope,
        chain: &[u8],
        after: u64,
        limit: u32,
        sink: &mut (dyn FnMut(u64, &[u8]) + Send),
    ) -> impl Future<Output = Result<ChainRead, RecordsDenied>> + Send {
        let _ = (who, scope, chain, after, limit, sink);
        async move { held::<Result<ChainRead, RecordsDenied>>() }
    }
}

/// The host-private scope of one instance: (stamp name, configured instance name), length-framed.
pub(crate) fn label(who: &Caller<'_>) -> String {
    format!("{}:{}/{}", who.plugin.len(), who.plugin, who.name)
}

/// `key` in `scope`: `0 ‖ key` for the instance's own records, `1 ‖ subject ‖ key` for one caller's.
pub(super) fn scoped_key(scope: Scope, key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(33 + key.len());
    match scope.subject {
        None => out.push(0),
        Some(subject) => {
            out.push(1);
            out.extend_from_slice(&subject);
        }
    }
    out.extend_from_slice(key);
    out
}

/// W1-K5 red: an operation not written yet.
fn held<T>() -> T {
    todo!("W1-K5")
}
