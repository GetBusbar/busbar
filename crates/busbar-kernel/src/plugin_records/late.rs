// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! [`LateRecords`]: the records owner a `HostNeeds` is built over before the store it serves exists.
//!
//! The registry owns the Need handlers and the store opens through the registry, so the handlers are built before
//! the store (boot step 2b). `LateRecords` is the handle they own: every call answers `Unavailable` until the boot
//! installs the one records owner (once, after the store opens and before the first 2c instance), and from then
//! on it is that owner. Clones share the one slot.

use core::future::Future;
use std::sync::{Arc, OnceLock};

use busbar_plugin_abi::host_side::caller::Caller;

use super::{ChainRead, CommitOp, CommitOutcome, PluginRecords, RecordsDenied, Scope};

/// The records owner that is not there yet.
pub struct LateRecords<R: PluginRecords> {
    slot: Arc<OnceLock<R>>,
}

impl<R: PluginRecords> Clone for LateRecords<R> {
    fn clone(&self) -> Self {
        Self {
            slot: Arc::clone(&self.slot),
        }
    }
}

impl<R: PluginRecords> Default for LateRecords<R> {
    fn default() -> Self {
        Self {
            slot: Arc::new(OnceLock::new()),
        }
    }
}

impl<R: PluginRecords> LateRecords<R> {
    /// The owner every clone answers through from now on. The first install stays: false = one was installed.
    pub fn install(&self, records: R) -> bool {
        self.slot.set(records).is_ok()
    }
}

impl<R: PluginRecords> PluginRecords for LateRecords<R> {
    fn get(
        &self,
        who: &Caller<'_>,
        scope: Scope,
        key: &[u8],
        sink: &mut (dyn FnMut(&[u8]) + Send),
    ) -> impl Future<Output = Result<bool, RecordsDenied>> + Send {
        async move {
            match self.slot.get() {
                Some(records) => records.get(who, scope, key, sink).await,
                None => Err(RecordsDenied::Unavailable),
            }
        }
    }
    fn put(
        &self,
        who: &Caller<'_>,
        scope: Scope,
        key: &[u8],
        value: &[u8],
        ttl_s: u64,
    ) -> impl Future<Output = Result<(), RecordsDenied>> + Send {
        async move {
            match self.slot.get() {
                Some(records) => records.put(who, scope, key, value, ttl_s).await,
                None => Err(RecordsDenied::Unavailable),
            }
        }
    }
    fn claim(
        &self,
        who: &Caller<'_>,
        scope: Scope,
        key: &[u8],
        value: &[u8],
        ttl_s: u64,
    ) -> impl Future<Output = Result<bool, RecordsDenied>> + Send {
        async move {
            match self.slot.get() {
                Some(records) => records.claim(who, scope, key, value, ttl_s).await,
                None => Err(RecordsDenied::Unavailable),
            }
        }
    }
    fn del(
        &self,
        who: &Caller<'_>,
        scope: Scope,
        key: &[u8],
    ) -> impl Future<Output = Result<(), RecordsDenied>> + Send {
        async move {
            match self.slot.get() {
                Some(records) => records.del(who, scope, key).await,
                None => Err(RecordsDenied::Unavailable),
            }
        }
    }
    fn list(
        &self,
        who: &Caller<'_>,
        scope: Scope,
        prefix: &[u8],
        limit: u32,
        sink: &mut (dyn FnMut(&[u8], &[u8]) + Send),
    ) -> impl Future<Output = Result<u32, RecordsDenied>> + Send {
        async move {
            match self.slot.get() {
                Some(records) => records.list(who, scope, prefix, limit, sink).await,
                None => Err(RecordsDenied::Unavailable),
            }
        }
    }
    fn commit(
        &self,
        who: &Caller<'_>,
        scope: Scope,
        ops: &[CommitOp<'_>],
    ) -> impl Future<Output = Result<CommitOutcome, RecordsDenied>> + Send {
        async move {
            match self.slot.get() {
                Some(records) => records.commit(who, scope, ops).await,
                None => Err(RecordsDenied::Unavailable),
            }
        }
    }
    fn append(
        &self,
        who: &Caller<'_>,
        scope: Scope,
        chain: &[u8],
        entry: &[u8],
    ) -> impl Future<Output = Result<u64, RecordsDenied>> + Send {
        async move {
            match self.slot.get() {
                Some(records) => records.append(who, scope, chain, entry).await,
                None => Err(RecordsDenied::Unavailable),
            }
        }
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
        async move {
            match self.slot.get() {
                Some(records) => records.chain(who, scope, chain, after, limit, sink).await,
                None => Err(RecordsDenied::Unavailable),
            }
        }
    }
}
