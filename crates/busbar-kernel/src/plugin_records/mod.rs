// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Plugin records: RECORD Needs and plane LOOKUP/STORE/DELETE/COMMIT over core's store (IF §12.5). The frozen
//! contract is below; [`StoreRecords`] (store.rs, chain.rs) keeps it over the configured store through CoreStore.

use core::future::Future;

use busbar_plugin_abi::host_side::caller::Caller;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordsDenied {
    Quota,
    TooLarge,
    Unavailable,
    Invalid,
}
/// subject = SHA-256 of the request's ID_SUBJECT for plane LK_CALLER / REC_CALLER records, else None. Part of
/// the key, so one caller can never read another caller's caller-bound record.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Scope {
    pub subject: Option<[u8; 32]>,
}
/// One commit operation. `caller` = REC_CALLER (the op uses the commit's subject scope; plane only).
#[derive(Clone, Copy, Debug)]
pub enum CommitOp<'a> {
    Absent {
        key: &'a [u8],
        caller: bool,
    },
    Present {
        key: &'a [u8],
        caller: bool,
    },
    Equals {
        key: &'a [u8],
        value: &'a [u8],
        caller: bool,
    },
    Put {
        key: &'a [u8],
        value: &'a [u8],
        ttl_s: u64,
        caller: bool,
    },
    Del {
        key: &'a [u8],
        caller: bool,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitOutcome {
    Applied,
    Conflict { failed: u32 },
}
/// RECORD Needs and plane LOOKUP/STORE/DELETE/COMMIT. Namespace = (who.plugin, who.name, scope): the verified
/// stamp name and the **configured instance name** (stable across restart, reconfigure and replicas; never the
/// runtime id, never a config hash), chosen by core and never shown to the plugin. Backed by the configured store
/// through CoreStore (slotted commits); `commit` is exactly one CoreStore commit whose predicates and mutations
/// are the ops (one `PersistenceBackend::commit`: all or nothing, as origin/dev; round 17 drops the STORE-TRANSACTIONS citation). **Round 12, TTL:**
/// `ttl_s` 0 = no expiry, everywhere (RECORD Need, plane STORE, REC_PUT, `put`/`claim`/`CommitOp::Put`); a
/// non-zero value is clamped to 1..=`MAX_TTL_S` (K5's constant, today's plugin-records maximum, unchanged).
/// Unexpiring records are bounded by the instance's records quota (`RecordsDenied::Quota`), not by time. ≤
/// commit::MAX_OPS ops. Replaces round 1's `Sessions` trait, door_tasks/door_sessions and
/// `sdk/plane/conditional`.
/// Not dyn: RPITIT (I5), consumers generic over `R: PluginRecords`. Values are handed to `sink` while the
/// store's read buffer is live (no intermediate Vec).
pub trait PluginRecords: Send + Sync + 'static {
    /// Ok(true) = found; `sink(value)` was called once.
    fn get(
        &self,
        who: &Caller<'_>,
        scope: Scope,
        key: &[u8],
        sink: &mut (dyn FnMut(&[u8]) + Send),
    ) -> impl Future<Output = Result<bool, RecordsDenied>> + Send;
    fn put(
        &self,
        who: &Caller<'_>,
        scope: Scope,
        key: &[u8],
        value: &[u8],
        ttl_s: u64,
    ) -> impl Future<Output = Result<(), RecordsDenied>> + Send;
    /// Put-if-absent. Ok(true) = this caller won.
    fn claim(
        &self,
        who: &Caller<'_>,
        scope: Scope,
        key: &[u8],
        value: &[u8],
        ttl_s: u64,
    ) -> impl Future<Output = Result<bool, RecordsDenied>> + Send;
    fn del(
        &self,
        who: &Caller<'_>,
        scope: Scope,
        key: &[u8],
    ) -> impl Future<Output = Result<(), RecordsDenied>> + Send;
    /// `sink(key, value)` per hit, in key order, at most `limit`. Ok(n) = hits.
    fn list(
        &self,
        who: &Caller<'_>,
        scope: Scope,
        prefix: &[u8],
        limit: u32,
        sink: &mut (dyn FnMut(&[u8], &[u8]) + Send),
    ) -> impl Future<Output = Result<u32, RecordsDenied>> + Send;
    /// All predicates hold, then all mutations apply, atomically; else nothing applies.
    fn commit(
        &self,
        who: &Caller<'_>,
        scope: Scope,
        ops: &[CommitOp<'_>],
    ) -> impl Future<Output = Result<CommitOutcome, RecordsDenied>> + Send;
    /// Round 12 (plane STORE with LK_CHAIN, §8.6): append `entry` to the host chain `chain` in this namespace and
    /// scope; core frames (length-prefixed), links (hash over the previous link and the scope) and seals it with
    /// kernel `host_chains.rs` (append :276), kept unchanged and keyed by this namespace. Ok(seq), 1-based.
    fn append(
        &self,
        who: &Caller<'_>,
        scope: Scope,
        chain: &[u8],
        entry: &[u8],
    ) -> impl Future<Output = Result<u64, RecordsDenied>> + Send;
    /// Round 12 (plane LOOKUP with LK_CHAIN): verified read, `host_chains.rs` verify-on-read (:1004-1035).
    /// `sink(seq, entry)` per verified entry after `after`, in order, at most `limit`; stops at the first entry
    /// that fails verification or is missing.
    fn chain(
        &self,
        who: &Caller<'_>,
        scope: Scope,
        chain: &[u8],
        after: u64,
        limit: u32,
        sink: &mut (dyn FnMut(u64, &[u8]) + Send),
    ) -> impl Future<Output = Result<ChainRead, RecordsDenied>> + Send;
}
/// Round 12. `broken_at` 0 = intact through `len`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ChainRead {
    pub hits: u32,
    pub len: u64,
    pub broken_at: u64,
}

/// Round 12: the largest TTL a record keeps. A non-zero `ttl_s` is clamped to `1..=MAX_TTL_S`; 0 = no expiry.
/// 30 days (W1-K5 ruling, MIN3-RULINGS-COORD.md: origin/dev states no plugin-records maximum, only a non-zero
/// claim TTL, so this is the bound core keeps for every record from here on).
pub const MAX_TTL_S: u64 = 30 * 24 * 60 * 60;
/// The largest key, chain name or list prefix a namespace takes (`RecordsDenied::TooLarge` above it).
pub const MAX_KEY: usize = 1024;
/// The largest record value (IF §13 `NeedLimits::max_record_value`).
pub const MAX_VALUE: usize = 64 * 1024;
/// The largest chain entry (IF §8.6 StoreRec: LK_CHAIN `value` ≤ 64 KiB).
pub const MAX_CHAIN_ENTRY: usize = 64 * 1024;

mod chain;
#[cfg(test)]
mod late_tests;
pub(crate) mod store;

pub use store::StoreRecords;

/// One records owner shared by every consumer of the instance's namespace: the connector's RECORD Need
/// handler (`HostNeeds<_, R, _>` owns its `R`) and the kernel's plane driver serve the same namespace, so both
/// hold an `Arc` of the one `StoreRecords` and the in-doubt writes it parks are collected in one place.
impl<R: PluginRecords> PluginRecords for std::sync::Arc<R> {
    fn get(
        &self,
        who: &Caller<'_>,
        scope: Scope,
        key: &[u8],
        sink: &mut (dyn FnMut(&[u8]) + Send),
    ) -> impl Future<Output = Result<bool, RecordsDenied>> + Send {
        (**self).get(who, scope, key, sink)
    }
    fn put(
        &self,
        who: &Caller<'_>,
        scope: Scope,
        key: &[u8],
        value: &[u8],
        ttl_s: u64,
    ) -> impl Future<Output = Result<(), RecordsDenied>> + Send {
        (**self).put(who, scope, key, value, ttl_s)
    }
    fn claim(
        &self,
        who: &Caller<'_>,
        scope: Scope,
        key: &[u8],
        value: &[u8],
        ttl_s: u64,
    ) -> impl Future<Output = Result<bool, RecordsDenied>> + Send {
        (**self).claim(who, scope, key, value, ttl_s)
    }
    fn del(
        &self,
        who: &Caller<'_>,
        scope: Scope,
        key: &[u8],
    ) -> impl Future<Output = Result<(), RecordsDenied>> + Send {
        (**self).del(who, scope, key)
    }
    fn list(
        &self,
        who: &Caller<'_>,
        scope: Scope,
        prefix: &[u8],
        limit: u32,
        sink: &mut (dyn FnMut(&[u8], &[u8]) + Send),
    ) -> impl Future<Output = Result<u32, RecordsDenied>> + Send {
        (**self).list(who, scope, prefix, limit, sink)
    }
    fn commit(
        &self,
        who: &Caller<'_>,
        scope: Scope,
        ops: &[CommitOp<'_>],
    ) -> impl Future<Output = Result<CommitOutcome, RecordsDenied>> + Send {
        (**self).commit(who, scope, ops)
    }
    fn append(
        &self,
        who: &Caller<'_>,
        scope: Scope,
        chain: &[u8],
        entry: &[u8],
    ) -> impl Future<Output = Result<u64, RecordsDenied>> + Send {
        (**self).append(who, scope, chain, entry)
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
        (**self).chain(who, scope, chain, after, limit, sink)
    }
}

#[cfg(test)]
mod tests;
