// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Plugin records: RECORD Needs and plane LOOKUP/STORE/DELETE/COMMIT over core's store (IF §12.5). W0-ABI stub: frozen signatures, `todo!()` bodies; W1-K5 fills it.

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
