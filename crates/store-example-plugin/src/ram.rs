// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! [`RamStore`] — the example plugin's OWN in-process backend, in the crate that ships it.
//!
//! ## Why this file exists rather than a dependency on `busbar-store-memory`
//!
//! This crate is the copy-me template for `kind: store`, and `docs/design/PLUGIN-TREE.md` §4 states
//! the rule kind-agnostically and without exception: *"No sibling instance, ever. No crate of any
//! kind may name another instance of any kind — not in a dependency, not in a type, not in a string
//! literal, not in a `cfg` feature."* This crate used to name `busbar-store-memory`, the in-tree
//! `kind: store` instance, and the manifest allow-list carried a waiver for it. A template that only
//! compiles because of a waiver teaches every third-party store plugin the pattern that fails the
//! kind-isolation rule on the day it ships, so the dependency is gone and the waiver with it.
//!
//! ## What it covers, and what it deliberately does not
//!
//! Exactly the verbs [`Store`] leaves UNDEFAULTED — keys, the usage ledger, metering — plus
//! [`Store::scrub_key`], whose trait default is a loud error and would turn a compliance-relevant
//! request into a failure rather than an erasure. Every other verb keeps the trait default, which is
//! the honest posture for a RAM fixture: a store that pretends to durably hold credentials it never
//! reads back is the claim this crate exists to catch.
//!
//! The semantics that ARE here are the ones a store gets WRONG in a way no caller can see:
//! the tombstone precondition on [`Store::put_key`] (a live-shaped write must not resurrect a
//! revoked id), the cascade on [`Store::delete_key`] (the key row survives for attribution, the
//! usage ledger does not), and a monotonic `revision` so incremental hydration works. Those three
//! are what a copied template must carry; the rest a real backend supplies itself.

use busbar_contract::store::{
    MeteringDelta, MeteringRow, Store, StoreError, StoreResult, UsageDelta, UsageLedger, VirtualKey,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

/// Retention ceiling for tombstoned `keys` and `usage` rows, keyed by the row's own epoch-second
/// field (`deleted_at` / `window_start`). A bound, not a policy: every map in this file is swept
/// against it, so no map here can grow for the life of the process.
const MAX_RETENTION_SECS: u64 = 31 * 86_400;

/// Amortized sweep cadence: one `retain()` pass per this many writes on the map being swept.
const SWEEP_INTERVAL: u64 = 256;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The example plugin's in-process store: keys by id, token ledgers by `(bucket_id, window_start)`,
/// metering rows by `(key_id, bucket, model, provider)`. Every map is BOUNDED (see
/// `MAX_RETENTION_SECS`); the whole thing dies with the process, which is the point of the
/// `durable_path` mode next door.
#[derive(Default)]
pub(crate) struct RamStore {
    keys: RwLock<HashMap<String, VirtualKey>>,
    usage: RwLock<HashMap<(String, u64), UsageLedger>>,
    metering: RwLock<HashMap<(String, u64, String, String), MeteringRow>>,
    keys_sweep_ticker: AtomicU64,
    usage_sweep_ticker: AtomicU64,
    metering_sweep_ticker: AtomicU64,
    /// Monotonic revision stamped on every key mutation, so `list_keys_since`'s trait default (a
    /// filter on `revision > since`) answers a real delta rather than "everything, always".
    revision: AtomicU64,
}

impl RamStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    fn next_revision(&self) -> u64 {
        self.revision
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1)
    }

    /// One tick of an amortized sweep counter; `true` on every `SWEEP_INTERVAL`-th write.
    fn tick(counter: &AtomicU64) -> bool {
        counter
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1)
            .is_multiple_of(SWEEP_INTERVAL)
    }
}

impl Store for RamStore {
    fn put_key(&self, key: &VirtualKey) -> StoreResult<()> {
        let mut key = key.clone();
        let mut keys = keys_write(&self.keys);
        // The tombstone precondition, tested and applied under ONE guard acquisition so it is
        // atomic. A live-shaped write over a tombstoned row would resurrect a key an operator
        // revoked; a caller-side `deleted_at` check cannot close that, because it is
        // read-then-write and a `delete_key` committing in the gap goes straight through. A write
        // that CARRIES a tombstone clears nothing and stays allowed.
        if key.deleted_at.is_none() {
            if let Some(existing) = keys.get(&key.id) {
                if existing.deleted_at.is_some() {
                    return Err(StoreError(format!(
                        "put_key: '{}' is tombstoned and its id is never reissued; refusing to \
                         clear the tombstone",
                        key.id
                    )));
                }
            }
        }
        key.revision = self.next_revision();
        keys.insert(key.id.clone(), key);
        if Self::tick(&self.keys_sweep_ticker) {
            let n = now();
            // NEVER prunes a live row: only `deleted_at.is_some()` rows are candidates, and only
            // past the same ceiling attribution already stops caring past.
            keys.retain(|_, k| match k.deleted_at {
                None => true,
                Some(deleted_at) => deleted_at.saturating_add(MAX_RETENTION_SECS) > n,
            });
        }
        Ok(())
    }

    fn get_key(&self, id: &str) -> StoreResult<Option<VirtualKey>> {
        Ok(keys_read(&self.keys).get(id).cloned())
    }

    fn list_keys(&self) -> StoreResult<Vec<VirtualKey>> {
        // Deliberately UNFILTERED — tombstones are included, so the admin listing caller (which
        // filters live-only itself) and the default `list_keys_since` (which needs tombstones
        // visible to evict a revoked key's cached credentials) are both served by this one method.
        let mut v: Vec<VirtualKey> = keys_read(&self.keys).values().cloned().collect();
        v.sort_by_key(|k| k.created_at);
        Ok(v)
    }

    fn delete_key(&self, id: &str) -> StoreResult<()> {
        // TOMBSTONE: the key row SURVIVES, so anything that attributes by key id (metering rows,
        // audit records) keeps resolving forever and the id is never reissued. The `usage` ledger
        // IS removed. Both guards are held for the WHOLE cascade, in a fixed order
        // (keys → usage), so a concurrent `add_usage` cannot resurrect a ledger row in the gap.
        let mut keys = keys_write(&self.keys);
        let mut usage = usage_write(&self.usage);
        let Some(key) = keys.get_mut(id) else {
            // NOT the idempotent case. "Already tombstoned" (below) means the operator's intent is
            // satisfied; "no such id" means nothing was touched, and `Ok(())` here would tell an
            // operator who typo'd an id that a key was revoked when none was.
            return Err(StoreError(format!("delete_key: unknown id '{id}'")));
        };
        if key.deleted_at.is_some() {
            return Ok(()); // idempotent: already tombstoned
        }
        let rev = self
            .revision
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1);
        key.enabled = false;
        key.deleted_at = Some(now());
        key.revision = rev;
        usage.retain(|(k, _), _| k != id);
        Ok(())
    }

    fn scrub_key(&self, id: &str) -> StoreResult<()> {
        let mut keys = keys_write(&self.keys);
        let Some(key) = keys.get_mut(id) else {
            return Err(StoreError(format!("scrub_key: unknown key '{id}'")));
        };
        if key.deleted_at.is_none() {
            return Err(StoreError(format!(
                "scrub_key: '{id}' is not tombstoned — delete it first"
            )));
        }
        key.name.clear();
        key.labels.clear();
        key.revision = self.next_revision();
        Ok(())
    }

    fn get_usage(&self, bucket_id: &str, window_start: u64) -> StoreResult<UsageLedger> {
        Ok(usage_read(&self.usage)
            .get(&(bucket_id.to_string(), window_start))
            .cloned()
            .unwrap_or_default())
    }

    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> StoreResult<()> {
        // Write-behind ABSOLUTE set: memory is authoritative in the engine, this is durability only.
        usage_write(&self.usage).insert((bucket_id.to_string(), window_start), ledger.clone());
        Ok(())
    }

    fn add_usage(&self, bucket_id: &str, window_start: u64, delta: &UsageDelta) -> StoreResult<()> {
        // ADDITIVE accumulate under the write lock. This is the hot path (`flush_budgets` calls it
        // on every tick), so this is where the `usage` map is swept.
        let mut usage = usage_write(&self.usage);
        usage
            .entry((bucket_id.to_string(), window_start))
            .or_default()
            .apply_delta(delta);
        if Self::tick(&self.usage_sweep_ticker) {
            let n = now();
            usage
                .retain(|(_, window_start), _| window_start.saturating_add(MAX_RETENTION_SECS) > n);
        }
        Ok(())
    }

    fn add_metering(&self, d: &MeteringDelta) -> StoreResult<()> {
        let mut m = metering_write(&self.metering);
        let e = m
            .entry((
                d.key_id.clone(),
                d.bucket,
                d.model.clone(),
                d.provider.clone(),
            ))
            .or_insert_with(|| MeteringRow {
                key_id: d.key_id.clone(),
                model: d.model.clone(),
                provider: d.provider.clone(),
                tokens_input: 0,
                tokens_output: 0,
                tokens_cache_read: 0,
                tokens_cache_write: 0,
                requests: 0,
                billable_requests: 0,
                key_group_at_use: d.key_group_at_use.clone(),
                pricing_version: d.pricing_version.clone(),
            });
        e.tokens_input = e.tokens_input.saturating_add(d.tokens_input);
        e.tokens_output = e.tokens_output.saturating_add(d.tokens_output);
        e.tokens_cache_read = e.tokens_cache_read.saturating_add(d.tokens_cache_read);
        e.tokens_cache_write = e.tokens_cache_write.saturating_add(d.tokens_cache_write);
        e.requests = e.requests.saturating_add(d.requests);
        e.billable_requests = e.billable_requests.saturating_add(d.billable_requests);
        if Self::tick(&self.metering_sweep_ticker) {
            let n = now();
            m.retain(|(_, bucket, _, _), _| bucket.saturating_add(MAX_RETENTION_SECS) > n);
        }
        Ok(())
    }

    fn list_metering(&self, bucket: u64) -> StoreResult<Vec<MeteringRow>> {
        Ok(metering_read(&self.metering)
            .iter()
            .filter(|((_, b, _, _), _)| *b == bucket)
            .map(|(_, row)| row.clone())
            .collect())
    }
}

// ── lock helpers ────────────────────────────────────────────────────────────────────────────────
//
// A poisoned lock is RECOVERED (`into_inner`), never unwrapped into a second panic. A store that
// panics on every subsequent call because one earlier caller panicked turns a single failed request
// into a dead process; the maps below are plain data with no invariant a half-finished write can
// break, so the recovered guard is sound.

macro_rules! guard {
    ($name:ident, $method:ident, $g:ident, $t:ty) => {
        fn $name(lock: &RwLock<$t>) -> std::sync::$g<'_, $t> {
            lock.$method().unwrap_or_else(|e| e.into_inner())
        }
    };
}

guard!(keys_write, write, RwLockWriteGuard, HashMap<String, VirtualKey>);
guard!(keys_read, read, RwLockReadGuard, HashMap<String, VirtualKey>);
guard!(usage_write, write, RwLockWriteGuard, HashMap<(String, u64), UsageLedger>);
guard!(usage_read, read, RwLockReadGuard, HashMap<(String, u64), UsageLedger>);
guard!(metering_write, write, RwLockWriteGuard, HashMap<(String, u64, String, String), MeteringRow>);
guard!(metering_read, read, RwLockReadGuard, HashMap<(String, u64, String, String), MeteringRow>);
