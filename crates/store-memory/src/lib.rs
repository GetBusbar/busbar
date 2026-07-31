// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The DEFAULT `db` backend: an in-memory (RAM) store. Zero setup, no dependencies beyond the
//! `busbar-api` contract — governance works out of the box. EPHEMERAL: every counter, key, and
//! credential is lost on restart; configure a durable backend (e.g. `store-sqlite`/`store-postgres`)
//! for persistence. Poison-recovering locks (the governance surface must never panic on a request).

use busbar_api::{
    AwsCredential, MeteringDelta, MeteringRow, Store, StoreResult, UsageDelta, UsageLedger,
    VirtualKey,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

/// Retention ceiling for `usage`/`metering` rows, keyed by their epoch-second period-start field
/// (`window_start` / `bucket`). Mirrors `busbar::governance`'s own 31-day `max_window` sweep of its
/// in-memory rate-map cells (`crates/busbar/src/governance/mod.rs`): this store's ledgers are a
/// durability shadow of that engine state, so retaining them exactly as long as the engine keeps
/// its own cells is the right correspondence, not an arbitrary shorter/longer number.
const MAX_RETENTION_SECS: u64 = 31 * 86_400;

/// Amortized sweep cadence: one `retain()` pass per this many writes. Mirrors
/// `DEFAULT_RATE_SWEEP_INTERVAL` (`crates/busbar/src/config/mod.rs`).
const SWEEP_INTERVAL: u64 = 256;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// In-memory `Store`: keys by id, AWS credentials by access-key-id, token ledgers keyed by
/// (bucket_id, window_start), metering rows keyed by (key_id, bucket, model, provider).
#[derive(Default)]
pub struct MemoryStore {
    keys: RwLock<HashMap<String, VirtualKey>>,
    creds: RwLock<HashMap<String, AwsCredential>>,
    usage: RwLock<HashMap<(String, u64), UsageLedger>>,
    metering: RwLock<HashMap<(String, u64, String, String), MeteringRow>>,
    /// The revocation DENYLIST: denied subject ids (1.5.0 signed-token keys). A set (the reason is
    /// audit-only and not needed for the enforcement read).
    denylist: RwLock<std::collections::HashSet<String>>,
    /// Amortized-sweep write counters for `usage`/`metering` (see `MAX_RETENTION_SECS`). Separate
    /// per map since the two maps see independent write rates.
    usage_sweep_ticker: AtomicU64,
    metering_sweep_ticker: AtomicU64,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
    fn keys(&self) -> std::sync::RwLockWriteGuard<'_, HashMap<String, VirtualKey>> {
        self.keys.write().unwrap_or_else(|e| e.into_inner())
    }
    fn creds(&self) -> std::sync::RwLockWriteGuard<'_, HashMap<String, AwsCredential>> {
        self.creds.write().unwrap_or_else(|e| e.into_inner())
    }
    fn usage(&self) -> std::sync::RwLockWriteGuard<'_, HashMap<(String, u64), UsageLedger>> {
        self.usage.write().unwrap_or_else(|e| e.into_inner())
    }
    fn metering(
        &self,
    ) -> std::sync::RwLockWriteGuard<'_, HashMap<(String, u64, String, String), MeteringRow>> {
        self.metering.write().unwrap_or_else(|e| e.into_inner())
    }
}

impl Store for MemoryStore {
    fn put_key(&self, key: &VirtualKey) -> StoreResult<()> {
        self.keys().insert(key.id.clone(), key.clone());
        Ok(())
    }

    fn get_key(&self, id: &str) -> StoreResult<Option<VirtualKey>> {
        Ok(self.keys().get(id).cloned())
    }

    fn list_keys(&self) -> StoreResult<Vec<VirtualKey>> {
        let mut v: Vec<VirtualKey> = self.keys().values().cloned().collect();
        v.sort_by_key(|k| k.created_at); // mirror SqliteStore's ORDER BY created_at
        Ok(v)
    }

    fn delete_key(&self, id: &str) -> StoreResult<()> {
        // Cascade, mirroring SqliteStore::delete_key: the key, its usage counters, and its AWS
        // credentials go together — a revoked key's credential must not outlive it.
        //
        // ATOMICITY (audit LOW): hold ALL THREE write guards for the WHOLE cascade rather than taking
        // them one-at-a-time. The prior sequential form released the `keys` guard before touching
        // `usage`, so a concurrent write-behind `add_usage` (flush_budgets) could re-insert a usage row
        // for the just-deleted key in the gap — resurrecting a ledger the delete was meant to remove.
        // Under a single held set the delete is atomic across the maps. Acquire in a FIXED order
        // (keys → usage → creds); `delete_key` is the only method taking more than one lock, so this
        // order cannot deadlock against any other method.
        let mut keys = self.keys();
        let mut usage = self.usage();
        let mut creds = self.creds();
        keys.remove(id);
        usage.retain(|(k, _), _| k != id);
        creds.retain(|_, c| c.key_id != id);
        Ok(())
    }

    fn get_usage(&self, bucket_id: &str, window_start: u64) -> StoreResult<UsageLedger> {
        Ok(self
            .usage()
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
        // Write-behind ABSOLUTE set (memory is authoritative in the engine; this is durability only).
        self.usage()
            .insert((bucket_id.to_string(), window_start), ledger.clone());
        Ok(())
    }

    fn add_usage(&self, bucket_id: &str, window_start: u64, delta: &UsageDelta) -> StoreResult<()> {
        // ADDITIVE accumulate under the write lock (atomic within this process), floored at 0.
        let mut usage = self.usage();
        let u = usage
            .entry((bucket_id.to_string(), window_start))
            .or_default();
        u.apply_delta(delta);

        // Amortized bounded eviction of stale windows, on the write-behind hot path
        // (`flush_budgets` calls `add_usage` on every tick). `put_usage` (the absolute-set path) is
        // deliberately NOT swept: `add_usage` is the common/hot path so sweeping it alone is
        // sufficient to bound growth, and skipping `put_usage` keeps this change minimal.
        let sweep_needed = self
            .usage_sweep_ticker
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1)
            .is_multiple_of(SWEEP_INTERVAL);
        if sweep_needed {
            let n = now();
            usage
                .retain(|(_, window_start), _| window_start.saturating_add(MAX_RETENTION_SECS) > n);
        }
        Ok(())
    }

    fn add_metering(&self, d: &MeteringDelta) -> StoreResult<()> {
        let mut m = self.metering();
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
                tokens_cache_creation: 0,
                requests: 0,
            });
        e.tokens_input = e.tokens_input.saturating_add(d.tokens_input);
        e.tokens_output = e.tokens_output.saturating_add(d.tokens_output);
        e.tokens_cache_read = e.tokens_cache_read.saturating_add(d.tokens_cache_read);
        e.tokens_cache_creation = e
            .tokens_cache_creation
            .saturating_add(d.tokens_cache_creation);
        e.requests = e.requests.saturating_add(d.requests);

        // Amortized bounded eviction of stale buckets, mirroring `add_usage` above.
        let sweep_needed = self
            .metering_sweep_ticker
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1)
            .is_multiple_of(SWEEP_INTERVAL);
        if sweep_needed {
            let n = now();
            m.retain(|(_, bucket, _, _), _| bucket.saturating_add(MAX_RETENTION_SECS) > n);
        }
        Ok(())
    }

    fn list_metering(&self, bucket: u64) -> StoreResult<Vec<MeteringRow>> {
        Ok(self
            .metering()
            .iter()
            .filter(|((_, b, _, _), _)| *b == bucket)
            .map(|(_, row)| row.clone())
            .collect())
    }

    fn put_aws_credential(&self, cred: &AwsCredential) -> StoreResult<()> {
        self.creds()
            .insert(cred.access_key_id.clone(), cred.clone());
        Ok(())
    }

    fn list_aws_credentials(&self) -> StoreResult<Vec<AwsCredential>> {
        Ok(self.creds().values().cloned().collect())
    }

    fn add_denylist(&self, sub: &str, _reason: &str) -> StoreResult<()> {
        self.denylist
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(sub.to_string());
        Ok(())
    }

    fn list_denylist(&self) -> StoreResult<Vec<String>> {
        Ok(self
            .denylist
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .cloned()
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(id: &str) -> VirtualKey {
        VirtualKey {
            id: id.to_string(),
            generation_hash: format!("h_{id}"),
            name: "t".to_string(),
            allowed_pools: None,
            enabled: true,
            created_at: 0,
            group: None,
            labels: std::collections::BTreeMap::new(),
        }
    }

    fn ledger(requests: u64, model: &str, input: u64, output: u64) -> UsageLedger {
        UsageLedger {
            requests,
            billable_requests: requests,
            models: vec![busbar_api::ModelTokens {
                model: model.to_string(),
                tokens: busbar_api::TierTokens {
                    input,
                    output,
                    cache_read: 0,
                    cache_write: 0,
                },
            }],
        }
    }

    #[test]
    fn key_crud_and_ledger_roundtrip() {
        let s = MemoryStore::new();
        s.put_key(&key("a")).unwrap();
        assert_eq!(s.get_key("a").unwrap().unwrap().id, "a");
        assert_eq!(s.list_keys().unwrap().len(), 1);
        // absolute put_usage then read back
        s.put_usage("a", 0, &ledger(3, "m", 100, 40)).unwrap();
        let u = s.get_usage("a", 0).unwrap();
        assert_eq!(u.requests, 3);
        assert_eq!(u.tokens_for("m").unwrap().input, 100);
        // absolute overwrite (not additive)
        s.put_usage("a", 0, &ledger(1, "m", 20, 0)).unwrap();
        assert_eq!(
            s.get_usage("a", 0).unwrap().tokens_for("m").unwrap().input,
            20
        );
        // unknown window is default-empty
        assert_eq!(s.get_usage("a", 999).unwrap(), UsageLedger::default());
    }

    /// Additive per-model delta accumulate: two adds sum, a second model materializes its own row,
    /// and negative deltas floor at 0 (parity contract with sqlite/postgres/redis).
    #[test]
    fn add_usage_accumulates_per_model() {
        let s = MemoryStore::new();
        let d = UsageDelta {
            requests: 1,
            billable_requests: 1,
            models: vec![busbar_api::ModelTokensDelta {
                model: "gpt-5".to_string(),
                tokens: busbar_api::TierTokensDelta {
                    input: 10,
                    output: 5,
                    cache_read: 1,
                    cache_write: 0,
                },
            }],
        };
        s.add_usage("bucket", 100, &d).unwrap();
        s.add_usage("bucket", 100, &d).unwrap();
        let u = s.get_usage("bucket", 100).unwrap();
        assert_eq!(u.requests, 2);
        let t = u.tokens_for("gpt-5").unwrap();
        assert_eq!((t.input, t.output, t.cache_read), (20, 10, 2));
        // Refund floors at zero.
        s.add_usage(
            "bucket",
            100,
            &UsageDelta {
                requests: -5,
                billable_requests: -5,
                models: vec![],
            },
        )
        .unwrap();
        assert_eq!(s.get_usage("bucket", 100).unwrap().requests, 0);
    }

    #[test]
    fn delete_key_cascades_usage_and_creds() {
        let s = MemoryStore::new();
        s.put_key(&key("a")).unwrap();
        s.put_usage("a", 0, &ledger(1, "m", 5, 0)).unwrap();
        s.put_aws_credential(&AwsCredential {
            access_key_id: "AKIA1".to_string(),
            key_id: "a".to_string(),
            secret_access_key: "sek".to_string(),
        })
        .unwrap();
        s.delete_key("a").unwrap();
        assert!(s.get_key("a").unwrap().is_none());
        assert_eq!(s.get_usage("a", 0).unwrap(), UsageLedger::default());
        assert!(s.list_aws_credentials().unwrap().is_empty());
    }

    #[test]
    fn metering_accumulates_per_bucket() {
        let s = MemoryStore::new();
        let d = MeteringDelta {
            key_id: "a".to_string(),
            bucket: 7,
            model: "m".to_string(),
            provider: "p".to_string(),
            tokens_input: 10,
            tokens_output: 5,
            tokens_cache_read: 0,
            tokens_cache_creation: 0,
            requests: 1,
        };
        s.add_metering(&d).unwrap();
        s.add_metering(&d).unwrap();
        let rows = s.list_metering(7).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].tokens_input, 20);
        assert_eq!(rows[0].requests, 2);
        assert!(s.list_metering(999).unwrap().is_empty());
    }

    /// Regression: `usage` must not grow unbounded forever. A window older than the 31-day
    /// retention ceiling gets swept once `add_usage` has been called `SWEEP_INTERVAL` times
    /// (the amortized sweep cadence), even though nothing ever explicitly deletes it.
    #[test]
    fn add_usage_sweeps_stale_windows() {
        let s = MemoryStore::new();
        let old_window = now().saturating_sub(40 * 86_400); // 40 days old > 31-day retention
        let d = UsageDelta {
            requests: 1,
            billable_requests: 1,
            models: vec![],
        };
        for _ in 0..SWEEP_INTERVAL {
            s.add_usage("old-bucket", old_window, &d).unwrap();
        }
        // The sweep fired on the SWEEP_INTERVAL-th write and evicted the stale row (including the
        // one just written in that same call, since it's aged by its window_start, not by
        // recency-of-write).
        assert_eq!(
            s.get_usage("old-bucket", old_window).unwrap(),
            UsageLedger::default()
        );

        // A fresh window written afterward is unaffected.
        let fresh_window = now();
        s.add_usage("fresh-bucket", fresh_window, &d).unwrap();
        assert_eq!(
            s.get_usage("fresh-bucket", fresh_window).unwrap().requests,
            1
        );
    }

    /// Regression: the sweep must not over-prune. A window well within the 31-day retention
    /// ceiling survives a sweep triggered by writes to an unrelated, genuinely stale window.
    #[test]
    fn add_usage_sweep_preserves_fresh_windows() {
        let s = MemoryStore::new();
        let young_window = now().saturating_sub(5 * 86_400); // 5 days old, well within retention
        let old_window = now().saturating_sub(40 * 86_400); // 40 days old, past retention
        let d = UsageDelta {
            requests: 1,
            billable_requests: 1,
            models: vec![],
        };
        s.add_usage("young-bucket", young_window, &d).unwrap();
        for _ in 0..(SWEEP_INTERVAL - 1) {
            s.add_usage("old-bucket", old_window, &d).unwrap();
        }
        // That's SWEEP_INTERVAL total add_usage calls, so the sweep just fired.
        assert_eq!(
            s.get_usage("young-bucket", young_window).unwrap().requests,
            1
        );
        assert_eq!(
            s.get_usage("old-bucket", old_window).unwrap(),
            UsageLedger::default()
        );
    }

    /// Regression: `metering` must not grow unbounded forever either — same amortized sweep, keyed
    /// by the (day) `bucket` field this time.
    #[test]
    fn add_metering_sweeps_stale_buckets() {
        let s = MemoryStore::new();
        let old_bucket = now().saturating_sub(40 * 86_400);
        let d = MeteringDelta {
            key_id: "k".to_string(),
            bucket: old_bucket,
            model: "m".to_string(),
            provider: "p".to_string(),
            tokens_input: 1,
            tokens_output: 0,
            tokens_cache_read: 0,
            tokens_cache_creation: 0,
            requests: 1,
        };
        for _ in 0..SWEEP_INTERVAL {
            s.add_metering(&d).unwrap();
        }
        assert!(s.list_metering(old_bucket).unwrap().is_empty());

        let fresh_bucket = now();
        let fresh = MeteringDelta {
            bucket: fresh_bucket,
            ..d.clone()
        };
        s.add_metering(&fresh).unwrap();
        assert_eq!(s.list_metering(fresh_bucket).unwrap().len(), 1);
    }

    /// Regression: metering sweep must not over-prune fresh buckets either.
    #[test]
    fn add_metering_sweep_preserves_fresh_buckets() {
        let s = MemoryStore::new();
        let young_bucket = now().saturating_sub(5 * 86_400);
        let old_bucket = now().saturating_sub(40 * 86_400);
        let young = MeteringDelta {
            key_id: "k".to_string(),
            bucket: young_bucket,
            model: "m".to_string(),
            provider: "p".to_string(),
            tokens_input: 1,
            tokens_output: 0,
            tokens_cache_read: 0,
            tokens_cache_creation: 0,
            requests: 1,
        };
        let old = MeteringDelta {
            bucket: old_bucket,
            ..young.clone()
        };
        s.add_metering(&young).unwrap();
        for _ in 0..(SWEEP_INTERVAL - 1) {
            s.add_metering(&old).unwrap();
        }
        assert_eq!(s.list_metering(young_bucket).unwrap().len(), 1);
        assert!(s.list_metering(old_bucket).unwrap().is_empty());
    }
}
