// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The DEFAULT `db` backend: an in-memory (RAM) store. Zero setup, no dependencies beyond the
//! `busbar-api` contract — governance works out of the box. EPHEMERAL: every counter, key, and
//! credential is lost on restart; configure a durable backend (e.g. `store-sqlite`/`store-postgres`)
//! for persistence. Poison-recovering locks (the governance surface must never panic on a request).

use busbar_api::{
    CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, Store, StoreError, StoreResult,
    UsageDelta, UsageLedger, VirtualKey,
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

/// In-memory `Store`: keys by id, row-looked-up credentials by id (indexed by `(kind, public_id)`
/// for lookup and by `key_id` for the per-key listing/cascade), token ledgers keyed by (bucket_id,
/// window_start), metering rows keyed by (key_id, bucket, model, provider).
#[derive(Default)]
pub struct MemoryStore {
    keys: RwLock<HashMap<String, VirtualKey>>,
    creds: RwLock<HashMap<String, CredentialSecret>>,
    usage: RwLock<HashMap<(String, u64), UsageLedger>>,
    metering: RwLock<HashMap<(String, u64, String, String), MeteringRow>>,
    /// The revocation DENYLIST: denied subject ids (1.5.0 signed-token keys). A set (the reason is
    /// audit-only and not needed for the enforcement read).
    denylist: RwLock<std::collections::HashSet<String>>,
    /// Amortized-sweep write counters for `usage`/`metering` (see `MAX_RETENTION_SECS`). Separate
    /// per map since the two maps see independent write rates.
    usage_sweep_ticker: AtomicU64,
    metering_sweep_ticker: AtomicU64,
    /// The store-global monotonic revision counter (see `VirtualKey::revision`). Bumped on every
    /// mutation to `keys`/`creds`/the denylist.
    revision: AtomicU64,
    /// Test-only pinned clock for the retention sweep. `0` (the `Default`) means "use the real wall
    /// clock" (`now()`); any non-zero value pins `self.now()` to that epoch-second so a test can make
    /// the sweep's retention ceiling EXACTLY match the timestamp the test itself captured. This
    /// removes the wall-clock race in the exact-boundary sweep tests, where a one-second tick between
    /// the test's `now()` and the sweep's `now()` would otherwise shift the ceiling and evict the
    /// "one second inside" row. Prod behavior is untouched: the field is only ever set from tests.
    clock: AtomicU64,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
    fn keys(&self) -> std::sync::RwLockWriteGuard<'_, HashMap<String, VirtualKey>> {
        self.keys.write().unwrap_or_else(|e| e.into_inner())
    }
    fn creds(&self) -> std::sync::RwLockWriteGuard<'_, HashMap<String, CredentialSecret>> {
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
    fn next_revision(&self) -> u64 {
        self.revision.fetch_add(1, Ordering::Relaxed) + 1
    }
    /// "Now" as the retention sweep sees it: the pinned test clock if set (`clock != 0`), else the
    /// real wall clock. See the `clock` field.
    fn now(&self) -> u64 {
        match self.clock.load(Ordering::Relaxed) {
            0 => now(),
            pinned => pinned,
        }
    }
    /// Test-only: pin `self.now()` to `t` so the sweep's retention ceiling is deterministic.
    #[cfg(test)]
    fn pin_clock(&self, t: u64) {
        self.clock.store(t, Ordering::Relaxed);
    }
}

impl Store for MemoryStore {
    fn put_key(&self, key: &VirtualKey) -> StoreResult<()> {
        let mut key = key.clone();
        key.revision = self.next_revision();
        self.keys().insert(key.id.clone(), key);
        Ok(())
    }

    fn get_key(&self, id: &str) -> StoreResult<Option<VirtualKey>> {
        Ok(self.keys().get(id).cloned())
    }

    fn list_keys(&self) -> StoreResult<Vec<VirtualKey>> {
        // Deliberately UNFILTERED — see the trait doc. Tombstones are included so both the admin
        // listing caller (which filters live-only itself) and the default `list_keys_since` (which
        // needs tombstones visible) are served by this one method.
        let mut v: Vec<VirtualKey> = self.keys().values().cloned().collect();
        v.sort_by_key(|k| k.created_at); // mirror SqliteStore's ORDER BY created_at
        Ok(v)
    }

    fn delete_key(&self, id: &str) -> StoreResult<()> {
        // TOMBSTONE (1.5.0 redesign): the key row SURVIVES, so anything that attributes by key id
        // (billing/metering rows, audit records) keeps resolving forever, and the id is never
        // reissued. Only the CREDENTIALS (live secret material) and the rate/budget `usage` ledger
        // are actually removed — `metering` is durable billing evidence and was never cascaded here
        // even before this redesign (confirmed: it has its own independent lifecycle from `usage`).
        //
        // ATOMICITY: hold ALL THREE write guards for the WHOLE cascade rather than taking them
        // one-at-a-time, for the same reason as before this redesign — a concurrent write-behind
        // `add_usage` must not be able to resurrect a ledger row in the gap. Fixed lock order
        // (keys → usage → creds) so this cannot deadlock against any other method.
        let mut keys = self.keys();
        let mut usage = self.usage();
        let mut creds = self.creds();
        let Some(key) = keys.get_mut(id) else {
            return Ok(()); // idempotent: deleting an unknown id is a no-op, not an error
        };
        if key.deleted_at.is_some() {
            return Ok(()); // idempotent: already tombstoned
        }
        let rev = self.next_revision();
        key.enabled = false;
        key.deleted_at = Some(now());
        key.revision = rev;
        usage.retain(|(k, _), _| k != id);
        creds.retain(|_, c| c.meta.key_id != id);
        Ok(())
    }

    fn scrub_key(&self, id: &str) -> StoreResult<()> {
        let mut keys = self.keys();
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

    fn list_keys_since(&self, since: u64) -> StoreResult<Vec<VirtualKey>> {
        Ok(self
            .keys()
            .values()
            .filter(|k| k.revision > since)
            .cloned()
            .collect())
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
            let n = self.now();
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

        // Amortized bounded eviction of stale buckets, mirroring `add_usage` above.
        let sweep_needed = self
            .metering_sweep_ticker
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1)
            .is_multiple_of(SWEEP_INTERVAL);
        if sweep_needed {
            let n = self.now();
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

    fn put_credential(&self, secret: &CredentialSecret) -> StoreResult<()> {
        let mut creds = self.creds();
        // Reject an explicit slot pointed at a LIVE credential of the same (key_id, kind) — see the
        // trait doc: silently clobbering a working credential mid-overlap-window is almost always an
        // operator mistake, not an intended rotation.
        let occupied = creds.values().any(|c| {
            c.meta.id != secret.meta.id
                && c.meta.key_id == secret.meta.key_id
                && c.meta.kind == secret.meta.kind
                && c.meta.slot == secret.meta.slot
                && c.meta.revoked_at.is_none()
        });
        if occupied {
            return Err(StoreError(format!(
                "put_credential: slot {} for key '{}' kind '{}' holds a live credential; revoke it first",
                secret.meta.slot, secret.meta.key_id, secret.meta.kind
            )));
        }
        // UNIQUE(kind, public_id): a public_id must never resolve to two different credentials,
        // even across keys (an AccessKeyId is a global lookup handle).
        let public_id_taken = creds.values().any(|c| {
            c.meta.id != secret.meta.id
                && c.meta.kind == secret.meta.kind
                && c.meta.public_id == secret.meta.public_id
        });
        if public_id_taken {
            return Err(StoreError(format!(
                "put_credential: public_id '{}' is already in use for kind '{}'",
                secret.meta.public_id, secret.meta.kind
            )));
        }
        let mut secret = secret.clone();
        secret.meta.revision = self.next_revision();
        creds.insert(secret.meta.id.clone(), secret);
        Ok(())
    }

    fn list_credentials(&self, key_id: &str) -> StoreResult<Vec<CredentialMeta>> {
        Ok(self
            .creds()
            .values()
            .filter(|c| c.meta.key_id == key_id)
            .map(|c| c.meta.clone())
            .collect())
    }

    fn lookup_credential_secret(
        &self,
        kind: &str,
        public_id: &str,
    ) -> StoreResult<Option<CredentialSecret>> {
        Ok(self
            .creds()
            .values()
            .find(|c| c.meta.kind == kind && c.meta.public_id == public_id)
            .cloned())
    }

    fn revoke_credential(&self, id: &str, reason: &str) -> StoreResult<()> {
        let mut creds = self.creds();
        let Some(c) = creds.get_mut(id) else {
            return Err(StoreError(format!("revoke_credential: unknown id '{id}'")));
        };
        if c.meta.revoked_at.is_none() {
            c.meta.revoked_at = Some(now());
            c.meta.revoke_reason = Some(reason.to_string());
            c.meta.revision = self.next_revision();
        } // idempotent: already revoked
        Ok(())
    }

    fn list_credentials_since(&self, since: u64) -> StoreResult<Vec<CredentialSecret>> {
        Ok(self
            .creds()
            .values()
            .filter(|c| c.meta.revision > since)
            .cloned()
            .collect())
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
    use busbar_api::SecretForm;

    fn key(id: &str) -> VirtualKey {
        VirtualKey {
            id: id.to_string(),
            generation_hash: format!("h_{id}"),
            name: "t".to_string(),
            allowed_scopes: None,
            enabled: true,
            created_at: 0,
            group: None,
            labels: std::collections::BTreeMap::new(),
            expires_at: None,
            deleted_at: None,
            revision: 0,
        }
    }

    fn credential(id: &str, key_id: &str, public_id: &str) -> CredentialSecret {
        CredentialSecret {
            meta: CredentialMeta {
                id: id.to_string(),
                key_id: key_id.to_string(),
                kind: "sigv4".to_string(),
                slot: 0,
                public_id: public_id.to_string(),
                secret_form: SecretForm::Recoverable,
                created_at: 0,
                updated_at: 0,
                expires_at: None,
                revoked_at: None,
                revoke_reason: None,
                revision: 0,
            },
            secret: "v1:plain:sek".to_string(),
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
    fn delete_key_tombstones_and_cascades_usage_and_creds() {
        let s = MemoryStore::new();
        s.put_key(&key("a")).unwrap();
        s.put_usage("a", 0, &ledger(1, "m", 5, 0)).unwrap();
        s.put_credential(&credential("c1", "a", "AKIA1")).unwrap();
        s.delete_key("a").unwrap();
        // TOMBSTONE, not removed: the row survives, disabled, with deleted_at set.
        let tombstone = s.get_key("a").unwrap().unwrap();
        assert!(!tombstone.enabled);
        assert!(tombstone.deleted_at.is_some());
        assert_eq!(s.get_usage("a", 0).unwrap(), UsageLedger::default());
        assert!(s.list_credentials("a").unwrap().is_empty());
        // Idempotent: a second delete of an already-tombstoned key is a no-op, not an error.
        s.delete_key("a").unwrap();
    }

    #[test]
    fn put_credential_rejects_a_slot_already_holding_a_live_credential() {
        let s = MemoryStore::new();
        s.put_key(&key("a")).unwrap();
        s.put_credential(&credential("c1", "a", "AKIA1")).unwrap();
        // Same (key_id, kind, slot), different id/public_id: must fail, not silently clobber.
        let clobber = credential("c2", "a", "AKIA2");
        assert!(s.put_credential(&clobber).is_err());
        // Revoking the occupant frees the slot for a fresh mint.
        s.revoke_credential("c1", "rotated").unwrap();
        assert!(s.put_credential(&clobber).is_ok());
    }

    #[test]
    fn put_credential_rejects_a_public_id_reused_under_a_different_key() {
        let s = MemoryStore::new();
        s.put_key(&key("a")).unwrap();
        s.put_key(&key("b")).unwrap();
        s.put_credential(&credential("c1", "a", "AKIA1")).unwrap();
        // Different key, different id, SAME (kind, public_id) — the global AccessKeyId->credential
        // lookup handle must resolve to exactly one credential.
        let mut dupe = credential("c2", "b", "AKIA1");
        dupe.meta.slot = 1; // different slot too, so only the public_id clash can reject it
        assert!(s.put_credential(&dupe).is_err());
        // A genuinely distinct public_id under the other key is fine.
        let mut ok = credential("c3", "b", "AKIA2");
        ok.meta.slot = 1;
        assert!(s.put_credential(&ok).is_ok());
    }

    #[test]
    fn put_credential_public_id_check_excludes_its_own_row_on_reput() {
        // The uniqueness scan excludes the row with the SAME id (`c.meta.id != secret.meta.id`) —
        // otherwise a credential could never even be inserted once the id already existed. This
        // only matters once an id can legitimately be re-put; simulate it by inserting once, then
        // putting the identical secret again under the identical id/public_id/kind and confirming
        // it's accepted, not rejected as "colliding with itself".
        let s = MemoryStore::new();
        s.put_key(&key("a")).unwrap();
        let c = credential("c1", "a", "AKIA1");
        s.put_credential(&c).unwrap();
        assert!(
            s.put_credential(&c).is_ok(),
            "a row must not collide with itself"
        );
    }

    #[test]
    fn list_credentials_filters_by_key_id_and_since_boundary_is_exclusive() {
        let s = MemoryStore::new();
        s.put_key(&key("a")).unwrap();
        s.put_key(&key("b")).unwrap();
        s.put_credential(&credential("c1", "a", "AKIA1")).unwrap();
        let mut c2 = credential("c2", "b", "AKIA2");
        c2.meta.slot = 1;
        s.put_credential(&c2).unwrap();

        let for_a = s.list_credentials("a").unwrap();
        assert_eq!(for_a.len(), 1, "must not also return key b's credential");
        assert_eq!(for_a[0].id, "c1");

        // revision boundary: `revision > since` is exclusive of `since` itself. c2 was put after
        // c1, so it holds the higher revision — use IT as the boundary reference, or c1 (the lower
        // revision) would still be `> since` and the assertion below would be vacuous. The store's
        // revision counter is global (shared with `put_key`), so c1's revision is NOT necessarily
        // `newest_rev - 1` — read it directly rather than assuming adjacency.
        let oldest_rev = s.list_credentials("a").unwrap()[0].revision;
        let newest_rev = s.list_credentials("b").unwrap()[0].revision;
        assert!(newest_rev > oldest_rev);
        assert_eq!(
            s.list_credentials_since(newest_rev).unwrap().len(),
            0,
            "since == the newest row's own revision must exclude it"
        );
        assert_eq!(
            s.list_credentials_since(oldest_rev - 1).unwrap().len(),
            2,
            "since one below the lowest revision must include everything"
        );
    }

    #[test]
    fn list_keys_since_boundary_is_exclusive() {
        let s = MemoryStore::new();
        s.put_key(&key("a")).unwrap();
        s.put_key(&key("b")).unwrap();
        let rev_a = s.get_key("a").unwrap().unwrap().revision;
        let rev_b = s.get_key("b").unwrap().unwrap().revision;
        assert!(rev_b > rev_a);
        assert_eq!(
            s.list_keys_since(rev_b).unwrap().len(),
            0,
            "since == the newest row's own revision must exclude it"
        );
        assert_eq!(
            s.list_keys_since(rev_a).unwrap().len(),
            1,
            "must include only b"
        );
        assert_eq!(s.list_keys_since(rev_a - 1).unwrap().len(), 2);
    }

    #[test]
    fn next_revision_is_strictly_monotonic_starting_above_zero() {
        let s = MemoryStore::new();
        s.put_key(&key("a")).unwrap();
        s.put_key(&key("b")).unwrap();
        let rev_a = s.get_key("a").unwrap().unwrap().revision;
        let rev_b = s.get_key("b").unwrap().unwrap().revision;
        assert!(
            rev_a > 0,
            "the counter must not hand out 0 as a real revision"
        );
        assert_eq!(rev_b, rev_a + 1, "each call must advance by exactly 1");
    }

    #[test]
    fn lookup_credential_secret_resolves_by_kind_and_public_id() {
        let s = MemoryStore::new();
        s.put_key(&key("a")).unwrap();
        s.put_credential(&credential("c1", "a", "AKIA1")).unwrap();
        let found = s
            .lookup_credential_secret("sigv4", "AKIA1")
            .unwrap()
            .unwrap();
        assert_eq!(found.meta.key_id, "a");
        assert_eq!(found.secret, "v1:plain:sek");
        assert!(s
            .lookup_credential_secret("sigv4", "unknown")
            .unwrap()
            .is_none());
    }

    #[test]
    fn scrub_key_requires_tombstone_first() {
        let s = MemoryStore::new();
        s.put_key(&key("a")).unwrap();
        // A live key must not be scrubbable — that would be silent, un-auditable data loss on an
        // active principal.
        assert!(s.scrub_key("a").is_err());
        s.delete_key("a").unwrap();
        s.scrub_key("a").unwrap();
        let scrubbed = s.get_key("a").unwrap().unwrap();
        assert!(scrubbed.name.is_empty());
        assert!(scrubbed.labels.is_empty());
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
            tokens_cache_write: 0,
            requests: 1,
            billable_requests: 1,
            key_group_at_use: String::new(),
            pricing_version: String::new(),
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

    /// The sweep boundary itself: a window exactly `MAX_RETENTION_SECS` old sits AT the ceiling
    /// (`window_start + MAX_RETENTION_SECS == now`) and must be evicted (`>`, not `>=`, is the
    /// retain condition — a row must be STRICTLY inside the window to survive), while one second
    /// fresher survives.
    #[test]
    fn add_usage_sweep_boundary_is_exact() {
        let s = MemoryStore::new();
        let n = now();
        // Pin the sweep's clock to the SAME `n` the test derives its buckets from, so the retention
        // ceiling is exact and a wall-clock tick between here and the sweep can't shift it. Without
        // this, `one_inside` intermittently falls at/below an advanced ceiling and is wrongly evicted.
        s.pin_clock(n);
        let at_ceiling = n.saturating_sub(MAX_RETENTION_SECS);
        let one_inside = at_ceiling + 1;
        let d = UsageDelta {
            requests: 1,
            billable_requests: 1,
            models: vec![],
        };
        s.add_usage("at-ceiling", at_ceiling, &d).unwrap();
        s.add_usage("one-inside", one_inside, &d).unwrap();
        for _ in 0..(SWEEP_INTERVAL - 2) {
            s.add_usage("filler", one_inside, &d).unwrap();
        }
        assert_eq!(
            s.get_usage("at-ceiling", at_ceiling).unwrap(),
            UsageLedger::default(),
            "a window exactly at the retention ceiling must be evicted"
        );
        assert_eq!(
            s.get_usage("one-inside", one_inside).unwrap().requests,
            1,
            "a window one second inside the ceiling must survive"
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
            tokens_cache_write: 0,
            requests: 1,
            billable_requests: 1,
            key_group_at_use: String::new(),
            pricing_version: String::new(),
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
            tokens_cache_write: 0,
            requests: 1,
            billable_requests: 1,
            key_group_at_use: String::new(),
            pricing_version: String::new(),
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

    /// Same exact-boundary case as `add_usage_sweep_boundary_is_exact`, for metering's bucket
    /// retention: a bucket exactly `MAX_RETENTION_SECS` old must be evicted, one second fresher
    /// must survive.
    #[test]
    fn add_metering_sweep_boundary_is_exact() {
        let s = MemoryStore::new();
        let n = now();
        // Pin the sweep's clock to the SAME `n` the test derives its buckets from (see the usage
        // boundary test above) so the retention ceiling is exact and race-free.
        s.pin_clock(n);
        let at_ceiling = n.saturating_sub(MAX_RETENTION_SECS);
        let one_inside = at_ceiling + 1;
        let base = MeteringDelta {
            key_id: "k".to_string(),
            bucket: at_ceiling,
            model: "m".to_string(),
            provider: "p".to_string(),
            tokens_input: 1,
            tokens_output: 0,
            tokens_cache_read: 0,
            tokens_cache_write: 0,
            requests: 1,
            billable_requests: 1,
            key_group_at_use: String::new(),
            pricing_version: String::new(),
        };
        let inside = MeteringDelta {
            bucket: one_inside,
            ..base.clone()
        };
        s.add_metering(&base).unwrap();
        for _ in 0..(SWEEP_INTERVAL - 1) {
            s.add_metering(&inside).unwrap();
        }
        assert!(
            s.list_metering(at_ceiling).unwrap().is_empty(),
            "a bucket exactly at the retention ceiling must be evicted"
        );
        assert_eq!(
            s.list_metering(one_inside).unwrap().len(),
            1,
            "a bucket one second inside the ceiling must survive"
        );
    }
}
