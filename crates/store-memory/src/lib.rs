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
/// in-memory rate-map cells (`crates/busbar-core/src/governance/mod.rs`): this store's ledgers are a
/// durability shadow of that engine state, so retaining them exactly as long as the engine keeps
/// its own cells is the right correspondence, not an arbitrary shorter/longer number.
const MAX_RETENTION_SECS: u64 = 31 * 86_400;

/// Amortized sweep cadence: one `retain()` pass per this many writes. Mirrors
/// `DEFAULT_RATE_SWEEP_INTERVAL` (`crates/busbar-core/src/config/mod.rs`).
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
    /// Amortized-sweep write counters for `usage`/`metering`/tombstoned `keys`/revoked `creds` (see
    /// `MAX_RETENTION_SECS`). Separate per map since the maps see independent write rates.
    usage_sweep_ticker: AtomicU64,
    metering_sweep_ticker: AtomicU64,
    keys_sweep_ticker: AtomicU64,
    creds_sweep_ticker: AtomicU64,
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
        let mut keys = self.keys();
        // The tombstone precondition, tested and applied under ONE guard acquisition so it is
        // atomic — see the trait doc. A live-shaped write over a tombstoned row would resurrect a
        // key an operator revoked, and core's caller-side `deleted_at` checks cannot close that:
        // they are read-then-write, and a `delete_key` committing in the gap goes straight through.
        // A write that CARRIES a tombstone clears nothing and stays allowed.
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

        // Amortized bounded eviction of stale TOMBSTONES, mirroring `add_usage`/`add_metering`
        // above: `keys` tombstones survive `delete_key` forever (by design, for billing/audit
        // attribution) but a repeated self-serve issue/refresh loop by one principal is a `put_key`
        // hot path, so sweeping it here bounds the map the same way. NEVER prunes a live row (only
        // `deleted_at.is_some()` rows are even candidates), and only past the SAME 31-day ceiling
        // attribution already stops caring past.
        let sweep_needed = self
            .keys_sweep_ticker
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1)
            .is_multiple_of(SWEEP_INTERVAL);
        if sweep_needed {
            let n = self.now();
            keys.retain(|_, k| match k.deleted_at {
                None => true, // live rows are never pruned
                Some(deleted_at) => deleted_at.saturating_add(MAX_RETENTION_SECS) > n,
            });
        }
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
            // NOT the idempotent case. "Already tombstoned" (below) means the operator's intent is
            // satisfied and the evidence is on disk; "no such id" means nothing was touched, and
            // `Ok(())` here tells an operator who typo'd an id that a key was revoked when none was.
            return Err(StoreError(format!("delete_key: unknown id '{id}'")));
        };
        if key.deleted_at.is_some() {
            return Ok(()); // idempotent: already tombstoned
        }
        let rev = self.next_revision();
        key.enabled = false;
        key.deleted_at = Some(self.now());
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

        // Amortized bounded eviction of stale REVOKED credentials, mirroring `put_key`'s tombstone
        // sweep above: `creds` had NO retention sweep at all before this (the only prior shrink path
        // was `delete_key`'s cascade, which never fires for a credential rotated on a LIVE key), so a
        // long-lived key's occupied-slot -> revoke -> re-put rotation cycle grew this map without
        // bound. A row is a candidate ONLY once `revoked_at` is set — a LIVE (unrevoked) credential is
        // NEVER pruned regardless of age, exactly like a live `VirtualKey` is never a `put_key` sweep
        // candidate — so this can never evict a credential a live key is still presenting. Age is
        // measured from `revoked_at` (when the credential stopped being usable), not `created_at`, so
        // a credential that lived (unrevoked) for years isn't punished the instant it's rotated out —
        // only ages PAST the 31-day ceiling once it's actually dead.
        let sweep_needed = self
            .creds_sweep_ticker
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1)
            .is_multiple_of(SWEEP_INTERVAL);
        if sweep_needed {
            let n = self.now();
            creds.retain(|_, c| match c.meta.revoked_at {
                None => true, // live credentials are never pruned
                Some(revoked_at) => revoked_at.saturating_add(MAX_RETENTION_SECS) > n,
            });
        }
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
            // `self.now()` (pinned-clock-aware), not the bare free function — the `creds` sweep
            // added for the retention fix ages rows off `revoked_at` against `self.now()`, so
            // stamping it from any other clock would desync the sweep's boundary from what a test
            // (or, in prod, a paused/adjusted clock) actually pinned. Matches `delete_key`'s
            // `deleted_at = Some(self.now())` for the same reason.
            c.meta.revoked_at = Some(self.now());
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
#[path = "tests/lib_tests.rs"]
mod tests;
