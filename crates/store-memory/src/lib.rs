// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The DEFAULT `db` backend: an in-memory (RAM) store. Zero setup, no dependencies beyond the
//! `busbar-contract` records contract — governance works out of the box. EPHEMERAL: every counter, key, and
//! credential is lost on restart; configure a durable backend (e.g. `store-sqlite`/`store-postgres`)
//! for persistence. Poison-recovering locks (the governance surface must never panic on a request).
//!
//! BOTH DOORS, ONE CONSTRUCTOR (#2): [`open`] is what a build that links this crate registers
//! ([`linked::STORE`]) and what the dropped-in `cdylib` answers `busbar_open` with (feature
//! `dropped-in`, the [`exports`] module). Unsafe code is denied crate-wide; the one exception is the
//! door module the contract's export macro generates, whose C-ABI symbols cannot be written without it.

#![deny(unsafe_code)]

use busbar_contract::records::{
    AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, PlaneDisposition,
    PlaneRecord, PlaneRecordRef, PlaneSelector, RecordStore as Store,
    RecordStoreError as StoreError, RecordStoreResult as StoreResult, UsageDelta, UsageLedger,
    VirtualKey,
};
// The record half of the store protocol: the three verbs a `PlaneRecord` leg is run over, at the
// contract's own spelling. `StoreError` is imported under a second name because the two protocols
// each carry one and this crate answers both.
use busbar_contract::ids::RecordSchemaId;
use busbar_contract::kinds::{RecordBytes, StoreError as ContractStoreError};
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

/// The `records` map: `(schema, key) -> body`, in KEY ORDER because `record_scan` promises a
/// prefix walk answers in it.
type RecordMap = std::collections::BTreeMap<(String, Vec<u8>), RecordBytes>;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// In-memory `Store`: keys by id, row-looked-up credentials by id (`(kind, public_id)` lookup and
/// the per-key listing/cascade are SCANS over that one map, not secondary indexes — the RAM backend
/// holds a fixture-sized table and a second map to keep in step with every sweep, tombstone cascade
/// and rotation is more failure surface than the scan costs), token ledgers keyed by (bucket_id,
/// window_start), metering rows keyed by (key_id, bucket, model, provider, priced_from_ms).
/// A metering row's key: (key_id, bucket, model, provider, priced_from_ms).
type MeteringKey = (String, u64, String, String, u64);

#[derive(Default)]
pub struct MemoryStore {
    keys: RwLock<HashMap<String, VirtualKey>>,
    creds: RwLock<HashMap<String, CredentialSecret>>,
    usage: RwLock<HashMap<(String, u64), UsageLedger>>,
    metering: RwLock<HashMap<MeteringKey, MeteringRow>>,
    /// The revocation DENYLIST: denied subject ids (1.5.0 signed-token keys). A set (the reason is
    /// audit-only and not needed for the enforcement read).
    denylist: RwLock<std::collections::HashSet<String>>,
    /// The SPENT-TOKEN ledger behind `redeem_plane_token`: `(kind, token) -> expires_at`. Presence
    /// means "already redeemed", so the test-and-set is an occupied-entry check under one guard.
    /// Bounded by dropping lapsed rows on every redemption (a token past its own `expires_at` can
    /// never be presented again, so keeping it proves nothing).
    plane_tokens: RwLock<HashMap<(String, String), u64>>,
    /// Plane records keyed by `(kind, identity, seq)`. The identity is the record's `parent` for the
    /// APPENDED child kinds (a chain is `(parent, seq)`) and its `id` for the upserted ones, which
    /// take `seq` 0 — one map serves both because the child kinds never point-read by id.
    plane_records: RwLock<HashMap<(String, String, u64), PlaneRecord>>,
    /// KERNEL-HELD DURABLE RECORDS, under the contract's own three verbs, keyed by
    /// `(schema, key)`.
    ///
    /// A SECOND map beside `plane_records` and deliberately not a re-keying of it. The eight
    /// kind-tagged verbs above are the PUBLISHED store protocol the previous release's callers still
    /// drive, byte for byte; these three are what `busbar_contract::abi::sdk::store::StoreSlots` declares for a
    /// record leg, and they key on an opaque byte string rather than on the `(kind, id, seq)`
    /// columns. Folding them onto one map would make every record leg a change to the published
    /// path's key shape, which is precisely the thing that has to stay identical.
    ///
    /// A `BTreeMap` because `record_scan` walks a PREFIX and answers in key order: a hash map would
    /// have to sort on every scan, and "the order a scan answers in" is a promise a caller reads a
    /// chain by.
    ///
    /// NEVER AGED OUT. An active work handle is never evicted (`BUSBAR-1.6.0.md` THE DESIGN §1,
    /// "Admission bounds live work; nothing evicts it"): a real bound on live work is a refusal at
    /// admission, and retention bounds only SETTLED handles. Settledness is a sidecar the store is
    /// handed, never a body it decodes — the published path's [`PlaneDisposition`], which
    /// `purge_plane_records_before` honours (the conformance suite's
    /// `assert_plane_purge_task_keeps_active_rows`). A record-leg row carries no such sidecar: its
    /// key is opaque bytes and its value an opaque body, so this backend can never know a row is
    /// settled, and a row it cannot prove settled is one it may not drop. Write age is not
    /// settledness: an interrupted task waiting on a human is exactly the row nothing rewrites for
    /// the longest, and a one-time claim (`records.claim`) dropped by age is a claim that can be
    /// made twice.
    ///
    /// Nor is there a delete verb: `busbar_contract::abi::sdk::store::StoreSlots` declares
    /// `record_put`/`record_get`/`record_scan` and nothing that removes a row, so a backend cannot
    /// invent one here. The map's bound is the kernel's admission and its own settled-handle sweep,
    /// not this backend's clock; and the backend is EPHEMERAL, so a restart empties it.
    records: RwLock<RecordMap>,
    /// The durable admin AUDIT log, by `seq`. EPHEMERAL like every other map here — this backend is
    /// RAM — but append-only and fork-detecting within the process's life, which is what the
    /// engine's write-through actually asks of a store. Ordered reads come from the `BTreeMap`.
    audit: RwLock<std::collections::BTreeMap<u64, AuditRecord>>,
    /// Amortized-sweep write counters for `usage`/`metering`/tombstoned `keys`/revoked `creds`
    /// (see `MAX_RETENTION_SECS`). Separate per map since the maps see independent write rates. The
    /// `records` map has none: it is never aged out (see its doc).
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
    /// The store v3 slots' own state: the `op_id` dedupe log, the caps, the drawn totals, the
    /// slices, the ledger streams and the session directory ([`v3`]).
    v3: v3::State,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Write one of a plane's kernel-held durable records.
    ///
    /// The verb is `busbar_contract::abi::sdk::store::StoreSlots::record_put`'s, and the three
    /// below are its siblings. They are INHERENT rather than a trait implementation for one reason,
    /// and it is a rule rather than a preference: the manifest allow-list refuses a store-kind crate
    /// that names `busbar-kernel`, so the kernel's own record sink is not a trait this crate may
    /// implement; and the contract's `StoreSlots` is the whole store table, of which this
    /// backend answers the published half through [`Store`] above. What is here is the record half,
    /// at the contract's own spelling, so the adapter that binds a loaded store to the kernel's sink
    /// has one shape to forward to rather than two.
    ///
    /// The value arrives as a [`RecordBytes`], which is where the record ceiling is enforced: a body
    /// over it cannot be constructed, so this method cannot be handed one.
    ///
    /// # Errors
    ///
    /// Never, for a RAM backend: there is nothing under it to be unavailable. The result is the
    /// contract's shape so a durable backend can answer in the same place.
    pub fn record_put(
        &self,
        schema: RecordSchemaId,
        key: &[u8],
        value: &RecordBytes,
    ) -> Result<(), ContractStoreError> {
        self.record_put_at(schema.as_str(), key, value);
        Ok(())
    }

    /// [`Self::record_put`] under a schema named at run time (the store v3 table's `record_put`).
    pub(crate) fn record_put_at(&self, schema: &str, key: &[u8], value: &RecordBytes) {
        // No age sweep rides this write: a record-leg row is never evicted by age (see the
        // `records` field's doc), because nothing here can tell an active work handle from a
        // settled one.
        self.records
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert((schema.to_string(), key.to_vec()), value.clone());
    }

    /// Read one of a plane's kernel-held durable records.
    ///
    /// # Errors
    ///
    /// Never, for a RAM backend. An absent record is `Ok(None)` and not an error: a plane asking
    /// for a row it has not written yet is an ordinary answer, not a fault.
    pub fn record_get(
        &self,
        schema: RecordSchemaId,
        key: &[u8],
    ) -> Result<Option<RecordBytes>, ContractStoreError> {
        Ok(self.record_get_at(schema.as_str(), key))
    }

    /// [`Self::record_get`] under a schema named at run time.
    pub(crate) fn record_get_at(&self, schema: &str, key: &[u8]) -> Option<RecordBytes> {
        self.records
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&(schema.to_string(), key.to_vec()))
            .cloned()
    }

    /// Walk a plane's records under a prefix, in key order, at most `limit` of them.
    ///
    /// `limit` 0 means NOTHING, not everything. A caller that wants the whole prefix names a number;
    /// reading zero as unbounded would make a miscomputed bound the one case that returns the entire
    /// schema.
    ///
    /// # Errors
    ///
    /// Never, for a RAM backend.
    pub fn record_scan(
        &self,
        schema: RecordSchemaId,
        prefix: &[u8],
        limit: u32,
    ) -> Result<Vec<(Vec<u8>, RecordBytes)>, ContractStoreError> {
        Ok(self.record_scan_at(schema.as_str(), prefix, limit))
    }

    /// [`Self::record_scan`] under a schema named at run time.
    pub(crate) fn record_scan_at(
        &self,
        schema: &str,
        prefix: &[u8],
        limit: u32,
    ) -> Vec<(Vec<u8>, RecordBytes)> {
        self.records
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|((s, k), _)| s == schema && k.starts_with(prefix))
            .take(limit as usize)
            .map(|((_, k), value)| (k.clone(), value.clone()))
            .collect()
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
    fn metering(&self) -> std::sync::RwLockWriteGuard<'_, HashMap<MeteringKey, MeteringRow>> {
        self.metering.write().unwrap_or_else(|e| e.into_inner())
    }
    // The SHARED (read) side of the same four locks, for the methods that only ever read. A pure
    // read taking the exclusive side serializes every concurrent reader behind it, and the reads
    // here are the expensive ones — `list_keys`/`list_credentials`/`list_metering` clone whole
    // tables — so a governance `get_key` on the admit path would wait out an admin listing pass.
    // Poison-recovering for the same reason the write accessors are: the governance surface must
    // never panic on a request.
    fn keys_read(&self) -> std::sync::RwLockReadGuard<'_, HashMap<String, VirtualKey>> {
        self.keys.read().unwrap_or_else(|e| e.into_inner())
    }
    fn creds_read(&self) -> std::sync::RwLockReadGuard<'_, HashMap<String, CredentialSecret>> {
        self.creds.read().unwrap_or_else(|e| e.into_inner())
    }
    fn usage_read(&self) -> std::sync::RwLockReadGuard<'_, HashMap<(String, u64), UsageLedger>> {
        self.usage.read().unwrap_or_else(|e| e.into_inner())
    }
    fn metering_read(&self) -> std::sync::RwLockReadGuard<'_, HashMap<MeteringKey, MeteringRow>> {
        self.metering.read().unwrap_or_else(|e| e.into_inner())
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
    fn plane_records(
        &self,
    ) -> std::sync::RwLockWriteGuard<'_, HashMap<(String, String, u64), PlaneRecord>> {
        self.plane_records
            .write()
            .unwrap_or_else(|e| e.into_inner())
    }
    fn plane_records_read(
        &self,
    ) -> std::sync::RwLockReadGuard<'_, HashMap<(String, String, u64), PlaneRecord>> {
        self.plane_records.read().unwrap_or_else(|e| e.into_inner())
    }
    /// A plane record's identity in the one map: its `parent` when it is an APPENDED child (a chain
    /// position is `(parent, seq)`), else its own `id` at `seq` 0.
    fn plane_key(record: PlaneRecordRef<'_>) -> (String, String, u64) {
        let identity = record.parent.unwrap_or(record.id).to_string();
        (record.kind.to_string(), identity, record.seq)
    }
    /// The two credential-table preconditions, factored out of `put_credential` so the ATOMIC
    /// `put_key_with_credential` can run the identical rules under its own single critical section
    /// rather than a second, drifting copy of them. Takes the map (not the guard) so either caller's
    /// guard serves.
    fn credential_preconditions(
        creds: &HashMap<String, CredentialSecret>,
        secret: &CredentialSecret,
    ) -> StoreResult<()> {
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
        Ok(())
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
        Ok(self.keys_read().get(id).cloned())
    }

    fn list_keys(&self) -> StoreResult<Vec<VirtualKey>> {
        // Deliberately UNFILTERED — see the trait doc. Tombstones are included so both the admin
        // listing caller (which filters live-only itself) and the default `list_keys_since` (which
        // needs tombstones visible) are served by this one method.
        let mut v: Vec<VirtualKey> = self.keys_read().values().cloned().collect();
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
            .keys_read()
            .values()
            .filter(|k| k.revision > since)
            .cloned()
            .collect())
    }

    fn get_usage(&self, bucket_id: &str, window_start: u64) -> StoreResult<UsageLedger> {
        Ok(self
            .usage_read()
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
            // `priced_from_ms` is part of the key, not just the row: it is the `effective_from`
            // of the rate-card entry in force when these counts were accrued, so a card edit inside
            // a UTC day opens a SECOND row for that day and each half keeps the card it was earned
            // under (DECISION #79). Folding it into one row would leave a sum earned under two
            // cards with only one card to be read against.
            .entry((
                d.key_id.clone(),
                d.bucket,
                d.model.clone(),
                d.provider.clone(),
                d.priced_from_ms,
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
                priced_from_ms: d.priced_from_ms,
                usage_units: std::collections::BTreeMap::new(),
            });
        e.tokens_input = e.tokens_input.saturating_add(d.tokens_input);
        e.tokens_output = e.tokens_output.saturating_add(d.tokens_output);
        e.tokens_cache_read = e.tokens_cache_read.saturating_add(d.tokens_cache_read);
        e.tokens_cache_write = e.tokens_cache_write.saturating_add(d.tokens_cache_write);
        e.requests = e.requests.saturating_add(d.requests);
        e.billable_requests = e.billable_requests.saturating_add(d.billable_requests);
        // Every ledgered class the token columns do not hold, additive like them.
        for (class, n) in &d.usage_units {
            let cur = e.usage_units.entry(class.clone()).or_insert(0);
            *cur = cur.saturating_add(*n);
        }

        // Amortized bounded eviction of stale buckets, mirroring `add_usage` above.
        let sweep_needed = self
            .metering_sweep_ticker
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1)
            .is_multiple_of(SWEEP_INTERVAL);
        if sweep_needed {
            let n = self.now();
            m.retain(|(_, bucket, _, _, _), _| bucket.saturating_add(MAX_RETENTION_SECS) > n);
        }
        Ok(())
    }

    fn list_metering(&self, bucket: u64) -> StoreResult<Vec<MeteringRow>> {
        Ok(self
            .metering_read()
            .iter()
            .filter(|((_, b, _, _, _), _)| *b == bucket)
            .map(|(_, row)| row.clone())
            .collect())
    }

    fn put_credential(&self, secret: &CredentialSecret) -> StoreResult<()> {
        // The owning key is read under the SAME critical section as the credential write, in
        // `delete_key`'s fixed lock order (keys → creds) so the two can never deadlock against each
        // other. Checking the key first and writing after would let a `delete_key` commit in the
        // gap: its cascade removes the credentials that exist AT THAT MOMENT, so material written
        // just behind it survives the tombstone and keeps resolving — the same read-then-write hole
        // `put_key`'s own tombstone precondition closes, one door over.
        let keys = self.keys_read();
        let mut creds = self.creds();
        let Some(owner) = keys.get(&secret.meta.key_id) else {
            return Err(StoreError(format!(
                "put_credential: key '{}' does not exist; a credential must hang off a real key",
                secret.meta.key_id
            )));
        };
        if owner.deleted_at.is_some() {
            return Err(StoreError(format!(
                "put_credential: key '{}' is tombstoned; its credentials were revoked with it and \
                 are never reissued",
                secret.meta.key_id
            )));
        }
        Self::credential_preconditions(&creds, secret)?;
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

    fn put_key_with_credential(
        &self,
        key: &VirtualKey,
        secret: &CredentialSecret,
    ) -> StoreResult<()> {
        // The trait calls this mint ATOMIC, and the DEFAULT it inherits is `put_key` followed by
        // `put_credential` — two independent critical sections. When the credential leg fails (a
        // reused `public_id` is the ordinary way it does), the key leg has already committed, so the
        // caller is told the mint failed while a bearer key with no credential is left live in the
        // table: a row nobody will ever clean up, and a `put_key` the operator never asked for. Both
        // rows go in under ONE acquisition of the same two guards `delete_key` takes, in the same
        // fixed order, with every precondition tested before anything is written.
        let mut keys = self.keys();
        let mut creds = self.creds();
        if key.deleted_at.is_none() {
            if let Some(existing) = keys.get(&key.id) {
                if existing.deleted_at.is_some() {
                    return Err(StoreError(format!(
                        "put_key_with_credential: '{}' is tombstoned and its id is never reissued",
                        key.id
                    )));
                }
            }
        }
        // The credential must name the key being minted alongside it — a mint that quietly hung its
        // secret material off some OTHER key is not the operation the caller asked for, and the
        // tombstone/existence check `put_credential` makes cannot apply to a key that does not exist
        // until this call commits.
        if secret.meta.key_id != key.id {
            return Err(StoreError(format!(
                "put_key_with_credential: the credential names key '{}', not the key '{}' being \
                 minted with it",
                secret.meta.key_id, key.id
            )));
        }
        Self::credential_preconditions(&creds, secret)?;

        let mut key = key.clone();
        key.revision = self.next_revision();
        keys.insert(key.id.clone(), key);
        let mut secret = secret.clone();
        secret.meta.revision = self.next_revision();
        creds.insert(secret.meta.id.clone(), secret);
        Ok(())
    }

    fn list_credentials(&self, key_id: &str) -> StoreResult<Vec<CredentialMeta>> {
        Ok(self
            .creds_read()
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
            .creds_read()
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
            .creds_read()
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

    fn append_audit(&self, entry: &AuditRecord) -> StoreResult<()> {
        // Append-only, never rewriting: a second record on an occupied `seq` is EITHER the
        // write-through retrying (byte-identical → Ok, the common case) or a forked/tampered chain
        // (different → error). Collapsing those two is the one thing an audit store must not do.
        let mut audit = self.audit.write().unwrap_or_else(|e| e.into_inner());
        match audit.get(&entry.seq) {
            Some(stored) if stored == entry => Ok(()),
            Some(_) => Err(StoreError(format!(
                "append_audit: seq {} already holds a DIFFERENT record — the audit chain has forked",
                entry.seq
            ))),
            None => {
                audit.insert(entry.seq, entry.clone());
                Ok(())
            }
        }
    }

    fn list_audit(&self) -> StoreResult<Vec<AuditRecord>> {
        Ok(self
            .audit
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect())
    }

    fn upsert_plane_record(&self, record: PlaneRecordRef<'_>) -> StoreResult<()> {
        self.plane_records()
            .insert(Self::plane_key(record), record.to_record());
        Ok(())
    }

    fn get_plane_record(&self, kind: &str, id: &str) -> StoreResult<Option<Vec<u8>>> {
        Ok(self
            .plane_records_read()
            .get(&(kind.to_string(), id.to_string(), 0))
            .map(|r| r.body.clone()))
    }

    fn append_plane_record(&self, record: PlaneRecordRef<'_>) -> StoreResult<()> {
        // Keyed by `(parent, seq)`. APPEND-ONLY, never a blind overwrite — mirrors `append_audit`'s
        // own fork detection above so the two append-only paths can never disagree about what a
        // fork is: a second record at an already-occupied position is EITHER the write-through
        // retrying after a timeout (byte-identical → Ok, the common case) or a SECOND WRITER forking
        // the chain (different → refused, never silently applied). A blind upsert here would let two
        // busbar processes pointed at one durable store silently overwrite each other's
        // `task_event`/`call`/`audit` rows — exactly the defect `append_audit`'s own check exists to
        // catch, restored on this newer seam.
        let mut records = self.plane_records();
        let key = Self::plane_key(record);
        match records.get(&key) {
            Some(existing) if existing.view() == record => Ok(()),
            Some(_) => Err(StoreError(format!(
                "append_plane_record: kind '{}' parent '{}' seq {} already holds a DIFFERENT \
                 record — the chain has forked",
                record.kind,
                record.parent.unwrap_or(record.id),
                record.seq
            ))),
            None => {
                records.insert(key, record.to_record());
                Ok(())
            }
        }
    }

    fn list_plane_records(
        &self,
        kind: &str,
        selector: &PlaneSelector<'_>,
    ) -> StoreResult<Vec<Vec<u8>>> {
        let records = self.plane_records_read();
        let mut rows: Vec<(u64, Vec<u8>)> = records
            .iter()
            .filter(|((k, _, _), r)| {
                k == kind
                    && match selector {
                        PlaneSelector::All => true,
                        PlaneSelector::Parent(p) => r.parent.as_deref() == Some(&**p),
                    }
            })
            .map(|(_, r)| (r.seq, r.body.clone()))
            .collect();
        // Oldest-first by `seq` — the order the engine's chain verifier reads a parent's events in.
        rows.sort_by_key(|(seq, _)| *seq);
        Ok(rows.into_iter().map(|(_, body)| body).collect())
    }

    fn list_plane_record_parents(&self, kind: &str) -> StoreResult<Vec<String>> {
        let records = self.plane_records_read();
        let mut parents: Vec<String> = records
            .iter()
            .filter(|((k, _, _), _)| k == kind)
            .filter_map(|(_, r)| r.parent.clone())
            .collect();
        parents.sort();
        parents.dedup();
        Ok(parents)
    }

    fn purge_plane_records_before(&self, kind: &str, before: u64) -> StoreResult<u64> {
        // WHICH rows go is the kind's contract: `task` drops only TERMINAL rows (an interrupted task
        // waiting on a human is exactly the row that sits still longest, and dropping it loses the
        // work), every other kind drops any row older than `before`.
        let mut records = self.plane_records();
        let before_len = records.len();
        records.retain(|(k, _, _), r| {
            if k != kind || r.ts >= before {
                return true;
            }
            k == "task" && r.disposition != PlaneDisposition::Terminal
        });
        Ok((before_len - records.len()) as u64)
    }

    fn delete_plane_record(&self, kind: &str, id: &str) -> StoreResult<()> {
        // Absent is a no-op, per the trait. Every `seq` under the identity goes, so deleting a
        // parent's record cannot leave part of a chain behind.
        self.plane_records()
            .retain(|(k, i, _), _| !(k == kind && i == id));
        Ok(())
    }

    fn redeem_plane_token(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> StoreResult<bool> {
        // TEST-AND-SET under ONE guard. The trait's default is `Ok(true)` — "this store keeps no
        // ledger" — which on the DEFAULT backend makes every single-use approval token replayable:
        // a confirm-once tool re-executes for anyone who replays the nonce, and the store reports
        // each replay as the first redemption. Governance's out-of-the-box posture cannot be that.
        let mut spent = self.plane_tokens.write().unwrap_or_else(|e| e.into_inner());
        // Lapsed rows go in the same call: a token past its own expiry can never be presented
        // again, so retaining it only grows the map.
        spent.retain(|_, exp| *exp > now);
        let first = spent
            .insert((kind.to_string(), token.to_string()), expires_at)
            .is_none();
        Ok(first)
    }

    fn plane_token_live(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> StoreResult<bool> {
        // MULTI-use and SPENDS NOTHING — the opposite of `redeem_plane_token`'s single-use
        // test-and-set. This is a plain READ of the `(kind, token)` upsert record (an upsert kind
        // lives at `seq` 0, exactly where `get_plane_record` point-reads it), live only while that
        // record is present, its disposition is still `Active` (non-terminal), and `now` has not
        // reached `expires_at`. Nothing is inserted, removed or mutated, so asking twice answers the
        // same twice — the whole point of the verb.
        //
        // The trait default is `Ok(false)` precisely so a backend that keeps no records refuses these
        // callbacks fail-closed. This backend DOES keep them, in the same `plane_records` map the
        // upsert leg wrote to, so it answers from there — and it stays fail-closed for the same three
        // reasons: an unknown `(kind, token)`, a terminal disposition, and a lapsed deadline each
        // yield `Ok(false)`.
        Ok(self
            .plane_records_read()
            .get(&(kind.to_string(), token.to_string(), 0))
            .is_some_and(|r| r.disposition == PlaneDisposition::Active && now < expires_at))
    }
}

/// Open this store in process. It reads no configuration, so every body opens the same fresh RAM
/// store. The kernel reaches the store through its door ([`door`]), compiled in or dropped in; this
/// constructor is the Rust-side twin a test drives directly.
pub fn open(_cfg: &str) -> Result<Box<dyn Store>, String> {
    Ok(Box::new(MemoryStore::new()))
}

/// THE STORE DOOR (store v3, `busbar_contract::abi::store`): every slot of the store v3 table over
/// [`MemoryStore`], through the contract's store SDK (`abi::sdk::store`). `door` is what a build that
/// links this crate registers as its compiled-in row, and what the dropped-in `cdylib` exports
/// ([`door_export`]): compiled in or dropped in, the kernel reaches the same table. The memory store
/// never pends, so its `max_inflight` is set well above any worker count; it only bounds a flood.
pub use v3::door;

/// THE DROPPED-IN DOOR (feature `dropped-in`): [`door`] exported as the image's ONE symbol through
/// the contract's `export_door!`. The one module in this crate where unsafe code is allowed: the
/// exported symbol is `#[unsafe(no_mangle)]`.
#[cfg(feature = "dropped-in")]
#[allow(unsafe_code)]
pub mod door_export {
    busbar_contract::export_door!(crate::v3::door);
}

/// THE LINKED ENTRY (DECISIONS #2 rule (1)): what a build that links this store registers onto the
/// store axis — the same door a dropped-in store exports. `STORE` is `(key, ephemeral, door,
/// canonical)`: the key `store.module` selects it by (and the store catalog prints), its statement
/// that what it holds is lost on restart, its store v3 door, which boot opens it through (the store
/// axis), and its canonical name — the manifest name its release tarball carries (plugins.yaml
/// `manifest_name`, the repo), which config may name it by too, one plugin whichever door it
/// arrives by (ARCHITECT C'). It claims no default: a config names its store (Q-STORE = (B)).
pub mod linked {
    /// `(key, ephemeral, door, canonical)`.
    pub const STORE: (
        &str,
        bool,
        busbar_contract::abi::mechanism::door::DoorFn,
        &str,
    ) = ("memory", true, super::door, "busbar-store-memory");
}

mod v3;

#[cfg(test)]
#[path = "tests/lib_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/v3_tests.rs"]
mod v3_tests;
