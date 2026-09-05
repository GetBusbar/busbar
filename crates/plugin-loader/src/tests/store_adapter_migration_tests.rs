// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The migration's read off a store at the published payload schema, and the three rules it has to
//! keep.
//!
//! 1. **The opening figures are the seed.** A store is seeded with the previous release's rows and
//!    the sealed checkpoint is compared to them figure by figure — per bucket, per day, per lane, per
//!    provider — not merely totalled.
//! 2. **The second boot is a no-op.** Proved on the store's own request log: a boot that finds a
//!    marker issues no request at all.
//! 3. **Nothing is ever written.** The double records every call it is given and PANICS on every
//!    write, so a migration that grew a write-read-back probe goes from green to a panic rather than
//!    to a silent pass. A deployment on a read-only replica is the previous release's supported
//!    shape.
//!
//! The store at the published schema is modelled twice, as it is next door: an in-memory double
//! bound to payload schema 2, which is where the request log lives, and the REAL published sqlite
//! store from the oracle cache, which skips when the cache is cold.

use super::store_adapter_tests::cached_published_sqlite_tarball;
use super::*;
use crate::store_adapter::{LegacyReadPlan, StoreAdapter, BILLABLE_REQUESTS_CLASS};
use busbar_api::{
    AuditRecord, MeteringDelta, MeteringRow, ModelTokens, Store as AbiStore, StoreError,
    StoreResult, UsageLedger, VirtualKey,
};
use busbar_unit_ledger::migration::{
    migrate, LegacyFamily, MigrationRecords, Outcome, OPENING_CHECKPOINT_SEQ,
};
use busbar_unit_ledger::totals::{BucketId, BucketScope, CapDimension, Totals, TotalsKey};
use std::sync::{Arc, Mutex};

/// The published payload schema — the one every 1.5.x store plugin is built against.
const PUBLISHED_SCHEMA: u32 = crate::registry::STORE_ABI_FLOOR;

/// A store at the published schema holding the previous release's rows, recording every request it
/// is given and refusing — loudly — to be written to.
#[derive(Default)]
struct SeededRows {
    usage: Mutex<Vec<(String, u64, UsageLedger)>>,
    metering: Mutex<Vec<(u64, MeteringRow)>>,
    keys: Mutex<Vec<VirtualKey>>,
    audit: Mutex<Vec<AuditRecord>>,
    log: Mutex<Vec<String>>,
}

impl SeededRows {
    fn note(&self, request: impl Into<String>) {
        self.log
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(request.into());
    }

    fn requests(&self) -> Vec<String> {
        self.log.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    fn seed_usage(&self, bucket: &str, window: u64, ledger: UsageLedger) {
        self.usage.lock().unwrap_or_else(|p| p.into_inner()).push((
            bucket.to_string(),
            window,
            ledger,
        ));
    }

    fn seed_metering(&self, day: u64, row: MeteringRow) {
        self.metering
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push((day, row));
    }

    fn seed_key(&self, id: &str) {
        self.keys
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(VirtualKey {
                id: id.to_string(),
                generation_hash: "gen".to_string(),
                name: id.to_string(),
                enabled: true,
                created_at: 1_700_000_000,
                ..Default::default()
            });
    }

    fn seed_audit(&self, seq: u64, hash: &str) {
        self.audit
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(AuditRecord {
                seq,
                ts: 1_700_000_000,
                action: "plugin.install".to_string(),
                resource: "store".to_string(),
                outcome: "applied".to_string(),
                principal: "admin".to_string(),
                prev_hash: String::new(),
                hash: hash.to_string(),
            });
    }
}

impl AbiStore for SeededRows {
    fn put_key(&self, _key: &VirtualKey) -> StoreResult<()> {
        self.note("put_key");
        panic!("the migration must never write a key row");
    }

    fn get_key(&self, id: &str) -> StoreResult<Option<VirtualKey>> {
        self.note(format!("get_key {id}"));
        Ok(self
            .keys
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .find(|k| k.id == id)
            .cloned())
    }

    fn list_keys(&self) -> StoreResult<Vec<VirtualKey>> {
        self.note("list_keys");
        Ok(self.keys.lock().unwrap_or_else(|p| p.into_inner()).clone())
    }

    fn delete_key(&self, _id: &str) -> StoreResult<()> {
        self.note("delete_key");
        panic!("the migration must never delete a key row");
    }

    fn get_usage(&self, bucket_id: &str, window_start: u64) -> StoreResult<UsageLedger> {
        self.note(format!("get_usage {bucket_id}@{window_start}"));
        Ok(self
            .usage
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .find(|(b, w, _)| b == bucket_id && *w == window_start)
            .map(|(_, _, ledger)| ledger.clone())
            .unwrap_or_default())
    }

    fn put_usage(&self, _b: &str, _w: u64, _l: &UsageLedger) -> StoreResult<()> {
        self.note("put_usage");
        panic!("the migration must never write a usage row: no write-read-back probe");
    }

    fn add_metering(&self, _delta: &MeteringDelta) -> StoreResult<()> {
        self.note("add_metering");
        panic!("the migration must never write a metering row");
    }

    fn list_metering(&self, bucket: u64) -> StoreResult<Vec<MeteringRow>> {
        self.note(format!("list_metering {bucket}"));
        Ok(self
            .metering
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .filter(|(day, _)| *day == bucket)
            .map(|(_, row)| row.clone())
            .collect())
    }

    fn list_audit(&self) -> StoreResult<Vec<AuditRecord>> {
        self.note("list_audit");
        Ok(self.audit.lock().unwrap_or_else(|p| p.into_inner()).clone())
    }

    fn append_audit(&self, _entry: &AuditRecord) -> StoreResult<()> {
        self.note("append_audit");
        panic!("the migration must never append an audit record");
    }
}

/// A store that answers nothing at all — the older backend that does not know the operations, and
/// the deployment whose store keeps nothing across a restart.
#[derive(Default)]
struct SaysNothing {
    log: Mutex<Vec<String>>,
}

impl SaysNothing {
    fn requests(&self) -> Vec<String> {
        self.log.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    fn note(&self, request: &str) {
        self.log
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(request.to_string());
    }
}

impl AbiStore for SaysNothing {
    fn put_key(&self, _key: &VirtualKey) -> StoreResult<()> {
        panic!("write");
    }
    fn get_key(&self, _id: &str) -> StoreResult<Option<VirtualKey>> {
        Ok(None)
    }
    fn list_keys(&self) -> StoreResult<Vec<VirtualKey>> {
        self.note("list_keys");
        Err(StoreError("this store does not know that".to_string()))
    }
    fn delete_key(&self, _id: &str) -> StoreResult<()> {
        panic!("write");
    }
    fn get_usage(&self, _b: &str, _w: u64) -> StoreResult<UsageLedger> {
        self.note("get_usage");
        Err(StoreError("this store does not know that".to_string()))
    }
    fn put_usage(&self, _b: &str, _w: u64, _l: &UsageLedger) -> StoreResult<()> {
        panic!("write");
    }
    fn add_metering(&self, _d: &MeteringDelta) -> StoreResult<()> {
        panic!("write");
    }
    fn list_metering(&self, _bucket: u64) -> StoreResult<Vec<MeteringRow>> {
        self.note("list_metering");
        Err(StoreError("this store does not know that".to_string()))
    }
}

fn model(name: &str, units: &[(&str, u64)]) -> ModelTokens {
    ModelTokens {
        model: name.to_string(),
        usage_units: units.iter().map(|(k, v)| ((*k).to_string(), *v)).collect(),
    }
}

fn metering_row(key_id: &str, model: &str, provider: &str) -> MeteringRow {
    MeteringRow {
        key_id: key_id.to_string(),
        model: model.to_string(),
        provider: provider.to_string(),
        tokens_input: 4_000,
        tokens_output: 1_100,
        tokens_cache_read: 0,
        tokens_cache_write: 7,
        requests: 300,
        billable_requests: 290,
        key_group_at_use: String::new(),
        pricing_version: "v1".to_string(),
    }
}

/// The window every seeded token ledger is in, and the day every seeded metering row is on.
const WINDOW: u64 = 86_400;

/// A store holding what a deployment that has been serving holds.
fn a_serving_store() -> Arc<SeededRows> {
    let store = Arc::new(SeededRows::default());
    store.seed_key("vk_a");
    store.seed_key("vk_b");
    store.seed_audit(1, "hash-one");
    store.seed_audit(4_211, "hash-head");
    store.seed_usage(
        "vk_a",
        WINDOW,
        UsageLedger {
            requests: 512,
            billable_requests: 500,
            models: vec![
                model("gpt-4", &[("input", 6_000), ("output", 2_500)]),
                model("claude", &[("input", 500)]),
            ],
        },
    );
    store.seed_usage(
        "vk_b",
        WINDOW,
        UsageLedger {
            requests: 3,
            billable_requests: 3,
            models: vec![model("gpt-4", &[("input", 40)])],
        },
    );
    store.seed_metering(WINDOW, metering_row("vk_a", "gpt-4", "openai"));
    store.seed_metering(WINDOW, metering_row("vk_a", "gpt-4", "azure"));
    store
}

fn adapter_over(store: Arc<dyn AbiStore>) -> StoreAdapter {
    StoreAdapter::new(store, PUBLISHED_SCHEMA)
}

fn opened(
    totals: &std::collections::BTreeMap<(TotalsKey, u64), Totals>,
    bucket: &str,
    dimension: CapDimension,
    scope: BucketScope,
) -> Totals {
    let key = TotalsKey::new(BucketId::new(bucket), dimension, scope);
    totals.get(&(key, WINDOW)).copied().unwrap_or_default()
}

/// The opening figures ARE the seeded rows: per bucket, per day, per lane, per provider.
#[test]
fn the_opening_figures_equal_the_seeded_legacy_rows() {
    let store = a_serving_store();
    let adapter = adapter_over(store.clone());
    let plan = adapter
        .key_bucket_plan(WINDOW, &[], &[WINDOW])
        .expect("the key rows list");
    assert_eq!(plan.windows.len(), 2, "one bucket per key row");

    let rows = adapter.legacy_ledger_rows(plan);
    let mut records = adapter.migration_records();
    let Outcome::Sealed(opening) =
        migrate(&rows, &mut records, 1, 1_700_000_000, 3, None).expect("the migration seals")
    else {
        panic!("the first boot seals");
    };
    let totals = &opening.checkpoint.totals;

    // The token ledger: the bucket's request counts at the bucket's own scope, and each lane's
    // units in their own balance.
    assert_eq!(
        opened(totals, "vk_a", CapDimension::Requests, BucketScope::All).settled,
        512
    );
    assert_eq!(
        opened(
            totals,
            "vk_a",
            CapDimension::Class(BILLABLE_REQUESTS_CLASS.into()),
            BucketScope::All
        )
        .settled,
        500
    );
    assert_eq!(
        opened(
            totals,
            "vk_a",
            CapDimension::Class("input".into()),
            BucketScope::Pool("lane:gpt-4".into())
        )
        .settled,
        6_000
    );
    assert_eq!(
        opened(
            totals,
            "vk_a",
            CapDimension::Class("output".into()),
            BucketScope::Pool("lane:gpt-4".into())
        )
        .settled,
        2_500
    );
    assert_eq!(
        opened(
            totals,
            "vk_a",
            CapDimension::Class("input".into()),
            BucketScope::Pool("lane:claude".into())
        )
        .settled,
        500
    );
    assert_eq!(
        opened(
            totals,
            "vk_b",
            CapDimension::Class("input".into()),
            BucketScope::Pool("lane:gpt-4".into())
        )
        .settled,
        40
    );

    // The metering rows: the same day, one balance per lane and provider, and the cache-write
    // column is its own dimension rather than being folded into the input one.
    for provider in ["openai", "azure"] {
        let pool = BucketScope::Pool(format!("meter:gpt-4/{provider}"));
        assert_eq!(
            opened(
                totals,
                "vk_a",
                CapDimension::Class("input".into()),
                pool.clone()
            )
            .settled,
            4_000
        );
        assert_eq!(
            opened(
                totals,
                "vk_a",
                CapDimension::Class("cache_write".into()),
                pool.clone()
            )
            .settled,
            7
        );
        assert_eq!(
            opened(totals, "vk_a", CapDimension::Requests, pool.clone()).settled,
            300
        );
        assert_eq!(
            opened(
                totals,
                "vk_a",
                CapDimension::Class("cache_read".into()),
                pool
            )
            .settled,
            0,
            "a column the rows hold at zero opens no balance at all"
        );
    }

    assert_eq!(opening.checkpoint.checkpoint_seq, OPENING_CHECKPOINT_SEQ);
    assert!(opening.checkpoint.body_hash_verifies());
    assert!(opening.unreadable.is_empty());
    assert_eq!(
        opening.checkpoint.store_seq_high_water, 4_211,
        "the previous release's audit head is where this release's chain continues from"
    );
    assert_eq!(
        opening.balances,
        vec![
            busbar_unit_ledger::legacy::OpeningBalance {
                bucket: "vk_a".to_string(),
                amount: 9_000,
                rate_card_version: 3,
            },
            busbar_unit_ledger::legacy::OpeningBalance {
                bucket: "vk_b".to_string(),
                amount: 40,
                rate_card_version: 3,
            },
        ],
        "one opening entry per bucket, at the card version the migration was told to name"
    );
}

/// Nothing the migration does is a write. Asserted on the store's own request log — every request it
/// received, in order — and not merely on the absence of an error.
#[test]
fn the_migration_never_writes_to_the_rows_it_read() {
    let store = a_serving_store();
    let adapter = adapter_over(store.clone());
    let plan = adapter
        .key_bucket_plan(WINDOW, &[], &[WINDOW])
        .expect("the key rows list");
    let rows = adapter.legacy_ledger_rows(plan);
    let mut records = adapter.migration_records();
    migrate(&rows, &mut records, 1, 1, 1, None).expect("the migration seals");

    let requests = store.requests();
    let writes: Vec<&String> = requests
        .iter()
        .filter(|r| {
            [
                "put_", "add_", "delete_", "append_", "purge_", "scrub_", "revoke_",
            ]
            .iter()
            .any(|w| r.starts_with(w))
        })
        .collect();
    assert!(
        writes.is_empty(),
        "the migration issued a write to the previous release's rows: {writes:?}"
    );
    assert!(
        requests.iter().any(|r| r.starts_with("get_usage")),
        "and it did read the rows, so the absence of writes means something: {requests:?}"
    );
    assert!(requests.iter().any(|r| r.starts_with("list_metering")));
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.starts_with("get_usage"))
            .count(),
        2,
        "each named token ledger is read exactly once across the whole migration"
    );
}

/// The second boot issues no request at all. The marker is what makes it free, and the request log
/// is what proves it.
#[test]
fn a_second_boot_issues_no_request_to_the_store() {
    let store = a_serving_store();
    let adapter = adapter_over(store.clone());
    let plan = adapter
        .key_bucket_plan(WINDOW, &[], &[WINDOW])
        .expect("the key rows list");
    let first = adapter.legacy_ledger_rows(plan.clone());
    let mut records = adapter.migration_records();
    let sealed = migrate(&first, &mut records, 1, 1_700_000_000, 3, None).expect("seals");
    assert!(sealed.sealed_now());
    let after_first = store.requests().len();
    assert!(after_first > 0);

    // The same node, booting again: a fresh source over the same plan, the same records.
    let second_rows = adapter.legacy_ledger_rows(plan);
    let second = migrate(&second_rows, &mut records, 1, 1_700_000_100, 3, None).expect("no-op");
    assert!(!second.sealed_now(), "the second boot must not seal again");
    assert_eq!(
        store.requests().len(),
        after_first,
        "a boot that finds a marker must not touch the previous release's rows"
    );
    assert_eq!(second.marker(), sealed.marker());
    assert_eq!(
        adapter
            .migration_records()
            .read_marker()
            .expect("the records read")
            .as_ref(),
        Some(sealed.marker()),
        "the marker is on the adapter, not on the rows that were read"
    );
}

/// A store with no legacy rows opens at zero and STILL seals a checkpoint — including the store that
/// refuses every read it is given, which is what an older backend and an empty deployment both look
/// like from here.
#[test]
fn a_store_with_no_legacy_rows_opens_at_zero_and_still_seals() {
    let store = Arc::new(SaysNothing::default());
    let adapter = adapter_over(store.clone());
    // The key listing is where the plan comes from, and this store will not answer it either.
    assert!(adapter.key_bucket_plan(WINDOW, &[], &[WINDOW]).is_err());
    // So the migration reads the plan it was left with, which names one bucket and one day.
    let plan = LegacyReadPlan {
        windows: vec![("vk_a".to_string(), WINDOW)],
        days: vec![WINDOW],
    };
    let rows = adapter.legacy_ledger_rows(plan);
    let mut records = adapter.migration_records();
    let Outcome::Sealed(opening) = migrate(&rows, &mut records, 1, 1_700_000_000, 1, None)
        .expect("an empty store still seals")
    else {
        panic!("an empty store seals an opening at zero");
    };
    assert!(
        opening.checkpoint.totals.is_empty(),
        "nothing opens at zero"
    );
    assert!(opening.checkpoint.body_hash_verifies());
    assert!(opening.balances.is_empty());
    assert_eq!(
        opening.unreadable.len(),
        2,
        "and the rows that could not be read are named rather than lost: {:?}",
        opening.unreadable
    );
    assert!(
        store.requests().iter().any(|r| r == "get_usage"),
        "the read was attempted"
    );
}

/// A plan naming nothing reads nothing, which is the shape a deployment with no buckets at all
/// takes: the migration still seals, so the node has a point to measure from.
#[test]
fn a_plan_naming_nothing_seals_an_empty_opening() {
    let store = a_serving_store();
    let adapter = adapter_over(store.clone());
    let rows = adapter.legacy_ledger_rows(LegacyReadPlan::nothing());
    let mut records = adapter.migration_records();
    let Outcome::Sealed(opening) = migrate(&rows, &mut records, 1, 1, 1, None).expect("seals")
    else {
        panic!("seals");
    };
    assert!(opening.checkpoint.totals.is_empty());
    assert!(
        !store
            .requests()
            .iter()
            .any(|r| r.starts_with("get_usage") || r.starts_with("list_metering")),
        "a plan that names nothing reads nothing"
    );
}

/// The two row families stay apart on a real reading too: the same bucket, the same day, the same
/// lane and the same unit, held once by the token ledger and once by a metering row, opens two
/// balances rather than one at their sum.
#[test]
fn the_window_and_metering_views_of_one_consumption_do_not_fold() {
    let store = Arc::new(SeededRows::default());
    store.seed_key("vk_a");
    store.seed_usage(
        "vk_a",
        WINDOW,
        UsageLedger {
            requests: 0,
            billable_requests: 0,
            models: vec![model("gpt-4", &[("input", 100)])],
        },
    );
    store.seed_metering(
        WINDOW,
        MeteringRow {
            tokens_input: 100,
            tokens_output: 0,
            tokens_cache_read: 0,
            tokens_cache_write: 0,
            requests: 0,
            billable_requests: 0,
            ..metering_row("vk_a", "gpt-4", "")
        },
    );
    let adapter = adapter_over(store.clone());
    let rows = adapter.legacy_ledger_rows(
        adapter
            .key_bucket_plan(WINDOW, &[], &[WINDOW])
            .expect("the key rows list"),
    );
    let mut records = adapter.migration_records();
    let Outcome::Sealed(opening) = migrate(&rows, &mut records, 1, 1, 1, None).expect("seals")
    else {
        panic!("seals");
    };
    assert_eq!(
        opening.checkpoint.totals.len(),
        2,
        "one consumption held in two places opens two balances, not one at double"
    );
    for figures in opening.checkpoint.totals.values() {
        assert_eq!(figures.settled, 100);
        assert_eq!(figures.drawn, 100);
    }
    let read: Vec<_> = adapter
        .legacy_ledger_rows(LegacyReadPlan {
            windows: vec![("vk_a".to_string(), WINDOW)],
            days: vec![WINDOW],
        })
        .cells()
        .figures
        .iter()
        .map(|f| f.family)
        .collect();
    assert!(read.contains(&LegacyFamily::Window) && read.contains(&LegacyFamily::Meter));
}

// ---------------------------------------------------------------------------------------------
// The same three rules, against the PUBLISHED sqlite store.
// ---------------------------------------------------------------------------------------------

/// A store handle that reads through and PANICS on every write — a read-only replica or a
/// grant-restricted database, which is a supported shape and not an exotic one.
struct ReadOnly(Arc<dyn AbiStore>);

impl AbiStore for ReadOnly {
    fn put_key(&self, _key: &VirtualKey) -> StoreResult<()> {
        panic!("the migration must never write a key row");
    }
    fn get_key(&self, id: &str) -> StoreResult<Option<VirtualKey>> {
        self.0.get_key(id)
    }
    fn list_keys(&self) -> StoreResult<Vec<VirtualKey>> {
        self.0.list_keys()
    }
    fn delete_key(&self, _id: &str) -> StoreResult<()> {
        panic!("the migration must never delete a key row");
    }
    fn get_usage(&self, bucket_id: &str, window_start: u64) -> StoreResult<UsageLedger> {
        self.0.get_usage(bucket_id, window_start)
    }
    fn put_usage(&self, _b: &str, _w: u64, _l: &UsageLedger) -> StoreResult<()> {
        panic!("the migration must never write a usage row");
    }
    fn add_metering(&self, _delta: &MeteringDelta) -> StoreResult<()> {
        panic!("the migration must never write a metering row");
    }
    fn list_metering(&self, bucket: u64) -> StoreResult<Vec<MeteringRow>> {
        self.0.list_metering(bucket)
    }
    fn list_audit(&self) -> StoreResult<Vec<AuditRecord>> {
        self.0.list_audit()
    }
    fn list_audit_tail(&self, limit: u64) -> StoreResult<Vec<AuditRecord>> {
        self.0.list_audit_tail(limit)
    }
    fn append_audit(&self, _entry: &AuditRecord) -> StoreResult<()> {
        panic!("the migration must never append an audit record");
    }
}

/// The previous release's rows, on the REAL published sqlite store: seeded through the published
/// wire, then migrated through a handle that cannot be written to. Same tarball, same pinned digest
/// the oracle's store-persist cell drives, so what that proves about the wire and what this proves
/// about the opening figures are about one binary.
#[test]
fn an_opening_sealed_off_the_published_sqlite_store() {
    let Some(tarball_path) = cached_published_sqlite_tarball() else {
        eprintln!(
            "skip: no published store-sqlite tarball in the oracle cache (run \
             `testing/shadow-oracle/fetch-plugin.sh store-sqlite`)"
        );
        return;
    };
    let bytes = std::fs::read(&tarball_path).expect("read the cached published tarball");
    let unpacked = tarball::unpack(&bytes).expect("the published tarball unpacks");
    assert_eq!(unpacked.manifest.abi_version, PUBLISHED_SCHEMA);

    let db = std::env::temp_dir().join(format!(
        "busbar-store-adapter-migration-{}.db",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&db);
    let cfg = serde_json::json!({ "db_path": db.to_string_lossy() }).to_string();
    let store = load_dyn_store_from_bytes_at_abi(
        &unpacked.lib_bytes,
        &cfg,
        "published-store-sqlite",
        &unpacked.manifest.kind,
        unpacked.manifest.abi_version,
    )
    .unwrap_or_else(|e| panic!("the published sqlite store must load on this binary: {e}"));
    let seeding = StoreAdapter::over_loaded_store(store);

    // The previous release's rows, written through the published wire the previous release used.
    seeding
        .store()
        .put_key(&VirtualKey {
            id: "vk_sqlite".to_string(),
            generation_hash: "gen".to_string(),
            name: "migration".to_string(),
            enabled: true,
            created_at: 1_700_000_000,
            ..Default::default()
        })
        .expect("the published wire takes a key");
    seeding
        .store()
        .put_usage(
            "vk_sqlite",
            WINDOW,
            &UsageLedger {
                requests: 21,
                billable_requests: 20,
                models: vec![model("gpt-4", &[("input", 1_234), ("output", 56)])],
            },
        )
        .expect("the published wire takes a token ledger");
    seeding
        .store()
        .add_metering(&MeteringDelta {
            key_id: "vk_sqlite".to_string(),
            bucket: WINDOW,
            model: "gpt-4".to_string(),
            provider: "openai".to_string(),
            tokens_input: 1_234,
            tokens_output: 56,
            tokens_cache_read: 0,
            tokens_cache_write: 0,
            requests: 21,
            billable_requests: 20,
            key_group_at_use: String::new(),
            pricing_version: "v1".to_string(),
        })
        .expect("the published wire takes a metering delta");

    // And now the migration, through a handle that would panic on any write.
    let read_only = StoreAdapter::new(Arc::new(ReadOnly(seeding.store())), PUBLISHED_SCHEMA);
    let plan = read_only
        .key_bucket_plan(WINDOW, &[], &[WINDOW])
        .expect("the key rows list off sqlite");
    let rows = read_only.legacy_ledger_rows(plan);
    let mut records = read_only.migration_records();
    let Outcome::Sealed(opening) =
        migrate(&rows, &mut records, 1, 1_700_000_000, 2, None).expect("the migration seals")
    else {
        panic!("the first boot seals");
    };

    assert_eq!(
        opened(
            &opening.checkpoint.totals,
            "vk_sqlite",
            CapDimension::Class("input".into()),
            BucketScope::Pool("lane:gpt-4".into())
        )
        .settled,
        1_234,
        "the sealed figure is the row sqlite actually holds"
    );
    assert_eq!(
        opened(
            &opening.checkpoint.totals,
            "vk_sqlite",
            CapDimension::Class("input".into()),
            BucketScope::Pool("meter:gpt-4/openai".into())
        )
        .settled,
        1_234
    );
    assert_eq!(
        opened(
            &opening.checkpoint.totals,
            "vk_sqlite",
            CapDimension::Requests,
            BucketScope::All
        )
        .settled,
        21
    );
    assert!(opening.unreadable.is_empty());
    assert!(opening.checkpoint.body_hash_verifies());

    // The second boot on the same node is a no-op, on the real store as on the double.
    let again = migrate(
        &read_only.legacy_ledger_rows(LegacyReadPlan {
            windows: vec![("vk_sqlite".to_string(), WINDOW)],
            days: vec![WINDOW],
        }),
        &mut records,
        1,
        1_700_000_100,
        2,
        None,
    )
    .expect("the second boot is fine");
    assert!(!again.sealed_now());
    assert_eq!(again.marker(), &opening.marker);

    drop(read_only);
    drop(seeding);
    let _ = std::fs::remove_file(&db);
}
