// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_kernel::config::{HookCfg, HookKind, PromptAccess, UserAccess};

#[path = "usage_adjustment_range.rs"]
mod usage_adjustment_range;

pub(crate) fn hook(kind: HookKind, global: bool) -> HookCfg {
    HookCfg {
        kind,
        plugin: "test-hook".to_string(),
        timeout_ms: 5,
        on_error: "weighted".to_string(),
        prompt: PromptAccess::No,
        user: UserAccess::No,
        priority: 0,
        settings: serde_json::Map::new(),
        at: None,
        on_empty: None,
        global,
        default: false,
        signals: Vec::new(),
        groups: Vec::new(),
        phase: Vec::new(),
    }
}

use busbar_kernel::admission::{Inventoried, Judged, Stated};

fn tmp_plugins_dir(tag: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);

    static PROC_TOKEN: std::sync::OnceLock<u128> = std::sync::OnceLock::new();
    let token = PROC_TOKEN.get_or_init(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    });
    let d = std::env::temp_dir().join(format!(
        "busbar-plugin-admin-{}-{token:x}-{n}-{tag}",
        std::process::id(),
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn inspect_rejects_oversized_tarball_before_unpacking() {
    let cap = 64 * 1024;
    let huge = vec![0u8; cap + 1];
    let err = check_inspect_tarball_size(huge.len(), cap as u64).unwrap_err();
    assert!(
        matches!(&err, AdminError::Validation(msg) if msg.contains("byte cap")),
        "got {err:?}"
    );
}

#[test]
fn inspect_reports_the_admissions_verdict_in_the_catalog_vocabulary() {
    for (judged, word) in [
        (
            Judged::Trusted {
                publisher: "acme".into(),
            },
            "trusted",
        ),
        (Judged::Allowed, "unverified"),
        (
            Judged::Rejected {
                reason: "unsigned plugin".into(),
            },
            "rejected",
        ),
    ] {
        let manifest = Stated {
            name: "acme-store-v".into(),
            alias: "v".into(),
            kind: "store".into(),
            version: "1.0.0".into(),
            publisher: "acme".into(),
            abi_version: 3,
            settings_schema: None,
        };
        let view = inspect_plugin_view(manifest, judged, |_| true);
        assert_eq!(view["trust"], word, "{word}");
        assert_eq!(view["name"], "acme-store-v");
        assert_eq!(view["kind"], "store");
        assert_eq!(view["restart_required_default"], true);
    }
}

#[test]
fn catalog_preserves_manifest_kinds_and_filters_store_queries() {
    let mut inventory = Vec::new();
    for kind in [
        "store",
        "auth",
        "secret",
        "hook",
        "export",
        "transport",
        "plane",
        "unknown",
    ] {
        inventory.push(Inventoried {
            file: format!("{kind}.tar.gz"),
            stated: Some(Stated {
                name: kind.into(),
                alias: kind.into(),
                kind: kind.into(),
                version: "1.0.0".into(),
                publisher: "acme".into(),
                abi_version: 3,
                settings_schema: None,
            }),
            signature: "unsigned (allowed)".into(),
            status: "ready".into(),
        });
    }
    inventory.push(Inventoried {
        file: "corrupt.tar.gz".into(),
        stated: None,
        signature: "-".into(),
        status: "INVALID: invalid manifest".into(),
    });
    let catalog: Vec<_> = inventory.into_iter().map(plugin_inventory_view).collect();
    for kind in [
        "store",
        "auth",
        "secret",
        "hook",
        "export",
        "transport",
        "plane",
        "unknown",
        "corrupt",
    ] {
        let file = format!("{kind}.tar.gz");
        let row = catalog
            .iter()
            .find(|p| p.file.as_deref() == Some(file.as_str()))
            .unwrap();
        let expected = if matches!(kind, "unknown" | "corrupt") {
            "store"
        } else {
            kind
        };
        assert_eq!(row.r#type, expected, "{file}");
    }
    for query in ["store", "db"] {
        assert!(matches!(plugin_query(query), Ok(PluginQuery::Store)));
        let mut files: Vec<_> = catalog_rows_of_kind(catalog.clone(), "store")
            .filter_map(|row| row.file)
            .collect();
        files.sort();
        assert_eq!(files, ["corrupt.tar.gz", "store.tar.gz", "unknown.tar.gz"]);
    }
    for query in ["export", "transport", "plane"] {
        assert!(
            matches!(plugin_query(query), Err(AdminError::Validation(_))),
            "the catalog correction adds no new query type"
        );
    }
}

#[test]
fn catalog_projects_each_inventory_row_into_the_catalog_vocabulary() {
    let mut inventory = Vec::new();
    for (file, name, signature, status) in [
        ("a.tar.gz", "acme-store-a", "publisher:acme", "ready"),
        ("b.tar.gz", "acme-store-b", "unsigned (allowed)", "ready"),
        (
            "c.tar.gz",
            "acme-store-c",
            "unsigned",
            "SKIPPED: unsigned plugin",
        ),
    ] {
        inventory.push(Inventoried {
            file: file.into(),
            stated: Some(Stated {
                name: name.into(),
                alias: name.into(),
                kind: "store".into(),
                version: "2.1.0".into(),
                publisher: "acme".into(),
                abi_version: 3,
                settings_schema: None,
            }),
            signature: signature.into(),
            status: status.into(),
        });
    }
    inventory.push(Inventoried {
        file: "d.tar.gz".into(),
        stated: None,
        signature: "-".into(),
        status: "INVALID: not a tarball".into(),
    });
    let cat: Vec<_> = inventory.into_iter().map(plugin_inventory_view).collect();
    let row = |file: &str| {
        cat.iter()
            .find(|p| p.target.as_deref() == Some(file))
            .unwrap_or_else(|| panic!("{file} is listed: {cat:?}"))
    };
    assert_eq!(row("a.tar.gz").trust, Some("trusted"));
    assert_eq!(row("a.tar.gz").publisher.as_deref(), Some("acme"));
    assert_eq!(row("a.tar.gz").version.as_deref(), Some("2.1.0"));
    assert_eq!(row("b.tar.gz").trust, Some("unverified"));
    assert_eq!(row("c.tar.gz").trust, Some("rejected"));
    assert_eq!(row("c.tar.gz").valid, Some(false));
    assert!(row("c.tar.gz")
        .error
        .as_deref()
        .is_some_and(|e| e.contains("SKIPPED")));
    assert_eq!(row("d.tar.gz").trust, None);
    assert_eq!(
        row("d.tar.gz").name,
        "d.tar.gz",
        "no manifest: named by its file"
    );
}

#[test]
fn catalog_cache_ttl_prunes_stale_entries() {
    let now = CATALOG_CACHE_TTL_SECS + 10;
    let dir = std::path::PathBuf::from("cached");
    let mut cache = HashMap::from([(
        dir.clone(),
        CatalogCacheEntry {
            key: 0,
            rows: Vec::new(),
            misses: 1,
            inserted_at: now,
        },
    )]);
    assert!(
        cache.contains_key(&dir),
        "the input contains a cached entry"
    );
    cache.get_mut(&dir).expect("entry present").inserted_at =
        now.saturating_sub(CATALOG_CACHE_TTL_SECS + 1);
    prune_catalog_cache(&mut cache, now);
    assert!(
        !cache.contains_key(&dir),
        "an entry older than CATALOG_CACHE_TTL_SECS must be pruned on the next cache access"
    );
}

#[test]
fn catalog_cache_future_inserted_at_is_treated_as_stale() {
    let now = CATALOG_CACHE_TTL_SECS + 10;
    let dir = std::path::PathBuf::from("cached");
    let mut cache = HashMap::from([(
        dir.clone(),
        CatalogCacheEntry {
            key: 0,
            rows: Vec::new(),
            misses: 1,
            inserted_at: now,
        },
    )]);
    assert!(
        cache.contains_key(&dir),
        "the input contains a cached entry"
    );
    cache.get_mut(&dir).expect("entry present").inserted_at = now + CATALOG_CACHE_TTL_SECS + 1;
    prune_catalog_cache(&mut cache, now);
    assert!(!cache.contains_key(&dir), "an entry whose inserted_at is in the future (backward clock jump) must be treated as stale, not ageless");
}

use busbar_kernel::config::groups::{LimitMetric, LimitWindow};
use busbar_kernel::config::{GroupCfg, LimitCfg};

use busbar_kernel::governance::{GovState, VirtualKey};

use busbar_kernel_testkit::test_support::store_double::MemoryStore;

fn usage_group_cfg() -> GroupCfg {
    let limit = |metric, amount, per, pool: Option<&str>| LimitCfg {
        metric,
        amount,
        per: Some(per),
        scope: pool.map(busbar_contract::records::ScopeRef::pool),
        on_exhaust: None,
        downgrade_to: None,
        admission: None,
        on_exhaustion: None,
    };
    GroupCfg {
        limits: vec![
            limit(LimitMetric::Requests, 5, LimitWindow::Day, None),
            limit(LimitMetric::Budget, 1_000, LimitWindow::Month, None),
            limit(
                LimitMetric::Budget,
                500,
                LimitWindow::Month,
                Some("frontier"),
            ),
        ],
        ..Default::default()
    }
}

fn usage_cost(
    groups: &std::collections::BTreeMap<String, GroupCfg>,
) -> busbar_kernel::cost::CostModel {
    let card = std::collections::BTreeMap::from([(
        "m".to_string(),
        busbar_kernel::config::RateEntryCfg {
            input_utok: 10.0,
            output_utok: 10.0,
            cache_read_utok: 0.0,
            cache_write_utok: 0.0,
            ..Default::default()
        },
    )]);
    busbar_kernel::cost::CostModel::resolve_parts(Some(&card), 0, groups)
}

fn usage_key(group: &str) -> VirtualKey {
    VirtualKey {
        id: "vk_usage_probe".to_string(),
        generation_hash: "h:vk_usage_probe".to_string(),
        name: "usage-probe".to_string(),
        allowed_scopes: None,
        enabled: true,
        created_at: 0,
        group: Some(group.to_string()),
        labels: Default::default(),
        expires_at: None,
        deleted_at: None,
        revision: 1,
        ..Default::default()
    }
}

fn input_toks(n: u64) -> std::collections::BTreeMap<String, u64> {
    let mut m = std::collections::BTreeMap::new();
    if n != 0 {
        m.insert(busbar_contract::records::UNIT_INPUT.to_string(), n);
    }
    m
}

struct WaitsForTheRuntime {
    inner: MemoryStore,
    started: Arc<tokio::sync::Notify>,
    word: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
    waited: std::sync::atomic::AtomicBool,
    heard: Arc<std::sync::atomic::AtomicBool>,
}

impl busbar_contract::records::RecordStore for WaitsForTheRuntime {
    fn put_key(
        &self,
        key: &busbar_contract::records::VirtualKey,
    ) -> busbar_contract::records::RecordStoreResult<()> {
        self.inner.put_key(key)
    }
    fn get_key(
        &self,
        id: &str,
    ) -> busbar_contract::records::RecordStoreResult<Option<busbar_contract::records::VirtualKey>>
    {
        self.inner.get_key(id)
    }
    fn list_keys(
        &self,
    ) -> busbar_contract::records::RecordStoreResult<Vec<busbar_contract::records::VirtualKey>>
    {
        self.inner.list_keys()
    }
    fn delete_key(&self, id: &str) -> busbar_contract::records::RecordStoreResult<()> {
        self.inner.delete_key(id)
    }
    fn get_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
    ) -> busbar_contract::records::RecordStoreResult<busbar_contract::records::UsageLedger> {
        use std::sync::atomic::Ordering::SeqCst;
        if !self.waited.swap(true, SeqCst) {
            self.started.notify_one();
            let word = self
                .word
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if word.recv_timeout(std::time::Duration::from_secs(5)).is_ok() {
                self.heard.store(true, SeqCst);
            }
        }
        self.inner.get_usage(bucket_id, window_start)
    }
    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &busbar_contract::records::UsageLedger,
    ) -> busbar_contract::records::RecordStoreResult<()> {
        self.inner.put_usage(bucket_id, window_start, ledger)
    }
    fn add_metering(
        &self,
        delta: &busbar_contract::records::MeteringDelta,
    ) -> busbar_contract::records::RecordStoreResult<()> {
        self.inner.add_metering(delta)
    }
    fn list_metering(
        &self,
        bucket: u64,
    ) -> busbar_contract::records::RecordStoreResult<Vec<busbar_contract::records::MeteringRow>>
    {
        self.inner.list_metering(bucket)
    }
}

#[tokio::test(flavor = "current_thread")]
async fn get_group_usage_reads_the_store_off_the_async_worker() {
    let started = Arc::new(tokio::sync::Notify::new());
    let (tell, word) = std::sync::mpsc::channel();
    let heard = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let store = Arc::new(WaitsForTheRuntime {
        inner: MemoryStore::new(),
        started: Arc::clone(&started),
        word: std::sync::Mutex::new(word),
        waited: std::sync::atomic::AtomicBool::new(false),
        heard: Arc::clone(&heard),
    });
    let sibling = tokio::spawn(async move {
        started.notified().await;
        let _ = tell.send(());
    });
    let groups = std::collections::BTreeMap::from([("acme".to_string(), usage_group_cfg())]);
    let gov = Arc::new(GovState::new(store, None).unwrap());
    let app = crate::new_test_app()
        .group("acme", usage_group_cfg())
        .cost(usage_cost(&groups))
        .governance(gov)
        .build();
    let view = AdminService::new(app)
        .get_group_usage("acme")
        .await
        .expect("usage read");
    assert_eq!(view.buckets.len(), 3, "{:?}", view.buckets);
    sibling.await.expect("the sibling task runs");
    assert!(
        heard.load(std::sync::atomic::Ordering::SeqCst),
        "the group usage read held the async worker: no other task ran while the store read was \
         in progress"
    );
}

#[test]
fn admin_usage_breakdown_json_is_byte_identical_flat_token_aliases() {
    use crate::v1::contract::UsageBreakdown;
    let b = UsageBreakdown {
        tokens_input: 100,
        tokens_output: 40,
        tokens_cache_read: 7,
        tokens_cache_creation: 3,
        requests: 5,
        spend_micros: 12_345,
        classes: Default::default(),
    };
    let json = serde_json::to_string(&b).unwrap();
    assert_eq!(
        json,
        r#"{"tokens_input":100,"tokens_output":40,"tokens_cache_read":7,"tokens_cache_creation":3,"requests":5,"spend_micros":12345}"#,
        "the admin usage JSON must keep the flat token aliases, byte-identical to pre-M1b"
    );
}

/// A `Store` decorator whose `list_metering` always fails, everything else delegating to a
/// real `MemoryStore` — proves `get_usage`'s store-failure arm without needing a real broken
/// backend.
#[derive(Default)]
struct FailingMeteringStore {
    inner: MemoryStore,
}
impl busbar_contract::records::RecordStore for FailingMeteringStore {
    fn put_key(&self, key: &VirtualKey) -> busbar_contract::records::RecordStoreResult<()> {
        self.inner.put_key(key)
    }
    fn get_key(&self, id: &str) -> busbar_contract::records::RecordStoreResult<Option<VirtualKey>> {
        self.inner.get_key(id)
    }
    fn list_keys(&self) -> busbar_contract::records::RecordStoreResult<Vec<VirtualKey>> {
        self.inner.list_keys()
    }
    fn delete_key(&self, id: &str) -> busbar_contract::records::RecordStoreResult<()> {
        self.inner.delete_key(id)
    }
    fn get_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
    ) -> busbar_contract::records::RecordStoreResult<busbar_contract::records::UsageLedger> {
        self.inner.get_usage(bucket_id, window_start)
    }
    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &busbar_contract::records::UsageLedger,
    ) -> busbar_contract::records::RecordStoreResult<()> {
        self.inner.put_usage(bucket_id, window_start, ledger)
    }
    fn add_metering(
        &self,
        delta: &busbar_contract::records::MeteringDelta,
    ) -> busbar_contract::records::RecordStoreResult<()> {
        self.inner.add_metering(delta)
    }
    fn list_metering(
        &self,
        _bucket: u64,
    ) -> busbar_contract::records::RecordStoreResult<Vec<busbar_contract::records::MeteringRow>>
    {
        Err(busbar_contract::records::RecordStoreError(
            "simulated metering store outage".to_string(),
        ))
    }
}

#[test]
fn usage_read_store_failure_logs_the_real_error() {
    use tracing_subscriber::layer::SubscriberExt as _;
    let cap = busbar_kernel_testkit::test_support::warn_capture::WarnCapture::default();
    let subscriber = tracing_subscriber::registry().with(cap.clone());
    tracing::subscriber::with_default(subscriber, || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let gov =
                Arc::new(GovState::new(Arc::new(FailingMeteringStore::default()), None).unwrap());
            let app = crate::new_test_app().governance(gov).build();
            let svc = AdminService::new(app);
            let err = svc.get_usage(None, None).await.unwrap_err();
            assert!(
                matches!(err, AdminError::Internal),
                "wire contract is unchanged: still AdminError::Internal, {err:?}"
            );
        });
    });
    assert!(
        cap.contains("usage.metering") && cap.contains("simulated metering store outage"),
        "the real store error and which read failed must be logged: {:?}",
        cap.messages()
    );
}

#[test]
fn plugins_dir_fingerprint_treats_a_missing_dir_as_ok_empty() {
    let missing = tmp_plugins_dir("fingerprint-missing");
    std::fs::remove_dir_all(&missing).unwrap();
    assert!(
        !missing.exists(),
        "precondition: the directory must genuinely not exist"
    );
    let fp = plugins_dir_fingerprint(&missing).expect("a missing dir must not I/O-error");

    let empty = tmp_plugins_dir("fingerprint-really-empty");
    std::fs::create_dir_all(&empty).unwrap();
    let empty_fp =
        plugins_dir_fingerprint(&empty).expect("a real empty dir must not I/O-error either");
    assert_eq!(
        fp, empty_fp,
        "a missing dir's fingerprint must equal a real empty dir's fingerprint, not some \
             other Ok value"
    );

    std::fs::write(empty.join("something"), b"x").unwrap();
    let nonempty_fp = plugins_dir_fingerprint(&empty).expect("a populated dir must not error");
    assert_ne!(
        fp, nonempty_fp,
        "a populated dir's fingerprint must differ from the empty one"
    );
}

#[test]
fn validate_plugin_filename_rejects_each_escape_form_independently() {
    assert!(
        validate_plugin_filename_with("../evil.tar.gz", |file| file.ends_with(".tar.gz")
            || file.ends_with(".tgz"))
        .is_err(),
        "..  alone must reject"
    );
    assert!(
        validate_plugin_filename_with("sub/evil.tar.gz", |file| file.ends_with(".tar.gz")
            || file.ends_with(".tgz"))
        .is_err(),
        "/ alone must reject"
    );
    assert!(
        validate_plugin_filename_with("sub\\evil.tar.gz", |file| file.ends_with(".tar.gz")
            || file.ends_with(".tgz"))
        .is_err(),
        "\\ alone must reject"
    );
    assert!(
        validate_plugin_filename_with("plain.tar.gz", |file| file.ends_with(".tar.gz")
            || file.ends_with(".tgz"))
        .is_ok(),
        "a bare filename with none of the three must be accepted"
    );
}

#[test]
fn validate_plugin_filename_length_boundary_is_exact() {
    let suffix = ".tar.gz";
    let at_cap = "a".repeat(MAX_PLUGIN_FILENAME_LEN - suffix.len()) + suffix;
    assert_eq!(at_cap.len(), MAX_PLUGIN_FILENAME_LEN);
    assert!(
        validate_plugin_filename_with(&at_cap, |file| file.ends_with(".tar.gz")
            || file.ends_with(".tgz"))
        .is_ok(),
        "exactly MAX_PLUGIN_FILENAME_LEN chars must be accepted"
    );
    let over_cap = format!("a{at_cap}");
    assert!(
        validate_plugin_filename_with(&over_cap, |file| file.ends_with(".tar.gz")
            || file.ends_with(".tgz"))
        .is_err(),
        "MAX_PLUGIN_FILENAME_LEN + 1 chars must be rejected"
    );
}

#[test]
fn max_settings_bytes_is_exactly_64_kibibytes() {
    assert_eq!(MAX_SETTINGS_BYTES, 65_536);
    assert_eq!(MAX_SETTINGS_BYTES, 64 * 1024);
}

#[test]
fn max_inspect_schema_json_bytes_is_exactly_256_kibibytes() {
    assert_eq!(MAX_INSPECT_SCHEMA_JSON_BYTES, 262_144);
    assert_eq!(MAX_INSPECT_SCHEMA_JSON_BYTES, 256 * 1024);
}

#[test]
fn build_with_registry_rejects_more_than_one_default_but_allows_exactly_one() {
    let mut one_default = hook(HookKind::Tap, false);
    one_default.default = true;
    let mut registry = HashMap::new();
    registry.insert("a".to_string(), one_default.clone());
    assert!(
        validate_hook_registry(&registry, &[]).is_ok(),
        "exactly one default: true hook must be accepted"
    );

    let mut second_default = hook(HookKind::Tap, false);
    second_default.default = true;
    registry.insert("b".to_string(), second_default);
    assert!(
        validate_hook_registry(&registry, &[]).is_err(),
        "more than one default: true hook must be rejected"
    );
}

#[test]
fn build_with_registry_rejects_a_dangling_global_hook_reference() {
    let mut registry = HashMap::new();
    registry.insert("logger".to_string(), hook(HookKind::Tap, true));

    assert!(
        validate_hook_registry(&registry, &["logger".to_string()]).is_ok(),
        "a global_hooks entry that IS in the registry must be accepted"
    );

    assert!(
        validate_hook_registry(&registry, &["ghost".to_string()]).is_err(),
        "a global_hooks entry naming an unregistered hook must be rejected"
    );
}

#[cfg(test)]
mod dated_rate_card_history {
    use super::*;
    use busbar_kernel::cost::{Author, CardEntryDraft, History, RateCard, TierRates};
    use busbar_kernel::governance::GovState;
    use busbar_kernel_testkit::test_support::store_double::MemoryStore;

    const LANE: &str = "m-priced-chat";
    const PROVIDER: &str = "priced-chat";
    const KEY: &str = "vk_payg";

    const TOKENS: u64 = 1_000;
    const DAY: u64 = busbar_kernel::governance::METERING_BUCKET_SECS;

    pub(super) fn card(micro_per_token: f64) -> RateCard {
        RateCard::from_config(
            Some([(
                LANE,
                TierRates {
                    input: Some((micro_per_token * 1000.0).round() as u64),
                    ..Default::default()
                },
            )]),
            0,
        )
    }

    fn newest_cost() -> busbar_kernel::cost::CostModel {
        let rates = std::collections::BTreeMap::from([(
            LANE.to_string(),
            busbar_kernel::config::RateEntryCfg {
                input_utok: 1.0,
                output_utok: 0.0,
                cache_read_utok: 0.0,
                cache_write_utok: 0.0,
                ..Default::default()
            },
        )]);
        busbar_kernel::cost::CostModel::resolve_parts(
            Some(&rates),
            0,
            &std::collections::BTreeMap::new(),
        )
    }

    pub(super) fn source(history: History) -> &'static Arc<History> {
        Box::leak(Box::new(Arc::new(history)))
    }

    pub(super) fn metering_rows(
        rows: &[(u64, u64)],
    ) -> Vec<(u64, busbar_kernel::governance::MeteringRow)> {
        priced_metering_rows(rows.iter().map(|(bucket, era)| (*bucket, *era, "")))
    }

    pub(super) fn priced_metering_rows<'a>(
        rows: impl IntoIterator<Item = (u64, u64, &'a str)>,
    ) -> Vec<(u64, busbar_kernel::governance::MeteringRow)> {
        rows.into_iter()
            .map(|(bucket, priced_from_ms, pricing_version)| {
                (
                    bucket,
                    busbar_kernel::governance::MeteringRow {
                        usage_units: Default::default(),
                        key_id: KEY.to_string(),
                        model: LANE.to_string(),
                        provider: PROVIDER.to_string(),
                        tokens_input: TOKENS,
                        tokens_output: 0,
                        tokens_cache_read: 0,
                        tokens_cache_write: 0,
                        requests: 1,
                        billable_requests: 1,
                        key_group_at_use: String::new(),
                        pricing_version: pricing_version.to_string(),
                        priced_from_ms,
                    },
                )
            })
            .collect()
    }

    async fn read_stored(gov: Arc<GovState>, src: &'static Arc<History>, bucket: u64) -> UsageView {
        let app = crate::new_test_app()
            .governance(gov)
            .cost(newest_cost())
            .build();
        AdminService::new(app)
            .with_rate_history(Arc::clone(src))
            .get_usage(Some(bucket), None)
            .await
            .expect("usage read")
    }

    async fn read(
        rows: Vec<(u64, busbar_kernel::governance::MeteringRow)>,
        src: &'static Arc<History>,
        bucket: u64,
    ) -> UsageView {
        read_as_of(rows, src, bucket, None)
            .await
            .expect("usage read")
    }

    pub(super) async fn read_as_of(
        rows: Vec<(u64, busbar_kernel::governance::MeteringRow)>,
        src: &'static Arc<History>,
        bucket: u64,
        as_of: Option<busbar_kernel::cost::EntryKey>,
    ) -> Result<UsageView, AdminError> {
        let snapshot = as_of
            .map(|key| validated_snapshot(Some(src.as_ref()), key))
            .transpose()?;
        let rows = rows
            .into_iter()
            .filter(|(window, _)| *window == bucket)
            .map(|(_, row)| row)
            .collect();
        super::super::operations::project_usage_rows(
            Arc::new(newest_cost()),
            Some(Arc::clone(src)),
            snapshot,
            UsageWindow {
                start: bucket,
                end: bucket + DAY,
            },
            busbar_kernel::store::now(),
            (rows, HashMap::new(), Vec::new()),
        )
    }

    pub(super) async fn read_no_source_as_of(
        rows: Vec<(u64, busbar_kernel::governance::MeteringRow)>,
        bucket: u64,
        as_of: Option<busbar_kernel::cost::EntryKey>,
    ) -> Result<UsageView, AdminError> {
        let snapshot = as_of.map(|key| validated_snapshot(None, key)).transpose()?;
        let rows = rows
            .into_iter()
            .filter(|(window, _)| *window == bucket)
            .map(|(_, row)| row)
            .collect();
        super::super::operations::project_usage_rows(
            Arc::new(newest_cost()),
            None,
            snapshot,
            UsageWindow {
                start: bucket,
                end: bucket + DAY,
            },
            busbar_kernel::store::now(),
            (rows, HashMap::new(), Vec::new()),
        )
    }

    #[tokio::test]
    async fn an_adjust_of_a_units_counts_moves_the_served_usage_figure() {
        use busbar_kernel::governance::{AdjustRefused, Adjustment};
        const ADJUSTED_KEY: &str = "vk_adjust_404";

        let (day, _, _) = windows();
        let served_at = day + 5;
        let store = Arc::new(MemoryStore::new());
        let key = VirtualKey {
            id: ADJUSTED_KEY.to_string(),
            generation_hash: format!("h:{ADJUSTED_KEY}"),
            name: "adjusted".to_string(),
            enabled: true,
            revision: 1,
            ..Default::default()
        };
        busbar_contract::records::RecordStore::put_key(store.as_ref(), &key).expect("key persists");
        busbar_contract::records::RecordStore::add_metering(
            store.as_ref(),
            &busbar_contract::records::MeteringDelta {
                key_id: ADJUSTED_KEY.to_string(),
                bucket: day,
                model: LANE.to_string(),
                provider: PROVIDER.to_string(),
                tokens_input: TOKENS,
                tokens_output: 0,
                tokens_cache_read: 0,
                tokens_cache_write: 0,
                requests: 1,
                billable_requests: 1,
                key_group_at_use: String::new(),
                pricing_version: String::new(),
                priced_from_ms: 0,
                usage_units: Default::default(),
            },
        )
        .expect("the memory store accepts a metering delta");
        let cost = newest_cost();
        let gov = Arc::new(GovState::new(store.clone(), None).expect("governance builds"));

        let units = std::collections::BTreeMap::from([(
            busbar_contract::records::UNIT_INPUT.to_string(),
            TOKENS,
        )]);
        gov.record_usage(&cost, &key, "", LANE, &units, served_at);
        let src = source(History::opening(card(2.5), 0));

        let before = read_stored(gov.clone(), src, day).await.total;
        assert_eq!((before.tokens_input, before.spend_micros), (1_000, 2_500));

        let era = busbar_kernel::rate_apply::effective_from_at(busbar_kernel::store::now_ms());
        let adjust = |key_id: &'static str, by: i64| {
            let delta = std::collections::BTreeMap::from([(
                busbar_contract::records::UNIT_INPUT.to_string(),
                by,
            )]);
            gov.adjust_usage(
                &cost,
                &Adjustment {
                    key_id,
                    pool: "",
                    model: LANE,
                    entry_era: era,
                    entry_id: None,
                    card_epoch_ms: served_at * 1_000,
                    delta: &delta,
                    now: busbar_kernel::store::now(),
                },
            )
            .expect("the store reads")
        };
        assert!(
            matches!(
                adjust(ADJUSTED_KEY, -1_001),
                Err(AdjustRefused::Exceeds { .. })
            ),
            "an adjustment past the metered count is refused"
        );
        assert_eq!(
            read_stored(gov.clone(), src, day).await.total.spend_micros,
            2_500,
            "a refused adjustment moves nothing"
        );
        assert_eq!(adjust(ADJUSTED_KEY, -200), Ok(()));
        let after = read_stored(gov.clone(), src, day).await.total;
        assert_eq!(
            (after.tokens_input, after.spend_micros),
            (800, 2_000),
            "the served figure prices the adjusted counts: 800 x 2.5"
        );

        let restarted = Arc::new(GovState::new(store, None).expect("governance builds"));
        let again = read_stored(restarted, src, day).await.total;
        assert_eq!(
            (again.tokens_input, again.spend_micros),
            (800, 2_000),
            "the adjustment row is durable: a restart serves the same figure"
        );
    }

    pub(super) fn windows() -> (u64, u64, u64) {
        let today = busbar_kernel::governance::metering_bucket(busbar_kernel::store::now());
        (today - 3 * DAY, today - 2 * DAY, today - DAY)
    }

    fn payg_then_monthly_then_prepaid(monthly: u64, prepaid: u64) -> History {
        let mut history = History::opening(card(10.0), 0);
        history.append(CardEntryDraft {
            effective_from: monthly * 1_000,
            effective_until: None,
            card: card(5.0),
            appended_at: monthly * 1_000,
            author: Author::Config { policy_epoch: 1 },
        });
        history.append(CardEntryDraft {
            effective_from: prepaid * 1_000,
            effective_until: None,
            card: card(1.0),
            appended_at: prepaid * 1_000,
            author: Author::Config { policy_epoch: 2 },
        });
        history
    }

    #[tokio::test]
    async fn each_window_prices_at_the_card_in_force_when_it_was_earned() {
        let (payg, monthly, prepaid) = windows();
        let src = source(payg_then_monthly_then_prepaid(monthly, prepaid));

        let gov = metering_rows(&[
            (payg, 0),
            (monthly, monthly * 1_000),
            (prepaid, prepaid * 1_000),
        ]);

        assert_eq!(
            read(gov.clone(), src, payg).await.total.spend_micros,
            10_000,
            "the PAYG window keeps the card it was earned under (10 x 1_000 tokens)"
        );
        assert_eq!(
            read(gov.clone(), src, monthly).await.total.spend_micros,
            5_000,
            "the month-to-month window prices at 5"
        );
        assert_eq!(
            read(gov, src, prepaid).await.total.spend_micros,
            1_000,
            "the prepaid window prices at 1"
        );
    }

    #[tokio::test]
    async fn old_served_counts_keep_their_config_era_across_a_later_bucket_and_activation() {
        let (old, activated, later) = windows();
        let mut history = History::opening(card(20.0), 0);
        history.append(CardEntryDraft {
            effective_from: old * 1_000,
            effective_until: None,
            card: card(10.0),
            appended_at: old * 1_000,
            author: Author::Config { policy_epoch: 1 },
        });
        let old_seq = history.head_key().expect("the appended entry has a key");
        history.append(CardEntryDraft {
            effective_from: activated * 1_000,
            effective_until: None,
            card: card(1.0),
            appended_at: activated * 1_000,
            author: Author::Config { policy_epoch: 2 },
        });
        let src = source(history);
        let old_rows = metering_rows(&[(later, old * 1_000)]);
        let old_read = read(old_rows.clone(), src, later).await;
        assert_eq!(old_read.total.spend_micros, 10_000);
        assert_eq!(old_read.rate_card_version, Some(old_seq.hex()));
        assert_eq!(
            read_as_of(old_rows, src, later, Some(old_seq))
                .await
                .unwrap()
                .total
                .spend_micros,
            10_000,
        );
        let both = metering_rows(&[(later, old * 1_000), (later, activated * 1_000)]);
        let both_read = read(both, src, later).await;
        assert_eq!(both_read.total.tokens_input, TOKENS * 2);
        assert_eq!(both_read.total.spend_micros, 11_000);
    }

    #[tokio::test]
    async fn amendments_reach_old_served_eras_without_enabling_later_config_repricing() {
        let (old, activated, corrected_day) = windows();
        let mut history = History::opening(card(20.0), 0);
        history.append(CardEntryDraft {
            effective_from: old * 1_000,
            effective_until: None,
            card: card(10.0),
            appended_at: old * 1_000,
            author: Author::Config { policy_epoch: 1 },
        });
        let old_seq = history.head_key().expect("the appended entry has a key");
        history.append(CardEntryDraft {
            effective_from: activated * 1_000,
            effective_until: None,
            card: card(1.0),
            appended_at: activated * 1_000,
            author: Author::Config { policy_epoch: 2 },
        });
        let activated_seq = history.head_key().expect("the appended entry has a key");
        history.append(CardEntryDraft {
            effective_from: corrected_day * 1_000,
            effective_until: Some((corrected_day + DAY) * 1_000),
            card: card(5.0),
            appended_at: busbar_kernel::store::now_ms(),
            author: Author::Amend {
                reason_hash: [7; 32],
            },
        });
        let amended_seq = history.head_key().expect("the appended entry has a key");
        let src = source(history);
        let rows = metering_rows(&[(activated, old * 1_000), (corrected_day, old * 1_000)]);
        let before = read_as_of(rows.clone(), src, corrected_day, Some(activated_seq))
            .await
            .unwrap();
        assert_eq!(before.total.spend_micros, 10_000);
        assert_eq!(before.rate_card_version, Some(old_seq.hex()));
        let corrected = read(rows.clone(), src, corrected_day).await;
        assert_eq!(corrected.total.spend_micros, 5_000);
        assert_eq!(corrected.rate_card_version, Some(amended_seq.hex()));
        assert_eq!(read(rows, src, activated).await.total.spend_micros, 10_000);
    }

    #[tokio::test]
    async fn exact_opening_provenance_survives_a_later_config_and_legacy_names_keep_their_reading()
    {
        use busbar_kernel::cost::EntryId;
        const UNKNOWN_ENTRY_ID: &str = "ffffffffffffffffffffffff";
        const LEGACY_NAMED_VERSION: &str = "historical-card";
        let (_old, activated, later) = windows();
        let mut history = History::opening(card(10.0), 0);
        let opening_version = history.entries()[0].id().metering_version();
        history.append(CardEntryDraft {
            effective_from: activated * 1_000,
            effective_until: None,
            card: card(1.0),
            appended_at: activated * 1_000,
            author: Author::Config { policy_epoch: 1 },
        });
        let activated_seq = history.head_key().expect("the appended entry has a key");
        let activated_version = history.entries()[1].id().metering_version();
        let src = source(history);
        let known = priced_metering_rows([(later, 0, opening_version.as_str())]);
        let view = read(known, src, later).await;
        assert_eq!(view.total.spend_micros, 10_000);
        assert_eq!(view.rate_card_version, Some(src.entries()[0].key().hex()));
        for legacy in ["", LEGACY_NAMED_VERSION] {
            let rows = priced_metering_rows([(later, 0, legacy)]);
            let view = read(rows, src, later).await;
            assert_eq!(view.total.spend_micros, 1_000);
            assert_eq!(view.rate_card_version, Some(activated_seq.hex()));
        }
        let malformed = EntryId::METERING_VERSION_PREFIX;
        let unknown = EntryId::parse_hex(UNKNOWN_ENTRY_ID)
            .unwrap()
            .metering_version();
        for (era, version) in [
            (0, malformed),
            (0, unknown.as_str()),
            (activated * 1_000, opening_version.as_str()),
        ] {
            let rows = priced_metering_rows([(later, era, version)]);
            assert!(matches!(
                read_as_of(rows, src, later, None).await,
                Err(AdminError::Internal)
            ));
        }
        let new_rows =
            priced_metering_rows([(later, activated * 1_000, activated_version.as_str())]);
        assert!(
            matches!(
                read_as_of(new_rows, src, later, Some(src.entries()[0].key())).await,
                Err(AdminError::Internal)
            ),
            "a snapshot cannot price counts whose exact source entry it does not contain"
        );
    }

    #[tokio::test]
    async fn the_usage_response_names_the_rate_card_version_that_priced_it() {
        let (payg, monthly, prepaid) = windows();
        let src = source(payg_then_monthly_then_prepaid(monthly, prepaid));
        let gov = metering_rows(&[
            (payg, 0),
            (monthly, monthly * 1_000),
            (prepaid, prepaid * 1_000),
        ]);
        for (bucket, index) in [(payg, 0), (monthly, 1), (prepaid, 2)] {
            let seq = src.entries()[index].key();
            let live = read(gov.clone(), src, bucket).await;
            assert_eq!(
                live.rate_card_version,
                Some(seq.hex()),
                "the window at {bucket} is priced by history entry {seq}"
            );
            let pinned = read_as_of(gov.clone(), src, bucket, Some(seq))
                .await
                .expect("the named version is a snapshot this history holds");
            assert_eq!(
                pinned.total.spend_micros, live.total.spend_micros,
                "`?as_of=<rate_card_version>` re-derives the figure the version was served beside"
            );
            assert_eq!(pinned.rate_card_version, Some(seq.hex()));
            let wire = serde_json::to_value(&live).expect("a usage view serializes");
            assert_eq!(wire["rate_card_version"], serde_json::json!(seq.hex()));
        }
        let none = read_no_source_as_of(gov, payg, None)
            .await
            .expect("a node with no dated history still reads");
        assert_eq!(none.rate_card_version, None);
        let wire = serde_json::to_value(&none).expect("a usage view serializes");
        assert!(
            wire["rate_card_version"].is_null(),
            "no history: the version is null, never a zero"
        );
    }

    #[tokio::test]
    async fn a_hole_in_the_dated_history_refuses_rather_than_pricing_at_the_current_card() {
        let (payg, monthly, _prepaid) = windows();
        let mut history = History::new();
        history.append(CardEntryDraft {
            effective_from: monthly * 1_000,
            effective_until: None,
            card: card(5.0),
            appended_at: monthly * 1_000,
            author: Author::Config { policy_epoch: 0 },
        });
        let src = source(history);
        let gov = metering_rows(&[(payg, 0), (monthly, monthly * 1_000)]);

        assert_eq!(
            read(gov.clone(), src, monthly).await.total.spend_micros,
            5_000,
            "the covered window prices at the entry in force (5 x 1_000 tokens)"
        );
        assert!(
            matches!(
                read_as_of(gov, src, payg, None).await,
                Err(AdminError::Internal)
            ),
            "a row no history entry covers must REFUSE the read, never price at the current card"
        );
    }

    #[tokio::test]
    async fn publishing_a_card_leaves_the_window_before_it_byte_identical() {
        let (payg, _, _) = windows();
        let gov = metering_rows(&[(payg, 0)]);

        let before = source(History::opening(card(10.0), 0));

        let mut published = History::opening(card(10.0), 0);
        let now_ms = busbar_kernel::store::now().saturating_mul(1_000);
        published.append(CardEntryDraft {
            effective_from: now_ms,
            effective_until: None,
            card: card(1.0),
            appended_at: now_ms,
            author: Author::Config { policy_epoch: 1 },
        });
        let after = source(published);

        let bytes = |mut v: serde_json::Value| {
            v["as_of"] = serde_json::json!(0);
            serde_json::to_string(&v).expect("a usage view serializes")
        };
        let a =
            bytes(serde_json::to_value(read(gov.clone(), before, payg).await).expect("serializes"));
        let b = bytes(serde_json::to_value(read(gov, after, payg).await).expect("serializes"));
        assert_eq!(
            a, b,
            "a forward-dated publish must not touch the window before its effective_from"
        );
        assert!(
            a.contains("\"spend_micros\":10000"),
            "and the window is still priced at the card it was earned under: {a}"
        );
    }

    #[tokio::test]
    async fn a_back_dated_correction_reprices_its_window_and_nothing_outside_it() {
        let (payg, monthly, prepaid) = windows();

        let gov = metering_rows(&[(payg, 0), (monthly, 0), (prepaid, 0)]);

        let before = source(History::opening(card(10.0), 0));
        for w in [payg, monthly, prepaid] {
            assert_eq!(
                read(gov.clone(), before, w).await.total.spend_micros,
                10_000,
                "a single-entry history prices every window at the opening card"
            );
        }

        let mut corrected = History::opening(card(10.0), 0);
        corrected.append(CardEntryDraft {
            effective_from: monthly * 1_000,
            effective_until: Some(prepaid * 1_000),
            card: card(5.0),
            appended_at: busbar_kernel::store::now().saturating_mul(1_000),
            author: Author::Amend {
                reason_hash: [7u8; 32],
            },
        });
        let after = source(corrected);

        assert_eq!(
            read(gov.clone(), after, payg).await.total.spend_micros,
            10_000,
            "OUTSIDE, before effective_from: unmoved"
        );
        assert_eq!(
            read(gov.clone(), after, monthly).await.total.spend_micros,
            5_000,
            "INSIDE [effective_from, effective_until): repriced"
        );
        assert_eq!(
            read(gov, after, prepaid).await.total.spend_micros,
            10_000,
            "OUTSIDE, at and after effective_until: unmoved"
        );
    }

    #[tokio::test]
    async fn a_card_edit_inside_a_day_splits_the_day_and_each_half_keeps_its_own_card() {
        let (_, _, today) = windows();
        let noon = (today + DAY / 2) * 1_000;
        let mut history = History::opening(card(10.0), 0);
        history.append(CardEntryDraft {
            effective_from: noon,
            effective_until: None,
            card: card(1.0),
            appended_at: noon,
            author: Author::Config { policy_epoch: 1 },
        });
        let src = source(history);

        let gov = metering_rows(&[(today, 0), (today, noon)]);

        let view = read(gov, src, today).await;
        assert_eq!(
            view.total.spend_micros, 11_000,
            "the day is 10 x 1_000 earned before noon plus 1 x 1_000 earned after it — not \
             20_000 (all morning) and not 2_000 (all afternoon)"
        );
        assert_eq!(
            view.total.tokens_input, 2_000,
            "and the quantities still roll up whole: splitting the price never splits the counts"
        );
        assert_eq!(
            view.by_model.len(),
            1,
            "the split is a PRICING fact, not an attribution one: one model, one provider, one row \
             in the report"
        );
    }
}

#[cfg(test)]
mod usage_as_of {
    use super::dated_rate_card_history::{
        card, metering_rows, priced_metering_rows, read_as_of, source, windows,
    };
    use busbar_kernel::cost::{Author, CardEntryDraft, History};

    #[tokio::test]
    async fn an_older_snapshot_is_re_derivable_and_the_publish_moves_neither() {
        let (payg, _, _) = windows();
        let gov = metering_rows(&[(payg, 0)]);
        let mut history = History::opening(card(10.0), 0);
        let now_ms = busbar_kernel::store::now().saturating_mul(1_000);
        history.append(CardEntryDraft {
            effective_from: now_ms,
            effective_until: None,
            card: card(1.0),
            appended_at: now_ms,
            author: Author::Config { policy_epoch: 1 },
        });
        let src = source(history);

        assert_eq!(
            read_as_of(gov.clone(), src, payg, Some(src.entries()[0].key()))
                .await
                .expect("the opening key exists")
                .total
                .spend_micros,
            10_000,
            "at the opening snapshot the window prices at the opening card"
        );
        assert_eq!(
            read_as_of(gov, src, payg, Some(src.entries()[1].key()))
                .await
                .expect("the head key exists")
                .total
                .spend_micros,
            10_000,
            "and at the head too — the publish is dated after the window it did not touch"
        );
    }

    #[tokio::test]
    async fn a_snapshot_before_a_correction_still_answers_the_old_figure() {
        let (payg, _, _) = windows();
        let gov = metering_rows(&[(payg, 0)]);
        let mut history = History::opening(card(10.0), 0);
        history.append(CardEntryDraft {
            effective_from: payg.saturating_mul(1_000),
            effective_until: Some(payg.saturating_add(86_400).saturating_mul(1_000)),
            card: card(5.0),
            appended_at: busbar_kernel::store::now().saturating_mul(1_000),
            author: Author::Amend {
                reason_hash: [7u8; 32],
            },
        });
        let src = source(history);

        assert_eq!(
            read_as_of(gov.clone(), src, payg, Some(src.entries()[0].key()))
                .await
                .expect("the opening key exists")
                .total
                .spend_micros,
            10_000,
            "the snapshot taken before the correction re-derives the figure it was cut at"
        );
        assert_eq!(
            read_as_of(gov.clone(), src, payg, Some(src.entries()[1].key()))
                .await
                .expect("the head key exists")
                .total
                .spend_micros,
            5_000,
            "the snapshot that can see the correction reports the corrected figure"
        );
        assert_eq!(
            read_as_of(gov, src, payg, None)
                .await
                .expect("no snapshot named")
                .total
                .spend_micros,
            5_000,
            "and naming no snapshot is the history as it stands, which is the head"
        );
    }

    #[test]
    fn an_unknown_snapshot_key_is_refused_on_either_side_of_known_entries() {
        use busbar_kernel::cost::EntryKey;
        let mut history = History::new();
        for at in [100, 300] {
            history.insert(
                EntryKey::new(at, [1; 8], 0),
                CardEntryDraft {
                    effective_from: at,
                    effective_until: None,
                    card: card(10.0),
                    appended_at: at,
                    author: Author::Config { policy_epoch: at },
                },
            );
        }
        let src = history;
        for at in [50, 200, 400] {
            let unknown = EntryKey::new(at, [1; 8], 0);
            let err = validated_snapshot(Some(&src), unknown)
                .expect_err("a snapshot key that does not exist is a refusal");
            let crate::v1::contract::AdminError::Validation(msg) = &err else {
                panic!("expected a client-safe validation refusal, got {err:?}");
            };
            assert!(
                msg.contains(&unknown.hex()) && msg.contains("known rate-card history entry"),
                "the refusal must name the unknown key without interpreting its position: {msg}"
            );
        }
    }

    #[test]
    fn a_snapshot_of_a_history_that_does_not_exist_is_refused() {
        let err = validated_snapshot(None, busbar_kernel::cost::EntryKey::new(0, [0; 8], 0))
            .expect_err("there is no snapshot of a history that does not exist");
        let crate::v1::contract::AdminError::Validation(msg) = &err else {
            panic!("expected a client-safe validation refusal, got {err:?}");
        };
        assert!(
            msg.contains("no rate-card history"),
            "the refusal must say WHY there is nothing to snapshot: {msg}"
        );
    }

    #[tokio::test]
    async fn a_saved_keyed_read_replays_after_an_earlier_peer_entry_arrives() {
        use busbar_kernel::cost::EntryKey;
        let (payg, _, _) = windows();
        let wall = payg * 1_000;
        let draft = |at, rate| CardEntryDraft {
            effective_from: at,
            effective_until: None,
            card: card(rate),
            appended_at: at,
            author: Author::Config { policy_epoch: at },
        };
        let opening = EntryKey::new(100, [1; 8], 0);
        let saved = EntryKey::new(300, [1; 8], 1);
        let late_peer = EntryKey::new(200, [2; 8], 0);
        let mut history = History::new();
        let mut first = draft(0, 20.0);
        first.author = Author::Opening;
        history.insert(opening, first);
        history.insert(saved, draft(300, 10.0));
        let version = saved.id().metering_version();
        for gov in [
            metering_rows(&[(payg, 0)]),
            priced_metering_rows([(payg, 300, version.as_str())]),
        ] {
            let before = read_as_of(gov.clone(), source(history.clone()), payg, Some(saved))
                .await
                .expect("the saved key is present before peer delivery");
            assert_eq!(before.total.spend_micros, 10_000);
            assert_eq!(before.rate_card_version, Some(saved.hex()));
            assert!(wall > 300, "all three entries cover the row instant");

            let mut after_history = history.clone();
            after_history.insert(late_peer, draft(200, 2.0));
            let after_source = source(after_history);
            let current = read_as_of(gov.clone(), after_source, payg, None)
                .await
                .unwrap();
            assert_eq!(current.total.spend_micros, 10_000);
            let after = read_as_of(gov, after_source, payg, Some(saved))
                .await
                .expect("late delivery cannot invalidate the saved boundary");
            assert_eq!(after.total.spend_micros, before.total.spend_micros);
            assert_eq!(after.rate_card_version, before.rate_card_version);
            assert_eq!(after.total.tokens_input, before.total.tokens_input);
        }
    }
}

#[test]
fn every_admin_trust_resolution_warns_about_a_malformed_floor() {
    use busbar_kernel::diagnostics::CONFIG_ANTIDOWNGRADE_FLOOR_INVALID;
    #[derive(Clone)]
    struct Captured(Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for Captured {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut cfg = busbar_kernel::config::PluginsCfg::default();
    cfg.min_versions.insert("p".into(), "v2".into());
    let captured = Arc::new(std::sync::Mutex::new(Vec::new()));
    let writer = Captured(captured.clone());
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        assert_eq!(
            super::operations::resolve_admission(&cfg, None)
                .err()
                .as_deref(),
            Some("no plugin trust policy is installed (the composition root's)")
        );
    });
    let messages = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
    assert!(
        messages.contains(&CONFIG_ANTIDOWNGRADE_FLOOR_INVALID.banner().to_string()),
        "{messages}"
    );
}

#[test]
fn an_admin_view_shows_only_declared_public_setting_values() {
    let public = |module: &str| -> std::collections::BTreeSet<String> {
        match module {
            "stub" => ["url".to_string()].into_iter().collect(),
            _ => std::collections::BTreeSet::new(),
        }
    };
    let mut v = serde_json::json!({
        "store": { "module": "stub", "settings": {
            "url": "https://ledger.internal", "password": "hunter2", "undeclared": "u-value"
        } },
        "other": { "module": "plain", "settings": { "url": "https://plain.internal" } }
    });
    super::redact_settings_bags_with(&mut v, &public);
    let text = v.to_string();
    for hidden in ["hunter2", "u-value", "https://plain.internal"] {
        assert!(!text.contains(hidden), "`{hidden}` shown: {text}");
    }
    assert_eq!(
        v["store"]["settings_public"],
        serde_json::json!({ "url": "https://ledger.internal" })
    );
    assert_eq!(
        v["store"]["settings_keys"],
        serde_json::json!(["password", "undeclared", "url"])
    );
    assert!(v["other"].get("settings_public").is_none(), "{text}");
    assert_eq!(v["other"]["settings_keys"], serde_json::json!(["url"]));
}
