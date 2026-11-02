// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use crate::appbuild::{load_config_from_disk, load_config_from_disk_with_store, AcceptAll};
use crate::config::overlay::{persist_root, RootSettings};
use busbar_contract::{
    abi::store::OpId,
    kinds::RecordBytes,
    records::{MeteringDelta, PlaneRecordRef, PlaneSelector, UsageDelta},
    store_calls::{StoreCall, StoreCalls, StoreFailure},
};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

struct FailOverlayReads {
    actual: Arc<dyn StoreCalls>,
    fail: AtomicBool,
}
impl StoreCalls for FailOverlayReads {
    fn supports_usage_correction(&self) -> bool {
        self.actual.supports_usage_correction()
    }
    fn apply_usage_correction<'a>(
        &'a self,
        request: &'a crate::records::correction::Request,
    ) -> StoreCall<'a, crate::records::correction::Decision> {
        self.actual.apply_usage_correction(request)
    }
    fn supports_record_transaction(&self) -> bool {
        self.actual.supports_record_transaction()
    }
    fn record_transaction<'a>(
        &'a self,
        request: &'a crate::abi::sdk::store::conditional::Request,
    ) -> StoreCall<'a, crate::abi::sdk::store::conditional::Decision> {
        self.actual.record_transaction(request)
    }
    fn add_usage_batch<'a>(
        &'a self,
        op: OpId,
        cells: &'a [(&'a str, u64, UsageDelta)],
    ) -> StoreCall<'a, ()> {
        self.actual.add_usage_batch(op, cells)
    }
    fn add_metering_batch<'a>(
        &'a self,
        op: OpId,
        deltas: &'a [MeteringDelta],
    ) -> StoreCall<'a, ()> {
        self.actual.add_metering_batch(op, deltas)
    }
    fn record_put<'a>(
        &'a self,
        schema: &'a str,
        key: &'a [u8],
        value: &'a RecordBytes,
    ) -> StoreCall<'a, ()> {
        self.actual.record_put(schema, key, value)
    }
    fn record_get<'a>(
        &'a self,
        schema: &'a str,
        key: &'a [u8],
    ) -> StoreCall<'a, Option<RecordBytes>> {
        if schema == "busbar.config.overlay.v1" && self.fail.load(Ordering::SeqCst) {
            Box::pin(std::future::ready(Err(StoreFailure::Failed(
                "overlay read interrupted".into(),
            ))))
        } else {
            self.actual.record_get(schema, key)
        }
    }
    fn record_scan<'a>(
        &'a self,
        schema: &'a str,
        prefix: &'a [u8],
        limit: u32,
    ) -> StoreCall<'a, Vec<(Vec<u8>, RecordBytes)>> {
        self.actual.record_scan(schema, prefix, limit)
    }
    fn put_key<'a>(&'a self, key: &'a crate::records::VirtualKey) -> StoreCall<'a, ()> {
        self.actual.put_key(key)
    }
    fn get_key<'a>(&'a self, id: &'a str) -> StoreCall<'a, Option<crate::records::VirtualKey>> {
        self.actual.get_key(id)
    }
    fn list_keys(&self) -> StoreCall<'_, Vec<crate::records::VirtualKey>> {
        self.actual.list_keys()
    }
    fn delete_key<'a>(&'a self, id: &'a str) -> StoreCall<'a, ()> {
        self.actual.delete_key(id)
    }
    fn put_key_with_credential<'a>(
        &'a self,
        key: &'a crate::records::VirtualKey,
        secret: &'a crate::records::CredentialSecret,
    ) -> StoreCall<'a, ()> {
        self.actual.put_key_with_credential(key, secret)
    }
    fn list_credentials<'a>(
        &'a self,
        key_id: &'a str,
    ) -> StoreCall<'a, Vec<crate::records::CredentialMeta>> {
        self.actual.list_credentials(key_id)
    }
    fn revoke_credential<'a>(&'a self, id: &'a str, reason: &'a str) -> StoreCall<'a, ()> {
        self.actual.revoke_credential(id, reason)
    }
    fn list_credentials_since(
        &self,
        since: u64,
    ) -> StoreCall<'_, Vec<crate::records::CredentialSecret>> {
        self.actual.list_credentials_since(since)
    }
    fn add_denylist<'a>(&'a self, sub: &'a str, reason: &'a str) -> StoreCall<'a, ()> {
        self.actual.add_denylist(sub, reason)
    }
    fn list_denylist(&self) -> StoreCall<'_, Vec<String>> {
        self.actual.list_denylist()
    }
    fn list_metering(&self, bucket: u64) -> StoreCall<'_, Vec<crate::records::MeteringRow>> {
        self.actual.list_metering(bucket)
    }
    fn list_audit(&self) -> StoreCall<'_, Vec<crate::records::AuditRecord>> {
        self.actual.list_audit()
    }
    fn list_audit_tail(&self, limit: u64) -> StoreCall<'_, Vec<crate::records::AuditRecord>> {
        self.actual.list_audit_tail(limit)
    }
    fn upsert_plane_record<'a>(&'a self, record: PlaneRecordRef<'a>) -> StoreCall<'a, ()> {
        self.actual.upsert_plane_record(record)
    }
    fn get_plane_record<'a>(
        &'a self,
        kind: &'a str,
        id: &'a str,
    ) -> StoreCall<'a, Option<Vec<u8>>> {
        self.actual.get_plane_record(kind, id)
    }
    fn append_plane_record<'a>(
        &'a self,
        op: OpId,
        record: PlaneRecordRef<'a>,
    ) -> StoreCall<'a, ()> {
        self.actual.append_plane_record(op, record)
    }
    fn list_plane_records<'a>(
        &'a self,
        kind: &'a str,
        selector: &'a PlaneSelector<'a>,
    ) -> StoreCall<'a, Vec<Vec<u8>>> {
        self.actual.list_plane_records(kind, selector)
    }
    fn delete_plane_record<'a>(&'a self, kind: &'a str, id: &'a str) -> StoreCall<'a, ()> {
        self.actual.delete_plane_record(kind, id)
    }
    fn redeem_plane_token<'a>(
        &'a self,
        kind: &'a str,
        token: &'a str,
        expires_at: u64,
        now: u64,
    ) -> StoreCall<'a, bool> {
        self.actual.redeem_plane_token(kind, token, expires_at, now)
    }
    fn plane_token_live<'a>(
        &'a self,
        kind: &'a str,
        token: &'a str,
        expires_at: u64,
        now: u64,
    ) -> StoreCall<'a, bool> {
        self.actual.plane_token_live(kind, token, expires_at, now)
    }
    fn list_plane_record_parents<'a>(&'a self, kind: &'a str) -> StoreCall<'a, Vec<String>> {
        self.actual.list_plane_record_parents(kind)
    }
    fn purge_plane_records_before<'a>(&'a self, kind: &'a str, before: u64) -> StoreCall<'a, u64> {
        self.actual.purge_plane_records_before(kind, before)
    }
    fn purge_usage_before(&self, before: u64) -> StoreCall<'_, u64> {
        self.actual.purge_usage_before(before)
    }
}

struct InputsDir(std::path::PathBuf);
impl InputsDir {
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}
impl Drop for InputsDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn inputs() -> (InputsDir, std::path::PathBuf) {
    let dir = InputsDir(std::env::temp_dir().join(format!(
        "busbar-config-store-{}-{}",
        std::process::id(),
        hex::encode(crate::door::op_id().0)
    )));
    std::fs::create_dir_all(dir.path()).unwrap();
    let config = dir.path().join("config.yaml");
    std::fs::write(
        &config,
        "providers: {}\nmodels: {}\nstore:\n  module: memory\n  settings: {}\n",
    )
    .unwrap();
    std::fs::write(dir.path().join("providers.yaml"), "{}\n").unwrap();
    (dir, config)
}

#[test]
fn operator_input_loader_never_reads_a_legacy_overlay_or_opens_a_store() {
    let (dir, path) = inputs();
    let legacy = dir.path().join("busbar-overlay.json");
    std::fs::write(&legacy, b"invalid legacy data remains owner-owned").unwrap();
    let loaded =
        load_config_from_disk(&path, None, false, crate::config::EnvSubst::Lenient).unwrap();
    assert!(loaded.overlay_path.is_none());
    assert!(loaded.overlay_doc.is_none());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 3);
    assert_eq!(
        std::fs::read(&legacy).unwrap(),
        b"invalid legacy data remains owner-owned"
    );
}

#[test]
fn reload_recovers_exact_store_anchor_and_refuses_unreadable_security_state() {
    let (_dir, path) = inputs();
    let calls = Arc::new(FailOverlayReads {
        actual: crate::real_store::store(),
        fail: AtomicBool::new(false),
    });
    let backend = crate::config::overlay::OverlayStore::new(calls.clone()).unwrap();
    persist_root(
        Some(&backend),
        &RootSettings {
            admin_require_mtls: Some(true),
            per_request_fee: Some(11),
            ..Default::default()
        },
    )
    .unwrap();
    let loaded = load_config_from_disk_with_store(
        &path,
        None,
        false,
        crate::config::EnvSubst::Strict,
        &AcceptAll,
        Some(backend.clone()),
    )
    .unwrap();
    assert_eq!(
        loaded.overlay_path.as_ref().unwrap().read_bytes().unwrap(),
        backend.read_bytes().unwrap()
    );
    assert_eq!(
        loaded.overlay_doc.unwrap().root.unwrap().per_request_fee,
        Some(11)
    );
    calls.fail.store(true, Ordering::SeqCst);
    assert!(load_config_from_disk_with_store(
        &path,
        None,
        false,
        crate::config::EnvSubst::Strict,
        &AcceptAll,
        Some(backend.clone())
    )
    .is_err());
    let quarantined = load_config_from_disk_with_store(
        &path,
        None,
        true,
        crate::config::EnvSubst::Strict,
        &AcceptAll,
        Some(backend),
    )
    .unwrap();
    assert!(quarantined.overlay_doc.is_none());
    assert!(quarantined.overlay_path.is_some());
}

#[test]
fn locked_reload_never_reads_the_overlay_even_when_its_store_is_unreadable() {
    let (_dir, path) = inputs();
    std::fs::write(&path, "config:\n  locked: true\nproviders: {}\nmodels: {}\nstore:\n  module: memory\n  settings: {}\n").unwrap();
    let calls = Arc::new(FailOverlayReads {
        actual: crate::real_store::store(),
        fail: AtomicBool::new(true),
    });
    let backend = crate::config::overlay::OverlayStore::new(calls).unwrap();
    let loaded = load_config_from_disk_with_store(
        &path,
        None,
        false,
        crate::config::EnvSubst::Strict,
        &AcceptAll,
        Some(backend),
    )
    .unwrap();
    assert!(loaded.config_locked);
    assert!(loaded.overlay_path.is_none());
    assert!(loaded.overlay_doc.is_none());
}

#[test]
fn bootstrap_dependency_closure_uses_declared_reference_paths_and_canonical_identities() {
    let deploy = crate::config::deploy_from_deserializer(serde_json::json!({
        "providers": {}, "models": {},
        "auth": {"chain": [], "admin_auth": []},
        "store": {"module": "store-alias", "settings": {
            "token": {"module": "secret-alias", "settings": {}},
            "data": {"literal": {"module": "unrelated", "settings": {}}}
        }}
    }))
    .unwrap();
    let cfg = crate::config::resolve(&deploy, &Default::default()).unwrap();
    assert_eq!(
        crate::appbuild::bootstrap_dependency_names_from_metadata(
            &cfg,
            &["token".to_string()],
            |module| match module {
                "store-alias" => "canonical-store".to_string(),
                "secret-alias" => "canonical-secret".to_string(),
                other => other.to_string(),
            }
        ),
        std::collections::BTreeSet::from(["canonical-store".into(), "canonical-secret".into()])
    );
}

#[test]
fn native_bootstrap_archive_pins_match_exact_retained_bytes_and_canonical_identity() {
    let pinned = "aa".repeat(32);
    let other = "bb".repeat(32);
    let mut plugins = crate::config::PluginsCfg::default();
    assert!(crate::appbuild::validate_bootstrap_archive(
        "canonical-store",
        "canonical-store.tar.gz",
        Some(&pinned),
        &plugins
    )
    .unwrap_err()
    .contains("base plugins.fetch"));
    plugins.fetch = vec![crate::config::PluginFetch::Url(crate::config::UrlFetch {
        url: "https://plugins.invalid/canonical-store.tar.gz".into(),
        sha256: Some(other),
    })];
    assert!(crate::appbuild::validate_bootstrap_archive(
        "canonical-store",
        "canonical-store.tar.gz",
        Some(&pinned),
        &plugins
    )
    .is_err());
    let crate::config::PluginFetch::Url(target) = &mut plugins.fetch[0] else {
        unreachable!()
    };
    target.sha256 = Some(pinned.clone());
    crate::appbuild::validate_bootstrap_archive(
        "canonical-store",
        "canonical-store.tar.gz",
        Some(&pinned),
        &plugins,
    )
    .unwrap();
}

#[test]
fn malformed_and_conflicting_bootstrap_pins_cannot_authorize_native_code() {
    let digest = "aa".repeat(32);
    let mut plugins = crate::config::PluginsCfg::default();
    for hashes in [vec!["aa".into()], vec![digest.clone(), "bb".repeat(32)]] {
        plugins.fetch = hashes
            .into_iter()
            .map(|hash| {
                crate::config::PluginFetch::Url(crate::config::UrlFetch {
                    url: "https://plugins.invalid/store.tar.gz".into(),
                    sha256: Some(hash),
                })
            })
            .collect();
        assert!(crate::appbuild::validate_bootstrap_archive(
            "store",
            "store.tar.gz",
            Some(&digest),
            &plugins
        )
        .is_err());
    }
}
