// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use crate::appbuild::{load_config_from_disk, load_config_from_disk_with_store, AcceptAll};
use crate::config::overlay::{persist_root_async, RootSettings};
use busbar_contract::persistence::{
    BackendInfo, Call, ClockObservation, DatasetId, Decision, Failure, Page, PersistenceBackend,
    PreparedCandidate, Read, ReadResult, Scan,
};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

struct FailOverlayReads {
    actual: Arc<dyn PersistenceBackend>,
    fail: AtomicBool,
}
impl PersistenceBackend for FailOverlayReads {
    fn info(&self) -> BackendInfo {
        self.actual.info()
    }
    fn read(&self, request: Arc<Read>) -> Call<'_, ReadResult> {
        let schema = b"busbar.config.overlay.v1";
        if self.fail.load(Ordering::SeqCst)
            && request.addresses.iter().any(|address| {
                address
                    .key
                    .windows(schema.len())
                    .any(|bytes| bytes == schema)
            })
        {
            Box::pin(async { Err(Failure::Unavailable) })
        } else {
            self.actual.read(request)
        }
    }
    fn scan(&self, request: Arc<Scan>) -> Call<'_, Page> {
        self.actual.scan(request)
    }
    fn commit(&self, candidate: PreparedCandidate) -> Call<'_, Decision> {
        self.actual.commit(candidate)
    }
    fn clock(&self, dataset: DatasetId) -> Call<'_, ClockObservation> {
        self.actual.clock(dataset)
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

#[tokio::test]
async fn reload_recovers_exact_store_anchor_and_refuses_unreadable_security_state() {
    let (_dir, path) = inputs();
    let calls = Arc::new(FailOverlayReads {
        actual: crate::real_store::native_backend().await,
        fail: AtomicBool::new(false),
    });
    let core = crate::real_store::core_over(calls.clone()).await;
    let backend = crate::config::overlay::OverlayStore::from_core(core).unwrap();
    persist_root_async(
        Some(&backend),
        &RootSettings {
            admin_require_mtls: Some(true),
            per_request_fee: Some(11),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let loaded = load_config_from_disk_with_store(
        &path,
        None,
        false,
        crate::config::EnvSubst::Strict,
        &AcceptAll,
        Some(backend.clone()),
    )
    .await
    .unwrap();
    assert_eq!(
        loaded
            .overlay_path
            .as_ref()
            .unwrap()
            .read_bytes_async()
            .await
            .unwrap(),
        backend.read_bytes_async().await.unwrap()
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
    .await
    .is_err());
    let quarantined = load_config_from_disk_with_store(
        &path,
        None,
        true,
        crate::config::EnvSubst::Strict,
        &AcceptAll,
        Some(backend),
    )
    .await
    .unwrap();
    assert!(quarantined.overlay_doc.is_none());
    assert!(quarantined.overlay_path.is_some());
}

#[tokio::test]
async fn locked_reload_never_reads_the_overlay_even_when_its_store_is_unreadable() {
    let (_dir, path) = inputs();
    std::fs::write(&path, "config:\n  locked: true\nproviders: {}\nmodels: {}\nstore:\n  module: memory\n  settings: {}\n").unwrap();
    let calls = Arc::new(FailOverlayReads {
        actual: crate::real_store::native_backend().await,
        fail: AtomicBool::new(false),
    });
    let core = crate::real_store::core_over(calls.clone()).await;
    let backend = crate::config::overlay::OverlayStore::from_core(core).unwrap();
    calls.fail.store(true, Ordering::SeqCst);
    let loaded = load_config_from_disk_with_store(
        &path,
        None,
        false,
        crate::config::EnvSubst::Strict,
        &AcceptAll,
        Some(backend),
    )
    .await
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
