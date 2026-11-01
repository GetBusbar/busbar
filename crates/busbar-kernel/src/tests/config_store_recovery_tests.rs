// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use crate::appbuild::{load_config_from_disk, load_config_from_disk_with_store, AcceptAll};
use crate::config::overlay::{persist_root, RootSettings};
use crate::test_support::TestOverlayStore;

fn inputs() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
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
    let fixture = TestOverlayStore::new();
    let backend = fixture.backend();
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
    fixture.fail_reads(true);
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
    let fixture = TestOverlayStore::new();
    fixture.fail_reads(true);
    let loaded = load_config_from_disk_with_store(
        &path,
        None,
        false,
        crate::config::EnvSubst::Strict,
        &AcceptAll,
        Some(fixture.backend()),
    )
    .unwrap();
    assert!(loaded.config_locked);
    assert!(loaded.overlay_path.is_none());
    assert!(loaded.overlay_doc.is_none());
}

#[test]
fn base_store_bootstrap_and_effective_build_share_the_same_opened_store() {
    let _limits_lock = crate::config::limits::LIMITS_TEST_LOCK.blocking_lock();
    crate::test_support::register_neutral_test_plane();
    crate::snapshot::init();
    let _fixture = crate::test_support::TestApp::new();
    let cfg = crate::test_support::cfg_with_provider_api_key(crate::config::SecretRef::none());
    let opened =
        crate::appbuild::bootstrap_config_store(&cfg, &crate::config::PluginsCfg::default())
            .unwrap();
    let calls = opened.calls.as_ref().unwrap().clone();
    let backend = crate::config::overlay::OverlayStore::new(calls.clone()).unwrap();
    persist_root(
        Some(&backend),
        &RootSettings {
            per_request_fee: Some(23),
            ..Default::default()
        },
    )
    .unwrap();
    let rules: std::sync::Arc<dyn crate::appbuild::RootRules> = std::sync::Arc::new(AcceptAll);
    let (app, _, _limits) = crate::appbuild::build_app_from_config_with_store(
        cfg,
        crate::config::PluginsCfg::default(),
        Some(backend),
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
        Some(opened),
    )
    .unwrap();
    assert!(std::sync::Arc::ptr_eq(
        &app.governance.unwrap().store_calls().unwrap(),
        &calls
    ));
}

#[test]
fn a_cross_node_sibling_update_and_intervening_get_cannot_authorize_a_stale_app_commit() {
    let fixture = TestOverlayStore::new();
    let backend = fixture.backend();
    persist_root(Some(&backend), &RootSettings::default()).unwrap();
    let app = crate::test_support::TestApp::new()
        .overlay_backend(backend.clone())
        .build();
    let handle = crate::state::AppHandle::new(app);
    let before = handle.load();
    let other = fixture.fork_backend();
    crate::config::overlay::persist_groups(
        Some(&other),
        &std::collections::BTreeMap::from([("remote_security_team".into(), Default::default())]),
        None,
        None,
        &Default::default(),
    )
    .unwrap();
    // These are the ordinary diagnostic read paths. Neither may advance the old App's baseline.
    assert!(backend
        .read_required()
        .unwrap()
        .unwrap()
        .groups
        .contains_key("remote_security_team"));
    assert!(backend.read_bytes().unwrap().is_some());
    let next = std::sync::Arc::new(
        crate::governance::group_provision::build_with_group(
            &before,
            "local_candidate",
            Default::default(),
        )
        .unwrap(),
    );
    let persist = crate::governance::group_provision::persist_provisioned_group(
        next.clone(),
        "local_candidate".into(),
        "test".into(),
    );
    assert!(handle.commit_and_swap(next, persist).is_err());
    assert!(std::sync::Arc::ptr_eq(&handle.load(), &before));
    let stored = backend.read_required().unwrap().unwrap();
    assert!(stored.groups.contains_key("remote_security_team"));
    assert!(!stored.groups.contains_key("local_candidate"));
}
