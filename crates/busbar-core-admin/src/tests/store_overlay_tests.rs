// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use axum::extract::State;
use axum::http::HeaderMap;
use busbar_kernel::auth::AuthPrincipal;
use busbar_kernel::state::AppHandle;

#[tokio::test]
async fn settings_preserves_a_large_store_overlay_across_reload() {
    let (dir, overlay, addr, server, _limits_lock) = settings_test_app("large-store-overlay").await;
    let groups: std::collections::BTreeMap<String, busbar_kernel::config::GroupCfg> = (0..32)
        .map(|index| (format!("persisted-team-{index:04}"), Default::default()))
        .collect();
    overlay.seed_bytes(
        serde_json::json!({
            "version": busbar_kernel::config::overlay::OVERLAY_VERSION,
            "groups": groups
        })
        .to_string()
        .as_bytes(),
    );
    let response = reqwest::Client::new()
        .put(format!("http://{addr}/api/v1/admin/config/settings"))
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"per_request_fee": 31}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status().as_u16(),
        200,
        "{:?}",
        response.text().await
    );
    let loaded = busbar_kernel::load_config_from_disk_with_store(
        &dir.join("config.yaml"),
        Some(&dir.join("providers.yaml")),
        false,
        busbar_kernel::config::EnvSubst::Strict,
        &busbar_kernel::appbuild::AcceptAll,
        Some(overlay.backend()),
    )
    .unwrap();
    let doc = loaded.overlay_doc.unwrap();
    assert_eq!(doc.root.unwrap().per_request_fee, Some(31));
    assert_eq!(
        serde_json::to_value(doc.groups).unwrap(),
        serde_json::to_value(groups).unwrap()
    );
    assert!(overlay.read_bytes().unwrap().len() > busbar_contract::MAX_RECORD_BYTES);
    server.abort();
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn unknown_settings_receipt_requires_successful_reload_before_new_mutation() {
    let _audit_guard = OVERLAY_ROOT_AUDIT.lock().await;
    let _limits_lock = busbar_kernel_testkit::limits::LIMITS_TEST_LOCK.lock().await;
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (dir, config_path, providers_path) = write_reset_fixture("unknown-reload-custody");
    let original_config = std::fs::read(&config_path).unwrap();
    let overlay = TestOverlayStore::new();
    let gov = gov_with_signer(Arc::new(MemoryStore::new()), Some("admintok".into()));
    let mut app = crate::new_test_app()
        .governance(gov)
        .overlay_backend(overlay.backend())
        .build();
    {
        let inner = Arc::get_mut(&mut app).unwrap();
        inner.config_path = Some(config_path.clone());
        inner.providers_path = Some(providers_path);
    }
    let handle = Arc::new(AppHandle::new(app));
    let before = handle.load();
    overlay.lose_next_commit_reply();
    let put = |fee| {
        crate::v1::json::put_config_settings(
            State(handle.clone()),
            axum::Extension(AuthPrincipal(None)),
            HeaderMap::new(),
            serde_json::json!({"per_request_fee": fee})
                .to_string()
                .into(),
        )
    };
    assert_eq!(put(17).await.status().as_u16(), 400);
    assert!(Arc::ptr_eq(&handle.load(), &before));
    assert_eq!(
        overlay
            .backend()
            .read_required()
            .unwrap()
            .unwrap()
            .root
            .unwrap()
            .per_request_fee,
        Some(17),
        "the Store applied the candidate before its reply was lost"
    );

    assert_eq!(put(29).await.status().as_u16(), 400);
    assert!(Arc::ptr_eq(&handle.load(), &before));
    let candidates = overlay.candidates();
    assert_eq!(candidates.len(), 2);
    assert_eq!(candidates[0].op_id, candidates[1].op_id);
    assert_eq!(candidates[0].fingerprint(), candidates[1].fingerprint());

    std::fs::write(
        &config_path,
        "store: {module: memory}\nproviders: {}\nmodels: {}\ngroups:\n  broken:\n    parent: missing\n",
    )
    .unwrap();
    let failed =
        crate::v1::json::reload_config(State(handle.clone()), axum::Extension(AuthPrincipal(None)))
            .await;
    assert_eq!(failed.status().as_u16(), 400);
    assert!(Arc::ptr_eq(&handle.load(), &before));
    let group = crate::v1::json::register_group(
        State(handle.clone()),
        axum::Extension(AuthPrincipal(None)),
        HeaderMap::new(),
        serde_json::json!({"name": "after_failed_reload", "config": {}})
            .to_string()
            .into(),
    )
    .await;
    assert_eq!(group.status().as_u16(), 400);
    assert!(Arc::ptr_eq(&handle.load(), &before));
    assert_eq!(
        overlay.candidates().len(),
        2,
        "quarantine admits no new candidate"
    );

    std::fs::write(&config_path, original_config).unwrap();
    let reset = crate::v1::json::reset_overlay_section(
        State(handle.clone()),
        axum::Extension(AuthPrincipal(None)),
        axum::extract::Path("root".to_string()),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(
        reset.status().as_u16(),
        400,
        "a reset rebuild also retains quarantine"
    );
    assert!(Arc::ptr_eq(&handle.load(), &before));
    assert_eq!(overlay.candidates().len(), 2);

    let reloaded =
        crate::v1::json::reload_config(State(handle.clone()), axum::Extension(AuthPrincipal(None)))
            .await;
    assert_eq!(reloaded.status().as_u16(), 200);
    let recovered = handle.load();
    assert!(!Arc::ptr_eq(&recovered, &before));
    assert_eq!(
        recovered
            .overlay_path
            .as_ref()
            .unwrap()
            .read_required()
            .unwrap()
            .unwrap()
            .root
            .unwrap()
            .per_request_fee,
        Some(17),
        "reload publishes the recovered Store generation"
    );
    assert_eq!(
        put(41).await.status().as_u16(),
        200,
        "the published fresh carrier can mutate"
    );
    assert_eq!(
        overlay
            .backend()
            .read_required()
            .unwrap()
            .unwrap()
            .root
            .unwrap()
            .per_request_fee,
        Some(41),
        "the new mutation persists to the same configured Store"
    );
    assert!(
        busbar_kernel::config::overlay::persist_root(
            Some(&overlay.backend()),
            &busbar_kernel::config::overlay::RootSettings::default(),
        )
        .is_err(),
        "publishing a new carrier never clears the old generation's quarantine"
    );
    let _ = std::fs::remove_dir_all(dir);
}
