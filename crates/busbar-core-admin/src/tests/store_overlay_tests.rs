// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use axum::extract::State;
use axum::http::HeaderMap;
use busbar_kernel::auth::AuthPrincipal;
use busbar_kernel::state::AppHandle;

/// Full-config apply cannot silently erase security hooks or groups when Store recovery fails.
/// Exercise transport failure, corrupt JSON and a newer document through the actual handler.
#[tokio::test]
async fn apply_refuses_unrecoverable_store_overlay_before_replacing_security_state() {
    for failure in ["read", "corrupt", "newer"] {
        let overlay = TestOverlayStore::new();
        let hook: busbar_kernel::config::HookCfg = serde_json::from_value(serde_json::json!({
            "kind": "gate", "module": "test-hook", "global": true
        }))
        .unwrap();
        let app = crate::new_test_app()
            .overlay_backend(overlay.backend())
            .hook("security_gate", hook)
            .group("security_team", Default::default())
            .build();
        let handle = Arc::new(AppHandle::new(app));
        let before = handle.load();
        match failure {
            "read" => overlay.fail_reads(true),
            "corrupt" => overlay.seed_bytes(b"{ not json"),
            "newer" => overlay.seed_bytes(
                serde_json::json!({
                    "version": busbar_kernel::config::overlay::OVERLAY_VERSION + 1
                })
                .to_string()
                .as_bytes(),
            ),
            _ => unreachable!(),
        }
        let response = crate::v1::json::apply_config(
            State(handle.clone()),
            axum::Extension(AuthPrincipal(None)),
            HeaderMap::new(),
            serde_json::json!({
                "config": {"providers": {}, "models": {}, "store": {"module": migrated_store_module()}}
            })
            .to_string()
            .into(),
        )
        .await;
        assert_eq!(response.status().as_u16(), 400, "{failure}");
        let after = handle.load();
        assert!(Arc::ptr_eq(&after, &before), "{failure} must not swap");
        assert!(after.hook_registry.contains_key("security_gate"));
        assert!(after.groups_registry.contains_key("security_team"));
        assert_eq!(after.config_version, before.config_version);
    }
}

/// Every semantic rebuild receives the live Store anchor; a failed read must refuse before
/// resolving a base-only candidate that would drop persisted hooks/groups.
#[tokio::test]
async fn reload_refuses_a_store_read_failure_and_preserves_the_running_generation() {
    let (dir, config_path, providers_path) = write_reset_fixture("store-reload-failure");
    let overlay = TestOverlayStore::new();
    let mut app = crate::new_test_app()
        .overlay_backend(overlay.backend())
        .group("persisted_team", Default::default())
        .build();
    {
        let inner = Arc::get_mut(&mut app).unwrap();
        inner.config_path = Some(config_path);
        inner.providers_path = Some(providers_path);
    }
    let handle = Arc::new(AppHandle::new(app));
    let before = handle.load();
    overlay.fail_reads(true);
    let response =
        crate::v1::json::reload_config(State(handle.clone()), axum::Extension(AuthPrincipal(None)))
            .await;
    assert_eq!(response.status().as_u16(), 400);
    assert!(Arc::ptr_eq(&handle.load(), &before));
    assert!(handle.load().groups_registry.contains_key("persisted_team"));
    let _ = std::fs::remove_dir_all(dir);
}

/// Drive the actual group caller through Store refusal and an applied write with a lost reply.
/// Both refuse the request without changing the live generation or exposing the candidate group.
#[tokio::test]
async fn group_creation_refuses_store_failure_and_unknown_commit() {
    for unknown in [false, true] {
        let overlay = TestOverlayStore::new();
        let app = crate::new_test_app()
            .overlay_backend(overlay.backend())
            .build();
        let handle = Arc::new(AppHandle::new(app));
        let before = handle.load();
        if unknown {
            overlay.lose_next_commit_reply();
        } else {
            overlay.fail_writes(true);
        }
        let response = crate::v1::json::register_group(
            State(handle.clone()),
            axum::Extension(AuthPrincipal(None)),
            HeaderMap::new(),
            serde_json::json!({"name": "candidate_team", "config": {}})
                .to_string()
                .into(),
        )
        .await;
        assert_eq!(response.status().as_u16(), 400, "unknown={unknown}");
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let body = std::str::from_utf8(&body).unwrap();
        assert!(body.contains("not confirmed"), "{body}");
        assert!(!body.contains("nothing was changed"), "{body}");
        let after = handle.load();
        assert!(Arc::ptr_eq(&after, &before));
        assert!(!after.groups_registry.contains_key("candidate_team"));
        let durable = overlay.backend().read_required().unwrap();
        assert_eq!(
            durable.is_some_and(|doc| doc.groups.contains_key("candidate_team")),
            unknown,
            "only the unknown-outcome case applied the Store write"
        );
    }
}

/// The full Store document can exceed one record: a settings update preserves a large sibling
/// section, and a fresh Store-aware load recovers it without a file overlay or manual merge.
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

/// An unconfirmed settings commit belongs to the published carrier. Mutation rebuilds cannot
/// bypass its quarantine, and a failed reload cannot publish the loader's writable candidate.
/// Only a successful explicit reload publishes recovered state and enables a subsequent write.
#[tokio::test]
async fn unknown_settings_receipt_requires_successful_reload_before_new_mutation() {
    let _audit_guard = OVERLAY_ROOT_AUDIT.lock().await;
    let _limits_lock = busbar_kernel::config::limits::LIMITS_TEST_LOCK.lock().await;
    busbar_kernel::snapshot::init();
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
    // This rebuild reconciles the exact prior receipt and gets a fresh carrier. Its own write
    // must still use the original carrier, which now requires explicit reload publication.
    assert_eq!(put(29).await.status().as_u16(), 400);
    assert!(Arc::ptr_eq(&handle.load(), &before));
    let candidates = overlay.candidates();
    assert_eq!(candidates.len(), 2);
    assert_eq!(candidates[0].op_id, candidates[1].op_id);
    assert_eq!(candidates[0].fingerprint(), candidates[1].fingerprint());

    // Typed operator input that fails semantic group validation AFTER Store recovery.
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
