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
