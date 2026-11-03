// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::hook_health_projection;

#[tokio::test]
async fn test_admin_v1_hook_health_best_effort() {
    let mk = |plugin: &str| busbar_kernel::config::HookCfg {
        kind: busbar_kernel::config::HookKind::Gate,
        plugin: plugin.to_string(),
        timeout_ms: 5,
        on_error: "weighted".to_string(),
        prompt: busbar_kernel::config::PromptAccess::No,
        user: busbar_kernel::config::UserAccess::No,
        priority: 0,
        settings: serde_json::Map::new(),
        at: None,
        on_empty: None,
        global: false,
        default: false,
        signals: Vec::new(),
        groups: Vec::new(),
        phase: Vec::new(),
    };
    let missing = hook_health_projection("nope", None, &[], None, None).unwrap_err();
    let missing = crate::v1::json::err_json(&missing);
    assert_eq!(missing.status().as_u16(), 404);
    let bytes = axum::body::to_bytes(missing.into_body(), 4096)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["error"]["code"], "not_found");

    let web = mk("web-hook-plugin");
    let web =
        serde_json::to_value(hook_health_projection("web", Some(&web), &[], None, None).unwrap())
            .unwrap();
    assert_eq!(web["name"], "web");
    assert_eq!(web["transport"]["kind"], "plugin");
    assert_eq!(
        web["reachable"],
        serde_json::json!(false),
        "uninstalled plugin is unreachable"
    );

    let sock = mk("sock-hook-plugin");
    let sock =
        serde_json::to_value(hook_health_projection("sock", Some(&sock), &[], None, None).unwrap())
            .unwrap();
    assert_eq!(sock["transport"]["kind"], "plugin");
    assert_eq!(
        sock["reachable"],
        serde_json::json!(false),
        "uninstalled plugin is unreachable"
    );
}
