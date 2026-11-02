// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::contract::Page;
use super::named_def_views::{export_def_view, identity_provider_view};
use super::service::project_hook_view;

#[test]
fn test_admin_v1_named_map_reads_project_settings_keys_never_values() {
    let idp: busbar_kernel::config::IdentityProviderCfg =
        serde_json::from_value(serde_json::json!({
            "module": "acme-idp",
            "settings": {"issuer": "https://idp.example.com", "client_secret": "hunter2-idp"}
        }))
        .unwrap();
    let export: busbar_kernel::config::ExportDefCfg = serde_json::from_value(serde_json::json!({
        "module": "generic-webhook",
        "settings": {"url": "https://siem.example.com/in", "auth_header": {"name": "authorization", "value": "Bearer hunter2-siem"}}
    })).unwrap();
    for (section, name, secret, keys) in [
        (
            "identity-providers",
            "corp-oidc",
            "hunter2-idp",
            ["client_secret", "issuer"],
        ),
        ("export", "siem", "hunter2-siem", ["auth_header", "url"]),
    ] {
        for (listed, url) in [
            (true, format!("/api/v1/admin/{section}")),
            (false, format!("/api/v1/admin/{section}/{name}")),
        ] {
            let view = match section {
                "identity-providers" => identity_provider_view(name, &idp),
                "export" => export_def_view(name, &export),
                _ => unreachable!("the two original typed input sections"),
            };
            let body = if listed {
                serde_json::to_string(&Page::single(vec![view])).unwrap()
            } else {
                serde_json::to_string(&view).unwrap()
            };
            assert!(
                !body.contains(secret),
                "{url} projected a settings VALUE — this read is reachable at READ-ONLY admin \
                 scope, so an operator credential just leaked: {body}"
            );
            let json: serde_json::Value = serde_json::from_str(&body).unwrap();
            let def = json
                .get("items")
                .and_then(|i| i.get(0))
                .cloned()
                .unwrap_or(json);
            assert_eq!(
                def["settings_keys"],
                serde_json::json!(keys),
                "{url} must project the settings KEY NAMES (sorted), so `what is configured` \
                 introspection survives the redaction"
            );
            assert!(
                def.get("settings").is_none(),
                "the raw settings bag must not be projected at all: {def}"
            );
        }
    }
}

#[test]
fn test_admin_v1_hook_reads_project_settings_keys_never_values() {
    let mut cfg: busbar_kernel::config::HookCfg = serde_json::from_value(serde_json::json!({
        "kind": "gate",
        "module": "test-hook",
        "timeout_ms": 5,
        "on_error": "weighted"
    }))
    .unwrap();
    cfg.settings = serde_json::json!({
        "endpoint": "https://gate.example.com",
        "api_token": "hunter2-hook"
    })
    .as_object()
    .unwrap()
    .clone();
    for (listed, url) in [
        (true, "/api/v1/admin/hooks"),
        (false, "/api/v1/admin/hooks/baa-gate"),
    ] {
        let view = project_hook_view("baa-gate", &cfg, &[]);
        let body = if listed {
            serde_json::to_string(&Page::single(vec![view])).unwrap()
        } else {
            serde_json::to_string(&view).unwrap()
        };
        assert!(
            !body.contains("hunter2-hook"),
            "{url} projected a hook settings VALUE at READ-ONLY admin scope: {body}"
        );
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        let view = json
            .get("items")
            .and_then(|i| i.get(0))
            .cloned()
            .unwrap_or(json);
        assert_eq!(
            view["settings_keys"],
            serde_json::json!(["api_token", "endpoint"]),
            "the hook read must project the settings KEY NAMES, sorted"
        );
        assert!(
            view.get("settings").is_none(),
            "the raw hook settings bag must not be projected at all: {view}"
        );
    }
}
