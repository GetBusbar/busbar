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
                def["module"],
                match section {
                    "identity-providers" => "acme-idp",
                    "export" => "generic-webhook",
                    _ => unreachable!(),
                },
                "{url} must identify the backing module"
            );
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
    .clone()
    .into();
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

#[test]
fn unparseable_named_definitions_project_only_an_actual_module() {
    for (raw, module) in [
        (
            serde_json::json!({"url": "https://agent.example.com"}),
            None,
        ),
        (serde_json::json!({"module": null}), None),
        (serde_json::json!({"module": 7}), None),
        (
            serde_json::json!({"module": "acme-export"}),
            Some("acme-export"),
        ),
    ] {
        let entry = busbar_kernel::config::overlay::UnparseableNamedDef {
            raw,
            error: "invalid stored definition".to_string(),
        };
        let view = super::named_def_views::unparseable_def_view("pending", &entry);
        assert_eq!(view.module.as_deref(), module);
        let body = serde_json::to_value(view).unwrap();
        assert_eq!(
            body.get("module").and_then(serde_json::Value::as_str),
            module
        );
        assert_eq!(body.get("module").is_some(), module.is_some());
        assert_eq!(body["unparseable"], "invalid stored definition");
    }
}

#[cfg(feature = "openapi-schema")]
#[test]
fn named_definition_module_schema_matches_omitted_or_string_output() {
    let doc = super::json::openapi_doc();
    for name in ["NamedDefView", "MutatedDefView"] {
        let schema = &doc["components"]["schemas"][name];
        assert_eq!(schema["properties"]["module"]["type"], "string", "{name}");
        assert!(
            !schema["required"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("module")),
            "{name}"
        );
    }
}
