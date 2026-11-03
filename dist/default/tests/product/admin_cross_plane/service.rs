// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_core_admin::v1::service::{build_with_hook, build_without_hook};
use busbar_kernel::config::{HookCfg, HookKind, PromptAccess, UserAccess};

fn hook(module: &str, kind: HookKind, global: bool) -> HookCfg {
    HookCfg {
        kind,
        plugin: module.to_string(),
        timeout_ms: 5,
        on_error: "weighted".to_string(),
        prompt: PromptAccess::No,
        user: UserAccess::No,
        priority: 0,
        settings: serde_json::from_value(serde_json::json!({"url":"http://127.0.0.1:1/hook"}))
            .unwrap(),
        at: None,
        on_empty: None,
        global,
        default: false,
        signals: Vec::new(),
        groups: Vec::new(),
        phase: Vec::new(),
    }
}

#[test]
fn build_with_hook_makes_a_plane_attach_live() {
    let tools = {
        crate::distribution::admin_cross_plane::ensure_seam();
        busbar_kernel::plane_driver::registry::plane_decl_for_config_section("tools")
            .expect("the product tools plane is registered")
    };
    let (app, hook_module) = {
        crate::distribution::admin_cross_plane::ensure_seam();
        let directory = super::plugins::scratch(&format!(
            "admin-root-{}",
            busbar_kernel::door::op_id().counter()
        ));
        let library_path = std::path::PathBuf::from(
            std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
                .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual Store product"),
        );
        let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
            .expect("the actual Store statement reads")
            .expect("the actual Store states itself");
        let facts = busbar_contract::abi::mechanism::rendering::read(&statement)
            .expect("the actual Store statement parses");
        let mut manifest =
            super::plugins::manifest("store", &facts.name, super::plugins::FIXTURE_PUBLISHER);
        manifest.version = facts.version;
        manifest.statement = Some(hex::encode(statement));
        let archive = super::plugins::signed(
            &crate::dist_root_install::release_key(),
            manifest,
            &std::fs::read(library_path).expect("the actual Store artifact reads"),
        );
        std::fs::write(directory.join("store.tar.gz"), archive)
            .expect("stage the actual Store product");
        let hook_path = std::path::PathBuf::from(
            std::env::var_os("BUSBAR_TEST_WEBREQUEST_CDYLIB")
                .expect("the actual built webrequest hook is required"),
        );
        let hook_statement = busbar_plugin_loader::dispatch::rendering_of_library(&hook_path)
            .expect("the actual hook statement reads")
            .expect("the actual hook states its door");
        let hook_module = busbar_contract::abi::mechanism::rendering::read(&hook_statement)
            .expect("the actual hook statement parses")
            .name;
        let mut hook_manifest =
            super::plugins::manifest("hook", &hook_module, super::plugins::FIXTURE_PUBLISHER);
        hook_manifest.statement = Some(hex::encode(hook_statement));
        let hook_archive = super::plugins::signed(
            &crate::dist_root_install::release_key(),
            hook_manifest,
            &std::fs::read(hook_path).expect("the actual hook artifact reads"),
        );
        std::fs::write(directory.join("hook.tar.gz"), hook_archive)
            .expect("stage the actual signed hook product");
        std::fs::write(directory.join("admin.token"), "admintok")
            .expect("write the operator credential");
        let settings: serde_json::Value = serde_json::from_str(
            &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
        )
        .expect("the actual Store settings are JSON");
        let mut document = serde_json::json!({"tools": {"fs": {"url":"https://tools.internal/fs","pin":{"mechanism":"cert_spki","key":"sha256/BASE="},"hooks":["screen"]}}});
        // A parsed deployment must define every attached hook. Exercise a missing live
        // definition through the real delete API after this valid deployment has booted.
        document["hooks"] =
            serde_json::json!({"screen": hook(&hook_module, HookKind::Gate, false)});
        document["providers"] = serde_json::json!({});
        document["models"] = serde_json::json!({});
        document["store"] = serde_json::json!({"module": facts.name, "settings": settings});
        document["auth"] = serde_json::json!({"chain": [], "admin_auth": ["admin-tokens"]});
        document["identity-providers"] = serde_json::json!({"admin-tokens": {
            "module": "admin-tokens", "token": {"file": directory.join("admin.token")}
        }});
        document["advanced"] = serde_json::json!({"allow_destinations": ["127.0.0.1"]});
        let deploy = busbar_kernel::config::deploy_from_deserializer(document)
            .expect("the actual admin deployment parses");
        let cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the actual admin deployment resolves");
        let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
            as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
        let (app, rotate, limits) = busbar_kernel::build_app_from_config(
            cfg,
            super::plugins::trusted_config(&directory),
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
        )
        .expect("the product root builds the actual admin application");
        limits.keep().expect("the product limits commit");
        if let Some(rotate) = rotate {
            rotate();
        }

        (std::sync::Arc::new(app), hook_module)
    };
    assert_eq!(
        app.plane_gates(tools.key)
            .and_then(|g| g.get("fs"))
            .map(Vec::len),
        Some(1),
        "the valid initial deployment resolves its attached hook"
    );
    let app = build_without_hook(&app, "screen").expect("the live definition is removed");
    assert!(
        !app.plane_gates(tools.key)
            .is_some_and(|g| g.contains_key("fs")),
        "the attach remains after its live definition is removed, so it resolves to nothing"
    );

    let next = build_with_hook(&app, "screen", hook(&hook_module, HookKind::Gate, false))
        .expect("a valid gate registers");
    assert_eq!(
        next.plane_gates(tools.key)
            .and_then(|g| g.get("fs"))
            .map(|g| g.len())
            .unwrap_or_default(),
        1,
        "registering the DEFINITION must make the server's existing attach resolve — a 200 OK that \
         leaves the chain empty is an operator told a control is attached when it is not"
    );
}
