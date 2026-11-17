// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::json;
use std::collections::HashSet;
use std::sync::Arc;

use crate::test_common as common;

const AUDIENCE: &str = "api://admin-namedmap-readonly";

#[tokio::test]
async fn test_admin_v1_named_map_rejects_an_under_scoped_caller() {
    const CHILD: &str = "BUSBAR_ADMIN_BOOT_0DF96A015ED4";
    const WITNESS: &str =
        "actual root case test_admin_v1_named_map_rejects_an_under_scoped_caller completed";
    isolated!(CHILD, WITNESS);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store(
        "test_admin_v1_named_map_rejects_an_under_scoped_caller-actual-store",
    );
    assert!(
        settings.is_object(),
        "the actual Store settings are an object"
    );
    let oidc_path = common::plugins::token_verifier_cdylib_path()
        .expect("the freshly built actual OIDC product is required");
    let oidc_statement = busbar_plugin_loader::dispatch::rendering_of_library(&oidc_path)
        .expect("the actual OIDC statement reads")
        .expect("the actual OIDC exports its statement");
    let oidc_module = busbar_contract::abi::mechanism::rendering::read(&oidc_statement)
        .expect("the actual OIDC statement is valid")
        .name;
    common::credentials::install_auth_plugin(&directory, &oidc_module, "test-scope-module", true);
    let viewer_token = common::credentials::token_for("viewers", &["viewers"], AUDIENCE);
    let signing_key = directory.join("signing-key");
    let operator_token = directory.join("operator-token");
    std::fs::write(&signing_key, hex::encode([9u8; 32])).expect("write the test signing input");
    std::fs::write(&operator_token, "admintok").expect("write the test operator input");
    let operator = busbar_kernel::config::operator_provider();
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "advanced": {  },
        "identity-providers": {},
    });
    document["identity-providers"][operator] = serde_json::json!({
        "module": operator, "token": { "file": operator_token },
    });
    document["identity-providers"]["test-scope-module"] = serde_json::json!({
        "module": oidc_module,
        "settings": common::credentials::settings(AUDIENCE),
        "max_admin_scope": "read-only",
    });
    document["auth"]["admin_auth"] = serde_json::json!(["test-scope-module", operator]);
    document["auth"]["role_bindings"] = serde_json::json!({
        "test-scope-module": { "viewers": { "admin_scope": "read-only" } },
    });
    document["export"] = serde_json::json!({
        "base-metrics": {"module":"prometheus","settings":{"buffer_seconds":60}},
    });
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        document,
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let crate::root::min3_boot::fixture::Admitted {
        core: anchor,
        rules,
    } = crate::root::test_plugins::bootstrap_fresh_application_store(
        &config,
        &plugin_config,
        &directory,
    )
    .await
    .expect("the actual Store opens the configuration authority");
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(anchor.clone())
        .expect("the actual Store supports conditional configuration records");
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        Some(overlay),
        HashSet::new(),
        HashSet::new(),
        (None, None),
        None,
        &rules,
        Some(anchor),
        true,
    )
    .await
    .expect("the real root composes the configured Store and admin application");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .await
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().await.expect("the actual limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    assert_eq!(
        app.export_defs["base-metrics"].module, "prometheus",
        "the actual deployment owns its existing export definition"
    );
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let viewer = |r: reqwest::RequestBuilder| {
        r.header("x-admin-token", &viewer_token)
            .header("content-type", "application/json")
    };

    for section in ["identity-providers", "export"] {
        let r = viewer(client.get(format!("http://{addr}/api/v1/admin/{section}")))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 200, "read-only CAN read /{section}");

        for (label, req) in [
            (
                "put",
                viewer(client.put(format!("http://{addr}/api/v1/admin/{section}/x")))
                    .body(r#"{"module":"keys"}"#),
            ),
            (
                "patch-settings",
                viewer(client.patch(format!(
                    "http://{addr}/api/v1/admin/{section}/base-metrics/settings"
                )))
                .body(r#"{"settings":{}}"#),
            ),
            (
                "delete",
                viewer(client.delete(format!("http://{addr}/api/v1/admin/{section}/base-metrics"))),
            ),
        ] {
            let r = req.send().await.unwrap();
            assert_eq!(
                r.status().as_u16(),
                403,
                "read-only cannot {label} /{section}"
            );
            let body = json::parse_value(&r.bytes().await.unwrap()).unwrap();
            assert_eq!(body["error"]["code"], "forbidden", "{label} /{section}");
        }
    }
    handle.abort();
    println!("{WITNESS}");
}
