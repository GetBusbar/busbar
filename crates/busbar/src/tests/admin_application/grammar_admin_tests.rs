// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SECRET-SHORTHAND-BOOT MR-B3 (§3.12): a reload-class operation runs the authority pre-check over
//! the whole security digest and `plugins.fetch` before any fetch or scan of `plugins.dir`, and
//! admin validate answers `needs full operator` exactly where apply answers forbidden.
//!
//! The deployment admits two delegated callers through the actual OIDC verifier: `editors` may
//! call `post_config_apply` (a named verb, never full-operator authority) and `viewers` hold the
//! read-only rung (which admits the stateless `config/validate`).

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use busbar_contract::json;

use crate::test_common as common;

const AUDIENCE: &str = "api://admin-grammar-precheck";

/// A served actual deployment with the two delegated callers. Answers its address, the editor's and
/// the viewer's tokens, the configuration it serves (the body a caller starts from) and its
/// directory.
struct Served {
    addr: std::net::SocketAddr,
    server: tokio::task::JoinHandle<()>,
    editor: String,
    viewer: String,
    document: json::Value,
    directory: std::path::PathBuf,
}

async fn served(tag: &str) -> Served {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store(tag);
    let oidc_path = common::plugins::token_verifier_cdylib_path()
        .expect("the freshly built actual OIDC product is required");
    let oidc_statement = busbar_plugin_loader::dispatch::rendering_of_library(&oidc_path)
        .expect("the actual OIDC statement reads")
        .expect("the actual OIDC exports its statement");
    let oidc_module = busbar_contract::abi::mechanism::rendering::read(&oidc_statement)
        .expect("the actual OIDC statement is valid")
        .name;
    common::credentials::install_auth_plugin(&directory, &oidc_module, "test-scope-module", true);
    let editor = common::credentials::token_for("editors", &["editors"], AUDIENCE);
    let viewer = common::credentials::token_for("viewers", &["viewers"], AUDIENCE);
    let signing_key = directory.join("signing-key");
    let operator_token = directory.join("operator-token");
    std::fs::write(&signing_key, hex::encode([9u8; 32])).expect("write the test signing input");
    std::fs::write(&operator_token, "admintok").expect("write the test operator input");
    let operator = busbar_kernel::config::operator_provider();
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let mut document = json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "plugins": crate::root::test_plugins::config_document(&plugin_config),
        "advanced": {  },
        "identity-providers": {},
    });
    document["identity-providers"][operator] = json::json!({
        "module": operator, "settings": { "sha256": crate::root::test_plugins::operator_sha256_of(&operator_token) },
    });
    document["identity-providers"]["test-scope-module"] = json::json!({
        "module": oidc_module,
        "settings": common::credentials::settings(AUDIENCE),
        "max_admin_scope": "full",
    });
    document["auth"]["admin_auth"] = json::json!(["test-scope-module", operator]);
    document["auth"]["role_bindings"] = json::json!({
        "test-scope-module": {
            "editors": { "verbs": ["post_config_apply"] },
            "viewers": { "admin_scope": "read-only" },
        },
    });
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        &document,
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
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
        crate::root::test_plugins::plaintext_listeners(config),
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
    let router =
        busbar_kernel::build_router(crate::root::real_store::hydrated(Arc::new(app)).await);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    Served {
        addr,
        server,
        editor,
        viewer,
        document,
        directory,
    }
}

/// A local endpoint a `plugins.fetch` entry names, counting every connection made to it: a fetch
/// the pre-check refused never connects.
async fn fetch_double() -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&connections);
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            counted.fetch_add(1, Ordering::SeqCst);
            drop(stream);
        }
    });
    (
        format!("http://{addr}/fixture-plugin.tar.gz"),
        connections,
        task,
    )
}

async fn post(served: &Served, path: &str, token: &str, body: &json::Value) -> (u16, json::Value) {
    let response = reqwest::Client::new()
        .post(format!("http://{}/api/v1/admin/{path}", served.addr))
        .header("authorization", format!("Bearer {}", token))
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    let bytes = response.bytes().await.unwrap_or_default();
    (
        status,
        json::parse_value(&bytes).unwrap_or_else(|_| json::Value::new()),
    )
}

/// R12 (§3.12, F10): a caller without full-operator authority whose apply adds a `plugins.fetch`
/// entry is refused before anything is downloaded.
#[tokio::test]
async fn nonoperator_apply_adding_plugins_fetch_is_forbidden_before_fetch() {
    const CHILD: &str = "BUSBAR_SSB_B3_R12_CHILD";
    const WITNESS: &str =
        "actual root case nonoperator_apply_adding_plugins_fetch_is_forbidden_before_fetch completed";
    isolated!(CHILD, WITNESS);
    let served = served("ssb-b3-r12-store").await;
    let (url, connections, double) = fetch_double().await;
    let mut config = served.document.clone();
    config["plugins"]["fetch"] = json::json!([{ "url": url, "sha256": "0".repeat(64) }]);
    let (status, body) = post(
        &served,
        "config/apply",
        &served.editor,
        &json::json!({ "config": config, "providers": {} }),
    )
    .await;
    assert_eq!(status, 403, "the apply is forbidden: {body}");
    assert_eq!(body["error"]["code"], "forbidden", "{body}");
    assert_eq!(
        connections.load(Ordering::SeqCst),
        0,
        "nothing was fetched for a forbidden apply"
    );
    double.abort();
    served.server.abort();
    println!("{WITNESS}");
}

/// G9 (§3.12): an apply that points `plugins.dir` elsewhere, by a caller without full-operator
/// authority, is forbidden before that directory is fetched into or scanned.
#[tokio::test]
async fn nonoperator_apply_changing_plugins_dir_is_forbidden_before_scan() {
    const CHILD: &str = "BUSBAR_SSB_B3_G9_CHILD";
    const WITNESS: &str =
        "actual root case nonoperator_apply_changing_plugins_dir_is_forbidden_before_scan completed";
    isolated!(CHILD, WITNESS);
    let served = served("ssb-b3-g9-store").await;
    let (url, connections, double) = fetch_double().await;
    let elsewhere = served.directory.join("must-not-be-scanned");
    let mut config = served.document.clone();
    config["plugins"]["dir"] = json::json!(elsewhere);
    config["plugins"]["fetch"] = json::json!([{ "url": url, "sha256": "0".repeat(64) }]);
    let (status, body) = post(
        &served,
        "config/apply",
        &served.editor,
        &json::json!({ "config": config, "providers": {} }),
    )
    .await;
    assert_eq!(status, 403, "the apply is forbidden: {body}");
    assert!(
        !elsewhere.exists(),
        "the forbidden apply's directory was never created, fetched into or scanned"
    );
    assert_eq!(connections.load(Ordering::SeqCst), 0);
    double.abort();
    served.server.abort();
    println!("{WITNESS}");
}

/// R13 (§3.12, audit F): admin validate runs apply's pre-check with the caller's authority. Where
/// apply answers forbidden, validate answers `needs full operator` with the field class, and
/// scans nothing.
#[tokio::test]
async fn admin_validate_answers_needs_full_operator_where_apply_forbids() {
    const CHILD: &str = "BUSBAR_SSB_B3_R13_CHILD";
    const WITNESS: &str = "actual root case \
         admin_validate_answers_needs_full_operator_where_apply_forbids completed";
    isolated!(CHILD, WITNESS);
    let served = served("ssb-b3-r13-store").await;
    let (url, connections, double) = fetch_double().await;
    let mut config = served.document.clone();
    config["plugins"]["fetch"] = json::json!([{ "url": url, "sha256": "0".repeat(64) }]);
    let request = json::json!({ "config": config, "providers": {} });

    let (status, view) = post(&served, "config/validate", &served.viewer, &request).await;
    assert_eq!(status, 200, "validate answers a verdict: {view}");
    assert_eq!(view["ok"], false, "{view}");
    let errors = view["errors"].to_string();
    assert!(
        errors.contains("needs full operator") && errors.contains("plugins.fetch"),
        "validate names the cause class and the field class: {view}"
    );
    assert!(
        !errors.contains(".tar.gz") && !errors.contains("allow_untrusted"),
        "the answer carries no file name and no trust setting: {view}"
    );

    let (status, body) = post(&served, "config/apply", &served.editor, &request).await;
    assert_eq!(status, 403, "apply forbids the same body: {body}");
    assert_eq!(connections.load(Ordering::SeqCst), 0);
    double.abort();
    served.server.abort();
    println!("{WITNESS}");
}
