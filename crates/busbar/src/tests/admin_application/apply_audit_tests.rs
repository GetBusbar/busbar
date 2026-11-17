// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SECRET-SHORTHAND-BOOT MR-A: a refused config apply is audited (F2), and a transaction that ends
//! without publishing leaves the live dropped-in secret set as it found it (F1).

use std::collections::HashSet;
use std::sync::Arc;

use busbar_core_admin::v1::contract::AdminError;
use busbar_kernel::audit_ring;
use busbar_kernel::config::transaction::config_transaction;

/// RA6 (F2): `POST config/apply` whose body the parse refuses is a refused apply like any other:
/// the audit records it as rejected.
#[tokio::test]
async fn admin_apply_parse_refusal_is_audited() {
    const CHILD: &str = "BUSBAR_SSB_APPLY_AUDIT_CHILD";
    const WITNESS: &str = "actual root case admin_apply_parse_refusal_is_audited completed";
    isolated!(CHILD, WITNESS);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) =
        crate::distribution::rig::actual_store("admin_apply_parse_refusal_is_audited-store");
    let signing_key = directory.join("signing-key");
    let operator_token = directory.join("operator-token");
    std::fs::write(&signing_key, hex::encode([9u8; 32])).expect("write the test signing input");
    std::fs::write(&operator_token, "admintok").expect("write the test operator input");
    let operator = busbar_kernel::config::operator_provider();
    let plugin_document = crate::root::test_plugins::config_document(
        &crate::root::test_plugins::trusted_config(&directory),
    );
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "plugins": plugin_document,
        "advanced": {  },
        "identity-providers": {},
    });
    document["identity-providers"][operator] = serde_json::json!({
        "module": operator, "token": { "file": operator_token },
    });
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        document,
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let crate::root::min3_boot::fixture::Fixture {
        backend: anchor,
        rules,
    } = crate::root::min3_boot::fixture::open(&config, &plugin_config, rules.clone())
        .await
        .expect("the actual Store opens the configuration authority");
    let anchor = crate::root::real_store::core_over(anchor).await;
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
    let router =
        busbar_kernel::build_router(crate::root::real_store::hydrated(Arc::new(app)).await);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

    let refused = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/admin/config/apply"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "config": {
                    "not_a_config_key": true,
                    "providers": {},
                    "store": {"module": module, "settings": settings},
                    "plugins": plugin_document,
                    "models": {}
                },
                "providers": {}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    let status = refused.status().as_u16();
    let body = refused.text().await.unwrap();
    assert_eq!(status, 400, "the parse refuses the body: {body}");

    let rows = busbar_kernel::audit::auditlog::AUDIT_LOG.list_filtered(
        0,
        audit_ring::MAX_AUDIT_ENTRIES,
        Some("config.apply"),
        None,
    );
    assert!(
        rows.iter()
            .any(|e| e.resource == "config:body" && e.outcome == audit_ring::OUTCOME_REJECTED),
        "a parse-refused apply is audited as rejected: {rows:?}"
    );
    handle.abort();
    println!("{WITNESS}");
}

/// ADMIN-API-1.6-ONE-MODEL §7.1 (#312): every new admin-chain row is sealed under hash scheme 4,
/// which adds the sealed `at_ms` (the same instant as `ts`) and `unconditional` (admitted on
/// `If-Match: *`).
#[tokio::test]
async fn admin_rows_seal_under_scheme4() {
    use busbar_contract::json::JsonValueTrait as _;
    const CHILD: &str = "BUSBAR_ADMIN_SCHEME4_CHILD_5A1C";
    const WITNESS: &str = "actual root case admin_rows_seal_under_scheme4 completed";
    isolated!(CHILD, WITNESS);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) =
        crate::distribution::rig::actual_store("admin_rows_seal_under_scheme4-store");
    let signing_key = directory.join("signing-key");
    let operator_token = directory.join("operator-token");
    std::fs::write(&signing_key, hex::encode([9u8; 32])).expect("write the test signing input");
    std::fs::write(&operator_token, "admintok").expect("write the test operator input");
    let operator = busbar_kernel::config::operator_provider();
    let plugin_document = crate::root::test_plugins::config_document(
        &crate::root::test_plugins::trusted_config(&directory),
    );
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "plugins": plugin_document,
        "advanced": {  },
        "identity-providers": {},
    });
    document["identity-providers"][operator] = serde_json::json!({
        "module": operator, "token": { "file": operator_token },
    });
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        document,
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let crate::root::min3_boot::fixture::Fixture {
        backend: anchor,
        rules,
    } = crate::root::min3_boot::fixture::open(&config, &plugin_config, rules.clone())
        .await
        .expect("the actual Store opens the configuration authority");
    let anchor = crate::root::real_store::core_over(anchor).await;
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
    let router =
        busbar_kernel::build_router(crate::root::real_store::hydrated(Arc::new(app)).await);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

    let refused = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/admin/config/apply"))
        .header("x-admin-token", "admintok")
        .header("if-match", "*")
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "config": {
                    "not_a_config_key": true,
                    "providers": {},
                    "store": {"module": module, "settings": settings},
                    "plugins": plugin_document,
                    "models": {}
                },
                "providers": {}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    let status = refused.status().as_u16();
    let body = refused.text().await.unwrap();
    assert_eq!(status, 400, "the parse refuses the body: {body}");

    let rows = busbar_kernel::audit::auditlog::AUDIT_LOG.list_filtered(
        0,
        audit_ring::MAX_AUDIT_ENTRIES,
        Some("config.apply"),
        None,
    );
    let row = rows
        .iter()
        .find(|e| e.resource == "config:body" && e.outcome == audit_ring::OUTCOME_REJECTED)
        .expect("the refused apply is audited");
    assert_eq!(
        row.scheme, 4,
        "a new admin row is sealed under scheme 4: {row:?}"
    );
    let served = busbar_contract::json::to_value(row).expect("the row serializes");
    let at_ms = served["at_ms"]
        .as_u64()
        .expect("a scheme-4 row serves at_ms");
    assert_eq!(
        at_ms / 1000,
        row.ts,
        "at_ms is the sealed instant ts names, in milliseconds"
    );
    assert_eq!(
        served["unconditional"].as_bool(),
        Some(true),
        "a request admitted on If-Match: * is sealed as unconditional: {served:?}"
    );
    handle.abort();
    println!("{WITNESS}");
}
