// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SECRET-SHORTHAND-BOOT MR-A: a refused config apply is audited (F2), and a transaction that ends
//! without publishing leaves the live dropped-in secret set as it found it (F1).

use std::collections::HashSet;
use std::sync::Arc;

use busbar_contract::json;
use busbar_kernel::audit_ring;

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
    let mut document = json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "plugins": plugin_document,
        "advanced": {  },
        "identity-providers": {},
    });
    document["identity-providers"][operator] = json::json!({
        "module": operator, "settings": { "sha256": crate::root::test_plugins::operator_sha256_of(&operator_token) },
    });
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        &document,
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let crate::root::min3_boot::fixture::Admitted {
        core: anchor,
        rules,
    } = crate::root::min3_boot::fixture::open(&config, &plugin_config, rules.clone())
        .await
        .expect("the actual Store opens the configuration authority")
        .admit()
        .await;
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
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

    let refused = crate::root::test_plugins::operator_client()
        .post(format!("http://{addr}/api/v1/admin/config/apply"))
        .header("authorization", "Bearer admintok")
        .header("content-type", "application/json")
        .body(
            json::json!({
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
    let mut document = json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "plugins": plugin_document,
        "advanced": {  },
        "identity-providers": {},
    });
    document["identity-providers"][operator] = json::json!({
        "module": operator, "settings": { "sha256": crate::root::test_plugins::operator_sha256_of(&operator_token) },
    });
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        &document,
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let crate::root::min3_boot::fixture::Admitted {
        core: anchor,
        rules,
    } = crate::root::min3_boot::fixture::open(&config, &plugin_config, rules.clone())
        .await
        .expect("the actual Store opens the configuration authority")
        .admit()
        .await;
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
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

    let refused = crate::root::test_plugins::operator_client()
        .post(format!("http://{addr}/api/v1/admin/config/apply"))
        .header("authorization", "Bearer admintok")
        .header("if-match", "*")
        .header("content-type", "application/json")
        .body(
            json::json!({
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

/// ADMIN-API-1.6-ONE-MODEL §7 and §7.1 (#312): the engine always mints the request id; a valid
/// client `X-Request-Id` is kept beside it as `client_request_id` and echoed as
/// `X-Client-Request-Id`; a `traceparent` puts the request on the caller's trace, answered with the
/// same trace id and the admin span's id. A scheme-4 row seals and serves `client_request_id`,
/// `trace_id` and, for a request that created an operation, its `operation_id`. An invalid client id
/// is dropped without comment.
#[tokio::test]
async fn admin_rows_seal_the_request_correlation() {
    use busbar_contract::json::JsonValueTrait as _;
    const CHILD: &str = "BUSBAR_ADMIN_CORRELATION_CHILD_7D2E";
    const WITNESS: &str = "actual root case admin_rows_seal_the_request_correlation completed";
    isolated!(CHILD, WITNESS);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) =
        crate::distribution::rig::actual_store("admin_rows_seal_the_request_correlation-store");
    let signing_key = directory.join("signing-key");
    let operator_token = directory.join("operator-token");
    std::fs::write(&signing_key, hex::encode([9u8; 32])).expect("write the test signing input");
    std::fs::write(&operator_token, "admintok").expect("write the test operator input");
    let operator = busbar_kernel::config::operator_provider();
    let plugin_document = crate::root::test_plugins::config_document(
        &crate::root::test_plugins::trusted_config(&directory),
    );
    let mut document = json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "plugins": plugin_document,
        "advanced": {  },
        "identity-providers": {},
    });
    document["identity-providers"][operator] = json::json!({
        "module": operator, "settings": { "sha256": crate::root::test_plugins::operator_sha256_of(&operator_token) },
    });
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        &document,
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let crate::root::min3_boot::fixture::Admitted {
        core: anchor,
        rules,
    } = crate::root::min3_boot::fixture::open(&config, &plugin_config, rules.clone())
        .await
        .expect("the actual Store opens the configuration authority")
        .admit()
        .await;
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
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

    const TRACE: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
    const CALLER_SPAN: &str = "00f067aa0ba902b7";
    let refused_apply = |client_id: &str, key: &str| {
        crate::root::test_plugins::operator_client()
            .post(format!("http://{addr}/api/v1/admin/config/apply"))
            .header("authorization", "Bearer admintok")
            .header("if-match", "*")
            .header("idempotency-key", key)
            .header("x-request-id", client_id)
            .header("traceparent", format!("00-{TRACE}-{CALLER_SPAN}-01"))
            .header("tracestate", "vendor=opaque")
            .header("content-type", "application/json")
            .body(
                json::json!({
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
    };
    let header = |response: &reqwest::Response, name: &str| {
        response
            .headers()
            .get(name)
            .map(|v| v.to_str().expect("a visible-ASCII header").to_owned())
    };

    let kept = refused_apply("console-req.1:a_b-c", "corr-1")
        .await
        .unwrap();
    let request_id =
        header(&kept, "x-request-id").expect("every admin answer carries X-Request-Id");
    assert!(
        request_id.starts_with("r_"),
        "the engine mints the request id; the caller never chooses it: {request_id}"
    );
    assert_eq!(
        header(&kept, "x-client-request-id").as_deref(),
        Some("console-req.1:a_b-c"),
        "a valid client X-Request-Id is echoed as X-Client-Request-Id"
    );
    let traceparent = header(&kept, "traceparent").expect("a traceparent in is answered");
    let parts: Vec<&str> = traceparent.split('-').collect();
    assert_eq!(
        parts.len(),
        4,
        "traceparent is version-trace-span-flags: {traceparent}"
    );
    assert_eq!(parts[0], "00");
    assert_eq!(parts[1], TRACE, "the answer stays on the caller's trace");
    assert_eq!(
        parts[2].len(),
        16,
        "the admin span id is 8 bytes, hex: {traceparent}"
    );
    assert!(
        parts[2]
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            && parts[2] != "0000000000000000"
            && parts[2] != CALLER_SPAN,
        "the answer names the admin span, the child of the caller's: {traceparent}"
    );
    assert_eq!(parts[3], "01", "the caller's trace flags are kept");
    let status = kept.status().as_u16();
    assert_eq!(
        status,
        400,
        "the parse refuses the body: {}",
        kept.text().await.unwrap()
    );

    let dropped = refused_apply("not valid", "corr-2").await.unwrap();
    let dropped_id =
        header(&dropped, "x-request-id").expect("every admin answer carries X-Request-Id");
    assert!(
        header(&dropped, "x-client-request-id").is_none(),
        "an invalid client X-Request-Id is dropped, not echoed"
    );
    assert_eq!(
        dropped.status().as_u16(),
        400,
        "an invalid client id is not an error itself"
    );

    let operation = crate::root::test_plugins::operator_client()
        .get(format!("http://{addr}/api/v1/admin/operations/corr-1"))
        .header("authorization", "Bearer admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(
        operation.status().as_u16(),
        200,
        "the keyed request is an operation"
    );
    let operation = busbar_contract::json::parse_value(&operation.bytes().await.unwrap()).unwrap();
    let operation_id = operation["operation_id"]
        .as_str()
        .expect("an operation names its id")
        .to_owned();

    let rows = busbar_kernel::audit::auditlog::AUDIT_LOG.list_filtered(
        0,
        audit_ring::MAX_AUDIT_ENTRIES,
        Some("config.apply"),
        None,
    );
    let row_of = |id: &str| {
        let row = rows
            .iter()
            .find(|e| e.request_id.as_deref() == Some(id))
            .unwrap_or_else(|| panic!("the refused apply {id} is audited: {rows:?}"));
        assert_eq!(
            row.scheme, 4,
            "a new admin row is sealed under scheme 4: {row:?}"
        );
        busbar_contract::json::to_value(row).expect("the row serializes")
    };
    let served = row_of(&request_id);
    assert_eq!(
        served["client_request_id"].as_str(),
        Some("console-req.1:a_b-c"),
        "the row seals the client's id beside the engine's: {served:?}"
    );
    assert_eq!(
        served["trace_id"].as_str(),
        Some(TRACE),
        "the row seals the caller's trace id: {served:?}"
    );
    assert_eq!(
        served["operation_id"].as_str(),
        Some(operation_id.as_str()),
        "the row seals the operation the request created: {served:?}"
    );
    let served = row_of(&dropped_id);
    assert!(
        served["client_request_id"].is_null(),
        "a dropped client id is not sealed: {served:?}"
    );
    assert_eq!(served["trace_id"].as_str(), Some(TRACE));
    handle.abort();
    println!("{WITNESS}");
}
