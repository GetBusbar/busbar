// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_core_admin::test_support::openapi_doc;

#[cfg(feature = "openapi-schema")]
#[test]
fn openapi_operations_carry_stable_operation_ids() {
    use std::collections::HashMap;
    let doc = openapi_doc_seamed();
    let paths = doc["paths"].as_object().expect("paths object");
    let mut seen: HashMap<String, (String, String)> = HashMap::new();
    let mut checked = 0usize;
    for (path, methods) in paths {
        for (method, op) in methods.as_object().expect("methods") {
            if !matches!(method.as_str(), "get" | "post" | "put" | "patch" | "delete") {
                continue;
            }
            let oid = op["operationId"]
                .as_str()
                .unwrap_or_else(|| panic!("{method} {path} missing operationId"));
            assert!(!oid.is_empty(), "{method} {path} has an empty operationId");
            if let Some((prev_method, prev_path)) =
                seen.insert(oid.to_string(), (method.clone(), path.clone()))
            {
                panic!("operationId {oid} collides: {prev_method} {prev_path} vs {method} {path}");
            }
            checked += 1;
        }
    }

    assert_eq!(checked, 100, "expected exactly 100 admin operations");

    assert_eq!(
        doc["paths"]["/api/v1/admin/keys"]["get"]["operationId"],
        "GetKeys"
    );
    assert_eq!(
        doc["paths"]["/api/v1/admin/keys/{id}/rotate"]["post"]["operationId"],
        "PostKeysIdRotate"
    );
    assert_eq!(
        doc["paths"]["/api/v1/admin/plugins/{file}/schema"]["get"]["operationId"],
        "GetPluginsFileSchema"
    );
    assert_eq!(
        doc["paths"]["/api/v1/admin/admin-auth"]["put"]["operationId"],
        "PutAdminAuth"
    );
}

#[cfg(feature = "openapi-schema")]
const COMMITTED_OPENAPI_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../crates/busbar-core-admin/src/v1/json/openapi.json"
);

#[cfg(feature = "openapi-schema")]
fn render_committed_openapi() -> String {
    format!(
        "{}\n",
        serde_json::to_string_pretty(&openapi_doc_seamed()).expect("serialize openapi doc")
    )
}

#[cfg(feature = "openapi-schema")]
pub(crate) fn openapi_doc_seamed() -> serde_json::Value {
    crate::ensure_seam();
    openapi_doc()
}

#[cfg(feature = "openapi-schema")]
#[test]
fn openapi_json_matches_committed_file() {
    crate::ensure_seam();
    let fresh = render_committed_openapi();
    if std::env::var("UPDATE_OPENAPI").is_ok_and(|v| v == "1") {
        std::fs::write(COMMITTED_OPENAPI_PATH, &fresh)
            .unwrap_or_else(|e| panic!("write {COMMITTED_OPENAPI_PATH}: {e}"));

        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        std::io::Write::write_all(&mut enc, fresh.as_bytes()).expect("gz write");
        let gz = enc.finish().expect("gz finish");
        std::fs::write(format!("{COMMITTED_OPENAPI_PATH}.gz"), gz)
            .unwrap_or_else(|e| panic!("write {COMMITTED_OPENAPI_PATH}.gz: {e}"));
        return;
    }
    let committed = std::fs::read_to_string(COMMITTED_OPENAPI_PATH)
        .unwrap_or_else(|e| panic!("read {COMMITTED_OPENAPI_PATH}: {e}"));
    assert_eq!(
        committed, fresh,
        "committed openapi.json is stale — regenerate with `UPDATE_OPENAPI=1 cargo test -p busbar \
         --features openapi-schema openapi_json_matches_committed_file`"
    );
}

#[cfg(feature = "openapi-schema")]
#[test]
fn openapi_rendered_component_schemas_are_the_committed_ones() {
    crate::ensure_seam();
    let committed: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(COMMITTED_OPENAPI_PATH).expect("read committed openapi"),
    )
    .expect("committed openapi parses");
    let committed = committed["components"]["schemas"]
        .as_object()
        .expect("committed component schemas");
    let actual = openapi_doc_seamed();
    let schemas = actual["components"]["schemas"]
        .as_object()
        .expect("rendered component schemas");
    assert_eq!(
        schemas.len(),
        committed.len(),
        "component schema count changed"
    );
    let mut seen = 0usize;
    for (name, schema) in schemas {
        assert_eq!(
            committed.get(name),
            Some(schema),
            "rendered component schema `{name}` differs from the committed openapi.json"
        );
        seen += 1;
    }
    assert!(
        seen > 0,
        "the rendered OpenAPI document has no component schema"
    );
}

#[cfg(feature = "openapi-schema")]
#[test]
fn openapi_every_mutating_operation_declares_a_request_body() {
    const BODYLESS: &[(&str, &str)] = &[
        ("post", "/api/v1/admin/config/reload"),
        ("post", "/api/v1/admin/plugins/reload"),
        ("post", "/api/v1/admin/signing-key/rotate"),
        ("post", "/api/v1/admin/keys/{id}/revoke"),
        ("post", "/api/v1/admin/keys/{id}/rotate"),
        ("delete", "/api/v1/admin/groups/{name}"),
        ("delete", "/api/v1/admin/hooks/{name}"),
        ("delete", "/api/v1/admin/keys/{id}"),
        ("delete", "/api/v1/admin/overlay/{section}"),
        ("delete", "/api/v1/admin/plugins/{file}"),
        ("delete", "/api/v1/admin/identity-providers/{name}"),
        ("delete", "/api/v1/admin/export/{name}"),
        ("delete", "/api/v1/admin/tools/{name}"),
        ("delete", "/api/v1/admin/agents/{name}"),
        ("post", "/api/v1/admin/tools/{name}/connect"),
        ("post", "/api/v1/admin/agents/{name}/connect"),
        ("post", "/api/v1/admin/chain-break"),
    ];

    let doc = openapi_doc_seamed();
    let schemas = doc["components"]["schemas"].as_object().expect("schemas");
    let paths = doc["paths"].as_object().expect("paths");
    let mut declared = 0usize;
    let mut bodyless_seen = Vec::new();

    for (path, methods) in paths {
        for (method, op) in methods.as_object().expect("methods") {
            if method.starts_with("x-") || method == "get" {
                continue;
            }
            let listed = BODYLESS.contains(&(method.as_str(), path.as_str()));
            let body = op.get("requestBody");
            if listed {
                assert!(
                    body.is_none(),
                    "{method} {path} is declared bodyless but documents a requestBody"
                );
                bodyless_seen.push((method.clone(), path.clone()));
                continue;
            }
            let body = body.unwrap_or_else(|| {
                panic!(
                    "{method} {path} documents no requestBody and is not declared bodyless — a \
                     client cannot construct a call to it"
                )
            });
            let schema = &body["content"]["application/json"]["schema"];

            if let Some(reference) = schema["$ref"].as_str() {
                let name = reference
                    .strip_prefix("#/components/schemas/")
                    .unwrap_or_else(|| {
                        panic!("{method} {path} $ref is not a component: {reference}")
                    });
                assert!(
                    schemas.contains_key(name),
                    "{method} {path} references undefined component {name}"
                );
            } else {
                assert_eq!(
                    schema["type"], "object",
                    "{method} {path} requestBody must be a $ref or an object schema"
                );
            }
            declared += 1;
        }
    }

    assert_eq!(
        bodyless_seen.len(),
        BODYLESS.len(),
        "every BODYLESS entry must name a real operation; saw {bodyless_seen:?}"
    );
    assert_eq!(
        declared, 34,
        "34 mutating operations take a body; a change here is a deliberate API change. 34 = 22 \
         + each plane section's PUT and PATCH-settings (both DELETEs are bodyless, above) + the \
         agents plane's approve verb, whose body carries the fingerprint the \
         operator is attesting they read + the seven 1.6.0 kernel verbs that read one \
         (`store-restore`, `adjust`, `ledger/amend-rate-history`, since owner answer Q71(2) \
         `plane-record-write` and `commit-upgrade`, and the ARCHITECT's 2026-10-06 \
         `trust/approve` and `trust/revoke`, whose body names the trust key)"
    );
}
