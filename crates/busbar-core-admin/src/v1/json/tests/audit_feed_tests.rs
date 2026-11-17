// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ADMIN-API-1.6 section 7.2: the `/audit` query surface.

use std::collections::HashMap;

use axum::extract::Query;

use super::handlers::get_audit;

fn q(pairs: &[(&str, &str)]) -> Query<HashMap<String, String>> {
    Query(
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect(),
    )
}

#[tokio::test]
async fn audit_has_no_kinds_param() {
    let response = get_audit(q(&[("kinds", "hook")])).await;
    assert_eq!(response.status().as_u16(), 400, "`kinds=` does not exist");
}

#[tokio::test]
async fn audit_severity_is_a_closed_set() {
    assert_eq!(
        get_audit(q(&[("severity", "loud")]))
            .await
            .status()
            .as_u16(),
        400
    );
    for ok in ["info", "warning", "error"] {
        assert_eq!(
            get_audit(q(&[("severity", ok)])).await.status().as_u16(),
            200,
            "{ok}"
        );
    }
}

#[tokio::test]
async fn audit_takes_kind_and_instance_filters() {
    let response = get_audit(q(&[("kind", "openai"), ("instance", "primary")])).await;
    assert_eq!(response.status().as_u16(), 200);
}

#[cfg(feature = "openapi-schema")]
#[test]
fn audit_action_catalogue_closed() {
    let doc = crate::v1::json::handlers::openapi_doc();
    let table = doc["components"]["x-busbar-audit-actions"]
        .as_object()
        .expect("components.x-busbar-audit-actions is generated");
    let published: Vec<&str> = table.keys().map(String::as_str).collect();
    let mut kernel = busbar_kernel::audit::auditlog::AUDIT_ACTIONS.to_vec();
    kernel.sort_unstable();
    let mut published_sorted = published.clone();
    published_sorted.sort_unstable();
    assert_eq!(
        published_sorted, kernel,
        "the document publishes the kernel catalogue"
    );
    assert!(!published.contains(&"keyset.rotated"));
    if let Some(params) = doc["paths"]["/api/v1/admin/audit"]["get"]["parameters"].as_array() {
        let names: Vec<&str> = params.iter().filter_map(|p| p["name"].as_str()).collect();
        assert!(!names.contains(&"kinds"), "{names:?}");
    }
}
