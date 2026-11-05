// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn view(rows: usize, label: &str) -> TelemetryView {
    TelemetryView {
        process_boot_nonce: "0123456789abcdef0123456789abcdef".into(),
        uptime_since_start_ms: ExactU64(9_007_199_254_740_993),
        captured_at_unix_ms: ExactU64(1_799_000_000_123),
        upper_bounds_ms: UPPER_BOUNDS_MS,
        identities: (0..rows)
            .map(|_| Identity {
                plane: label.into(),
                phase: Phase::LlmProducerDrive,
                pool: label.into(),
                ingress_protocol: label.into(),
                count: ExactU64(u64::MAX),
                errors: ExactU64(9_007_199_254_740_993),
                client_errors: ExactU64(1),
                sum_us: ExactU64(u64::MAX),
                bins: std::array::from_fn(|i| ExactU64(if i == 0 { u64::MAX } else { 0 })),
            })
            .collect(),
        omitted_identities: ExactU64(2),
        truncated: true,
        dropped: Dropped {
            invalid_duration: ExactU64(0),
            integer_overflow: ExactU64(1),
            series_capacity: ExactU64(0),
            boot_nonce_unavailable: ExactU64(0),
            histogram_capacity: ExactU64(0),
            unregistered_labels: ExactU64(0),
        },
    }
}

#[test]
fn telemetry_preserves_exact_integer_strings_and_exclusive_bins() {
    let bytes = encode(view(1, "test")).unwrap();
    let doc: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(doc["uptime_since_start_ms"], "9007199254740993");
    let row = &doc["identities"][0];
    assert_eq!(row["count"], "18446744073709551615");
    assert_eq!(row["errors"], "9007199254740993");
    assert_eq!(row["client_errors"], "1");
    assert_eq!(doc["captured_at_unix_ms"], "1799000000123");
    assert_eq!(row["sum_us"], "18446744073709551615");
    assert_eq!(row["bins"][0], "18446744073709551615");
    assert!(row["bins"].as_array().unwrap()[1..]
        .iter()
        .all(|v| v == "0"));
    assert_eq!(
        doc["upper_bounds_ms"],
        serde_json::json!([
            1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000, 60000, 120000, null
        ])
    );
    assert_eq!(doc["omitted_identities"], "2");
    assert_eq!(doc["truncated"], true);
}

#[test]
fn telemetry_caps_rows_and_encoded_bytes_with_explicit_omissions() {
    let doc: serde_json::Value =
        serde_json::from_slice(&encode(view(40, "small")).unwrap()).unwrap();
    assert_eq!(doc["identities"].as_array().unwrap().len(), 32);
    assert_eq!(doc["omitted_identities"], "10");
    // JSON escaping expands each byte sixfold, despite the source's 256-byte label cap.
    let bytes = encode(view(32, &"\u{0001}".repeat(256))).unwrap();
    assert!(bytes.len() <= MAX_BODY_BYTES);
    let doc: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let kept = doc["identities"].as_array().unwrap().len();
    assert!(kept > 0 && kept < 32);
    assert_eq!(doc["omitted_identities"], (34 - kept).to_string());
    assert_eq!(doc["truncated"], true);
    assert_eq!(doc["identities"][0]["count"], "18446744073709551615");
}

#[tokio::test]
async fn telemetry_unavailable_is_503_and_success_is_not_cached() {
    use http_body_util::BodyExt;
    let failed = response(Err(AdminError::Unavailable(
        "telemetry collection is disabled or unavailable".into(),
    )));
    assert_eq!(failed.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = failed.into_body().collect().await.unwrap().to_bytes();
    let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(doc["error"]["code"], "unavailable");
    assert!(doc.get("identities").is_none());
    let ok = response(Ok(view(1, "test")));
    assert_eq!(ok.status(), StatusCode::OK);
    assert_eq!(ok.headers()[header::CACHE_CONTROL], "no-store");
    assert!(ok.into_body().collect().await.unwrap().to_bytes().len() <= MAX_BODY_BYTES);
}

#[cfg(feature = "openapi-schema")]
#[test]
fn telemetry_is_a_declared_read_with_bounded_schema_and_unavailable_response() {
    let row = crate::verb::row_of(crate::KernelVerb::GetTelemetry).unwrap();
    assert_eq!(row.path, "/api/v1/admin/telemetry");
    assert_eq!(row.scope, crate::VerbScope::ReadOnly);
    assert!(crate::VerbScope::ReadOnly.allows(row.scope));
    assert_eq!(
        crate::rate::MutationClass::for_verb(row.verb, &[]),
        crate::rate::MutationClass::Forbidden
    );
    let doc = crate::v1::json::openapi_doc();
    let operation = &doc["paths"][row.path]["get"];
    assert_eq!(operation["operationId"], "GetTelemetry");
    assert_eq!(operation["x-busbar-required-scope"], "read-only");
    assert!(operation["responses"].get("401").is_some());
    assert!(operation["responses"].get("503").is_some());
    let schema = &doc["components"]["schemas"]["TelemetryView"];
    assert_eq!(schema["properties"]["identities"]["maxItems"], 32);
    assert_eq!(
        doc["components"]["schemas"]["TelemetryExactU64"]["type"],
        "string"
    );
    assert_eq!(
        doc["components"]["schemas"]["TelemetryExactU64"]["pattern"],
        "^(0|[1-9][0-9]*)$"
    );
}
