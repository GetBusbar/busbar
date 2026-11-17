// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use axum::http::HeaderValue;
use busbar_contract::abi::export::{
    SCRAPE_KIND_COUNTER, SCRAPE_KIND_HISTOGRAM, SCRAPE_KIND_SUMMARY,
};
use busbar_contract::export_calls::Sample;
use busbar_contract::json::{JsonContainerTrait as _, JsonValueTrait as _};
use http_body_util::BodyExt;

#[tokio::test]
async fn real_encoded_frame_alias_retains_payload_credit_after_response_drop() {
    use busbar_kernel::limits::process_admission::{AdmissionClass, ProcessAdmission};
    for representation in [
        Representation::Json,
        Representation::Text(Format::Prometheus),
    ] {
        let process = ProcessAdmission::with_limits(1, 1024 * 1024, 1024);
        let request = process.try_enter(AdmissionClass::Operator).unwrap();
        let response = encode_response(&families(), &request, representation).unwrap();
        drop(request);
        let used = process.used();
        assert!(used.0 > 0, "an unpolled response owns its backing");
        assert!(process.try_enter(AdmissionClass::Operator).is_err());
        let mut body = response.into_body();
        let frame = body.frame().await.unwrap().unwrap().into_data().unwrap();
        let alias = frame.slice(0..1);
        drop(frame);
        drop(body);
        assert_eq!(process.used(), used);
        assert!(process.try_enter(AdmissionClass::Operator).is_err());
        drop(alias);
        assert_eq!(process.used(), (0, 0));
        assert!(process.try_enter(AdmissionClass::Operator).is_ok());
    }
}

#[test]
fn real_encoder_refusal_drops_partial_body_without_partial_success() {
    use busbar_kernel::limits::process_admission::{AdmissionClass, ProcessAdmission};
    for representation in [
        Representation::Json,
        Representation::Text(Format::Prometheus),
    ] {
        let process = ProcessAdmission::with_limits(0, 512, 0);
        let request = process.try_enter(AdmissionClass::Operator).unwrap();
        assert!(matches!(
            encode_response(&families(), &request, representation),
            Err(OutputError::Capacity)
        ));
        assert_eq!(process.used(), (0, 0));
    }
}

#[test]
fn json_escape_scratch_is_reserved_before_the_real_writer_runs() {
    use busbar_kernel::limits::output::CaptureScope;
    use busbar_kernel::limits::process_admission::{AdmissionClass, ProcessAdmission};
    let mut value = families();
    value[0].help = Some("\\\"\n".repeat(2048));
    let needed = json_scratch(&value).unwrap();
    let process = ProcessAdmission::with_limits(0, u32::try_from(needed - 1).unwrap(), 0);
    let request = process.try_enter(AdmissionClass::Operator).unwrap();
    let mut scope = CaptureScope::new(&request).unwrap();
    assert_eq!(scope.reserve_requested(needed), Err(OutputError::Capacity));
    assert_eq!(process.used(), (0, 0));
}

#[tokio::test]
async fn capacity_refusal_preserves_existing_correlated_error_schema() {
    let response = busbar_kernel::admin::gate::in_request_scope("r_0123456789abcdef", || {
        output_refused(OutputError::Capacity)
    });
    let (status, headers, bytes) = body(response).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let document = busbar_contract::json::parse_value(&bytes).unwrap();
    assert_eq!(document["code"], "BUSBAR-8110");
    assert_eq!(document["error"].as_object().unwrap().len(), 6);
    assert_eq!(document["error"]["request_id"], "r_0123456789abcdef");
    assert_eq!(headers["x-request-id"], "r_0123456789abcdef");
    assert_eq!(bytes.len(), 189);
}

// Existing representation fixtures borrow caller-owned families. Use the real charged encoder;
// source-capture allocation and route tests exercise the separate production projection owner.
fn render(families: &[Family], representation: Representation) -> Response {
    use busbar_kernel::limits::output::CaptureScope;
    use busbar_kernel::limits::process_admission::{AdmissionClass, ProcessAdmission};
    let process = ProcessAdmission::with_limits(0, 16 * 1024 * 1024, 0);
    let request = process.try_enter(AdmissionClass::Operator).unwrap();
    let mut scope = CaptureScope::new(&request).unwrap();
    if representation == Representation::Json {
        scope
            .reserve_requested(json_scratch(families).unwrap())
            .unwrap();
    }
    encode_response(families, &request, representation).unwrap()
}

fn accept(value: &str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(header::ACCEPT, HeaderValue::from_str(value).unwrap());
    h
}

fn sample(name: &str, labels: &[(&str, &str)], value: &str) -> Sample {
    Sample {
        name: name.into(),
        labels: labels
            .iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect(),
        value: value.into(),
    }
}

fn families() -> Vec<Family> {
    vec![
        Family {
            name: "busbar_requests_total".into(),
            help: Some("r".into()),
            unit: None,
            kind: SCRAPE_KIND_COUNTER,
            samples: vec![
                sample("busbar_requests_total", &[("pool", "a")], "3"),
                sample("busbar_requests_total", &[("pool", "b")], "4"),
            ],
        },
        Family {
            name: "busbar_d_seconds".into(),
            help: Some("d".into()),
            unit: None,
            kind: SCRAPE_KIND_HISTOGRAM,
            samples: vec![
                sample(
                    "busbar_d_seconds_bucket",
                    &[("pool", "a"), ("le", "1")],
                    "1",
                ),
                sample(
                    "busbar_d_seconds_bucket",
                    &[("pool", "a"), ("le", "+Inf")],
                    "2",
                ),
                sample("busbar_d_seconds_sum", &[("pool", "a")], "1.5"),
                sample("busbar_d_seconds_count", &[("pool", "a")], "2"),
                sample(
                    "busbar_d_seconds_bucket",
                    &[("pool", "b"), ("le", "1")],
                    "0",
                ),
                sample(
                    "busbar_d_seconds_bucket",
                    &[("pool", "b"), ("le", "+Inf")],
                    "1",
                ),
                sample("busbar_d_seconds_sum", &[("pool", "b")], "9"),
                sample("busbar_d_seconds_count", &[("pool", "b")], "1"),
            ],
        },
        Family {
            name: "hook_latency".into(),
            help: None,
            unit: None,
            kind: SCRAPE_KIND_SUMMARY,
            samples: vec![
                sample("hook_latency", &[("quantile", "0.5")], "0.2"),
                sample("hook_latency_sum", &[], "1"),
                sample("hook_latency_count", &[], "5"),
            ],
        },
    ]
}

async fn body(response: Response) -> (StatusCode, HeaderMap, Vec<u8>) {
    let (parts, body) = response.into_parts();
    (
        parts.status,
        parts.headers,
        body.collect().await.unwrap().to_bytes().to_vec(),
    )
}

#[test]
fn metrics_accept_selects_the_representation() {
    use crate::metrics_text::Format::{OpenMetrics, Prometheus};
    assert_eq!(
        negotiate(&HeaderMap::new()),
        Representation::Text(Prometheus)
    );
    assert_eq!(negotiate(&accept("*/*")), Representation::Text(Prometheus));
    assert_eq!(
        negotiate(&accept("text/plain")),
        Representation::Text(Prometheus)
    );
    assert_eq!(
        negotiate(&accept(
            "application/openmetrics-text; version=1.0.0; q=0.9, text/plain; q=0.5"
        )),
        Representation::Text(OpenMetrics)
    );
    assert_eq!(negotiate(&accept("application/json")), Representation::Json);
    assert_eq!(
        negotiate(&accept("application/json;q=0, text/plain")),
        Representation::Text(Prometheus)
    );
}

#[tokio::test]
async fn metrics_openmetrics_by_accept() {
    let (status, headers, bytes) = body(render(
        &families(),
        negotiate(&accept("application/openmetrics-text")),
    ))
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(headers[header::CONTENT_TYPE]
        .to_str()
        .unwrap()
        .starts_with("application/openmetrics-text"));
    assert_eq!(headers[header::VARY], "Accept");
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    let text = String::from_utf8(bytes).unwrap();
    assert!(text.contains("busbar_requests_total{pool=\"a\"} 3\n"));
    assert!(text.ends_with("# EOF\n"));
}

#[tokio::test]
async fn metrics_text_is_the_default() {
    let (status, headers, bytes) = body(render(&families(), negotiate(&HeaderMap::new()))).await;
    assert_eq!(status, StatusCode::OK);
    assert!(headers[header::CONTENT_TYPE]
        .to_str()
        .unwrap()
        .starts_with("text/plain; version=0.0.4"));
    assert!(!String::from_utf8(bytes).unwrap().contains("# EOF"));
}

#[tokio::test]
async fn metrics_json_by_accept_covers_every_family() {
    let (status, headers, bytes) =
        body(render(&families(), negotiate(&accept("application/json")))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers[header::CONTENT_TYPE],
        busbar_contract::protocol::APPLICATION_JSON
    );
    let doc = busbar_contract::json::parse_value(&bytes).unwrap();
    let listed: Vec<&str> = doc["families"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        listed,
        ["busbar_requests_total", "busbar_d_seconds", "hook_latency"]
    );
    assert!(doc["cursor"].is_null());

    let counter = &doc["families"][0];
    assert_eq!(counter["type"], "counter");
    assert_eq!(counter["owner"], "core");
    assert_eq!(counter["help"], "r");
    assert_eq!(counter["labels"], busbar_contract::json::json!(["pool"]));
    assert_eq!(
        counter["series"][1],
        busbar_contract::json::json!({"labels": {"pool": "b"}, "value": 4.0})
    );

    let histogram = &doc["families"][1];
    assert_eq!(histogram["type"], "histogram");
    assert_eq!(histogram["labels"], busbar_contract::json::json!(["pool"]));
    assert_eq!(histogram["series"].as_array().unwrap().len(), 2);
    assert_eq!(
        histogram["series"][0],
        busbar_contract::json::json!({
            "labels": {"pool": "a"},
            "buckets": [{"le": "1", "count": 1.0}, {"le": "+Inf", "count": 2.0}],
            "sum": 1.5,
            "count": 2.0
        })
    );
    assert_eq!(histogram["series"][1]["sum"], 9.0);

    let summary = &doc["families"][2];
    assert_eq!(summary["owner"], "plugin");
    assert_eq!(summary["series"][1]["name"], "hook_latency_sum");
}

#[tokio::test]
async fn metrics_explicit_off_is_503_with_reason_telemetry_disabled() {
    let (status, headers, bytes) = body(refused(ScrapeRefusal::TelemetryDisabled)).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let doc = busbar_contract::json::parse_value(&bytes).unwrap();
    assert_eq!(doc["error"]["code"], "unavailable");
    assert_eq!(doc["error"]["reason"], "telemetry_disabled");
    assert!(headers.contains_key("x-request-id"));
    let (status, _, bytes) = body(refused(ScrapeRefusal::NotReady)).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let doc = busbar_contract::json::parse_value(&bytes).unwrap();
    assert_ne!(doc["error"]["reason"], "telemetry_disabled");
}
