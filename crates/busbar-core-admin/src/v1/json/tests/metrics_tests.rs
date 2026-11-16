// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use axum::http::HeaderValue;
use busbar_contract::abi::export::{
    SCRAPE_KIND_COUNTER, SCRAPE_KIND_HISTOGRAM, SCRAPE_KIND_SUMMARY,
};
use busbar_contract::export_calls::Sample;
use busbar_contract::json::JsonValueTrait as _;
use http_body_util::BodyExt;

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
