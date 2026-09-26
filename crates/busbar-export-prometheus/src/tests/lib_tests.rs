// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The sink's own statements: what it carries, where it serves, how it refuses settings, and that
//! it renders a snapshot back into the exposition it was taken from. The linked-vs-dropped-in proof
//! is the composition root's (`root::linked::tests`), where the linked tables live.

use super::*;
use busbar_plugin_sdk::MetricSample;

fn sink() -> Box<dyn ExportHandler> {
    open("{}").expect("the sink opens")
}

#[test]
fn it_carries_the_metrics_stream_and_declares_no_route_of_its_own() {
    let sink = sink();
    assert_eq!(sink.streams(), vec![ExportStream::Metrics]);
    assert!(sink.routes().is_empty(), "the host serves /metrics");
}

/// The refusals read as the configuration's own settings errors always have — one line each,
/// `export.<instance>.settings: <serde's words>`.
#[test]
fn its_settings_refusals_are_the_configurations_words() {
    let sink = sink();
    let check = |v: serde_json::Value| sink.validate("m", &v);
    assert!(check(serde_json::json!({ "buffer_seconds": 60 })).is_empty());
    assert!(check(serde_json::json!({ "buffer_seconds": 60, "key_gauge_limit": 5 })).is_empty());
    assert_eq!(
        check(serde_json::json!({})),
        vec!["export.m.settings: missing field `buffer_seconds`".to_string()]
    );
    assert_eq!(
        check(serde_json::json!({ "buffer_seconds": 60, "buffer": 1 })),
        vec![
            "export.m.settings: unknown field `buffer`, expected `buffer_seconds` or \
             `key_gauge_limit`"
                .to_string()
        ]
    );
    assert_eq!(
        check(serde_json::json!({ "buffer_seconds": 0 })),
        vec![
            "the `module: prometheus` export instance sets settings.buffer_seconds: 0, which \
             retains no observations — every scrape would report empty quantiles while still paying \
             the recording cost. Name a positive retention window in seconds, or remove the \
             instance to turn metrics off"
                .to_string()
        ]
    );
    assert_eq!(
        check(serde_json::json!({ "buffer_seconds": "60" })),
        vec!["export.m.settings: invalid type: string \"60\", expected u64".to_string()]
    );
}

/// Every family type in order — HELP optional, labels escaped as carried, numbers as spelled —
/// renders back to the exposition the snapshot was read from, byte for byte.
#[test]
fn it_renders_the_snapshot_back_into_the_exposition() {
    let sample = |name: &str, labels: &[(&str, &str)], value: &str| MetricSample {
        name: name.to_string(),
        labels: labels
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        value: value.to_string(),
    };
    let families = vec![
        MetricFamily {
            name: "busbar_requests_total".to_string(),
            kind: "counter".to_string(),
            help: Some("requests served".to_string()),
            samples: vec![sample(
                "busbar_requests_total",
                &[("pool", "a\\\"b"), ("outcome", "ok")],
                "3",
            )],
        },
        MetricFamily {
            name: "busbar_request_duration_seconds".to_string(),
            kind: "summary".to_string(),
            help: None,
            samples: vec![
                sample(
                    "busbar_request_duration_seconds",
                    &[("quantile", "0.5")],
                    "0.0125",
                ),
                sample("busbar_request_duration_seconds_sum", &[], "0.05"),
                sample("busbar_request_duration_seconds_count", &[], "4"),
            ],
        },
    ];
    let (content_type, body) = sink().render(&families);
    assert_eq!(content_type, "text/plain; version=0.0.4");
    assert_eq!(
        body,
        "# HELP busbar_requests_total requests served\n\
         # TYPE busbar_requests_total counter\n\
         busbar_requests_total{pool=\"a\\\"b\",outcome=\"ok\"} 3\n\
         \n\
         # TYPE busbar_request_duration_seconds summary\n\
         busbar_request_duration_seconds{quantile=\"0.5\"} 0.0125\n\
         busbar_request_duration_seconds_sum 0.05\n\
         busbar_request_duration_seconds_count 4\n\
         \n"
    );
    assert_eq!(
        sink().render(&[]).1,
        "",
        "an empty recorder renders nothing"
    );
}

#[test]
fn the_linked_entry_states_the_row_and_this_crates_boundary() {
    let (name, alias, declares, entry) = linked::EXPORT;
    assert_eq!(
        (name, alias, declares),
        ("busbar-export-prometheus", "prometheus", "{}")
    );
    assert!(std::ptr::eq(entry, &BUSBAR_COLD_ENTRY));
}
