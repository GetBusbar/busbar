// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Coverage for the trivial `kind: export` reference plugin: it declares exactly the `Metrics` and
//! `Logs` streams, takes the trait's default no-op `deliver`, and `open` accepts any config (including
//! malformed JSON) since this sink has no configurable shape.

use super::*;

#[test]
fn open_accepts_empty_config() {
    assert!(open("").is_ok());
}

#[test]
fn open_accepts_malformed_json_config_since_none_is_read() {
    // Unlike every other example plugin's `open`, this one reads NOTHING from `cfg` — a stray
    // trailing comma or outright garbage must not fail the load, since there is no shape to parse.
    assert!(open("{ not json at all").is_ok());
    assert!(open(r#"{"durable_path": "/x",}"#).is_ok());
}

#[test]
fn the_sink_declares_exactly_the_metrics_logs_and_traces_streams() {
    let sink = open("").unwrap();
    assert_eq!(
        sink.streams(),
        vec![
            ExportStream::Metrics,
            ExportStream::Logs,
            ExportStream::Traces
        ]
    );
}

#[test]
fn deliver_counts_the_batch_and_does_not_panic() {
    let sink = open("").unwrap();
    // Calling it for the declared stream and for one it did NOT declare must both be safe: routing
    // is the engine's job, and a sink is never the thing that refuses a stream it was handed.
    sink.deliver(ExportStream::Metrics, &serde_json::json!({"n": 1}));
    sink.deliver(ExportStream::Logs, &serde_json::json!({}));
    let obs = sink.drain_observations();
    assert_eq!(obs.metrics.len(), 1);
    assert_eq!(obs.metrics[0].name, DELIVERED_TOTAL);
    assert_eq!(obs.metrics[0].value, 2.0);
}

/// A DRAIN RESETS. The SDK calls it once per boundary call and the host folds a counter as a DELTA,
/// so reporting a running total would make every response re-report every earlier delivery and the
/// folded series would climb quadratically against a flat workload.
#[test]
fn draining_twice_reports_the_second_window_only() {
    let sink = open("").unwrap();
    sink.deliver(ExportStream::Metrics, &serde_json::json!({}));
    assert_eq!(sink.drain_observations().metrics[0].value, 1.0);
    // Nothing happened in between, so there is nothing to report.
    assert!(sink.drain_observations().is_empty());
    sink.deliver(ExportStream::Metrics, &serde_json::json!({}));
    sink.deliver(ExportStream::Metrics, &serde_json::json!({}));
    assert_eq!(sink.drain_observations().metrics[0].value, 2.0);
}

/// A sink that has done nothing reports NOTHING — so the overwhelmingly common response stays a bare
/// envelope and the back-channel is not a per-call tax.
#[test]
fn a_sink_that_did_nothing_reports_nothing() {
    let sink = open("").unwrap();
    assert!(sink.drain_observations().is_empty());
}

/// THE SERIES IS OUTSIDE THE RESERVED NAMESPACE. The host drops any plugin metric named `busbar_*`
/// so nothing can impersonate a first-party series; a reference plugin that tripped that rule would
/// be demonstrating the wrong thing.
#[test]
fn the_reported_series_is_not_in_the_reserved_namespace() {
    assert!(!DELIVERED_TOTAL.starts_with("busbar_"));
}
