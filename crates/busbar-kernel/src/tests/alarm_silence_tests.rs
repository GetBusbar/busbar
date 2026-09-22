// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Binding: an alarm and a disputes-report entry are ledger-endpoint rows ONLY. On a 1.5.5-shaped
//! deployment (no ledger, no data dir, no plane claimed) a normal request lifecycle emits no log
//! event, no metric series and no stderr line that mentions an alarm or a dispute — 1.5.5's
//! structured-field sweep and its closed metric set are byte-identical.
//!
//! `a_1_5_5_request_lifecycle_emits_no_alarm_or_dispute_event_or_metric` — the real-request-lifecycle
//! half of this binding — MOVED to `tests/alarm_silence_cross_plane.rs`: it drives a real router
//! built from `TestApp::lane`/`.pool()`, which only routes through the REAL `busbar_llm` plane's
//! `build_runtime`/`viewer` (see that file's header, and `endpoints_cross_plane.rs`'s for the same
//! reason). What stays here is the pure-function half: the marker matcher and the exposition-line
//! name extractor the moved test (and any future alarm code) both drive.
//!
//! The closed-set half of the same binding (no series outside 1.5.5's 25 names on the shipped
//! binary) lives in the busbar crate's `scrape_shape_1_5_5` integration test, which boots the real
//! binary with every plane compiled in.

/// The words an alarm or a disputes-report entry would carry, matched case-insensitively.
const MARKERS: &[&str] = &["alarm", "dispute"];

fn mentions_a_marker(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    MARKERS.iter().any(|m| lower.contains(m))
}

/// The metric name of one exposition line: the token before `{` or the first space on a sample
/// line, or the second token of a `# HELP` / `# TYPE` line.
fn metric_name(line: &str) -> Option<&str> {
    if let Some(rest) = line.strip_prefix("# ") {
        let mut it = rest.split_whitespace();
        let _kind = it.next()?;
        return it.next();
    }
    let end = line.find(['{', ' ']).unwrap_or(line.len());
    let name = &line[..end];
    (!name.is_empty()).then_some(name)
}

/// The name extractor reads sample, summary and comment lines the way the assertion needs.
#[test]
fn metric_name_reads_every_exposition_line_shape() {
    assert_eq!(
        metric_name("busbar_requests_total{a=\"b\"} 1"),
        Some("busbar_requests_total")
    );
    assert_eq!(
        metric_name("busbar_billing_truncated_total 0"),
        Some("busbar_billing_truncated_total")
    );
    assert_eq!(
        metric_name("busbar_request_duration_seconds_count{pool=\"p\"} 3"),
        Some("busbar_request_duration_seconds_count")
    );
    assert_eq!(metric_name("# HELP busbar_x Some help"), Some("busbar_x"));
    assert_eq!(metric_name("# TYPE busbar_x counter"), Some("busbar_x"));
    assert_eq!(metric_name(""), None);
    assert!(mentions_a_marker("busbar_stall_ALARM_total"));
    assert!(!mentions_a_marker("busbar_requests_total"));
}
