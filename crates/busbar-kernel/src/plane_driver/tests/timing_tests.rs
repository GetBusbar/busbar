// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use std::sync::Arc;

#[test]
fn a_disabled_attempt_span_reads_no_clock_and_keeps_no_note() {
    let mut timing = AttemptTiming::new(tracing::Span::none(), 1, 2, None, None);
    assert!(
        timing.start.is_none(),
        "no clock read for a span nobody records"
    );
    assert!(timing.trail.is_none());
    timing.retry(Some("rate_limited"));
    assert!(timing.terminal);
}

#[test]
fn the_summary_note_takes_the_first_status_and_the_failover_reason() {
    let log: crate::observability::request::AttemptLog = Arc::default();
    let trail = crate::observability::request::AttemptTrail::open(Arc::clone(&log), "a", "openai");
    let mut timing = AttemptTiming::new(tracing::Span::none(), 1, 1, None, Some(trail));
    timing.piece(&FarPiece {
        status: Some((503, 5)),
        fail_over: true,
        ..FarPiece::default()
    });
    timing.retry(Some("upstream_5xx"));
    drop(timing);
    let notes = log.lock().unwrap().clone();
    assert_eq!(notes.len(), 1, "one note per attempt, even once dropped");
    assert_eq!(notes[0].lane, "a");
    assert_eq!(notes[0].provider, "openai");
    assert_eq!(notes[0].status, 503);
    assert_eq!(notes[0].outcome, "retry");
    assert_eq!(notes[0].failover, Some("upstream_5xx"));
}
