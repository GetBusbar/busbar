// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What this sink decides for itself: the bytes of the POST it frames, and which outcomes are worth
//! telling its composer about. Nothing here opens a socket — there is nothing in this crate that
//! could.

use super::*;
use std::sync::Mutex;

/// A [`Report`] that records every event as the line its composer would log, so a test can assert
/// what actually reached the composer rather than that something did.
#[derive(Default)]
struct Recorder(Mutex<Vec<String>>);

impl Report for Recorder {
    fn report(&self, event: Event<'_>) {
        let line = match event {
            Event::Non2xx { url, status } => format!("non2xx {url} {status}"),
            Event::TransportError { url, error } => format!("transport {url} {error}"),
        };
        self.0.lock().unwrap_or_else(|e| e.into_inner()).push(line);
    }
}

impl Recorder {
    fn lines(&self) -> Vec<String> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

fn sink(auth: Option<(String, String)>, report: &Arc<Recorder>) -> WebhookSink {
    WebhookSink::new(
        "https://user:hunter2@logs.example.com/busbar".to_string(),
        "https://***@logs.example.com/busbar".to_string(),
        auth,
        Duration::from_secs(2),
        report.clone(),
    )
}

/// THE FRAME IS THE PAYLOAD'S, BYTE FOR BYTE. The line the composer serialized to this instance's
/// projection is the body, unaltered and un-re-encoded, under the one media type a request-log line
/// has — and the request goes to the target, not to the masked spelling of it.
#[test]
fn delivery_frames_the_payload_bytes_at_the_target() {
    let report = Arc::new(Recorder::default());
    let s = sink(None, &report);
    let payload = r#"{"ts":1700000000,"pool":"prod","outcome":"ok","latency_ms":42}"#;

    let d = s.delivery(payload);

    assert_eq!(
        d.url, "https://user:hunter2@logs.example.com/busbar",
        "the delivery is addressed to the TARGET, never to the masked display spelling"
    );
    assert_eq!(
        d.headers,
        vec![("content-type".to_string(), "application/json".to_string())]
    );
    assert_eq!(
        d.body,
        payload.as_bytes(),
        "the body is the serialized line, byte for byte"
    );
    assert!(
        report.lines().is_empty(),
        "a framed delivery reports nothing"
    );
}

/// The operator's auth header rides on the delivery, AFTER the media type, exactly as configured —
/// this sink neither validates it nor invents one.
#[test]
fn the_operators_auth_header_rides_the_delivery_as_configured() {
    let report = Arc::new(Recorder::default());

    let s = sink(
        Some(("Authorization".to_string(), "Bearer sekret".to_string())),
        &report,
    );
    assert_eq!(
        s.delivery("{}").headers,
        vec![
            ("content-type".to_string(), "application/json".to_string()),
            ("Authorization".to_string(), "Bearer sekret".to_string()),
        ]
    );
}

/// A DELIVERY IS STATED, NEVER JUDGED. Whether a target can be reached — or addressed at all — is
/// the composer's answer, and it comes back through [`WebhookSink::observe`]; this sink states the
/// line either way rather than second-guessing the wire it does not own.
#[test]
fn a_target_this_sink_cannot_judge_is_still_stated() {
    let report = Arc::new(Recorder::default());
    let s = WebhookSink::new(
        "not a uri".to_string(),
        "not a uri".to_string(),
        None,
        Duration::from_secs(2),
        report.clone(),
    );

    assert_eq!(s.delivery("{}").url, "not a uri");
    assert!(
        report.lines().is_empty(),
        "stating a delivery reports nothing"
    );

    // ...and when the composer comes back with what its wire made of that target, THAT is reported.
    s.observe(Err("target URL does not parse".to_string()));
    assert_eq!(
        report.lines(),
        vec!["transport not a uri target URL does not parse"]
    );
}

/// SUCCESS IS SILENT; EVERY OTHER OUTCOME NAMES THE MASKED TARGET. A sink that leaked the userinfo
/// on one arm and not the other is the shape this holds shut: both arms carry `display_url` and
/// there is no other URL in this crate to carry.
#[test]
fn observe_reports_every_failure_with_the_masked_target_and_nothing_on_success() {
    let report = Arc::new(Recorder::default());
    let s = sink(None, &report);

    s.observe(Ok(200));
    s.observe(Ok(204));
    s.observe(Ok(299));
    assert!(report.lines().is_empty(), "a 2xx delivery says nothing");

    s.observe(Ok(500));
    s.observe(Err("connection refused".to_string()));

    let lines = report.lines();
    assert_eq!(
        lines,
        vec![
            "non2xx https://***@logs.example.com/busbar 500",
            "transport https://***@logs.example.com/busbar connection refused",
        ]
    );
    assert!(
        !lines.join("\n").contains("hunter2"),
        "no report may carry the operator's credentials: {lines:?}"
    );
}
