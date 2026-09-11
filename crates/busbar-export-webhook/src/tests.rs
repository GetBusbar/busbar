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

    let wire = Wire::default();
    let ack = busbar_contract::Export::receive(
        &s,
        busbar_contract::ExportItem {
            stream: "logs",
            bytes: b"{}",
        },
        &wire,
    );
    assert_eq!(
        wire.sent.lock().unwrap_or_else(|e| e.into_inner())[0].target,
        "not a uri",
        "the target is stated as the operator wrote it, judged by nobody here"
    );
    assert_eq!(ack, busbar_contract::Ack::Received);
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

// ── the face ─────────────────────────────────────────────────────────────────────────────────

/// A host that lends this sink the one thing it asks for — a wire — and keeps what was put on it,
/// so a test can see the bytes that would have left the process.
#[derive(Default)]
struct Wire {
    sent: Mutex<Vec<busbar_contract::Delivery>>,
    refuse: bool,
}

impl busbar_contract::ExportHost for Wire {
    fn send(&self, delivery: busbar_contract::Delivery) -> bool {
        if self.refuse {
            return false;
        }
        self.sent
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(delivery);
        true
    }
    fn read(&self, _stream: &str) -> Option<String> {
        unreachable!("a push sink never asks its host for a reading")
    }
}

/// THE SERVED PATH REACHES THIS SINK THROUGH THE FACE, AND THE BYTES ARE THE SAME.
///
/// A request-log line handed to `busbar_contract::Export::receive` through a `dyn Export` — no
/// crate name, no `delivery` — is framed at the same target, under the same headers in the same
/// order, with the same body, as the frame the composer's direct call produced before the face
/// existed. Red first: without `impl Export for WebhookSink` this does not compile, and a `receive`
/// that re-encoded the line or reordered the headers would move the bytes on the wire.
#[test]
fn a_line_through_the_face_is_the_post_the_direct_frame_stated() {
    use busbar_contract::{Ack, Export, ExportItem};

    let report = Arc::new(Recorder::default());
    let s = sink(
        Some(("Authorization".to_string(), "Bearer sekret".to_string())),
        &report,
    );
    let payload = r#"{"ts":1700000000,"pool":"prod","outcome":"ok","latency_ms":42}"#;

    let wire = Wire::default();
    let faced: Box<dyn Export> = Box::new(s);
    let ack = faced.receive(
        ExportItem {
            stream: "logs",
            bytes: payload.as_bytes(),
        },
        &wire,
    );

    let sent = wire.sent.lock().unwrap_or_else(|e| e.into_inner()).clone();
    assert_eq!(sent.len(), 1, "one item is one delivery");
    assert_eq!(
        sent[0].target, "https://user:hunter2@logs.example.com/busbar",
        "the delivery is addressed to the TARGET, never to the masked display spelling"
    );
    assert_eq!(
        sent[0].headers,
        vec![
            ("content-type".to_string(), "application/json".to_string()),
            ("Authorization".to_string(), "Bearer sekret".to_string()),
        ],
        "the media type, then the operator's header, in that order — the 1.5.x frame"
    );
    assert_eq!(
        sent[0].body,
        payload.as_bytes(),
        "the body is the serialized line, byte for byte"
    );
    assert_eq!(
        ack,
        Ack::Received,
        "a delivery the host's wire accepted is Received: this sink never learns whether it landed"
    );
    assert_eq!(faced.streams(), &["logs"]);
    assert!(
        faced.routes().is_empty(),
        "a push sink declares no route: it is delivered to, never scraped"
    );
    assert!(
        report.lines().is_empty(),
        "a framed delivery reports nothing"
    );
}

/// A DELIVERY THE HOST WOULD NOT TAKE IS NOT ACKNOWLEDGED AS TAKEN.
///
/// The wire belongs to the composer, so a refusal is the composer's answer — and the honest thing
/// for the sink to say about a record that went nowhere is that it did not take it.
#[test]
fn a_delivery_the_host_refused_is_not_acknowledged_as_taken() {
    use busbar_contract::{Ack, Export, ExportItem};

    let report = Arc::new(Recorder::default());
    let faced: Box<dyn Export> = Box::new(sink(None, &report));
    let wire = Wire {
        refuse: true,
        ..Wire::default()
    };

    assert_eq!(
        faced.receive(
            ExportItem {
                stream: "logs",
                bytes: b"{}",
            },
            &wire,
        ),
        Ack::Retry,
    );
}
