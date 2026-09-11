// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What this sink decides for itself: the OTLP request it frames out of a batch of observed spans,
//! and which collector answers are worth telling its composer about. Nothing here opens a socket —
//! there is nothing in this crate that could.
//!
//! THE FRAMING IS PINNED BY DECODING IT BACK, not by comparing a byte blob: a golden protobuf blob
//! would pass for the wrong reason the day a field number moved, while a decode-and-read says what
//! a COLLECTOR would see, which is the only thing this sink exists to be right about.

use super::*;
use std::sync::Mutex;

/// A [`Report`] that records every event as the line its composer would log, so a test can assert
/// what actually reached the composer rather than that something did.
#[derive(Default)]
struct Recorder(Mutex<Vec<String>>);

impl Report for Recorder {
    fn report(&self, event: Event<'_>) {
        let line = match event {
            Event::Refused { status } => format!("refused {status}"),
            Event::Unavailable { status } => format!("unavailable {status}"),
            Event::TransportError { error } => format!("transport {error}"),
            Event::MalformedBatch { error } => format!("malformed {error}"),
        };
        self.0.lock().unwrap_or_else(|e| e.into_inner()).push(line);
    }
}

impl Recorder {
    fn lines(&self) -> Vec<String> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

/// A host that lends this sink the one thing it asks for — a wire — and keeps what was put on it,
/// so a test can see the bytes that would have left the process.
#[derive(Default)]
struct Wire {
    sent: Mutex<Vec<Delivery>>,
    refuse: bool,
}

impl ExportHost for Wire {
    fn send(&self, delivery: Delivery) -> bool {
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

fn sink(report: &Arc<Recorder>) -> OtlpSink {
    OtlpSink::new(
        "https://collector.example.com/v1/traces".to_string(),
        vec![("authorization".to_string(), "Basic dTpw".to_string())],
        vec![("service.name".to_string(), "busbar".to_string())],
        report.clone(),
    )
}

/// One finished span as the composer would have read it off this process.
fn span_record(parent: Option<[u8; 8]>) -> SpanRecord {
    SpanRecord {
        trace_id: [
            0x4b, 0xf9, 0x2f, 0x35, 0x77, 0xb3, 0x4d, 0xa6, 0xa3, 0xce, 0x92, 0x9d, 0x0e, 0x0e,
            0x47, 0x36,
        ],
        span_id: [0x00, 0xf0, 0x67, 0xaa, 0x0b, 0xa9, 0x02, 0xb7],
        parent_span_id: parent,
        name: "forward".to_string(),
        kind: SpanKind::Server,
        start_unix_nanos: 1_700_000_000_000_000_000,
        end_unix_nanos: 1_700_000_000_042_000_000,
        status: SpanStatus::Error {
            message: "upstream refused".to_string(),
        },
        attributes: vec![
            ("pool".to_string(), AttrValue::Str("prod".to_string())),
            ("status".to_string(), AttrValue::Int(502)),
            ("retried".to_string(), AttrValue::Bool(true)),
        ],
        dropped_attributes: 7,
    }
}

/// The bytes a composer hands this sink for the `traces` stream: the batch, serialized.
fn batch_bytes(records: &[SpanRecord]) -> Vec<u8> {
    serde_json::to_vec(records).expect("a span batch serializes")
}

// ── the face ─────────────────────────────────────────────────────────────────────────────────

/// A SPAN REACHES THIS SINK AS BYTES, AND WHAT LEAVES IS THE OTLP REQUEST THIS SINK FRAMED.
///
/// The composer observed a span, serialized it and handed it over through
/// `busbar_contract::Export::receive` on a `dyn Export` — no crate name, no `delivery`, no span
/// type crossing the face. What the host's wire is handed is one `ExportTraceServiceRequest`
/// carrying this process's resource, the `busbar` scope, and that span with its ids, its window,
/// its kind, its status and its attributes intact. Red first: without `impl Export for OtlpSink`
/// this does not compile, and without the framing the body is not a decodable export request.
#[test]
fn a_span_batch_through_the_face_is_the_otlp_request_this_sink_framed() {
    let report = Arc::new(Recorder::default());
    let parent = [0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81];
    let bytes = batch_bytes(&[span_record(Some(parent))]);

    let wire = Wire::default();
    let faced: Box<dyn Export> = Box::new(sink(&report));
    let ack = faced.receive(
        ExportItem {
            stream: STREAM,
            bytes: &bytes,
        },
        &wire,
    );

    let sent = wire.sent.lock().unwrap_or_else(|e| e.into_inner()).clone();
    assert_eq!(sent.len(), 1, "one drained batch is one export request");
    assert_eq!(
        sent[0].target, "https://collector.example.com/v1/traces",
        "the request is addressed to the endpoint the composer resolved"
    );
    assert_eq!(
        sent[0].headers,
        vec![
            (
                "content-type".to_string(),
                "application/x-protobuf".to_string()
            ),
            ("authorization".to_string(), "Basic dTpw".to_string()),
        ],
        "the binding's one media type, then the credential the composer split off the URL"
    );

    // DECODE IT BACK. This is what a collector sees.
    let decoded = ExportTraceServiceRequest::decode(sent[0].body.as_slice())
        .expect("the body is an OTLP export request");
    let rs = &decoded.resource_spans[0];
    let resource = rs.resource.as_ref().expect("the resource is carried");
    assert_eq!(resource.attributes[0].key, "service.name");
    assert_eq!(
        resource.attributes[0].value.as_ref().unwrap().value,
        Some(any_value::Value::StringValue("busbar".to_string()))
    );
    let ss = &rs.scope_spans[0];
    assert_eq!(
        ss.scope.as_ref().expect("the scope is carried").name,
        "busbar"
    );
    assert_eq!(ss.spans.len(), 1);
    let s = &ss.spans[0];
    assert_eq!(s.trace_id, span_record(None).trace_id.to_vec());
    assert_eq!(s.span_id, span_record(None).span_id.to_vec());
    assert_eq!(s.parent_span_id, parent.to_vec(), "the parent is linked");
    assert_eq!(s.name, "forward");
    assert_eq!(s.kind, span::SpanKind::Server as i32);
    assert_eq!(s.start_time_unix_nano, 1_700_000_000_000_000_000);
    assert_eq!(s.end_time_unix_nano, 1_700_000_000_042_000_000);
    assert_eq!(
        s.status.as_ref().map(|st| (st.code, st.message.clone())),
        Some((
            status::StatusCode::Error as i32,
            "upstream refused".to_string()
        )),
        "an error status crosses as an error, with what the callsite said"
    );
    assert_eq!(
        s.attributes
            .iter()
            .map(|kv| (kv.key.clone(), kv.value.as_ref().unwrap().value.clone()))
            .collect::<Vec<_>>(),
        vec![
            (
                "pool".to_string(),
                Some(any_value::Value::StringValue("prod".to_string()))
            ),
            ("status".to_string(), Some(any_value::Value::IntValue(502))),
            (
                "retried".to_string(),
                Some(any_value::Value::BoolValue(true))
            ),
        ],
        "every attribute the composer granted crosses in its own type"
    );
    assert_eq!(
        s.dropped_attributes_count, 7,
        "a truncated span crosses as truncated: the collector is told, not shown a whole one"
    );

    assert_eq!(
        ack,
        Ack::Received,
        "a request the host's wire took is Received: this sink never learns whether it landed"
    );
    assert_eq!(faced.streams(), &["traces"]);
    assert!(
        faced.routes().is_empty(),
        "a push sink declares no route: it is delivered to, never scraped"
    );
    assert!(
        report.lines().is_empty(),
        "a framed request reports nothing"
    );
}

/// EVERY SPAN'S PARENT IS ITS OWN RECORD'S, AND A ROOT'S IS NOTHING.
///
/// Stated over a MIXED batch, because that is the only version of this that can fail: an all-zero
/// parent encodes identically to an absent one (proto3 elides a zero-valued bytes field), so
/// "not zeroed" is not a fact the wire can carry. What CAN go wrong is a sink that links a root to
/// something — its own id, or the parent of the record beside it — and hands a collector a tree this
/// process never observed. So the batch carries a parented span and a root, and each is read back
/// against the record it came from.
#[test]
fn every_spans_parent_is_its_own_records_and_a_roots_is_nothing() {
    let report = Arc::new(Recorder::default());
    let parent = [0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81];
    let bytes = batch_bytes(&[span_record(Some(parent)), span_record(None)]);
    let wire = Wire::default();

    let _ = sink(&report).receive(
        ExportItem {
            stream: STREAM,
            bytes: &bytes,
        },
        &wire,
    );

    let sent = wire.sent.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let decoded =
        ExportTraceServiceRequest::decode(sent[0].body.as_slice()).expect("an export request");
    let spans = &decoded.resource_spans[0].scope_spans[0].spans;
    assert_eq!(spans.len(), 2, "one record in, one span out, in order");
    assert_eq!(
        spans[0].parent_span_id,
        parent.to_vec(),
        "the parented span links to the parent ITS record named"
    );
    assert!(
        spans[1].parent_span_id.is_empty(),
        "the root links to nothing, and not to its neighbour or to itself: {:?}",
        spans[1].parent_span_id
    );
    assert_ne!(
        spans[1].parent_span_id, spans[1].span_id,
        "a root that linked to itself would be a cycle a collector cannot draw"
    );
}

/// A REFUSED DELIVERY IS `Retry`, AND NEVER `Received`.
///
/// The host took the framed request NOWHERE — its gate was spent, its wire was shut, whatever the
/// reason, which is not this sink's business. `Received` would be a claim this sink is not entitled
/// to make, and the whole reason the SDK's batch processor was deleted rather than wrapped is that
/// behind a queue this sink could never have told the difference.
#[test]
fn a_refused_delivery_is_retry_and_never_received() {
    let report = Arc::new(Recorder::default());
    let bytes = batch_bytes(&[span_record(None)]);
    let wire = Wire {
        refuse: true,
        ..Wire::default()
    };

    let faced: Box<dyn Export> = Box::new(sink(&report));
    let ack = faced.receive(
        ExportItem {
            stream: STREAM,
            bytes: &bytes,
        },
        &wire,
    );

    assert_eq!(ack, Ack::Retry, "a record that reached nowhere is Retry");
    assert!(
        wire.sent
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty(),
        "a refused host put nothing on any wire"
    );
}

/// BYTES THAT ARE NOT A SPAN BATCH ARE `Retry`, AND THEY ARE SAID OUT LOUD.
///
/// Structurally unreachable — the only producer of this stream's bytes is the composer's own layer
/// — and therefore exactly the case a silent `Received` would hide forever.
#[test]
fn bytes_that_are_not_a_span_batch_are_retry_and_are_reported() {
    let report = Arc::new(Recorder::default());
    let wire = Wire::default();

    let ack = sink(&report).receive(
        ExportItem {
            stream: STREAM,
            bytes: b"not a span batch",
        },
        &wire,
    );

    assert_eq!(
        ack,
        Ack::Retry,
        "a record this sink could not read is Retry"
    );
    assert!(
        wire.sent
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty(),
        "nothing is framed out of bytes that are not a batch"
    );
    assert_eq!(report.lines().len(), 1);
    assert!(
        report.lines()[0].starts_with("malformed "),
        "said: {:?}",
        report.lines()
    );
}

// ── the judgement ────────────────────────────────────────────────────────────────────────────

/// A COLLECTOR THAT IS BUSY AND A COLLECTOR THAT IS MISCONFIGURED ARE DIFFERENT FACTS.
///
/// `429`/`503`/`408` and the rest of `5xx` say TRY AGAIN; every other `4xx` is a statement about
/// the request itself that no number of retries changes. Both arms drop this batch — a retry queue
/// in front of a telemetry sink is a memory leak with a deadline — but only one of them is worth an
/// operator's attention.
#[test]
fn a_retryable_answer_and_a_permanent_one_are_reported_as_different_things() {
    let report = Arc::new(Recorder::default());
    let s = sink(&report);

    s.observe(Ok(200));
    s.observe(Ok(202));
    assert!(report.lines().is_empty(), "a 2xx export says nothing");

    for status in [408u16, 429, 500, 503] {
        assert!(retryable(status), "{status} says try again");
    }
    for status in [400u16, 401, 403, 404, 413, 415] {
        assert!(!retryable(status), "{status} is about the request itself");
    }

    s.observe(Ok(503));
    s.observe(Ok(404));
    s.observe(Err("connection refused".to_string()));
    assert_eq!(
        report.lines(),
        vec![
            "unavailable 503",
            "refused 404",
            "transport connection refused",
        ]
    );
}

/// NO REPORT THIS SINK RAISES CAN CARRY THE OPERATOR'S CREDENTIAL, because none of them names the
/// target at all — the endpoint arrived credential-free and the credential arrived as a header this
/// crate only ever copies into a delivery.
#[test]
fn no_report_names_the_target_or_the_credential() {
    let report = Arc::new(Recorder::default());
    let s = sink(&report);
    s.observe(Ok(401));
    s.observe(Err("connection reset by peer".to_string()));
    let lines = report.lines().join("\n");
    assert!(!lines.contains("collector.example.com"), "{lines}");
    assert!(!lines.contains("Basic dTpw"), "{lines}");
}
