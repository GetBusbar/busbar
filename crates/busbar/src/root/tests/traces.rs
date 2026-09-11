// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/root/units_export/traces.rs` — the span producer.
//!
//! WHAT IS PROVEN HERE IS THE HALF A SINK CANNOT PROVE: that a span this process observed reaches
//! the sink AS BYTES THE SINK FRAMES, that a child links to its parent, that the attribute bound the
//! sink declares is the one the composer applies, and that a full gate DROPS AND COUNTS. The sink's
//! own file proves what it does with those bytes.
//!
//! NOTHING HERE INSTALLS A GLOBAL SUBSCRIBER. The layer holds the composition it feeds rather than
//! reading a process-global, so every cell below drives a real `tracing_subscriber::Registry`
//! scoped to itself — which is also what makes them runnable in parallel with the rest of the suite.
//!
//! The credential split and its base64 vectors are PORTED, not rewritten: they came from
//! `root/tests/logging.rs` with the code they prove, and the only change is the shape of what the
//! split hands back — a header PAIR the sink copies into its delivery, rather than a typed header
//! value the retired exporter's client took as an argument.

use super::*;
use std::sync::Mutex as StdMutex;

// ── the credential, ported with the code ─────────────────────────────────────────────────────

#[test]
fn base64_encode_matches_the_rfc4648_vectors() {
    // Standard RFC 4648 test vectors, including the padding edge cases the Basic-auth token
    // exercises (input lengths not a multiple of 3).
    assert_eq!(base64_encode(b""), "");
    assert_eq!(base64_encode(b"f"), "Zg==");
    assert_eq!(base64_encode(b"fo"), "Zm8=");
    assert_eq!(base64_encode(b"foo"), "Zm9v");
    assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
    assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
    assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    // The exact token the credential path produces for `alice:s3cr3t`.
    assert_eq!(base64_encode(b"alice:s3cr3t"), "YWxpY2U6czNjcjN0");
}

#[test]
fn the_credential_leaves_the_url_and_becomes_a_header() {
    // Regression: an endpoint with embedded userinfo must yield (a) a credential-FREE target — the
    // only endpoint string the sink ever holds, and therefore the only one any report could name —
    // and (b) an `Authorization: Basic base64(user:pass)` header carrying it out of band.
    let (clean, headers) =
        split_credentials("https://alice:s3cr3t@collector.example.com:4318/v1/traces");
    assert!(
        !clean.contains("alice") && !clean.contains("s3cr3t") && !clean.contains('@'),
        "the target handed to the sink must be credential-free: {clean}"
    );
    // ...while still pointing at the same collector (host/port/path preserved).
    assert_eq!(clean, "https://collector.example.com:4318/v1/traces");
    assert_eq!(
        headers,
        vec![(
            "authorization".to_string(),
            "Basic YWxpY2U6czNjcjN0".to_string() // golden wire-contract literal (kept bare on purpose)
        )]
    );
    assert!(
        !headers[0].1.contains("s3cr3t") && !headers[0].1.contains("alice"),
        "the credential must be base64-encoded, not plaintext: {:?}",
        headers[0].1
    );
}

#[test]
fn password_only_and_user_only_userinfo_both_leave_the_url() {
    let (clean, headers) = split_credentials("https://:topsecret@host:4318/v1/traces");
    assert!(
        !clean.contains("topsecret") && !clean.contains('@'),
        "password-only secret must leave the URL: {clean}"
    );
    assert_eq!(
        headers[0].1,
        format!("Basic {}", base64_encode(b":topsecret")) // golden wire-contract literal (kept bare on purpose)
    );

    let (clean, headers) = split_credentials("https://tokenuser@host:4318/v1/traces");
    assert!(
        !clean.contains("tokenuser") && !clean.contains('@'),
        "username-only secret must leave the URL: {clean}"
    );
    assert_eq!(
        headers[0].1,
        format!("Basic {}", base64_encode(b"tokenuser:")) // golden wire-contract literal (kept bare on purpose)
    );
}

#[test]
fn an_endpoint_without_userinfo_is_passed_through_untouched() {
    // A credential-free endpoint must be returned unchanged with NO header, so unauthenticated
    // collectors keep working exactly as before.
    let (clean, headers) = split_credentials("https://collector.example.com:4318/v1/traces");
    assert_eq!(clean, "https://collector.example.com:4318/v1/traces");
    assert!(headers.is_empty(), "no userinfo must mean no auth header");
    let (clean, headers) = split_credentials("http://localhost:4318");
    assert!(headers.is_empty());
    assert!(clean.starts_with("http://localhost:4318"));
}

#[test]
fn percent_encoded_userinfo_is_decoded_before_it_is_encoded() {
    // Percent-encoded userinfo (e.g. a password containing `@` or `:`) must be decoded so the wire
    // credential matches what the operator configured. `%40` is `@`, `%3A` is `:`.
    let (clean, headers) = split_credentials("https://u:p%40ss%3Aword@host/v1/traces");
    assert!(!clean.contains('@'), "userinfo stripped: {clean}");
    // Decoded credential is `u:p@ss:word`.
    assert_eq!(
        headers[0].1,
        format!("Basic {}", base64_encode(b"u:p@ss:word")) // golden wire-contract literal (kept bare on purpose)
    );
}

// ── the producer ─────────────────────────────────────────────────────────────────────────────

/// What the fake wire kept: the target, the headers and the body one export request would have
/// carried out of this process.
type Sent = (String, Vec<(String, String)>, Vec<u8>);

/// A composition over a wire of the test's own: everything `install` builds except the client and
/// the config read, so a cell can see the bytes that would have left.
fn composed(endpoint: &str) -> (Arc<Traces>, Arc<StdMutex<Vec<Sent>>>) {
    let sent: Arc<StdMutex<Vec<Sent>>> = Arc::new(StdMutex::new(Vec::new()));
    let seen = sent.clone();
    let send: ExportDeliverySend = Arc::new(move |url, headers, body, _timeout, hold, outcome| {
        drop(hold);
        seen.lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((url, headers, body));
        outcome(Ok(200));
    });
    (Arc::new(compose(endpoint, send)), sent)
}

/// A SPAN THIS PROCESS CLOSED REACHES THE SINK AS BYTES THE SINK FRAMES.
///
/// Red first: before this layer existed there was no producer for the `traces` stream at all — the
/// spans went into an SDK batch processor the process could not see into, and nothing in the tree
/// was on a stack that could hand one to `Export::receive`.
#[test]
fn a_closed_span_reaches_the_sink_as_bytes_on_the_traces_stream() {
    use tracing_subscriber::layer::SubscriberExt as _;

    let (traces, sent) = composed("https://collector.example.com/v1/traces");
    {
        let subscriber = tracing_subscriber::registry().with(TraceLayer {
            traces: traces.clone(),
            shown: String::new(),
        });
        let _g = tracing::subscriber::set_default(subscriber);
        let s = tracing::info_span!("forward", pool = "prod", attempts = 2i64);
        let _e = s.enter();
    }
    assert_eq!(traces.drain(), 1, "one closed span is one drained record");

    let sent = sent.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(sent.len(), 1, "one drain is one export request");
    assert_eq!(sent[0].0, "https://collector.example.com/v1/traces");
    assert!(
        sent[0].1.contains(&(
            "content-type".to_string(),
            "application/x-protobuf".to_string()
        )),
        "the sink framed it: {:?}",
        sent[0].1
    );
    assert!(
        !sent[0].2.is_empty(),
        "the framed body is what the sink made of the bytes this layer produced"
    );
}

/// A CHILD INHERITS ITS PARENT'S TRACE AND LINKS TO IT; A ROOT STARTS ITS OWN.
///
/// This is the piece `tracing-opentelemetry` used to do, and the piece a sink cannot do: parent
/// linking is read off the REGISTRY's own span extensions, which only a layer can reach.
#[test]
fn a_child_span_inherits_the_trace_and_links_to_its_parent() {
    use tracing_subscriber::layer::SubscriberExt as _;

    let (traces, _sent) = composed("https://collector.example.com/v1/traces");
    {
        let subscriber = tracing_subscriber::registry().with(TraceLayer {
            traces: traces.clone(),
            shown: String::new(),
        });
        let _g = tracing::subscriber::set_default(subscriber);
        let parent = tracing::info_span!("forward");
        let _pe = parent.enter();
        let child = tracing::info_span!("attempt");
        let _ce = child.enter();
    }

    let queued: Vec<busbar_export_otlp::SpanRecord> = traces
        .queue
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .map(|(r, _)| r.clone())
        .collect();
    assert_eq!(queued.len(), 2, "two closed spans, two records");
    // The CHILD closes first (it is exited and dropped inside the parent's scope).
    let child = &queued[0];
    let parent = &queued[1];
    assert_eq!(child.name, "attempt");
    assert_eq!(parent.name, "forward");
    assert_eq!(
        child.trace_id, parent.trace_id,
        "one trace, so one trace id across both spans"
    );
    assert_eq!(
        child.parent_span_id,
        Some(parent.span_id),
        "the child links to the span it was entered under"
    );
    assert_eq!(
        parent.parent_span_id, None,
        "a root span links to nothing, and says so by absence"
    );
    assert_ne!(child.span_id, parent.span_id, "two spans, two ids");
    assert_ne!(
        parent.trace_id, [0u8; 16],
        "an all-zero trace id is invalid"
    );
}

/// THE ATTRIBUTE BOUND IS THE SINK'S, AND THE COMPOSER IS THE PARTY THAT APPLIES IT.
///
/// A span with more attributes than the sink declared it will take crosses TRUNCATED and SAYS SO:
/// the count of what was left off rides along, so the collector is told rather than shown a
/// complete-looking span. The three `otel.*` fields are STATEMENTS about the span and never count
/// against the bound.
#[test]
fn the_attribute_bound_is_the_sinks_and_a_truncated_span_says_so() {
    use tracing_subscriber::layer::SubscriberExt as _;

    let (traces, _sent) = composed("https://collector.example.com/v1/traces");
    {
        let subscriber = tracing_subscriber::registry().with(TraceLayer {
            traces: traces.clone(),
            shown: String::new(),
        });
        let _g = tracing::subscriber::set_default(subscriber);
        let span = tracing::info_span!(
            "forward",
            otel.kind = "server",
            otel.status_code = "ERROR",
            otel.status_message = "upstream refused",
            big = tracing::field::Empty,
        );
        // One field recorded over and over: `record` appends, so this drives the bound.
        for _ in 0..(MAX_ATTRIBUTES_PER_SPAN + 5) {
            span.record("big", "x");
        }
        let _e = span.enter();
    }

    let queued = traces.queue.lock().unwrap_or_else(|e| e.into_inner());
    let (record, _) = &queued[0];
    assert_eq!(
        record.attributes.len(),
        MAX_ATTRIBUTES_PER_SPAN,
        "the composer stops at the bound the SINK declared"
    );
    assert_eq!(
        record.dropped_attributes, 5,
        "what was left off is counted and carried, not silently lost"
    );
    assert_eq!(
        record.kind,
        busbar_export_otlp::SpanKind::Server,
        "`otel.kind` is a statement about the span"
    );
    assert_eq!(
        record.status,
        busbar_export_otlp::SpanStatus::Error {
            message: "upstream refused".to_string()
        },
        "`otel.status_code`/`otel.status_message` are a statement about the span"
    );
    assert!(
        !record
            .attributes
            .iter()
            .any(|(k, _)| k.starts_with("otel.")),
        "a statement about the span is never an attribute of it: {:?}",
        record.attributes
    );
}

/// A FULL QUEUE DROPS, AND THE COUNT IS THE GATE'S.
///
/// ONE queue, ONE declared bound, and the party that drops a span is the party that declared it
/// may. The retired batch processor had a queue and a drop rule of its own behind this process's
/// gate — two sheds for one stream, and the one that actually dropped spans was the one nobody
/// declared. There is no second drop counter here on purpose: every denial lands on
/// `busbar_admission_denied_total{gate="otlp"}`, uniformly with every other gate in this process.
#[test]
fn a_full_queue_drops_and_the_bound_is_the_one_the_sink_declared() {
    let (traces, sent) = composed("https://collector.example.com/v1/traces");
    let record = |n: u64| busbar_export_otlp::SpanRecord {
        trace_id: [1u8; 16],
        span_id: n.to_be_bytes(),
        parent_span_id: None,
        name: "forward".to_string(),
        kind: busbar_export_otlp::SpanKind::Internal,
        start_unix_nanos: 1,
        end_unix_nanos: 2,
        status: busbar_export_otlp::SpanStatus::Unset,
        attributes: Vec::new(),
        dropped_attributes: 0,
    };
    for n in 0..(MAX_SPANS_PER_DELIVERY as u64 + 64) {
        traces.offer(record(n + 1));
    }
    assert_eq!(
        traces.queue.lock().unwrap_or_else(|e| e.into_inner()).len(),
        MAX_SPANS_PER_DELIVERY,
        "the queue never exceeds the bound the sink declared"
    );
    assert_eq!(
        traces.drain(),
        MAX_SPANS_PER_DELIVERY,
        "the whole queue goes into ONE export request"
    );
    assert_eq!(
        traces.queue.lock().unwrap_or_else(|e| e.into_inner()).len(),
        0,
        "a drain empties the queue and returns every slot"
    );
    assert_eq!(
        sent.lock().unwrap_or_else(|e| e.into_inner()).len(),
        1,
        "one drain is one exchange, which is what makes the tick the in-flight bound"
    );

    // ...and the slots are back, so the next interval's spans are admitted again.
    traces.offer(record(9_999));
    assert_eq!(
        traces.queue.lock().unwrap_or_else(|e| e.into_inner()).len(),
        1
    );
}

/// AN EMPTY DRAIN PUTS NOTHING ON ANY WIRE. A tick that lands on an idle process must not post an
/// export request carrying no spans.
#[test]
fn an_empty_drain_sends_nothing() {
    let (traces, sent) = composed("https://collector.example.com/v1/traces");
    assert_eq!(traces.drain(), 0);
    assert!(sent.lock().unwrap_or_else(|e| e.into_inner()).is_empty());
}

// ── the oracle ───────────────────────────────────────────────────────────────────────────────

/// THE WHOLE CHAIN, READ BACK AS A COLLECTOR WOULD READ IT.
///
/// Every other cell in this file stops at the sink's door and every cell in the sink's own file
/// starts at a hand-built batch, so between them sat the one question neither could answer: does a
/// span THIS PROCESS EMITTED arrive at a collector as that span? This drives a real
/// `tracing_subscriber::Registry` with the real layer, the real gate, the real drain and the real
/// sink, takes the bytes off a fake wire, and DECODES THE PROTOBUF BACK — the resource, the scope,
/// the parent link and the span's own window and status, in the schema's own words.
///
/// IT IS NOT THE COLLECTOR FIXTURE THE DESIGN NAMED. That one runs the real binary against a
/// process that speaks OTLP and pins what crosses a socket; this one pins what crosses the wire's
/// door, which is everything this tree decides. The socket in between is the engine's egress
/// client, already proven where it lives. Stated plainly so the gap is a measurement rather than a
/// silence.
#[test]
fn a_span_this_process_emitted_decodes_as_that_span_at_a_collector() {
    use prost::Message as _;
    use tracing_subscriber::layer::SubscriberExt as _;

    let (traces, sent) = composed("https://collector.example.com/v1/traces");
    {
        let subscriber = tracing_subscriber::registry().with(TraceLayer {
            traces: traces.clone(),
            shown: String::new(),
        });
        let _g = tracing::subscriber::set_default(subscriber);
        let parent = tracing::info_span!("forward", otel.kind = "server", pool = "prod");
        let _pe = parent.enter();
        let child = tracing::info_span!(
            "attempt",
            otel.status_code = "ERROR",
            otel.status_message = "upstream refused",
            retried = true,
        );
        let _ce = child.enter();
    }
    assert_eq!(traces.drain(), 2, "two closed spans, one export request");

    let sent = sent.lock().unwrap_or_else(|e| e.into_inner());
    let decoded =
        opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest::decode(
            sent[0].2.as_slice(),
        )
        .expect("what left this process is an OTLP export request");

    let rs = &decoded.resource_spans[0];
    let resource: Vec<String> = rs
        .resource
        .as_ref()
        .expect("a collector is told what this process is")
        .attributes
        .iter()
        .map(|kv| kv.key.clone())
        .collect();
    assert_eq!(resource, vec!["service.name", "service.version"]);
    let ss = &rs.scope_spans[0];
    assert_eq!(ss.scope.as_ref().expect("one scope").name, "busbar");
    assert_eq!(ss.spans.len(), 2, "both spans ride one request");

    // The CHILD closes first, so it is first in the batch.
    let (child, parent) = (&ss.spans[0], &ss.spans[1]);
    assert_eq!(child.name, "attempt");
    assert_eq!(parent.name, "forward");
    assert_eq!(
        child.trace_id, parent.trace_id,
        "one trace reaches the collector as one trace"
    );
    assert_eq!(
        child.parent_span_id, parent.span_id,
        "the collector can rebuild the tree this process observed"
    );
    assert!(
        parent.parent_span_id.is_empty(),
        "the root of the trace says so by absence, not by a zeroed id"
    );
    assert_eq!(
        parent.kind,
        opentelemetry_proto::tonic::trace::v1::span::SpanKind::Server as i32,
        "`otel.kind` reached the wire as the schema's own kind"
    );
    assert_eq!(
        child.status.as_ref().map(|s| (s.code, s.message.clone())),
        Some((
            opentelemetry_proto::tonic::trace::v1::status::StatusCode::Error as i32,
            "upstream refused".to_string()
        )),
        "a failing span reaches the collector as a failing span"
    );
    assert!(
        parent.start_time_unix_nano > 0 && parent.end_time_unix_nano >= parent.start_time_unix_nano,
        "the window is this process's clock and it runs forwards"
    );
    assert_eq!(
        parent
            .attributes
            .iter()
            .map(|kv| kv.key.clone())
            .collect::<Vec<_>>(),
        vec!["pool"],
        "the callsite's field crossed, and the three `otel.*` statements did not become attributes"
    );
}
