// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![forbid(unsafe_code)]

//! The built-in **`otlp`** export sink: frame one drained batch of finished spans as ONE
//! OTLP export request, and say what came back of it.
//!
//! # What this crate is, and what it deliberately is not
//!
//! It is a sink of kind `export`, the same object the file, webhook and prometheus sinks are, and
//! it implements the same four-method face they do. It takes an already-serialized record for the
//! `traces` stream and states the delivery that carries it. It does not open the socket, it does
//! not hold a queue, it does not decide whether there is room, and it does not capture a span: all
//! four of those belong to the process this sink was composed into.
//!
//! ## What this replaces, and why that matters more than what it adds
//!
//! Before this crate, OTLP was `opentelemetry_sdk::trace::SdkTracerProvider` with a BATCH exporter
//! behind `tracing_opentelemetry::layer()`, built in the composition root. That processor carried
//! its own queue, its own flush cadence, its own drop-on-full rule and its own shutdown — none of
//! which the process could see. Every other sink in this tree is shed for by ONE
//! composer-owned gate, against a bound the sink declares. An OTLP sink presented as an export
//! while that processor still existed would have been a sink with a SECOND queue behind the
//! composer's gate: two shed policies for one stream, and the one that actually dropped spans is
//! the one nobody declared. So the SDK's queue is deleted rather than wrapped, and what is left
//! here is framing — which is all a sink ever was.
//!
//! That deletion is what makes the acknowledgement mean something. Against a batch processor,
//! [`Ack::Received`] would have answered for an ENQUEUE and never for a delivery: the same word
//! forever, carrying no information, which is worse than none. Here it answers for exactly one
//! thing — whether the host's wire took the framed request — and [`Ack::Retry`] answers for the two
//! ways it did not.
//!
//! # Why this crate has dependencies when its three siblings have none
//!
//! Stated in `Cargo.toml` beside the dependencies themselves, and repeated here because it is the
//! first thing about this crate a reader will notice: OTLP is protobuf against a schema the
//! OpenTelemetry project publishes. A sink that framed that schema out of the standard library
//! would be a hand-written copy of a wire fact. It names `opentelemetry-proto` (the generated
//! message types), `prost` (the protobuf runtime), and `serde`/`serde_json` for the record shape
//! the composer fills. It names NO exporter, NO SDK, NO subscriber and NO client.
//!
//! # The record shape is declared here because this sink is the party that reads it
//!
//! [`ExportItem`] hands a sink BYTES — already serialized, already bounded by a projection resolved
//! from the operator's document long before it got here. For the `traces` stream those bytes are a
//! JSON array of [`SpanRecord`], and [`SpanRecord`] is declared on this crate rather than spelled
//! twice: a composer FILLS the shape the sink READS, so there is exactly one declaration of it and
//! nothing to drift.

use busbar_contract::{
    AbiVersion, Ack, Delivery, Export, ExportHost, ExportItem, Kind, Plugin, RouteStatement,
    ServeRequest, Served, EXPORT_ABI,
};
use prost::Message as _;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::{any_value, AnyValue, InstrumentationScope, KeyValue};
use opentelemetry_proto::tonic::resource::v1::Resource;
use opentelemetry_proto::tonic::trace::v1::{
    span, status, ResourceSpans, ScopeSpans, Span, Status,
};

/// The operator's `module:` token for this sink.
pub const MODULE: &str = "otlp";

/// The label this sink's composer names its capacity gate with on the shared
/// `busbar_admission_denied_total{gate="..."}` series. Stated by the sink so the label is never a
/// string the composer invented about an instance it is shedding for.
pub const GATE: &str = "otlp";

/// The ONE stream this sink carries, in the frozen export vocabulary's own token.
pub const STREAM: &str = "traces";

/// THE BATCH BOUND THIS SINK DECLARES: how many finished spans may be waiting for the next delivery
/// before the composer starts dropping them. The composer sheds against it with a gate of its own
/// and counts every denial on `busbar_admission_denied_total{gate="otlp"}`, exactly as it does for
/// the file and webhook sinks — ONE queue, ONE declared bound, and the party that drops a span is
/// the party that declared it may.
pub const MAX_SPANS_PER_DELIVERY: usize = 512;

/// THE ATTRIBUTE BOUND THIS SINK DECLARES: how many attributes of one span may cross. A span with
/// more is carried with the first [`MAX_ATTRIBUTES_PER_SPAN`] and a non-zero
/// [`SpanRecord::dropped_attributes`], which is the OTLP schema's own way of saying so — the
/// receiving collector is told the span was truncated rather than shown a complete-looking one.
pub const MAX_ATTRIBUTES_PER_SPAN: usize = 64;

/// The media type an OTLP protobuf export request rides under, and the header it rides on. There
/// is no negotiation here and no setting — the binding names exactly one encoding — so it is a
/// constant of the sink rather than of its composer.
const CONTENT_TYPE: (&str, &str) = ("content-type", "application/x-protobuf");

/// The instrumentation scope every span this process exports is attributed to.
const SCOPE_NAME: &str = "busbar";

/// ONE SPAN, as the composer read it off this process and serialized it.
///
/// Every field is a FACT THE COMPOSER OBSERVED. This sink derives none of them and asks for none it
/// was not given: it has no clock, no registry, no subscriber and no random source, so a span it
/// was not handed is a span it cannot invent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpanRecord {
    /// The W3C trace id, 16 bytes. Shared by every span of one trace.
    pub trace_id: [u8; 16],
    /// This span's own id, 8 bytes.
    pub span_id: [u8; 8],
    /// The id of the span this one was entered under, when there was one. `None` is a ROOT span,
    /// and is carried to the wire as the schema's empty parent — never as eight zero bytes the
    /// composer made up.
    pub parent_span_id: Option<[u8; 8]>,
    /// The span's name, as the callsite declared it.
    pub name: String,
    /// What KIND of operation it was.
    pub kind: SpanKind,
    /// When it was entered, in nanoseconds since the Unix epoch.
    pub start_unix_nanos: u64,
    /// When it closed, in nanoseconds since the Unix epoch.
    pub end_unix_nanos: u64,
    /// What the callsite said about the outcome.
    pub status: SpanStatus,
    /// The span's attributes, ALREADY BOUNDED by the composer (see [`MAX_ATTRIBUTES_PER_SPAN`]).
    pub attributes: Vec<(String, AttrValue)>,
    /// How many attributes the composer left off because the bound was reached. Carried to the
    /// wire so a collector sees a truncated span as truncated.
    pub dropped_attributes: u32,
}

/// What KIND of operation a span covers, in the OTLP schema's own closed set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpanKind {
    /// Internal to this process.
    Internal,
    /// This process answering an inbound request.
    Server,
    /// This process making an outbound request.
    Client,
    /// This process putting a message on a queue.
    Producer,
    /// This process taking a message off a queue.
    Consumer,
}

/// What the callsite said about a span's outcome, in the OTLP schema's own closed set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpanStatus {
    /// Nothing was said. NOT the same fact as `Ok`, and carried as a different one.
    Unset,
    /// The operation succeeded.
    Ok,
    /// The operation failed, with what the callsite said about it.
    Error {
        /// The failure message, bounded by the composer.
        message: String,
    },
}

/// One attribute value, in the subset of the OTLP `AnyValue` union a `tracing` field can be.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttrValue {
    /// A string.
    Str(String),
    /// A signed integer.
    Int(i64),
    /// A boolean.
    Bool(bool),
}

/// Something one delivery did that the sink cannot act on itself, handed to whoever composed it.
///
/// The three variants are three DIFFERENT facts, and that is the whole of what this sink judges: a
/// collector that is briefly unavailable is not a collector that is misconfigured, and an operator
/// reading a log line is entitled to be told which one happened.
pub enum Event<'a> {
    /// The collector answered with a status that says THIS EXPORT WILL NEVER SUCCEED as configured
    /// — a bad endpoint path, a rejected credential, a payload the collector refuses. Worth one
    /// loud line, because retrying it forever would only hide it.
    Refused {
        /// The status the collector answered with.
        status: u16,
    },
    /// The collector answered with a status that says TRY AGAIN — it is overloaded, restarting or
    /// briefly gone. This batch is still dropped (see the crate docs: a retry queue in front of a
    /// telemetry sink is a memory leak with a deadline), but it is not a misconfiguration.
    Unavailable {
        /// The status the collector answered with.
        status: u16,
    },
    /// The delivery never got an answer at all.
    TransportError {
        /// A URL-FREE description of what went wrong. The composer supplies these from its own
        /// transport, which does not carry the target in its error type.
        error: &'a str,
    },
    /// The composer handed this sink bytes that are not a span batch. Structurally unreachable —
    /// the only producer is the composer's own layer — and reported rather than silently dropped
    /// so a wire that ever did drift says so.
    MalformedBatch {
        /// What the decode said.
        error: &'a str,
    },
}

/// What this process does with what a delivery reports. One method, so a composer that adds a
/// counter to one arm cannot silently leave the sibling arms unrecorded.
pub trait Report: Send + Sync {
    /// Handle one report. Called on the drain's own task, never on the request path.
    fn report(&self, event: Event<'_>);
}

/// A [`Report`] that drops every event — for a composer that wants the framing and nothing else,
/// and for tests that are not about reporting.
pub struct Silent;

impl Report for Silent {
    fn report(&self, _event: Event<'_>) {}
}

/// WHETHER A COLLECTOR'S ANSWER SAYS "TRY AGAIN" OR "THIS WILL NEVER WORK", which is POLICY and is
/// therefore decided here rather than by whoever runs the send.
///
/// `429` and `503` are the OTLP specification's own throttling answers; `408` is a timeout the
/// collector itself declared; every other `5xx` is a server that failed at something transient.
/// Everything else in the `4xx` range is a statement about the REQUEST — the path, the credential,
/// the encoding — and no number of retries changes any of those.
pub fn retryable(status: u16) -> bool {
    matches!(status, 408 | 429) || (500..600).contains(&status)
}

/// One configured OTLP collector: where a batch goes, what rides with it, and what this process
/// calls itself on the wire.
pub struct OtlpSink {
    target: String,
    headers: Vec<(String, String)>,
    resource: Vec<(String, String)>,
    report: Arc<dyn Report>,
}

impl OtlpSink {
    /// Build a sink over an ALREADY-VALIDATED, ALREADY-CREDENTIAL-FREE target.
    ///
    /// `target` is the endpoint every export request is addressed to and carries NO userinfo: the
    /// composer split any embedded credential out of the URL and into `headers` before this sink
    /// existed, which is why this crate holds no masker and has nothing to leak into an [`Event`]
    /// (none of its events names the target at all). `resource` is what this process calls itself
    /// — the OTLP resource attributes — read off the composition, because a sink does not know what
    /// binary it was linked into.
    pub fn new(
        target: String,
        headers: Vec<(String, String)>,
        resource: Vec<(String, String)>,
        report: Arc<dyn Report>,
    ) -> Self {
        Self {
            target,
            headers,
            resource,
            report,
        }
    }

    /// FRAME ONE BATCH: the whole of what this sink decides about putting spans on a wire.
    ///
    /// Pure — no I/O, no clock, no randomness. One `ExportTraceServiceRequest`, one `ResourceSpans`
    /// carrying this process's resource, one `ScopeSpans` carrying every span of the batch, encoded
    /// with the protobuf runtime the schema is generated for.
    ///
    /// PRIVATE: the only way into this sink is [`Export::receive`]. A framing a composer could
    /// reach around the face to call is a second entry point, and two entry points are two
    /// behaviours a month later.
    fn delivery(&self, batch: &[SpanRecord]) -> Delivery {
        let request = ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                resource: Some(Resource {
                    attributes: self
                        .resource
                        .iter()
                        .map(|(k, v)| {
                            key_value(
                                k,
                                AnyValue {
                                    value: Some(any_value::Value::StringValue(v.clone())),
                                },
                            )
                        })
                        .collect(),
                    ..Default::default()
                }),
                scope_spans: vec![ScopeSpans {
                    scope: Some(InstrumentationScope {
                        name: SCOPE_NAME.to_string(),
                        ..Default::default()
                    }),
                    spans: batch.iter().map(proto_span).collect(),
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };
        let mut headers = vec![(CONTENT_TYPE.0.to_string(), CONTENT_TYPE.1.to_string())];
        headers.extend(self.headers.iter().cloned());
        Delivery {
            target: self.target.clone(),
            headers,
            body: request.encode_to_vec(),
        }
    }

    /// What came back of one export request. `Ok` carries the answered status, `Err` a URL-free
    /// cause. A success status is the only outcome that reports nothing.
    pub fn observe(&self, outcome: Result<u16, String>) {
        match outcome {
            Ok(status) if (200..300).contains(&status) => {}
            Ok(status) if retryable(status) => self.report.report(Event::Unavailable { status }),
            Ok(status) => self.report.report(Event::Refused { status }),
            Err(error) => self.report.report(Event::TransportError { error: &error }),
        }
    }
}

/// One protobuf key/value pair.
fn key_value(key: &str, value: AnyValue) -> KeyValue {
    KeyValue {
        key: key.to_string(),
        value: Some(value),
        ..Default::default()
    }
}

/// One observed span, in the schema's own words. Every field this sink does not have a fact for is
/// left at the schema's default rather than filled with a guess.
fn proto_span(record: &SpanRecord) -> Span {
    Span {
        trace_id: record.trace_id.to_vec(),
        span_id: record.span_id.to_vec(),
        // A ROOT SPAN CARRIES AN EMPTY PARENT, not eight zero bytes: the schema spells "no parent"
        // as an absent field, and a zeroed id is a span id that a collector may try to link.
        parent_span_id: record
            .parent_span_id
            .map(|p| p.to_vec())
            .unwrap_or_default(),
        name: record.name.clone(),
        kind: match record.kind {
            SpanKind::Internal => span::SpanKind::Internal,
            SpanKind::Server => span::SpanKind::Server,
            SpanKind::Client => span::SpanKind::Client,
            SpanKind::Producer => span::SpanKind::Producer,
            SpanKind::Consumer => span::SpanKind::Consumer,
        } as i32,
        start_time_unix_nano: record.start_unix_nanos,
        end_time_unix_nano: record.end_unix_nanos,
        attributes: record
            .attributes
            .iter()
            .map(|(k, v)| {
                key_value(
                    k,
                    AnyValue {
                        value: Some(match v {
                            AttrValue::Str(s) => any_value::Value::StringValue(s.clone()),
                            AttrValue::Int(i) => any_value::Value::IntValue(*i),
                            AttrValue::Bool(b) => any_value::Value::BoolValue(*b),
                        }),
                    },
                )
            })
            .collect(),
        dropped_attributes_count: record.dropped_attributes,
        status: Some(match &record.status {
            SpanStatus::Unset => Status {
                message: String::new(),
                code: status::StatusCode::Unset as i32,
            },
            SpanStatus::Ok => Status {
                message: String::new(),
                code: status::StatusCode::Ok as i32,
            },
            SpanStatus::Error { message } => Status {
                message: message.clone(),
                code: status::StatusCode::Error as i32,
            },
        }),
        ..Default::default()
    }
}

impl Plugin for OtlpSink {
    fn key(&self) -> &'static str {
        MODULE
    }
    fn kind(&self) -> Kind {
        Kind::Export
    }
    fn abi(&self) -> AbiVersion {
        EXPORT_ABI
    }
}

/// THE FACE. What this sink carries, what it does with a record of it, and — because it is a PUSH
/// sink and is delivered to rather than scraped — the two halves of the face that say so by being
/// empty.
impl Export for OtlpSink {
    /// Distributed traces, in the frozen export vocabulary's own token. Stated by the sink, so a
    /// composer routes nothing to it that it never said it would take.
    fn streams(&self) -> &'static [&'static str] {
        &[STREAM]
    }

    /// Frame one drained batch as this collector's export request and put it on the wire the HOST
    /// lends for the length of this call. The framing is this sink's and the socket is the host's,
    /// which is the same division every other push sink of this kind makes.
    ///
    /// The ACK is what actually happened, and it can say that only because there is no queue behind
    /// it any more. [`Ack::Received`] means the host's wire took the framed request; this sink
    /// never learns whether the collector stored it, so `Durable` is a word it may never say.
    /// [`Ack::Retry`] means either the host took it nowhere or the bytes were not a span batch —
    /// two ways of not having taken the record, and neither of them is `Received`.
    fn receive(&self, item: ExportItem<'_>, host: &dyn ExportHost) -> Ack {
        let batch: Vec<SpanRecord> = match serde_json::from_slice(item.bytes) {
            Ok(b) => b,
            Err(e) => {
                self.report.report(Event::MalformedBatch {
                    error: &e.to_string(),
                });
                return Ack::Retry;
            }
        };
        if host.send(self.delivery(&batch)) {
            Ack::Received
        } else {
            Ack::Retry
        }
    }

    /// None. A push sink is delivered to; it is not scraped, and it claims no path on this
    /// process's front door.
    fn routes(&self) -> &'static [RouteStatement] {
        &[]
    }

    /// Unreachable: a host only dispatches to a route the sink declared, and this sink declares
    /// none. Answered rather than panicked, because a sink is not the party that decides what a
    /// host does with a request nobody claimed.
    fn serve(&self, _req: &ServeRequest<'_>, _host: &dyn ExportHost) -> Served {
        Served {
            status: 404,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
