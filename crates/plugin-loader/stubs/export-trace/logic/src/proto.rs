// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE `traces` BATCH → ONE OTLP/HTTP protobuf `ExportTraceServiceRequest`
//! (`opentelemetry/proto/collector/trace/v1/trace_service.proto`, OTLP 1.x), encoded here by hand:
//! the handful of messages it takes do not justify a code generator in the binary.
//!
//! The request is `resource_spans[1]`: `resource.attributes = [service.name = "busbar"]`, one
//! `scope_spans` whose `scope.name` is `busbar`, and one `Span` per record, in batch order:
//!
//! | record field | `Span` field |
//! |---|---|
//! | `trace_id` (16 hex digits) | `trace_id` (1): 16 bytes, the id's 8 big-endian bytes after 8 zero bytes |
//! | `span_id` | `span_id` (2): its 8 big-endian bytes |
//! | `parent_span_id` | `parent_span_id` (4), when present |
//! | `name` | `name` (5) |
//! | — | `kind` (6): `SPAN_KIND_INTERNAL` |
//! | `start` (epoch µs) | `start_time_unix_nano` (7) |
//! | `start` + `duration_us` | `end_time_unix_nano` (8) |
//! | `pool` `ingress` `op` `lane` `provider` `model` | `attributes` (9), in that order, string values |
//!
//! Proto3 rules, as every conforming encoder writes them: fields in field-number order, a field at
//! its default (empty, zero) left off, a `oneof` member written whenever it is set. A record with no
//! usable `trace_id` or `span_id` is no span; a batch with no span encodes to nothing.

use serde_json::Value;

/// The OTLP resource's `service.name`, and the instrumentation scope's name.
pub const SERVICE: &str = "busbar";
/// The record fields that become span attributes, in the order they are written.
pub const ATTRIBUTES: [&str; 6] = ["pool", "ingress", "op", "lane", "provider", "model"];
/// `SPAN_KIND_INTERNAL`.
const SPAN_KIND_INTERNAL: u64 = 1;

/// Protobuf wire types.
const VARINT: u32 = 0;
const FIXED64: u32 = 1;
const LEN: u32 = 2;

/// The encoded `ExportTraceServiceRequest` carrying each of `records` that is a span, in order, or
/// `None` when none of them carries a usable span identity.
pub fn export_request<'a>(records: impl IntoIterator<Item = &'a Value>) -> Option<Vec<u8>> {
    let mut scope = Vec::new();
    string(&mut scope, 1, SERVICE);
    let mut scope_spans = Vec::new();
    message(&mut scope_spans, 1, &scope);
    let mut spans = 0usize;
    for span in records.into_iter().filter_map(span) {
        message(&mut scope_spans, 2, &span);
        spans += 1;
    }
    if spans == 0 {
        return None;
    }
    let mut resource = Vec::new();
    message(&mut resource, 1, &key_value("service.name", SERVICE));
    let mut resource_spans = Vec::new();
    message(&mut resource_spans, 1, &resource);
    message(&mut resource_spans, 2, &scope_spans);
    let mut request = Vec::new();
    message(&mut request, 1, &resource_spans);
    Some(request)
}

/// Whether `record` carries a usable span identity (it is a span [`export_request`] encodes).
pub fn is_span(record: &Value) -> bool {
    span(record).is_some()
}

/// The record's `Span` message.
fn span(record: &Value) -> Option<Vec<u8>> {
    let trace_id = id(record.get("trace_id")?)?;
    let span_id = id(record.get("span_id")?)?;
    let parent = record.get("parent_span_id").and_then(id);
    let text = |key: &str| record.get(key).and_then(Value::as_str).unwrap_or_default();
    let micros = |key: &str| record.get(key).and_then(Value::as_u64).unwrap_or_default();
    let start = micros("start").saturating_mul(1000);
    let end = start.saturating_add(micros("duration_us").saturating_mul(1000));

    let mut out = Vec::new();
    let mut trace = [0u8; 16];
    trace[8..].copy_from_slice(&trace_id);
    bytes(&mut out, 1, &trace);
    bytes(&mut out, 2, &span_id);
    if let Some(parent) = parent {
        bytes(&mut out, 4, &parent);
    }
    string(&mut out, 5, text("name"));
    varint_field(&mut out, 6, SPAN_KIND_INTERNAL);
    fixed64(&mut out, 7, start);
    fixed64(&mut out, 8, end);
    for key in ATTRIBUTES {
        let value = match record.get(key) {
            None | Some(Value::Null) => continue,
            Some(Value::String(s)) => s.clone(),
            Some(other) => other.to_string(),
        };
        message(&mut out, 9, &key_value(key, &value));
    }
    Some(out)
}

/// A record's span id — 16 hex digits — as its 8 big-endian bytes; `None` when it is not one, or
/// is zero (the invalid id in OTLP).
fn id(value: &Value) -> Option<[u8; 8]> {
    let text = value.as_str()?;
    if text.is_empty() || text.len() > 16 {
        return None;
    }
    let n = u64::from_str_radix(text, 16).ok().filter(|n| *n != 0)?;
    Some(n.to_be_bytes())
}

/// A `KeyValue { key, value: AnyValue { string_value } }`.
fn key_value(key: &str, value: &str) -> Vec<u8> {
    let mut any = Vec::new();
    // `AnyValue.value` is a oneof: its member is written even when it is the empty string.
    tag(&mut any, 1, LEN);
    varint(&mut any, value.len() as u64);
    any.extend_from_slice(value.as_bytes());
    let mut kv = Vec::new();
    string(&mut kv, 1, key);
    message(&mut kv, 2, &any);
    kv
}

fn tag(out: &mut Vec<u8>, field: u32, wire: u32) {
    varint(out, u64::from((field << 3) | wire));
}

fn varint(out: &mut Vec<u8>, mut n: u64) {
    while n >= 0x80 {
        out.push((n as u8) | 0x80);
        n >>= 7;
    }
    out.push(n as u8);
}

fn varint_field(out: &mut Vec<u8>, field: u32, n: u64) {
    if n != 0 {
        tag(out, field, VARINT);
        varint(out, n);
    }
}

fn fixed64(out: &mut Vec<u8>, field: u32, n: u64) {
    if n != 0 {
        tag(out, field, FIXED64);
        out.extend_from_slice(&n.to_le_bytes());
    }
}

fn bytes(out: &mut Vec<u8>, field: u32, b: &[u8]) {
    if !b.is_empty() {
        tag(out, field, LEN);
        varint(out, b.len() as u64);
        out.extend_from_slice(b);
    }
}

fn string(out: &mut Vec<u8>, field: u32, s: &str) {
    bytes(out, field, s.as_bytes());
}

/// An embedded message — written even when empty, as a set message field is.
fn message(out: &mut Vec<u8>, field: u32, encoded: &[u8]) {
    tag(out, field, LEN);
    varint(out, encoded.len() as u64);
    out.extend_from_slice(encoded);
}
