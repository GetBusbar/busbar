// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The traces producer (K9a S7): what record a closed span becomes, and what a sink's projection
//! lets through. The axis delivery it feeds is the one `logs` rides (`export/plugin.rs`); the
//! dropped-in sink that receives these records end to end is driven by the composition root's
//! `export_plugin_dropped_in_serves` test.

use super::*;
use busbar_contract::abi::export::{ExportField, ExportStream};
use tracing_subscriber::layer::SubscriberExt as _;

static SEEN: std::sync::Mutex<Vec<Vec<(ExportField, Value)>>> = std::sync::Mutex::new(Vec::new());

fn capture(facts: &[(ExportField, Value)], _: Option<&Value>) {
    SEEN.lock()
        .unwrap_or_else(|e| e.into_inner())
        .push(facts.to_vec());
}

fn field(facts: &[(ExportField, Value)], f: ExportField) -> Option<&Value> {
    facts.iter().find(|(k, _)| *k == f).map(|(_, v)| v)
}

/// A closed span becomes ONE record of the stream's documented fields: its own id, its root's id
/// as the trace id, its parent's id, its name, when it started and how long it lasted, and the
/// stream fields it recorded (`pool`, `model`, …) — nothing it recorded outside the vocabulary.
/// RED: a producer that dropped the parent link (or the trace id) would fail the joins below.
#[test]
fn a_closed_span_becomes_one_record_joined_to_its_trace() {
    let subscriber = tracing_subscriber::registry().with(Producer(capture, no_records));
    tracing::subscriber::with_default(subscriber, || {
        let outer =
            tracing::debug_span!("named", pool = "p1", secret = "not-a-field", key_id = "k1");
        let _entered = outer.enter();
        tracing::debug_span!("adhoc", provider = "mock", model = %"m1").in_scope(|| {});
    });
    let seen = std::mem::take(&mut *SEEN.lock().unwrap_or_else(|e| e.into_inner()));
    assert_eq!(seen.len(), 2, "one record per closed span: {seen:?}");
    let (inner, outer) = (&seen[0], &seen[1]);
    assert_eq!(field(inner, ExportField::Name), Some(&Value::from("adhoc")));
    assert_eq!(field(inner, ExportField::Model), Some(&Value::from("m1")));
    assert_eq!(field(outer, ExportField::Pool), Some(&Value::from("p1")));
    // Only the stream's own vocabulary: an unknown field, and a field of ANOTHER stream (`key_id`
    // is `identity`'s), are not traces facts.
    assert!(outer.iter().all(|(_, v)| v != "not-a-field" && v != "k1"));
    assert_eq!(
        field(inner, ExportField::ParentSpanId),
        field(outer, ExportField::SpanId)
    );
    assert_eq!(
        field(inner, ExportField::TraceId),
        field(outer, ExportField::SpanId)
    );
    assert_eq!(
        field(outer, ExportField::TraceId),
        field(outer, ExportField::SpanId)
    );
    assert!(field(outer, ExportField::ParentSpanId).is_none());
    assert!(field(inner, ExportField::DurationUs).is_some_and(Value::is_u64));
    assert!(field(inner, ExportField::Start).is_some_and(Value::is_u64));
}

/// A sink's record is built TO ITS PROJECTION: a subscriber to `traces` without `fields:` is granted
/// the stream's documented fields; one that does not subscribe is granted nothing of it.
#[test]
fn a_traces_record_is_built_to_the_sinks_projection() {
    let facts = [
        (ExportField::TraceId, Value::from("01")),
        (ExportField::Model, Value::from("m1")),
    ];
    let mut errors = Vec::new();
    let sub = crate::export::projection::resolve_projection(
        "t",
        "m",
        Some(&[ExportStream::Traces, ExportStream::Logs]),
        Some(&["traces".to_string()]),
        None,
        false,
        &mut errors,
    );
    assert!(errors.is_empty(), "{errors:?}");
    let granted = record(sub, &facts, None);
    assert_eq!(
        *granted,
        serde_json::json!({"trace_id": "01", "model": "m1"})
    );
    let logs_only = crate::export::projection::Projection::for_test(
        &[ExportStream::Logs],
        ExportStream::Logs.default_fields(),
    );
    let ungranted = record(logs_only, &facts, None);
    assert_eq!(*ungranted, serde_json::json!({}));
}

static RECORDED: std::sync::Mutex<Vec<Vec<(ExportField, Value)>>> =
    std::sync::Mutex::new(Vec::new());

fn capture_recorded(facts: &[(ExportField, Value)], _: Option<&Value>) {
    RECORDED
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push(facts.to_vec());
}

/// A VALUE A SPAN RECORDS AFTER IT OPENED IS ONE OF ITS FACTS (status row 173): the unit's
/// `forward` opens before the plane has read the request and records its `pool`, `ingress` and
/// `op` once it has (v1.5.5 `proxy/engine/mod.rs:120` carried all three). A field recorded twice
/// keeps its last value, once. RED before the producer read recorded values: the record carried
/// none of the three.
#[test]
fn a_value_recorded_after_the_span_opened_is_one_of_its_facts() {
    let subscriber = tracing_subscriber::registry().with(Producer(capture_recorded, no_records));
    tracing::subscriber::with_default(subscriber, || {
        let span = tracing::debug_span!(
            "forward",
            pool = tracing::field::Empty,
            ingress = tracing::field::Empty,
            op = tracing::field::Empty,
            lane = tracing::field::Empty,
            request_id = tracing::field::Empty
        );
        span.record("lane", 3_u64);
        span.record("pool", "first");
        span.record("pool", "p1");
        span.record("ingress", "dialect_a");
        span.record("op", "chat");
        span.record("request_id", 7_u64);
    });
    let seen = std::mem::take(&mut *RECORDED.lock().unwrap_or_else(|e| e.into_inner()));
    assert_eq!(seen.len(), 1, "one record per closed span: {seen:?}");
    let facts = &seen[0];
    assert_eq!(
        field(facts, ExportField::Name),
        Some(&Value::from("forward"))
    );
    assert_eq!(field(facts, ExportField::Pool), Some(&Value::from("p1")));
    assert_eq!(
        field(facts, ExportField::Ingress),
        Some(&Value::from("dialect_a"))
    );
    assert_eq!(field(facts, ExportField::Op), Some(&Value::from("chat")));
    assert_eq!(
        field(facts, ExportField::Lane),
        Some(&Value::from("3")),
        "a `u64` field is its text, as 1.5.5's exporter wrote it (0.33 has no `record_u64`)"
    );
    assert_eq!(
        facts
            .iter()
            .filter(|(f, _)| *f == ExportField::Pool)
            .count(),
        1,
        "a field recorded twice is one fact: {facts:?}"
    );
}

/// No sink takes full span records.
fn no_records() -> bool {
    false
}

/// Some sink takes full span records.
fn records() -> bool {
    true
}

static FULL: std::sync::Mutex<Vec<Value>> = std::sync::Mutex::new(Vec::new());

fn capture_full(_: &[(ExportField, Value)], span: Option<&Value>) {
    FULL.lock()
        .unwrap_or_else(|e| e.into_inner())
        .extend(span.cloned());
}

/// THE FULL SPAN RECORD (status row 173; K9e-2): what the previous release's
/// tracing-opentelemetry 0.33 layer exported for a span, in its attribute order and types: the
/// code location, `thread.id` (an integer), `thread.name`, `target`, the span's fields as recorded
/// (a `u64` its text), then `busy_ns` and `idle_ns` (integers); each event in it with `level`,
/// `target`, its fields and its code location; its status, an error once an ERROR event lands; its
/// start and its end in nanoseconds. RED before the producer kept it: no record at all.
#[test]
fn a_span_record_carries_what_the_previous_exporter_sent() {
    let subscriber = tracing_subscriber::registry().with(Producer(capture_full, records));
    tracing::subscriber::with_default(subscriber, || {
        let span = tracing::span!(
            target: "busbar::proxy::engine",
            tracing::Level::DEBUG,
            "forward",
            pool = "p1",
            op = tracing::field::Empty,
            request_id = tracing::field::Empty
        );
        span.record("request_id", 7_u64);
        {
            let _entered = span.enter();
            tracing::warn!(hint = 1_i64, "slow");
        }
        drop(span);
        let failing = tracing::debug_span!("failing");
        failing.in_scope(|| tracing::error!("broke"));
    });
    let seen = std::mem::take(&mut *FULL.lock().unwrap_or_else(|e| e.into_inner()));
    assert_eq!(seen.len(), 2, "{seen:?}");
    let keys = |v: &Value| -> Vec<String> {
        v.as_array()
            .map(|a| {
                a.iter()
                    .map(|kv| kv["key"].as_str().unwrap_or_default().to_string())
                    .collect()
            })
            .unwrap_or_default()
    };
    let value = |v: &Value, key: &str| -> Value {
        v.as_array()
            .and_then(|a| a.iter().find(|kv| kv["key"] == key))
            .map_or(Value::Null, |kv| kv["value"].clone())
    };
    let forward = &seen[0];
    assert_eq!(forward["name"], "forward");
    assert_eq!(
        keys(&forward["attributes"]),
        [
            "code.file.path",
            "code.module.name",
            "code.line.number",
            "thread.id",
            "thread.name",
            "target",
            "pool",
            "request_id",
            "busy_ns",
            "idle_ns"
        ]
    );
    let attributes = &forward["attributes"];
    assert_eq!(value(attributes, "target"), "busbar::proxy::engine");
    assert_eq!(value(attributes, "pool"), "p1");
    assert_eq!(value(attributes, "request_id"), "7", "a u64 is its text");
    assert!(value(attributes, "thread.id").is_i64());
    assert!(value(attributes, "code.line.number").is_i64());
    assert!(value(attributes, "busy_ns").is_i64());
    assert!(value(attributes, "idle_ns").is_i64());
    assert!(forward["end_ns"].as_u64() >= forward["start_ns"].as_u64());
    assert_eq!(forward["status"]["code"], "unset");
    let event = &forward["events"][0];
    assert_eq!(event["name"], "slow");
    assert_eq!(
        keys(&event["attributes"]),
        [
            "level",
            "target",
            "hint",
            "code.file.path",
            "code.module.name",
            "code.line.number"
        ]
    );
    assert_eq!(value(&event["attributes"], "level"), "WARN");
    assert_eq!(value(&event["attributes"], "hint"), 1);
    assert_eq!(
        seen[1]["status"]["code"], "error",
        "an ERROR event marks it"
    );
}

static FIRST: std::sync::Mutex<Vec<Vec<(ExportField, Value)>>> = std::sync::Mutex::new(Vec::new());

fn capture_first(facts: &[(ExportField, Value)], _: Option<&Value>) {
    FIRST
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push(facts.to_vec());
}

/// A span's export id is unique ACROSS processes, not only within one: the OTLP backend joins on
/// trace and span ids, so a restarted (or second) busbar that minted ids from 1 again would merge
/// its traces into the previous run's (the previous release sent random ids). The ids start at a
/// value drawn from OS entropy once per process, so a test process that has opened only a handful
/// of spans does not hold a small id (the chance a random start lands below 2^32 is 2^-32).
/// RED: a counter that starts at a fixed 1 mints ids 1, 2, 3, … in every process.
#[test]
fn span_ids_do_not_restart_from_a_fixed_value_in_each_process() {
    let subscriber = tracing_subscriber::registry().with(Producer(capture_first, no_records));
    tracing::subscriber::with_default(subscriber, || {
        tracing::debug_span!("first").in_scope(|| {});
    });
    let seen = std::mem::take(&mut *FIRST.lock().unwrap_or_else(|e| e.into_inner()));
    let id = field(&seen[0], ExportField::SpanId)
        .and_then(Value::as_str)
        .and_then(|h| u64::from_str_radix(h, 16).ok())
        .expect("a span id in hex");
    assert!(
        id > u64::from(u32::MAX),
        "span id {id} is a small fixed-start counter value: every process mints the same ids"
    );
}
