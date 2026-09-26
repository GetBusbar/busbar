// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The traces producer (K9a S7): what record a closed span becomes, and what a sink's projection
//! lets through. The axis delivery it feeds is the one `logs` rides (`export/plugin.rs`); the
//! dropped-in sink that receives these records end to end is driven by the composition root's
//! `export_plugin_dropped_in_serves` test.

use super::*;
use busbar_plugin_loader::{ExportField, ExportStream};
use tracing_subscriber::layer::SubscriberExt as _;

static SEEN: std::sync::Mutex<Vec<Vec<(ExportField, Value)>>> = std::sync::Mutex::new(Vec::new());

fn capture(facts: &[(ExportField, Value)]) {
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
    let subscriber = tracing_subscriber::registry().with(Producer(capture));
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
    let granted = record(sub, &facts);
    assert_eq!(
        *granted,
        serde_json::json!({"trace_id": "01", "model": "m1"})
    );
    let logs_only = crate::export::projection::Projection::for_test(
        &[ExportStream::Logs],
        ExportStream::Logs.default_fields(),
    );
    let ungranted = record(logs_only, &facts);
    assert_eq!(*ungranted, serde_json::json!({}));
}
