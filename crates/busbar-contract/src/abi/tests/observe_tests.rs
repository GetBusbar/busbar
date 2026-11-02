// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the uniform observability envelope (#85).

use super::*;
use serde_json::json;

/// THE FIXED POINT. `PluginMetric` is the hook kind's frozen metric shape generalized, and the hook

#[test]
fn plugin_metric_reads_the_hook_metric_wire_form_unchanged() {
    let raw = json!({
        "name": "tokens_saved_total",
        "type": "counter",
        "value": 42.0,
        "labels": {"strategy": "dedupe", "model": "m"},
        "quantiles": {"0.95": 12.5},
        "buckets": {"0.5": 1.0, "+Inf": 3.0},
        "estimated": true,
        "ci_low": 1.0,
        "ci_high": 9.0,
        "help": "tokens saved",
        "label": "Saved",
        "unit": "ms",
        "viz": "sparkline",
        "max": 100.0
    });
    let m: PluginMetric = serde_json::from_value(raw).expect("the hook wire form still decodes");
    assert_eq!(m.name, "tokens_saved_total");

    assert_eq!(m.kind, "counter");
    assert_eq!(m.value, 42.0);
    assert_eq!(m.labels.as_ref().expect("labels").len(), 2);
    assert_eq!(m.quantiles.as_ref().expect("quantiles")["0.95"], 12.5);
    assert_eq!(m.buckets.as_ref().expect("buckets")["+Inf"], 3.0);
    assert_eq!(m.estimated, Some(true));
    assert_eq!((m.ci_low, m.ci_high), (Some(1.0), Some(9.0)));
    assert_eq!(m.help.as_deref(), Some("tokens saved"));
    assert_eq!(m.label.as_deref(), Some("Saved"));
    assert_eq!(m.unit.as_deref(), Some("ms"));
    assert_eq!(m.viz.as_deref(), Some("sparkline"));
    assert_eq!(m.max, Some(100.0));
}

/// The MINIMAL entry — `{name, type}` — is what the simplest plugin sends, and `value` defaults to

#[test]
fn plugin_metric_accepts_the_minimal_entry() {
    let m: PluginMetric =
        serde_json::from_value(json!({"name": "x_total", "type": "counter"})).expect("minimal");
    assert_eq!(m.value, 0.0);
    assert!(m.labels.is_none());
}

/// A plugin may send members this build does not know — a newer plugin against an older host — and

#[test]
fn plugin_metric_ignores_unknown_members() {
    let m: PluginMetric = serde_json::from_value(
        json!({"name": "x_total", "type": "counter", "series": [1, 2, 3], "future": {}}),
    )
    .expect("unknown members are ignored");
    assert_eq!(m.name, "x_total");
}

/// The SERIALIZED form omits every unset optional, so the common `{name, type, value}` sample costs

#[test]
fn plugin_metric_serializes_without_unset_optionals() {
    let s = serde_json::to_string(&PluginMetric::counter("x_total", 1.0)).expect("serialize");
    assert_eq!(s, r#"{"name":"x_total","type":"counter","value":1.0}"#);
}

/// A builder-built sample round-trips to exactly what it says.
#[test]
fn plugin_metric_builders_produce_the_declared_sample() {
    let m = PluginMetric::gauge("queue_depth", 7.0)
        .label("sink", "audit")
        .help("depth");
    let v = serde_json::to_value(&m).expect("serialize");
    assert_eq!(
        v,
        json!({"name":"queue_depth","type":"gauge","value":7.0,"labels":{"sink":"audit"},"help":"depth"})
    );
    let back: PluginMetric = serde_json::from_value(v).expect("round trip");
    assert_eq!(back, m);
}

/// The envelope's WIRE FORM, pinned. A plugin author in C/Go/Zig matches these three keys literally,

#[test]
fn envelope_wire_form_is_pinned() {
    let e = Envelope {
        result: json!({"Streams": ["logs"]}),
        metrics: vec![json!({"name": "a_total", "type": "counter", "value": 1})],
        diagnostics: vec![json!({"code": "BUSBAR-0001"})],
    };
    assert_eq!(
        serde_json::to_string(&e).expect("serialize"),
        r#"{"result":{"Streams":["logs"]},"metrics":[{"name":"a_total","type":"counter","value":1}],"diagnostics":[{"code":"BUSBAR-0001"}]}"#
    );
}

/// THE COMMON CASE COSTS NOTHING. A plugin with nothing to report emits only `result` — the two

#[test]
fn a_bare_envelope_carries_only_the_result() {
    let e = Envelope::bare(json!({"Delivered": null}));
    assert!(e.is_bare());
    assert_eq!(
        serde_json::to_string(&e).expect("serialize"),
        r#"{"result":{"Delivered":null}}"#
    );
}

/// And it decodes back: an absent `metrics`/`diagnostics` is an EMPTY one, never a decode failure.

#[test]
fn an_absent_back_channel_decodes_as_empty() {
    let e: Envelope<serde_json::Value> =
        serde_json::from_str(r#"{"result":"Delivered"}"#).expect("decode");
    assert!(e.is_bare());
    assert_eq!(e.result, json!("Delivered"));
}

/// A DIAGNOSTIC's minimal entry is its code alone, read at `warn` — the level the catalogue mostly

#[test]
fn plugin_diagnostic_defaults_to_warn() {
    let d: PluginDiagnostic = serde_json::from_value(json!({"code": "BUSBAR-1234"})).expect("min");
    assert_eq!(d.level, DiagLevel::Warn);
    assert_eq!(d.message, "");
    assert!(d.fields.is_empty());
}

/// The diagnostic wire form, pinned, including the snake_case level tokens.
#[test]
fn plugin_diagnostic_wire_form_is_pinned() {
    let d = PluginDiagnostic::new("BUSBAR-1234", DiagLevel::Error, "it broke").field("path", "/x");
    assert_eq!(
        serde_json::to_string(&d).expect("serialize"),
        r#"{"code":"BUSBAR-1234","level":"error","message":"it broke","fields":{"path":"/x"}}"#
    );
}

/// Every level's token is the one `as_token` names, so a host log line and the wire cannot drift.
#[test]
fn diag_level_tokens_match_serde() {
    for lvl in [
        DiagLevel::Error,
        DiagLevel::Warn,
        DiagLevel::Info,
        DiagLevel::Debug,
    ] {
        let wire = serde_json::to_string(&lvl).expect("serialize");
        assert_eq!(wire, format!("\"{}\"", lvl.as_token()));
    }
}

/// K9c: a diagnostic's fields attached OUT of key order carry that order (`order`), which a host

#[test]
fn a_diagnostics_attach_order_rides_the_wire_only_when_it_is_not_key_order() {
    let d = PluginDiagnostic::warn("BUSBAR-1", "m")
        .field("webhook_url", "u")
        .field("status", "503");
    let wire = serde_json::to_value(&d).unwrap();
    assert_eq!(wire["order"], serde_json::json!(["webhook_url", "status"]));
    assert_eq!(
        d.ordered_fields(),
        vec![
            ("webhook_url".to_string(), "u".to_string()),
            ("status".to_string(), "503".to_string())
        ]
    );
    let sorted = PluginDiagnostic::warn("BUSBAR-1", "m")
        .field("a", "1")
        .field("b", "2");
    assert!(serde_json::to_value(&sorted)
        .unwrap()
        .get("order")
        .is_none());
    assert_eq!(sorted.ordered_fields().len(), 2);
}
