// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::config::{ExportDefCfg, ExportDefs};
use crate::export::projection::{
    produced_fields, resolve_projection, FieldValue, ProjectedRecord, Projection, ProjectionUnion,
    PRODUCED_STREAMS,
};
use busbar_contract::abi::export::ExportField;
use busbar_contract::export_stream::ExportStream;
use busbar_contract::json::{self, JsonContainerTrait as _};

fn resolve_errs(yaml: &str, carries: &[ExportStream]) -> Vec<String> {
    let defs: ExportDefs = busbar_contract::yaml::from_str(yaml).expect("fixture parses");
    let mut errors = Vec::new();
    for (name, def) in defs {
        resolve_projection(
            &name,
            &def.module,
            Some(carries),
            def.streams.as_deref(),
            def.fields.as_deref(),
            def.durable,
            &mut errors,
        );
    }
    errors
}

#[track_caller]
fn assert_error_mentions(errors: &[String], needles: &[&str]) {
    assert!(
        errors.iter().any(|e| needles.iter().all(|n| e.contains(n))),
        "no error mentioned all of {needles:?}; errors were: {errors:#?}"
    );
}

#[test]
fn producerless_stream_is_a_loud_config_error() {
    let producerless: Vec<&str> = ExportStream::ALL
        .iter()
        .filter(|s| !PRODUCED_STREAMS.contains(*s))
        .map(|s| s.as_token())
        .collect();
    assert_eq!(
        producerless.len(),
        6,
        "this release produces {} of the {} frozen streams; the producerless set is {producerless:?}",
        PRODUCED_STREAMS.len(),
        ExportStream::ALL.len()
    );
    for stream in producerless {
        let errors = resolve_errs(
            &format!("siem:\n  module: fixture-export\n  streams: [{stream}]\n  settings: {{}}\n"),
            &[ExportStream::Logs],
        );
        assert!(
            !errors.is_empty(),
            "`streams: [{stream}]` VALIDATED — it has no producer, so this config would report \
             success and deliver nothing"
        );
        assert_error_mentions(&errors, &[stream, "NO PRODUCER", "later release"]);
    }
}

#[test]
fn produced_streams_are_accepted() {
    let errors = resolve_errs(
        "req-log:\n  module: fixture-export\n  streams: [logs]\n  settings: {}\n",
        &[ExportStream::Logs],
    );
    assert!(errors.is_empty(), "logs should validate: {errors:#?}");
    let errors = resolve_errs(
        "metrics:\n  module: fixture-export\n  streams: [metrics]\n  settings: {}\n",
        &[ExportStream::Metrics],
    );
    assert!(errors.is_empty(), "metrics should validate: {errors:#?}");
    let errors = resolve_errs(
        "traces:\n  module: fixture-export\n  streams: [traces]\n  settings: {}\n",
        &[ExportStream::Traces],
    );
    assert!(errors.is_empty(), "traces should validate: {errors:#?}");
}

#[test]
fn audit_is_refused_as_a_stream_with_the_reason() {
    let errors = resolve_errs(
        "soc2:\n  module: fixture-export\n  streams: [audit]\n  settings: {}\n",
        &[ExportStream::Logs],
    );
    assert_error_mentions(&errors, &["audit", "NOT a stream", "logs"]);
}

#[test]
fn unknown_stream_names_the_vocabulary() {
    let errors = resolve_errs(
        "x:\n  module: fixture-export\n  streams: [buckets]\n  settings: {}\n",
        &[ExportStream::Logs],
    );
    assert_error_mentions(&errors, &["unknown stream", "buckets", "completions"]);
}

#[test]
fn stream_the_module_cannot_carry_is_a_loud_error() {
    let errors = resolve_errs(
        "m:\n  module: fixture-export\n  streams: [logs]\n  settings: {}\n",
        &[ExportStream::Metrics],
    );
    assert_error_mentions(&errors, &["fixture-export", "cannot carry", "logs"]);
}

#[test]
fn empty_streams_list_is_a_loud_error() {
    let errors = resolve_errs(
        "x:\n  module: fixture-export\n  streams: []\n  settings: {}\n",
        &[ExportStream::Logs],
    );
    assert_error_mentions(&errors, &["EMPTY", "receives nothing"]);
}

#[test]
fn absent_streams_takes_the_modules_own_streams() {
    let mut errors = Vec::new();
    let proj = resolve_projection(
        "req-log",
        "fixture-export",
        Some(&[ExportStream::Logs]),
        None,
        None,
        false,
        &mut errors,
    );
    assert!(errors.is_empty(), "{errors:#?}");
    assert!(proj.wants_stream(ExportStream::Logs));
    assert!(!proj.wants_stream(ExportStream::Metrics));
    assert!(!proj.granted_fields(ExportStream::Logs).is_empty());
}

#[test]
fn durable_true_is_a_loud_not_yet_implemented_error() {
    let errors = resolve_errs(
        "spooled:\n  module: fixture-export\n  durable: true\n  settings: {}\n",
        &[ExportStream::Logs],
    );
    assert_error_mentions(&errors, &["durable", "NOT YET IMPLEMENTED"]);

    let errors = resolve_errs(
        "plain:\n  module: fixture-export\n  durable: false\n  settings: {}\n",
        &[ExportStream::Logs],
    );
    assert!(errors.is_empty(), "{errors:#?}");
}

#[test]
fn logs_fields_override_accepted() {
    let errors = resolve_errs(
        "soc2:\n  module: fixture-export\n  streams: [logs]\n  fields: [correlation_id, ts]\n  settings: {}\n",
        &[ExportStream::Logs],
    );
    assert!(errors.is_empty(), "{errors:#?}");
}

#[test]
fn logs_fields_override_omitting_correlation_id_is_refused_at_the_pin() {
    let errors = resolve_errs(
        "soc2:\n  module: fixture-export\n  streams: [logs]\n  fields: [ts, pool]\n  settings: {}\n",
        &[ExportStream::Logs],
    );
    assert_error_mentions(&errors, &["logs", "PINNED", "correlation_id"]);
}

#[test]
fn logs_never_carry_deployment_or_node() {
    for token in ["deployment_id", "node_id"] {
        let errors = resolve_errs(
            &format!(
                "soc2:\n  module: fixture-export\n  streams: [logs]\n  fields: [correlation_id, ts, {token}]\n  settings: {{}}\n"
            ),
            &[ExportStream::Logs],
        );
        assert_error_mentions(&errors, &[token, "is not a field of any subscribed stream"]);
    }
    assert!(!produced_fields(ExportStream::Logs).contains(&ExportField::DeploymentId));
    assert!(!produced_fields(ExportStream::Logs).contains(&ExportField::NodeId));
}

#[test]
fn logs_default_grant_adds_only_correlation_id() {
    assert_eq!(
        produced_fields(ExportStream::Logs),
        &[
            ExportField::CorrelationId,
            ExportField::Ts,
            ExportField::IngressProtocol,
            ExportField::Pool,
            ExportField::Outcome,
            ExportField::LatencyMs,
        ]
    );
}

#[test]
fn logs_default_line_carries_correlation_id() {
    let all_logs = Projection::for_test(&[ExportStream::Logs], produced_fields(ExportStream::Logs));
    let facts = crate::export::RequestLogFacts {
        correlation_id: Some("node_00000000000000aa.0123456789abcdef0123456789abcdef.7"),
        ts: 1,
        ingress_protocol: "acme",
        pool: "p",
        outcome: "ok",
        latency_ms: 5,
    };
    let line: json::Value =
        json::parse_value(&crate::export::build_request_log(all_logs, &facts).line).unwrap();
    assert_eq!(
        line["correlation_id"],
        "node_00000000000000aa.0123456789abcdef0123456789abcdef.7"
    );
}

#[test]
fn omitted_streams_take_only_produced() {
    let mut errors = Vec::new();
    let proj = resolve_projection(
        "mixed",
        "fixture-export",
        Some(&[ExportStream::Logs, ExportStream::Content]),
        None,
        None,
        false,
        &mut errors,
    );
    assert!(errors.is_empty(), "{errors:#?}");
    assert!(proj.wants_stream(ExportStream::Logs));
    assert!(!proj.wants_stream(ExportStream::Content));

    let errors = resolve_errs(
        "only:\n  module: fixture-export\n  settings: {}\n",
        &[ExportStream::Content],
    );
    assert_error_mentions(&errors, &["only", "content", "NO PRODUCER"]);
}

#[test]
fn fields_on_metrics_is_a_loud_error() {
    let errors = resolve_errs(
        "m:\n  module: fixture-export\n  streams: [metrics]\n  fields: [pool]\n  settings: {}\n",
        &[ExportStream::Metrics],
    );
    assert_error_mentions(&errors, &["metrics", "no per-record fields"]);
}

#[test]
fn empty_fields_list_is_a_loud_error() {
    let errors = resolve_errs(
        "x:\n  module: fixture-export\n  streams: [logs]\n  fields: []\n  settings: {}\n",
        &[ExportStream::Logs],
    );
    assert_error_mentions(&errors, &["EMPTY", "EXHAUSTIVE OVERRIDE"]);
}

#[test]
fn omitting_a_pinned_field_is_a_loud_error_with_the_reason() {
    let mut errors = Vec::new();
    let proj = resolve_projection(
        "chain",
        "some-event-sink",
        None,
        Some(&["events".to_string()]),
        Some(&[
            "seq".to_string(),
            "ts".to_string(),
            "kind".to_string(),
            "actor".to_string(),
        ]),
        false,
        &mut errors,
    );
    assert_error_mentions(&errors, &["prev_hash", "PINNED", "events", "chain"]);

    assert!(proj.is_empty());
}

#[test]
fn fields_override_replaces_the_default_set_rather_than_adding_to_it() {
    let mut errors = Vec::new();
    let proj = resolve_projection(
        "chain",
        "some-event-sink",
        None,
        Some(&["events".to_string()]),
        Some(&[
            "seq".to_string(),
            "ts".to_string(),
            "prev_hash".to_string(),
            "kind".to_string(),
        ]),
        false,
        &mut errors,
    );
    assert!(errors.is_empty(), "{errors:#?}");
    let granted = proj.granted_fields(ExportStream::Events);
    assert_eq!(
        granted,
        vec![
            ExportField::Ts,
            ExportField::Seq,
            ExportField::PrevHash,
            ExportField::Kind
        ],
        "the override must be exhaustive"
    );

    for not_listed in [
        ExportField::Actor,
        ExportField::Resource,
        ExportField::Outcome,
    ] {
        assert!(
            !proj.grants(ExportStream::Events, not_listed),
            "{} leaked into an exhaustive override that did not list it",
            not_listed.as_token()
        );
    }
}

#[test]
fn field_outside_the_subscribed_streams_is_a_loud_error() {
    let mut errors = Vec::new();
    resolve_projection(
        "chain",
        "some-event-sink",
        None,
        Some(&["events".to_string()]),
        Some(&[
            "seq".into(),
            "ts".into(),
            "prev_hash".into(),
            "subject".into(),
        ]),
        false,
        &mut errors,
    );
    assert_error_mentions(
        &errors,
        &["subject", "not a field of any subscribed stream"],
    );
}

#[test]
fn projected_record_cannot_carry_an_ungranted_field() {
    let mut errors = Vec::new();
    let proj = resolve_projection(
        "chain",
        "some-event-sink",
        None,
        Some(&["events".to_string()]),
        Some(&["seq".into(), "ts".into(), "prev_hash".into(), "kind".into()]),
        false,
        &mut errors,
    );
    assert!(errors.is_empty(), "{errors:#?}");

    let mut rec = ProjectedRecord::new(proj, ExportStream::Events);
    rec.set(ExportField::Seq, 7u64)
        .set(ExportField::Ts, 1_700_000_000u64)
        .set(ExportField::PrevHash, "abc")
        .set(ExportField::Kind, "key.delete")
        .set(ExportField::Actor, "admin@example.com")
        .set(ExportField::Resource, "key:k1");
    let payload: json::Value = json::parse_value(&rec.finish().line).unwrap();

    let obj = payload.as_object().expect("an object");
    let mut keys: Vec<&str> = obj.iter().map(|(k, _)| k).collect();
    keys.sort();
    assert_eq!(keys, vec!["kind", "prev_hash", "seq", "ts"]);

    let bytes = json::to_string(&payload).unwrap();
    assert!(!bytes.contains("admin@example.com"), "{bytes}");
    assert!(!bytes.contains("actor"), "{bytes}");
}

#[test]
fn a_grant_on_one_stream_does_not_leak_into_another() {
    let mut errors = Vec::new();
    let proj = resolve_projection(
        "chain",
        "some-event-sink",
        None,
        Some(&["events".to_string()]),
        None,
        false,
        &mut errors,
    );
    assert!(errors.is_empty(), "{errors:#?}");
    assert!(proj.grants(ExportStream::Events, ExportField::Ts));

    let mut rec = ProjectedRecord::new(proj, ExportStream::Logs);
    rec.set(ExportField::Ts, 1u64).set(ExportField::Pool, "p");
    assert_eq!(rec.finish().line, b"{}");
}

#[test]
fn a_projected_record_is_byte_for_byte_its_json_document() {
    let fields = [
        ExportField::Ts,
        ExportField::IngressProtocol,
        ExportField::Pool,
        ExportField::Outcome,
        ExportField::LatencyMs,
        ExportField::TraceId,
        ExportField::SpanId,
        ExportField::Lane,
        ExportField::Start,
    ];
    let proj = Projection::for_test(&[ExportStream::Traces], &fields);
    let mut rec = ProjectedRecord::new(proj, ExportStream::Traces);
    rec.set(ExportField::Ts, 1_700_000_000u64)
        .set(ExportField::Pool, "p\"1\\\u{1}é")
        .set(ExportField::Outcome, FieldValue::F64(f64::NAN))
        .set(ExportField::LatencyMs, FieldValue::F64(1e21))
        .set(ExportField::TraceId, FieldValue::Hex(0xab))
        .set(ExportField::Lane, FieldValue::I64(-3))
        .set(ExportField::Start, FieldValue::Bool(true))
        .set(ExportField::SpanId, FieldValue::F64(0.1));
    rec.span(b"{\"name\":\"s\"}");
    let rendered = rec.finish();
    let document = json::json!({
        "ts": 1_700_000_000u64,
        "pool": "p\"1\\\u{1}é",
        "outcome": {"$busbar_f64": "NaN"},
        "latency_ms": 1e21,
        "trace_id": "00000000000000ab",
        "lane": -3,
        "start": true,
        "span_id": 0.1,
        "span": {"name": "s"},
    });
    assert_eq!(rendered.line, json::to_vec(&document).unwrap());
    assert!(rendered
        .members
        .names()
        .eq(document.as_object().unwrap().iter().map(|(k, _)| k)));
}

#[test]
fn projection_union_is_the_compute_gate() {
    let empty = ProjectionUnion::default();
    assert!(empty.is_empty());
    for s in ExportStream::ALL {
        assert!(!empty.wants_stream(*s));
    }

    let defs: ExportDefs = busbar_contract::yaml::from_str(
        "req-log:\n  module: fixture-export\n  streams: [logs]\n  settings: {}\ntraces:\n  module: fixture-export\n  streams: [traces]\n  settings: {}\n",
    )
    .unwrap();
    let mut errors = Vec::new();
    let plugins = defs
        .into_iter()
        .map(|(name, def)| {
            let projection = resolve_projection(
                &name,
                &def.module,
                None,
                def.streams.as_deref(),
                def.fields.as_deref(),
                def.durable,
                &mut errors,
            );
            crate::config::PluginExportSettings {
                name,
                def,
                projection,
                scrape: false,
            }
        })
        .collect();
    let cfg = crate::config::ExportCfg {
        read: Default::default(),
        recorder: None,
        plugins,
    };
    assert!(errors.is_empty(), "{errors:#?}");
    let union = cfg.projection_union();
    assert!(union.wants_stream(ExportStream::Logs));
    assert!(union.wants_stream(ExportStream::Traces));
    assert!(!union.wants_stream(ExportStream::Metrics));
    assert!(!union.wants_stream(ExportStream::Events));
}

#[test]
fn produced_logs_fields_match_the_request_log_producer() {
    let all_logs = Projection::for_test(&[ExportStream::Logs], ExportStream::Logs.default_fields());
    let facts = crate::export::RequestLogFacts {
        correlation_id: Some("node_1.n.1"),
        ts: 1,
        ingress_protocol: "acme",
        pool: "p",
        outcome: "ok",
        latency_ms: 5,
    };
    let payload: json::Value =
        json::parse_value(&crate::export::build_request_log(all_logs, &facts).line).unwrap();
    let mut written: Vec<&str> = payload
        .as_object()
        .expect("an object")
        .iter()
        .map(|(k, _)| k)
        .collect();
    written.sort();
    let mut claimed: Vec<&str> = produced_fields(ExportStream::Logs)
        .iter()
        .map(|f| f.as_token())
        .collect();
    claimed.sort();
    assert_eq!(
        written, claimed,
        "produced_fields(logs) does not match what build_request_log emits"
    );
}

#[test]
fn produced_fields_are_a_subset_of_the_documented_defaults() {
    for s in ExportStream::ALL {
        for f in produced_fields(*s) {
            assert!(
                s.default_fields().contains(f),
                "{} is claimed produced for {} but is not one of its documented fields",
                f.as_token(),
                s.as_token()
            );
        }
        if !PRODUCED_STREAMS.contains(s) {
            assert!(
                produced_fields(*s).is_empty(),
                "{} has no producer, so it can claim no produced fields",
                s.as_token()
            );
        }
    }
}

#[test]
fn projection_keys_are_instance_level_not_settings() {
    let def: ExportDefCfg = busbar_contract::yaml::from_str(
        "module: fixture-export\nstreams: [logs]\ndurable: false\nsettings:\n  option: opaque\n",
    )
    .unwrap();
    assert_eq!(def.streams.as_deref(), Some(&["logs".to_string()][..]));
    assert!(!def.durable);
    assert!(def.settings.key_names().contains(&"option".to_owned()));
    assert!(!def.settings.key_names().contains(&"streams".to_owned()));
}
