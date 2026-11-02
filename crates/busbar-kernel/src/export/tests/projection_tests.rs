// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::config::{ExportDefCfg, ExportDefs};
use crate::export::projection::{
    produced_fields, resolve_projection, ProjectedRecord, Projection, ProjectionUnion,
    PRODUCED_STREAMS,
};
use busbar_contract::abi::export::{ExportField, ExportStream};

fn resolve_errs(yaml: &str) -> Vec<String> {
    let defs: ExportDefs = serde_yaml::from_str(yaml).expect("fixture parses");
    let mut errors = Vec::new();
    for (name, def) in defs {
        // Grammar inputs are declarations, not an exporter implementation. Product
        // loading and config-axis wiring are exercised in the distribution tests.
        let carries = match def.module.as_str() {
            "request-log-webhook" => &[ExportStream::Logs][..],
            "prometheus" => &[ExportStream::Metrics][..],
            "otlp" => &[ExportStream::Traces][..],
            module => panic!("unexpected grammar input module {module}"),
        };
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
        5,
        "this release produces {} of the {} frozen streams; the producerless set is {producerless:?}",
        PRODUCED_STREAMS.len(),
        ExportStream::ALL.len()
    );
    for stream in producerless {
        let errors = resolve_errs(&format!(
            "siem:\n  module: request-log-webhook\n  streams: [{stream}]\n  settings:\n    url: https://sink.example.com/l\n"
        ));
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
        "req-log:\n  module: request-log-webhook\n  streams: [logs]\n  settings:\n    url: https://sink.example.com/l\n",
    );
    assert!(errors.is_empty(), "logs should validate: {errors:#?}");
    let errors = resolve_errs("metrics:\n  module: prometheus\n  streams: [metrics]\n  settings:\n    buffer_seconds: 60\n");
    assert!(errors.is_empty(), "metrics should validate: {errors:#?}");
    let errors =
        resolve_errs("traces:\n  module: otlp\n  streams: [traces]\n  settings:\n    url: http://localhost:4318/v1/traces\n");
    assert!(errors.is_empty(), "traces should validate: {errors:#?}");
}

#[test]
fn audit_is_refused_as_a_stream_with_the_reason() {
    let errors = resolve_errs(
        "soc2:\n  module: request-log-webhook\n  streams: [audit]\n  settings:\n    url: https://sink.example.com/l\n",
    );
    assert_error_mentions(&errors, &["audit", "NOT a stream", "logs"]);
}

#[test]
fn unknown_stream_names_the_vocabulary() {
    let errors = resolve_errs(
        "x:\n  module: request-log-webhook\n  streams: [buckets]\n  settings:\n    url: https://sink.example.com/l\n",
    );
    assert_error_mentions(&errors, &["unknown stream", "buckets", "completions"]);
}

#[test]
fn stream_the_module_cannot_carry_is_a_loud_error() {
    let errors = resolve_errs(
        "m:\n  module: prometheus\n  streams: [logs]\n  settings:\n    buffer_seconds: 60\n",
    );
    assert_error_mentions(&errors, &["prometheus", "cannot carry", "logs"]);
}

#[test]
fn empty_streams_list_is_a_loud_error() {
    let errors = resolve_errs(
        "x:\n  module: request-log-webhook\n  streams: []\n  settings:\n    url: https://sink.example.com/l\n",
    );
    assert_error_mentions(&errors, &["EMPTY", "receives nothing"]);
}

#[test]
fn absent_streams_takes_the_modules_own_streams() {
    let mut errors = Vec::new();
    let proj = resolve_projection(
        "req-log",
        "request-log-webhook",
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
        "spooled:\n  module: request-log-webhook\n  durable: true\n  settings:\n    url: https://sink.example.com/l\n",
    );
    assert_error_mentions(&errors, &["durable", "NOT YET IMPLEMENTED"]);

    let errors = resolve_errs(
        "plain:\n  module: request-log-webhook\n  durable: false\n  settings:\n    url: https://sink.example.com/l\n",
    );
    assert!(errors.is_empty(), "{errors:#?}");
}

#[test]
fn fields_on_logs_is_refused_while_its_pinned_field_has_no_producer() {
    let errors = resolve_errs(
        "soc2:\n  module: request-log-webhook\n  streams: [logs]\n  fields: [ts, pool]\n  settings:\n    url: https://sink.example.com/l\n",
    );
    assert_error_mentions(
        &errors,
        &[
            "logs",
            "PINNED",
            "correlation_id",
            "NO PRODUCER",
            "later release",
        ],
    );
}

#[test]
fn fields_on_metrics_is_a_loud_error() {
    let errors = resolve_errs(
        "m:\n  module: prometheus\n  streams: [metrics]\n  fields: [pool]\n  settings:\n    buffer_seconds: 60\n",
    );
    assert_error_mentions(&errors, &["metrics", "no per-record fields"]);
}

#[test]
fn empty_fields_list_is_a_loud_error() {
    let errors = resolve_errs(
        "x:\n  module: request-log-webhook\n  streams: [logs]\n  fields: []\n  settings:\n    url: https://sink.example.com/l\n",
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
    let payload = rec.finish();

    let obj = payload.as_object().expect("an object");
    let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, vec!["kind", "prev_hash", "seq", "ts"]);

    let bytes = serde_json::to_string(&payload).unwrap();
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
    assert_eq!(rec.finish(), serde_json::json!({}));
}

#[test]
fn projection_union_is_the_compute_gate() {
    let empty = ProjectionUnion::default();
    assert!(empty.is_empty());
    for s in ExportStream::ALL {
        assert!(!empty.wants_stream(*s));
    }

    let defs: ExportDefs = serde_yaml::from_str(
        "req-log:\n  module: request-log-webhook\n  streams: [logs]\n  settings:\n    url: https://sink.example.com/l\ntraces:\n  module: otlp\n  streams: [traces]\n  settings:\n    url: http://localhost:4318/v1/traces\n",
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
        ts: 1,
        ingress_protocol: "acme",
        pool: "p",
        outcome: "ok",
        latency_ms: 5,
    };
    let payload = crate::export::build_request_log(all_logs, &facts);
    let mut written: Vec<&str> = payload
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    written.sort_unstable();
    let mut claimed: Vec<&str> = produced_fields(ExportStream::Logs)
        .iter()
        .map(|f| f.as_token())
        .collect();
    claimed.sort_unstable();
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
    let def: ExportDefCfg = serde_yaml::from_str(
        "module: request-log-webhook\nstreams: [logs]\ndurable: false\nsettings:\n  url: https://sink.example.com/l\n",
    )
    .unwrap();
    assert_eq!(def.streams.as_deref(), Some(&["logs".to_string()][..]));
    assert!(!def.durable);
    assert!(def.settings.contains_key("url"));
    assert!(!def.settings.contains_key("streams"));
}

#[test]
fn a_producerless_stream_fails_the_boot_validate_pipeline() {
    crate::test_support::register_neutral_test_plane();

    let base = r#"
listen: "0.0.0.0:8080"
auth:
  chain: [keys]
  signing_key: { env: BUSBAR_SIGNING_KEY }
  admin_auth: []
  role_bindings:
    keys:
      platform:
        allowed_pools: [main]
        group: eng
providers: {}
models: {}
pools:
  main:
    members: []
groups:
  eng:
    limits:
      - { requests: 500, per: minute }
store:
  module: memory
"#;
    let defs = std::collections::HashMap::new();

    let control: crate::config::DeployCfg = serde_yaml::from_str(base).expect("fixture parses");
    if let Err(errors) = crate::config::resolve(&control, &defs) {
        panic!("the fixture without `export:` must resolve; errors were: {errors:#?}");
    }
    let yaml = format!(
        "{base}export:\n  siem:\n    module: request-log-webhook\n    streams: [prompts]\n    \
         settings:\n      url: https://siem.example.com/l\n"
    );
    let deploy: crate::config::DeployCfg = serde_yaml::from_str(&yaml).expect("fixture parses");
    let errors = crate::config::resolve(&deploy, &defs)
        .expect_err("a producerless stream must make the whole config fail to resolve");
    assert_error_mentions(&errors, &["prompts", "NO PRODUCER", "later release"]);
}
