// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the EXPORT PROJECTION GRAMMAR (`crate::export::projection`).
//!
//! The theme of every test here is the defect class this release kept surfacing — *reports success
//! while quietly not taking effect*. A config surface that validates and then delivers nothing would
//! be a fresh, hand-built instance of it, so each rule below is proven to fail LOUD.

use crate::config::{ExportDefCfg, ExportDefs};
use crate::export::projection::{
    produced_fields, resolve_projection, ProjectedRecord, Projection, ProjectionUnion,
    PRODUCED_STREAMS,
};
use busbar_plugin_loader::{ExportField, ExportStream};

/// Build a one-instance `export:` map and resolve it, returning the accumulated errors.
fn resolve_errs(yaml: &str) -> Vec<String> {
    let defs: ExportDefs = serde_yaml::from_str(yaml).expect("fixture parses");
    let mut errors = Vec::new();
    let _ = crate::config::resolve_export(&defs, &mut errors);
    errors
}

/// Assert that SOME error mentions every one of `needles` — a projection error must NAME the thing
/// it refused, not just say no.
#[track_caller]
fn assert_error_mentions(errors: &[String], needles: &[&str]) {
    assert!(
        errors.iter().any(|e| needles.iter().all(|n| e.contains(n))),
        "no error mentioned all of {needles:?}; errors were: {errors:#?}"
    );
}

// ── THE HARD RULE: only streams with a PRODUCER are accepted ────────────────────────────────────

/// THE HARD RULE. A stream in the frozen vocabulary that this release cannot produce must LOUD-FAIL
/// at validate, naming the stream and saying it arrives later. Accepting it would validate and
/// silently deliver nothing — the exact defect class (key delete, cache flush, the migrator, the
/// release verifier) every audit round in this release surfaced.
#[test]
fn producerless_stream_is_a_loud_config_error() {
    for stream in ["costs", "decisions", "identity", "prompts", "completions"] {
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

/// Every stream this release DOES produce is accepted (on a module that carries it) — the rule is a
/// gate, not a blanket refusal.
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

/// `audit` is REMOVED as a stream: an auditor is a PROJECTION made of other streams. The refusal
/// must say so and point at the replacement, not just report an unknown token.
#[test]
fn audit_is_refused_as_a_stream_with_the_reason() {
    let errors = resolve_errs(
        "soc2:\n  module: request-log-webhook\n  streams: [audit]\n  settings:\n    url: https://sink.example.com/l\n",
    );
    assert_error_mentions(&errors, &["audit", "NOT a stream", "logs"]);
}

/// An unknown token names the whole vocabulary, so the operator can fix it from the message.
#[test]
fn unknown_stream_names_the_vocabulary() {
    let errors = resolve_errs(
        "x:\n  module: request-log-webhook\n  streams: [buckets]\n  settings:\n    url: https://sink.example.com/l\n",
    );
    assert_error_mentions(&errors, &["unknown stream", "buckets", "completions"]);
}

/// A stream the instance's MODULE cannot carry is a loud error, not an empty subscription — the same
/// silently-delivers-nothing shape.
#[test]
fn stream_the_module_cannot_carry_is_a_loud_error() {
    let errors = resolve_errs(
        "m:\n  module: prometheus\n  streams: [logs]\n  settings:\n    buffer_seconds: 60\n",
    );
    assert_error_mentions(&errors, &["prometheus", "cannot carry", "logs"]);
}

/// An EMPTY `streams:` list would subscribe to nothing at all.
#[test]
fn empty_streams_list_is_a_loud_error() {
    let errors = resolve_errs(
        "x:\n  module: request-log-webhook\n  streams: []\n  settings:\n    url: https://sink.example.com/l\n",
    );
    assert_error_mentions(&errors, &["EMPTY", "receives nothing"]);
}

/// An instance with no `streams:` key — every config written before the projection grammar — keeps
/// its meaning: the module's own streams. It must NOT resolve to an empty projection.
#[test]
fn absent_streams_takes_the_modules_own_streams() {
    let defs: ExportDefs = serde_yaml::from_str(
        "req-log:\n  module: request-log-webhook\n  settings:\n    url: https://sink.example.com/l\n",
    )
    .unwrap();
    let mut errors = Vec::new();
    let cfg = crate::config::resolve_export(&defs, &mut errors);
    assert!(errors.is_empty(), "{errors:#?}");
    let proj = cfg.request_log_webhooks[0].projection;
    assert!(proj.wants_stream(ExportStream::Logs));
    assert!(!proj.wants_stream(ExportStream::Metrics));
    assert!(!proj.granted_fields(ExportStream::Logs).is_empty());
}

// ── `durable:` ──────────────────────────────────────────────────────────────────────────────────

/// `durable: true` is a completeness PROMISE. The spool that keeps it is a later unit, so accepting
/// the key silently would be the same defect again — it must refuse loudly.
#[test]
fn durable_true_is_a_loud_not_yet_implemented_error() {
    let errors = resolve_errs(
        "spooled:\n  module: request-log-webhook\n  durable: true\n  settings:\n    url: https://sink.example.com/l\n",
    );
    assert_error_mentions(&errors, &["durable", "NOT YET IMPLEMENTED"]);
    // `durable: false` (and the absent key) are fine — the surface exists, the promise is refused.
    let errors = resolve_errs(
        "plain:\n  module: request-log-webhook\n  durable: false\n  settings:\n    url: https://sink.example.com/l\n",
    );
    assert!(errors.is_empty(), "{errors:#?}");
}

// ── `fields:` — exhaustive override, pinned fields, producer honesty ────────────────────────────

/// A `fields:` list naming a field of a stream whose PINNED field this release cannot produce is
/// refused with BOTH halves of the reason. Without this the operator would be caught between "you
/// must include correlation_id" and "correlation_id has no producer".
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

/// `fields:` cannot apply to `metrics` at all — its unit is the metric catalog, not record fields.
#[test]
fn fields_on_metrics_is_a_loud_error() {
    let errors = resolve_errs(
        "m:\n  module: prometheus\n  streams: [metrics]\n  fields: [pool]\n  settings:\n    buffer_seconds: 60\n",
    );
    assert_error_mentions(&errors, &["metrics", "no per-record fields"]);
}

/// An EMPTY `fields:` list means a record with no fields — an exhaustive override of nothing.
#[test]
fn empty_fields_list_is_a_loud_error() {
    let errors = resolve_errs(
        "x:\n  module: request-log-webhook\n  streams: [logs]\n  fields: []\n  settings:\n    url: https://sink.example.com/l\n",
    );
    assert_error_mentions(&errors, &["EMPTY", "EXHAUSTIVE OVERRIDE"]);
}

/// THE PINNED-FIELD RULE, proven directly against the validator (the config path for `events` is
/// blocked earlier by the module rule, so this exercises the rule itself): omitting a pinned field
/// is a config error carrying the REASON, never a silent no-op and never a silent re-add.
#[test]
fn omitting_a_pinned_field_is_a_loud_error_with_the_reason() {
    let mut errors = Vec::new();
    let proj = resolve_projection(
        "chain",
        "some-event-sink",
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
    // The refusal is total: a failed projection grants nothing.
    assert!(proj.is_empty());
}

/// `fields:` is an EXHAUSTIVE OVERRIDE, never additive: a listed set replaces the stream's defaults
/// entirely, so a default field the operator did not list is NOT granted.
#[test]
fn fields_override_replaces_the_default_set_rather_than_adding_to_it() {
    let mut errors = Vec::new();
    let proj = resolve_projection(
        "chain",
        "some-event-sink",
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
    // `actor`, `resource` and `outcome` are DEFAULT fields of `events` that the operator did not
    // list. Additive semantics would hand them over anyway — that is the silent widening this rule
    // exists to prevent.
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

/// A field that belongs to no subscribed stream would never arrive — loud, not ignored.
#[test]
fn field_outside_the_subscribed_streams_is_a_loud_error() {
    let mut errors = Vec::new();
    resolve_projection(
        "chain",
        "some-event-sink",
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

// ── CORE-SIDE ENFORCEMENT: an ungranted field is never serialized ───────────────────────────────

/// The enforcement property, stated directly: a record built to a projection carries EXACTLY the
/// granted fields. An ungranted field is dropped at the writer, so it is never serialized and
/// therefore never crosses the ABI — an over-reading sink is impossible, not merely forbidden.
#[test]
fn projected_record_cannot_carry_an_ungranted_field() {
    let mut errors = Vec::new();
    let proj = resolve_projection(
        "chain",
        "some-event-sink",
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
        // OFFERED but NOT granted — the producer may hand it over freely; the record refuses it.
        .set(ExportField::Actor, "admin@example.com")
        .set(ExportField::Resource, "key:k1");
    let payload = rec.finish();

    let obj = payload.as_object().expect("an object");
    let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, vec!["kind", "prev_hash", "seq", "ts"]);
    // Not merely absent from the map — absent from the SERIALIZED bytes, which is the property that
    // matters: the ungranted value never crosses the ABI.
    let bytes = serde_json::to_string(&payload).unwrap();
    assert!(!bytes.contains("admin@example.com"), "{bytes}");
    assert!(!bytes.contains("actor"), "{bytes}");
}

/// A record for a stream the projection does not subscribe to carries nothing at all, even for a
/// field the projection grants on ANOTHER stream — a grant is (stream, field), never a bare field.
#[test]
fn a_grant_on_one_stream_does_not_leak_into_another() {
    let mut errors = Vec::new();
    let proj = resolve_projection(
        "chain",
        "some-event-sink",
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

// ── THE UNION-OF-PROJECTIONS COMPUTE GATE ───────────────────────────────────────────────────────

/// The compute gate: the union across every configured instance decides what core GENERATES. With
/// nothing configured it is empty, so the producer never runs — the same "the read runs only when
/// declared, never call-then-discard" discipline `hooks::requested_signals` applies to hook signals.
#[test]
fn projection_union_is_the_compute_gate() {
    let empty = ProjectionUnion::default();
    assert!(empty.is_empty());
    for s in ExportStream::ALL {
        assert!(!empty.wants_stream(*s));
    }

    let defs: ExportDefs = serde_yaml::from_str(
        "req-log:\n  module: request-log-webhook\n  settings:\n    url: https://sink.example.com/l\ntraces:\n  module: otlp\n  settings:\n    url: http://localhost:4318/v1/traces\n",
    )
    .unwrap();
    let mut errors = Vec::new();
    let cfg = crate::config::resolve_export(&defs, &mut errors);
    assert!(errors.is_empty(), "{errors:#?}");
    let union = cfg.projection_union();
    assert!(union.wants_stream(ExportStream::Logs));
    assert!(union.wants_stream(ExportStream::Traces));
    assert!(!union.wants_stream(ExportStream::Metrics));
    assert!(!union.wants_stream(ExportStream::Events));
}

// ── ANTI-DRIFT: the produced-field table must match the producer it claims to describe ──────────

/// `produced_fields(Logs)` claims to be exactly what `build_request_log` fills in. Prove it against
/// the producer itself, so the table cannot drift from the code and quietly start promising a field
/// nothing writes (which is how a "no producer" gate turns into a lie).
#[test]
fn produced_logs_fields_match_the_request_log_producer() {
    // A projection granting EVERY documented logs field: whatever the producer writes, gets through.
    let all_logs = Projection::for_test(&[ExportStream::Logs], ExportStream::Logs.default_fields());
    let payload = crate::export::build_request_log(all_logs, 1, "openai", "p", "ok", 5);
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

/// Every produced-field table is a SUBSET of its stream's frozen documented default set — a table
/// entry outside it would grant a field the contract does not define.
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

/// The `settings:` bag is still typed per module — the projection keys did not turn the outer layer
/// opaque. (Guards against the new keys being absorbed into `settings:` by a stray `flatten`.)
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

// ── THE BOOT/`--validate` PATH, end to end ──────────────────────────────────────────────────────

/// The rules above are proven against `resolve_export`. This one proves they are actually REACHED by
/// the boot / `--validate` pipeline: `config::resolve` (crates/busbar/src/config/mod.rs:4044) returns
/// `Result<RootCfg, Vec<String>>` and lowers the `export:` block through the same `resolve_export`
/// (mod.rs:4052) — and BOTH boot entry points treat that `Err` as fatal (main.rs:293, main.rs:853).
/// Without this test the whole grammar could be validated in a function nothing fatal ever calls.
#[test]
fn a_producerless_stream_fails_the_boot_validate_pipeline() {
    let yaml = r#"
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
providers:
  anthropic:
    api_key: { env: ANTHROPIC_API_KEY }
models:
  claude:
    provider: anthropic
pools:
  main:
    members:
      - model: claude
groups:
  eng:
    limits:
      - { requests: 500, per: minute }
store:
  module: memory
export:
  siem:
    module: request-log-webhook
    streams: [prompts]
    settings:
      url: https://siem.example.com/l
"#;
    let deploy: crate::config::DeployCfg = serde_yaml::from_str(yaml).expect("fixture parses");
    let def: crate::config::ProviderDef = serde_yaml::from_str(
        "protocol: anthropic\nbase_url: https://api.anthropic.com\nerror_map:\n  \"400\": client_error\n",
    )
    .unwrap();
    let defs = std::collections::HashMap::from([("anthropic".to_string(), def)]);
    let errors = crate::config::resolve(&deploy, &defs)
        .err()
        .expect("a producerless stream must make the whole config fail to resolve");
    assert_error_mentions(&errors, &["prompts", "NO PRODUCER", "later release"]);
}
