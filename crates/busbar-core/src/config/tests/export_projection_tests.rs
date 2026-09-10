// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the `export:` DOCUMENT half of the projection grammar — every rule proven the way an
//! operator meets it, through a real `export:` YAML block and `config::resolve_export`.
//!
//! The theme of every test here is the defect class this release kept surfacing — *reports success
//! while quietly not taking effect*. A config surface that validates and then delivers nothing would
//! be a fresh, hand-built instance of it, so each rule below is proven to fail LOUD.
//!
//! The grammar's OWN half — the disclosure gate, the empty union, and the anti-drift proofs that pin
//! `produced_fields` to the record builder — moved with the grammar to
//! `busbar_plugin::cold::export::projection`, where the table and the producer it describes are
//! finally in one crate. These tests are unchanged apart from that split: they were ported, not
//! rewritten.

use super::{ExportDefCfg, ExportDefs};
use busbar_plugin_loader::ExportStream;

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
/// release verifier) this release keeps guarding against.
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

// ── THE UNION-OF-PROJECTIONS COMPUTE GATE ───────────────────────────────────────────────────────

/// The compute gate: the union across every configured instance decides what core GENERATES. With
/// nothing configured it is empty, so the producer never runs — the same "the read runs only when
/// declared, never call-then-discard" discipline `hooks::requested_signals` applies to hook signals.
#[test]
fn projection_union_is_the_compute_gate() {
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
/// the boot / `--validate` pipeline: `config::resolve` (crates/busbar-core/src/config/mod.rs:4044) returns
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
        .expect_err("a producerless stream must make the whole config fail to resolve");
    assert_error_mentions(&errors, &["prompts", "NO PRODUCER", "later release"]);
}
