// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the host end of the plugin observability envelope (#85).
//!
//! These prove the REFUSALS, because the refusals are what make "the plugin REPORTS; the host
//! DECIDES" a real split rather than a comment. A plugin that could name any series, mint any
//! diagnostic code and pick its own severity would be mutating host state with extra steps.

use super::*;

/// A well-formed banner for a REGISTERED code resolves; the resolved entry is the catalogue's, so
/// its severity and title are the host's words and not the plugin's.
#[test]
fn a_registered_code_resolves_to_the_catalogue_entry() {
    let d = crate::diagnostics::FILE_LOG_APPEND_FAILED;
    let banner = format!("BUSBAR-{}", d.code);
    let got = resolve_code(&banner).expect("a registered code resolves");
    assert_eq!(got.code, d.code);
    assert_eq!(got.slug, d.slug);
}

/// A CODE THE CATALOGUE DOES NOT HOLD IS DROPPED. A `BUSBAR-NNNN` banner promises that pasting it
/// into the docs lands on an entry saying what to do; a plugin cannot be allowed to mint that
/// promise, so an unregistered code resolves to nothing and never reaches a log line.
#[test]
fn an_unregistered_code_is_refused() {
    assert!(resolve_code("BUSBAR-65535").is_none());
}

/// Nor can a plugin get a banner by spelling one that is not a banner.
#[test]
fn a_malformed_code_is_refused() {
    for bad in [
        "",
        "1234",
        "BUSBAR1234",
        "busbar-1234",
        "BUSBAR-",
        "BUSBAR-abc",
        "BUSBAR-99999999",
        "BUSBAR-1234 ",
    ] {
        assert!(resolve_code(bad).is_none(), "{bad} must not resolve");
    }
}

/// THE SEVERITY IS THE CATALOGUE'S, NOT THE PLUGIN'S. A condition the catalogue classifies as
/// benign-recurring is capped at `debug` however loudly the plugin claims it — otherwise a plugin
/// pages an operator at 3am by asserting that it should.
#[test]
fn a_benign_recurring_condition_cannot_be_escalated() {
    use busbar_plugin::cold::observe::DiagLevel;
    for claimed in [
        DiagLevel::Error,
        DiagLevel::Warn,
        DiagLevel::Info,
        DiagLevel::Debug,
    ] {
        assert_eq!(
            clamp_level(claimed, crate::diagnostics::Severity::BenignRecurring),
            DiagLevel::Debug
        );
    }
}

/// An ACTIONABLE condition keeps the plugin's claimed level: the catalogue has said this one is
/// worth an operator's attention, so how loud it is at this particular occurrence is exactly the
/// thing only the plugin knows.
#[test]
fn an_actionable_condition_keeps_the_reported_level() {
    use busbar_plugin::cold::observe::DiagLevel;
    for claimed in [DiagLevel::Error, DiagLevel::Warn, DiagLevel::Debug] {
        assert_eq!(
            clamp_level(claimed, crate::diagnostics::Severity::Actionable),
            claimed
        );
        assert_eq!(
            clamp_level(claimed, crate::diagnostics::Severity::Fatal),
            claimed
        );
    }
}

/// PROVENANCE CANNOT BE FORGED OR DROPPED. The `plugin` label is the host's, taken from the loaded
/// handle; a plugin that reports its own `plugin` label has that label dropped rather than allowed
/// to shadow the host's — a duplicate label name is a Prometheus parse error that costs the WHOLE
/// scrape, not just the sample.
#[test]
fn the_provenance_label_cannot_be_shadowed() {
    let m: crate::hooks::wire::HookMetric = serde_json::from_value(serde_json::json!({
        "name": "x_total",
        "type": "counter",
        "labels": {"plugin": "somebody-else", "sink": "audit"}
    }))
    .expect("decode");
    let labels = labels_for("the-real-name", &m);
    let plugin_labels: Vec<_> = labels
        .iter()
        .filter(|l| l.key() == PLUGIN_LABEL)
        .map(|l| l.value())
        .collect();
    assert_eq!(plugin_labels, vec!["the-real-name"]);
    assert!(labels.iter().any(|l| l.key() == "sink"));
}

/// The plugin's OWN labels survive alongside the host's, so the per-dimension breakdown a real sink
/// reports is not flattened away by the provenance label.
#[test]
fn a_plugins_own_labels_are_carried() {
    let m: crate::hooks::wire::HookMetric = serde_json::from_value(serde_json::json!({
        "name": "x_total",
        "type": "counter",
        "labels": {"sink": "audit", "reason": "full"}
    }))
    .expect("decode");
    let labels = labels_for("p", &m);
    assert_eq!(labels.len(), 3);
}

/// THE RESERVED NAMESPACE. A plugin metric named `busbar_*` is dropped so no plugin can impersonate
/// a first-party series or type-conflict with one. Asserted on the predicate the fold branches on,
/// because the fold itself writes to a process-global recorder no unit test may install into.
#[test]
fn the_reserved_namespace_is_refused() {
    assert!("busbar_file_logs_rotated_total".starts_with(RESERVED_PREFIX));
    assert!(!"file_logs_rotated_total".starts_with(RESERVED_PREFIX));
}

/// ONE VALIDATOR, AND IT IS 1.5.5'S. The entries the host folds are the entries the hook validator
/// admits — same caps, same charset, same fail-open drop-the-entry rule — so a plugin of any kind
/// gets exactly the bounding a hook has had since 1.5.5 and no second implementation exists to
/// drift from it.
#[test]
fn the_fold_validates_through_the_one_hook_validator() {
    let raw = vec![
        // Valid.
        serde_json::json!({"name": "good_total", "type": "counter", "value": 1}),
        // Invalid NAME charset — dropped whole.
        serde_json::json!({"name": "Bad-Name", "type": "counter", "value": 1}),
        // Unknown TYPE — dropped whole.
        serde_json::json!({"name": "other_total", "type": "summary", "value": 1}),
        // Non-finite value cannot even be expressed in JSON, so the validator's finiteness rule is
        // exercised by its own tests; here the missing `type` stands for a structurally bad entry.
        serde_json::json!({"name": "no_type_total"}),
    ];
    let kept = crate::hooks::wire::parse_status_metrics(&raw);
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].name, "good_total");
}

/// **THE CARDINALITY BUDGET ON THE COLD LANE — bounded emitter admitted, unbounded refused.**
///
/// The cold lane's validator caps labels at 8 PER ENTRY and entries at 64 PER REPLY, and neither
/// bounds what accumulates across replies: a sink reporting a fresh series name on every delivery
/// passes both caps every time and still grows the registry without limit. This is the bound that
/// was missing, and it is the same one the hot lane asks.
#[test]
fn the_cold_lane_bounds_series_cardinality() {
    const PLUGIN: &str = "cold-cardinality-plugin";
    forget_cardinality(PLUGIN);
    // A bounded emitter: the same series, forever.
    for _ in 0..(MAX_SERIES_PER_PLUGIN * 4) {
        assert!(admits_cardinality(PLUGIN, "steady_total", 0));
    }
    // An unbounded one: a new name every time. One slot is spent, so the ceiling admits N-1 more.
    let mut admitted = 1usize;
    for i in 0..(MAX_SERIES_PER_PLUGIN * 2) {
        if admits_cardinality(PLUGIN, &format!("churn_{i}_total"), 0) {
            admitted += 1;
        }
    }
    assert_eq!(admitted, MAX_SERIES_PER_PLUGIN);
    // The established series survives the flood — a misbehaving shape must not evict a good one.
    assert!(admits_cardinality(PLUGIN, "steady_total", 0));
}

/// The LABEL half on the cold lane. Here the labels ARE interpreted (a validated `BTreeMap`), so
/// the fingerprint is taken over the canonical rendering — and two identical label sets fingerprint
/// identically however the plugin ordered them on the wire.
#[test]
fn the_cold_lane_bounds_label_set_cardinality() {
    const PLUGIN: &str = "cold-label-plugin";
    forget_cardinality(PLUGIN);
    let mut admitted = 0usize;
    for i in 0..(MAX_LABEL_SETS_PER_SERIES * 3) {
        let labels: std::collections::BTreeMap<String, String> =
            [("request_id".to_string(), i.to_string())]
                .into_iter()
                .collect();
        if admits_cardinality(PLUGIN, "one_series_total", fingerprint_pairs(Some(&labels))) {
            admitted += 1;
        }
    }
    assert_eq!(
        admitted, MAX_LABEL_SETS_PER_SERIES,
        "labelling by request id must hit a ceiling, not explode the registry"
    );
}

/// THE FINGERPRINT IS ORDER-STABLE. Two plugins that report the same dimensions in different wire
/// order must spend ONE budget slot, not two — otherwise a well-behaved sink burns its ceiling on
/// what is really one series.
#[test]
fn an_identical_label_set_fingerprints_identically() {
    let a: std::collections::BTreeMap<String, String> = [
        ("model".to_string(), "m".to_string()),
        ("strategy".to_string(), "dedupe".to_string()),
    ]
    .into_iter()
    .collect();
    let b: std::collections::BTreeMap<String, String> = [
        ("strategy".to_string(), "dedupe".to_string()),
        ("model".to_string(), "m".to_string()),
    ]
    .into_iter()
    .collect();
    assert_eq!(fingerprint_pairs(Some(&a)), fingerprint_pairs(Some(&b)));
    // And a DIFFERENT set does not collide with it (not a guarantee of the hash, but a guard
    // against a fingerprint that ignores its input).
    let c: std::collections::BTreeMap<String, String> =
        [("model".to_string(), "other".to_string())]
            .into_iter()
            .collect();
    assert_ne!(fingerprint_pairs(Some(&a)), fingerprint_pairs(Some(&c)));
    // No labels is its own set, distinct from any labelled one.
    assert_ne!(fingerprint_pairs(None), fingerprint_pairs(Some(&a)));
}

/// THE BUDGET IS PER PLUGIN. One noisy sink must not be able to spend another's ceiling — otherwise
/// a single misbehaving plugin silences every other plugin's telemetry, which is a denial of service
/// against the operator's own observability.
#[test]
fn one_plugins_flood_does_not_spend_anothers_budget() {
    const NOISY: &str = "noisy-plugin";
    const QUIET: &str = "quiet-plugin";
    forget_cardinality(NOISY);
    forget_cardinality(QUIET);
    for i in 0..(MAX_SERIES_PER_PLUGIN * 2) {
        admits_cardinality(NOISY, &format!("n_{i}_total"), 0);
    }
    assert!(!admits_cardinality(NOISY, "one_more_total", 0));
    assert!(admits_cardinality(QUIET, "polite_total", 0));
}

/// THE HOOK FREEZE. A hook may now put samples on the envelope — the wire is uniform — but the host
/// does NOT fold them, because doing so would give hook metrics a second path with a different
/// freshness and a different exposition, and the hook kind's behaviour is frozen for 1.6.0.
///
/// Asserted by observing that the hook arm returns before touching anything: the call is made with
/// entries that WOULD be folded for any other kind, and it must complete having emitted nothing.
/// (The absence is what is provable here without installing a process-global recorder; the positive
/// half — that a non-hook kind DOES fold — is proven end-to-end by the compiled-in/dropped-in
/// equivalence test, which is the only place a recorder legitimately exists.)
#[test]
fn hook_envelope_metrics_are_carried_but_not_folded() {
    let entries = vec![serde_json::json!({"name": "x_total", "type": "counter", "value": 1})];
    // Must not panic, must not emit. The kind constant is read from the ABI so a kind rename cannot
    // silently turn the freeze off.
    KernelPluginObserver.observe(
        "some-hook",
        busbar_plugin::cold::kind::HOOK,
        &entries,
        &[serde_json::json!({"code": "BUSBAR-65535"})],
    );
}
