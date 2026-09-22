// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the host side of the observability envelope (#85).
//!
//! Every test that reads folds takes `testing::exclusive()` first — the observer is a
//! process-global `OnceLock` by design (the engine installs exactly one) and `cargo test` runs a
//! binary's tests concurrently, so the log has to be serialized or a test reads its neighbour's
//! folds and calls it a failure of the seam.

use super::*;
use testing::exclusive;

/// A BARE envelope never reaches the observer at all. That is the common case on every kind, and it
/// is what keeps the envelope from being a per-call tax on a plugin with nothing to say.
#[test]
fn a_bare_envelope_is_not_folded() {
    let _guard = exclusive();
    fold("p", "export", &Envelope::bare("Delivered"));
    assert!(testing::folds().is_empty());
}

/// What a plugin reported reaches the observer VERBATIM — the loader does not parse, filter or
/// rewrite it, because validating is the host's job and a loader that pre-parsed would be deciding
/// which entries the decider gets to see.
#[test]
fn a_reported_back_channel_reaches_the_observer_verbatim() {
    let _guard = exclusive();
    let env = Envelope {
        result: "Delivered",
        metrics: vec![serde_json::json!({"name": "rotated_total", "type": "counter", "value": 2})],
        diagnostics: vec![serde_json::json!({"code": "BUSBAR-9999", "message": "hi"})],
    };
    fold("export-file", "export", &env);
    let got = testing::folds();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].0, "export-file");
    assert_eq!(got[0].1, "export");
    assert_eq!(got[0].2, env.metrics);
    assert_eq!(got[0].3, env.diagnostics);
}

/// THE PROVENANCE LABEL IS THE HOST'S. The plugin never sends its own name or its own kind — both
/// come off the loaded handle, which was cross-checked against the signed manifest at load. So a
/// plugin cannot attribute its metrics to another plugin, or claim to be another kind in order to
/// pick up that kind's folding policy.
#[test]
fn provenance_comes_from_the_handle_not_the_wire() {
    let _guard = exclusive();
    let env = Envelope {
        // A plugin trying to say who it is. Nothing reads these.
        result: serde_json::json!({"plugin": "somebody-else", "kind": "store"}),
        metrics: vec![serde_json::json!({"name": "x_total", "type": "counter"})],
        diagnostics: Vec::new(),
    };
    fold("the-real-name", "export", &env);
    let got = testing::folds();
    assert_eq!(got[0].0, "the-real-name");
    assert_eq!(got[0].1, "export");
}

/// Metrics WITHOUT diagnostics, and diagnostics WITHOUT metrics, both fold — the two halves are
/// independent and neither gates the other.
#[test]
fn either_half_alone_still_folds() {
    let _guard = exclusive();
    fold(
        "p",
        "export",
        &Envelope {
            result: (),
            metrics: vec![serde_json::json!({"name": "a_total", "type": "counter"})],
            diagnostics: Vec::new(),
        },
    );
    fold(
        "p",
        "export",
        &Envelope {
            result: (),
            metrics: Vec::new(),
            diagnostics: vec![serde_json::json!({"code": "BUSBAR-0001"})],
        },
    );
    let got = testing::folds();
    assert_eq!(got.len(), 2);
    assert_eq!(got[0].2.len(), 1);
    assert!(got[0].3.is_empty());
    assert!(got[1].2.is_empty());
    assert_eq!(got[1].3.len(), 1);
}

/// The FIRST install wins and a later one is refused, so a second caller cannot silently re-point
/// where plugin telemetry goes mid-process. (`exclusive` has already installed the test recorder, so
/// this call is the second one by construction.)
#[test]
fn a_second_install_is_refused() {
    struct Other;
    impl PluginObserver for Other {
        fn observe(&self, _: &str, _: &str, _: &[serde_json::Value], _: &[serde_json::Value]) {}
    }
    let _guard = exclusive();
    assert!(!install_plugin_observer(&Other));
    assert!(observer_installed());
}
