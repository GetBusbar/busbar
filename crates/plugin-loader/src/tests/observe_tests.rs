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
        fn dropped(&self, _: u64) {}
        fn observe(&self, _: &str, _: &str, _: &[serde_json::Value], _: &[serde_json::Value]) {}
    }
    let _guard = exclusive();
    assert!(!install_plugin_observer(&Other));
    assert!(OBSERVER.get().is_some());
}

/// K9b: a first-party sink's declaration marked `shed` is the counter the host counts its shed
/// deliveries on. RED ARMS, in the same test: an unmarked declaration, a non-counter marked one, and
/// the same marked declaration made by a plugin that is not first-party are none of them a shed
/// counter.
#[test]
fn a_granted_shed_declaration_is_the_hosts_shed_counter() {
    use busbar_contract::abi::mechanism::observe::SeriesDecl;
    let declared = [
        SeriesDecl::new("k9b_rotated_total", "counter"),
        SeriesDecl::new("k9b_dropped_total", "counter").shed(),
        SeriesDecl::new("k9b_level", "gauge").shed(),
    ];
    grant_series("k9b-first-party", true, &declared).expect("granted");
    assert_eq!(shed_series("k9b-first-party"), vec!["k9b_dropped_total"]);
    let third: Vec<SeriesDecl> = declared
        .iter()
        .map(|d| SeriesDecl::new(format!("{}_3p", d.name), d.kind.clone()).shed())
        .collect();
    grant_series("k9b-third-party", false, &third).expect("nothing to refuse");
    assert!(shed_series("k9b-third-party").is_empty());
}

// ── ENVELOPE-ALL (ARCHITECT ruling 2026-10-03): every kind's envelope, through a bounded intake ──

/// A binder's own sink, recorded: what the door's binder still receives once the host's
/// observability stands before it.
#[derive(Default)]
struct Binder(std::sync::Mutex<Vec<String>>);

impl crate::dispatch::EnvelopeSink for Binder {
    fn metric(&self, m: crate::dispatch::Metric<'_>) {
        self.0.lock().unwrap().push(format!("metric {}", m.family));
    }
    fn diag(&self, d: crate::dispatch::Diagnostic<'_>) {
        self.0
            .lock()
            .unwrap()
            .push(format!("diag {}", String::from_utf8_lossy(d.text)));
    }
    fn dropped(&self, why: crate::dispatch::Dropped) {
        self.0.lock().unwrap().push(format!("dropped {why:?}"));
    }
}

/// THE ONE BIND OBSERVES EVERY KIND: `door` (a real plugin's, where the kind has one in this
/// crate's graph; the kind's existing fixture otherwise) bound through the one load with a sink of
/// its binder's own, and handed — as the dispatcher hands every reply's ingested envelope — a
/// declared diagnostic and a log record. The diagnostic reaches the host's observer under the
/// plugin's Statement name and `kind`; the log record does not (it is the plugin log's); the
/// binder's sink still receives both. RED before the ruling: every binder but export's bound
/// `NoSink` downstream of the log sink, and the observer received nothing.
fn observed_through_its_bind<K: crate::dispatch::Kind>(
    door: busbar_contract::abi::mechanism::door::DoorFn,
    kind: &str,
) {
    let guard = exclusive();
    let d = crate::dispatch::Dispatcher::new(crate::dispatch::DispatchConfig::default());
    let binder = std::sync::Arc::new(Binder::default());
    let row = crate::dispatch::LinkedRow::of(door).expect("the door states its Statement");
    let name = busbar_contract::abi::mechanism::rendering::read(&row.statement)
        .expect("the Statement reads back")
        .name;
    let plugin = crate::dispatch::load_linked::<K>(
        &row,
        crate::dispatch::Bind {
            instance: std::sync::Arc::from("envelope-all"),
            max_inflight_cap: 64,
            sink: binder.clone(),
            dispatcher: d.adopter(),
            conns: None,
        },
    )
    .expect("the door binds");
    testing::clear(&guard);
    let sink = plugin.envelope_sink();
    sink.diag(crate::dispatch::Diagnostic {
        id: 0,
        name: b"BUSBAR-7999",
        severity: 2,
        text: b"a declared diagnostic",
    });
    sink.diag(crate::dispatch::Diagnostic {
        id: busbar_contract::abi::mechanism::call::DIAG_LOG,
        name: b"",
        severity: 0,
        text: b"a log record",
    });
    let folds = testing::folds();
    assert_eq!(folds.len(), 1, "{kind}: {folds:?}");
    let (plugin_name, folded_kind, metrics, diagnostics) = &folds[0];
    assert_eq!(
        (plugin_name.as_str(), folded_kind.as_str()),
        (name.as_str(), kind)
    );
    assert!(metrics.is_empty());
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(diagnostics[0]["code"], "BUSBAR-7999");
    assert_eq!(diagnostics[0]["level"], "error");
    assert_eq!(diagnostics[0]["message"], "a declared diagnostic");
    assert_eq!(
        *binder.0.lock().unwrap(),
        vec![
            "diag a declared diagnostic".to_string(),
            "diag a log record".to_string()
        ],
        "{kind}: the binder's sink still receives every entry"
    );
}

/// `kind: plane` — the plane kind's door fixture (no real plane door in this crate's graph).
#[test]
fn a_plane_envelope_reaches_the_host_observer() {
    observed_through_its_bind::<crate::dispatch::kinds::plane::Plane>(
        crate::plane_door_plugin::door,
        busbar_contract::abi::cold::kind::PLANE,
    );
}

/// `kind: auth` — the real operator admin-tokens module (the `auth-verify` both-ways row).
#[test]
fn an_auth_envelope_reaches_the_host_observer() {
    observed_through_its_bind::<crate::dispatch::kinds::auth::Auth>(
        crate::both_ways::door_fixture("auth-verify").1,
        busbar_contract::abi::cold::kind::AUTH,
    );
}

/// `kind: store` — the real in-memory store's door (the `store` both-ways row).
#[test]
fn a_store_envelope_reaches_the_host_observer() {
    observed_through_its_bind::<crate::dispatch::kinds::store::Store>(
        crate::both_ways::store_fixture::door,
        busbar_contract::abi::cold::kind::STORE,
    );
}

/// `kind: hook` — the hook kind's door fixture (no real hook door in this crate's graph).
#[test]
fn a_hook_envelope_reaches_the_host_observer() {
    observed_through_its_bind::<crate::dispatch::kinds::hook::Hook>(
        crate::hook_door_conformance_tests::hook_door_plugin::conforming::door,
        busbar_contract::abi::cold::kind::HOOK,
    );
}

/// `kind: secret` — the real env secret source's door (the `secret` both-ways row).
#[test]
fn a_secret_envelope_reaches_the_host_observer() {
    observed_through_its_bind::<crate::dispatch::kinds::secret::Secret>(
        crate::both_ways::secret_fixture::door::door,
        busbar_contract::abi::cold::kind::SECRET,
    );
}

/// `kind: transport` — the real tcp transport's door (the `transport` both-ways row).
#[test]
fn a_transport_envelope_reaches_the_host_observer() {
    observed_through_its_bind::<crate::dispatch::kinds::transport::Transport>(
        crate::both_ways::transport_linked::door,
        busbar_contract::abi::cold::kind::TRANSPORT,
    );
}

/// `kind: export` — the real request-log file sink's door.
#[test]
fn an_export_envelope_reaches_the_host_observer() {
    observed_through_its_bind::<crate::dispatch::kinds::export::Export>(
        busbar_export_file::door,
        busbar_contract::abi::cold::kind::EXPORT,
    );
}

/// A declared metric family's entry is folded named by its family, through the one bind's observer
/// as through the export arm's (`export_conformance_tests`): every metric of a door reaches the
/// host the same way.
#[test]
fn a_metric_is_named_by_its_family_for_every_kind() {
    use crate::dispatch::EnvelopeSink as _;
    let guard = exclusive();
    let kinds = [
        busbar_contract::abi::cold::kind::PLANE,
        busbar_contract::abi::cold::kind::AUTH,
        busbar_contract::abi::cold::kind::STORE,
        busbar_contract::abi::cold::kind::HOOK,
        busbar_contract::abi::cold::kind::SECRET,
        busbar_contract::abi::cold::kind::TRANSPORT,
    ];
    for kind in kinds {
        testing::clear(&guard);
        let sink = EnvelopeObserver::before(
            std::sync::Arc::new(Binder::default()),
            "envelope-all",
            kind,
            vec![busbar_contract::abi::mechanism::rendering::ReadFamily {
                name: "envelope_all_events_total".into(),
                help: String::new(),
                unit: String::new(),
                label_keys: vec!["outcome".into()],
                kind: busbar_contract::abi::mechanism::door::FAMILY_COUNTER,
            }],
        );
        sink.metric(crate::dispatch::Metric {
            family: 0,
            kind: busbar_contract::abi::mechanism::call::METRIC_ADD,
            value: 2.0,
            labels: &[b"ok"],
        });
        let folds = testing::folds();
        assert_eq!(folds.len(), 1, "{kind}: {folds:?}");
        assert_eq!(folds[0].1, kind);
        assert_eq!(
            folds[0].2,
            vec![serde_json::json!({
                "name": "envelope_all_events_total",
                "type": "counter",
                "value": 2.0,
                "labels": { "outcome": "ok" },
            })]
        );
    }
}

/// THE INTAKE IS BOUNDED AND NEVER BLOCKS: with the observer stalled, a plugin's back-channels
/// past the intake's room are DROPPED at once — the reporting call returns without waiting — and
/// every one dropped is counted to the observer ([`PluginObserver::dropped`], the host's
/// `busbar_plugin_observations_dropped_total`); once the observer catches up it has every one that
/// was kept. RED: an inline (or blocking) intake stalls the reporting calls for as long as the
/// observer does.
#[test]
fn a_full_intake_drops_and_counts_and_never_stalls_the_caller() {
    use std::sync::atomic::Ordering;
    let guard = exclusive();
    testing::clear(&guard);
    let dropped_before = testing::DROPPED.load(Ordering::SeqCst);
    let sent = INTAKE_BOUND + 100;
    testing::HOLD.store(true, Ordering::SeqCst);
    let started = std::time::Instant::now();
    for n in 0..sent {
        fold_entries(
            "intake-witness",
            busbar_contract::abi::cold::kind::EXPORT,
            &[serde_json::json!({ "name": "intake_witness_total", "type": "counter", "value": n })],
            &[],
        );
    }
    let took = started.elapsed();
    testing::HOLD.store(false, Ordering::SeqCst);
    let kept = testing::folds()
        .iter()
        .filter(|(p, ..)| p == "intake-witness")
        .count();
    let dropped = testing::DROPPED.load(Ordering::SeqCst) - dropped_before;
    assert!(
        took < std::time::Duration::from_secs(2),
        "the reporting calls waited on a stalled observer: {took:?}"
    );
    // The observer thread may hold one it took before the stall, beside a full intake.
    assert!(kept <= INTAKE_BOUND + 1, "kept {kept}");
    assert!(kept >= 1, "nothing reached the observer");
    assert!(
        dropped as usize >= sent - kept,
        "every back-channel not kept is counted dropped: sent {sent}, kept {kept}, dropped {dropped}"
    );
}
