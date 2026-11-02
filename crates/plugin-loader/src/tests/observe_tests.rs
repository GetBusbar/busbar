// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use testing::exclusive;

fn fold<R>(plugin: &str, kind: &str, envelope: &Envelope<R>) {
    testing::observing().fold(plugin, kind, envelope);
}

fn fold_entries(
    plugin: &str,
    kind: &str,
    metrics: &[serde_json::Value],
    diagnostics: &[serde_json::Value],
) {
    testing::observing().fold_entries(plugin, kind, metrics, diagnostics);
}

#[test]
fn a_bare_envelope_is_not_folded() {
    let _guard = exclusive();
    fold("p", "export", &Envelope::bare("Delivered"));
    assert!(testing::folds().is_empty());
}

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

#[test]
fn provenance_comes_from_the_handle_not_the_wire() {
    let _guard = exclusive();
    let env = Envelope {
        result: serde_json::json!({"plugin": "somebody-else", "kind": "store"}),
        metrics: vec![serde_json::json!({"name": "x_total", "type": "counter"})],
        diagnostics: Vec::new(),
    };
    fold("the-real-name", "export", &env);
    let got = testing::folds();
    assert_eq!(got[0].0, "the-real-name");
    assert_eq!(got[0].1, "export");
}

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

#[test]
fn a_second_install_is_refused() {
    struct Other;
    impl PluginObserver for Other {
        fn dropped(&self, _: u64) {}
        fn observe(&self, _: &str, _: &str, _: &[serde_json::Value], _: &[serde_json::Value]) {}
        fn refused(&self, _: &str, _: &str, _: crate::observe::BindRefusal<'_>) {}
    }
    let _guard = exclusive();
    let observing = Observing::default();
    assert!(!observing.install_observer(&Other));
    assert!(observing.observer.get().is_some());
}

#[test]
fn the_observer_and_the_host_series_are_the_dispatchers() {
    use busbar_contract::abi::mechanism::observe::SeriesDecl;
    let mine = crate::dispatch::Dispatcher::new(crate::dispatch::DispatchConfig::default());
    let other = crate::dispatch::Dispatcher::new(crate::dispatch::DispatchConfig::default());
    assert!(mine
        .observing()
        .install_host_series(|name| name == "dispatcher_owned_host_total"));
    assert!(
        !mine.observing().install_host_series(|_| true),
        "first install wins"
    );
    let claim = [SeriesDecl::new("dispatcher_owned_host_total", "counter")];
    let refused = grant_series(mine.observing(), "seam-mine", true, &claim)
        .expect_err("the host's own series is refused on the dispatcher that names it");
    assert!(refused.contains("dispatcher_owned_host_total"), "{refused}");
    let _held = grant_series(other.observing(), "seam-other", true, &claim)
        .expect("a dispatcher whose host named no series refuses nothing");

    let adopted = mine
        .adopter()
        .observing()
        .expect("an adopter of a live dispatcher");
    assert!(std::ptr::eq(&*adopted, mine.observing()));
    assert!(!std::ptr::eq(&*adopted, other.observing()));
}

#[test]
fn a_granted_shed_declaration_is_the_hosts_shed_counter() {
    use busbar_contract::abi::mechanism::observe::SeriesDecl;
    let declared = [
        SeriesDecl::new("k9b_rotated_total", "counter"),
        SeriesDecl::new("k9b_dropped_total", "counter").shed(),
        SeriesDecl::new("k9b_level", "gauge").shed(),
    ];
    let _held =
        grant_series(&testing::observing(), "k9b-first-party", true, &declared).expect("granted");
    assert_eq!(shed_series("k9b-first-party"), vec!["k9b_dropped_total"]);
    let third: Vec<SeriesDecl> = declared
        .iter()
        .map(|d| SeriesDecl::new(format!("{}_3p", d.name), d.kind.clone()).shed())
        .collect();
    let _third = grant_series(&testing::observing(), "k9b-third-party", false, &third)
        .expect("nothing to refuse");
    assert!(shed_series("k9b-third-party").is_empty());
}

#[test]
fn a_first_party_grant_goes_with_its_last_instance() {
    use busbar_contract::abi::mechanism::observe::SeriesDecl;
    let declared = [SeriesDecl::new("grant_life_total", "counter")];
    {
        let _first =
            grant_series(&testing::observing(), "grant-life", true, &declared).expect("granted");
        {
            let _second = grant_series(&testing::observing(), "grant-life", true, &declared)
                .expect("a second instance of the same plugin holds the same grant");
        }
        assert!(
            first_party("grant-life"),
            "one first-party instance still holds the grant"
        );
        assert!(first_party_series(
            "grant-life",
            "grant_life_total",
            "counter"
        ));
    }
    assert!(
        !first_party("grant-life"),
        "no first-party instance of the name is live"
    );
    assert!(!first_party_series(
        "grant-life",
        "grant_life_total",
        "counter"
    ));
    let _next = grant_series(&testing::observing(), "grant-life-next", true, &declared)
        .expect("a series whose plugin went is free for the plugin that replaces it");
}

#[test]
fn a_live_series_name_cannot_be_reclaimed_with_a_different_kind_or_shed_flag() {
    use busbar_contract::abi::mechanism::observe::SeriesDecl;
    let observing = testing::observing();
    let name = "grant_conflicting_metadata_total";
    let original = [SeriesDecl::new(name, "counter")];
    let held = grant_series(&observing, "grant-metadata-owner", true, &original)
        .expect("the first writer owns the series");
    for conflicting in [
        SeriesDecl::new(name, "gauge"),
        SeriesDecl::new(name, "counter").shed(),
    ] {
        let refused = grant_series(&observing, "grant-metadata-contender", true, &[conflicting])
            .expect_err("changing declaration metadata cannot claim another writer's name");
        assert!(refused.contains(name) && refused.contains("grant-metadata-owner"));
        assert!(!first_party("grant-metadata-contender"));
        assert!(first_party_series("grant-metadata-owner", name, "counter"));
    }
    drop(held);
    let _replacement = grant_series(
        &observing,
        "grant-metadata-contender",
        true,
        &[SeriesDecl::new(name, "gauge")],
    )
    .expect("the name is available after its last writer is gone");
}

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
            conns: crate::dispatch::ConnTable::Probe,
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

#[test]
fn a_plane_envelope_reaches_the_host_observer() {
    observed_through_its_bind::<crate::dispatch::kinds::plane::Plane>(
        crate::plane_door_plugin::door,
        busbar_contract::abi::mechanism::kind::PLANE,
    );
}

#[test]
fn an_auth_envelope_reaches_the_host_observer() {
    observed_through_its_bind::<crate::dispatch::kinds::auth::Auth>(
        crate::both_ways::door_fixture("auth-verify").1,
        busbar_contract::abi::mechanism::kind::AUTH,
    );
}

#[test]
fn a_store_envelope_reaches_the_host_observer() {
    observed_through_its_bind::<crate::dispatch::kinds::store::Store>(
        crate::both_ways::store_fixture::door,
        busbar_contract::abi::mechanism::kind::STORE,
    );
}

#[test]
fn a_hook_envelope_reaches_the_host_observer() {
    observed_through_its_bind::<crate::dispatch::kinds::hook::Hook>(
        crate::hook_door_conformance_tests::hook_door_plugin::conforming::door,
        busbar_contract::abi::mechanism::kind::HOOK,
    );
}

#[test]
fn a_secret_envelope_reaches_the_host_observer() {
    observed_through_its_bind::<crate::dispatch::kinds::secret::Secret>(
        crate::both_ways::secret_fixture::door::door,
        busbar_contract::abi::mechanism::kind::SECRET,
    );
}

#[test]
fn a_transport_envelope_reaches_the_host_observer() {
    observed_through_its_bind::<crate::dispatch::kinds::transport::Transport>(
        crate::both_ways::transport_fixture::linked::door,
        busbar_contract::abi::mechanism::kind::TRANSPORT,
    );
}

#[test]
fn an_export_envelope_reaches_the_host_observer() {
    observed_through_its_bind::<crate::dispatch::kinds::export::Export>(
        crate::both_ways::export_fixture::door,
        busbar_contract::abi::mechanism::kind::EXPORT,
    );
}

#[test]
fn a_metric_is_named_by_its_family_for_every_kind() {
    use crate::dispatch::EnvelopeSink as _;
    let guard = exclusive();
    let kinds = [
        busbar_contract::abi::mechanism::kind::PLANE,
        busbar_contract::abi::mechanism::kind::AUTH,
        busbar_contract::abi::mechanism::kind::STORE,
        busbar_contract::abi::mechanism::kind::HOOK,
        busbar_contract::abi::mechanism::kind::SECRET,
        busbar_contract::abi::mechanism::kind::TRANSPORT,
    ];
    for kind in kinds {
        testing::clear(&guard);
        let sink = EnvelopeObserver::before(
            testing::observing(),
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
            busbar_contract::abi::mechanism::kind::EXPORT,
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

    assert!(kept <= INTAKE_BOUND + 1, "kept {kept}");
    assert!(kept >= 1, "nothing reached the observer");
    assert!(
        dropped as usize >= sent - kept,
        "every back-channel not kept is counted dropped: sent {sent}, kept {kept}, dropped {dropped}"
    );
}

#[test]
fn a_reader_counts_only_its_own_tests_folds() {
    let _guard = exclusive();
    let metric = |name: &str| Envelope {
        result: (),
        metrics: vec![serde_json::json!({"name": name, "type": "counter"})],
        diagnostics: Vec::new(),
    };
    fold("scope-reader", "export", &metric("mine_total"));
    std::thread::spawn(move || fold("scope-neighbour", "export", &metric("theirs_total")))
        .join()
        .expect("the neighbour folds");
    fold("scope-reader", "export", &metric("mine_total"));
    let got = testing::folds();
    assert_eq!(
        got.iter().map(|f| f.0.as_str()).collect::<Vec<_>>(),
        ["scope-reader", "scope-reader"],
        "{got:?}"
    );
}
