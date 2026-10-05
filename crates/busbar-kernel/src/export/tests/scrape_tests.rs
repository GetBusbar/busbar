// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the host snapshot service (`export/scrape.rs`): `/metrics` and `/metrics/hooks` are
//! the scrape sink's OWN routes, answered by its `serve` over `snapshot.read` (owner law
//! 2026-09-27; ARCHITECT Q-U2-4); the snapshot is lent only to the crossing granted it; and the
//! sink renders the recorder's bytes back.

use super::*;
use crate::config::{resolve_export, ExportCfg, ExportDefs};
use busbar_contract::abi::mechanism::route::{Route, RouteAuth, RouteMethod};
use busbar_contract::export_calls::{ExportAxis, ExportCalls};

/// The export axis THIS test binary resolves `export:` against: the neutral rows, and the scrape
/// sink (`prometheus`) LINKED ahead of them as the composition root links it — the configuration
/// layer asks its answers to know it is the scrape sink. Every test here that resolves an `export:`
/// block installs it first (the first install holds).
pub(crate) fn installed_axis() {
    crate::test_support::export_axis::install_first_party_door(
        busbar_export_prometheus::NAME,
        busbar_export_prometheus::ALIAS,
        busbar_export_prometheus::door::door,
    );
}

/// The scrape sink, opened as boot opens it, on the test dispatcher (which serves the kernel's host
/// services).
fn scrape_sink() -> Arc<dyn ExportCalls> {
    installed_axis();
    crate::test_support::export_axis::STAND_IN
        .open(
            "prometheus",
            "export.metrics",
            &serde_json::json!({"buffer_seconds": 60}),
        )
        .expect("the scrape sink opens")
}

/// A `GET` of `path`.
fn get(path: &str) -> EndpointRequest {
    EndpointRequest {
        method: "GET".into(),
        path: path.into(),
        query: String::new(),
        headers: vec![],
        body: vec![],
    }
}

/// The instance subscribed to `metrics` is the scrape sink, and the recorder's settings ride on it.
#[test]
fn the_metrics_instance_is_the_scrape_sink() {
    installed_axis();
    let defs: ExportDefs = serde_yaml::from_str(
        "metrics: { module: prometheus, settings: { buffer_seconds: 60, key_gauge_limit: 7 } }\n",
    )
    .expect("parses");
    let mut errors = Vec::new();
    let cfg = resolve_export(&defs, &mut errors);
    assert!(errors.is_empty(), "{errors:?}");
    let scraped: Vec<_> = cfg
        .plugins
        .iter()
        .filter(|p| p.scrape)
        .map(|p| &p.name)
        .collect();
    assert_eq!(scraped, ["metrics"]);
    assert_eq!(
        cfg.recorder
            .as_ref()
            .map(|r| (r.buffer_seconds, r.key_gauge_limit)),
        Some((60, 7)),
        "the recorder's settings ride on the scrape sink's instance"
    );
}

/// THE ROUTES ARE THE SINK'S (owner law: "the kernel owns no route that exists for one plugin"):
/// with no scrape sink configured nothing declares `/metrics` (the presence-is-the-switch
/// contract); the scrape sink DECLARES `GET /metrics` and `GET /metrics/hooks` behind the data
/// plane's key, and its declarations build a live route table — the kernel declares neither.
#[test]
fn metrics_route_declared_only_when_configured() {
    assert!(
        crate::export::route_decls(&ExportCfg::default()).is_empty(),
        "no scrape sink configured ⇒ no /metrics route (zero-config default unchanged)"
    );
    let sink = scrape_sink();
    let key = |path: &str| Route {
        path: path.to_string(),
        method: RouteMethod::Get,
        auth: RouteAuth::Key,
    };
    assert_eq!(sink.routes(), [key("/metrics"), key("/metrics/hooks")]);
    let decls = sink
        .routes()
        .iter()
        .map(|route| crate::plugin_routes::RouteDecl {
            owner: "prometheus".into(),
            kind: crate::plugin_routes::RouteKind::Export,
            route: route.clone(),
            scrape: true,
            dispatch: Arc::new(Granted(Arc::new(super::super::plugin::Served(
                sink.clone(),
            )))),
        })
        .collect();
    let table = crate::plugin_routes::build_route_table(decls).expect("both confine");
    for path in ["/metrics", "/metrics/hooks"] {
        assert_eq!(
            table.declared_auth(path, &axum::http::Method::GET),
            Some(RouteAuth::Key)
        );
    }
}

/// THE GRANTED SCRAPE: through the grant, `GET /metrics` is the sink's `200` rendering of the
/// recorder's snapshot under 1.5.5's content type, and `GET /metrics/hooks` the hook rendering
/// under its own (the app-less arm folds no hook, so it is empty).
#[test]
fn a_granted_scrape_is_the_sinks_rendering_of_the_snapshot() {
    crate::snapshot::init();
    let granted = Granted(Arc::new(super::super::plugin::Served(scrape_sink())));
    let resp = granted.handle_http(&get("/metrics"));
    assert_eq!(
        resp.status,
        200,
        "{:?}",
        String::from_utf8_lossy(&resp.body)
    );
    assert_eq!(
        resp.headers,
        [(
            "content-type".to_string(),
            "text/plain; version=0.0.4".to_string()
        )]
    );
    let text = String::from_utf8(resp.body).expect("UTF-8");
    let families = busbar_contract::export_calls::parse_families(&text).expect("an exposition");
    assert!(!families.is_empty(), "the recorder's families, rendered");
    let hooks = granted.handle_http(&get("/metrics/hooks"));
    assert_eq!(
        (hooks.status, hooks.headers, hooks.body),
        (
            200,
            vec![(
                "content-type".to_string(),
                "text/plain; version=0.0.4; charset=utf-8".to_string()
            )],
            vec![]
        )
    );
}

/// RED: the snapshot is lent ONLY to the crossing granted it. The same sink's route dispatched
/// without the grant reads nothing (a `502` with no body, never the host's own text), and a read
/// from no crossing is refused.
#[test]
fn an_ungranted_crossing_reads_no_snapshot() {
    crate::snapshot::init();
    let served = super::super::plugin::Served(scrape_sink());
    let resp = crate::plugin_routes::PluginHttpDispatch::handle_http(&served, &get("/metrics"));
    assert_eq!(
        (resp.status, resp.headers, resp.body),
        (502, vec![], vec![])
    );
    assert_eq!(
        read(busbar_contract::abi::host::service::SNAPSHOT_SCOPE_WHOLE),
        Snapshot::Refused(NOT_GRANTED)
    );
}

/// The lend is the crossing's: inside it the read answers (and the read takes the lend, so a
/// crossing the read makes is not lent it, then restores it); an unknown scope is refused; after
/// the crossing nothing is lent.
#[test]
fn the_lend_lasts_exactly_the_crossing() {
    crate::snapshot::init();
    lend(None, || {
        assert!(matches!(
            read(busbar_contract::abi::host::service::SNAPSHOT_SCOPE_WHOLE),
            Snapshot::Families(_)
        ));
        assert_eq!(
            read(busbar_contract::abi::host::service::SNAPSHOT_SCOPE_HOOKS),
            Snapshot::Families(Vec::new()),
            "read again in the same crossing: the lend was restored"
        );
        assert_eq!(read(7), Snapshot::Refused(UNKNOWN_SCOPE));
    });
    assert_eq!(read(0), Snapshot::Refused(NOT_GRANTED));
}

/// THE SINK RENDERS THE RECORDER'S BYTES BACK: the linked scrape sink, handed the snapshot of an
/// exposition carrying every family type the recorder writes (a HELP-less counter, labels with
/// escapes, a histogram, a quantile summary), answers exactly those bytes.
#[test]
fn the_scrape_sink_renders_the_recorder_snapshot_byte_identically() {
    let sink = scrape_sink();
    // Listed in the sink's stable order — every counter, then every gauge, then every
    // histogram/summary (v1.5.5's own renderer drains its maps in that fixed order), name-sorted
    // within a kind — so the bytes come back unchanged.
    let own = "# TYPE busbar_requests_total counter\n\
               busbar_requests_total{pool=\"a\\\"b\\\\c\\nd\",outcome=\"ok\"} 3\n\
               \n\
               # TYPE busbar_plane_request_duration_seconds summary\n\
               busbar_plane_request_duration_seconds{quantile=\"0.99\"} 0.0125\n\
               busbar_plane_request_duration_seconds_sum 1e-3\n\
               busbar_plane_request_duration_seconds_count 4\n\
               \n\
               # HELP busbar_request_duration_seconds request latency\n\
               # TYPE busbar_request_duration_seconds histogram\n\
               busbar_request_duration_seconds_bucket{le=\"0.5\"} 1\n\
               busbar_request_duration_seconds_bucket{le=\"+Inf\"} 2\n\
               busbar_request_duration_seconds_sum 0.75\n\
               busbar_request_duration_seconds_count 2\n\
               \n";
    let families = busbar_contract::export_calls::parse_families(own).expect("the text snapshots");
    let body = sink.scrape(&families).expect("the sink renders");
    assert_eq!(
        body,
        own.as_bytes(),
        "the scrape is the recorder's bytes, back"
    );
}
