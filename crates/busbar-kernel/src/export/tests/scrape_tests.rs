// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the host's scrape (`export/scrape.rs`): `/metrics` is registered only with a scrape
//! sink configured, it is the route the sink claimed, and a scrape is the sink's rendering of the
//! recorder's snapshot — the recorder's own bytes, back.

use super::*;
use crate::config::{resolve_export, ExportDefs};
use busbar_plugin_loader::{Route, RouteAuth, RouteMethod};

/// The export axis THIS test binary resolves `export:` against: the neutral rows, and the scrape
/// sink (`prometheus`) LINKED ahead of them as the composition root links it — the configuration
/// layer asks its answers to know it is the scrape sink. Every test here that resolves an `export:`
/// block installs it first (the first install holds).
pub(crate) fn installed_axis() {
    let (name, alias, _, entry) = busbar_export_prometheus::linked::EXPORT;
    let linked = busbar_plugin_loader::LinkedPlugin::first_party("export", name, alias, entry);
    crate::test_support::export_axis::install_export_axis_with(vec![linked]);
}

/// The `export:` block with one `module: prometheus` instance named `metrics`, resolved against
/// the test binary's axis (where the scrape sink is linked).
fn cfg_with_scrape_sink() -> ExportCfg {
    crate::export::scrape::tests::installed_axis();
    let defs: ExportDefs = serde_yaml::from_str(
        "metrics: { module: prometheus, settings: { buffer_seconds: 60, key_gauge_limit: 7 } }\n",
    )
    .expect("parses");
    let mut errors = Vec::new();
    let cfg = resolve_export(&defs, &mut errors);
    assert!(errors.is_empty(), "{errors:?}");
    cfg
}

/// `/metrics` is registered ONLY with a scrape sink configured — the presence-is-the-switch
/// contract — as the well-known `GET /metrics` (auth `key`), owned by the module the operator
/// named, which is what a colliding sink is refused against.
#[test]
fn metrics_route_declared_only_when_configured() {
    assert!(
        route_decl(&ExportCfg::default()).is_none(),
        "no scrape sink configured ⇒ no /metrics route (zero-config default unchanged)"
    );

    let cfg = cfg_with_scrape_sink();
    let scraped: Vec<_> = cfg
        .plugins
        .iter()
        .filter(|p| p.scrape)
        .map(|p| &p.name)
        .collect();
    assert_eq!(
        scraped,
        ["metrics"],
        "the instance subscribed to `metrics` is the scrape sink"
    );
    assert_eq!(
        cfg.recorder
            .as_ref()
            .map(|r| (r.buffer_seconds, r.key_gauge_limit)),
        Some((60, 7)),
        "the recorder's settings ride on the scrape sink's instance"
    );
    let decl = route_decl(&cfg).expect("a scrape sink ⇒ a /metrics route is declared");
    assert_eq!(decl.owner, "prometheus");
    assert_eq!(
        decl.route,
        Route {
            path: METRICS_PATH.to_string(),
            method: RouteMethod::Get,
            auth: RouteAuth::Key,
        }
    );
    assert_eq!(decl.kind, RouteKind::Export);
}

/// The declared route builds a live plugin-route table: `GET /metrics` resolves to auth `key`, so
/// the mounted handler dispatches every scrape to the host's scrape.
#[test]
fn metrics_served_via_endpoint_registration() {
    let cfg = cfg_with_scrape_sink();
    let table = crate::plugin_routes::build_route_table(crate::export::route_decls(&cfg))
        .expect("the /metrics route confines + collides cleanly");
    assert_eq!(
        table.declared_auth("/metrics", &axum::http::Method::GET),
        Some(RouteAuth::Key),
        "the built table exposes GET /metrics via the plugin endpoint registration (data-plane auth)"
    );
}

/// With nothing to render but the recorder, a scrape is a `200` Prometheus text exposition with the
/// canonical content type. `metrics::init()` installs synchronously in tests, so the recorder is
/// installed before the scrape regardless of test order (an uninstalled one answers `503`).
#[test]
fn dispatch_renders_prometheus_exposition() {
    crate::metrics::init();
    let req = EndpointRequest {
        method: "GET".into(),
        path: "/metrics".into(),
        query: String::new(),
        headers: vec![],
        body: vec![],
    };
    let resp = decl("metrics", None).dispatch.handle_http(&req);
    assert_eq!(resp.status, 200);
    assert!(
        resp.headers
            .iter()
            .any(|(k, v)| k == "content-type" && v.contains("text/plain")),
        "the exposition carries the Prometheus content type"
    );
}

/// THE SINK RENDERS THE RECORDER'S BYTES BACK: the linked scrape sink, handed the snapshot of an
/// exposition carrying every family type the recorder writes (a HELP-less counter, labels with
/// escapes, a histogram, a quantile summary), answers exactly those bytes, and the host serves that
/// answer. And the RED arm: text the snapshot cannot place is never rendered from — the host
/// serves its own bytes under its own type.
#[test]
fn the_scrape_sink_renders_the_recorder_snapshot_byte_identically() {
    let (name, alias, _, entry) = busbar_export_prometheus::linked::EXPORT;
    let axis = busbar_plugin_loader::PluginRegistry::empty()
        .link(vec![busbar_plugin_loader::LinkedPlugin::first_party(
            "export", name, alias, entry,
        )])
        .expect("linked");
    let sink = axis
        .open_export("prometheus", r#"{"buffer_seconds":60}"#)
        .expect("the scrape sink opens");
    let own = "# TYPE busbar_requests_total counter\n\
               busbar_requests_total{pool=\"a\\\"b\\\\c\\nd\",outcome=\"ok\"} 3\n\
               \n\
               # HELP busbar_request_duration_seconds request latency\n\
               # TYPE busbar_request_duration_seconds histogram\n\
               busbar_request_duration_seconds_bucket{le=\"0.5\"} 1\n\
               busbar_request_duration_seconds_bucket{le=\"+Inf\"} 2\n\
               busbar_request_duration_seconds_sum 0.75\n\
               busbar_request_duration_seconds_count 2\n\
               \n\
               # TYPE busbar_plane_request_duration_seconds summary\n\
               busbar_plane_request_duration_seconds{quantile=\"0.99\"} 0.0125\n\
               busbar_plane_request_duration_seconds_sum 1e-3\n\
               busbar_plane_request_duration_seconds_count 4\n\
               \n";
    let families = busbar_plugin_loader::scrape::snapshot(own).expect("the text snapshots");
    let (content_type, body) = sink.scrape(families).expect("the sink renders");
    assert_eq!(content_type, crate::metrics::PROMETHEUS_CONTENT_TYPE);
    assert_eq!(body, own, "the scrape is the recorder's bytes, back");
    let header = |r: &EndpointResponse| r.headers[0].1.clone();
    let served = busbar_plugin_loader::scrape::exposition(Some(&sink), Some(own.into()), "x/own");
    assert_eq!((served.status, header(&served)), (200, content_type));
    assert_eq!(
        served.body,
        own.as_bytes(),
        "the host serves the sink's rendering"
    );
    let orphan = "busbar_orphan_sample 1\n";
    let served =
        busbar_plugin_loader::scrape::exposition(Some(&sink), Some(orphan.into()), "x/own");
    assert_eq!(
        (header(&served), served.body),
        ("x/own".to_string(), orphan.as_bytes().to_vec()),
        "a sample outside a typed family is not snapshotted: the host serves its own text"
    );
    let refused = busbar_plugin_loader::scrape::exposition(Some(&sink), None, "x/own");
    assert_eq!(
        (refused.status, refused.headers, refused.body),
        (
            503,
            vec![("retry-after".to_string(), "1".to_string())],
            vec![]
        ),
        "no recorder yet: refused, never an empty success"
    );
}
