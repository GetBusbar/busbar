// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the host's scrape (`export/scrape.rs`): `/metrics` is registered only with a scrape
//! sink configured, it is the route the sink claimed, and a scrape is the sink's rendering of the
//! recorder's snapshot — the recorder's own bytes, back.

use super::*;
use crate::config::{resolve_export, ExportDefs};
use busbar_contract::abi::mechanism::route::{Route, RouteAuth, RouteMethod};
use busbar_contract::export_calls::ExportAxis;

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

/// THE KERNEL RENDERS NO EXPOSITION (D4, TODO step 26). RED: with the recorder installed and no
/// sink to render it, `/metrics` is a `502` with no body — the host never serves bytes of its own
/// (before D4 it answered `200` with the recorder's own text). The control: the same scrape through
/// a sink is a `200` of that sink's bytes under the exposition's content type.
#[test]
fn without_a_sink_the_kernel_serves_no_exposition() {
    crate::metrics::init();
    let req = EndpointRequest {
        method: "GET".into(),
        path: "/metrics".into(),
        query: String::new(),
        headers: vec![],
        body: vec![],
    };
    let resp = decl("metrics", Box::new(|| None))
        .dispatch
        .handle_http(&req);
    assert_eq!(
        (resp.status, resp.headers, resp.body),
        (502, vec![], vec![]),
        "no sink renders: the kernel has no exposition of its own to serve"
    );
    let resp = crate::test_support::export_axis::lines_scrape_route()
        .dispatch
        .handle_http(&req);
    assert_eq!(resp.status, 200);
    assert_eq!(
        resp.headers,
        vec![("content-type".to_string(), CONTENT_TYPE.to_string())]
    );
    let snapshot = crate::metrics::snapshot().expect("the recorder is installed");
    assert!(
        resp.body.starts_with(b"# "),
        "the sink's rendering of a non-empty snapshot ({} families)",
        snapshot.len()
    );
}

/// THE SINK RENDERS THE RECORDER'S BYTES BACK: the linked scrape sink, handed the snapshot of an
/// exposition carrying every family type the recorder writes (a HELP-less counter, labels with
/// escapes, a histogram, a quantile summary), answers exactly those bytes, and the host serves that
/// answer. And the RED arms: a sink that does not render is a `502`, never the host's own bytes;
/// no recorder yet is a `503`.
#[test]
fn the_scrape_sink_renders_the_recorder_snapshot_byte_identically() {
    installed_axis();
    let sink = crate::test_support::export_axis::STAND_IN
        .open(
            "prometheus",
            "export.metrics",
            &serde_json::json!({"buffer_seconds": 60}),
        )
        .expect("the scrape sink opens");
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
    let served = exposition(Some(&*sink), Some(families.clone()));
    assert_eq!(
        (served.status, served.headers[0].1.clone()),
        (200, CONTENT_TYPE.to_string())
    );
    assert_eq!(
        served.body,
        own.as_bytes(),
        "the host serves the sink's rendering"
    );
    struct Fails;
    impl busbar_contract::export_calls::ExportCalls for Fails {
        fn streams(&self) -> &[u8] {
            &[]
        }
        fn routes(&self) -> &[Route] {
            &[]
        }
        fn deliver(
            &self,
            _: u8,
            _: Vec<u8>,
            _: Box<dyn Send>,
        ) -> busbar_contract::export_calls::Delivered {
            busbar_contract::export_calls::Delivered::Shed
        }
        fn scrape(&self, _: &[busbar_contract::export_calls::Family]) -> Result<Vec<u8>, String> {
            Err("faulted".into())
        }
        fn status(&self) -> Option<Vec<u8>> {
            None
        }
        fn serve(
            &self,
            _: &busbar_contract::export_calls::ServeRequest<'_>,
        ) -> Result<busbar_contract::export_calls::Served, String> {
            Err("no route".into())
        }
    }
    let failed = exposition(Some(&Fails), Some(families));
    assert_eq!(
        (failed.status, failed.headers, failed.body),
        (502, vec![], vec![]),
        "a sink that does not render: a 502, never the host's own text"
    );
    let refused = exposition(Some(&*sink), None);
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
