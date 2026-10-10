// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the host snapshot service (`export/scrape.rs`): `/metrics` and `/metrics/hooks` are
//! the scrape sink's OWN routes, answered by its `serve` over `snapshot.read` (owner law
//! 2026-09-27; ARCHITECT Q-U2-4); the snapshot is lent only to the crossing granted it; and what the
//! sink answers reaches the scrape verbatim. The sink here is the stand-in axis's scrape DOUBLE
//! (`test_support::export_axis::ScrapeDouble`, R-FIX3); the real scrape sink's rendering is proven
//! where it is linked (`crates/busbar/tests/export_scrape_linked_sink.rs`).

use super::*;
use crate::config::{resolve_export, ExportCfg, ExportDefs};
use crate::test_support::export_axis::{
    scrape_module, SCRAPE_DOUBLE_CONTENT_TYPE, SCRAPE_DOUBLE_HOOKS_CONTENT_TYPE,
};
use busbar_contract::abi::mechanism::route::{Route, RouteAuth, RouteMethod};
use busbar_contract::export_calls::{ExportAxis, ExportCalls};

/// The export axis THIS test binary resolves `export:` against: the neutral rows, and the scrape
/// double answering the frozen scrape module word (`prometheus`) linked ahead of them, as the
/// composition root links its scrape sink — the configuration layer asks its answers to know it is
/// the scrape sink. Every test here that resolves an `export:` block installs it first (the first
/// install holds, and every install in this binary is this one).
pub(crate) fn installed_axis() {
    crate::test_support::export_axis::install_export_axis();
}

/// The scrape sink, opened as boot opens it, on the stand-in axis.
fn scrape_sink() -> Arc<dyn ExportCalls> {
    installed_axis();
    crate::test_support::export_axis::STAND_IN
        .open(
            scrape_module(),
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
/// recorder's snapshot under the sink's own content type, and `GET /metrics/hooks` the hook
/// rendering under its own (the app-less arm folds no hook, so it is empty) — the kernel passes the
/// sink's answer through verbatim, headers included.
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
            SCRAPE_DOUBLE_CONTENT_TYPE.to_string()
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
                SCRAPE_DOUBLE_HOOKS_CONTENT_TYPE.to_string()
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
