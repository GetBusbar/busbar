// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::config::{resolve_export, ExportCfg, ExportDefs};
use crate::test_support::export_axis::{
    scrape_module, SCRAPE_DOUBLE_CONTENT_TYPE, SCRAPE_DOUBLE_HOOKS_CONTENT_TYPE,
};
use busbar_contract::abi::mechanism::route::{Route, RouteAuth, RouteMethod};
use busbar_contract::export_calls::{ExportAxis, ExportCalls};

pub(crate) fn installed_axis() {
    crate::test_support::export_axis::install_export_axis();
}

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

fn get(path: &str) -> EndpointRequest {
    EndpointRequest {
        method: "GET".into(),
        path: path.into(),
        query: String::new(),
        headers: vec![],
        body: vec![],
    }
}

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
            source_instance: "prometheus".into(),
            dispatch_available: true,
            kind: crate::plugin_routes::RouteKind::Export,
            route: route.clone(),
            scrape: true,
            persistent: route.path == "/metrics/hooks",
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

#[test]
fn a_granted_scrape_is_the_sinks_rendering_of_the_snapshot() {
    crate::snapshot::init_for_test(std::time::Duration::from_secs(3600));
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

#[test]
fn an_ungranted_crossing_reads_no_snapshot() {
    crate::snapshot::init_for_test(std::time::Duration::from_secs(3600));
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

#[test]
fn the_lend_lasts_exactly_the_crossing() {
    crate::snapshot::init_for_test(std::time::Duration::from_secs(3600));
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
