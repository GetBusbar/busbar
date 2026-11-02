// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The former kernel scrape-double oracles, crossing the actual linked exporter.

use busbar_contract::abi::mechanism::endpoint::EndpointRequest;
use busbar_contract::abi::mechanism::route::{Route, RouteAuth, RouteMethod};
use busbar_contract::export_calls::{ExportAxis, ExportCalls};
use std::sync::Arc;

fn sink() -> Arc<dyn ExportCalls> {
    crate::dist_root_install::install();
    crate::root::exports::EXPORTS
        .open(
            "prometheus",
            "export.scrape-crossing",
            &serde_json::json!({"buffer_seconds": 60}),
        )
        .expect("the actual linked scrape sink opens")
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
fn metrics_route_declarations_come_from_the_actual_sink() {
    let sink = sink();
    let key = |path: &str| Route {
        path: path.to_string(),
        method: RouteMethod::Get,
        auth: RouteAuth::Key,
    };
    assert_eq!(sink.routes(), [key("/metrics"), key("/metrics/hooks")]);
    let dispatch = busbar_kernel::export::serve_test_sink(sink.clone());
    let decls = sink
        .routes()
        .iter()
        .map(|route| busbar_kernel::plugin_routes::RouteDecl {
            owner: "prometheus".into(),
            source_instance: "scrape-crossing".into(),
            dispatch_available: true,
            kind: busbar_kernel::plugin_routes::RouteKind::Export,
            route: route.clone(),
            scrape: true,
            persistent: route.path == "/metrics/hooks",
            dispatch: dispatch.clone(),
        })
        .collect();
    let table = busbar_kernel::plugin_routes::build_route_table(decls).expect("both confine");
    for path in ["/metrics", "/metrics/hooks"] {
        assert_eq!(
            table.declared_auth(path, &axum::http::Method::GET),
            Some(RouteAuth::Key)
        );
    }
}

#[test]
fn a_granted_scrape_is_the_actual_sinks_rendering_of_the_snapshot() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let granted = busbar_kernel::export::serve_test_sink(sink());
    let resp = granted.handle_http(&get("/metrics"));
    assert_eq!(
        resp.status,
        200,
        "{:?}",
        String::from_utf8_lossy(&resp.body)
    );
    assert_eq!(
        resp.headers,
        [("content-type".into(), "text/plain; version=0.0.4".into())]
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
                "content-type".into(),
                "text/plain; version=0.0.4; charset=utf-8".into()
            )],
            vec![]
        )
    );
    assert_eq!(
        busbar_kernel::export::read_test_snapshot(0),
        busbar_contract::services::Snapshot::Refused(
            "the snapshot is lent only to the crossing granted it"
        )
    );
}

#[test]
fn an_ungranted_actual_sink_cannot_read_the_snapshot() {
    use busbar_contract::export_calls::ServeRequest;
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let sink = sink();
    let request = get("/metrics");
    let response = sink.serve(&ServeRequest {
        method: &request.method,
        path: &request.path,
        query: None,
        headers: &request.headers,
        body: &request.body,
    });
    assert!(
        response.is_err(),
        "the actual exporter must refuse an ungranted snapshot read"
    );
    assert_eq!(
        busbar_kernel::export::read_test_snapshot(0),
        busbar_contract::services::Snapshot::Refused(
            "the snapshot is lent only to the crossing granted it"
        )
    );
}
