// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The former kernel scrape-double oracles, crossing the actual linked exporter.

use busbar_contract::abi::mechanism::endpoint::EndpointRequest;
use busbar_contract::abi::mechanism::route::{Route, RouteAuth, RouteMethod};
use busbar_contract::export_calls::ExportCalls;
use std::sync::Arc;

fn sink() -> Arc<dyn ExportCalls> {
    use crate::root::loader::dispatch::{
        kinds::export::Export, load_dropped, rendering_of_library, Bind, ConnTable, DispatchConfig,
        Dispatcher, NoSink,
    };
    crate::dist_root_install::install();
    let path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_TEST_PROMETHEUS_CDYLIB")
            .expect("the actual qualified metrics exporter is required"),
    );
    let statement = rendering_of_library(&path).unwrap().unwrap();
    let mut services = busbar_kernel::host_services::KernelServices::new();
    if let Ok(runtime) = tokio::runtime::Handle::try_current() {
        services = services.with_pool(Arc::new(busbar_kernel::host_services::BlockingPool::new(
            runtime, 64,
        )));
    }
    let dispatcher = Arc::new(Dispatcher::with_services(
        DispatchConfig::default(),
        Arc::new(services),
        busbar_kernel::host_services::caller_binding(),
    ));
    crate::root::connector::install_io(&dispatcher);
    let transport_settings = busbar_contract::transport::TransportSettings::default();
    let conns = busbar_core_connector::process::build_with_secrets(
        || {
            crate::root::connector::entries_on(
                &dispatcher,
                crate::LINKED_TRANSPORT_DOORS,
                &transport_settings,
            )
        },
        busbar_core_connector::process::dest_judge(&busbar_kernel::config::Destinations {
            block_private_addresses: true,
            ..Default::default()
        })
        .expect("the scrape fixture's native destination guard builds"),
        &[],
        dispatcher.conn_waker(),
        crate::root::connector::pool_posture(&transport_settings),
        crate::root::connector::spawn_secret_resolver(),
    )
    .expect("the scrape fixture builds its actual linked transport connection table");
    let plugin = load_dropped::<Export>(
        &path,
        &statement,
        Bind {
            instance: "export.scrape-crossing".into(),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: ConnTable::Host(conns),
        },
    )
    .expect("the actual scrape exporter loads with its asynchronous host services");
    Arc::new(
        crate::root::loader::export_door::ExportInstance::open(
            plugin,
            dispatcher,
            br#"{"buffer_seconds":60}"#,
        )
        .expect("the actual linked scrape sink opens"),
    )
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_granted_scrape_is_the_actual_sinks_rendering_of_the_snapshot() {
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
        busbar_kernel::export::read_test_snapshot(0).await,
        busbar_contract::services::Snapshot::Refused(
            "the snapshot is lent only to the crossing granted it"
        )
    );
}

// SERVE is synchronous while the actual host schedules the refused read on this runtime.
// Keep a worker available to deliver that refusal, as for the granted crossing above.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ungranted_actual_sink_cannot_read_the_snapshot() {
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
        busbar_kernel::export::read_test_snapshot(0).await,
        busbar_contract::services::Snapshot::Refused(
            "the snapshot is lent only to the crossing granted it"
        )
    );
}
