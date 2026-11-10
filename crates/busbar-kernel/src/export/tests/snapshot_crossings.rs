// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Snapshot authority across a real SDK export door, independent of product rendering.

use crate as busbar_kernel;
use busbar_contract::abi::mechanism::endpoint::EndpointRequest;
use busbar_contract::abi::mechanism::route::{Route, RouteAuth, RouteMethod};
use busbar_contract::export_calls::ExportCalls;
use std::sync::Arc;

#[path = "snapshot_export_fixture.rs"]
mod fixture;

fn sink() -> Arc<dyn ExportCalls> {
    use busbar_plugin_loader::dispatch::{
        kinds::export::Export, load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, LinkedRow,
        NoSink,
    };
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
    let row = LinkedRow::of(fixture::door).expect("the neutral kind fixture declares itself");
    let plugin = load_linked::<Export>(
        &row,
        Bind {
            instance: "export.snapshot-crossing".into(),
            max_inflight_cap: 4,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: ConnTable::NoNeeds,
        },
    )
    .expect("the SDK fixture loads with the real asynchronous host services");
    Arc::new(
        busbar_plugin_loader::export_door::ExportInstance::open(plugin, dispatcher, b"{}")
            .expect("the neutral export opens"),
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
fn route_declarations_cross_the_kind_boundary() {
    let sink = sink();
    let key = |path: &str| Route {
        path: path.to_string(),
        method: RouteMethod::Get,
        auth: RouteAuth::Key,
    };
    assert_eq!(sink.routes(), [key(fixture::WHOLE), key(fixture::HOOKS)]);
    let dispatch = busbar_kernel::export::serve_test_sink(sink.clone());
    let decls = sink
        .routes()
        .iter()
        .map(|route| busbar_kernel::plugin_routes::RouteDecl {
            owner: "snapshot-reader-witness".into(),
            source_instance: "scrape-crossing".into(),
            dispatch_available: true,
            kind: busbar_kernel::plugin_routes::RouteKind::Export,
            route: route.clone(),
            scrape: true,
            persistent: route.path == fixture::HOOKS,
            dispatch: dispatch.clone(),
        })
        .collect();
    let table = busbar_kernel::plugin_routes::build_route_table(decls).expect("both confine");
    for path in [fixture::WHOLE, fixture::HOOKS] {
        assert_eq!(
            table.declared_auth(path, &axum::http::Method::GET),
            Some(RouteAuth::Key)
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_granted_export_crossing_reads_the_real_host_snapshot() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let granted = busbar_kernel::export::serve_test_sink(sink());
    let resp = granted.handle_http(&get(fixture::WHOLE));
    assert_eq!(
        resp.status,
        200,
        "{:?}",
        String::from_utf8_lossy(&resp.body)
    );
    assert!(resp.headers.is_empty());
    assert_eq!(resp.body.len(), 12);
    assert_eq!(u32::from_le_bytes(resp.body[..4].try_into().unwrap()), 0);
    assert!(
        u64::from_le_bytes(resp.body[4..].try_into().unwrap()) > 0,
        "the actual host recorder supplied families"
    );
    let hooks = granted.handle_http(&get(fixture::HOOKS));
    let mut expected = 1_u32.to_le_bytes().to_vec();
    expected.extend(0_u64.to_le_bytes());
    assert_eq!(
        (hooks.status, hooks.headers, hooks.body),
        (200, vec![], expected)
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
async fn an_ungranted_export_crossing_cannot_read_the_snapshot() {
    use busbar_contract::export_calls::ServeRequest;
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let sink = sink();
    let request = get(fixture::WHOLE);
    let response = sink.serve(&ServeRequest {
        method: &request.method,
        path: &request.path,
        query: None,
        headers: &request.headers,
        body: &request.body,
    });
    assert!(
        response.is_err(),
        "an ungranted SDK export cannot read the host snapshot"
    );
    assert_eq!(
        busbar_kernel::export::read_test_snapshot(0).await,
        busbar_contract::services::Snapshot::Refused(
            "the snapshot is lent only to the crossing granted it"
        )
    );
}
