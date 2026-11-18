// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use busbar_contract::abi::mechanism::route::{RouteAuth, RouteMethod};
use busbar_kernel::plane_routes::{PlaneReqCtx, PlaneRouteSpec};

const DOOR: &str = "/door-route-test/call";

fn door(auth: RouteAuth) -> PlaneRouteSpec {
    door_at(DOOR, auth)
}

fn door_at(path: &str, auth: RouteAuth) -> PlaneRouteSpec {
    PlaneRouteSpec {
        path: path.to_string(),
        method: RouteMethod::Post,
        auth,
        handler: Arc::new(|ctx: PlaneReqCtx| {
            Box::pin(async move {
                let body = format!("door {} {}", ctx.path, String::from_utf8_lossy(&ctx.body));
                axum::response::Response::new(axum::body::Body::from(body))
            })
        }),
    }
}

#[test]
fn a_door_route_is_recorded_at_the_bar_it_declares() {
    let table = crate::router::base_data_router(
        &crate::plugin_routes::PluginRouteTable::default(),
        &Default::default(),
        None,
        vec![door(RouteAuth::Key)],
    )
    .1;
    let row = table
        .routes()
        .iter()
        .find(|r| r.path == DOOR)
        .map(|r| (r.method.as_str(), r.auth));
    assert_eq!(row, Some(("POST", RouteAuth::Key)));
}

#[test]
fn adding_an_instance_owned_route_preserves_existing_bars_and_exact_method_scope() {
    use axum::http::{Method, StatusCode};
    let (router, core_routes) = crate::router::base_data_router(
        &crate::plugin_routes::PluginRouteTable::default(),
        &Default::default(),
        None,
        vec![door(RouteAuth::Key)],
    );
    let prepared = crate::router::PreparedListener {
        router,
        core_routes,
        physical: None,
        data: None,
        refusals: Vec::new(),
        refuse_by_path: None,
        root_surface: true,
        dispatch_layer: |router| router,
    }
    .with_core_routes(|routes| {
        routes.route(
            "/provision/idp/{*rest}",
            RouteMethod::Post,
            RouteAuth::None,
            || async { StatusCode::NO_CONTENT },
        )
    });
    assert_eq!(
        prepared.core_routes.declared_auth(DOOR, &Method::POST),
        Some(RouteAuth::Key)
    );
    assert_eq!(
        prepared
            .core_routes
            .declared_auth("/provision/idp/{*rest}", &Method::POST),
        Some(RouteAuth::None)
    );
    assert_eq!(
        prepared
            .core_routes
            .declared_auth("/provision/idp/{*rest}", &Method::DELETE),
        None
    );
    assert_eq!(
        prepared
            .core_routes
            .declared_auth("/provision/other/{*rest}", &Method::POST),
        None
    );
}

fn served_route(
    handle: &Arc<crate::state::AppHandle>,
    max_body: usize,
    handler: crate::plane_routes::PlaneRouteFn,
) -> axum::Router {
    let router = super::mount_plane_route(
        crate::core_routes::CoreRouter::new(),
        Arc::new(()),
        PlaneRouteSpec {
            path: DOOR.into(),
            method: RouteMethod::Post,
            auth: RouteAuth::None,
            handler,
        },
    );
    let (router, routes) = router.into_parts();
    super::apply_common_layers(router, routes, handle, max_body, false)
}

#[tokio::test]
async fn actual_route_keeps_original_lease_handle_and_pinned_snapshot_through_body_backing() {
    use crate::limits::process_admission::{AdmissionClass, ProcessAdmission};
    use tower::ServiceExt as _;
    let pinned = crate::inbound::native::tests::app();
    let handle = Arc::new(crate::state::AppHandle::new(
        crate::inbound::native::tests::app(),
    ));
    assert!(!Arc::ptr_eq(&pinned, &handle.load()));
    let budget = ProcessAdmission::with_limits(2, 32, 4);
    let request = budget.try_enter(AdmissionClass::Data).unwrap();
    let source = request.copy_input(b"abc").unwrap().into_bytes();
    let (seen, received) = tokio::sync::oneshot::channel();
    let seen = Arc::new(std::sync::Mutex::new(Some(seen)));
    let router = served_route(
        &handle,
        3,
        Arc::new(move |ctx| {
            let seen = Arc::clone(&seen);
            Box::pin(async move {
                let _ = seen.lock().unwrap().take().unwrap().send((
                    ctx.request,
                    ctx.handle,
                    ctx.engine,
                ));
                axum::response::Response::new(axum::body::Body::from(ctx.body))
            })
        }),
    );
    let response = router
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(DOOR)
                .extension(request.clone())
                .extension(Arc::clone(&pinned))
                .body(axum::body::Body::from(source.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let (inherited, actual_handle, engine) = received.await.unwrap();
    assert!(request.same_request(&inherited));
    assert!(Arc::ptr_eq(&actual_handle, &handle));
    assert!(Arc::ptr_eq(
        &engine.downcast::<crate::state::App>().ok().unwrap(),
        &pinned
    ));
    assert_eq!(
        budget.used(),
        (6, 6),
        "opaque source and retained gather own independent credits"
    );
    drop(source);
    drop(inherited);
    drop(request);
    assert_eq!(budget.used(), (3, 3));
    assert!(budget.try_enter(AdmissionClass::Data).is_err());
    drop(response);
    assert_eq!(budget.used(), (0, 0));
    assert!(budget.try_enter(AdmissionClass::Data).is_ok());
}

#[tokio::test]
async fn actual_route_missing_admission_refuses_before_polling_input() {
    use futures::stream;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tower::ServiceExt as _;
    let handle = Arc::new(crate::state::AppHandle::new(
        crate::inbound::native::tests::app(),
    ));
    let polled = Arc::new(AtomicUsize::new(0));
    let input_polled = Arc::clone(&polled);
    let body = axum::body::Body::from_stream(stream::poll_fn(move |_| {
        input_polled.fetch_add(1, Ordering::SeqCst);
        std::task::Poll::Ready(Some(Ok::<_, std::io::Error>(bytes::Bytes::from_static(
            b"unread",
        ))))
    }));
    let router = served_route(
        &handle,
        16,
        Arc::new(|_| {
            Box::pin(async { panic!("missing original admission cannot reach dispatch") })
        }),
    );
    let response = router
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(DOOR)
                .body(body)
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(polled.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn actual_route_distinguishes_configured_message_limit_and_shared_capacity() {
    use crate::limits::process_admission::{AdmissionClass, ProcessAdmission};
    use tower::ServiceExt as _;
    let handle = Arc::new(crate::state::AppHandle::new(
        crate::inbound::native::tests::app(),
    ));
    for capacity in [false, true] {
        let budget = ProcessAdmission::with_limits(2, 10, 2);
        let request = budget.try_enter(AdmissionClass::Data).unwrap();
        let held = capacity.then(|| request.try_reserve(8).unwrap());
        let router = served_route(
            &handle,
            3,
            Arc::new(|_| Box::pin(async { panic!("refused input cannot reach dispatch") })),
        );
        let payload = if capacity { "x" } else { "abcd" };
        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(DOOR)
                    .extension(request.clone())
                    .body(axum::body::Body::from(payload))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            if capacity {
                axum::http::StatusCode::SERVICE_UNAVAILABLE
            } else {
                axum::http::StatusCode::PAYLOAD_TOO_LARGE
            }
        );
        assert_eq!(budget.used(), if capacity { (8, 8) } else { (0, 0) });
        drop(held);
        assert_eq!(budget.used(), (0, 0));
    }
}

#[tokio::test]
async fn cancelling_the_actual_route_gather_reclaims_its_partial_output() {
    use crate::limits::process_admission::{AdmissionClass, ProcessAdmission};
    use futures::{stream, StreamExt as _};
    use tower::ServiceExt as _;
    let handle = Arc::new(crate::state::AppHandle::new(
        crate::inbound::native::tests::app(),
    ));
    let budget = ProcessAdmission::with_limits(2, 32, 4);
    let request = budget.try_enter(AdmissionClass::Data).unwrap();
    let input = stream::iter([Ok::<_, std::io::Error>(bytes::Bytes::from_static(b"part"))])
        .chain(stream::pending());
    let router = served_route(
        &handle,
        16,
        Arc::new(|_| Box::pin(async { panic!("unfinished input cannot reach dispatch") })),
    );
    let mut response = Box::pin(
        router.oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(DOOR)
                .extension(request.clone())
                .body(axum::body::Body::from_stream(input))
                .unwrap(),
        ),
    );
    assert!(futures::poll!(&mut response).is_pending());
    assert_eq!(budget.used(), (4, 4));
    drop(response);
    assert_eq!(budget.used(), (0, 0));
    drop(request);
    assert!(budget.try_enter(AdmissionClass::Data).is_ok());
}

#[tokio::test]
async fn actual_route_read_failure_reclaims_partial_input_before_refusing() {
    use crate::limits::process_admission::{AdmissionClass, ProcessAdmission};
    use futures::stream;
    use tower::ServiceExt as _;
    let handle = Arc::new(crate::state::AppHandle::new(
        crate::inbound::native::tests::app(),
    ));
    let budget = ProcessAdmission::with_limits(2, 32, 4);
    let request = budget.try_enter(AdmissionClass::Data).unwrap();
    let input = stream::iter([
        Ok(bytes::Bytes::from_static(b"part")),
        Err(std::io::Error::other("reader fixture failure")),
    ]);
    let router = served_route(
        &handle,
        16,
        Arc::new(|_| {
            Box::pin(async {
                panic!("failed input cannot reach dispatch");
            })
        }),
    );
    let response = router
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(DOOR)
                .extension(request.clone())
                .body(axum::body::Body::from_stream(input))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    assert_eq!(budget.used(), (0, 0));
}
