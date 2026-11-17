// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

fn served_session(
    handle: &Arc<crate::state::AppHandle>,
    handler: crate::plane_routes::PlaneSessionFn,
) -> axum::Router {
    let router = super::mount_plane_session(
        crate::core_routes::CoreRouter::new(),
        Arc::new(()),
        crate::plane_routes::PlaneSessionSpec {
            path: "/owned-session".into(),
            auth: busbar_contract::abi::mechanism::route::RouteAuth::None,
            handler,
        },
    );
    let (router, routes) = router.into_parts();
    super::apply_common_layers(router, routes, handle, 16, false)
}

#[tokio::test]
async fn actual_session_dispatch_retains_the_original_request_and_live_handle() {
    use crate::limits::process_admission::{AdmissionClass, ProcessAdmission};
    use tower::ServiceExt as _;
    let pinned = crate::inbound::native::tests::app();
    let handle = Arc::new(crate::state::AppHandle::new(
        crate::inbound::native::tests::app(),
    ));
    let budget = ProcessAdmission::with_limits(2, 32, 4);
    let request = budget.try_enter(AdmissionClass::Operator).unwrap();
    let (admit, mut admissions) = tokio::sync::mpsc::unbounded_channel();
    let slot = crate::plane_routes::FramedSession::with_admission(admit, 71);
    let (seen, received) = tokio::sync::oneshot::channel();
    let seen = Arc::new(std::sync::Mutex::new(Some(seen)));
    let router = served_session(
        &handle,
        Arc::new(move |ctx| {
            let seen = Arc::clone(&seen);
            Box::pin(async move {
                assert!(ctx.body.is_empty());
                let _ = seen.lock().unwrap().take().unwrap().send((
                    ctx.request,
                    ctx.handle,
                    ctx.engine,
                ));
                let mut response = axum::response::Response::new(axum::body::Body::empty());
                *response.status_mut() = axum::http::StatusCode::NO_CONTENT;
                crate::plane_routes::SessionAnswer::Refused(response)
            })
        }),
    );
    let response = router.oneshot(
        axum::http::Request::builder()
            .uri("/owned-session")
            .extension(request.clone())
            .extension(slot)
            .extension(Arc::clone(&pinned))
            .body(axum::body::Body::empty())
            .unwrap(),
    );
    let admit = async {
        let admission = admissions.recv().await.unwrap();
        assert_eq!(admission.stream, 71);
        admission.reply.send(true).unwrap();
    };
    let (response, ()) = tokio::join!(response, admit);
    assert_eq!(
        response.unwrap().status(),
        axum::http::StatusCode::NO_CONTENT
    );
    let (inherited, actual_handle, engine) = received.await.unwrap();
    assert!(request.same_request(&inherited));
    assert_eq!(inherited.class(), AdmissionClass::Operator);
    assert!(Arc::ptr_eq(&actual_handle, &handle));
    let engine = engine.downcast::<crate::state::App>().ok().unwrap();
    assert!(Arc::ptr_eq(&engine, &pinned));
}

#[tokio::test]
async fn a_missing_original_request_cannot_consume_session_admission() {
    use tower::ServiceExt as _;
    let handle = Arc::new(crate::state::AppHandle::new(
        crate::inbound::native::tests::app(),
    ));
    let (admit, mut admissions) = tokio::sync::mpsc::unbounded_channel();
    let slot = crate::plane_routes::FramedSession::with_admission(admit, 72);
    let router = served_session(
        &handle,
        Arc::new(|_| {
            Box::pin(async {
                panic!("missing original request cannot enter a session handler");
            })
        }),
    );
    let response = router
        .oneshot(
            axum::http::Request::builder()
                .uri("/owned-session")
                .extension(slot)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    );
    assert!(
        admissions.try_recv().is_err(),
        "the upgrade slot remains untouched"
    );
}
