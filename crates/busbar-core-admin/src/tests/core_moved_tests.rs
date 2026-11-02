// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use axum::Router;

#[tokio::test]
async fn split_admin_listener_no_double_exposure() {
    use busbar_kernel::governance::GovState;
    use busbar_kernel_testkit::test_support::store_double::MemoryStore;
    use busbar_kernel_testkit::test_support::LaneSpec;
    use std::sync::Arc;
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));

    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());

    let app = crate::new_test_app()
        .lane(LaneSpec::new(
            "test-model",
            crate::linked_protocol(),
            "http://127.0.0.1:1",
        ))
        .pool("pa", &[(0, 1)])
        .governance(gov)
        .build();
    let (data_router, admin_router, _handle) = crate::build_split_routers_with_limits(
        app,
        busbar_kernel_egress::upstream::max_translate_body_bytes(),
        busbar_kernel::config::DEFAULT_MAX_INBOUND_CONCURRENT,
        busbar_kernel::config::DEFAULT_RESPONSE_HEADERS_SERVER_TIMING,
    );

    async fn get(router: Router, path: &str, token: Option<&str>) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let mut req = reqwest::Client::new().get(format!("http://{addr}{path}"));
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        let code = req.send().await.unwrap().status().as_u16();
        server.abort();
        code
    }

    let admin_path = format!("{}/keys", crate::v1::contract::ADMIN_PREFIX);

    assert_eq!(
        get(admin_router.clone(), &admin_path, Some("admintok")).await,
        200,
        "admin router must serve the admin surface"
    );

    assert_eq!(
        get(data_router.clone(), &admin_path, Some("admintok")).await,
        404,
        "data router must NOT serve the admin surface even for an authenticated admin request"
    );

    assert_eq!(get(admin_router, "/healthz", None).await, 200);
    assert_eq!(get(data_router, "/healthz", None).await, 200);
}
