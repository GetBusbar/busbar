use super::route_matches;

#[test]
fn a_door_route_pattern_matches_as_the_router_does() {
    assert!(route_matches("/v1/op", "/v1/op"));
    assert!(route_matches("/door/items/{id}", "/door/items/7"));
    assert!(route_matches("/door/{*rest}", "/door/a/b"));

    assert!(!route_matches("/v1/op", "/v1/ops"));
    assert!(!route_matches("/v1/op", "/v1/op/x"));
    assert!(!route_matches("/door/items/{id}", "/door/items/"));
    assert!(!route_matches("/v1/op", "/v1"));
}

#[tokio::test]
async fn a_catchall_refusal_and_ticket_match_the_routers_nonempty_tail() {
    use busbar_contract::abi::mechanism::route::RouteMethod;
    use busbar_kernel::plane_routes::{DoorRouteId, PlaneRefusalSpec, PlaneResponse};
    use std::sync::Arc;
    use tower::ServiceExt as _;

    let route = "/door/{*rest}";
    let table = super::CoreRouteTable::default().with_door_refusals(vec![PlaneRefusalSpec {
        route: DoorRouteId {
            path: route.to_string(),
            method: RouteMethod::Get,
        },
        refuse: Arc::new(|_, _| PlaneResponse::default()),
        ticket_prefix: Some("tk_".to_string()),
        signed_ingress: Arc::from(Vec::<String>::new()),
    }]);
    let router = axum::Router::new().route(route, axum::routing::get(|| async { "matched" }));
    for (path, matches) in [
        ("/door", false),
        ("/door/", false),
        ("/door/x", true),
        ("/door//", true),
        ("/door/a/b", true),
    ] {
        let response = router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri(path)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status().is_success(), matches, "Axum at {path}");
        assert_eq!(
            table.door_refusal(path, &axum::http::Method::GET).is_some(),
            matches,
            "refusal at {path}"
        );
        assert_eq!(
            table.door_ticket(path, &axum::http::Method::GET),
            matches.then_some("tk_"),
            "ticket at {path}"
        );
    }
}

#[test]
fn only_a_ticket_route_names_a_ticket_prefix() {
    use busbar_contract::abi::mechanism::route::RouteMethod;
    use std::sync::Arc;
    let spec = |path: &str, prefix: Option<&str>| busbar_kernel::plane_routes::PlaneRefusalSpec {
        route: busbar_kernel::plane_routes::DoorRouteId {
            path: path.to_string(),
            method: RouteMethod::Post,
        },
        refuse: Arc::new(|_: busbar_contract::caps::ReasonCode, _: &str| {
            busbar_kernel::plane_routes::PlaneResponse::default()
        }),
        ticket_prefix: prefix.map(str::to_string),
        signed_ingress: Arc::from(Vec::<String>::new()),
    };
    let table = super::CoreRouteTable::default().with_door_refusals(vec![
        spec("/v1/calls", Some("tk_")),
        spec("/v1/keyed", None),
    ]);
    let post = axum::http::Method::POST;
    assert_eq!(table.door_ticket("/v1/calls", &post), Some("tk_"));

    assert_eq!(table.door_ticket("/v1/keyed", &post), None);
    assert_eq!(
        table.door_ticket("/v1/calls", &axum::http::Method::GET),
        None
    );
    assert_eq!(table.door_ticket("/v1/other", &post), None);
}

#[test]
fn a_signed_path_is_looked_up_by_path_whatever_the_verb() {
    use busbar_contract::abi::mechanism::route::RouteMethod;
    use busbar_kernel::plane_routes::{DoorRouteId, PlaneRefusalSpec, PlaneResponse};
    use std::sync::Arc;
    let signed: Arc<[String]> = vec![
        "/door/*/sign".to_string(),
        "/door/*/sign-stream".to_string(),
    ]
    .into();
    let table = super::CoreRouteTable::default().with_door_refusals(vec![PlaneRefusalSpec {
        route: DoorRouteId {
            path: "/door/{*rest}".to_string(),
            method: RouteMethod::Post,
        },
        refuse: Arc::new(|_: busbar_contract::caps::ReasonCode, _: &str| PlaneResponse::default()),
        signed_ingress: signed,
        ticket_prefix: None,
    }]);
    assert!(table.signed_ingress("/door/x/sign"));
    assert!(table.signed_ingress("/door/arn:a:b/c:0/sign"));
    assert!(table.signed_ingress("/door/arn%3Aa%2Fc/sign"));
    assert!(table.signed_ingress("/door/sign"));
    assert!(table.signed_ingress("/door/sign-stream"));
    assert!(table.signed_ingress("/door//sign"));
    assert!(!table.signed_ingress("/door/x/sign/"));
    assert!(!table.signed_ingress("//door/x/sign"));
    assert!(!table.signed_ingress("/door/x/sign-more"));
    assert!(!table.signed_ingress("/door/x/other"));
    assert!(!table.signed_ingress("/elsewhere/x/sign"));
    assert!(!super::CoreRouteTable::default().signed_ingress("/door/x/sign"));
}
