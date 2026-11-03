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

#[tokio::test]
async fn door_metadata_follows_guest_precedence_instead_of_plane_mount_order() {
    use busbar_contract::abi::mechanism::route::RouteMethod;
    use busbar_contract::abi::transport::route::{method_bit, PATH_EXACT, PATH_PATTERN};
    use busbar_kernel::guest::{Claimant, GuestList, Line, LineAuth, Matched, Route};
    use busbar_kernel::plane_routes::{DoorRouteId, PlaneRefusalSpec, PlaneResponse};
    use std::sync::Arc;

    let spec = |path: &str, method, prefix: Option<&str>, status| PlaneRefusalSpec {
        route: DoorRouteId {
            path: path.into(),
            method,
        },
        ticket_prefix: prefix.map(str::to_owned),
        signed_ingress: Arc::from([]),
        refuse: Arc::new(move |_, _| {
            axum::http::Response::builder()
                .status(status)
                .body(axum::body::Body::empty())
                .unwrap()
        }),
    };
    // The full product mounts a key-only plane fallback before this exact ticket claim.
    for ticket_path in ["/v1/realtime/calls", "/v1/{session}/calls"] {
        for reverse in [false, true] {
            let mut rows = vec![
                spec("/{*rest}", RouteMethod::Post, None, 401_u16),
                spec(ticket_path, RouteMethod::Post, Some("tk_"), 402),
            ];
            if reverse {
                rows.reverse();
            }
            let guests = GuestList::seal(
                rows.iter()
                    .enumerate()
                    .map(|(rung, r)| Line {
                        route: Route {
                            methods: method_bit(r.route.method.as_str()),
                            path_form: if r.route.path.contains('{') {
                                PATH_PATTERN
                            } else {
                                PATH_EXACT
                            },
                            path: r.route.path.clone(),
                            fields: Vec::new(),
                            rung: rung as u32,
                        },
                        claimant: Claimant::Plane(
                            if r.ticket_prefix.is_some() {
                                "ticket"
                            } else {
                                "fallback"
                            }
                            .into(),
                        ),
                        dialect: 0,
                        auth: LineAuth::None,
                        upgrade: None,
                        offered: busbar_contract::abi::auth::AuthPoints::HEAD,
                    })
                    .collect(),
            )
            .unwrap();
            let Matched::Line(selected) = guests.matched("POST", "/v1/realtime/calls", &[]) else {
                panic!("the real guest selector must select the more specific route")
            };
            assert_eq!(selected.claimant, Claimant::Plane("ticket".into()));
            let table = super::CoreRouteTable::default().with_door_refusals(rows);
            assert_eq!(
                table.door_ticket("/v1/realtime/calls", &axum::http::Method::POST),
                Some("tk_")
            );
            let refuse = table
                .door_refusal("/v1/realtime/calls", &axum::http::Method::POST)
                .unwrap();
            let response: PlaneResponse = refuse(
                busbar_contract::caps::ReasonCode::Unauthenticated,
                "/v1/realtime/calls",
            );
            assert_eq!(
                response.status().as_u16(),
                402,
                "refusal and ticket must name the same selected route"
            );
            assert_eq!(
                table.door_ticket("/v1/realtime/calls", &axum::http::Method::GET),
                None
            );
            assert_eq!(
                table.door_ticket("/unknown", &axum::http::Method::POST),
                None
            );
            assert_eq!(
                table.door_ticket("/v1/realtime/calls/extra", &axum::http::Method::POST),
                None
            );
        }
    }

    // Overlapping parameter routes with equal path rank cannot assign ticket authority to
    // different claimants. The existing guest seal refuses that ambiguity before mounting.
    let tied = |path: &str, owner: &str, rung| Line {
        route: Route {
            methods: method_bit("POST"),
            path_form: PATH_PATTERN,
            path: path.into(),
            fields: Vec::new(),
            rung,
        },
        claimant: Claimant::Plane(owner.into()),
        dialect: 0,
        auth: LineAuth::None,
        upgrade: None,
        offered: busbar_contract::abi::auth::AuthPoints::HEAD,
    };
    assert!(
        GuestList::seal(vec![
            tied("/v1/{first}/calls", "ticket", 0),
            tied("/v1/{second}/calls", "key-only", 1),
        ])
        .is_err(),
        "equal path precedence must not choose a different claimant by insertion order"
    );

    let catchall = super::CoreRouteTable::default().with_door_refusals(vec![spec(
        "/v1/{*rest}",
        RouteMethod::Post,
        Some("tk_"),
        402,
    )]);
    assert_eq!(
        catchall.door_ticket("/v1/other", &axum::http::Method::POST),
        Some("tk_")
    );
    assert_eq!(
        catchall.door_ticket("/unknown", &axum::http::Method::POST),
        None
    );
    let selected_unticketed = super::CoreRouteTable::default().with_door_refusals(vec![
        spec("/v1/{*rest}", RouteMethod::Post, Some("tk_"), 402),
        spec("/v1/key-only", RouteMethod::Post, None, 401),
    ]);
    assert_eq!(
        selected_unticketed.door_ticket("/v1/key-only", &axum::http::Method::POST),
        None,
        "an exact key-only route cannot inherit a broader route's ticket authority"
    );
    assert_eq!(
        selected_unticketed.door_ticket("/v1/key-only", &axum::http::Method::GET),
        None
    );
}
