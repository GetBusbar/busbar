use super::route_matches;

#[test]
fn a_door_route_pattern_matches_as_the_router_does() {
    assert!(route_matches("/v1/op", "/v1/op"));
    assert!(route_matches("/door/items/{id}", "/door/items/7"));
    assert!(route_matches("/door/{*rest}", "/door/a/b"));
    // RED ARMS: a sibling, a longer path, an empty segment for a variable, a shorter path.
    assert!(!route_matches("/v1/op", "/v1/ops"));
    assert!(!route_matches("/v1/op", "/v1/op/x"));
    assert!(!route_matches("/door/items/{id}", "/door/items/"));
    assert!(!route_matches("/v1/op", "/v1"));
}

/// THE SIGNED PATHS A DOOR PLANE STATES, LOOKED UP BY PATH (ARCHITECT rulings 2026-10-16, 3b A, and
/// 2026-10-17): a raw path that starts with one of the plane's signed raw affixes' prefix and ends
/// with its suffix is signed whatever the request's verb and whatever route its refusal was
/// recorded at, the odd paths as the previous release signed them (no identifier, an empty
/// segment). RED arms: a trailing `/`, a leading `//`, a sibling suffix, an unsigned surface of the
/// same prefix, a path with no plane signing it.
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
        dialect: "",
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

/// THE AUTH-DENIAL TAP LABEL, WHATEVER THE VERB. v1.5.5 labelled a `rejected_by_auth` response tap
/// with the dialect it read off the PATH alone (`crates/busbar/src/auth/mod.rs:1166-1167` at
/// v1.5.5: `unauthorized_with_completion_taps` takes `proto_for_path(path)`), so an OPTIONS or HEAD
/// at a dialect's path was tapped under that dialect, exactly as its POST was. The door routes
/// state the dialect per claim; a verb no route at the path takes reads the dialect of the most
/// specific route the path matches, method aside. RED arms: the wildcard tail's dialect for a path
/// an exact route names, and none for a path a route matches.
#[test]
fn an_auth_denial_is_tapped_under_the_paths_dialect_whatever_the_verb() {
    use busbar_contract::abi::mechanism::route::RouteMethod;
    use busbar_kernel::plane_routes::{DoorRouteId, PlaneRefusalSpec, PlaneResponse};
    use std::sync::Arc;
    let spec = |path: &str, method: RouteMethod, dialect: &'static str| PlaneRefusalSpec {
        route: DoorRouteId {
            path: path.to_string(),
            method,
        },
        refuse: Arc::new(|_: busbar_contract::caps::ReasonCode, _: &str| PlaneResponse::default()),
        signed_ingress: Arc::from(Vec::<String>::new()),
        dialect,
    };
    let table = super::CoreRouteTable::default().with_door_refusals(vec![
        spec("/{*rest}", RouteMethod::Get, "residual"),
        spec("/{*rest}", RouteMethod::Post, "residual"),
        spec("/v1/messages", RouteMethod::Post, "messages"),
    ]);
    let at = |path: &str, method: axum::http::Method| table.refusal_dialect(path, &method);
    // The verbs a route takes: the route's own dialect.
    assert_eq!(
        at("/v1/messages", axum::http::Method::POST),
        Some("messages")
    );
    assert_eq!(at("/elsewhere", axum::http::Method::GET), Some("residual"));
    // The verbs no route takes: the most specific route the path matches, method aside.
    for method in [axum::http::Method::OPTIONS, axum::http::Method::HEAD] {
        assert_eq!(
            at("/v1/messages", method.clone()),
            Some("messages"),
            "{method}"
        );
        assert_eq!(
            at("/elsewhere", method.clone()),
            Some("residual"),
            "{method}"
        );
    }
    // No door route at all: no dialect.
    assert_eq!(
        super::CoreRouteTable::default()
            .refusal_dialect("/v1/messages", &axum::http::Method::OPTIONS),
        None
    );
}
