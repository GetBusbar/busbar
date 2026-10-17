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

/// A route that takes tickets answers its plane's prefix; every other route, or another method on
/// it, answers none (row 132).
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
    };
    let table = super::CoreRouteTable::default().with_door_refusals(vec![
        spec("/v1/calls", Some("tk_")),
        spec("/v1/keyed", None),
    ]);
    let post = axum::http::Method::POST;
    assert_eq!(table.door_ticket("/v1/calls", &post), Some("tk_"));
    // RED: a keyed route, another method, a path no door serves.
    assert_eq!(table.door_ticket("/v1/keyed", &post), None);
    assert_eq!(
        table.door_ticket("/v1/calls", &axum::http::Method::GET),
        None
    );
    assert_eq!(table.door_ticket("/v1/other", &post), None);
}
