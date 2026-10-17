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

/// THE SIGNED PATHS A DOOR PLANE STATES, LOOKED UP BY PATH (ARCHITECT ruling 2026-10-16, 3b A): a
/// path one of the plane's signed guest-line paths matches is signed whatever the request's verb
/// and whatever route its refusal was recorded at; a `{name+}` spans an identifier's raw `/`. RED
/// arms: a sibling suffix, an unsigned surface of the same prefix, a path with no plane signing it.
#[test]
fn a_signed_path_is_looked_up_by_path_whatever_the_verb() {
    use busbar_contract::abi::mechanism::route::RouteMethod;
    use busbar_kernel::plane_routes::{DoorRouteId, PlaneRefusalSpec, PlaneResponse};
    use std::sync::Arc;
    let signed: Arc<[String]> = vec!["/door/{id+}/sign".to_string()].into();
    let table = super::CoreRouteTable::default().with_door_refusals(vec![PlaneRefusalSpec {
        route: DoorRouteId {
            path: "/door/{*rest}".to_string(),
            method: RouteMethod::Post,
        },
        refuse: Arc::new(|_: busbar_contract::caps::ReasonCode, _: &str| PlaneResponse::default()),
        signed_ingress: signed,
    }]);
    assert!(table.signed_ingress("/door/x/sign"));
    assert!(table.signed_ingress("/door/arn:a:b/c:0/sign"));
    assert!(table.signed_ingress("/door/arn%3Aa%2Fc/sign"));
    assert!(!table.signed_ingress("/door/x/sign-more"));
    assert!(!table.signed_ingress("/door/x/other"));
    assert!(!table.signed_ingress("/elsewhere/x/sign"));
    assert!(!super::CoreRouteTable::default().signed_ingress("/door/x/sign"));
}
