use super::*;

fn route(path: &str, method: RouteMethod, auth: RouteAuth) -> PlaneRouteSpec {
    PlaneRouteSpec {
        path: path.to_string(),
        method,
        auth,
        handler: Arc::new(|_: PlaneReqCtx| {
            Box::pin(async { PlaneResponse::default() }) as PlaneRouteFuture
        }),
    }
}

fn session(path: &str, auth: RouteAuth) -> PlaneSessionSpec {
    PlaneSessionSpec {
        path: path.to_string(),
        auth,
        handler: Arc::new(|_| Box::pin(async { SessionAnswer::Refused(PlaneResponse::default()) })),
    }
}

fn refusal(path: &str, method: RouteMethod) -> PlaneRefusalSpec {
    PlaneRefusalSpec {
        route: DoorRouteId {
            path: path.to_string(),
            method,
        },
        refuse: Arc::new(|_: busbar_contract::caps::ReasonCode, _: &str| PlaneResponse::default()),
    }
}

/// Every credentialed door route, request or session, pairs with exactly one refusal under its own
/// identity; an open route needs none.
#[test]
fn paired_door_routes_and_refusals_pass() {
    let routes = [
        route("/v1/op", RouteMethod::Post, RouteAuth::Key),
        route("/.well-known/doc", RouteMethod::Get, RouteAuth::None),
    ];
    let sessions = [session("/live", RouteAuth::Key)];
    let refusals = [
        refusal("/v1/op", RouteMethod::Post),
        refusal("/live", RouteMethod::Get),
    ];
    assert_eq!(pair_door_refusals(&routes, &sessions, &refusals), Ok(()));
    assert_eq!(pair_door_refusals(&[], &[], &[]), Ok(()));
}

/// RED ARMS: a credentialed route with no refusal, a refusal naming no route (or an open one, or
/// the right path under another method), and one route refused twice each refuse the boot.
#[test]
fn an_unpaired_door_route_or_refusal_refuses_the_boot() {
    let routes = [route("/v1/op", RouteMethod::Post, RouteAuth::Key)];
    let bare = pair_door_refusals(&routes, &[], &[]).expect_err("a route with no refusal");
    assert!(
        bare.contains("no refusal spec") && bare.contains("/v1/op"),
        "{bare}"
    );
    let session_bare = pair_door_refusals(&[], &[session("/live", RouteAuth::Key)], &[])
        .expect_err("a session route with no refusal");
    assert!(session_bare.contains("/live"), "{session_bare}");
    for orphan in [
        refusal("/v1/other", RouteMethod::Post),
        refusal("/v1/op", RouteMethod::Get),
    ] {
        let refused = pair_door_refusals(
            &routes,
            &[],
            &[refusal("/v1/op", RouteMethod::Post), orphan],
        )
        .expect_err("a refusal with no route");
        assert!(refused.contains("no door route"), "{refused}");
    }
    let open = [route("/.well-known/doc", RouteMethod::Get, RouteAuth::None)];
    assert!(
        pair_door_refusals(&open, &[], &[refusal("/.well-known/doc", RouteMethod::Get)]).is_err(),
        "an open route takes no refusal"
    );
    let twice = pair_door_refusals(
        &routes,
        &[],
        &[
            refusal("/v1/op", RouteMethod::Post),
            refusal("/v1/op", RouteMethod::Post),
        ],
    )
    .expect_err("one route refused twice");
    assert!(twice.contains("two refusal specs"), "{twice}");
}
