// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! IF §8.6, §12.11, §12.24, §12.27 (PLANE-DRIVER slice 8): which of a plane's routes core mounts where, the
//! recovery request core originates, and the CATALOG and HYDRATE admin calls.

use std::sync::Mutex;

use busbar_plugin_abi::host_side::caller::BoxFut;
use busbar_plugin_abi::plane::{
    ADMIN_HYDRATE, AUTH_OPERATOR, AUTH_OPTIONAL, AUTH_PRINCIPAL, AUTH_PUBLIC, AUTH_TICKET,
    ROUTE_ADMIN, ROUTE_CATALOG, ROUTE_LINE, ROUTE_RECOVERY, ROUTE_UPGRADE, RQ_RECOVERY,
};
use busbar_ports::plane::{
    PlaneIn, PlaneOut, PlanePort, PlaneSession, RouteInfo, TargetIn, UsageClass,
};
use busbar_ports::{CallCx, PortError};

use super::{admin_hydrate, recovery_request, PortRoutes, RouteRefused};

fn route(id: u32, flags: u32, auth: u32, pattern: &str) -> RouteInfo {
    RouteInfo {
        route: id,
        methods: 1,
        flags,
        auth,
        pattern: pattern.into(),
        cred_header: None,
        resource_kinds: Default::default(),
    }
}

fn none(_: u32) -> Option<u32> {
    None
}

/// The admission the test port states for `r`: a catalog walks core's pools, a route that names
/// resource kinds selects them, every other route states scope none; no money, shared callers.
/// (The rows below test where a route mounts; the record's own rules are in `auth::inbound_table`.)
fn stated(r: &RouteInfo) -> (u32, u32, u32, &'static str) {
    use busbar_plugin_abi::plane::{
        CALLERS_SHARED, MONEY_NONE, SCOPE_NONE, SCOPE_SELECTED, SCOPE_WALK,
    };
    let (scope, walk) = if r.flags == ROUTE_CATALOG {
        (SCOPE_WALK, "pool")
    } else if !r.resource_kinds.is_empty() {
        (SCOPE_SELECTED, "")
    } else {
        (SCOPE_NONE, "")
    };
    (scope, MONEY_NONE, CALLERS_SHARED, walk)
}

/// The mount table of a port that declares `routes`, each with the admission [`stated`] gives it.
fn plan(
    routes: &[RouteInfo],
    admin_openapi: Option<&str>,
    configured: &dyn Fn(u32) -> Option<u32>,
) -> Result<PortRoutes, RouteRefused> {
    super::plan(&port(routes, admin_openapi, true), configured)
}

/// A port that declares `routes`; `states`: whether it states their admissions.
fn port(routes: &[RouteInfo], admin_openapi: Option<&str>, states: bool) -> Admin {
    Admin {
        seen: Mutex::default(),
        routes: routes.to_vec(),
        openapi: admin_openapi.map(str::to_owned),
        states,
        answer: Err(()),
    }
}

/// The record's one path: what the port states for a route is the record its `Mounted` carries.
#[test]
fn a_mounted_route_carries_the_record_its_plane_stated() {
    use crate::auth::route_record::{Money, RecordRefused, RouteClass, Scope, Who};
    let table = plan(
        &[
            route(1, 0, AUTH_PRINCIPAL, "/v1/chat"),
            route(2, ROUTE_CATALOG, AUTH_PRINCIPAL, "/v1/models"),
        ],
        None,
        &none,
    )
    .unwrap();
    let chat = &table.data[0].record;
    assert_eq!(chat.class, RouteClass::Data);
    assert!(chat.who.is(Who::PRINCIPAL));
    assert!(chat.scope.is_none() && chat.scope_stated);
    assert_eq!(chat.money, Money::None);
    assert_eq!(table.data[1].record.scope, Scope::walk("pool"));

    // A port that states no admission for a route mounts nothing: the plane is refused.
    let silent = port(&[route(7, 0, AUTH_PRINCIPAL, "/x")], None, false);
    assert_eq!(
        super::plan(&silent, &none).unwrap_err(),
        RouteRefused::NoAdmission { route: 7 }
    );

    // A record that contradicts itself refuses the plane, naming the route and the field: a
    // catalog a public caller could list has no key to walk a scope for.
    assert_eq!(
        plan(
            &[route(2, ROUTE_CATALOG, AUTH_PUBLIC, "/v1/models")],
            None,
            &none
        )
        .unwrap_err(),
        RouteRefused::Record {
            route: 2,
            why: RecordRefused::OpenRouteCarriesScopeOrMoney
        }
    );
}

/// COMPLIANCE X4: a restricted key of a plane's own kind (MCP `mcp_tool`, A2A `agent`) can be
/// granted only once a kind is declared, and a MIN-3 plane declares its kinds in its route
/// records, nowhere else. A kind a mounted route states is a declared kind, added for the process;
/// a plane refused at mount declares nothing, and core's `pool` is never a plane's.
#[test]
fn restricted_key_kinds_are_the_kinds_mounted_route_records_state() {
    use crate::governance::plane_declares_kind;
    let mut selects = route(1, 0, AUTH_PRINCIPAL, "/mcp");
    selects.resource_kinds = vec![Box::<str>::from("x4_mounted_tool")].into();
    assert!(!plane_declares_kind("x4_mounted_tool"));
    plan(&[selects], None, &none).unwrap();
    assert!(
        plane_declares_kind("x4_mounted_tool"),
        "a kind a mounted route's record states can be granted to a key"
    );

    // A plane whose routes cannot all be mounted declares none of its kinds.
    let mut refused_selects = route(1, 0, AUTH_PRINCIPAL, "/a2a");
    refused_selects.resource_kinds = vec![Box::<str>::from("x4_refused_agent")].into();
    assert_eq!(
        plan(
            &[
                refused_selects,
                route(2, ROUTE_LINE, AUTH_PRINCIPAL, "/l1"),
                route(3, ROUTE_LINE, AUTH_PRINCIPAL, "/l2"),
            ],
            None,
            &none
        )
        .unwrap_err(),
        RouteRefused::TwoLines
    );
    assert!(!plane_declares_kind("x4_refused_agent"));

    // A catalog walks core's `pool`: mounting it never makes `pool` a plane's kind.
    plan(
        &[route(2, ROUTE_CATALOG, AUTH_PRINCIPAL, "/v1/models")],
        None,
        &none,
    )
    .unwrap();
    assert!(!plane_declares_kind("pool"));
}

#[test]
fn resource_metadata_cannot_activate_unsupported_or_ambiguous_mounts() {
    let mut r = route(1, 0, AUTH_PRINCIPAL, "/x");
    r.resource_kinds = vec![Box::<str>::from("pool")].into();
    assert_eq!(
        plan(&[r.clone()], None, &none).unwrap().data[0].resource_kinds,
        r.resource_kinds
    );
    for kinds in [
        vec![Box::<str>::from("Pool")],
        vec!["pool".into(), "pool".into()],
        vec!["pool".into(); 9],
    ] {
        r.resource_kinds = kinds.into();
        assert!(plan(&[r.clone()], None, &none).is_err());
    }
    r.resource_kinds = vec![Box::<str>::from("pool")].into();
    r.auth = AUTH_PUBLIC;
    assert!(plan(&[r.clone()], None, &none).is_err());
    r.auth = AUTH_PRINCIPAL;
    r.flags = ROUTE_UPGRADE;
    assert!(plan(&[r], None, &none).is_err());
}

#[test]
fn routes_are_mounted_where_their_flags_say_and_line_and_recovery_are_never_mounted() {
    let routes = [
        route(1, 0, AUTH_PRINCIPAL, "/v1/chat"),
        route(2, ROUTE_CATALOG, AUTH_PRINCIPAL, "/v1/models"),
        route(3, ROUTE_ADMIN, AUTH_OPERATOR, "/stats"),
        route(4, ROUTE_UPGRADE, AUTH_PRINCIPAL, "/v1/realtime"),
        route(5, ROUTE_LINE, AUTH_PRINCIPAL, "/line"),
        route(6, ROUTE_RECOVERY, AUTH_PRINCIPAL, "/v1/poll"),
    ];
    let p = plan(&routes, Some("{}"), &none).unwrap();
    let ids = |v: &[super::Mounted]| v.iter().map(|m| m.route).collect::<Vec<_>>();
    assert_eq!(ids(&p.data), vec![1, 2]);
    assert_eq!(ids(&p.admin), vec![3]);
    assert_eq!(ids(&p.upgrade), vec![4]);
    assert_eq!(p.line.as_ref().map(|m| m.route), Some(5));
    assert_eq!(ids(&p.recovery), vec![6]);
    assert_eq!(p.admin_openapi.as_deref(), Some("{}"));
    assert!(
        p.data[1].catalog,
        "the catalog route is answered with render(RENDER_CATALOG)"
    );
    assert!(!p.data[0].catalog);
}

#[test]
fn a_mounted_route_carries_its_effective_classes_and_the_operators_choice_wins_inside_the_mask() {
    // A key or a ticket: the one pair of callers the route record lets share a route.
    let routes = [route(1, 0, AUTH_PRINCIPAL | AUTH_TICKET, "/x")];
    let by_default = plan(&routes, None, &none).unwrap();
    assert_eq!(by_default.data[0].effective, AUTH_PRINCIPAL | AUTH_TICKET);
    let chosen = plan(&routes, None, &|r| (r == 1).then_some(AUTH_PRINCIPAL)).unwrap();
    assert_eq!(chosen.data[0].effective, AUTH_PRINCIPAL);
    // A mask that mixes an optional caller with a key is not a record: the plane is refused.
    let mixed = [route(1, 0, AUTH_PRINCIPAL | AUTH_OPTIONAL, "/x")];
    assert_eq!(
        plan(&mixed, None, &none).unwrap_err(),
        RouteRefused::Record {
            route: 1,
            why: crate::auth::route_record::RecordRefused::Who
        }
    );
}

#[test]
fn a_route_with_no_usable_class_or_a_class_outside_its_mask_refuses_the_plane() {
    let none_usable = [route(1, 0, 0, "/x")];
    assert_eq!(
        plan(&none_usable, None, &none).unwrap_err(),
        RouteRefused::Classes { route: 1 }
    );
    let outside = [route(2, 0, AUTH_PRINCIPAL, "/x")];
    assert_eq!(
        plan(&outside, None, &|_| Some(AUTH_PUBLIC)).unwrap_err(),
        RouteRefused::Classes { route: 2 }
    );
}

#[test]
fn admin_routes_need_the_operator_class_and_an_openapi_fragment() {
    let routes = [route(3, ROUTE_ADMIN, AUTH_OPERATOR, "/stats")];
    assert_eq!(
        plan(&routes, None, &none).unwrap_err(),
        RouteRefused::AdminWithoutOpenapi
    );
    let wrong = [route(3, ROUTE_ADMIN, AUTH_PRINCIPAL, "/stats")];
    assert_eq!(
        plan(&wrong, Some("{}"), &none).unwrap_err(),
        RouteRefused::AdminAuth { route: 3 }
    );
}

#[test]
fn flags_that_do_not_combine_refuse_the_plane() {
    for flags in [
        ROUTE_UPGRADE | ROUTE_CATALOG,
        ROUTE_LINE | ROUTE_ADMIN,
        ROUTE_RECOVERY | ROUTE_UPGRADE,
        ROUTE_ADMIN | ROUTE_CATALOG,
    ] {
        let routes = [route(9, flags, AUTH_OPERATOR, "/x")];
        assert_eq!(
            plan(&routes, Some("{}"), &none).unwrap_err(),
            RouteRefused::Flags { route: 9 },
            "flags {flags:#x}"
        );
    }
}

#[test]
fn more_than_one_line_route_refuses_the_plane() {
    let routes = [
        route(1, ROUTE_LINE, AUTH_PRINCIPAL, "/a"),
        route(2, ROUTE_LINE, AUTH_PRINCIPAL, "/b"),
    ];
    assert_eq!(
        plan(&routes, None, &none).unwrap_err(),
        RouteRefused::TwoLines
    );
}

#[test]
fn the_recovery_request_is_a_principal_request_on_the_recovery_route_carrying_the_work_reference() {
    let m = plan(
        &[route(6, ROUTE_RECOVERY, AUTH_PRINCIPAL, "/v1/poll")],
        None,
        &none,
    )
    .unwrap();
    let identity = b"identity-records";
    let req = recovery_request(&m.recovery[0], "ref-1", identity, "/v1/poll", 77);
    assert_eq!(req.route, 6);
    assert_eq!(req.flags & RQ_RECOVERY, RQ_RECOVERY);
    assert_eq!(req.work, "ref-1");
    assert_eq!(req.auth, AUTH_PRINCIPAL);
    assert_eq!(req.identity, identity);
    assert_eq!(
        (req.method, req.path, req.request_id, req.carrier),
        ("GET", "/v1/poll", 77, 0)
    );
}

/// IF §12.24 step 3: the poll's path and query are the WORK_OPEN target's, not the route pattern (the route
/// only selected the poll).
#[test]
fn the_recovery_request_carries_the_path_and_query_of_the_work_target() {
    let m = plan(
        &[route(6, ROUTE_RECOVERY, AUTH_PRINCIPAL, "/v1/jobs")],
        None,
        &none,
    )
    .unwrap();
    let req = recovery_request(&m.recovery[0], "ref-2", b"id", "/v1/jobs/42?cursor=7", 9);
    assert_eq!((req.path, req.query), ("/v1/jobs/42", "cursor=7"));
    let bare = recovery_request(&m.recovery[0], "ref-2", b"id", "/v1/jobs/42", 9);
    assert_eq!((bare.path, bare.query), ("/v1/jobs/42", ""));
}

/// A plane that answers `admin` with the op it was called with, recorded.
struct Admin {
    seen: Mutex<Vec<(u32, Vec<u8>)>>,
    /// The route table this port declares, and its admin OpenAPI fragment.
    routes: Vec<RouteInfo>,
    openapi: Option<String>,
    /// Whether the port states its routes' admissions (a port that does not mounts nothing).
    states: bool,
    answer: Result<Vec<u8>, ()>,
}

fn refused() -> PortError {
    PortError::Refused {
        code: 1,
        text: "no".into(),
        error: None,
    }
}

impl PlanePort for Admin {
    fn routes(&self) -> &[RouteInfo] {
        &self.routes
    }
    fn route_admission(&self, route: u32) -> Option<(u32, u32, u32, &str)> {
        if !self.states {
            return None;
        }
        self.routes.iter().find(|r| r.route == route).map(stated)
    }
    fn dialects(&self) -> &[Box<str>] {
        &[]
    }
    fn usage_classes(&self) -> &[UsageClass] {
        &[]
    }
    fn usage_shared(&self) -> (std::sync::Arc<[UsageClass]>, std::sync::Arc<[Box<str>]>) {
        Default::default()
    }
    fn facts(&self) -> u64 {
        0
    }
    fn tick_s(&self) -> Option<u64> {
        None
    }
    fn admin_openapi(&self) -> Option<&str> {
        self.openapi.as_deref()
    }
    fn charge(&self, _: busbar_plugin_abi::fail::FaultReason) {}
    fn request(
        &self,
        _: &PlaneIn<'_>,
        _: &[u8],
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<PlaneSession, PortError> {
        Err(refused())
    }
    fn upstream(
        &self,
        _: &mut PlaneSession,
        _: &TargetIn<'_>,
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        Err(refused())
    }
    fn piece(
        &self,
        _: &mut PlaneSession,
        _: u32,
        _: u32,
        _: u32,
        _: &[u8],
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        Err(refused())
    }
    fn rewrite(
        &self,
        _: &mut PlaneSession,
        _: &[u8],
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        Err(refused())
    }
    fn end(&self, _: PlaneSession, _: &mut dyn FnMut(PlaneOut<'_>)) -> Result<(), PortError> {
        Err(refused())
    }
    fn render(
        &self,
        _: &PlaneIn<'_>,
        _: u32,
        _: &[u8],
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        Err(refused())
    }
    fn probe(
        &self,
        _: &TargetIn<'_>,
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<PlaneSession, PortError> {
        Err(refused())
    }
    fn demux(&self, _: &str, _: &[u8], _: &mut dyn FnMut(PlaneOut<'_>)) -> Result<(), PortError> {
        Err(refused())
    }
    fn admin<'a>(
        &'a self,
        _: CallCx,
        op: u32,
        arg: &'a [u8],
    ) -> BoxFut<'a, Result<Vec<u8>, PortError>> {
        self.seen.lock().unwrap().push((op, arg.to_vec()));
        Box::pin(async move { self.answer.clone().map_err(|()| refused()) })
    }
}

#[tokio::test]
async fn hydrate_is_an_admin_op_and_its_answer_goes_to_core_as_it_is() {
    let port = Admin {
        seen: Mutex::default(),
        routes: Vec::new(),
        openapi: None,
        states: true,
        answer: Ok(b"answer".to_vec()),
    };
    assert_eq!(admin_hydrate(&port, b"stored").await.unwrap(), b"answer");
    assert_eq!(
        *port.seen.lock().unwrap(),
        vec![(ADMIN_HYDRATE, b"stored".to_vec())]
    );
    let failing = Admin {
        seen: Mutex::default(),
        routes: Vec::new(),
        openapi: None,
        states: true,
        answer: Err(()),
    };
    assert!(admin_hydrate(&failing, b"stored").await.is_err());
}
