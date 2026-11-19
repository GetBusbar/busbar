// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::route::{METHOD_GET, METHOD_HEAD, METHOD_POST, PATH_EXACT};
use busbar_kernel::guest::{Line, LineAuth, Route};
use busbar_kernel::plane_driver::port_routes::Mounted;
use busbar_kernel::plane_driver::port_routes::PortRoutes;
use busbar_plugin_abi::plane::AUTH_PRINCIPAL;

fn routes(entries: &[(u32, &str, u32)]) -> PortRoutes {
    PortRoutes {
        data: entries
            .iter()
            .map(|(route, pattern, methods)| Mounted {
                record: busbar_kernel::auth::route_record::RouteRecord::stated(
                    busbar_kernel::auth::route_record::RouteClass::Data,
                    busbar_kernel::auth::route_record::Who::PRINCIPAL,
                    busbar_kernel::auth::route_record::Scope::walk("pool"),
                    busbar_kernel::auth::route_record::Money::Unit,
                ),
                route: *route,
                methods: *methods,
                flags: 0,
                auth: AUTH_PRINCIPAL,
                effective: AUTH_PRINCIPAL,
                pattern: (*pattern).into(),
                cred_header: None,
                resource_kinds: Default::default(),
                catalog: false,
            })
            .collect(),
        ..Default::default()
    }
}

#[test]
fn native_selection_uses_guest_precedence_and_the_data_mounts_verbs() {
    let generic = routes(&[(9, "/jobs/{id}", METHOD_GET)]);
    let exact = routes(&[(4, "/jobs/current", METHOD_GET), (5, "/head", METHOD_HEAD)]);
    let selected = NativeNests::seal(
        Vec::new(),
        &[("generic", &generic), ("exact", &exact)],
        |_, _| true,
    )
    .unwrap();
    assert_eq!(
        selected.selected("GET", "/jobs/current?cursor=2"),
        Some((1, 4))
    );
    assert_eq!(selected.selected("GET", "/jobs/other"), Some((0, 9)));
    assert_eq!(selected.selected("POST", "/jobs/current"), None);
    assert_eq!(selected.selected("HEAD", "/head"), None);
}

#[test]
fn equal_precedence_native_destinations_refuse_before_publication() {
    let one = routes(&[(1, "/jobs/{id}", METHOD_GET)]);
    let other = routes(&[(7, "/jobs/{name}", METHOD_GET)]);
    assert!(NativeNests::seal(Vec::new(), &[("one", &one), ("two", &other)], |_, _| true).is_err());
}

/// A port's own data line, as the native listener seals it into the generation's guest list.
fn port_line(instance: &str, rung: u32, path: &str) -> Line {
    Line {
        route: Route {
            methods: METHOD_POST,
            path_form: PATH_EXACT,
            path: path.into(),
            fields: Vec::new(),
            rung,
        },
        claimant: Claimant::Plane(instance.into()),
        dialect: 0,
        auth: LineAuth::None,
        upgrade: None,
        offered: busbar_contract::route::AuthPoints::EMPTY,
    }
}

/// The native listener's guest list holds each served port route's own line; the generation's nest
/// table is built from that same list, so a port line is not a repeat of the nest's line for the same
/// route, and a port route the listener left unmounted (no line) is no nest destination.
#[test]
fn the_nest_table_is_built_over_a_guest_list_holding_the_ports_own_lines() {
    let llm = routes(&[
        (2, "/v1/chat/completions", METHOD_POST),
        (7, "/model/x", METHOD_POST),
    ]);
    let guests = vec![port_line("llm", 2, "/v1/chat/completions")];
    let nests = NativeNests::from_guests(&guests, &[("llm", &llm)]).unwrap();
    assert_eq!(nests.selected("POST", "/v1/chat/completions"), Some((0, 2)));
    assert_eq!(nests.selected("POST", "/model/x"), None);
    assert!(!nests.destinations.contains_key(&("llm".to_owned(), 7)));
}

#[test]
fn a_core_claim_cannot_fall_through_to_a_broader_native_destination() {
    let core = Line {
        route: Route {
            methods: METHOD_GET,
            path_form: PATH_EXACT,
            path: "/jobs/core".into(),
            fields: Vec::new(),
            rung: 0,
        },
        claimant: Claimant::Clean("core".into()),
        dialect: 0,
        auth: LineAuth::None,
        upgrade: None,
        offered: busbar_contract::route::AuthPoints::EMPTY,
    };
    let native = routes(&[(1, "/jobs/{id}", METHOD_GET | METHOD_POST)]);
    let selected = NativeNests::seal(vec![core], &[("native", &native)], |_, _| true).unwrap();
    assert_eq!(selected.selected("GET", "/jobs/core"), None);
    assert_eq!(selected.selected("POST", "/jobs/core"), Some((0, 1)));
}

fn reply(bound: usize) -> Reply {
    Reply {
        state: Mutex::default(),
        bound,
        owner: None,
    }
}

#[test]
fn bounded_reply_preserves_status_fields_and_body_order() {
    let reply = reply(8);
    assert!(reply.items(vec![
        ToClient::Head {
            status: 201,
            fields: vec![(b"x".to_vec(), b"y".to_vec())]
        },
        ToClient::Body(b"ab".to_vec())
    ]));
    assert!(reply.items(vec![
        ToClient::Msg {
            flags: 0,
            bytes: b"cd".to_vec()
        },
        ToClient::End
    ]));
    assert_eq!(
        reply.answer(),
        NestReply::Answered {
            status: 201,
            fields: vec![(b"x".to_vec(), b"y".to_vec())],
            body: b"abcd".to_vec()
        }
    );
}

#[test]
fn reply_bound_covers_headers_and_body_and_cannot_recover_after_overflow() {
    let reply = reply(4);
    assert!(reply.items(vec![ToClient::Head {
        status: 200,
        fields: vec![(b"x".to_vec(), b"y".to_vec())]
    }]));
    assert!(!reply.items(vec![ToClient::Body(b"abc".to_vec())]));
    assert!(!reply.items(vec![ToClient::End]));
    assert_eq!(reply.answer(), NestReply::Failed(NEST_UNREAD));
}

fn parent_key() -> Arc<VirtualKey> {
    Arc::new(VirtualKey {
        id: "nested-parent".into(),
        enabled: true,
        ..Default::default()
    })
}

fn nest_of(parent: &UnitRecord, principal: Option<Arc<VirtualKey>>) -> Nest {
    Nest {
        parent: 1,
        depth: parent.depth + 1,
        principal,
        ask: busbar_contract::services::NestAsk {
            verb: "POST".into(),
            target: "/call/local".into(),
            body: b"ping".to_vec(),
        },
        ancestry: Vec::new(),
        constraints: None,
    }
}

/// SECURITY (#105, Aikido 1074607025; v1.5.5 `nested_ordinary_child_never_spends_the_parent_key_on_a_protected_claim`):
/// an ordinary nested child presents no credential and is never authenticated as its keyed parent.
/// On a route that requires a principal it is refused 401 before the plane runs (so nothing is
/// charged); on an optional or public route it is served with no identity. No explicit delegation
/// exists for an ordinary child: the parent's key is only the money admission it spends.
#[tokio::test]
async fn nested_child_of_a_keyed_parent_is_refused_on_a_principal_route() {
    use busbar_kernel::plane_driver::port_auth::{admit, NoTickets};
    use busbar_kernel::refusal::CoreRefusals;
    use busbar_plugin_abi::fail::refused::R_AUTH_REQUIRED;
    use busbar_plugin_abi::plane::{AUTH_OPTIONAL, AUTH_PUBLIC};
    let key = parent_key();
    let parent = UnitRecord {
        principal: Some(Arc::clone(&key)),
        depth: 0,
    };
    let (money, creds) =
        child_admission(&parent, &nest_of(&parent, Some(Arc::clone(&key)))).expect("admitted");
    assert!(
        Arc::ptr_eq(&money, &key),
        "the child spends its parent's admission"
    );
    assert!(creds.bearer.is_none(), "no credential is copied to a child");
    let refusals = CoreRefusals::new();
    let refused = admit(9, AUTH_PRINCIPAL, &creds, &NoTickets, &refusals, "", 1)
        .await
        .err()
        .expect("a principal route refuses a nested child on its parent's key");
    assert_eq!(refused.status, 401);
    assert_eq!(refused.code, R_AUTH_REQUIRED);
    for open in [AUTH_OPTIONAL, AUTH_PUBLIC] {
        let admitted = admit(9, open, &creds, &NoTickets, &refusals, "", 1)
            .await
            .ok()
            .expect("an open route serves the child");
        assert!(
            admitted.identity.is_none(),
            "the child is handed no identity of its parent"
        );
    }
}

/// SECURITY (#105): a nest claiming a principal other than the very key its parent was admitted
/// under (a forged principal, even one naming the same id) is refused, as is one with none.
#[test]
fn nested_child_with_a_forged_principal_is_refused() {
    let key = parent_key();
    let parent = UnitRecord {
        principal: Some(Arc::clone(&key)),
        depth: 0,
    };
    for claimed in [Some(parent_key()), None] {
        assert_eq!(
            child_admission(&parent, &nest_of(&parent, claimed)).err(),
            Some(NEST_PARENT_GONE)
        );
    }
    let anonymous = UnitRecord {
        principal: None,
        depth: 0,
    };
    assert_eq!(
        child_admission(&anonymous, &nest_of(&anonymous, None)).err(),
        Some(PARENT_ADMISSION)
    );
}

#[test]
fn a_body_without_a_head_is_not_a_successful_reply() {
    let reply = reply(4);
    assert!(reply.items(vec![ToClient::Body(b"abc".to_vec())]));
    assert_eq!(reply.answer(), NestReply::Failed(NEST_UNREAD));
}
