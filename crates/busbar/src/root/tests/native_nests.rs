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

#[test]
fn a_body_without_a_head_is_not_a_successful_reply() {
    let reply = reply(4);
    assert!(reply.items(vec![ToClient::Body(b"abc".to_vec())]));
    assert_eq!(reply.answer(), NestReply::Failed(NEST_UNREAD));
}
