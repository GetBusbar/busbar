// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! PLANE-BOOT-MOUNT: what the HTTP mount of a MIN-3 plane's data routes makes of a route table and of the
//! session's client items. The plane itself is an ffi handle, so the request path runs in the image suite
//! (W2-SW-PLANE e2e); these are the pure seams between axum and `PortDriver::serve`.

use axum::http::{HeaderMap, HeaderValue};
use busbar_contract::abi::mechanism::route::{RouteAuth, RouteMethod};
use busbar_contract::abi::transport::route::{
    METHOD_DELETE, METHOD_GET, METHOD_HEAD, METHOD_PATCH, METHOD_POST, METHOD_PUT,
};
use busbar_kernel::plane_driver::port_session::ToClient;
use busbar_plugin_abi::plane::{AUTH_OPTIONAL, AUTH_PRINCIPAL, AUTH_PUBLIC, AUTH_TICKET};

use super::*;

#[test]
fn the_method_mask_mounts_the_five_verbs_and_drops_the_rest() {
    let all = METHOD_GET | METHOD_HEAD | METHOD_POST | METHOD_PUT | METHOD_PATCH | METHOD_DELETE;
    assert_eq!(
        methods_of(all),
        [
            RouteMethod::Get,
            RouteMethod::Post,
            RouteMethod::Put,
            RouteMethod::Patch,
            RouteMethod::Delete
        ]
    );
    assert_eq!(methods_of(METHOD_HEAD), []);
    assert_eq!(methods_of(METHOD_POST), [RouteMethod::Post]);
}

#[test]
fn only_a_principal_only_route_is_behind_the_data_auth_chain() {
    assert_eq!(auth_of(AUTH_PRINCIPAL), RouteAuth::Key);
    // Core classifies these itself, per request (§12.11): the data chain must not refuse them first.
    for classes in [
        AUTH_OPTIONAL,
        AUTH_PUBLIC,
        AUTH_TICKET,
        AUTH_PRINCIPAL | AUTH_TICKET,
        AUTH_PRINCIPAL | AUTH_OPTIONAL,
    ] {
        assert_eq!(auth_of(classes), RouteAuth::None, "{classes:#x}");
    }
}

#[test]
fn the_route_credential_header_wins_over_authorization() {
    let mut h = HeaderMap::new();
    h.insert("authorization", HeaderValue::from_static("Bearer tok-a"));
    h.insert("x-api-key", HeaderValue::from_static("tok-b"));
    assert_eq!(bearer_of(&h, None).as_deref(), Some("tok-a"));
    assert_eq!(bearer_of(&h, Some("x-api-key")).as_deref(), Some("tok-b"));
    assert_eq!(bearer_of(&h, Some("x-missing")), None);
    h.insert("authorization", HeaderValue::from_static("Basic abc"));
    assert_eq!(bearer_of(&h, None), None);
}

#[test]
fn client_items_become_one_response_in_the_order_the_plane_wrote_them() {
    let items = vec![
        ToClient::Head {
            status: 201,
            fields: vec![(b"content-type".to_vec(), b"text/plain".to_vec())],
        },
        ToClient::Body(b"he".to_vec()),
        ToClient::Msg {
            flags: 0,
            bytes: b"llo".to_vec(),
        },
        ToClient::End,
    ];
    let (status, fields, body) = parts_of(items);
    assert_eq!(status, 201);
    assert_eq!(fields, [(b"content-type".to_vec(), b"text/plain".to_vec())]);
    assert_eq!(body, b"hello");
}

#[test]
fn a_session_that_wrote_no_head_is_a_gateway_failure_not_a_200() {
    let (status, fields, body) = parts_of(vec![ToClient::Body(b"x".to_vec()), ToClient::End]);
    assert_eq!((status, fields.len(), body), (502, 0, Vec::new()));
}

#[test]
fn a_blocked_admission_is_answered_with_its_status_and_the_wait_it_names() {
    use busbar_kernel::governance::LimitBlocked;
    let limit = |metric, retry_after| LimitBlocked::Limit {
        group: "g".into(),
        metric,
        window: None,
        pool: None,
        downgrade_to: None,
        retry_after,
    };
    let rate = blocked_response(&limit("concurrent", None));
    assert_eq!(rate.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(rate.headers().get(header::RETRY_AFTER).is_none());
    let waited = blocked_response(&limit("requests", Some(30)));
    assert_eq!(waited.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(waited.headers()[header::RETRY_AFTER], "30");
    let frozen = blocked_response(&LimitBlocked::Disabled("g".into()));
    assert_eq!(frozen.status(), StatusCode::FORBIDDEN);
}
