// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ROUTE_ADMIN on the admin listener: which of a plane's admin routes a request names, and the answer the client
//! items make. The plane itself is an ffi handle, so the session runs in the image suite (W2-SW-PLANE e2e).

use busbar_contract::route::{METHOD_GET, METHOD_POST};
use busbar_plugin_abi::plane::{AUTH_OPERATOR, ROUTE_ADMIN};

use super::*;

fn admin(route: u32, methods: u32, pattern: &str) -> Mounted {
    Mounted {
        route,
        methods,
        flags: ROUTE_ADMIN,
        auth: AUTH_OPERATOR,
        effective: AUTH_OPERATOR,
        pattern: pattern.into(),
        cred_header: None,
        resource_kinds: Default::default(),
        catalog: false,
    }
}

#[test]
fn a_request_names_the_admin_route_its_method_and_path_match() {
    let routes = [
        admin(1, METHOD_GET | METHOD_POST, "/admin/connections/{id}"),
        admin(2, METHOD_GET, "/admin/health"),
    ];
    assert_eq!(
        matching(&routes, "GET", "/admin/connections/c1").map(|m| m.route),
        Some(1)
    );
    assert_eq!(
        matching(&routes, "POST", "/admin/connections/c1").map(|m| m.route),
        Some(1)
    );
    assert_eq!(
        matching(&routes, "GET", "/admin/health").map(|m| m.route),
        Some(2)
    );
    // The method is not in the route's mask, the path is another's, a segment is missing or extra.
    assert_eq!(matching(&routes, "POST", "/admin/health"), None);
    assert_eq!(matching(&routes, "DELETE", "/admin/connections/c1"), None);
    assert_eq!(matching(&routes, "GET", "/admin/connections"), None);
    assert_eq!(matching(&routes, "GET", "/admin/connections/c1/x"), None);
    assert_eq!(matching(&routes, "GET", "/v1/models"), None);
}

#[test]
fn a_method_outside_the_vocabulary_matches_no_route() {
    let routes = [admin(1, u32::MAX, "/admin/health")];
    assert_eq!(matching(&routes, "BREW", "/admin/health"), None);
}

#[test]
fn the_client_items_make_one_answer_and_no_head_is_a_bad_gateway() {
    let items = vec![
        ToClient::Head {
            status: 202,
            fields: vec![(b"content-type".to_vec(), b"application/json".to_vec())],
        },
        ToClient::Body(b"{\"a\":".to_vec()),
        ToClient::Msg {
            flags: 0,
            bytes: b"1}".to_vec(),
        },
        ToClient::End,
    ];
    let (status, fields, body) = joined(items);
    assert_eq!(status, 202);
    assert_eq!(
        fields,
        vec![(b"content-type".to_vec(), b"application/json".to_vec())]
    );
    assert_eq!(body, b"{\"a\":1}");
    assert_eq!(joined(vec![ToClient::End]), (502, Vec::new(), Vec::new()));
}

#[tokio::test]
async fn with_no_plane_installed_no_admin_route_is_answered() {
    use crate::limits::process_admission::{AdmissionClass, ProcessAdmission};
    let request = AdminRequest {
        request: ProcessAdmission::new(2)
            .try_enter(AdmissionClass::Operator)
            .unwrap(),
        method: "GET".into(),
        path: "/admin/health".into(),
        query: String::new(),
        headers: Vec::new(),
        body: bytes::Bytes::new(),
        request_id: 1,
        now_s: 1,
    };
    assert!(answer(&[], request).await.is_none());
}

/// ci/owed/cut/SECURITY-OWED.tsv `a_door_plane_admin_route_sees_no_consumed_credential_and_its_row_names_the_actor`,
/// the credential half. The admin listener copies the request's head fields into the request it
/// hands a native plane's admin route. The credential the operator chain judged must not be among
/// them, in any case and however many times it was sent; neither may a session cookie or a proxy
/// credential. Everything else, the plane's own fields included, is handed on untouched and in
/// order. (On the data path the same rule is `auth::native_data::withheld_carriers`.)
#[test]
fn a_planes_admin_route_is_handed_no_credential_the_admin_gate_read() {
    const SECRET: &[u8] = b"Bearer operator-secret-do-not-forward";
    let field = |name: &str, value: &[u8]| (name.to_owned(), value.to_vec());
    let handed = plane_headers(vec![
        field("content-type", b"application/json"),
        field("authorization", SECRET),
        field("Authorization", SECRET),
        field("AUTHORIZATION", SECRET),
        field("proxy-authorization", SECRET),
        field(
            "cookie",
            b"busbar_admin_session=operator-secret-do-not-forward",
        ),
        field("x-admin-token", b"operator-secret-do-not-forward"),
        field("x-plane-own-field", b"kept"),
        field("accept", b"*/*"),
    ]);
    for (name, value) in &handed {
        assert!(
            !value
                .windows(b"operator-secret-do-not-forward".len())
                .any(|window| window == b"operator-secret-do-not-forward"),
            "the plane was handed the operator's credential in `{name}`"
        );
    }
    assert_eq!(
        handed,
        vec![
            field("content-type", b"application/json"),
            field("x-plane-own-field", b"kept"),
            field("accept", b"*/*"),
        ],
        "every other field is handed on untouched and in order"
    );
}
