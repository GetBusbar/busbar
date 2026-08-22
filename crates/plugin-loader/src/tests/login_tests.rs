// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/plugin-loader/src/auth.rs`.

use super::*;
use busbar_plugin::cold::auth::{HttpRequest, Identity};

#[test]
fn dyn_auth_begin_login_wrong_variant_fail_closed() {
    // A v1 / verify-only plugin can only answer Pass/Identity to a begin — never AuthorizeUrl.
    // Every non-AuthorizeUrl shape (and Pass in particular) FAILS CLOSED to Reject.
    assert_eq!(
        map_begin_login("m", Ok(AuthResponse::Pass)),
        LoginOutcome::Reject
    );
    assert_eq!(
        map_begin_login(
            "m",
            Ok(AuthResponse::Identity(Identity::from(Principal::from_id(
                "x"
            ))))
        ),
        LoginOutcome::Reject
    );
    // The happy path still works.
    assert!(matches!(
        map_begin_login("m", Ok(AuthResponse::AuthorizeUrl("https://idp".into()))),
        LoginOutcome::Authorize(_)
    ));
}

#[test]
fn dyn_auth_complete_login_transport_error_rejects() {
    // A transport/module error on complete_login FAILS CLOSED.
    assert_eq!(
        map_complete_login("m", Err("boom".to_string())),
        LoginOutcome::Reject
    );
    // A wrong-variant (AuthorizeUrl on complete) also fails closed.
    assert_eq!(
        map_complete_login("m", Ok(AuthResponse::AuthorizeUrl("x".into()))),
        LoginOutcome::Reject
    );
    // Valid verdicts ride through.
    assert!(matches!(
        map_complete_login(
            "m",
            Ok(AuthResponse::TokenExchange(HttpRequest {
                method: "POST".into(),
                url: "https://idp/token".into(),
                form: vec![],
                secret_form_field: None,
                headers: vec![],
            }))
        ),
        LoginOutcome::Exchange(_)
    ));
}
