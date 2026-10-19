// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The route vocabulary's wire spellings (`abi/mechanism/route.rs`).

use super::*;

/// The method tokens are the stable UPPERCASE wire spellings a non-Rust author matches on, and
/// [`RouteMethod::as_str`] agrees with the serde spelling (the diagnostic + wire cannot drift).
#[test]
fn method_wire_spellings_are_pinned() {
    for (m, tok) in [
        (RouteMethod::Get, "GET"),
        (RouteMethod::Post, "POST"),
        (RouteMethod::Put, "PUT"),
        (RouteMethod::Patch, "PATCH"),
        (RouteMethod::Delete, "DELETE"),
    ] {
        assert_eq!(serde_json::to_value(m).unwrap(), serde_json::json!(tok));
        assert_eq!(m.as_str(), tok);
    }
}

/// The auth tokens are the stable snake_case wire spellings.
#[test]
fn auth_wire_spellings_are_pinned() {
    for (a, tok) in [
        (RouteAuth::None, "none"),
        (RouteAuth::Key, "key"),
        (RouteAuth::Admin, "admin"),
    ] {
        assert_eq!(serde_json::to_value(a).unwrap(), serde_json::json!(tok));
    }
}

/// A route declaration round-trips through JSON unchanged.
#[test]
fn route_json_roundtrip() {
    let r = Route {
        path: "/hooks/smart-router/feedback".into(),
        method: RouteMethod::Post,
        auth: RouteAuth::Key,
    };
    let j = serde_json::to_vec(&r).unwrap();
    let back: Route = serde_json::from_slice(&j).unwrap();
    assert_eq!(back, r);
}

/// RED (a zero never grants): the route vocabulary's zero is the undeclared bar, the
/// unauthenticated bar is never zero, and each declared bar carries the export and hook kinds'
/// `ROUTE_AUTH_*` code. A zeroed route states the undeclared bar.
#[test]
fn a_zeroed_route_declares_no_auth_bar() {
    use crate::abi::{export, hook};
    assert_eq!(Route::ZERO.auth, RouteAuth::Undeclared);
    assert_eq!(RouteAuth::Undeclared.code(), 0);
    assert_ne!(RouteAuth::None.code(), 0, "unauthenticated is never zero");
    for (a, e, h) in [
        (
            RouteAuth::Undeclared,
            export::ROUTE_AUTH_UNDECLARED,
            hook::ROUTE_AUTH_UNDECLARED,
        ),
        (RouteAuth::Key, export::ROUTE_AUTH_KEY, hook::ROUTE_AUTH_KEY),
        (
            RouteAuth::Admin,
            export::ROUTE_AUTH_ADMIN,
            hook::ROUTE_AUTH_ADMIN,
        ),
        (
            RouteAuth::None,
            export::ROUTE_AUTH_NONE,
            hook::ROUTE_AUTH_NONE,
        ),
    ] {
        assert_eq!((a.code(), a.code()), (e, h), "{a:?}");
        assert_eq!(RouteAuth::from_code(e), Some(a), "{a:?}");
    }
    assert_eq!(RouteAuth::from_code(4), None);
    // The undeclared bar has no wire spelling: a declaration cannot name it.
    assert!(serde_json::from_value::<RouteAuth>(serde_json::json!("undeclared")).is_err());
}
