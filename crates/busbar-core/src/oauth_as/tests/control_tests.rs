// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The translation this file performs is the security-critical half of the move: a bar that arrives
//! as `Bar::Operator` and leaves as `RouteAuth::None` is an unauthenticated consent screen, and
//! nothing else in the tree would notice. These tests read the DECLARED table and check the
//! translation row by row.

use super::*;
use busbar_control_oauth2::config::{AsIdentity, OauthAsCfg};
use busbar_plugin_loader::{RouteAuth, RouteMethod};

/// The decl the root installs is the one the surface names, and it is a CONTROL decl — two fields,
/// no meter class, no scope kind, no audience binding.
#[test]
fn the_registration_carries_the_surfaces_own_key() {
    assert_eq!(CONTROL_DECL.key, busbar_control_oauth2::meta::KEY);
    assert_eq!(CONTROL_DECL.key, "oauth2");
}

/// THE BAR SURVIVES THE TRANSLATION. `Bar::Operator` must become `RouteAuth::Admin` — the value that
/// puts the consent screen behind the node's existing admin chain — and `Bar::Open` must become
/// `RouteAuth::None`, which is what lets a conforming client reach `/token` with OAuth's own client
/// authentication in the body rather than busbar's.
///
/// Both directions are asserted. Only checking the `Admin` half would leave a translation that
/// mapped everything to `Admin` green, and that one refuses every conforming client.
#[test]
fn the_declared_bar_becomes_the_route_table_bar() {
    for route in ROUTES {
        let got = auth_of(route);
        let want = match route.bar {
            Bar::Open => RouteAuth::None,
            Bar::Operator => RouteAuth::Admin,
        };
        assert_eq!(
            got, want,
            "{:?} {:?} declared {:?} and was mounted as {got:?}",
            route.endpoint, route.method, route.bar
        );
    }
}

/// THE ONE BARRED PATH, named as a path rather than as an enum, because a path is what the auth
/// middleware matches on. This is the test that goes red if the consent screen is ever mounted open.
#[test]
fn the_consent_screen_and_only_the_consent_screen_takes_the_admin_bar() {
    let identity = AsIdentity::from_cfg(&OauthAsCfg {
        issuer: "https://gw.example.com".to_string(),
        signing_key: None,
        key_id: None,
        default_grant: Vec::new(),
        access_token_ttl_secs: None,
    })
    .expect("a root https issuer is valid");
    let admin_paths: Vec<String> = ROUTES
        .iter()
        .filter(|r| auth_of(r) == RouteAuth::Admin)
        .map(|r| r.endpoint.path_of(&identity).to_string())
        .collect();
    assert_eq!(
        admin_paths,
        vec!["/consent".to_string(), "/consent".to_string()],
        "exactly the consent screen's GET and POST sit behind the operator bar"
    );
}

/// The method survives too. Cheap, and the failure it catches is a `/token` mounted GET-only, which
/// answers 405 to every conforming client and looks like a client bug from the outside.
#[test]
fn the_declared_method_becomes_the_route_table_method() {
    for route in ROUTES {
        let want = match route.method {
            Method::Get => RouteMethod::Get,
            Method::Post => RouteMethod::Post,
        };
        assert_eq!(method_of(route), want);
    }
}
