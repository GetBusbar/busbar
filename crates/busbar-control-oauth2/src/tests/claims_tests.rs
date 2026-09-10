// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TABLE AGREES WITH THE IDENTITY: every row's composed path is the path the identity derived
//! and the metadata document advertises, for a root issuer and for a tenant-prefixed one.

use super::{Anchor, Bar, Handler, Method, Route, ROUTES};
use crate::config::{Identity, Section};

fn identity(issuer: &str) -> Identity {
    Identity::from_section(&Section {
        issuer: issuer.to_string(),
        key_id: None,
        default_grant: Vec::new(),
        access_token_ttl_secs: None,
    })
    .expect("valid")
}

fn derived(id: &Identity, route: &Route) -> String {
    match route.name {
        "metadata" => id.metadata_path().to_string(),
        "jwks" => id.jwks_path().to_string(),
        "authorize" => id.authorize_path().to_string(),
        "token" => id.token_path().to_string(),
        "consent" => id.consent_path().to_string(),
        "register" => id.register_path().to_string(),
        other => panic!("a row the identity does not derive: {other}"),
    }
}

#[test]
fn every_row_composes_to_the_path_the_identity_derives() {
    for issuer in ["https://gw.example.com", "https://gw.example.com/tenant1"] {
        let id = identity(issuer);
        for route in ROUTES {
            assert_eq!(
                route.path_of(&id),
                derived(&id, route),
                "{issuer} {}",
                route.name
            );
        }
    }
}

#[test]
fn the_table_is_the_seven_legacy_rows_in_mount_order() {
    let shape: Vec<_> = ROUTES
        .iter()
        .map(|r| (r.name, r.method, r.bar, r.handler, r.anchor))
        .collect();
    assert_eq!(
        shape,
        vec![
            (
                "metadata",
                Method::Get,
                Bar::Open,
                Handler::Forward,
                Anchor::BeforeIssuer
            ),
            (
                "jwks",
                Method::Get,
                Bar::Open,
                Handler::Forward,
                Anchor::UnderIssuer
            ),
            (
                "authorize",
                Method::Get,
                Bar::Open,
                Handler::Forward,
                Anchor::UnderIssuer
            ),
            (
                "token",
                Method::Post,
                Bar::Open,
                Handler::Forward,
                Anchor::UnderIssuer
            ),
            (
                "consent",
                Method::Get,
                Bar::Operator,
                Handler::ConsentScreen,
                Anchor::UnderIssuer
            ),
            (
                "consent",
                Method::Post,
                Bar::Operator,
                Handler::ConsentSubmit,
                Anchor::UnderIssuer
            ),
            (
                "register",
                Method::Post,
                Bar::Open,
                Handler::Forward,
                Anchor::UnderIssuer
            ),
        ]
    );
}

/// The consent rows are the ONLY operator-barred rows, and they are the only rows whose bodies
/// read a session cookie — the two facts the cookie `Path` scoping in `answer` depends on.
#[test]
fn only_the_consent_rows_are_operator_barred() {
    for route in ROUTES {
        assert_eq!(
            route.bar == Bar::Operator,
            route.name == "consent",
            "{}",
            route.name
        );
    }
}
