// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Conformance: this crate is a well-formed CONTROL surface.
//!
//! The module every sibling of a kind carries (`PLUGIN-TREE.md` §3). Two of the six standard tests
//! cannot be written yet and say so in their own bodies rather than being quietly omitted: there is
//! no `Kind::Control` in `busbar-contract` and no `CONTROL_ABI` floor, so `kind_is_declared_once`
//! and `abi_matches_the_kind_floor` have nothing to assert against. They are recorded here as
//! failing-to-exist rather than as passing, because a conformance file that is green because it
//! checks nothing is worse than one that is absent.

use crate::claims::{Bar, Endpoint, Handler, Method, ROUTES};
use crate::config::{AsIdentity, OauthAsCfg};
use crate::meta;

/// An identity to derive paths from. A root issuer, so the paths read as the RFC spells them.
fn identity() -> AsIdentity {
    AsIdentity::from_cfg(&OauthAsCfg {
        issuer: "https://gw.example.com".to_string(),
        signing_key: None,
        key_id: None,
        default_grant: vec!["mcp:read".to_string()],
        access_token_ttl_secs: None,
    })
    .expect("a root https issuer is valid")
}

#[test]
fn key_is_stable_and_lowercase() {
    assert_eq!(meta::KEY, "oauth2");
    assert!(meta::KEY
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'));
    assert_eq!(meta::DIALECT, "oauth2");
}

/// The control path is the LESSER workflow, and the assertion is that it is lesser: four rungs,
/// named, in order, and none of them a metered step. A control surface that grew `meter` or `route`
/// would be a plane wearing the wrong crate prefix.
#[test]
fn the_control_path_is_the_four_unmetered_rungs() {
    assert_eq!(meta::CONTROL_PATH, &["verify", "admit", "audit", "answer"]);
    for forbidden in ["decode", "approve", "route", "meter", "encode", "price"] {
        assert!(
            !meta::CONTROL_PATH.contains(&forbidden),
            "`{forbidden}` is a data-plane step and a control surface is never called at it"
        );
    }
}

/// EVERY DECLARED ROUTE RESOLVES TO A PATH — no stub facts. The rule the table exists to make
/// checkable is that this surface answers on exactly the paths it declares, so a row whose endpoint
/// had no path would be a row nothing could mount.
#[test]
fn every_declared_route_resolves_to_a_path() {
    let id = identity();
    for route in ROUTES {
        let path = route.endpoint.path_of(&id);
        assert!(
            path.starts_with('/'),
            "{:?} resolved to `{path}`, which is not a mountable path",
            route.endpoint
        );
    }
}

/// THE WHOLE INVENTORY, pinned. This is the list `busbar-core`'s `mount_tests.rs` subtracts one
/// route table from another to find, and the list an operator sees in a boot listing. A route added
/// without a line here is a route that entered the surface without anyone writing down that it did.
#[test]
fn the_declared_surface_is_exactly_these_seven_rows() {
    let id = identity();
    let rows: Vec<(String, Method, Bar, Handler)> = ROUTES
        .iter()
        .map(|r| {
            (
                r.endpoint.path_of(&id).to_string(),
                r.method,
                r.bar,
                r.handler,
            )
        })
        .collect();
    assert_eq!(
        rows,
        vec![
            (
                "/.well-known/oauth-authorization-server".to_string(),
                Method::Get,
                Bar::Open,
                Handler::Forward
            ),
            (
                "/jwks".to_string(),
                Method::Get,
                Bar::Open,
                Handler::Forward
            ),
            (
                "/authorize".to_string(),
                Method::Get,
                Bar::Open,
                Handler::Forward
            ),
            (
                "/token".to_string(),
                Method::Post,
                Bar::Open,
                Handler::Forward
            ),
            (
                "/consent".to_string(),
                Method::Get,
                Bar::Operator,
                Handler::ConsentScreen
            ),
            (
                "/consent".to_string(),
                Method::Post,
                Bar::Operator,
                Handler::ConsentSubmit
            ),
            (
                "/register".to_string(),
                Method::Post,
                Bar::Open,
                Handler::Forward
            ),
        ]
    );
}

/// THE ONE BARRED ROUTE, isolated. The consent screen is the only endpoint busbar authenticates
/// itself, and this test is what goes red if a future edit widens the bar off it — which would hand
/// an unauthenticated visitor a page that stakes an approval, or narrows it onto `/token`, which
/// would refuse every conforming client.
#[test]
fn only_the_consent_endpoint_is_behind_the_operator_bar() {
    let barred: Vec<Endpoint> = ROUTES
        .iter()
        .filter(|r| r.bar == Bar::Operator)
        .map(|r| r.endpoint)
        .collect();
    assert_eq!(barred, vec![Endpoint::Consent, Endpoint::Consent]);
}

/// A TENANT-PREFIXED ISSUER moves every path under the prefix, and the well-known one moves the
/// OTHER way (RFC 8414 §3.1 puts the segment BEFORE the issuer's path). Declared here rather than
/// only in `config_tests` because it is the table's behaviour that matters: a mount that got this
/// backwards would 404 every conforming client's discovery.
#[test]
fn a_tenant_prefixed_issuer_moves_every_declared_path() {
    let id = AsIdentity::from_cfg(&OauthAsCfg {
        issuer: "https://gw.example.com/tenant-a".to_string(),
        signing_key: None,
        key_id: None,
        default_grant: Vec::new(),
        access_token_ttl_secs: None,
    })
    .expect("a path-bearing https issuer is valid");
    assert_eq!(
        Endpoint::Metadata.path_of(&id),
        "/.well-known/oauth-authorization-server/tenant-a"
    );
    assert_eq!(Endpoint::Token.path_of(&id), "/tenant-a/token");
    assert_eq!(Endpoint::Consent.path_of(&id), "/tenant-a/consent");
}

/// **OWED, and red-by-construction rather than absent.** `PLUGIN-TREE.md` §3 requires every sibling
/// of a kind to assert `P.kind() == Kind::<K>` and `P.abi() == <K>_ABI`. Neither is writable:
/// `busbar_contract::plugin::Kind` has eight variants and none of them is `Control`, and the crate
/// carries an ABI floor for two kinds only (`STORE_ABI`, `TRANSPORT_ABI`). This test records the
/// gap so it is a line in a test report rather than a comment nobody runs, and it is deleted — not
/// weakened — on the day the control-kind row lands in the contract.
#[test]
#[ignore = "busbar-contract has no Kind::Control and no CONTROL_ABI yet; see docs/design/control-oauth2.md"]
fn kind_and_abi_are_declared_against_the_contract() {
    panic!(
        "busbar-contract carries no `Kind::Control` and no `CONTROL_ABI`, so this crate cannot \
         implement `busbar_contract::plugin::Plugin`. It declares `meta::CONTROL_ABI = {}` \
         locally instead. When the control-kind row lands in the contract, replace this test with \
         the two assertions PLUGIN-TREE.md section 3 requires.",
        meta::CONTROL_ABI
    );
}
