// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Per-server credential injection: the RFC 8693 request shape, RFC 8707 binding, and the per-server
//! independence §5.1 requires.
//!
//! The confused-deputy half of this module is in `deputy_tests.rs`; this file pins the WIRE SHAPE, so
//! a reader can compare it against RFC 8693 §2.1 field by field.

use crate::mcp::client::egress::{
    plan_credential, CredentialPlan, ExchangeCfg, UpstreamCredential,
};
use crate::mcp::client::support::{key_wildcard, sid, tkey};
use busbar_api::Redacted;

fn exchange_for(resource: &str) -> UpstreamCredential {
    UpstreamCredential::Exchange(ExchangeCfg {
        token_url: "https://idp.example.com/token".into(),
        subject_token: Redacted::new("subject".into()),
        subject_token_type: "urn:ietf:params:oauth:token-type:access_token".into(),
        resource: resource.into(),
    })
}

#[test]
fn the_exchange_form_carries_exactly_the_rfc_8693_fields() {
    let plan = plan_credential(
        &sid("payments"),
        &exchange_for("https://payments.internal/mcp"),
        &key_wildcard("k"),
        None,
        &tkey("payments", "refund"),
    )
    .unwrap();
    let CredentialPlan::Exchange(req) = plan else {
        panic!("expected an exchange");
    };
    let fields = req.form_fields();
    let names: Vec<&str> = fields.iter().map(|(k, _)| *k).collect();
    assert_eq!(
        names,
        vec![
            "grant_type",
            "subject_token",
            "subject_token_type",
            "requested_token_type",
            "resource",
            "scope",
        ]
    );
    let get = |n: &str| -> String {
        fields
            .iter()
            .find(|(k, _)| *k == n)
            .map(|(_, v)| v.clone())
            .unwrap()
    };
    assert_eq!(
        get("grant_type"),
        "urn:ietf:params:oauth:grant-type:token-exchange"
    );
    assert_eq!(
        get("requested_token_type"),
        "urn:ietf:params:oauth:token-type:access_token"
    );
    assert_eq!(get("resource"), "https://payments.internal/mcp");
    assert_eq!(get("scope"), "payments_refund");
}

/// RFC 8707: EVERY upstream gets a token bound to ITS OWN resource. Two servers, two audiences —
/// this is what stops a token minted for one backend being spendable at another, which is the same
/// rule busbar enforces on its own inbound side.
#[test]
fn each_upstream_gets_a_token_bound_to_its_own_resource() {
    let caller = key_wildcard("k");
    let cases = [
        ("payments", "https://payments.internal/mcp"),
        ("ledger", "https://ledger.internal/mcp"),
    ];
    assert_eq!(cases.len(), 2);
    let mut audiences = Vec::new();
    for (server, resource) in cases {
        let plan = plan_credential(
            &sid(server),
            &exchange_for(resource),
            &caller,
            None,
            &tkey(server, "op"),
        )
        .unwrap();
        let CredentialPlan::Exchange(req) = plan else {
            panic!("expected an exchange");
        };
        assert_eq!(req.resource, resource);
        audiences.push(req.resource);
    }
    assert_ne!(audiences[0], audiences[1], "the audiences must differ");
}

#[test]
fn a_static_credential_is_returned_verbatim_and_a_none_credential_sends_nothing() {
    let caller = key_wildcard("k");
    let plan = plan_credential(
        &sid("s"),
        &UpstreamCredential::Static(Redacted::new("server-secret".into())),
        &caller,
        None,
        &tkey("s", "t"),
    )
    .unwrap();
    match plan {
        CredentialPlan::Bearer(b) => assert_eq!(b.expose_secret(), "server-secret"),
        other => panic!("expected a bearer, got {other:?}"),
    }
    let none = plan_credential(
        &sid("s"),
        &UpstreamCredential::None,
        &caller,
        None,
        &tkey("s", "t"),
    )
    .unwrap();
    assert!(matches!(none, CredentialPlan::None));
}

#[test]
fn passthrough_forwards_the_callers_upstream_credential() {
    let plan = plan_credential(
        &sid("s"),
        &UpstreamCredential::Passthrough,
        &key_wildcard("k"),
        Some(&Redacted::new("caller-holds-this".into())),
        &tkey("s", "t"),
    )
    .unwrap();
    match plan {
        CredentialPlan::Bearer(b) => assert_eq!(b.expose_secret(), "caller-holds-this"),
        other => panic!("expected a bearer, got {other:?}"),
    }
}

/// §5.1: MCP credentials are PER SERVER and there is no plane-wide default. Two servers configured
/// differently behave differently for the same caller and the same tool name.
#[test]
fn two_servers_authenticate_independently() {
    let caller = key_wildcard("k");
    let a = plan_credential(
        &sid("a"),
        &UpstreamCredential::Static(Redacted::new("A".into())),
        &caller,
        None,
        &tkey("a", "t"),
    )
    .unwrap();
    let b = plan_credential(
        &sid("b"),
        &exchange_for("https://b.internal/mcp"),
        &caller,
        None,
        &tkey("b", "t"),
    )
    .unwrap();
    assert!(matches!(a, CredentialPlan::Bearer(_)));
    assert!(matches!(b, CredentialPlan::Exchange(_)));
}
