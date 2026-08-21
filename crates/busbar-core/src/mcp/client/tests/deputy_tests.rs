// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TRANSITIVE CONFUSED-DEPUTY DEFENCE — outbound credential selection bound to the INBOUND
//! principal's grant — and the single most important battery in the client direction.
//!
//! ## The bug being defended against, stated exactly
//!
//! busbar holds ambient credentials for upstream MCP servers. An authenticated inbound caller asks
//! busbar to call one. If busbar selects an upstream credential on the basis of its OWN identity —
//! "I have a token for `payments`, so I can call `payments`" — then the caller has just spent
//! authority it does not hold. That is the TRANSITIVE CONFUSED DEPUTY, and a client-only gateway
//! cannot have it, because
//! it has no inbound principal to be confused about. The bundle creates it, so the bundle closes it.
//!
//! ## What is proven here, and what is NOT
//!
//! PROVEN: outbound credential selection consults the INBOUND principal's grant, refuses without
//! both grants, and — for RFC 8693 — asks for a scope DERIVED from that grant rather than from
//! busbar's own authority.
//!
//! NOT PROVEN: that a real inbound MCP `tools/call` resolves to the principal used here. The
//! server direction's method surface does not exist yet. The principal is
//! a `busbar_api::VirtualKey`, which is the type BOTH directions resolve to and the one
//! `scope_allowed` is defined on, so the seam is real — but egress scoping is one of the two
//! integrity properties that are only meaningful as a PAIR with the inbound surface, so it is not
//! proven end to end until the two halves land together, and that is stated rather than implied.

use crate::mcp::client::egress::{
    authorise_tool_egress, downscope, plan_credential, CredentialPlan, EgressDenied, ExchangeCfg,
    UpstreamCredential,
};
use crate::mcp::client::support::{key_wildcard, key_with_scopes, sid, tkey};
use busbar_api::{Redacted, ScopeRef};

/// busbar's ambient credential for an upstream it is fully authorised for. Every test below uses
/// this, so a refusal can never be explained by busbar lacking a credential — the ONLY variable is
/// the inbound caller's grant.
fn ambient_exchange() -> UpstreamCredential {
    UpstreamCredential::Exchange(ExchangeCfg {
        token_url: "https://idp.example.com/token".into(),
        subject_token: Redacted::new("BUSBAR-OWN-AMBIENT-TOKEN".into()),
        subject_token_type: "urn:ietf:params:oauth:token-type:access_token".into(),
        resource: "https://payments.internal/mcp".into(),
    })
}

/// THE HEADLINE. busbar holds a credential; the caller does not hold the grant; NO credential is
/// selected. The refusal names the caller and the server, because an unattributable denial is a
/// denial nobody can act on.
#[test]
fn busbars_own_credential_is_not_spent_for_a_caller_without_the_server_grant() {
    let caller = key_with_scopes("agent-1", vec![ScopeRef::pool("fast")]);
    let called = tkey("payments", "refund");
    let err = plan_credential(
        &sid("payments"),
        &ambient_exchange(),
        &caller,
        None,
        &called,
    )
    .expect_err("an ungranted caller must not cause a credential to be selected");
    assert_eq!(
        err,
        EgressDenied::NoServerGrant {
            caller: "agent-1".into(),
            server: "payments".into()
        }
    );
    assert!(
        err.to_string()
            .contains("busbar does not spend its own credentials"),
        "the refusal must say why: {err}"
    );
}

/// A SERVER grant is not a TOOL grant. Both are required, and this is the case a single check would
/// get wrong — the caller may reach `payments` and is still not authorised for `refund`.
#[test]
fn a_server_grant_alone_does_not_authorise_a_tool() {
    let caller = key_with_scopes(
        "agent-1",
        vec![ScopeRef {
            kind: "mcp_server".into(),
            value: "payments".into(),
        }],
    );
    let err = plan_credential(
        &sid("payments"),
        &ambient_exchange(),
        &caller,
        None,
        &tkey("payments", "refund"),
    )
    .expect_err("a server grant is not a tool grant");
    assert_eq!(
        err,
        EgressDenied::NoToolGrant {
            caller: "agent-1".into(),
            tool: "payments_refund".into()
        }
    );
}

/// A TOOL grant alone does not authorise the server either. The two checks are independent in both
/// directions, which is what stops one of them being decorative.
#[test]
fn a_tool_grant_alone_does_not_authorise_the_server() {
    let caller = key_with_scopes(
        "agent-1",
        vec![ScopeRef {
            kind: "mcp_tool".into(),
            value: "payments_refund".into(),
        }],
    );
    assert_eq!(
        authorise_tool_egress(&caller, &tkey("payments", "refund")),
        Err(EgressDenied::NoServerGrant {
            caller: "agent-1".into(),
            server: "payments".into()
        })
    );
}

/// THE POSITIVE CASE, so the battery is not passing because everything is refused. With both grants
/// the plan is produced, and its shape is asserted.
#[test]
fn both_grants_produce_an_audience_bound_exchange() {
    let caller = key_with_scopes(
        "agent-1",
        vec![
            ScopeRef {
                kind: "mcp_server".into(),
                value: "payments".into(),
            },
            ScopeRef {
                kind: "mcp_tool".into(),
                value: "payments_refund".into(),
            },
        ],
    );
    let plan = plan_credential(
        &sid("payments"),
        &ambient_exchange(),
        &caller,
        None,
        &tkey("payments", "refund"),
    )
    .expect("a fully granted caller gets a plan");
    let CredentialPlan::Exchange(req) = plan else {
        panic!("expected an RFC 8693 exchange");
    };
    // RFC 8693 §2.1.
    assert_eq!(
        req.grant_type,
        "urn:ietf:params:oauth:grant-type:token-exchange"
    );
    assert_eq!(
        req.requested_token_type,
        "urn:ietf:params:oauth:token-type:access_token"
    );
    // RFC 8707: the token is bound to THIS upstream and no other.
    assert_eq!(req.resource, "https://payments.internal/mcp");
    // The down-scope is the caller's grant, not busbar's authority.
    assert_eq!(req.scope, "payments_refund");
    // The SUBJECT is busbar's own token. It has to be: exchanging the caller's busbar key would be
    // rule 1's violation wearing an RFC number.
    assert_eq!(
        req.subject_token.expose_secret(),
        "BUSBAR-OWN-AMBIENT-TOKEN"
    );
}

/// DOWN-SCOPING IS DERIVED FROM THE GRANT. A caller granted one tool on a server gets a token
/// scoped to one tool, even though busbar's own credential covers the whole server.
#[test]
fn the_requested_scope_is_the_callers_grant_and_nothing_wider() {
    let narrow = key_with_scopes(
        "narrow",
        vec![
            ScopeRef {
                kind: "mcp_server".into(),
                value: "payments".into(),
            },
            ScopeRef {
                kind: "mcp_tool".into(),
                value: "payments_refund".into(),
            },
        ],
    );
    let wide = key_with_scopes(
        "wide",
        vec![
            ScopeRef {
                kind: "mcp_server".into(),
                value: "payments".into(),
            },
            ScopeRef {
                kind: "mcp_tool".into(),
                value: "payments_refund".into(),
            },
            ScopeRef {
                kind: "mcp_tool".into(),
                value: "payments_charge".into(),
            },
            // A grant on a DIFFERENT server must not widen this server's token.
            ScopeRef {
                kind: "mcp_tool".into(),
                value: "ledger_write".into(),
            },
        ],
    );
    let called = tkey("payments", "refund");
    assert_eq!(
        downscope(&narrow, &sid("payments"), &called),
        "payments_refund"
    );
    assert_eq!(
        downscope(&wide, &sid("payments"), &called),
        "payments_charge payments_refund"
    );
}

/// A WILDCARD principal gets the SINGLE tool being called, not everything.
///
/// This is the case that would quietly make the whole egress gate vacuous in a small deployment,
/// where keys are often minted with no scope list at all. `allowed_scopes: None` is an absence of a
/// constraint on the INBOUND side; turning it into a grant of everything on the OUTBOUND side is
/// the confused deputy arriving through the default configuration.
#[test]
fn a_wildcard_principal_is_still_down_scoped_to_the_one_tool_it_called() {
    let caller = key_wildcard("root");
    assert_eq!(
        downscope(&caller, &sid("payments"), &tkey("payments", "refund")),
        "payments_refund"
    );
    // ...and it is authorised, because a wildcard IS a grant. The point is the scope, not the gate.
    assert!(authorise_tool_egress(&caller, &tkey("payments", "refund")).is_ok());
}

/// An EMPTY scope list is the empty set, never "all" — the frozen 1.5.3 semantics, re-asserted here
/// because this is the site where reading it the other way would be an authority grant.
#[test]
fn an_empty_scope_list_grants_nothing_on_the_egress_path() {
    let caller = key_with_scopes("locked-down", vec![]);
    assert!(authorise_tool_egress(&caller, &tkey("payments", "refund")).is_err());
}

/// PASSTHROUGH FAILS CLOSED. A server configured to forward the caller's own upstream credential
/// does NOT fall back to busbar's ambient one when the caller supplies none — that fallback is
/// exactly the deputy.
#[test]
fn passthrough_without_a_caller_credential_never_falls_back_to_busbars_own() {
    let caller = key_with_scopes(
        "agent-1",
        vec![
            ScopeRef {
                kind: "mcp_server".into(),
                value: "payments".into(),
            },
            ScopeRef {
                kind: "mcp_tool".into(),
                value: "payments_refund".into(),
            },
        ],
    );
    let err = plan_credential(
        &sid("payments"),
        &UpstreamCredential::Passthrough,
        &caller,
        None,
        &tkey("payments", "refund"),
    )
    .expect_err("passthrough with no caller credential must fail closed");
    assert_eq!(
        err,
        EgressDenied::PassthroughWithoutCallerCredential {
            server: "payments".into()
        }
    );
}

/// THE GATE RUNS BEFORE ANYTHING ELSE. An ungranted caller must not even cause a token-endpoint
/// round trip on busbar's credentials — a refusal that happens after the exchange has already been
/// requested has already spent the authority it was meant to withhold.
///
/// Asserted structurally: `plan_credential` returns the exchange REQUEST rather than performing it,
/// and for an ungranted caller it returns an error instead of a request. There is no code path from
/// an ungranted caller to an `ExchangeRequest` value.
#[test]
fn an_ungranted_caller_never_produces_an_exchange_request_at_all() {
    let caller = key_with_scopes("agent-1", vec![]);
    for credential in [
        ambient_exchange(),
        UpstreamCredential::Static(Redacted::new("static".into())),
        UpstreamCredential::Passthrough,
        UpstreamCredential::None,
    ] {
        let out = plan_credential(
            &sid("payments"),
            &credential,
            &caller,
            Some(&Redacted::new("caller-upstream".into())),
            &tkey("payments", "refund"),
        );
        assert!(
            matches!(out, Err(EgressDenied::NoServerGrant { .. })),
            "every credential mode must refuse an ungranted caller identically, got {out:?}"
        );
    }
}
