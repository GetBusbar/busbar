// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use base64::Engine as _;

use super::{bearer_constraint, is_dpop_bound, SenderConstraint};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

fn jwt(claims: serde_json::Value) -> String {
    format!(
        "{}.{}.c2ln",
        B64.encode(r#"{"alg":"ES256","typ":"at+jwt"}"#),
        B64.encode(claims.to_string())
    )
}

#[test]
fn only_a_token_carrying_cnf_jkt_is_dpop_bound() {
    assert!(is_dpop_bound(&jwt(
        serde_json::json!({ "sub": "a", "cnf": { "jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I" } })
    )));
    assert!(!is_dpop_bound(&jwt(serde_json::json!({ "sub": "a" }))));
    assert!(!is_dpop_bound(&jwt(
        serde_json::json!({ "sub": "a", "cnf": { "x5t#S256": "abc" } })
    )));
    assert!(!is_dpop_bound(&jwt(
        serde_json::json!({ "sub": "a", "cnf": { "jkt": 7 } })
    )));
    assert!(!is_dpop_bound("an-opaque-reference-token"));
    assert!(!is_dpop_bound(&format!(
        "{}{}",
        crate::governance::signing::TOKEN_PREFIX,
        "whatever.has.dots"
    )));
}

// These are internal constraint-policy continuations. Unconstrained means the DPoP filter
// leaves authentication to the actual chain; it never admits an unsigned JWT or opaque string.
#[test]
fn an_unbound_bearer_is_judged_exactly_as_before() {
    let unbound = jwt(serde_json::json!({ "sub": "a" }));
    for configured in [false, true] {
        assert!(matches!(
            bearer_constraint(configured, Some(&unbound), &mut None),
            SenderConstraint::Unconstrained
        ));
        assert!(matches!(
            bearer_constraint(configured, Some("opaque-token"), &mut None),
            SenderConstraint::Unconstrained
        ));
    }
}

#[test]
fn with_an_authorization_server_a_dpop_bound_bearer_is_refused() {
    let bound = jwt(serde_json::json!({ "sub": "a", "cnf": { "jkt": "abc" } }));
    for carrier in ["authorization", "x-api-key"] {
        let mut headers = axum::http::HeaderMap::new();
        let value = if carrier == "authorization" {
            format!("Bearer {bound}")
        } else {
            bound.clone()
        };
        headers.insert(
            axum::http::HeaderName::from_static(carrier),
            value.parse().unwrap(),
        );
        let bearer = crate::auth::carried_credential(
            &[axum::http::HeaderName::from_static(carrier)],
            &headers,
        );
        assert!(
            matches!(
                bearer_constraint(true, bearer.as_deref(), &mut None),
                SenderConstraint::Refused
            ),
            "bound token refused through {carrier}"
        );
    }
}

#[test]
fn without_an_authorization_server_a_dpop_bound_bearer_is_unconstrained() {
    let bound = jwt(serde_json::json!({ "sub": "a", "cnf": { "jkt": "abc" } }));
    for carrier in ["authorization", "x-api-key"] {
        let mut headers = axum::http::HeaderMap::new();
        let value = if carrier == "authorization" {
            format!("Bearer {bound}")
        } else {
            bound.clone()
        };
        headers.insert(
            axum::http::HeaderName::from_static(carrier),
            value.parse().unwrap(),
        );
        let bearer = crate::auth::carried_credential(
            &[axum::http::HeaderName::from_static(carrier)],
            &headers,
        );
        assert!(
            matches!(
                bearer_constraint(false, bearer.as_deref(), &mut None),
                SenderConstraint::Unconstrained
            ),
            "the chain still authenticates the token through {carrier}"
        );
    }
}

#[test]
fn the_bound_bearer_constraint_applies_before_exchange() {
    let bound = jwt(serde_json::json!({ "sub": "a", "cnf": { "jkt": "abc" } }));
    assert!(matches!(
        bearer_constraint(true, Some(&bound), &mut None),
        SenderConstraint::Refused
    ));
    let unbound = jwt(serde_json::json!({ "sub": "a" }));
    assert!(matches!(
        bearer_constraint(true, Some(&unbound), &mut None),
        SenderConstraint::Unconstrained
    ));
}

#[test]
fn without_an_authorization_server_exchange_bearer_constraints_are_identical() {
    let bound = jwt(serde_json::json!({ "sub": "a", "cnf": { "jkt": "abc" } }));
    let unbound = jwt(serde_json::json!({ "sub": "a" }));
    let bound_unconstrained = matches!(
        bearer_constraint(false, Some(&bound), &mut None),
        SenderConstraint::Unconstrained
    );
    let unbound_unconstrained = matches!(
        bearer_constraint(false, Some(&unbound), &mut None),
        SenderConstraint::Unconstrained
    );
    assert_eq!(
        bound_unconstrained, unbound_unconstrained,
        "cnf claims do not change the no-AS constraint decision"
    );
    assert!(
        bound_unconstrained,
        "the actual chain is still responsible for authentication"
    );
}
