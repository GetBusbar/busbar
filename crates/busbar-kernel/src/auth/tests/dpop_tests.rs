// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use base64::Engine as _;
use busbar_contract::json;

use super::{
    bearer_constraint, is_dpop_bound, refuse_bound_session, Refusal, SenderConstraint,
    BOUND_BEARER_DESCRIPTION, PROOF_FAILED_DESCRIPTION, UNVERIFIABLE_DESCRIPTION,
};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

fn jwt(claims: json::Value) -> String {
    format!(
        "{}.{}.c2ln",
        B64.encode(r#"{"alg":"ES256","typ":"at+jwt"}"#),
        B64.encode(claims.to_string())
    )
}

#[test]
fn a_malformed_jkt_is_bound() {
    assert!(is_dpop_bound(&jwt(
        json::json!({ "sub": "a", "cnf": { "jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I" } })
    )));
    assert!(!is_dpop_bound(&jwt(json::json!({ "sub": "a" }))));
    assert!(!is_dpop_bound(&jwt(
        json::json!({ "sub": "a", "cnf": { "x5t#S256": "abc" } })
    )));
    // Any cnf.jkt, whatever its type, demands a proof: a malformed one can only be refused.
    for jkt in [
        json::json!(7),
        json::json!(123),
        json::json!({}),
        json::json!(null),
    ] {
        assert!(
            is_dpop_bound(&jwt(json::json!({ "sub": "a", "cnf": { "jkt": jkt } }))),
            "cnf.jkt {jkt} is bound"
        );
    }
    assert!(!is_dpop_bound("an-opaque-reference-token"));
    assert!(!is_dpop_bound(&format!(
        "{}{}",
        crate::governance::signing::TOKEN_PREFIX,
        "whatever.has.dots"
    )));
}

fn carriers() -> Vec<axum::http::HeaderName> {
    vec![
        axum::http::header::AUTHORIZATION,
        axum::http::HeaderName::from_static("x-api-key"),
    ]
}

fn presenting(pairs: &[(&'static str, &str)]) -> axum::http::HeaderMap {
    let mut headers = axum::http::HeaderMap::new();
    for (name, value) in pairs {
        headers.append(
            axum::http::HeaderName::from_static(name),
            value.parse().unwrap(),
        );
    }
    headers
}

fn carried(carrier: &'static str, token: &str) -> axum::http::HeaderMap {
    let value = if carrier == "authorization" {
        format!("Bearer {token}")
    } else {
        token.to_owned()
    };
    presenting(&[(carrier, &value)])
}

#[test]
fn an_unbound_bearer_is_judged_exactly_as_before() {
    let unbound = jwt(json::json!({ "sub": "a" }));
    for carrier in ["authorization", "x-api-key"] {
        assert!(matches!(
            bearer_constraint(&carried(carrier, &unbound), &carriers()),
            SenderConstraint::Unconstrained
        ));
        assert!(matches!(
            bearer_constraint(&carried(carrier, "opaque-token"), &carriers()),
            SenderConstraint::Unconstrained
        ));
    }
}

#[test]
fn with_an_authorization_server_a_dpop_bound_bearer_is_refused() {
    let bound = jwt(json::json!({ "sub": "a", "cnf": { "jkt": "abc" } }));
    for carrier in ["authorization", "x-api-key"] {
        assert!(
            matches!(
                bearer_constraint(&carried(carrier, &bound), &carriers()),
                SenderConstraint::Refused(_)
            ),
            "bound token refused through {carrier}"
        );
        assert!(matches!(
            bearer_constraint(&carried(carrier, &bound), &carriers()),
            SenderConstraint::Refused(Refusal::BoundBearer)
        ));
    }
}

#[test]
fn without_an_authorization_server_a_dpop_bound_bearer_is_refused() {
    // The bearer judgement no longer depends on the deployment: a bound token is bound.
    let bound = jwt(json::json!({ "sub": "a", "cnf": { "jkt": "abc" } }));
    for carrier in ["authorization", "x-api-key"] {
        assert!(
            matches!(
                bearer_constraint(&carried(carrier, &bound), &carriers()),
                SenderConstraint::Refused(Refusal::BoundBearer)
            ),
            "a bound token is refused through {carrier} even with no authorization server"
        );
    }
    assert_eq!(
        Refusal::BoundBearer.description(true),
        UNVERIFIABLE_DESCRIPTION,
        "with no authorization server the caller is told to present an unbound token"
    );
}

#[test]
fn the_bound_bearer_constraint_applies_before_exchange() {
    let bound = jwt(json::json!({ "sub": "a", "cnf": { "jkt": "abc" } }));
    assert!(matches!(
        bearer_constraint(&carried("authorization", &bound), &carriers()),
        SenderConstraint::Refused(_)
    ));
    assert!(matches!(
        bearer_constraint(&carried("authorization", &bound), &carriers()),
        SenderConstraint::Refused(Refusal::BoundBearer)
    ));
    let unbound = jwt(json::json!({ "sub": "a" }));
    assert!(matches!(
        bearer_constraint(&carried("authorization", &unbound), &carriers()),
        SenderConstraint::Unconstrained
    ));
}

#[test]
fn without_an_authorization_server_exchange_bearer_constraints_are_refused() {
    let bound = jwt(json::json!({ "sub": "a", "cnf": { "jkt": "abc" } }));
    let unbound = jwt(json::json!({ "sub": "a" }));
    assert!(
        matches!(
            bearer_constraint(&carried("authorization", &bound), &carriers()),
            SenderConstraint::Refused(Refusal::BoundBearer)
        ),
        "a bound token is refused before the exchange with no authorization server"
    );
    assert!(
        matches!(
            bearer_constraint(&carried("authorization", &unbound), &carriers()),
            SenderConstraint::Unconstrained
        ),
        "the actual chain is still responsible for authenticating an unbound token"
    );
}

#[test]
fn a_bound_token_cannot_hide_behind_another_carrier_or_occurrence() {
    let bound = jwt(json::json!({ "sub": "a", "cnf": { "jkt": "abc" } }));
    let unbound = jwt(json::json!({ "sub": "a" }));
    let behind_bearer = format!("Bearer {unbound}");
    for headers in [
        presenting(&[("authorization", &behind_bearer), ("x-api-key", &bound)]),
        presenting(&[("x-api-key", &unbound), ("x-api-key", &bound)]),
    ] {
        assert!(matches!(
            bearer_constraint(&headers, &carriers()),
            SenderConstraint::Refused(Refusal::BoundBearer)
        ));
    }
    // Authorization is read as a bearer even when it is not a configured carrier.
    assert!(matches!(
        bearer_constraint(
            &carried("authorization", &bound),
            &[axum::http::HeaderName::from_static("x-api-key")]
        ),
        SenderConstraint::Refused(Refusal::BoundBearer)
    ));
    // A DPoP-scheme presentation is not a bearer; judge_method decides it before this runs.
    assert!(matches!(
        bearer_constraint(
            &presenting(&[("authorization", &format!("DPoP {bound}"))]),
            &carriers()
        ),
        SenderConstraint::Unconstrained
    ));
}

#[test]
fn every_refusal_reason_explains_itself() {
    assert_eq!(
        Refusal::ProofFailed.description(false),
        PROOF_FAILED_DESCRIPTION
    );
    assert_eq!(
        Refusal::BoundBearer.description(false),
        BOUND_BEARER_DESCRIPTION
    );
    for no_authorization_server in [false, true] {
        assert_eq!(
            Refusal::Unverifiable.description(no_authorization_server),
            UNVERIFIABLE_DESCRIPTION
        );
    }
    assert_eq!(
        [
            Refusal::ProofFailed.as_str(),
            Refusal::BoundBearer.as_str(),
            Refusal::Unverifiable.as_str()
        ],
        ["proof_failed", "bound_bearer", "unverifiable"]
    );
}

#[derive(Clone, Default)]
struct Buf(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Buf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_bound_line_session_credential_is_refused_and_recorded() {
    let buf = Buf::default();
    let writer = buf.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_target(false)
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .finish();
    let bound = jwt(json::json!({ "sub": "a", "cnf": { "jkt": {} } }));
    let unbound = jwt(json::json!({ "sub": "a" }));
    let (refused, admitted) = tracing::subscriber::with_default(subscriber, || {
        tracing::callsite::rebuild_interest_cache();
        (
            refuse_bound_session(&bound, true),
            refuse_bound_session(&unbound, true),
        )
    });
    assert!(refused && !admitted);
    let text = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    assert_eq!(text.lines().count(), 1, "{text:?}");
    for field in [
        "diag=BUSBAR-4032",
        "surface=session",
        "reason=unverifiable",
        "no_authorization_server=true",
    ] {
        assert!(text.contains(field), "{field} in {text:?}");
    }
    assert!(!text.contains(&bound), "the token is never recorded");
}
