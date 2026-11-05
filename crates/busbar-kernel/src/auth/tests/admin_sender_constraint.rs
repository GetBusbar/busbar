use super::*;
use base64::Engine as _;

fn jwt(cnf: serde_json::Value) -> String {
    format!(
        "e30.{}.signature",
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::json!({"cnf": cnf}).to_string())
    )
}

#[test]
fn every_admin_bearer_occurrence_requires_its_sender_proof() {
    for confirmation in [
        serde_json::json!({"jkt": "key-thumbprint"}),
        serde_json::json!({"jkt": ""}),
        serde_json::json!({"jkt": null}),
        serde_json::json!({"jkt": 12}),
    ] {
        let token = jwt(confirmation);
        for carrier in ["authorization", "x-admin-token", "x-provider-token"] {
            let mut headers = HeaderMap::new();
            let name = HeaderName::from_bytes(carrier.as_bytes()).unwrap();
            headers.append(name.clone(), "opaque-first-occurrence".parse().unwrap());
            let value = if carrier == "authorization" {
                format!("bEaReR {token}")
            } else {
                token.clone()
            };
            headers.append(name, value.parse().unwrap());
            headers.insert(
                "dpop",
                "unverified-proof-does-not-authorize".parse().unwrap(),
            );
            assert!(downgraded_in(&headers, &[carrier.to_owned()]), "{carrier}");
        }
    }
}

#[test]
fn opaque_service_bearers_and_unbound_jwts_are_not_sender_downgrades() {
    for token in [
        "opaque-service-token".to_owned(),
        jwt(serde_json::json!({})),
    ] {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, format!("Bearer {token}").parse().unwrap());
        headers.insert("x-admin-token", token.parse().unwrap());
        assert!(!downgraded_in(
            &headers,
            &["authorization".into(), "x-admin-token".into()]
        ));
    }
}

#[test]
fn explicit_dpop_presentations_remain_the_verifying_providers_responsibility() {
    let token = jwt(serde_json::json!({"jkt": "key-thumbprint"}));
    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, format!("DPoP {token}").parse().unwrap());
    // This guard does not identify or authorize that presentation, with or without a proof.
    assert!(!downgraded_in(&headers, &["authorization".into()]));
    headers.insert("x-admin-token", token.parse().unwrap());
    assert!(downgraded_in(
        &headers,
        &["authorization".into(), "x-admin-token".into()]
    ));
}
