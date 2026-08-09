// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/plugin-abi/src/auth.rs`.

use super::*;

fn sample_identity() -> Identity {
    Identity {
        sub: "oidc:alice@contoso.com".into(),
        groups: vec!["engineering".into(), "sre".into()],
        name: Some("Alice".into()),
        ttl_secs: Some(300),
    }
}

#[test]
fn request_response_json_roundtrip() {
    let reqs = vec![
        AuthRequest::Name,
        AuthRequest::Cacheable,
        AuthRequest::Authenticate {
            credential: String::new(),
        },
        AuthRequest::Authenticate {
            credential: "ey.jwt.token".into(),
        },
    ];
    for r in reqs {
        let j = serde_json::to_vec(&r).unwrap();
        let back: AuthRequest = serde_json::from_slice(&j).unwrap();
        assert_eq!(serde_json::to_vec(&back).unwrap(), j);
    }

    let resp = AuthResponse::Identity(sample_identity());
    let j = serde_json::to_vec(&resp).unwrap();
    match serde_json::from_slice::<AuthResponse>(&j).unwrap() {
        AuthResponse::Identity(i) => assert_eq!(i, sample_identity()),
        other => panic!("wrong variant: {other:?}"),
    }
}

/// The identity-only guarantee is STRUCTURAL: an extra field (a smuggled policy/scope) is
/// REJECTED by `deny_unknown_fields`, never ignored.
#[test]
fn identity_rejects_unknown_fields() {
    let rogue = r#"{"sub":"x","groups":[],"name":null,"ttl_secs":null,"admin_scope":"full"}"#;
    assert!(
        serde_json::from_str::<Identity>(rogue).is_err(),
        "a plugin smuggling a policy field must be rejected, not silently accepted"
    );
}

/// Identity <-> Principal is lossless (the seam the auth chain consumes; groups ↔ roles).
#[test]
fn identity_principal_roundtrip() {
    let id = sample_identity();
    let p: Principal = id.clone().into();
    assert_eq!(p.id, id.sub);
    assert_eq!(p.roles, id.groups);
    let back: Identity = p.into();
    assert_eq!(back, id);
}

/// `BeginLoginRequest`/`AuthorizeUrl` round-trip, and the begin request STRUCTURALLY carries no
/// secret field (the confidential-client secret never crosses on the begin path).
#[test]
fn begin_login_roundtrip_no_client_secret() {
    let req = AuthRequest::BeginLogin(BeginLoginRequest {
        redirect_uri: "https://busbar.example/auth/token".into(),
        state: "state-123".into(),
        code_challenge: "chal".into(),
        nonce: Some("nonce".into()),
        scopes: vec!["openid".into(), "email".into()],
    });
    let j = serde_json::to_vec(&req).unwrap();
    let back: AuthRequest = serde_json::from_slice(&j).unwrap();
    assert_eq!(serde_json::to_vec(&back).unwrap(), j);

    // No secret field anywhere in the serialized begin request.
    let s = String::from_utf8(j).unwrap();
    assert!(
        !s.contains("client_secret") && !s.contains("secret"),
        "begin request must carry no secret: {s}"
    );

    let resp = AuthResponse::AuthorizeUrl("https://idp/authorize?state=state-123".into());
    let j = serde_json::to_vec(&resp).unwrap();
    assert!(matches!(
        serde_json::from_slice::<AuthResponse>(&j).unwrap(),
        AuthResponse::AuthorizeUrl(_)
    ));
}

/// `CompleteLoginRequest` round-trips for both the OAuth-code shape and the generic `submitted`
/// credential map (which subsumed the old ad-hoc username/password), with `token_response`
/// present and absent.
#[test]
fn complete_login_oauth_and_credential_shapes() {
    let oauth = CompleteLoginRequest {
        code: Some("authcode".into()),
        redirect_uri: Some("https://busbar.example/auth/token".into()),
        code_verifier: Some("verifier".into()),
        ..Default::default()
    };
    let cred = CompleteLoginRequest {
        submitted: vec![
            ("username".into(), "alice".into()),
            ("password".into(), "pw".into()),
        ],
        ..Default::default()
    };
    let with_resp = CompleteLoginRequest {
        code: Some("authcode".into()),
        token_response: Some(HttpResponse {
            status: 200,
            body: r#"{"id_token":"ey.."}"#.into(),
        }),
        ..Default::default()
    };
    for c in [oauth, cred, with_resp] {
        let req = AuthRequest::CompleteLogin(c.clone());
        let j = serde_json::to_vec(&req).unwrap();
        match serde_json::from_slice::<AuthRequest>(&j).unwrap() {
            AuthRequest::CompleteLogin(back) => assert_eq!(back, c),
            other => panic!("wrong variant: {other:?}"),
        }
    }
}

/// The credential-flow wire additions round-trip: `LoginKind` (the load-time classification), a
/// `Prompt(LoginForm)` begin result, and the `submitted` map crossing engine↔wire with Redaction
/// re-applied on the engine side.
#[test]
fn credential_flow_wire_roundtrips() {
    // LoginKind op + response.
    let j = serde_json::to_vec(&AuthRequest::LoginKind).unwrap();
    assert!(matches!(
        serde_json::from_slice::<AuthRequest>(&j).unwrap(),
        AuthRequest::LoginKind
    ));
    for k in [LoginKind::Redirect, LoginKind::Credential] {
        let j = serde_json::to_vec(&AuthResponse::LoginKind(k)).unwrap();
        match serde_json::from_slice::<AuthResponse>(&j).unwrap() {
            AuthResponse::LoginKind(back) => assert_eq!(back, k),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    // Prompt(LoginForm) begin result.
    let form = LoginForm {
        fields: vec![
            LoginField {
                name: "username".into(),
                label: "Username".into(),
                kind: FieldKind::Text,
                required: true,
            },
            LoginField {
                name: "password".into(),
                label: "Password".into(),
                kind: FieldKind::Password,
                required: true,
            },
        ],
    };
    let j = serde_json::to_vec(&AuthResponse::Prompt(form.clone())).unwrap();
    match serde_json::from_slice::<AuthResponse>(&j).unwrap() {
        AuthResponse::Prompt(back) => assert_eq!(back, form),
        other => panic!("wrong variant: {other:?}"),
    }
    // Prompt survives the engine LoginOutcome round-trip both directions.
    let outcome = AuthResponse::Prompt(form.clone()).into_login_outcome();
    assert!(matches!(outcome, LoginOutcome::Prompt(_)));
    assert!(matches!(
        AuthResponse::from_login_outcome(outcome),
        AuthResponse::Prompt(_)
    ));

    // The submitted map: engine (Redacted) → wire (plain) → engine (Redacted) is lossless, and
    // the Redacted values never reveal themselves in Debug.
    let eng = CompleteLogin {
        submitted: vec![
            ("username".into(), Redacted::new("alice".to_string())),
            ("password".into(), Redacted::new("s3cr3t".to_string())),
        ],
        ..Default::default()
    };
    let wire: CompleteLoginRequest = eng.clone().into();
    assert_eq!(wire.submitted[1].1, "s3cr3t"); // plaintext crosses at this documented boundary
    let back: CompleteLogin = wire.into();
    assert_eq!(back.submitted[0].1.expose_secret(), "alice");
    assert_eq!(back.submitted[1].1.expose_secret(), "s3cr3t");
    assert!(
        !format!("{back:?}").contains("s3cr3t"),
        "engine side must redact"
    );
}

/// `TokenExchange(HttpRequest)` / `HttpResponse` round-trip; the secret field names a KEY, not a
/// value.
#[test]
fn token_exchange_and_http_response_roundtrip() {
    let hop = HttpRequest {
        method: "POST".into(),
        url: "https://idp/token".into(),
        form: vec![
            ("grant_type".into(), "authorization_code".into()),
            ("code".into(), "authcode".into()),
            ("code_verifier".into(), "verifier".into()),
            ("client_secret".into(), String::new()),
        ],
        secret_form_field: Some("client_secret".into()),
        headers: vec![("X-Trace".into(), "1".into())],
    };
    let resp = AuthResponse::TokenExchange(hop.clone());
    let j = serde_json::to_vec(&resp).unwrap();
    match serde_json::from_slice::<AuthResponse>(&j).unwrap() {
        AuthResponse::TokenExchange(back) => assert_eq!(back, hop),
        other => panic!("wrong variant: {other:?}"),
    }

    let hr = HttpResponse {
        status: 200,
        body: "{}".into(),
    };
    let j = serde_json::to_vec(&hr).unwrap();
    assert_eq!(serde_json::from_slice::<HttpResponse>(&j).unwrap(), hr);
}

#[test]
fn from_outcome_maps_verdicts() {
    let mut p = Principal::from_id("oidc:bob");
    p.roles = vec!["g".into()];
    match AuthResponse::from_outcome(AuthOutcome::Identify(p)) {
        AuthResponse::Identity(i) => assert_eq!(i.sub, "oidc:bob"),
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        AuthResponse::from_outcome(AuthOutcome::Reject),
        AuthResponse::Reject
    ));
    assert!(matches!(
        AuthResponse::from_outcome(AuthOutcome::Pass),
        AuthResponse::Pass
    ));
}
