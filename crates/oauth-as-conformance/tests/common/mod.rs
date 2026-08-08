//! Shared black-box plumbing. The AS is reached ONLY through `OAUTH_AS_BASE_URL`; every
//! endpoint beyond the RFC 8414 well-known document is discovered from the metadata itself,
//! so these tests also prove the advertised endpoints match reality.
#![allow(dead_code)]

use serde_json::Value;

/// Seeded fixtures the AS must provide under `OAUTH_AS_CONFORMANCE_SEED=1`.
/// See the crate-level contract in `src/lib.rs`.
pub const PUBLIC_CLIENT_ID: &str = "conformance-public";
pub const PUBLIC_REDIRECT_URI: &str = "http://127.0.0.1:8917/cb";
pub const CONFIDENTIAL_CLIENT_ID: &str = "conformance-confidential";
pub const CONFIDENTIAL_CLIENT_SECRET: &str = "conformance-secret-0123456789abcdef";

/// Base URL of the AS under test. FAILS LOUDLY when absent: this harness must never skip
/// silently and report green for an AS that was never contacted.
pub fn base_url() -> String {
    match std::env::var("OAUTH_AS_BASE_URL") {
        Ok(u) if !u.trim().is_empty() => u.trim_end_matches('/').to_string(),
        _ => panic!(
            "OAUTH_AS_BASE_URL is not set. The OAuth AS under test is NOT present or NOT \
             running. This conformance suite refuses to pass vacuously; launch the AS via \
             scripts/oauth-conformance.sh (which starts crates/oauth-as and exports the URL) \
             or export OAUTH_AS_BASE_URL yourself."
        ),
    }
}

/// An HTTP client that NEVER follows redirects: authorization responses are 302s whose
/// Location we must inspect, and a client that silently follows them can hide violations.
pub fn no_redirect_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("reqwest client")
}

/// Fetch and parse the RFC 8414 metadata document. Panics with the violation list when the
/// document itself is nonconformant, since every later test depends on it.
pub async fn metadata(client: &reqwest::Client) -> Value {
    let base = base_url();
    let url = format!("{base}/.well-known/oauth-authorization-server");
    let resp = client
        .get(&url)
        .send()
        .await
        .unwrap_or_else(|e| panic!("GET {url} failed: {e}; is the AS running?"));
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "RFC 8414 s3.1: the well-known metadata document must return 200"
    );
    let body: Value = resp
        .json()
        .await
        .expect("metadata must be JSON (RFC 8414 s3.1)");
    let violations = oauth_as_conformance::validate_as_metadata(&body, &base);
    assert!(
        violations.is_empty(),
        "RFC 8414 metadata violations: {violations:#?}"
    );
    body
}

pub fn endpoint(meta: &Value, key: &str) -> String {
    meta.get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("metadata missing {key}, which validate_as_metadata requires"))
        .to_string()
}

/// Assert an HTTP error response carries a conformant RFC 6749 s5.2 JSON body and return it.
pub async fn assert_error_body(resp: reqwest::Response, context: &str) -> Value {
    let status = resp.status();
    assert!(
        status == reqwest::StatusCode::BAD_REQUEST || status == reqwest::StatusCode::UNAUTHORIZED,
        "{context}: error responses must be 400 (or 401 for invalid_client), got {status} \
         (RFC 6749 s5.2)"
    );
    let body: Value = resp
        .json()
        .await
        .unwrap_or_else(|e| panic!("{context}: error body must be JSON (RFC 6749 s5.2): {e}"));
    let violations = oauth_as_conformance::validate_error_body(&body);
    assert!(
        violations.is_empty(),
        "{context}: error-body violations: {violations:#?}"
    );
    body
}

/// Run one auto-approved authorization-code round (the seeded-AS contract) and return the
/// issued code. `challenge` is a PKCE S256 code_challenge; `state` is echoed and checked.
pub async fn obtain_auth_code(
    client: &reqwest::Client,
    authorization_endpoint: &str,
    challenge: &str,
    state: &str,
) -> String {
    let url = reqwest::Url::parse_with_params(
        authorization_endpoint,
        &[
            ("response_type", "code"),
            ("client_id", PUBLIC_CLIENT_ID),
            ("redirect_uri", PUBLIC_REDIRECT_URI),
            ("state", state),
            ("code_challenge", challenge),
            ("code_challenge_method", "S256"),
        ],
    )
    .expect("authorize URL");
    let resp = client.get(url).send().await.expect("GET authorize");
    assert!(
        resp.status().is_redirection(),
        "seeded AS must auto-approve a valid authorization request with a 302 redirect \
         (conformance contract; RFC 6749 s4.1.2), got {}",
        resp.status()
    );
    let location = resp
        .headers()
        .get(reqwest::header::LOCATION)
        .expect("302 without Location header")
        .to_str()
        .expect("Location must be ASCII")
        .to_string();
    assert!(
        location.starts_with(PUBLIC_REDIRECT_URI),
        "redirect must target the registered redirect_uri exactly (OAuth 2.1 s4.1.3); got \
         {location}"
    );
    let redirect = reqwest::Url::parse(&location).expect("Location must be a valid URL");
    let mut code = None;
    let mut got_state = None;
    for (k, v) in redirect.query_pairs() {
        match k.as_ref() {
            "code" => code = Some(v.into_owned()),
            "state" => got_state = Some(v.into_owned()),
            _ => {}
        }
    }
    assert_eq!(
        got_state.as_deref(),
        Some(state),
        "state must be echoed back unmodified (RFC 6749 s4.1.2)"
    );
    code.expect("authorization response missing code parameter (RFC 6749 s4.1.2)")
}
