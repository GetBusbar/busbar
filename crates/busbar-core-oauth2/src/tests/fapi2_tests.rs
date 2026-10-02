// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE FAPI 2.0 SECURITY PROFILE POSTURE (`oauth_as.fapi2: true`), driven over a real socket.
//!
//! The posture is the one the OpenID Foundation's `fapi2-security-profile-final-test-plan` runs
//! under `openid=plain_oauth`, `client_auth_type=private_key_jwt`, `sender_constrain=dpop`,
//! `fapi_profile=plain_fapi`. Each test below is one requirement of that profile on an
//! authorization server, or one refusal it demands, with the clause it answers to:
//!
//! | requirement | clause | test |
//! |---|---|---|
//! | the metadata names PAR, DPoP, `private_key_jwt`, S256, `iss` | RFC 8414 s2, RFC 9126 s5, RFC 9449 s5.1, RFC 9207 s3 | [`the_metadata_advertises_the_profile`] |
//! | the plain posture advertises none of it | (the posture is opt-in) | [`the_plain_posture_advertises_none_of_the_profile`] |
//! | PAR, `private_key_jwt`, DPoP-bound code and token, `iss` | RFC 9126, RFC 7523, RFC 9449, RFC 9207, FAPI2 s5.3.2.1-9 | [`the_profile_flow_mints_a_sender_constrained_token`] |
//! | loading the page does not spend the `request_uri` | FAPI2 s5.3.2.2 NOTE 3 | [`showing_the_consent_screen_does_not_spend_the_pushed_request`] |
//! | the user can refuse | RFC 6749 s4.1.2.1 `access_denied` | [`the_operator_can_deny_a_pushed_request`] |
//! | a request not pushed is refused | FAPI2 s5.3.2.2-3, RFC 9126 s4 | [`an_authorization_request_not_pushed_is_refused`] |
//! | a `request_uri` is single use and bound to its client | RFC 9126 s4, s7.3, s2.2 | [`a_request_uri_is_single_use_and_bound_to_its_client`] |
//! | the push refusals: no client auth, wrong `aud`, no PKCE, `plain` PKCE, no `redirect_uri`, foreign key, replayed assertion | FAPI2 s5.3.2.1-8, s5.3.3.1-5, s5.3.2.2-6, RFC 7636, RFC 7523 s3 | [`the_pushed_authorization_endpoint_refuses_what_the_profile_forbids`] |
//! | the token refusals: no proof, foreign proof key, wrong `htu`, wrong verifier, code reuse | FAPI2 s5.3.4-2, RFC 9449 s4.3 s10, RFC 7636 s4.6, RFC 6749 s4.1.2 | [`the_token_endpoint_refuses_what_the_profile_forbids`] |

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use base64::Engine as _;
use oauth_as::client::{Client, ClientAuth, ClientId};
use oauth_as::client_assertion::AssertionKeys;
use oauth_as::grant::GrantType;
use oauth_as::jwt::{EcCurve, Jwk, JwsAlg};
use oauth_as::scope::ScopeSet;
use ring::signature::{EcdsaKeyPair, KeyPair as _, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde_json::{json, Value};

use busbar_kernel::oauth_as::config::OauthAsCfg;
use busbar_kernel::test_support::TestApp;

use crate::flow_tests::{location, path_of, percent_decode, query_param, send, Jar};
use crate::testkit::{oauth_as_plane, TestAppOauthExt};

/// The client's redirect URI. Never fetched: every flow ends at the redirect that carries the code.
const REDIRECT_URI: &str = "http://127.0.0.1:9999/cb";
/// RFC 7636 appendix B's verifier and challenge, so PKCE runs against a published vector.
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const SCOPE: &str = "read";
const CLIENT_ID: &str = "fapi-client";
const OTHER_CLIENT_ID: &str = "fapi-client-2";
/// RFC 7523 s2.2.
const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Every `jti` this file mints is distinct, so no refusal below is a replay by accident.
static JTI: AtomicU64 = AtomicU64::new(0);

fn jti() -> String {
    format!("jti-{}-{}", now(), JTI.fetch_add(1, Ordering::Relaxed))
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after the epoch")
        .as_secs()
}

// ── the client's keys ────────────────────────────────────────────────────────────────────────────

/// One ES256 key: a client's `private_key_jwt` key, or a DPoP key. Signed with `ring`, which the
/// server under test verifies with as well — but the JOSE framing is assembled here by hand from
/// the RFCs, so a server that misread RFC 7515 would not be agreeing with itself.
struct Key {
    pair: EcdsaKeyPair,
    kid: &'static str,
}

impl Key {
    fn new(kid: &'static str) -> Self {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .expect("generate a P-256 key");
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .expect("load the key just generated");
        Self { pair, kid }
    }

    fn coordinates(&self) -> (String, String) {
        let point = self.pair.public_key().as_ref();
        (B64.encode(&point[1..33]), B64.encode(&point[33..65]))
    }

    /// The public half as the client registers it.
    fn jwk(&self) -> Jwk {
        let (x, y) = self.coordinates();
        Jwk::Ec {
            crv: EcCurve::P256,
            x,
            y,
            kid: Some(self.kid.to_string()),
        }
    }

    /// The public half as a DPoP proof header carries it (RFC 9449 s4.2 `jwk`).
    fn public_json(&self) -> Value {
        let (x, y) = self.coordinates();
        json!({ "kty": "EC", "crv": "P-256", "x": x, "y": y })
    }

    /// RFC 7638 thumbprint: SHA-256 over the required members in lexicographic order.
    fn thumbprint(&self) -> String {
        let (x, y) = self.coordinates();
        let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
        B64.encode(ring::digest::digest(&ring::digest::SHA256, canonical.as_bytes()).as_ref())
    }

    /// RFC 7515 compact serialization, ES256.
    fn sign(&self, header: &Value, claims: &Value) -> String {
        let input = format!(
            "{}.{}",
            B64.encode(header.to_string()),
            B64.encode(claims.to_string())
        );
        let sig = self
            .pair
            .sign(&ring::rand::SystemRandom::new(), input.as_bytes())
            .expect("sign");
        format!("{input}.{}", B64.encode(sig.as_ref()))
    }

    /// An RFC 7523 client authentication assertion naming `aud`.
    fn assertion(&self, client_id: &str, aud: Value) -> String {
        self.sign(
            &json!({ "alg": "ES256", "kid": self.kid }),
            &json!({
                "iss": client_id,
                "sub": client_id,
                "aud": aud,
                "jti": jti(),
                "iat": now(),
                "exp": now() + 60,
            }),
        )
    }

    /// An RFC 9449 DPoP proof for `htm` `htu`.
    fn proof(&self, htm: &str, htu: &str) -> String {
        self.sign(
            &json!({ "typ": "dpop+jwt", "alg": "ES256", "jwk": self.public_json() }),
            &json!({ "jti": jti(), "htm": htm, "htu": htu, "iat": now() }),
        )
    }
}

// ── the subject ──────────────────────────────────────────────────────────────────────────────────

/// A served `fapi2: true` deployment with two `private_key_jwt` clients, each with its own key.
struct Subject {
    origin: String,
    client: reqwest::Client,
    /// `CLIENT_ID`'s registered key.
    key: Key,
    /// `OTHER_CLIENT_ID`'s registered key.
    other: Key,
}

async fn serve(fapi2: bool) -> Subject {
    busbar_kernel::metrics::init();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let origin = format!("http://{}", listener.local_addr().expect("addr"));
    let cfg = OauthAsCfg {
        issuer: origin.clone(),
        signing_key: None,
        key_id: None,
        default_grant: vec![SCOPE.to_string()],
        access_token_ttl_secs: None,
        fapi2,
    };
    // The open admin posture, as in `flow_tests::serve`: the consent screen's `RouteAuth::Admin`
    // is not the property under test here.
    let app = TestApp::new()
        .admin_chain(Vec::new())
        .oauth_as(&cfg)
        .build();
    let (key, other) = (Key::new("fapi-client-key"), Key::new("fapi-client-2-key"));
    let server = oauth_as_plane(&app).expect("configured").server().clone();
    for (client_id, key) in [(CLIENT_ID, &key), (OTHER_CLIENT_ID, &other)] {
        let scopes = ScopeSet::from_tokens([SCOPE]).expect("scope");
        server
            .register_client(Client {
                client_id: ClientId::new(client_id),
                auth: ClientAuth::ConfidentialAssertion {
                    keys: AssertionKeys::PublicKeys {
                        alg: JwsAlg::Es256,
                        keys: vec![key.jwk()],
                    },
                },
                grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
                redirect_uris: vec![REDIRECT_URI.to_string()],
                allowed_scopes: scopes.clone(),
                default_scopes: scopes,
                name: Some(client_id.to_string()),
                registration: None,
            })
            .await
            .expect("register a private_key_jwt client");
    }
    let router = busbar_kernel::build_router(Arc::clone(&app));
    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("serve");
    });
    Subject {
        origin,
        client: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("client"),
        key,
        other,
    }
}

/// A form POST with an optional DPoP proof: `(status, the JSON body or Null)`.
async fn post(
    s: &Subject,
    path: &str,
    form: &[(&str, String)],
    dpop: Option<String>,
) -> (u16, Value) {
    let mut req = s.client.post(format!("{}{path}", s.origin)).form(form);
    if let Some(proof) = dpop {
        req = req.header("DPoP", proof);
    }
    let resp = req.send().await.expect("request");
    let status = resp.status().as_u16();
    let body = resp.text().await.expect("body");
    (status, serde_json::from_str(&body).unwrap_or(Value::Null))
}

/// The pushed authorization request a conforming FAPI 2.0 client sends for `client_id`, signed by
/// `key`. Tests that probe a refusal edit this list, so every refusal differs from an accepted push
/// by exactly the one parameter it is about.
fn push_form(s: &Subject, client_id: &str, key: &Key) -> Vec<(&'static str, String)> {
    vec![
        ("response_type", "code".to_string()),
        ("client_id", client_id.to_string()),
        ("redirect_uri", REDIRECT_URI.to_string()),
        ("scope", SCOPE.to_string()),
        ("state", "s1".to_string()),
        ("code_challenge", CHALLENGE.to_string()),
        ("code_challenge_method", "S256".to_string()),
        ("client_assertion_type", ASSERTION_TYPE.to_string()),
        (
            "client_assertion",
            key.assertion(client_id, json!(s.origin)),
        ),
    ]
}

/// Push `form` with a DPoP proof from `dpop`, and hand back the `request_uri`.
async fn push(s: &Subject, form: &[(&str, String)], dpop: &Key) -> String {
    let proof = dpop.proof("POST", &format!("{}/par", s.origin));
    let (status, body) = post(s, "/par", form, Some(proof)).await;
    assert_eq!(status, 201, "RFC 9126 s2.2: an accepted push is 201: {body}");
    let expires_in = body["expires_in"].as_u64().expect("expires_in");
    assert!(
        expires_in > 0 && expires_in <= 600,
        "FAPI2 s5.3.2.2-12: a request_uri lives under 600 seconds, got {expires_in}"
    );
    body["request_uri"]
        .as_str()
        .expect("request_uri")
        .to_string()
}

/// Every byte outside RFC 3986 unreserved, percent-encoded.
fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

fn authorize_url(s: &Subject, client_id: &str, request_uri: &str) -> String {
    format!(
        "{}/authorize?client_id={client_id}&request_uri={}",
        s.origin,
        enc(request_uri)
    )
}

/// The browser half for a pushed request: `/authorize` sends it to the consent screen, the screen
/// renders, the operator answers `decision`, and the replayed `/authorize` answers. Returns where
/// that last answer sends the browser.
async fn consent(s: &Subject, jar: &mut Jar, authorize: &str, decision: &str) -> String {
    let (status, headers, body) =
        send(&s.client, jar, reqwest::Method::GET, authorize, None).await;
    assert_eq!(
        status, 302,
        "an undecided pushed request goes to consent: {body}"
    );
    let screen = location(&headers, &s.origin);
    assert_eq!(path_of(&screen), "/consent", "{screen}");
    let (status, _, page) = send(&s.client, jar, reqwest::Method::GET, &screen, None).await;
    assert_eq!(status, 200, "the consent screen renders: {page}");
    let return_to = percent_decode(&query_param(&screen, "return").expect("return"));
    let (status, headers, body) = send(
        &s.client,
        jar,
        reqwest::Method::POST,
        &format!("{}/consent", s.origin),
        Some(&[("return", return_to.as_str()), ("decision", decision)]),
    )
    .await;
    assert_eq!(status, 302, "the answer redirects back: {body}");
    let back = location(&headers, &s.origin);
    assert_eq!(path_of(&back), "/authorize");
    let (status, headers, body) = send(&s.client, jar, reqwest::Method::GET, &back, None).await;
    assert_eq!(status, 302, "a decided request redirects to the client: {body}");
    location(&headers, &s.origin)
}

/// PAR, consent, approve: the code.
async fn code_for(s: &Subject, dpop: &Key) -> String {
    let request_uri = push(s, &push_form(s, CLIENT_ID, &s.key), dpop).await;
    let mut jar = Jar::new(false);
    let redirect = consent(
        s,
        &mut jar,
        &authorize_url(s, CLIENT_ID, &request_uri),
        "approve",
    )
    .await;
    assert!(redirect.starts_with(REDIRECT_URI), "{redirect}");
    query_param(&redirect, "code").expect("a code")
}

/// The token request a conforming client sends for `code`.
fn token_form(s: &Subject, code: &str) -> Vec<(&'static str, String)> {
    vec![
        ("grant_type", "authorization_code".to_string()),
        ("code", code.to_string()),
        ("redirect_uri", REDIRECT_URI.to_string()),
        ("code_verifier", VERIFIER.to_string()),
        ("client_id", CLIENT_ID.to_string()),
        ("client_assertion_type", ASSERTION_TYPE.to_string()),
        (
            "client_assertion",
            s.key.assertion(CLIENT_ID, json!(s.origin)),
        ),
    ]
}

fn with(form: &[(&'static str, String)], name: &str, value: Value) -> Vec<(&'static str, String)> {
    form.iter()
        .filter_map(|(k, v)| {
            if *k != name {
                return Some((*k, v.clone()));
            }
            match &value {
                Value::Null => None,
                Value::String(s) => Some((*k, s.clone())),
                other => Some((*k, other.to_string())),
            }
        })
        .collect()
}

fn payload(jwt: &str) -> Value {
    let part = jwt.split('.').nth(1).expect("a compact JWS");
    serde_json::from_slice(&B64.decode(part).expect("base64url")).expect("JSON claims")
}

async fn metadata(s: &Subject) -> Value {
    let resp = s
        .client
        .get(format!(
            "{}/.well-known/oauth-authorization-server",
            s.origin
        ))
        .send()
        .await
        .expect("metadata");
    assert_eq!(resp.status(), 200);
    resp.json().await.expect("JSON metadata")
}

// ── the tests ────────────────────────────────────────────────────────────────────────────────────

/// RFC 8414 s2 as the profile reads it: the document names the PAR endpoint and makes it mandatory
/// (RFC 9126 s5), names the DPoP algorithms (RFC 9449 s5.1), offers `private_key_jwt` with the
/// FAPI algorithms only (FAPI2 s5.4.1: ES256/PS256, never RS256), S256 alone for PKCE, and the
/// RFC 9207 `iss` parameter.
#[tokio::test]
async fn the_metadata_advertises_the_profile() {
    let s = serve(true).await;
    let meta = metadata(&s).await;
    assert_eq!(
        meta["pushed_authorization_request_endpoint"],
        json!(format!("{}/par", s.origin))
    );
    assert_eq!(meta["require_pushed_authorization_requests"], json!(true));
    assert_eq!(meta["dpop_signing_alg_values_supported"], json!(["ES256"]));
    let methods = meta["token_endpoint_auth_methods_supported"]
        .as_array()
        .expect("methods");
    assert!(methods.contains(&json!("private_key_jwt")), "{meta}");
    let algs = meta["token_endpoint_auth_signing_alg_values_supported"]
        .as_array()
        .expect("assertion algorithms");
    assert!(algs.contains(&json!("ES256")), "{meta}");
    assert!(!algs.contains(&json!("RS256")), "FAPI2 s5.4.1 forbids RS256: {meta}");
    assert_eq!(meta["code_challenge_methods_supported"], json!(["S256"]));
    assert_eq!(
        meta["authorization_response_iss_parameter_supported"],
        json!(true)
    );
}

/// The posture is opt-in: a plain `oauth_as:` block advertises no PAR endpoint, no DPoP and no
/// assertion method, and serves no `/par`. (`signer_tests` pins the plain document's bytes.)
#[tokio::test]
async fn the_plain_posture_advertises_none_of_the_profile() {
    let s = serve(false).await;
    let meta = metadata(&s).await;
    for member in [
        "pushed_authorization_request_endpoint",
        "require_pushed_authorization_requests",
        "dpop_signing_alg_values_supported",
        "token_endpoint_auth_signing_alg_values_supported",
    ] {
        assert!(meta.get(member).is_none(), "`{member}` in {meta}");
    }
    assert_eq!(
        meta["token_endpoint_auth_methods_supported"],
        json!(["client_secret_basic", "client_secret_post", "none"])
    );
    let (status, _) = post(&s, "/par", &push_form(&s, CLIENT_ID, &s.key), None).await;
    assert_ne!(status, 201, "the plain posture serves no pushed authorization endpoint");
}

/// THE PROFILE, end to end: a `private_key_jwt` client pushes its request with a DPoP proof, the
/// operator approves, the code comes back with `iss` (RFC 9207 s2), and the code is redeemed —
/// with the same DPoP key — for a sender-constrained token (`token_type` DPoP, `cnf.jkt` the proof
/// key's RFC 7638 thumbprint). The refresh token is REUSED, not rotated (FAPI2 s5.3.2.1-9): it
/// redeems twice.
#[tokio::test]
async fn the_profile_flow_mints_a_sender_constrained_token() {
    let s = serve(true).await;
    let dpop = Key::new("dpop");
    let request_uri = push(&s, &push_form(&s, CLIENT_ID, &s.key), &dpop).await;
    let mut jar = Jar::new(false);
    let redirect = consent(
        &s,
        &mut jar,
        &authorize_url(&s, CLIENT_ID, &request_uri),
        "approve",
    )
    .await;
    assert!(redirect.starts_with(REDIRECT_URI), "{redirect}");
    assert_eq!(query_param(&redirect, "state").as_deref(), Some("s1"));
    assert_eq!(
        query_param(&redirect, "iss").map(|v| percent_decode(&v)),
        Some(s.origin.clone()),
        "RFC 9207 s2: the authorization response names its issuer"
    );
    let code = query_param(&redirect, "code").expect("a code");

    let proof = dpop.proof("POST", &format!("{}/token", s.origin));
    let (status, token) = post(&s, "/token", &token_form(&s, &code), Some(proof)).await;
    assert_eq!(status, 200, "{token}");
    assert_eq!(token["token_type"], json!("DPoP"), "RFC 9449 s5: {token}");
    let access = token["access_token"].as_str().expect("access_token");
    assert_eq!(
        payload(access)["cnf"]["jkt"],
        json!(dpop.thumbprint()),
        "RFC 9449 s6.1: the token is bound to the proof key"
    );

    let refresh = token["refresh_token"]
        .as_str()
        .expect("a refresh token")
        .to_string();
    for round in 1..=2 {
        let form = vec![
            ("grant_type", "refresh_token".to_string()),
            ("refresh_token", refresh.clone()),
            ("client_id", CLIENT_ID.to_string()),
            ("client_assertion_type", ASSERTION_TYPE.to_string()),
            (
                "client_assertion",
                s.key.assertion(CLIENT_ID, json!(s.origin)),
            ),
        ];
        let proof = dpop.proof("POST", &format!("{}/token", s.origin));
        let (status, body) = post(&s, "/token", &form, Some(proof)).await;
        assert_eq!(
            status, 200,
            "FAPI2 s5.3.2.1-9: the refresh token is not rotated, so redemption {round} succeeds: {body}"
        );
        assert_eq!(body["token_type"], json!("DPoP"));
    }
}

/// FAPI2 s5.3.2.2 NOTE 3: one-time use is enforced at the point of AUTHORIZATION, not at the point
/// of loading the page. Visiting `/authorize` twice before anyone answers leaves the pushed request
/// redeemable, and the second showing of the screen says it was shown before (`id="revisit"`).
#[tokio::test]
async fn showing_the_consent_screen_does_not_spend_the_pushed_request() {
    let s = serve(true).await;
    let dpop = Key::new("dpop");
    let request_uri = push(&s, &push_form(&s, CLIENT_ID, &s.key), &dpop).await;
    let authorize = authorize_url(&s, CLIENT_ID, &request_uri);
    let mut jar = Jar::new(false);
    for visit in 1..=2 {
        let (status, headers, body) =
            send(&s.client, &mut jar, reqwest::Method::GET, &authorize, None).await;
        assert_eq!(status, 302, "visit {visit}: {body}");
        let screen = location(&headers, &s.origin);
        let (status, _, page) =
            send(&s.client, &mut jar, reqwest::Method::GET, &screen, None).await;
        assert_eq!(status, 200, "visit {visit}: {page}");
        assert!(
            page.contains(&format!("<code>{SCOPE}</code>")),
            "the screen names the PUSHED scope, which is not in the URL: {page}"
        );
        assert_eq!(
            page.contains("id=\"revisit\""),
            visit == 2,
            "visit {visit}: only a repeat showing is marked: {page}"
        );
    }
    let redirect = consent(&s, &mut jar, &authorize, "approve").await;
    assert!(
        query_param(&redirect, "code").is_some(),
        "the twice-shown request still mints a code: {redirect}"
    );
}

/// RFC 6749 s4.1.2.1: the resource owner may refuse, and the client hears `access_denied` at its
/// redirect URI, with its `state` and (RFC 9207) the issuer.
#[tokio::test]
async fn the_operator_can_deny_a_pushed_request() {
    let s = serve(true).await;
    let dpop = Key::new("dpop");
    let request_uri = push(&s, &push_form(&s, CLIENT_ID, &s.key), &dpop).await;
    let mut jar = Jar::new(false);
    let redirect = consent(
        &s,
        &mut jar,
        &authorize_url(&s, CLIENT_ID, &request_uri),
        "deny",
    )
    .await;
    assert!(redirect.starts_with(REDIRECT_URI), "{redirect}");
    assert_eq!(
        query_param(&redirect, "error").as_deref(),
        Some("access_denied")
    );
    assert_eq!(query_param(&redirect, "state").as_deref(), Some("s1"));
    assert!(query_param(&redirect, "iss").is_some(), "{redirect}");
    assert!(query_param(&redirect, "code").is_none(), "{redirect}");
}

/// Assert `/authorize` refused with the HTML error page a browser can show (and the OIDF suite's
/// browser waits for), naming the RFC 6749 error code.
async fn assert_refused_with_a_page(s: &Subject, url: &str, code: &str) {
    let resp = s.client.get(url).send().await.expect("authorize");
    let status = resp.status().as_u16();
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let page = resp.text().await.expect("body");
    assert_eq!(status, 400, "{page}");
    assert!(content_type.starts_with("text/html"), "{content_type}: {page}");
    assert!(page.contains("Authorization error"), "{page}");
    assert!(page.contains(code), "the page names `{code}`: {page}");
}

/// FAPI2 s5.3.2.2-3 / RFC 9126 s4: authorization request data only via PAR. A plain query request
/// is refused, never sent to consent and never answered with a code.
#[tokio::test]
async fn an_authorization_request_not_pushed_is_refused() {
    let s = serve(true).await;
    let url = format!(
        "{}/authorize?response_type=code&client_id={CLIENT_ID}&redirect_uri={}&scope={SCOPE}\
         &state=s1&code_challenge={CHALLENGE}&code_challenge_method=S256",
        s.origin,
        enc(REDIRECT_URI)
    );
    assert_refused_with_a_page(&s, &url, "invalid_request").await;
}

/// RFC 9126 s4 / s7.3: a `request_uri` is single use, and s2.2: it is bound to the client that
/// pushed it. A redeemed handle, and another client's handle, are refused with the error page.
#[tokio::test]
async fn a_request_uri_is_single_use_and_bound_to_its_client() {
    let s = serve(true).await;
    let dpop = Key::new("dpop");

    let theirs = push(&s, &push_form(&s, CLIENT_ID, &s.key), &dpop).await;
    assert_refused_with_a_page(
        &s,
        &authorize_url(&s, OTHER_CLIENT_ID, &theirs),
        "invalid_request",
    )
    .await;

    let request_uri = push(&s, &push_form(&s, CLIENT_ID, &s.key), &dpop).await;
    let authorize = authorize_url(&s, CLIENT_ID, &request_uri);
    let mut jar = Jar::new(false);
    let redirect = consent(&s, &mut jar, &authorize, "approve").await;
    assert!(query_param(&redirect, "code").is_some(), "{redirect}");
    assert_refused_with_a_page(&s, &authorize, "invalid_request").await;
}

/// Assert a push was refused with `status` and one of `errors`.
async fn assert_push_refused(
    s: &Subject,
    form: &[(&str, String)],
    status: u16,
    errors: &[&str],
    why: &str,
) {
    let proof = Key::new("dpop").proof("POST", &format!("{}/par", s.origin));
    let (got, body) = post(s, "/par", form, Some(proof)).await;
    assert_eq!(got, status, "{why}: {body}");
    let error = body["error"].as_str().unwrap_or_default();
    assert!(errors.contains(&error), "{why}: `{error}` not in {errors:?}: {body}");
}

/// The pushed authorization endpoint's refusals, each one parameter away from an accepted push.
#[tokio::test]
async fn the_pushed_authorization_endpoint_refuses_what_the_profile_forbids() {
    let s = serve(true).await;
    let good = push_form(&s, CLIENT_ID, &s.key);
    let token_endpoint = format!("{}/token", s.origin);

    assert_push_refused(
        &s,
        &with(&with(&good, "client_assertion", Value::Null), "client_assertion_type", Value::Null),
        401,
        &["invalid_client"],
        "a confidential client that does not authenticate",
    )
    .await;
    assert_push_refused(
        &s,
        &with(
            &good,
            "client_assertion",
            json!(s.key.assertion(CLIENT_ID, json!(token_endpoint))),
        ),
        401,
        &["invalid_client"],
        "FAPI2 s5.3.2.1-8: the token endpoint URL is not the issuer",
    )
    .await;
    assert_push_refused(
        &s,
        &with(
            &good,
            "client_assertion",
            json!(s.key.assertion(CLIENT_ID, json!([s.origin, "https://other.example"]))),
        ),
        401,
        &["invalid_client"],
        "FAPI2 s5.3.3.1-5: the issuer as a string, never in an array",
    )
    .await;
    assert_push_refused(
        &s,
        &with(
            &good,
            "client_assertion",
            json!(s.other.assertion(CLIENT_ID, json!(s.origin))),
        ),
        401,
        &["invalid_client"],
        "RFC 7523 s3: an assertion signed by a key the client did not register",
    )
    .await;
    let replayed = s.key.assertion(CLIENT_ID, json!(s.origin));
    let once = with(&good, "client_assertion", json!(replayed));
    let proof = Key::new("dpop").proof("POST", &format!("{}/par", s.origin));
    let (status, body) = post(&s, "/par", &once, Some(proof)).await;
    assert_eq!(status, 201, "{body}");
    assert_push_refused(
        &s,
        &once,
        401,
        &["invalid_client"],
        "RFC 7523 s3 (7): an assertion's jti is single use",
    )
    .await;
    assert_push_refused(
        &s,
        &with(&with(&good, "code_challenge", Value::Null), "code_challenge_method", Value::Null),
        400,
        &["invalid_request"],
        "FAPI2 s5.3.2.2-5 / RFC 7636: PKCE is required",
    )
    .await;
    assert_push_refused(
        &s,
        &with(
            &with(&good, "code_challenge", json!(VERIFIER)),
            "code_challenge_method",
            json!("plain"),
        ),
        400,
        &["invalid_request"],
        "FAPI2 s5.3.2.2-5: S256 only, `plain` refused",
    )
    .await;
    assert_push_refused(
        &s,
        &with(&good, "redirect_uri", Value::Null),
        400,
        &["invalid_request"],
        "FAPI2 s5.3.2.2-6: redirect_uri is required in a pushed request",
    )
    .await;
}

/// Assert a token request was refused with a 4xx and one of `errors`.
async fn assert_token_refused(
    s: &Subject,
    form: &[(&str, String)],
    proof: Option<String>,
    errors: &[&str],
    why: &str,
) {
    let (status, body) = post(s, "/token", form, proof).await;
    assert!((400..500).contains(&status), "{why}: {status} {body}");
    let error = body["error"].as_str().unwrap_or_default();
    assert!(errors.contains(&error), "{why}: `{error}` not in {errors:?}: {body}");
}

/// The token endpoint's refusals. Each is checked against a FRESH code, so no refusal passes
/// because an earlier one spent the code — except the last, which is the reuse refusal itself and
/// is preceded by the correct redemption that proves the code was good.
#[tokio::test]
async fn the_token_endpoint_refuses_what_the_profile_forbids() {
    let s = serve(true).await;
    let dpop = Key::new("dpop");
    let token_endpoint = format!("{}/token", s.origin);
    let dpop_errors = &["invalid_dpop_proof", "invalid_request", "invalid_grant"];

    let code = code_for(&s, &dpop).await;
    assert_token_refused(
        &s,
        &token_form(&s, &code),
        None,
        dpop_errors,
        "FAPI2 s5.3.4-2: every token request carries a DPoP proof",
    )
    .await;

    let code = code_for(&s, &dpop).await;
    assert_token_refused(
        &s,
        &token_form(&s, &code),
        Some(Key::new("stranger").proof("POST", &token_endpoint)),
        dpop_errors,
        "RFC 9449 s10: the code is bound to the key the push proved",
    )
    .await;

    let code = code_for(&s, &dpop).await;
    assert_token_refused(
        &s,
        &token_form(&s, &code),
        Some(dpop.proof("POST", &format!("{}/elsewhere", s.origin))),
        dpop_errors,
        "RFC 9449 s4.3 (7): the proof's htu is this endpoint",
    )
    .await;

    let code = code_for(&s, &dpop).await;
    assert_token_refused(
        &s,
        &with(
            &token_form(&s, &code),
            "code_verifier",
            json!("a-verifier-that-does-not-hash-to-the-challenge-at-all-00"),
        ),
        Some(dpop.proof("POST", &token_endpoint)),
        &["invalid_grant"],
        "RFC 7636 s4.6: the verifier must hash to the pushed challenge",
    )
    .await;

    let code = code_for(&s, &dpop).await;
    let (status, body) = post(
        &s,
        "/token",
        &token_form(&s, &code),
        Some(dpop.proof("POST", &token_endpoint)),
    )
    .await;
    assert_eq!(status, 200, "a correct redemption succeeds: {body}");
    assert_token_refused(
        &s,
        &token_form(&s, &code),
        Some(dpop.proof("POST", &token_endpoint)),
        &["invalid_grant"],
        "RFC 6749 s4.1.2: a code is single use",
    )
    .await;
}
