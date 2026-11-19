// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The RFC 9449 proof a protected resource of this deployment asks this server to judge for the
//! URL the resource states (`AsPlane::prove_dpop`, the seam's `prove_dpop`): each field wrong is
//! refused for its own reason, and only a whole proof for this request, this token and this
//! token's key is proven, once.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use base64::Engine as _;
use busbar_contract::crypto::ecdsa_p256;
use busbar_kernel::oauth_as::seam::{DpopAtResource, DpopPresentation, DpopRefused, DpopVerdict};
use oauth_as::client::{Client, ClientAuth, ClientId};
use oauth_as::grant::GrantType;
use oauth_as::scope::ScopeSet;
use oauth_as::store::Storage as _;
use serde_json::{json, Value};

use crate::config::OauthAsCfg;

const ISSUER: &str = "https://as.example.com";
const RESOURCE: &str = "https://gw.example.com/mcp";
const REDIRECT_URI: &str = "http://127.0.0.1:9999/cb";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const CLIENT_ID: &str = "native-dpop-test-client";

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

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

fn ath(token: &str) -> String {
    B64.encode(busbar_contract::crypto::sha256(token.as_bytes()))
}

/// A client's P-256 proof key.
struct Key {
    pair: ecdsa_p256::KeyPair,
}

impl Key {
    fn new() -> Self {
        let pkcs8 = ecdsa_p256::generate_pkcs8().expect("generate a P-256 key");
        Self {
            pair: ecdsa_p256::from_pkcs8(&pkcs8).expect("load the key just generated"),
        }
    }

    fn public_json(&self) -> Value {
        let point = &self.pair.public_key();
        json!({
            "kty": "EC",
            "crv": "P-256",
            "x": B64.encode(&point[1..33]),
            "y": B64.encode(&point[33..65]),
        })
    }

    fn sign(&self, header: &Value, claims: &Value) -> String {
        let input = format!(
            "{}.{}",
            B64.encode(header.to_string()),
            B64.encode(claims.to_string())
        );
        let sig = self.pair.sign_fixed(input.as_bytes()).expect("sign");
        format!("{input}.{}", B64.encode(sig))
    }

    fn header(&self) -> Value {
        json!({ "typ": "dpop+jwt", "alg": "ES256", "jwk": self.public_json() })
    }

    /// A proof for one request, with a fresh `jti`.
    fn proof(&self, htm: &str, htu: &str, ath: Option<&str>, iat: u64) -> String {
        let mut claims = json!({ "jti": jti(), "htm": htm, "htu": htu, "iat": iat });
        if let Some(ath) = ath {
            claims["ath"] = json!(ath);
        }
        self.sign(&self.header(), &claims)
    }
}

async fn plane() -> Arc<crate::plane::AsPlane> {
    let config = OauthAsCfg {
        issuer: ISSUER.into(),
        default_grant: vec!["read".into()],
        ..Default::default()
    };
    let block = busbar_contract::yaml::to_value(
        config.authoring(&busbar_kernel::test_hooks::tokens::seal()),
    )
    .expect("owner config serializes");
    let plane = crate::plane::seam_build::<crate::NoConnections>(
        block,
        Vec::new(),
        vec![RESOURCE.to_string()],
        None,
        crate::testkit::memory_store().await,
        crate::testkit::ADMIN_ORIGIN.to_string(),
    )
    .await
    .expect("the owner seam builds over the store")
    .downcast::<crate::plane::AsPlane>()
    .unwrap_or_else(|_| panic!("the owner seam returns its plane"));
    let scope = ScopeSet::parse("read").expect("scope");
    plane
        .server()
        .register_client(Client {
            client_id: ClientId::new(CLIENT_ID),
            auth: ClientAuth::Public,
            grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
            redirect_uris: vec![REDIRECT_URI.into()],
            allowed_scopes: scope.clone(),
            default_scopes: scope,
            name: None,
            registration: None,
        })
        .await
        .expect("the store registers the client");
    plane
}

/// An access token for [`RESOURCE`]: bound to `key` (RFC 9449 s5: the token request carried its
/// proof) or, with none, an ordinary bearer.
async fn token(plane: &crate::plane::AsPlane, key: Option<&Key>) -> String {
    let request = oauth_as::authorization::AuthorizationRequest::from_pairs(vec![
        ("response_type", "code"),
        ("client_id", CLIENT_ID),
        ("redirect_uri", REDIRECT_URI),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
        ("resource", RESOURCE),
    ]);
    let validated = plane
        .server()
        .validate_authorization_request(&request)
        .await
        .expect("request validates");
    let code = plane
        .server()
        .issue_authorization_code(oauth_as::server::UserApproval::granted(
            &validated,
            "busbar-operator",
        ))
        .await
        .expect("the approved request mints a code");
    let proof = key.map(|key| key.proof("POST", &format!("{ISSUER}/token"), None, now()));
    let mut context = oauth_as::server::TokenRequestContext::default();
    if let Some(proof) = proof.as_deref() {
        context = context.with_dpop_proof(proof);
    }
    plane
        .server()
        .token_with_context(
            oauth_as::server::TokenRequest::AuthorizationCode {
                client_id: ClientId::new(CLIENT_ID),
                client_secret: None,
                code: code.code,
                redirect_uri: Some(REDIRECT_URI.into()),
                code_verifier: Some(VERIFIER.into()),
            },
            context,
        )
        .await
        .expect("the approved code exchanges")
        .access_token
}

/// One `POST` to [`RESOURCE`] presenting `token` with `proof`.
async fn judged(plane: &crate::plane::AsPlane, token: &str, proof: &str) -> DpopVerdict {
    plane
        .prove_dpop(DpopAtResource {
            method: "POST",
            htu: RESOURCE,
            token,
            proof,
        })
        .await
}

/// One `GET /stats` at the door, which states only its path.
fn at_door<'a>(token: &'a str, proof: &'a str) -> DpopPresentation<'a> {
    DpopPresentation {
        method: "GET",
        path: "/stats",
        token,
        proof,
    }
}

fn refused(reason: DpopRefused) -> DpopVerdict {
    DpopVerdict::Refused(reason)
}

#[tokio::test]
async fn a_whole_proof_for_this_request_is_proven() {
    let plane = plane().await;
    let key = Key::new();
    let access = token(&plane, Some(&key)).await;
    assert!(
        busbar_kernel::auth::dpop::is_dpop_bound(&access),
        "a token request that carried a proof mints a token bound to its key"
    );
    let proof = key.proof("POST", RESOURCE, Some(&ath(&access)), now());
    assert_eq!(judged(&plane, &access, &proof).await, DpopVerdict::Proven);
    // RFC 3986 s6.2.2.1: scheme and host compare without case; a query or a fragment in the
    // claimed `htu` is ignored (RFC 9449 s4.3 (9)).
    let relaxed = key.proof(
        "POST",
        "HTTPS://GW.EXAMPLE.COM/mcp?cursor=1#top",
        Some(&ath(&access)),
        now(),
    );
    assert_eq!(judged(&plane, &access, &relaxed).await, DpopVerdict::Proven);
}

#[tokio::test]
async fn a_proof_is_spent_by_its_first_use() {
    let plane = plane().await;
    let key = Key::new();
    let access = token(&plane, Some(&key)).await;
    let proof = key.proof("POST", RESOURCE, Some(&ath(&access)), now());
    assert_eq!(judged(&plane, &access, &proof).await, DpopVerdict::Proven);
    assert_eq!(
        judged(&plane, &access, &proof).await,
        refused(DpopRefused::Replayed),
        "the same jti under the same key is never proven twice"
    );
    // The door's judgement and the native path's spend one store: a proof proven by either is
    // spent for both.
    let htu = format!("{ISSUER}/stats");
    let other = key.proof("GET", &htu, Some(&ath(&access)), now());
    assert!(plane.verify_dpop(at_door(&access, &other)).await);
    assert_eq!(
        plane
            .prove_dpop(DpopAtResource {
                method: "GET",
                htu: &htu,
                token: &access,
                proof: &other,
            })
            .await,
        refused(DpopRefused::Replayed)
    );
}

#[tokio::test]
async fn a_proof_for_another_method_is_refused() {
    let plane = plane().await;
    let key = Key::new();
    let access = token(&plane, Some(&key)).await;
    for htm in ["GET", "post", "DELETE"] {
        let proof = key.proof(htm, RESOURCE, Some(&ath(&access)), now());
        assert_eq!(
            judged(&plane, &access, &proof).await,
            refused(DpopRefused::Method),
            "htm {htm}: RFC 9110 s9.1 methods are case sensitive"
        );
    }
}

#[tokio::test]
async fn a_proof_for_another_url_is_refused() {
    let plane = plane().await;
    let key = Key::new();
    let access = token(&plane, Some(&key)).await;
    for htu in [
        "https://gw.example.com/mcp/",
        "https://gw.example.com/MCP",
        "https://gw.example.com/other",
        "http://gw.example.com/mcp",
        "https://gw.example.com:8443/mcp",
        "https://evil.example.com/mcp",
        "https://as.example.com/mcp",
        "/mcp",
    ] {
        let proof = key.proof("POST", htu, Some(&ath(&access)), now());
        assert_eq!(
            judged(&plane, &access, &proof).await,
            refused(DpopRefused::Uri),
            "htu {htu}"
        );
    }
}

#[tokio::test]
async fn a_proof_outside_the_iat_window_is_refused() {
    let plane = plane().await;
    let key = Key::new();
    let access = token(&plane, Some(&key)).await;
    // The window is the one the door always used: the library's own two constants.
    let age = oauth_as::dpop::MAX_PROOF_AGE.as_secs();
    let ahead = oauth_as::dpop::CLOCK_SKEW_LEEWAY.as_secs();
    for iat in [now() - age - 5, now() - 3600, now() + ahead + 30, 0] {
        let proof = key.proof("POST", RESOURCE, Some(&ath(&access)), iat);
        assert_eq!(
            judged(&plane, &access, &proof).await,
            refused(DpopRefused::Stale),
            "iat {iat}"
        );
    }
    let absent = key.sign(
        &key.header(),
        &json!({ "jti": jti(), "htm": "POST", "htu": RESOURCE, "ath": ath(&access) }),
    );
    assert_eq!(
        judged(&plane, &access, &absent).await,
        refused(DpopRefused::Stale)
    );
    for iat in [now() - age + 30, now() + ahead - 30] {
        let proof = key.proof("POST", RESOURCE, Some(&ath(&access)), iat);
        assert_eq!(
            judged(&plane, &access, &proof).await,
            DpopVerdict::Proven,
            "iat {iat} is inside the window"
        );
    }
}

#[tokio::test]
async fn a_proof_without_a_usable_jti_is_refused() {
    let plane = plane().await;
    let key = Key::new();
    let access = token(&plane, Some(&key)).await;
    for jti in [json!(null), json!(""), json!(7)] {
        let mut claims = json!({
            "htm": "POST", "htu": RESOURCE, "iat": now(), "ath": ath(&access),
        });
        if !jti.is_null() {
            claims["jti"] = jti.clone();
        }
        let proof = key.sign(&key.header(), &claims);
        assert_eq!(
            judged(&plane, &access, &proof).await,
            refused(DpopRefused::Jti),
            "jti {jti}: a proof that cannot be remembered can be sent again"
        );
    }
}

#[tokio::test]
async fn a_proof_for_another_access_token_is_refused() {
    let plane = plane().await;
    let key = Key::new();
    let access = token(&plane, Some(&key)).await;
    // The same key's other token: both carry this key's thumbprint, only `ath` tells them apart.
    let other = token(&plane, Some(&key)).await;
    for claimed in [Some(ath(&other)), Some(ath("another-token")), None] {
        let proof = key.proof("POST", RESOURCE, claimed.as_deref(), now());
        assert_eq!(
            judged(&plane, &access, &proof).await,
            refused(DpopRefused::AccessTokenHash),
            "ath {claimed:?}"
        );
    }
}

#[tokio::test]
async fn a_proof_under_another_key_is_refused() {
    let plane = plane().await;
    let key = Key::new();
    let access = token(&plane, Some(&key)).await;
    // A thief holding the token signs a perfectly good proof with a key of its own.
    let stranger = Key::new();
    let proof = stranger.proof("POST", RESOURCE, Some(&ath(&access)), now());
    assert_eq!(
        judged(&plane, &access, &proof).await,
        refused(DpopRefused::KeyBinding),
        "the proof key's thumbprint is not the token's cnf.jkt"
    );
    // The thief names the owner's key in the header and signs with its own.
    let forged = stranger.sign(
        &key.header(),
        &json!({
            "jti": jti(), "htm": "POST", "htu": RESOURCE, "iat": now(), "ath": ath(&access),
        }),
    );
    assert_eq!(
        judged(&plane, &access, &forged).await,
        refused(DpopRefused::Signature)
    );
}

#[tokio::test]
async fn an_unbound_token_is_never_proven() {
    let plane = plane().await;
    let key = Key::new();
    let bearer = token(&plane, None).await;
    assert!(!busbar_kernel::auth::dpop::is_dpop_bound(&bearer));
    let proof = key.proof("POST", RESOURCE, Some(&ath(&bearer)), now());
    assert_eq!(
        judged(&plane, &bearer, &proof).await,
        refused(DpopRefused::KeyBinding),
        "a bearer token gains nothing from the DPoP scheme: it names no key to prove"
    );
}

#[tokio::test]
async fn a_symmetric_or_absent_algorithm_is_refused() {
    let plane = plane().await;
    let key = Key::new();
    let access = token(&plane, Some(&key)).await;
    let claims = json!({
        "jti": jti(), "htm": "POST", "htu": RESOURCE, "iat": now(), "ath": ath(&access),
    });
    for alg in ["HS256", "HS384", "HS512", "none", "RS256", "EdDSA"] {
        let proof = key.sign(
            &json!({ "typ": "dpop+jwt", "alg": alg, "jwk": key.public_json() }),
            &claims,
        );
        assert_eq!(
            judged(&plane, &access, &proof).await,
            refused(DpopRefused::Algorithm),
            "alg {alg}: only ES256 and PS256 prove possession here"
        );
    }
    // A MAC key offered as the proof key, under the name of an algorithm that is allowed.
    let oct = key.sign(
        &json!({
            "typ": "dpop+jwt", "alg": "ES256",
            "jwk": { "kty": "oct", "k": "c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0" },
        }),
        &claims,
    );
    assert_eq!(
        judged(&plane, &access, &oct).await,
        refused(DpopRefused::ProofKey)
    );
}

#[tokio::test]
async fn a_jwt_that_is_not_a_proof_is_refused() {
    let plane = plane().await;
    let key = Key::new();
    let access = token(&plane, Some(&key)).await;
    let claims = json!({
        "jti": jti(), "htm": "POST", "htu": RESOURCE, "iat": now(), "ath": ath(&access),
    });
    for typ in [
        json!("JWT"),
        json!("at+jwt"),
        json!("DPOP+JWT"),
        json!(null),
    ] {
        let mut header = json!({ "alg": "ES256", "jwk": key.public_json() });
        if !typ.is_null() {
            header["typ"] = typ.clone();
        }
        assert_eq!(
            judged(&plane, &access, &key.sign(&header, &claims)).await,
            refused(DpopRefused::NotAProof),
            "typ {typ}"
        );
    }
    let no_key = key.sign(&json!({ "typ": "dpop+jwt", "alg": "ES256" }), &claims);
    assert_eq!(
        judged(&plane, &access, &no_key).await,
        refused(DpopRefused::ProofKey)
    );
    let long = "x".repeat(5000);
    for garbage in ["", "not-a-proof", "a.b.c", long.as_str(), access.as_str()] {
        assert!(
            matches!(
                judged(&plane, &access, garbage).await,
                DpopVerdict::Refused(_)
            ),
            "{} bytes are not a proof",
            garbage.len()
        );
    }
}

#[tokio::test]
async fn a_token_its_issuer_no_longer_holds_is_refused_with_a_good_proof() {
    let plane = plane().await;
    let key = Key::new();
    let access = token(&plane, Some(&key)).await;
    plane
        .server()
        .store()
        .delete_token(&access)
        .await
        .expect("revocation removes the record");
    let proof = key.proof("POST", RESOURCE, Some(&ath(&access)), now());
    assert_eq!(
        judged(&plane, &access, &proof).await,
        refused(DpopRefused::NotHeld)
    );
    // A refused presentation spends nothing: a proof is spent only by being proven.
    let held = token(&plane, Some(&key)).await;
    let proof = key.proof("POST", RESOURCE, Some(&ath(&held)), now());
    assert_eq!(
        plane
            .prove_dpop(DpopAtResource {
                method: "POST",
                htu: "https://gw.example.com/other",
                token: &held,
                proof: &proof,
            })
            .await,
        refused(DpopRefused::Uri)
    );
    assert_eq!(judged(&plane, &held, &proof).await, DpopVerdict::Proven);
}

#[tokio::test]
async fn the_door_still_judges_a_proof_for_its_own_origin() {
    let plane = plane().await;
    let key = Key::new();
    let access = token(&plane, Some(&key)).await;
    let good = key.proof(
        "GET",
        &format!("{ISSUER}/stats"),
        Some(&ath(&access)),
        now(),
    );
    assert!(plane.verify_dpop(at_door(&access, &good)).await);
    assert!(
        !plane.verify_dpop(at_door(&access, &good)).await,
        "single use, as before"
    );
    let elsewhere = key.proof("GET", RESOURCE, Some(&ath(&access)), now());
    assert!(!plane.verify_dpop(at_door(&access, &elsewhere)).await);
}
