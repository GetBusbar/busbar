// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SIGNER CONFORMANCE GATE.
//!
//! `PROPOSAL-oauth-as-ring-backend.md` §4 states the debt the seam creates in one sentence: *a host
//! can install a broken signer, and wrong signatures fail silently*. A signature that does not
//! verify is indistinguishable, at a resource server, from a token somebody tampered with, so the
//! deployment learns about it from its users. That is why the harness ships WITH the backend and
//! not after it.
//!
//! The harness is `oauth_as::signer_conformance`, and the reason it is worth more than any test
//! written here is that it carries the RFC 7515 appendix A.3 known-answer vector. busbar's signer
//! and busbar's verifier agreeing with each other proves only that they agree; the RFC's vector is
//! a value neither of them produced.

use super::{RingEs256Key, RingEs256Verifier};

/// Build the signer the production plane builds, from a freshly generated key.
fn key(kid: &str) -> RingEs256Key {
    let der = RingEs256Key::generate_pkcs8().expect("generate a P-256 key");
    RingEs256Key::from_pkcs8_der(kid, &der).expect("load the key just generated")
}

/// EVERY CHECK IN THE UPSTREAM HARNESS, GREEN.
///
/// Reported by NAME on failure rather than as a count: "3 violations" sends a reader to a debugger,
/// and `signer/output_is_not_der` sends them to the one constant that is wrong.
#[tokio::test]
async fn the_ring_backend_passes_the_upstream_signer_conformance_harness() {
    let violations = oauth_as::signer_conformance::SignerConformance::new(
        key("busbar-as-test"),
        RingEs256Verifier,
    )
    .run()
    .await;

    assert!(
        violations.is_empty(),
        "the ring ES256 backend failed oauth-as's signer conformance harness:\n{}",
        violations
            .iter()
            .map(|v| format!("  {} — {}", v.check, v.detail))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// THE HARNESS ITSELF CAN GO RED, proven by planting the exact fault it exists to catch.
///
/// Emitting ASN.1 DER instead of the RFC 7518 §3.4 fixed-width `r || s` is THE way to get this
/// wrong: `ring` offers both under constants that differ by one word, both compile, and both
/// produce bytes. The `JwsSignature::Es256([u8; 64])` return type refuses the wrong LENGTH — a DER signature is 70-72
/// bytes and would not fit — so this fault is planted at the only place it still fits: a 64-byte
/// value that is not the signature. If this test ever passes, the harness has stopped checking and
/// the green above means nothing.
#[tokio::test]
async fn the_harness_fails_a_signer_that_does_not_actually_sign() {
    /// A signer that returns a fixed 64 bytes: right length, right type, no signature.
    struct ConstantSigner(oauth_as::jwt::Jwk);
    impl oauth_as::jwt::JwsSigner for ConstantSigner {
        fn alg(&self) -> oauth_as::jwt::JwsAlg {
            oauth_as::jwt::JwsAlg::Es256
        }
        async fn sign(
            &self,
            _signing_input: &[u8],
        ) -> Result<oauth_as::jwt::JwsSignature, oauth_as::jwt::SignerError> {
            Ok(oauth_as::jwt::JwsSignature::Es256([7u8; 64]))
        }
        fn public_jwk(&self) -> oauth_as::jwt::Jwk {
            self.0.clone()
        }
    }

    let real = key("busbar-as-planted-fault");
    let violations = oauth_as::signer_conformance::SignerConformance::new(
        ConstantSigner(oauth_as::jwt::JwsSigner::public_jwk(&real)),
        RingEs256Verifier,
    )
    .run()
    .await;

    assert!(
        !violations.is_empty(),
        "a signer that returns a constant passed the conformance harness, so the harness is not \
         checking anything and the green run above is not evidence"
    );
}

/// THE VERIFIER REFUSES THE DER ENCODING, stated here as well as inside the harness.
///
/// Accepting both encodings of one signature is malleability: a value a deployment recorded as
/// unique stops being unique. The harness has `verifier/rejects_the_der_encoding`; this restates it
/// against busbar's own type so a future refactor of the verifier cannot quietly widen it while the
/// upstream harness is skipped for an unrelated reason.
#[tokio::test]
async fn the_verifier_refuses_an_asn1_der_signature() {
    use oauth_as::jwt::{JwsSigner as _, JwsVerifier as _};

    let signer = key("busbar-as-der");
    let jwk = signer.public_jwk();
    let public = oauth_as::jwt::Jwk::from_coordinates(jwk.x(), jwk.y()).expect("coordinates");
    let input = b"the JWS signing input";
    let oauth_as::jwt::JwsSignature::Es256(fixed) = signer.sign(input).await.expect("sign") else {
        panic!("the ring ES256 signer produced a non-ES256 signature variant");
    };

    assert!(
        super::RingEs256Verifier.verify(&public, input, &fixed),
        "the fixed-width signature must verify, or the rest of this test proves nothing"
    );

    // Re-encode the same signature as the ASN.1 DER `SEQUENCE { r INTEGER, s INTEGER }` that
    // OpenSSL and most KMS APIs emit, so the verifier is presented with the exact wrong thing
    // rather than with random bytes.
    let der = der_encode(&fixed);
    assert!(
        !super::RingEs256Verifier.verify(&public, input, &der),
        "the verifier accepted the DER encoding of a signature it had already accepted in the \
         fixed-width form; two encodings of one signature is malleability"
    );
}

/// `r || s` as `SEQUENCE { r INTEGER, s INTEGER }`. Hand written, in the test, because pulling a
/// DER encoder into the dependency tree to build one test input would undo the reduction the ring
/// backend exists for.
fn der_encode(fixed: &[u8; 64]) -> Vec<u8> {
    fn integer(bytes: &[u8]) -> Vec<u8> {
        let trimmed = bytes
            .iter()
            .position(|b| *b != 0)
            .unwrap_or(bytes.len() - 1);
        let mut value = bytes[trimmed..].to_vec();
        // DER INTEGERs are signed, so a leading bit of 1 needs a zero byte in front of it.
        if value.first().is_some_and(|b| b & 0x80 != 0) {
            value.insert(0, 0x00);
        }
        let mut out = vec![0x02, value.len() as u8];
        out.extend_from_slice(&value);
        out
    }
    let mut body = integer(&fixed[..32]);
    body.extend_from_slice(&integer(&fixed[32..]));
    let mut out = vec![0x30, body.len() as u8];
    out.extend_from_slice(&body);
    out
}

/// THE TWO DISCOVERY DOCUMENTS, PINNED TO THE BYTE — the observable an `oauth-as` bump is most
/// likely to move without anybody deciding to move it.
///
/// `oauth-as` 0.10.0 dissolved the struct `Jwk` (which carried `use` and `alg` as members) into a
/// `kty`-tagged enum with neither, and re-derives `"use":"sig","alg":"ES256"` from the curve when it
/// SERVES the key set. A client or resource server that caches the JWKS, or compares metadata, sees
/// any change in member set, member order, header or status here. 1.5.5 shipped these exact bytes
/// (on `oauth-as` 0.9.3); §9.5 holds them identical, so a future bump that moves them fails here
/// and is queued as a customer-visible change instead of shipping as a recompile.
///
/// Driven through the plane's real `AuthorizationService` (the same `handle` `routes::forward`
/// hands every request to, unchanged), built by the boot path's own `AsPlane::build` with an
/// operator-supplied key, so the key coordinates are known and the whole body can be compared.
#[tokio::test]
async fn the_jwks_and_metadata_documents_are_byte_identical_to_1_5_5() {
    use base64::Engine as _;
    use http_body_util::BodyExt as _;
    use ring::signature::KeyPair as _;

    let der = RingEs256Key::generate_pkcs8().expect("generate a P-256 key");
    // The coordinates, read from `ring` directly rather than through the `oauth-as` JWK type whose
    // shape is precisely what this test watches.
    let pair = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        &der,
        &ring::rand::SystemRandom::new(),
    )
    .expect("load the key just generated");
    let point = pair.public_key().as_ref();
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let (x, y) = (b64.encode(&point[1..33]), b64.encode(&point[33..65]));

    let cfg = busbar_kernel::oauth_as::config::OauthAsCfg {
        issuer: "https://gw.example.com".to_string(),
        signing_key: None,
        key_id: None,
        default_grant: vec!["read".to_string()],
        access_token_ttl_secs: None,
    };
    let identity = busbar_kernel::oauth_as::config::AsIdentity::from_cfg(&cfg)
        .expect("a valid oauth_as block");
    let kid = identity.key_id().to_string();
    let (jwks_path, metadata_path) = (
        identity.jwks_path().to_string(),
        identity.metadata_path().to_string(),
    );
    let plane = crate::plane::AsPlane::build(
        identity,
        Some(&base64::engine::general_purpose::STANDARD.encode(&der)),
        vec!["https://gw.example.com/mcp".to_string()],
    )
    .expect("the plane builds with an operator-supplied key");

    let get = |path: String| {
        let service = plane.service();
        async move {
            let response = service
                .handle(
                    http::Request::get(path)
                        .body(http_body_util::Empty::<bytes::Bytes>::new())
                        .expect("a GET request"),
                )
                .await;
            let (parts, body) = response.into_parts();
            let bytes = body.collect().await.expect("body").to_bytes();
            (
                parts.status.as_u16(),
                parts
                    .headers
                    .iter()
                    .map(|(k, v)| format!("{k}: {}", v.to_str().unwrap_or("<binary>")))
                    .collect::<Vec<_>>(),
                String::from_utf8(bytes.to_vec()).expect("utf-8 body"),
            )
        }
    };

    // RFC 7517 §5: member order `kty`, `crv`, `x`, `y`, `kid`, `use`, `alg` — what 0.9.3's struct
    // `Jwk` serialized, and what 1.0.0's served `JwksEntry` must still serialize.
    let (status, headers, body) = get(jwks_path).await;
    assert_eq!(status, 200, "the JWKS document's status moved");
    assert_eq!(
        headers,
        ["content-type: application/jwk-set+json"],
        "the JWKS document's headers moved"
    );
    assert_eq!(
        body,
        format!(
            r#"{{"keys":[{{"kty":"EC","crv":"P-256","x":"{x}","y":"{y}","kid":"{kid}","use":"sig","alg":"ES256"}}]}}"#
        ),
        "the served JWKS document is not byte-identical to 1.5.5's; this is a customer-visible \
         change and must be queued, not absorbed"
    );

    // RFC 8414 §2 metadata. No signing-algorithm member appears at all: busbar enables none of
    // `client-assertion`/`jar`/`dpop`, and 0.10.0–0.11.0 re-plumbed exactly those members (the
    // per-algorithm `mark_alg_verifiable`, the `jws_alg_allow_list` filter). A bump that started
    // advertising an algorithm list here would be advertising a method the token endpoint refuses.
    let (status, headers, body) = get(metadata_path).await;
    assert_eq!(status, 200, "the metadata document's status moved");
    assert_eq!(
        headers,
        ["content-type: application/json;charset=UTF-8"],
        "the metadata document's headers moved"
    );
    assert_eq!(
        body,
        concat!(
            r#"{"issuer":"https://gw.example.com","#,
            r#""authorization_endpoint":"https://gw.example.com/authorize","#,
            r#""token_endpoint":"https://gw.example.com/token","#,
            r#""device_authorization_endpoint":"https://gw.example.com/device_authorization","#,
            r#""revocation_endpoint":"https://gw.example.com/revoke","#,
            r#""registration_endpoint":"https://gw.example.com/register","#,
            r#""jwks_uri":"https://gw.example.com/jwks","#,
            r#""scopes_supported":["read"],"#,
            r#""response_types_supported":["code"],"#,
            r#""response_modes_supported":["query"],"#,
            r#""grant_types_supported":["authorization_code","refresh_token","client_credentials","urn:ietf:params:oauth:grant-type:device_code"],"#,
            r#""token_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","none"],"#,
            r#""code_challenge_methods_supported":["S256"],"#,
            r#""protected_resources":["https://gw.example.com/mcp"],"#,
            r#""authorization_response_iss_parameter_supported":true}"#,
        ),
        "the served RFC 8414 metadata document is not byte-identical to 1.5.5's; this is a §9.5 \
         customer-visible change and must be queued, not absorbed"
    );
}
