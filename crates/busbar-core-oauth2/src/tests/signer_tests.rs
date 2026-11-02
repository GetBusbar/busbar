// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::{RingEs256Key, RingEs256Verifier};

fn key(kid: &str) -> RingEs256Key {
    let der = RingEs256Key::generate_pkcs8().expect("generate a P-256 key");
    RingEs256Key::from_pkcs8_der(kid, &der).expect("load the key just generated")
}

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

#[tokio::test]
async fn the_harness_fails_a_signer_that_does_not_actually_sign() {
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

    let der = der_encode(&fixed);
    assert!(
        !super::RingEs256Verifier.verify(&public, input, &der),
        "the verifier accepted the DER encoding of a signature it had already accepted in the \
         fixed-width form; two encodings of one signature is malleability"
    );
}

fn der_encode(fixed: &[u8; 64]) -> Vec<u8> {
    fn integer(bytes: &[u8]) -> Vec<u8> {
        let trimmed = bytes
            .iter()
            .position(|b| *b != 0)
            .unwrap_or(bytes.len() - 1);
        let mut value = bytes[trimmed..].to_vec();

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

#[tokio::test]
async fn the_jwks_and_metadata_documents_are_byte_identical_to_1_5_5() {
    use base64::Engine as _;
    use http_body_util::BodyExt as _;
    use ring::signature::KeyPair as _;

    let der = RingEs256Key::generate_pkcs8().expect("generate a P-256 key");

    let pair = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        &der,
        &ring::rand::SystemRandom::new(),
    )
    .expect("load the key just generated");
    let point = pair.public_key().as_ref();
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let (x, y) = (b64.encode(&point[1..33]), b64.encode(&point[33..65]));

    let cfg = crate::config::OauthAsCfg {
        issuer: "https://gw.example.com".to_string(),
        signing_key: None,
        key_id: None,
        default_grant: vec!["read".to_string()],
        access_token_ttl_secs: None,
        refresh_token_ttl_secs: None,
        fapi2: false,
        clients: Vec::new(),
    };
    let identity = crate::config::AsIdentity::from_cfg(&cfg).expect("a valid oauth_as block");
    let kid = identity.key_id().to_string();
    let (jwks_path, metadata_path) = (
        identity.jwks_path().to_string(),
        identity.metadata_path().to_string(),
    );
    let plane = crate::plane::AsPlane::build(
        identity,
        Some(&base64::engine::general_purpose::STANDARD.encode(&der)),
        vec!["https://gw.example.com/rpc".to_string()],
        crate::cimd::unconnected(),
    )
    .expect("the plane builds with an operator-supplied key");

    let get = |path: String| {
        let plane = &plane;
        async move {
            let response = plane
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
            r#""protected_resources":["https://gw.example.com/rpc"],"#,
            r#""authorization_response_iss_parameter_supported":true}"#,
        ),
        "the served RFC 8414 metadata document is not byte-identical to 1.5.5's; this is a §9.5 \
         customer-visible change and must be queued, not absorbed"
    );
}
