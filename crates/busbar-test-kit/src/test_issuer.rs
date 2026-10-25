// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A LOCAL TOKEN ISSUER FOR TESTS (`test-support`, never in a shipped build): an ES256 key, its
//! JWKS, and genuinely signed tokens.
//!
//! A test that loads a token-verifying auth plugin points it here: the plugin names the JWKS URL and
//! trusts the endpoint's certificate through its own settings (`ca_cert_pem`, the need's
//! `trust_from`), and the HOST fetches the JWKS for it over a declared need (the plugin holds no
//! socket and no TLS). Where the JWKS is served is the test's: in process, by the stand-in
//! connection table [`crate::https_conns::HttpsConns`] (which serves it only to a need trusting
//! [`Issuer::cert_pem`]), or over real TLS by a test that may hold a TLS library (the composition
//! root's, which then names its address and certificate with [`Issuer::served_at`]). No TLS library
//! is named here: TLS stays in the connector.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ring::signature::{EcdsaKeyPair, KeyPair as _, ECDSA_P256_SHA256_FIXED_SIGNING};

/// A local issuer: its identity, its signing key, its JWKS, and where (and under which
/// certificate) that JWKS is served.
pub struct Issuer {
    issuer: String,
    kid: String,
    key: EcdsaKeyPair,
    rng: ring::rand::SystemRandom,
    jwks: String,
    jwks_url: String,
    cert_pem: String,
}

impl std::fmt::Debug for Issuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Issuer")
            .field("issuer", &self.issuer)
            .field("jwks_url", &self.jwks_url)
            .finish_non_exhaustive()
    }
}

impl Issuer {
    /// An issuer named `issuer` (the `iss` its tokens carry), signing under key id `kid`. Its JWKS
    /// is served in process by [`crate::https_conns::HttpsConns`], at `<issuer>/jwks`, under a
    /// certificate of its own ([`Issuer::cert_pem`], an opaque PEM the table holds a need's trust
    /// against).
    ///
    /// # Panics
    /// The key cannot be made.
    #[must_use]
    pub fn start(issuer: &str, kid: &str) -> Self {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .expect("generate an ES256 key");
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .expect("load the ES256 key");
        let point = key.public_key().as_ref();
        let jwks = serde_json::json!({ "keys": [{
            "kty": "EC", "crv": "P-256", "kid": kid, "use": "sig", "alg": "ES256",
            "x": URL_SAFE_NO_PAD.encode(&point[1..33]),
            "y": URL_SAFE_NO_PAD.encode(&point[33..65]),
        }]})
        .to_string();
        // An opaque certificate PEM unique to this issuer: what a need must trust for the
        // in-process table to serve it.
        let mut seed = [0u8; 48];
        ring::rand::SecureRandom::fill(&rng, &mut seed).expect("randomness");
        let cert_pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            base64::engine::general_purpose::STANDARD.encode(seed)
        );
        Self {
            jwks_url: format!("{}/jwks", issuer.trim_end_matches('/')),
            issuer: issuer.to_string(),
            kid: kid.to_string(),
            key,
            rng,
            jwks,
            cert_pem,
        }
    }

    /// The same issuer, its JWKS served over real TLS at `jwks_url` under the certificate
    /// `cert_pem` (a test that stands that endpoint up names it here).
    #[must_use]
    pub fn served_at(mut self, jwks_url: &str, cert_pem: &str) -> Self {
        jwks_url.clone_into(&mut self.jwks_url);
        cert_pem.clone_into(&mut self.cert_pem);
        self
    }

    /// The `iss` this issuer's tokens carry.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The JWKS document (the public key, under its key id).
    #[must_use]
    pub fn jwks(&self) -> &str {
        &self.jwks
    }

    /// Where the JWKS is served.
    #[must_use]
    pub fn jwks_url(&self) -> &str {
        &self.jwks_url
    }

    /// The certificate the JWKS endpoint presents (a plugin's `ca_cert_pem`).
    #[must_use]
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// Settings that verify this issuer's tokens for `audience`: the issuer, the JWKS URL and its
    /// certificate, roles read from the `roles` claim, and explicit login endpoints (so nothing is
    /// discovered).
    #[must_use]
    pub fn settings(&self, audience: &str) -> serde_json::Map<String, serde_json::Value> {
        let serde_json::Value::Object(map) = serde_json::json!({
            "issuer": self.issuer,
            "audience": audience,
            "jwks_url": self.jwks_url,
            "ca_cert_pem": self.cert_pem,
            "role_claim": "roles",
            "authorization_endpoint": format!("{}/authorize", self.issuer),
            "token_endpoint": format!("{}/token", self.issuer),
        }) else {
            unreachable!("a JSON object literal")
        };
        map
    }

    /// A token for `sub` carrying `roles`, bound to `aud`, valid for an hour, signed by this issuer.
    ///
    /// # Panics
    /// The clock reads before the epoch, or the signature cannot be made.
    #[must_use]
    pub fn mint(&self, sub: &str, roles: &[&str], aud: &str) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("a clock after the epoch")
            .as_secs();
        self.sign(&serde_json::json!({
            "iss": self.issuer, "aud": aud, "sub": sub, "roles": roles,
            "exp": now + 3600, "nbf": now - 10,
        }))
    }

    /// `claims`, signed by this issuer as a compact JWS.
    ///
    /// # Panics
    /// The signature cannot be made.
    #[must_use]
    pub fn sign(&self, claims: &serde_json::Value) -> String {
        let head = serde_json::json!({ "alg": "ES256", "typ": "JWT", "kid": self.kid });
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&head).expect("encode the header")),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("encode the claims")),
        );
        let signature = self
            .key
            .sign(&self.rng, input.as_bytes())
            .expect("sign the token");
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.as_ref()))
    }
}
