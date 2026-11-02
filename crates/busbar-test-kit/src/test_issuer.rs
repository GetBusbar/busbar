// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ring::signature::{EcdsaKeyPair, KeyPair as _, ECDSA_P256_SHA256_FIXED_SIGNING};

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

    #[must_use]
    pub fn served_at(mut self, jwks_url: &str, cert_pem: &str) -> Self {
        jwks_url.clone_into(&mut self.jwks_url);
        cert_pem.clone_into(&mut self.cert_pem);
        self
    }

    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    #[must_use]
    pub fn jwks(&self) -> &str {
        &self.jwks
    }

    #[must_use]
    pub fn jwks_url(&self) -> &str {
        &self.jwks_url
    }

    #[must_use]
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

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
