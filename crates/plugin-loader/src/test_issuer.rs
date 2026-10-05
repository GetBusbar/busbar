// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A LOCAL TOKEN ISSUER FOR TESTS (`test-support`, never in a shipped build): an ES256 key, its
//! JWKS served over a certificate-verified loopback HTTPS endpoint, and genuinely signed tokens.
//!
//! A test that loads a token-verifying auth plugin points it here: the plugin names the JWKS URL
//! and trusts the endpoint's certificate through its own settings (`ca_cert_pem`, the need's
//! `trust_from`), and the HOST fetches it for the plugin over a declared need (the plugin holds no
//! socket and no TLS). [`Issuer::start`] binds a fresh loopback port and answers every request on
//! it with the JWKS, on one background thread, for the life of the process; [`Issuer::mint`] signs
//! tokens with the matching key. Nothing is stubbed: the plugin under test does the whole
//! verification, and the host does the whole fetch.

use std::io::{Read as _, Write as _};
use std::sync::Arc;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ring::signature::{EcdsaKeyPair, KeyPair as _, ECDSA_P256_SHA256_FIXED_SIGNING};

/// A running local issuer: its identity, its signing key, and where its JWKS is served.
pub struct Issuer {
    issuer: String,
    kid: String,
    key: EcdsaKeyPair,
    rng: ring::rand::SystemRandom,
    jwks_url: String,
    cert_pem: String,
    cert_der: Vec<u8>,
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
    /// Start an issuer named `issuer` (the `iss` its tokens carry), signing under key id `kid`,
    /// with its JWKS served on a fresh loopback port for the life of the process.
    ///
    /// # Panics
    /// The key, the certificate or the loopback listener cannot be made.
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

        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()])
            .expect("mint a self-signed certificate");
        let cert_pem = cert.cert.pem();
        let cert_der = cert.cert.der().to_vec();
        let chain = vec![cert.cert.der().clone()];
        let private = rustls_pki_types::PrivateKeyDer::Pkcs8(
            rustls_pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()),
        );
        let config = Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_no_client_auth()
            .with_single_cert(chain, private)
            .expect("server certificate"),
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a loopback port");
        let jwks_url = format!(
            "https://{}/jwks",
            listener.local_addr().expect("local addr")
        );
        std::thread::spawn(move || {
            for socket in listener.incoming() {
                let (Ok(socket), Ok(session)) =
                    (socket, rustls::ServerConnection::new(config.clone()))
                else {
                    continue;
                };
                let mut stream = rustls::StreamOwned::new(session, socket);
                let _ = stream.read(&mut [0u8; 4096]);
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
                     Connection: close\r\n\r\n{jwks}",
                    jwks.len()
                );
                let _ = stream.flush();
                stream.conn.send_close_notify();
                let _ = stream.flush();
            }
        });
        Self {
            issuer: issuer.to_string(),
            kid: kid.to_string(),
            key,
            rng,
            jwks_url,
            cert_pem,
            cert_der,
        }
    }

    /// The `iss` this issuer's tokens carry.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Where the JWKS is served (`https://127.0.0.1:<port>/jwks`).
    #[must_use]
    pub fn jwks_url(&self) -> &str {
        &self.jwks_url
    }

    /// The PEM certificate the JWKS endpoint presents (a plugin's `ca_cert_pem`).
    #[must_use]
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// The same certificate, DER.
    #[must_use]
    pub fn cert_der(&self) -> &[u8] {
        &self.cert_der
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
