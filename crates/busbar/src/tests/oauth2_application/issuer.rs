// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

// A single OIDC input for these distribution tests. Both the public key document and
// the tokens come from this key; the plugin fetches the document over a real TLS socket.
const KEY_ID: &str = "distribution-oidc";

type Idp = (ring::signature::EcdsaKeyPair, String, String);

fn idp() -> &'static Idp {
    use base64::Engine as _;
    use ring::signature::KeyPair as _;
    static IDP: std::sync::OnceLock<Idp> = std::sync::OnceLock::new();
    IDP.get_or_init(|| {
        let certificate = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()])
            .expect("the local IdP certificate");
        let signing_key = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &certificate.signing_key.serialize_der(),
            &ring::rand::SystemRandom::new(),
        )
        .expect("the IdP's P-256 signing key");
        let point = signing_key.public_key().as_ref();
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let jwks = serde_json::json!({"keys": [{
            "kty": "EC", "crv": "P-256", "kid": KEY_ID, "alg": "ES256", "use": "sig",
            "x": b64.encode(&point[1..33]), "y": b64.encode(&point[33..65]),
        }]})
        .to_string();
        let cert_pem = certificate.cert.pem();
        let private = rustls_pki_types::PrivateKeyDer::Pkcs8(
            rustls_pki_types::PrivatePkcs8KeyDer::from(certificate.signing_key.serialize_der()),
        );
        let tls = std::sync::Arc::new(
            rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .expect("TLS versions")
            .with_no_client_auth()
            .with_single_cert(vec![certificate.cert.der().clone()], private)
            .expect("the IdP TLS certificate"),
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("the local IdP port");
        let jwks_url = format!("https://{}/jwks", listener.local_addr().expect("the IdP address"));
        std::thread::spawn(move || {
            use std::io::{Read as _, Write as _};
            for socket in listener.incoming() {
                let Ok(socket) = socket else { continue };
                socket.set_read_timeout(Some(std::time::Duration::from_secs(5))).ok();
                socket.set_write_timeout(Some(std::time::Duration::from_secs(5))).ok();
                let session = rustls::ServerConnection::new(tls.clone()).expect("TLS session");
                let mut stream = rustls::StreamOwned::new(session, socket);
                let mut request = Vec::new();
                loop {
                    let mut byte = [0];
                    match stream.read(&mut byte) {
                        Ok(1) => request.push(byte[0]),
                        _ => break,
                    }
                    if request.ends_with(b"\r\n\r\n") || request.len() > 8192 {
                        break;
                    }
                }
                let (status, body) = if request.starts_with(b"GET /jwks HTTP/1.1\r\n") {
                    ("200 OK", jwks.as_str())
                } else {
                    ("404 Not Found", "{}")
                };
                let _ = write!(stream,
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len());
                let _ = stream.flush();
                stream.conn.send_close_notify();
                let _ = stream.flush();
            }
        });
        (signing_key, jwks_url, cert_pem)
    })
}

pub fn cert_pem() -> &'static str {
    &idp().2
}

pub fn settings(audience: &str) -> serde_json::Map<String, serde_json::Value> {
    serde_json::json!({
        "issuer": idp().1.trim_end_matches("/jwks"),
        "audience": audience,
        "jwks_url": idp().1,
        "ca_cert_pem": cert_pem(),
        "role_claim": "roles",
        "authorization_endpoint": format!("{}/authorize", idp().1.trim_end_matches("/jwks")),
        "token_endpoint": format!("{}/token", idp().1.trim_end_matches("/jwks")),
    })
    .as_object()
    .expect("OIDC settings")
    .clone()
}
