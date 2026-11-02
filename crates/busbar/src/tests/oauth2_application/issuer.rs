// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

// A single OIDC input for these distribution tests. Both the public key document and
// the tokens come from this key; the plugin fetches the document over a real TLS socket.
const KEY_ID: &str = "distribution-oidc";

struct Idp {
    jwks_url: String,
    certificate: String,
    exchanges: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, usize>>>,
}

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
        let issuer = jwks_url.trim_end_matches("/jwks").to_owned();
        let exchanges = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::<String,usize>::new()));
        let observed = exchanges.clone();
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
                let headers = String::from_utf8_lossy(&request);
                let length = headers.lines().find_map(|line| {
                    let (name,value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length").then(|| value.trim().parse::<usize>().ok()).flatten()
                }).unwrap_or(0);
                let mut content = vec![0; length.min(8192)];
                if stream.read_exact(&mut content).is_err() { continue; }
                let (status, body) = if request.starts_with(b"GET /jwks HTTP/1.1\r\n") {
                    ("200 OK", jwks.clone())
                } else if request.starts_with(b"POST /token HTTP/1.1\r\n") {
                    let form = String::from_utf8_lossy(&content);
                    let code = form.split('&').filter_map(|pair| pair.split_once('='))
                        .find(|(name,_)| *name=="code")
                        .map(|(_,value)| super::browser::percent_decode(&value.replace('+'," ")))
                        .unwrap_or_default();
                    *observed.lock().unwrap().entry(code.clone()).or_default() += 1;
                    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
                    let header = b64.encode(serde_json::json!({"alg":"ES256","typ":"JWT","kid":KEY_ID}).to_string());
                    let claims = b64.encode(serde_json::json!({
                        "iss":issuer,"aud":"oauth-hosted","sub":"alice","roles":["members"],
                        "iat":now,"exp":now+3600,"nonce":code,
                    }).to_string());
                    let input = format!("{header}.{claims}");
                    let signature = signing_key.sign(&ring::rand::SystemRandom::new(),input.as_bytes()).expect("sign actual IdP token");
                    let token = format!("{input}.{}",b64.encode(signature.as_ref()));
                    ("200 OK",serde_json::json!({"token_type":"Bearer","access_token":"local-oidc-access","id_token":token}).to_string())
                } else {
                    ("404 Not Found", "{}".into())
                };
                let _ = write!(stream,
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len());
                let _ = stream.flush();
                stream.conn.send_close_notify();
                let _ = stream.flush();
            }
        });
        Idp { jwks_url, certificate: cert_pem, exchanges }
    })
}

pub fn cert_pem() -> &'static str {
    &idp().certificate
}

pub fn settings(audience: &str) -> serde_json::Map<String, serde_json::Value> {
    serde_json::json!({
        "issuer": idp().jwks_url.trim_end_matches("/jwks"),
        "audience": audience,
        "jwks_url": idp().jwks_url,
        "ca_cert_pem": cert_pem(),
        "role_claim": "roles",
        "authorization_endpoint": format!("{}/authorize", idp().jwks_url.trim_end_matches("/jwks")),
        "token_endpoint": format!("{}/token", idp().jwks_url.trim_end_matches("/jwks")),
    })
    .as_object()
    .expect("OIDC settings")
    .clone()
}

pub fn exchanges_for(code: &str) -> usize {
    idp()
        .exchanges
        .lock()
        .unwrap()
        .get(code)
        .copied()
        .unwrap_or(0)
}
