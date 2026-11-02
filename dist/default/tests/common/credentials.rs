// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::path::Path;

// A single OIDC input for these distribution tests. Both the public key document and
// the tokens come from this key; the plugin fetches the document over a real TLS socket.
const ISSUER: &str = "https://issuer.e2e.invalid";
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

/// Start the local IdP before launching a distribution process.
pub fn issuer() {
    let _ = idp();
}

pub fn cert_pem() -> &'static str {
    &idp().2
}

pub fn settings(audience: &str) -> serde_json::Map<String, serde_json::Value> {
    serde_json::json!({
        "issuer": ISSUER,
        "audience": audience,
        "jwks_url": idp().1,
        "ca_cert_pem": cert_pem(),
        "role_claim": "roles",
        "authorization_endpoint": format!("{ISSUER}/authorize"),
        "token_endpoint": format!("{ISSUER}/token"),
    })
    .as_object()
    .expect("OIDC settings")
    .clone()
}

pub fn token_for(sub: &str, roles: &[&str], aud: &str) -> String {
    use base64::Engine as _;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock")
        .as_secs();
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header = b64.encode(
        serde_json::to_vec(&serde_json::json!({
            "alg": "ES256", "typ": "JWT", "kid": KEY_ID,
        }))
        .expect("JWT header"),
    );
    let claims = b64.encode(
        serde_json::to_vec(&serde_json::json!({
            "iss": ISSUER, "aud": aud, "sub": sub, "roles": roles,
            "exp": now + 3600, "nbf": now.saturating_sub(10),
        }))
        .expect("JWT claims"),
    );
    let signed = format!("{header}.{claims}");
    let signature = idp()
        .0
        .sign(&ring::rand::SystemRandom::new(), signed.as_bytes())
        .expect("sign the IdP token");
    format!("{signed}.{}", b64.encode(signature.as_ref()))
}

pub fn issuer_settings_yaml(audience: &str, indent: usize) -> String {
    settings(audience)
        .into_iter()
        .map(|(k, v)| format!("{}{k}: {v}\n", " ".repeat(indent)))
        .collect()
}

pub const HARNESS_FIRST_PARTY_KEY_ENV: &str = "BUSBAR_TEST_HARNESS_FIRST_PARTY_KEY";

pub fn harness_release_key() -> busbar_plugin_loader::sign::SigningKey {
    super::plugins::key(0x5a)
}

pub fn harness_release_key_hex() -> String {
    hex::encode(harness_release_key().verifying_key().as_bytes())
}

pub fn install_auth_plugin(plugins_dir: &Path, module: &str, alias: &str, first_party: bool) {
    let lib = super::plugins::token_verifier_cdylib_path()
        .and_then(|p| std::fs::read(p).ok())
        .unwrap_or_else(|| {
            super::plugins::missing(
                "pinned token-verifying `kind: auth` plugin's",
                super::plugins::BUILD_PINNED,
            )
        });
    let publisher = if first_party {
        busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER
    } else {
        "third-party"
    };
    let mut m = super::plugins::manifest("auth", module, publisher);
    m.alias = alias.into();

    static STAGED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let path = std::env::temp_dir().join(format!(
        "busbar-auth-module-{}-{}{}",
        std::process::id(),
        STAGED.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        std::env::consts::DLL_SUFFIX
    ));
    std::fs::write(&path, &lib).expect("stage the library");
    m.statement = busbar_plugin_loader::dispatch::rendering_of_library(&path)
        .expect("the token-verifying cdylib states its door")
        .map(hex::encode);
    let _ = std::fs::remove_file(&path);
    let bytes = if first_party {
        super::plugins::signed(&harness_release_key(), m, &lib)
    } else {
        super::plugins::signed(&super::plugins::key(0x33), m, &lib)
    };
    std::fs::create_dir_all(plugins_dir).expect("the plugins dir");
    std::fs::write(plugins_dir.join(format!("{module}.tar.gz")), bytes).expect("write the tarball");
}

pub fn generate_signing_key() -> ([u8; 32], String) {
    let out = std::process::Command::new(super::boot::exe())
        .arg("--generate-signing-key")
        .output()
        .expect("run busbar --generate-signing-key");
    assert!(out.status.success(), "--generate-signing-key failed");
    let hex_key = String::from_utf8(out.stdout)
        .expect("the key is text")
        .trim()
        .to_string();
    let bytes: [u8; 32] = hex::decode(&hex_key)
        .expect("the signing key is hex")
        .try_into()
        .expect("the signing key is 32 bytes");
    (bytes, hex_key)
}

pub fn bind_key(secret: &[u8; 32], plain: &str, audience: &str) -> String {
    use base64::Engine as _;
    use ed25519_dalek::Signer as _;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let body = plain
        .strip_prefix("bbk_")
        .unwrap_or_else(|| panic!("not a busbar key: {plain}"));
    let payload = body.split('.').next().expect("a payload");
    let claims: serde_json::Value =
        serde_json::from_slice(&b64.decode(payload).expect("base64 claims")).expect("JSON claims");
    let mut bound = serde_json::json!({
        "sub": claims["sub"],
        "exp": claims["exp"],
        "kid": claims["kid"],
        "a": audience,
    });
    if let Some(g) = claims.get("g") {
        bound["g"] = g.clone();
    }
    let raw = serde_json::to_vec(&bound).expect("claims serialize");
    let sig = ed25519_dalek::SigningKey::from_bytes(secret).sign(&raw);
    format!("bbk_{}.{}", b64.encode(&raw), b64.encode(sig.to_bytes()))
}
