// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::path::Path;

pub fn issuer() -> &'static busbar_test_kit::test_issuer::Issuer {
    static ONE: std::sync::OnceLock<busbar_test_kit::test_issuer::Issuer> =
        std::sync::OnceLock::new();
    ONE.get_or_init(|| {
        let issuer =
            busbar_test_kit::test_issuer::Issuer::start("https://issuer.e2e.invalid", "e2e-issuer");
        let (url, cert_pem) = serve_jwks(issuer.jwks().to_string());
        issuer.served_at(&url, &cert_pem)
    })
}

pub fn serve_jwks(jwks: String) -> (String, String) {
    use std::io::{Read as _, Write as _};
    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()])
        .expect("mint a self-signed certificate");
    let cert_pem = cert.cert.pem();
    let private = rustls_pki_types::PrivateKeyDer::Pkcs8(
        rustls_pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()),
    );
    let config = std::sync::Arc::new(
        rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert.der().clone()], private)
        .expect("server certificate"),
    );
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a loopback port");
    let url = format!(
        "https://{}/jwks",
        listener.local_addr().expect("local addr")
    );
    std::thread::spawn(move || {
        for socket in listener.incoming() {
            let (Ok(socket), Ok(session)) = (socket, rustls::ServerConnection::new(config.clone()))
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
    (url, cert_pem)
}

pub fn token_for(sub: &str, roles: &[&str], aud: &str) -> String {
    issuer().mint(sub, roles, aud)
}

pub fn issuer_settings_yaml(audience: &str, indent: usize) -> String {
    issuer()
        .settings(audience)
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
