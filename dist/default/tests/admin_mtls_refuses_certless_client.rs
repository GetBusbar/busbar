// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ADMIN LISTENER WITH `admin_tls.client_ca` REFUSES A CLIENT THAT OFFERS NO CERTIFICATE, end
//! to end: over the REAL binary, mutual TLS on `admin_listen` is enforced at the handshake, before
//! any HTTP and before the admin credential is looked at. The unit cells prove the rustls
//! config (`busbar_core_connector::tls`) and the boot guard (`admin_plane_boot_guard`); this is the
//! one cell that boots a node with `admin_tls.client_ca` and speaks to its admin port as a client.
//!
//! Four clients, one node: a client with a certificate from the named CA is answered (and the node
//! is up), a client that offers no certificate is refused, a client whose certificate chains to a
//! different CA is refused, and a client speaking plaintext to the admin port is given no HTTP
//! answer. The admin token is presented by every client, so what refuses the three is the handshake
//! and not the credential.
#![cfg(unix)]
// The fixture boots a REAL server with a provider row, as root_listeners_are_the_connectors.rs gates.
#![cfg(linked_section_pools)]

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

/// The admin surface's token.
const ADMIN_TOKEN: &str = "admin-mtls-certless-token";

fn fixture_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!("busbar-admin-mtls-{}-{}", std::process::id(), {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        format!(
            "{}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos()),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        )
    }));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A CA and a leaf it signs for `sans`: (ca_pem, leaf_pem, leaf_key_pem).
fn ca_and_leaf(sans: &[&str]) -> (String, String, String) {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_pem = ca_params.self_signed(&ca_key).unwrap().pem();
    let issuer = rcgen::Issuer::from_params(&ca_params, ca_key);
    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let leaf =
        rcgen::CertificateParams::new(sans.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>())
            .unwrap()
            .signed_by(&leaf_key, &issuer)
            .unwrap();
    (ca_pem, leaf.pem(), leaf_key.serialize_pem())
}

/// Kill the child when the test ends, however it ends.
struct Reap(Child);
impl Drop for Reap {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn log(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("out.log")).unwrap_or_default()
}

/// A reqwest client trusting `server_ca_pem`, presenting `identity` (leaf then key) when given.
fn client(server_ca_pem: &str, identity: Option<(&str, &str)>) -> reqwest::Client {
    let mut builder = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(server_ca_pem.as_bytes()).unwrap())
        .use_rustls_tls()
        .timeout(Duration::from_secs(10));
    if let Some((leaf, key)) = identity {
        builder = builder
            .identity(reqwest::Identity::from_pem(format!("{leaf}{key}").as_bytes()).unwrap());
    }
    builder.build().unwrap()
}

#[test]
fn admin_listener_with_admin_tls_client_ca_rejects_certless_client() {
    let dir = fixture_dir();
    // The admin listener's own certificate (self-signed, trusted by the clients as a root) and the
    // CA its clients' certificates must chain to.
    let server_key = rcgen::KeyPair::generate().unwrap();
    let server_cert = rcgen::CertificateParams::new(vec!["127.0.0.1".to_owned()])
        .unwrap()
        .self_signed(&server_key)
        .unwrap();
    let server_pem = server_cert.pem();
    let (client_ca, client_leaf, client_key) = ca_and_leaf(&["busbar-admin-client"]);
    let (_other_ca, other_leaf, other_key) = ca_and_leaf(&["impostor"]);
    for (name, pem) in [
        ("admin-cert.pem", server_pem.clone()),
        ("admin-key.pem", server_key.serialize_pem()),
        ("admin-ca.pem", client_ca.clone()),
    ] {
        std::fs::write(dir.join(name), pem).unwrap();
    }
    std::fs::write(
        dir.join("providers.yaml"),
        include_str!("fixtures/mock_provider.yaml"),
    )
    .unwrap();
    let (data, admin) = (common::boot::free_port(), common::boot::free_port());
    // `admin_require_mtls` is left at its default (on): the node serves the admin port only with a
    // client CA named.
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            r#"listen: "127.0.0.1:{data}"
admin_listen: "127.0.0.1:{admin}"
admin_tls:
  cert: {{ file: '{cert}' }}
  key: {{ file: '{key}' }}
  client_ca: {{ file: '{ca}' }}
store: {{module: memory}}
identity-providers:
  admin-tokens:
    module: admin-tokens
    token: {{ env: BUSBAR_ADMIN_TOKEN }}
auth:
  chain: []
  admin_auth:
    - admin-tokens
providers:
  mock:
    api_key: {{ env: MOCK_KEY }}
models:
  test-model:
    provider: mock
"#,
            cert = dir.join("admin-cert.pem").display(),
            key = dir.join("admin-key.pem").display(),
            ca = dir.join("admin-ca.pem").display(),
        ),
    )
    .unwrap();

    let out = std::fs::File::create(dir.join("out.log")).unwrap();
    let mut node = Reap(
        Command::new(common::boot::exe())
            .env("BUSBAR_CONFIG", dir.join("config.yaml"))
            .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
            .env("MOCK_KEY", "x")
            .env("BUSBAR_ADMIN_TOKEN", ADMIN_TOKEN)
            .stdout(out.try_clone().unwrap())
            .stderr(out)
            .spawn()
            .expect("spawn the server"),
    );

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let url = format!("https://127.0.0.1:{admin}/api/v1/admin/openapi.json");
        let token = format!("Bearer {ADMIN_TOKEN}");
        let valid = client(&server_pem, Some((&client_leaf, &client_key)));

        // The node is up when a client with a certificate from the named CA is answered.
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(s) = node.0.try_wait().expect("try_wait") {
                panic!("the server exited ({s:?}); log:\n{}", log(&dir));
            }
            match valid.get(&url).header("authorization", &token).send().await {
                Ok(r) => {
                    assert_eq!(
                        r.status().as_u16(),
                        200,
                        "a client whose certificate chains to admin_tls.client_ca is served"
                    );
                    break;
                }
                Err(e) => assert!(
                    Instant::now() < deadline,
                    "the admin listener never answered a valid client ({e}); log:\n{}",
                    log(&dir)
                ),
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // A client that trusts the server and presents the admin token but NO certificate is
        // refused at the handshake: no HTTP response of any status.
        let certless = client(&server_pem, None)
            .get(&url)
            .header("authorization", &token)
            .send()
            .await;
        assert!(
            certless.is_err(),
            "a certless client was answered: {:?}",
            certless.map(|r| r.status())
        );
        // So is one whose certificate chains to a different CA.
        let impostor = client(&server_pem, Some((&other_leaf, &other_key)))
            .get(&url)
            .header("authorization", &token)
            .send()
            .await;
        assert!(
            impostor.is_err(),
            "a client certificate from another CA was answered: {:?}",
            impostor.map(|r| r.status())
        );
        // Plaintext HTTP to the admin port is given no HTTP answer.
        let mut plain = TcpStream::connect(("127.0.0.1", admin)).unwrap();
        plain
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let _ = plain.write_all(
            format!(
                "GET /api/v1/admin/openapi.json HTTP/1.1\r\nHost: 127.0.0.1\r\n\
                 Authorization: {token}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        );
        let mut got = Vec::new();
        let _ = plain.read_to_end(&mut got);
        assert!(
            !got.starts_with(b"HTTP/"),
            "plaintext to the TLS admin port got an HTTP answer: {:?}",
            String::from_utf8_lossy(&got)
        );

        // The refusals did not take the listener down: the valid client is still served.
        let again = valid
            .get(&url)
            .header("authorization", &token)
            .send()
            .await
            .expect("the admin listener serves a valid client after refusing the others");
        assert_eq!(again.status().as_u16(), 200);
    });
    drop(node);
    let _ = std::fs::remove_dir_all(&dir);
}
