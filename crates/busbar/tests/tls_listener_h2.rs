// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TLS LISTENER SERVES HTTP/2 TO A CLIENT THAT OFFERS IT (OWNER RULING Q137, 2026-10-04: "offers
//! h2 on the TLS listener. yes why not?"), end to end over the production pieces: the connector's
//! `tls::prepare` builds the listener's wrap from a `tls:` block, the kernel's `tls::serve` runs the
//! accept loop and the hardened auto builder, and a real rustls client speaks to it.
//!
//! * a client offering `h2` negotiates `h2` and is SERVED HTTP/2, not merely advertised it;
//! * a client offering only `http/1.1` negotiates `http/1.1` and is served HTTP/1.1, as in 1.5.5.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::routing::get;
use axum::Router;
use busbar_kernel::config::secret::SecretResolver;
use busbar_kernel::config::sections::TlsCfg;
use busbar_kernel::config::SecretRef;
use rustls::pki_types::pem::PemObject;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A scratch directory of this process's own for one test's PEM files.
fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("busbar-tls-h2-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

/// A self-signed `localhost` identity written to two PEM files; the certificate PEM for the client.
fn identity(dir: &std::path::Path) -> (TlsCfg, String) {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("a test cert");
    let cert_pem = cert.pem();
    let cert_file = dir.join("cert.pem");
    let key_file = dir.join("key.pem");
    std::fs::write(&cert_file, &cert_pem).expect("write cert");
    std::fs::write(&key_file, signing_key.serialize_pem()).expect("write key");
    let tls = TlsCfg {
        cert: SecretRef::file(cert_file.to_string_lossy().into_owned()),
        key: SecretRef::file(key_file.to_string_lossy().into_owned()),
        client_ca: None,
    };
    (tls, cert_pem)
}

/// The listener a `tls:` block brings up, serving `/healthz`, on an ephemeral port.
async fn tls_listener(tls: &TlsCfg) -> (SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let security = busbar_core_connector::tls::prepare(
        "h2-listener",
        Some(tls),
        &SecretResolver::builtins_only(),
        true,
    )
    .expect("a valid tls: block over a capable transport");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let router = Router::new().route("/healthz", get(|| async { "ok" }));
    tokio::spawn(async move {
        let shutdown = async {
            let _ = stopped.await;
        };
        busbar_kernel::tls::serve(listener, router, security, shutdown, None)
            .await
            .expect("serve");
    });
    (addr, stop)
}

/// A TLS client to `addr` trusting `cert_pem` and offering exactly `protocols` over ALPN.
async fn connect(
    addr: SocketAddr,
    cert_pem: &str,
    protocols: &[&[u8]],
) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls::pki_types::CertificateDer::pem_slice_iter(cert_pem.as_bytes()) {
        roots.add(cert.expect("cert PEM")).expect("root");
    }
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("protocol versions")
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = protocols.iter().map(|p| p.to_vec()).collect();
    let tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
    tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(
            rustls::pki_types::ServerName::try_from("localhost").expect("name"),
            tcp,
        )
        .await
        .expect("the handshake completes")
}

#[tokio::test]
async fn a_client_offering_h2_is_served_http2_over_tls() {
    let dir = scratch("h2");
    let (tls, cert_pem) = identity(&dir);
    let (addr, _stop) = tls_listener(&tls).await;

    let stream = connect(addr, &cert_pem, &[b"h2", b"http/1.1"]).await;
    assert_eq!(
        stream.get_ref().1.alpn_protocol(),
        Some(&b"h2"[..]),
        "the listener offers h2 (owner ruling Q137)"
    );
    let (mut send, conn) = hyper::client::conn::http2::handshake(
        hyper_util::rt::TokioExecutor::new(),
        hyper_util::rt::TokioIo::new(stream),
    )
    .await
    .expect("the HTTP/2 connection opens");
    tokio::spawn(conn);
    let request = http::Request::get(format!("https://localhost:{}/healthz", addr.port()))
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .expect("request");
    let response = send
        .send_request(request)
        .await
        .expect("the request is served over HTTP/2");
    assert_eq!(response.version(), http::Version::HTTP_2);
    assert_eq!(response.status(), 200);
    let body = http_body_util::BodyExt::collect(response.into_body())
        .await
        .expect("body")
        .to_bytes();
    assert_eq!(&body[..], b"ok");
}

#[tokio::test]
async fn a_client_offering_only_http1_is_served_http1_as_in_1_5_5() {
    let dir = scratch("h1");
    let (tls, cert_pem) = identity(&dir);
    let (addr, _stop) = tls_listener(&tls).await;

    let mut stream = connect(addr, &cert_pem, &[b"http/1.1"]).await;
    assert_eq!(stream.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n")
        .await
        .expect("write");
    let mut got = Vec::new();
    let _ = stream.read_to_end(&mut got).await;
    let got = String::from_utf8_lossy(&got);
    assert!(got.starts_with("HTTP/1.1 200 OK\r\n"), "{got}");
    assert!(got.ends_with("\r\n\r\nok"), "{got}");
}
