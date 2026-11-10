// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::net::SocketAddr;
use std::sync::Arc;

use axum::routing::get;
use axum::Router;
use rustls::pki_types::pem::PemObject;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn identity() -> (super::tests::TlsFixture, String) {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("a test cert");
    let cert_pem = cert.pem();
    let tls = super::tests::tls_fixture(&cert_pem, &signing_key.serialize_pem(), None);
    (tls, cert_pem)
}

async fn tls_listener(
    tls: &super::tests::TlsFixture,
) -> (SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let security = busbar_core_connector::tls::prepare(
        "h2-listener",
        Some(&tls.config),
        &super::tests::tls_fixture_resolver(tls),
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
        super::serve(listener, router, security, shutdown, None)
            .await
            .expect("serve");
    });
    (addr, stop)
}

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
    let socket = tokio::net::TcpStream::connect(addr).await.expect("connect");
    tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(
            rustls::pki_types::ServerName::try_from("localhost").expect("name"),
            socket,
        )
        .await
        .expect("the handshake completes")
}

#[tokio::test]
async fn a_client_offering_h2_is_served_http2_over_tls() {
    let (tls, cert_pem) = identity();
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
    let (tls, cert_pem) = identity();
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
