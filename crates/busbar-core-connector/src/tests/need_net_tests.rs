// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The production Need I/O on loopback listeners in this process: plaintext and TLS dials, reads
//! and writes under their deadlines, the pooled-conn health check, STARTTLS, and the trust the
//! client config is built from.

use std::net::SocketAddr;
use std::sync::Arc;

use busbar_contract::crypto::testing::rcgen;
use busbar_contract::secure::SecureVec;
use busbar_kernel::plugin_config::TrustAnchor;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use super::*;

const BUDGET: Duration = Duration::from_secs(5);

async fn listener() -> (TcpListener, SocketAddr) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    (l, addr)
}

fn plain(addrs: &[SocketAddr]) -> Dial<'_> {
    Dial {
        addrs,
        unix: None,
        tls: None,
        timeout: BUDGET,
    }
}

/// A CA and an acceptor for a leaf it signs for `sans`, offering ALPN `h2`.
fn tls_server(sans: &[&str]) -> (Vec<u8>, TlsAcceptor) {
    use busbar_contract::crypto::testing::rcgen::{CertificateParams, IsCa, Issuer, KeyPair};
    let ca_kp = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_kp).unwrap();
    let issuer = Issuer::from_params(&ca_params, ca_kp);
    let leaf_kp = KeyPair::generate().unwrap();
    let leaf_params =
        CertificateParams::new(sans.iter().map(|s| (*s).to_string()).collect::<Vec<_>>()).unwrap();
    let leaf = leaf_params.signed_by(&leaf_kp, &issuer).unwrap();
    let key = PrivateKeyDer::from_pem_slice(leaf_kp.serialize_pem().as_bytes()).unwrap();
    let chain = vec![CertificateDer::from(leaf.der().to_vec())];
    let config = busbar_contract::crypto::tls::server_config(|b| {
        b.with_no_client_auth().with_single_cert(chain, key)
    })
    .unwrap();
    let mut config = Arc::unwrap_or_clone(config);
    config.alpn_protocols = vec![b"h2".to_vec()];
    (ca_cert.der().to_vec(), TlsAcceptor::from(Arc::new(config)))
}

fn anchor(ca: Vec<u8>) -> Arc<TrustAnchor> {
    Arc::new(TrustAnchor {
        der: vec![ca],
        sha256: [7; 32],
    })
}

fn plan<'a>(sni: &'a str, trust: Option<Arc<TrustAnchor>>, waive: bool) -> TlsPlan<'a> {
    TlsPlan {
        sni,
        alpn: "h2",
        trust,
        cert: None,
        waive,
    }
}

/// Echo five bytes over TLS, then hang up.
fn serve_tls_echo(l: TcpListener, acceptor: TlsAcceptor) {
    tokio::spawn(async move {
        let (s, _) = l.accept().await.unwrap();
        let Ok(mut s) = acceptor.accept(s).await else {
            return;
        };
        let mut b = [0u8; 5];
        if s.read_exact(&mut b).await.is_ok() {
            let _ = s.write_all(&b).await;
            let _ = s.flush().await;
        }
    });
}

#[tokio::test]
async fn a_plain_dial_writes_and_reads_what_a_loopback_peer_echoes() {
    let (l, addr) = listener().await;
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        let mut b = [0u8; 5];
        s.read_exact(&mut b).await.unwrap();
        s.write_all(&b).await.unwrap();
    });
    let io = ConnectorIo::new();
    let addrs = [addr];
    let mut d = io.dial(plain(&addrs)).await.unwrap();
    assert_eq!(&*d.alpn, "");
    assert!(!d.resumed);
    assert_eq!(io.write(&mut d.conn, b"hello", BUDGET).await, Ok(5));
    let mut buf = [0u8; 16];
    let n = io.read(&mut d.conn, &mut buf, BUDGET).await.unwrap();
    assert_eq!(&buf[..n], b"hello");
}

#[tokio::test]
async fn a_dial_nobody_answers_is_unavailable() {
    let (l, addr) = listener().await;
    drop(l);
    let io = ConnectorIo::new();
    let addrs = [addr];
    assert_eq!(
        io.dial(plain(&addrs)).await.err(),
        Some(NeedErr::Unavailable)
    );
}

#[tokio::test]
async fn the_next_admitted_address_is_tried_when_the_first_refuses() {
    let (dead, gone) = listener().await;
    drop(dead);
    let (l, addr) = listener().await;
    tokio::spawn(async move {
        let _held = l.accept().await.unwrap();
        tokio::time::sleep(BUDGET).await;
    });
    let io = ConnectorIo::new();
    let addrs = [gone, addr];
    assert!(io.dial(plain(&addrs)).await.is_ok());
}

#[tokio::test]
async fn a_dial_with_nowhere_to_go_is_invalid() {
    let io = ConnectorIo::new();
    assert_eq!(io.dial(plain(&[])).await.err(), Some(NeedErr::Invalid));
}

#[tokio::test]
async fn a_read_the_peer_never_answers_times_out() {
    let (l, addr) = listener().await;
    tokio::spawn(async move {
        let _held = l.accept().await.unwrap();
        tokio::time::sleep(BUDGET).await;
    });
    let io = ConnectorIo::new();
    let addrs = [addr];
    let mut d = io.dial(plain(&addrs)).await.unwrap();
    let mut buf = [0u8; 8];
    let got = io
        .read(&mut d.conn, &mut buf, Duration::from_millis(50))
        .await;
    assert_eq!(got, Err(NeedErr::Timeout));
}

#[tokio::test]
async fn a_peer_that_hangs_up_reads_as_end_of_stream() {
    let (l, addr) = listener().await;
    tokio::spawn(async move {
        drop(l.accept().await.unwrap());
    });
    let io = ConnectorIo::new();
    let addrs = [addr];
    let mut d = io.dial(plain(&addrs)).await.unwrap();
    let mut buf = [0u8; 8];
    assert_eq!(io.read(&mut d.conn, &mut buf, BUDGET).await, Ok(0));
}

#[tokio::test]
async fn a_conn_is_healthy_only_while_idle_and_open() {
    let (l, addr) = listener().await;
    let (go, wake) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        let _ = wake.await;
        s.write_all(b"x").await.unwrap();
        // Then hold it open until the test is done with it.
        tokio::time::sleep(BUDGET).await;
    });
    let io = ConnectorIo::new();
    let addrs = [addr];
    let d = io.dial(plain(&addrs)).await.unwrap();
    assert!(
        io.healthy(&d.conn),
        "a fresh conn with nothing waiting is good"
    );
    go.send(()).unwrap();
    let mut spent = 0;
    while io.healthy(&d.conn) {
        spent += 1;
        assert!(spent < 400, "the unread byte never showed");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[tokio::test]
async fn a_conn_the_peer_closed_is_not_healthy() {
    let (l, addr) = listener().await;
    tokio::spawn(async move {
        drop(l.accept().await.unwrap());
    });
    let io = ConnectorIo::new();
    let addrs = [addr];
    let d = io.dial(plain(&addrs)).await.unwrap();
    let mut spent = 0;
    while io.healthy(&d.conn) {
        spent += 1;
        assert!(spent < 400, "the close never showed");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[tokio::test]
async fn a_tls_dial_trusts_the_anchor_the_need_binds_and_negotiates_its_alpn() {
    let (ca, acceptor) = tls_server(&["upstream.test"]);
    let (l, addr) = listener().await;
    serve_tls_echo(l, acceptor);
    let io = ConnectorIo::new();
    let addrs = [addr];
    let mut d = io
        .dial(Dial {
            addrs: &addrs,
            unix: None,
            tls: Some(plan("upstream.test", Some(anchor(ca)), false)),
            timeout: BUDGET,
        })
        .await
        .unwrap();
    assert_eq!(&*d.alpn, "h2");
    assert_eq!(io.write(&mut d.conn, b"hello", BUDGET).await, Ok(5));
    let mut buf = [0u8; 16];
    let n = io.read(&mut d.conn, &mut buf, BUDGET).await.unwrap();
    assert_eq!(&buf[..n], b"hello");
}

#[tokio::test]
async fn a_tls_dial_without_the_anchor_does_not_trust_a_private_ca() {
    let (_ca, acceptor) = tls_server(&["upstream.test"]);
    let (l, addr) = listener().await;
    serve_tls_echo(l, acceptor);
    let io = ConnectorIo::new();
    let addrs = [addr];
    let got = io
        .dial(Dial {
            addrs: &addrs,
            unix: None,
            tls: Some(plan("upstream.test", None, false)),
            timeout: BUDGET,
        })
        .await;
    assert_eq!(got.err(), Some(NeedErr::Tls));
}

#[tokio::test]
async fn a_tls_dial_is_verified_against_the_name_it_asked_for() {
    let (ca, acceptor) = tls_server(&["upstream.test"]);
    let (l, addr) = listener().await;
    serve_tls_echo(l, acceptor);
    let io = ConnectorIo::new();
    let addrs = [addr];
    let got = io
        .dial(Dial {
            addrs: &addrs,
            unix: None,
            tls: Some(plan("other.test", Some(anchor(ca)), false)),
            timeout: BUDGET,
        })
        .await;
    assert_eq!(got.err(), Some(NeedErr::Tls));
}

#[tokio::test]
async fn only_a_held_accept_waives_verification() {
    let (_ca, acceptor) = tls_server(&["upstream.test"]);
    let (l, addr) = listener().await;
    serve_tls_echo(l, acceptor);
    let io = ConnectorIo::new();
    let addrs = [addr];
    let mut d = io
        .dial(Dial {
            addrs: &addrs,
            unix: None,
            tls: Some(plan("elsewhere.test", None, true)),
            timeout: BUDGET,
        })
        .await
        .unwrap();
    assert_eq!(io.write(&mut d.conn, b"hello", BUDGET).await, Ok(5));
}

#[tokio::test]
async fn a_peer_that_does_not_speak_tls_is_a_tls_failure() {
    let (l, addr) = listener().await;
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        let _ = s.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
        tokio::time::sleep(BUDGET).await;
    });
    let io = ConnectorIo::new();
    let addrs = [addr];
    let got = io
        .dial(Dial {
            addrs: &addrs,
            unix: None,
            tls: Some(plan("upstream.test", None, false)),
            timeout: BUDGET,
        })
        .await;
    assert_eq!(got.err(), Some(NeedErr::Tls));
}

#[tokio::test]
async fn starttls_upgrades_the_plain_conn_in_place() {
    let (ca, acceptor) = tls_server(&["upstream.test"]);
    let (l, addr) = listener().await;
    serve_tls_echo(l, acceptor);
    let io = ConnectorIo::new();
    let addrs = [addr];
    let d = io.dial(plain(&addrs)).await.unwrap();
    let mut up = io
        .upgrade(
            d.conn,
            plan("upstream.test", Some(anchor(ca)), false),
            BUDGET,
        )
        .await
        .unwrap();
    assert_eq!(&*up.alpn, "h2");
    assert_eq!(io.write(&mut up.conn, b"hello", BUDGET).await, Ok(5));
    let mut buf = [0u8; 16];
    let n = io.read(&mut up.conn, &mut buf, BUDGET).await.unwrap();
    assert_eq!(&buf[..n], b"hello");
}

#[tokio::test]
async fn a_conn_that_is_already_tls_cannot_be_upgraded_again() {
    let (ca, acceptor) = tls_server(&["upstream.test"]);
    let (l, addr) = listener().await;
    serve_tls_echo(l, acceptor);
    let io = ConnectorIo::new();
    let addrs = [addr];
    let secured = io
        .dial(Dial {
            addrs: &addrs,
            unix: None,
            tls: Some(plan("upstream.test", Some(anchor(ca.clone())), false)),
            timeout: BUDGET,
        })
        .await
        .unwrap();
    let again = io
        .upgrade(
            secured.conn,
            plan("upstream.test", Some(anchor(ca)), false),
            BUDGET,
        )
        .await;
    assert_eq!(again.err(), Some(NeedErr::Invalid));
}

#[test]
fn a_waiver_with_a_client_certificate_is_refused_not_silently_anonymous() {
    let mut p = plan("upstream.test", None, true);
    p.cert = Some(Arc::new(SecureVec::from(&b"not a pem"[..])));
    assert_eq!(
        Configs::default().get(&p, &[]).err(),
        Some(NeedErr::Invalid)
    );
}

#[test]
fn a_client_certificate_that_does_not_parse_is_invalid() {
    let mut p = plan("upstream.test", None, false);
    p.cert = Some(Arc::new(SecureVec::from(&b"not a pem"[..])));
    assert_eq!(
        Configs::default().get(&p, &[]).err(),
        Some(NeedErr::Invalid)
    );
}

#[test]
fn a_config_is_built_once_per_trust_and_alpn() {
    let configs = Configs::default();
    let p = plan("upstream.test", None, false);
    let alpn = [b"h2".to_vec()];
    let first = configs.get(&p, &alpn).unwrap();
    assert!(Arc::ptr_eq(&first, &configs.get(&p, &alpn).unwrap()));
    assert_eq!(first.alpn_protocols, vec![b"h2".to_vec()]);
    let other = configs.get(&p, &[]).unwrap();
    assert!(!Arc::ptr_eq(&first, &other));
    assert!(other.alpn_protocols.is_empty());
}
