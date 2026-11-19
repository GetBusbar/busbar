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
        instance: 7,
        dest: "upstream.test:443",
        route: super::super::judge::Route {
            addrs: addrs.to_vec(),
            tunnel: None,
        },
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
    let io = test_io();
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
    let io = test_io();
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
    let io = test_io();
    let addrs = [gone, addr];
    assert!(io.dial(plain(&addrs)).await.is_ok());
}

#[tokio::test]
async fn a_dial_with_nowhere_to_go_is_invalid() {
    let io = test_io();
    assert_eq!(io.dial(plain(&[])).await.err(), Some(NeedErr::Invalid));
}

#[tokio::test]
async fn a_read_the_peer_never_answers_times_out() {
    let (l, addr) = listener().await;
    tokio::spawn(async move {
        let _held = l.accept().await.unwrap();
        tokio::time::sleep(BUDGET).await;
    });
    let io = test_io();
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
    let io = test_io();
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
    let io = test_io();
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
    let io = test_io();
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
    let io = test_io();
    let addrs = [addr];
    let mut d = io
        .dial(Dial {
            instance: 7,
            dest: "upstream.test:443",
            route: super::super::judge::Route {
                addrs: addrs.to_vec(),
                tunnel: None,
            },
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
    let io = test_io();
    let addrs = [addr];
    let got = io
        .dial(Dial {
            instance: 7,
            dest: "upstream.test:443",
            route: super::super::judge::Route {
                addrs: addrs.to_vec(),
                tunnel: None,
            },
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
    let io = test_io();
    let addrs = [addr];
    let got = io
        .dial(Dial {
            instance: 7,
            dest: "upstream.test:443",
            route: super::super::judge::Route {
                addrs: addrs.to_vec(),
                tunnel: None,
            },
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
    let io = test_io();
    let addrs = [addr];
    let mut d = io
        .dial(Dial {
            instance: 7,
            dest: "upstream.test:443",
            route: super::super::judge::Route {
                addrs: addrs.to_vec(),
                tunnel: None,
            },
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
    let io = test_io();
    let addrs = [addr];
    let got = io
        .dial(Dial {
            instance: 7,
            dest: "upstream.test:443",
            route: super::super::judge::Route {
                addrs: addrs.to_vec(),
                tunnel: None,
            },
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
    let io = test_io();
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
    let io = test_io();
    let addrs = [addr];
    let secured = io
        .dial(Dial {
            instance: 7,
            dest: "upstream.test:443",
            route: super::super::judge::Route {
                addrs: addrs.to_vec(),
                tunnel: None,
            },
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
        test_configs().get("upstream.test", &p, &[]).err(),
        Some(NeedErr::Invalid)
    );
}

#[test]
fn a_client_certificate_that_does_not_parse_is_invalid() {
    let mut p = plan("upstream.test", None, false);
    p.cert = Some(Arc::new(SecureVec::from(&b"not a pem"[..])));
    assert_eq!(
        test_configs().get("upstream.test", &p, &[]).err(),
        Some(NeedErr::Invalid)
    );
}

#[test]
fn a_config_is_built_once_per_trust_and_alpn() {
    let configs = test_configs();
    let p = plan("upstream.test", None, false);
    let alpn = [b"h2".to_vec()];
    let first = configs.get("upstream.test", &p, &alpn).unwrap();
    assert!(Arc::ptr_eq(
        &first,
        &configs.get("upstream.test", &p, &alpn).unwrap()
    ));
    assert_eq!(first.alpn_protocols, vec![b"h2".to_vec()]);
    let other = configs.get("upstream.test", &p, &[]).unwrap();
    assert!(!Arc::ptr_eq(&first, &other));
    assert!(other.alpn_protocols.is_empty());
}

fn test_configs() -> Configs {
    Configs::new(Arc::new(
        crate::tls::store::TrustStore::build(
            &Default::default(),
            std::time::SystemTime::now(),
            &|_| None,
        )
        .expect("test trust"),
    ))
}

#[test]
fn ordered_alpn_protocol_boundaries_never_alias_in_native_cache() {
    let configs = test_configs();
    let p = plan("upstream.test", None, false);
    let first = configs
        .get("upstream.test", &p, &[b"ab".to_vec(), b"c".to_vec()])
        .unwrap();
    let second = configs
        .get("upstream.test", &p, &[b"a".to_vec(), b"bc".to_vec()])
        .unwrap();
    assert!(!Arc::ptr_eq(&first, &second));
    assert_eq!(second.alpn_protocols, [b"a".to_vec(), b"bc".to_vec()]);
}

fn operator_io(ca: &[u8]) -> ConnectorIo {
    use base64::Engine as _;
    let pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        base64::engine::general_purpose::STANDARD.encode(ca)
    );
    let cfg = busbar_contract::yaml::from_str(&format!(
        "roots: none\ndestinations:\n  - match: upstream.test\n    trust_anchors: [{pem:?}]\n"
    ))
    .expect("TLS config");
    let trust = Arc::new(
        crate::tls::store::TrustStore::build(&cfg, std::time::SystemTime::now(), &|_| None)
            .expect("operator CA"),
    );
    super::super::network::BootstrapConnector::new(super::super::network::NetworkInputs {
        runtime: tokio::runtime::Handle::current(),
        guard: crate::guard::Guard::default().freeze(),
        resolver: Arc::new(crate::guard::SystemResolver),
        trust,
        proxy: None,
        resolution: busbar_kernel::config::tls::ProxyResolution::Local,
        observations: Arc::default(),
    })
    .io()
}

#[tokio::test]
async fn configured_operator_trust_carries_native_open_write_read_by_logical_host() {
    let (ca, acceptor) = tls_server(&["separate-sni.test"]);
    let (l, addr) = listener().await;
    let (unmatched_listener, unmatched_addr) = listener().await;
    serve_tls_echo(unmatched_listener, acceptor.clone());
    serve_tls_echo(l, acceptor);
    let io = operator_io(&ca);
    let addrs = [addr];
    let mut dial = plain(&addrs);
    dial.tls = Some(plan("separate-sni.test", None, false));
    let mut held = io
        .dial(dial)
        .await
        .expect("configured operator CA without instance roots");
    assert_eq!(io.write(&mut held.conn, b"store", BUDGET).await.unwrap(), 5);
    let mut bytes = [0; 5];
    let mut read = 0;
    while read < bytes.len() {
        let n = io
            .read(&mut held.conn, &mut bytes[read..], BUDGET)
            .await
            .unwrap();
        assert_ne!(n, 0, "TLS peer ended before the command echo");
        read += n;
    }
    assert_eq!(&bytes, b"store");
    let unmatched_addrs = [unmatched_addr];
    let mut unmatched = plain(&unmatched_addrs);
    unmatched.dest = "unconfigured.test:443";
    unmatched.tls = Some(plan("separate-sni.test", None, false));
    assert_eq!(
        io.dial(unmatched).await.err(),
        Some(NeedErr::Tls),
        "offered SNI never selects the logical host's policy"
    );
    let observed = io.state.observations.drain();
    assert!(observed
        .facts
        .iter()
        .any(|fact| fact.owner == Some(7)
            && fact.outcome == super::super::observations::Outcome::Tls));
}

#[tokio::test]
async fn native_proxy_open_preserves_tunnel_prefix_and_confines_credentials() {
    let (listener, addr) = listener().await;
    let task = tokio::spawn(async move {
        let (mut peer, _) = listener.accept().await.unwrap();
        let mut head = Vec::new();
        let mut byte = [0];
        while !head.ends_with(b"\r\n\r\n") {
            peer.read_exact(&mut byte).await.unwrap();
            head.push(byte[0]);
        }
        assert!(head.starts_with(b"CONNECT 93.184.216.34:1234 HTTP/1.1\r\n"));
        assert!(String::from_utf8(head)
            .unwrap()
            .contains("Proxy-Authorization: Basic proxy-only"));
        peer.write_all(b"HTTP/1.1 200 Connected\r\n\r\ngreeting")
            .await
            .unwrap();
        let mut request = [0; 4];
        peer.read_exact(&mut request).await.unwrap();
        assert_eq!(
            &request, b"ping",
            "proxy credential is not written into origin protocol"
        );
        peer.write_all(&request).await.unwrap();
    });
    let io = test_io();
    let route = super::super::judge::Route {
        addrs: vec![addr],
        tunnel: Some(super::super::judge::Tunnel {
            hop: Arc::new(crate::proxy::ProxyHop::new(
                addr.ip().to_string(),
                addr.port(),
                Some("Basic proxy-only".into()),
            )),
            target: "93.184.216.34:1234".into(),
        }),
    };
    let mut held = io
        .dial(Dial {
            instance: 7,
            dest: "origin.example:1234",
            route,
            unix: None,
            tls: None,
            timeout: BUDGET,
        })
        .await
        .unwrap();
    let mut greeting = [0; 8];
    let mut read = 0;
    while read < greeting.len() {
        read += io
            .read(&mut held.conn, &mut greeting[read..], BUDGET)
            .await
            .unwrap();
    }
    assert_eq!(&greeting, b"greeting");
    io.write(&mut held.conn, b"ping", BUDGET).await.unwrap();
    let mut reply = [0; 4];
    let mut read = 0;
    while read < reply.len() {
        read += io
            .read(&mut held.conn, &mut reply[read..], BUDGET)
            .await
            .unwrap();
    }
    assert_eq!(&reply, b"ping");
    task.await.unwrap();
}

#[tokio::test]
async fn proxied_ip_literal_verifies_the_origin_address_without_sni() {
    let (ca, acceptor) = tls_server(&["93.184.216.34"]);
    let (listener, addr) = listener().await;
    let task = tokio::spawn(async move {
        let (mut peer, _) = listener.accept().await.unwrap();
        let mut head = Vec::new();
        let mut byte = [0];
        while !head.ends_with(b"\r\n\r\n") {
            peer.read_exact(&mut byte).await.unwrap();
            head.push(byte[0]);
        }
        peer.write_all(b"HTTP/1.1 200 Connected\r\n\r\n")
            .await
            .unwrap();
        let mut tls = acceptor
            .accept(peer)
            .await
            .expect("origin certificate through proxy");
        let mut command = [0; 5];
        tls.read_exact(&mut command).await.unwrap();
        assert_eq!(&command, b"hello");
    });
    let io = test_io();
    let route = super::super::judge::Route {
        addrs: vec![addr],
        tunnel: Some(super::super::judge::Tunnel {
            hop: Arc::new(crate::proxy::ProxyHop::new(
                addr.ip().to_string(),
                addr.port(),
                None,
            )),
            target: "93.184.216.34:443".into(),
        }),
    };
    let mut held = io
        .dial(Dial {
            instance: 7,
            dest: "93.184.216.34:443",
            route,
            unix: None,
            tls: Some(plan("", Some(anchor(ca)), false)),
            timeout: BUDGET,
        })
        .await
        .expect("verification uses logical origin IP, not the proxy socket peer");
    io.write(&mut held.conn, b"hello", BUDGET).await.unwrap();
    task.await.unwrap();
}

/// What a far end in the clear sends where only the upgraded stream may speak (a STARTTLS
/// injection): it must never reach the caller as post-upgrade data.
const FORGED: &[u8] = b"+OK forged in the clear\r\n";

/// A far end that reads `STARTTLS\n` in the clear and answers `OK\n` with [`FORGED`] behind it, in
/// the same segment (`gap` None) or as a segment of its own `gap` later, then speaks TLS.
async fn injecting_far_end(l: TcpListener, acceptor: TlsAcceptor, gap: Option<Duration>) {
    let (mut s, _) = l.accept().await.unwrap();
    let mut asked = [0_u8; 9];
    if s.read_exact(&mut asked).await.is_err() || &asked != b"STARTTLS\n" {
        return;
    }
    match gap {
        None => s.write_all(&[&b"OK\n"[..], FORGED].concat()).await.unwrap(),
        Some(gap) => {
            s.write_all(b"OK\n").await.unwrap();
            s.flush().await.unwrap();
            tokio::time::sleep(gap).await;
            s.write_all(FORGED).await.unwrap();
        }
    }
    s.flush().await.unwrap();
    if let Ok(mut s) = acceptor.accept(s).await {
        let mut b = [0u8; 5];
        if s.read_exact(&mut b).await.is_ok() {
            let _ = s.write_all(&b).await;
            let _ = s.flush().await;
        }
    }
}

/// Wait until clear bytes sit unread on `conn` (buffered by the conn or parked on the line).
async fn until_unread(io: &ConnectorIo, conn: &Stream) {
    let mut spent = 0;
    while io.healthy(conn) {
        spent += 1;
        assert!(spent < 400, "the clear bytes never arrived");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// STARTTLS injection, pipelined: the far end's clear `OK\n` and [`FORGED`] come in one segment and
/// the plugin reads only the three bytes it asked for; and a tunnel prefix (the bytes a proxy sent
/// behind its CONNECT answer, held in `Net::prefix`). The upgrade over unread clear bytes fails and
/// the conn is gone with it: the forged bytes never come back as post-upgrade data.
#[tokio::test]
async fn an_upgrade_over_a_short_reads_unread_rest_is_refused_and_the_stream_fails() {
    // Pipelined behind the clear answer.
    let (ca, acceptor) = tls_server(&["upstream.test"]);
    let (l, addr) = listener().await;
    let far = tokio::spawn(injecting_far_end(l, acceptor, None));
    let io = test_io();
    let addrs = [addr];
    let mut d = io.dial(plain(&addrs)).await.unwrap();
    assert_eq!(io.write(&mut d.conn, b"STARTTLS\n", BUDGET).await, Ok(9));
    let mut ok = [0u8; 3];
    let mut read = 0;
    while read < ok.len() {
        let n = io.read(&mut d.conn, &mut ok[read..], BUDGET).await.unwrap();
        assert_ne!(n, 0, "the far end hung up before its clear answer");
        read += n;
    }
    assert_eq!(&ok, b"OK\n");
    until_unread(&io, &d.conn).await;
    let up = io
        .upgrade(
            d.conn,
            plan("upstream.test", Some(anchor(ca)), false),
            BUDGET,
        )
        .await;
    assert_eq!(
        up.err(),
        Some(NeedErr::Tls),
        "no upgrade over clear bytes still unread"
    );
    let _ = far.await;

    // Held as a tunnel prefix behind the proxy's CONNECT answer.
    let (ca, acceptor) = tls_server(&["upstream.test"]);
    let (l, addr) = listener().await;
    let proxy = tokio::spawn(async move {
        let (mut peer, _) = l.accept().await.unwrap();
        let mut head = Vec::new();
        let mut byte = [0];
        while !head.ends_with(b"\r\n\r\n") {
            peer.read_exact(&mut byte).await.unwrap();
            head.push(byte[0]);
        }
        peer.write_all(&[&b"HTTP/1.1 200 Connected\r\n\r\n"[..], FORGED].concat())
            .await
            .unwrap();
        peer.flush().await.unwrap();
        let _ = acceptor.accept(peer).await;
    });
    let route = super::super::judge::Route {
        addrs: vec![addr],
        tunnel: Some(super::super::judge::Tunnel {
            hop: Arc::new(crate::proxy::ProxyHop::new(
                addr.ip().to_string(),
                addr.port(),
                None,
            )),
            target: "93.184.216.34:443".into(),
        }),
    };
    let d = io
        .dial(Dial {
            instance: 7,
            dest: "upstream.test:443",
            route,
            unix: None,
            tls: None,
            timeout: BUDGET,
        })
        .await
        .unwrap();
    until_unread(&io, &d.conn).await;
    let up = io
        .upgrade(
            d.conn,
            plan("upstream.test", Some(anchor(ca)), false),
            BUDGET,
        )
        .await;
    assert_eq!(
        up.err(),
        Some(NeedErr::Tls),
        "a tunnel prefix is clear bytes too: no upgrade over it"
    );
    let _ = proxy.await;
}

/// STARTTLS injection, parked: [`FORGED`] arrives as a segment of its own after the clear `OK\n`
/// was read whole. The upgrade over the parked piece fails and the conn is gone with it.
#[tokio::test]
async fn an_upgrade_over_a_piece_parked_on_the_line_is_refused_and_the_stream_fails() {
    let (ca, acceptor) = tls_server(&["upstream.test"]);
    let (l, addr) = listener().await;
    let far = tokio::spawn(injecting_far_end(
        l,
        acceptor,
        Some(Duration::from_millis(200)),
    ));
    let io = test_io();
    let addrs = [addr];
    let mut d = io.dial(plain(&addrs)).await.unwrap();
    assert_eq!(io.write(&mut d.conn, b"STARTTLS\n", BUDGET).await, Ok(9));
    let mut ok = [0u8; 16];
    let n = io.read(&mut d.conn, &mut ok, BUDGET).await.unwrap();
    assert_eq!(&ok[..n], b"OK\n", "the clear answer came alone");
    until_unread(&io, &d.conn).await;
    let up = io
        .upgrade(
            d.conn,
            plan("upstream.test", Some(anchor(ca)), false),
            BUDGET,
        )
        .await;
    assert_eq!(
        up.err(),
        Some(NeedErr::Tls),
        "a parked clear piece is still unread: no upgrade over it"
    );
    let _ = far.await;
}

/// The upgrade's handshake is bounded by the caller's timeout (need/net.rs `upgrade(.., timeout)`):
/// a far end that accepts TCP and never answers TLS ends `Timeout` at that bound, whichever it is.
#[tokio::test]
async fn security_upgrade_inherits_the_declared_or_per_open_timeout() {
    for bound in [Duration::from_millis(100), Duration::from_millis(400)] {
        let (l, addr) = listener().await;
        let held = tokio::spawn(async move {
            let (s, _) = l.accept().await.unwrap();
            tokio::time::sleep(BUDGET).await;
            drop(s);
        });
        let io = test_io();
        let addrs = [addr];
        let d = io.dial(plain(&addrs)).await.unwrap();
        let began = std::time::Instant::now();
        let up = tokio::time::timeout(
            BUDGET,
            io.upgrade(d.conn, plan("upstream.test", None, false), bound),
        )
        .await
        .expect("the caller's bound ends the handshake, not the test's");
        let took = began.elapsed();
        assert_eq!(up.err(), Some(NeedErr::Timeout), "{bound:?}");
        assert!(took >= bound, "ended at {took:?}, before its bound {bound:?}");
        assert!(
            took < bound + Duration::from_secs(2),
            "ended at {took:?}, long past its bound {bound:?}"
        );
        held.abort();
    }
}
