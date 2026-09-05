//! The transport battery, for `tls`: byte-exact round trip over a real rustls handshake, half
//! close, cancel mid-frame, handshake failure mapped to `TransportError::HandshakeFailed`, and the
//! two-level composition cell (a bottom-layer credential: the server config resolved through the
//! opaque key handle's slot).

use super::*;
use busbar_contract::{ConfigView, KernelSeal};
use futures::StreamExt;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc as StdArc;

struct FixtureSeal;
impl KernelSeal for FixtureSeal {
    fn seal_origin(&self) -> &'static str {
        "busbar-transport-tls test fixture"
    }
}

fn fixture_key(slot: u64) -> TransportKeyHandle {
    TransportKeyHandle::issue(&FixtureSeal, slot, "test")
}

struct TestCfg {
    bind: String,
}
impl ConfigView for TestCfg {
    fn get_str(&self, _key: &str) -> Option<&str> {
        None
    }
    fn get_int(&self, _key: &str) -> Option<i64> {
        None
    }
    fn get_bool(&self, _key: &str) -> Option<bool> {
        None
    }
}
impl TransportConfigView for TestCfg {
    fn bind(&self) -> Option<&str> {
        Some(&self.bind)
    }
}

/// A fresh self-signed keypair for "localhost", plus the client trust store that trusts exactly
/// it. Test-only: the real trust story is the transport-key unit's, never this crate's.
fn self_signed() -> (Arc<rustls::ServerConfig>, Arc<rustls::ClientConfig>) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .unwrap();
    let cert_pem = cert.pem();
    let key_pem = signing_key.serialize_pem();
    let cert_der = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key_der = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).unwrap();

    let server_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_der.clone(), key_der)
        .unwrap();

    let mut roots = rustls::RootCertStore::empty();
    for c in cert_der {
        roots.add(c).unwrap();
    }
    let client_cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    (Arc::new(server_cfg), Arc::new(client_cfg))
}

fn upstream_dest(addr: &str) -> busbar_contract::VerifiedDestination {
    let host: &'static str = Box::leak(addr.to_string().into_boxed_str());
    busbar_contract::VerifiedDestination::seal(
        &FixtureSeal,
        busbar_contract::DestinationFacts::Upstream {
            transport: "tls",
            address: busbar_contract::UpstreamAddress::socket(host),
            lane: busbar_contract::LaneId::new("test"),
        },
        "tls",
        None,
    )
}

async fn bound_pair() -> (StdArc<TlsTransport>, Listener, StdArc<TlsTransport>) {
    let (server_cfg, client_cfg) = self_signed();
    let server = StdArc::new(TlsTransport::new());
    server.register_server_config(0, server_cfg);
    let cfg = TestCfg {
        bind: "127.0.0.1:0".to_string(),
    };
    let listener = server.listen(&cfg, &fixture_key(0)).await.unwrap();

    let client = StdArc::new(TlsTransport::new());
    client.register_client_config(0, client_cfg);
    (server, listener, client)
}

#[tokio::test]
async fn byte_exact_round_trip_over_a_real_handshake() {
    let (server, listener, client) = bound_pair().await;
    let addr = listener.local_addr();
    let accept_fut = tokio::spawn({
        let server = server.clone();
        async move { server.accept(&listener).await.unwrap() }
    });

    let client_conn = client
        .dial(&upstream_dest(&addr), &fixture_key(0))
        .await
        .unwrap();
    let server_conn = accept_fut.await.unwrap();

    let payload = b"tls says hello, byte for byte";
    client
        .write(&client_conn, StreamId(0), ArenaBytes::new(payload))
        .await
        .unwrap();

    let mut frames = server.frames(server_conn);
    let (_s, frame) = frames.next().await.unwrap().unwrap();
    assert_eq!(frame.bytes.as_slice(), payload);
    assert_eq!(frame.meta.bytes, payload.len() as u64);
}

#[tokio::test]
async fn half_close_and_cancel_mid_frame() {
    let (server, listener, client) = bound_pair().await;
    let addr = listener.local_addr();
    let accept_fut = tokio::spawn({
        let server = server.clone();
        async move { server.accept(&listener).await.unwrap() }
    });
    let client_conn = client.dial(&upstream_dest(&addr), &fixture_key(0)).await.unwrap();
    let server_conn = accept_fut.await.unwrap();

    client
        .write(&client_conn, StreamId(0), ArenaBytes::new(b"bye"))
        .await
        .unwrap();
    client.close(client_conn, CloseReason::Normal);

    let mut frames = server.frames(server_conn.clone());
    let (_s, frame) = frames.next().await.unwrap().unwrap();
    assert_eq!(frame.bytes.as_slice(), b"bye");
    // TLS half-close: dropping the client side without a `close_notify` alert is exactly what
    // this crate's `close()` does (it never sends one), so rustls reports the abrupt EOF as an
    // error rather than a clean end-of-stream — unlike plain `tcp`, where the same drop is a
    // silent EOF. Either shape ends the stream with no further data, which is the cell's point.
    match frames.next().await {
        None => {}
        Some(Err(_)) => {}
        Some(Ok(_)) => panic!("no further data should arrive after the client closed"),
    }

    // Cancel mid-frame on a fresh connection: dropping a pending read must not poison the conn.
    let (server2, listener2, client2) = bound_pair().await;
    let addr2 = listener2.local_addr();
    let accept2 = tokio::spawn({
        let server2 = server2.clone();
        async move { server2.accept(&listener2).await.unwrap() }
    });
    let client_conn2 = client2.dial(&upstream_dest(&addr2), &fixture_key(0)).await.unwrap();
    let server_conn2 = accept2.await.unwrap();
    {
        let mut frames = server2.frames(server_conn2.clone());
        let fut = frames.next();
        tokio::pin!(fut);
        let _ = futures::poll!(fut.as_mut());
    }
    client2
        .write(&client_conn2, StreamId(0), ArenaBytes::new(b"still alive"))
        .await
        .unwrap();
    let mut frames2 = server2.frames(server_conn2);
    let (_s, frame) = frames2.next().await.unwrap().unwrap();
    assert_eq!(frame.bytes.as_slice(), b"still alive");
}

#[tokio::test]
async fn handshake_failure_maps_to_its_own_error() {
    // The server expects a TLS handshake; a plain-TCP dial into it fails the handshake, not the
    // connect.
    let (server, listener, _client) = bound_pair().await;
    let addr = listener.local_addr();
    let accept_fut = tokio::spawn({
        let server = server.clone();
        async move { server.accept(&listener).await }
    });
    let mut plain = tokio::net::TcpStream::connect(&addr).await.unwrap();
    tokio::io::AsyncWriteExt::write_all(&mut plain, b"not a tls handshake at all, just bytes")
        .await
        .ok();
    let result = accept_fut.await.unwrap();
    assert_eq!(result.unwrap_err(), TransportError::HandshakeFailed);
}

#[tokio::test]
async fn an_in_band_upgrade_adopts_the_lower_layers_stream() {
    // The in-band upgrade cell: a `tcp`-owned connection is handed off, mid-life, and becomes a
    // `tls`-framed one carrying the same bottom-layer credential (here: the same peer socket) —
    // the STARTTLS shape. The upgrade runs through the target's own `adopt`, so what comes out is
    // a connection this transport's registry holds.
    let (server_cfg, client_cfg) = self_signed();
    let tls = TlsTransport::new();
    tls.register_server_config(0, server_cfg.clone());
    let tcp = busbar_transport_tcp::TcpTransport::new();

    struct TcpCfg;
    impl ConfigView for TcpCfg {
        fn get_str(&self, _k: &str) -> Option<&str> {
            None
        }
        fn get_int(&self, _k: &str) -> Option<i64> {
            None
        }
        fn get_bool(&self, _k: &str) -> Option<bool> {
            None
        }
    }
    impl TransportConfigView for TcpCfg {
        fn bind(&self) -> Option<&str> {
            Some("127.0.0.1:0")
        }
    }
    let key0 = fixture_key(0);
    let listener = tcp.listen(&TcpCfg, &key0).await.unwrap();
    let addr = listener.local_addr();

    let accept_fut = tokio::spawn(async move { tcp.accept(&listener).await.map(|c| (tcp, c)) });

    let client_plain = tokio::net::TcpStream::connect(&addr).await.unwrap();
    let client_task = tokio::spawn(async move {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let connector = TlsConnector::from(client_cfg);
        let name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
        connector.connect(name, client_plain).await
    });

    let (tcp, tcp_conn) = accept_fut.await.unwrap().unwrap();
    let upgraded = tls.adopt(&tcp, tcp_conn.clone(), &key0).await.unwrap();
    // The facts of the pre-upgrade layer do not survive it: `tcp` has given the stream up and no
    // longer knows the connection, and the record the upgraded layer reports is its own, naming
    // the composed stack rather than either half of it.
    assert_eq!(tcp.arrival(&tcp_conn).port, 0, "the source kept nothing");
    let record = tls.arrival(&upgraded);
    assert_eq!(record.transport_chain, vec!["tcp", "tls"]);
    assert_eq!(record.sni.as_deref(), Some("localhost"), "re-resolved at the new layer");
    // Keep the client's TLS stream alive across the write below: dropping it right after the
    // handshake closes the socket (FIN/RST) and races the server's write, which is exactly the
    // flake this ordering avoids.
    let mut client_tls = client_task.await.unwrap().unwrap();

    let payload = b"upgraded mid-life";
    tls.write(&upgraded, StreamId(0), ArenaBytes::new(payload))
        .await
        .unwrap();

    let mut buf = vec![0_u8; payload.len()];
    tokio::io::AsyncReadExt::read_exact(&mut client_tls, &mut buf)
        .await
        .unwrap();
    assert_eq!(&buf, payload);
}

/// A handoff from a layer `tls` does not compose over is refused before the stream is taken, and
/// the source keeps it. The refusal names the mismatch rather than the framing, because nothing was
/// ever wrong with the bytes.
#[tokio::test]
async fn a_handoff_from_an_undeclared_layer_is_a_mismatch() {
    let (server_cfg, _client_cfg) = self_signed();
    let tls = TlsTransport::new();
    tls.register_server_config(0, server_cfg);
    let other = TlsTransport::new();

    let (server, listener, client) = bound_pair().await;
    let addr = listener.local_addr();
    let accept_fut = tokio::spawn({
        let server = server.clone();
        async move { server.accept(&listener).await.unwrap() }
    });
    let client_conn = client.dial(&upstream_dest(&addr), &fixture_key(0)).await.unwrap();
    let server_conn = accept_fut.await.unwrap();

    // `tls` composes over `tcp` and nothing else; a `tls` source names no declared handoff.
    let err = tls
        .adopt(&other, server_conn.clone(), &fixture_key(0))
        .await
        .unwrap_err();
    assert_eq!(err, TransportError::HandoffMismatch);
    client.close(client_conn, CloseReason::Normal);
    server.close(server_conn, CloseReason::Normal);
}

/// The destination names the certificate's own DNS name, and that is what the handshake offers —
/// not the address it was pinned to. Before the address shape closed, the only name available was
/// the connect address's IP, so a certificate issued for a DNS name could never match.
#[tokio::test]
async fn a_declared_certificate_name_is_what_the_handshake_offers() {
    let (server, listener, client) = bound_pair().await;
    let addr = listener.local_addr();
    let accept_fut = tokio::spawn({
        let server = server.clone();
        async move { server.accept(&listener).await.unwrap() }
    });

    let leaked: &'static str = Box::leak(addr.into_boxed_str());
    let dest = busbar_contract::VerifiedDestination::seal(
        &FixtureSeal,
        busbar_contract::DestinationFacts::Upstream {
            transport: "tls",
            address: busbar_contract::UpstreamAddress::Socket {
                authority: leaked,
                sni: Some("localhost"),
            },
            lane: busbar_contract::LaneId::new("test"),
        },
        "tls",
        None,
    );
    let client_conn = client.dial(&dest, &fixture_key(0)).await.unwrap();
    let server_conn = accept_fut.await.unwrap();

    assert_eq!(server.arrival(&server_conn).sni.as_deref(), Some("localhost"));
    client.close(client_conn, CloseReason::Normal);
}

/// With no name declared, the authority's own host part is offered — the only name a transport can
/// name honestly, and right exactly when the upstream is addressed by IP.
#[tokio::test]
async fn with_no_declared_name_the_address_itself_stands_in() {
    let (server, listener, client) = bound_pair().await;
    let addr = listener.local_addr();
    let accept_fut = tokio::spawn({
        let server = server.clone();
        async move { server.accept(&listener).await.unwrap() }
    });

    let client_conn = client.dial(&upstream_dest(&addr), &fixture_key(0)).await.unwrap();
    let server_conn = accept_fut.await.unwrap();

    // A dial to an IP literal offers no SNI at all on the wire, which is the correct reading of
    // "the address is the name": rustls does not send a server_name extension for an IP.
    assert_eq!(server.arrival(&server_conn).sni, None);
    client.close(client_conn, CloseReason::Normal);
}
