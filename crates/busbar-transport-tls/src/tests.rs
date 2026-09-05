//! The transport battery, for `tls`: byte-exact round trip over a real rustls handshake, half
//! close, cancel mid-frame, handshake failure mapped to `TransportError::HandshakeFailed`, and the
//! two-level composition cell (a bottom-layer credential: the server config resolved through the
//! opaque key handle's slot).

use super::*;
use busbar_contract::plugin::KernelSeal;
use busbar_contract::ConfigView;
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
            address: busbar_contract_transport::dest::UpstreamAddress::socket(host),
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
    let client_conn = client
        .dial(&upstream_dest(&addr), &fixture_key(0))
        .await
        .unwrap();
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
    let client_conn2 = client2
        .dial(&upstream_dest(&addr2), &fixture_key(0))
        .await
        .unwrap();
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
    assert_eq!(
        record.sni.as_deref(),
        Some("localhost"),
        "re-resolved at the new layer"
    );
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
    let client_conn = client
        .dial(&upstream_dest(&addr), &fixture_key(0))
        .await
        .unwrap();
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

/// The transport-key unit is the registrant, and a listener has a key because the unit put one
/// there.
///
/// Before this path existed the only thing that ever registered a config was this crate's own
/// tests: the unit built a `ServerConfig` and had no way to reach a transport, so a production
/// listener resolved a slot to nothing and refused every connection for want of a key. The whole
/// path runs here — the secret source is read, the access is journaled once per secret, the config
/// lands in the slot the handle names, and a real client completes a handshake against it.
#[tokio::test]
async fn the_transport_key_unit_is_what_gives_a_listener_its_key() {
    use busbar_unit_transport_key::{AccessJournal, AccessPurpose, SecretSource};
    use std::sync::Mutex as StdMutex;

    struct MapSource(std::collections::HashMap<&'static str, Vec<u8>>);
    impl SecretSource for MapSource {
        fn resolve(&self, location: &str) -> Result<Vec<u8>, String> {
            self.0
                .get(location)
                .cloned()
                .ok_or_else(|| format!("no secret at {location}"))
        }
    }

    #[derive(Default)]
    struct RecordingJournal(StdMutex<Vec<(String, AccessPurpose)>>);
    impl AccessJournal for RecordingJournal {
        fn record_access(&self, location: &str, purpose: AccessPurpose) {
            self.0.lock().unwrap().push((location.to_string(), purpose));
        }
    }

    busbar_unit_transport_key::install_crypto_provider();
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .unwrap();
    let cert_pem = cert.pem();
    let key_pem = signing_key.serialize_pem();

    let source = MapSource(
        [
            ("secret://tls/cert", cert_pem.clone().into_bytes()),
            ("secret://tls/key", key_pem.into_bytes()),
        ]
        .into_iter()
        .collect(),
    );
    let journal = RecordingJournal::default();

    // The transport offers somewhere to put a config; the unit is what puts one there.
    let server = StdArc::new(TlsTransport::new());
    let seal = busbar_caps::KernelSeal::acquire_for_kernel();
    let keys = busbar_unit_transport_key::provision_server(
        &source,
        &journal,
        &*server,
        &busbar_caps::TransportKeyToken::mint(&seal),
        busbar_unit_transport_key::Slot {
            index: 0,
            fingerprint: "fixture",
        },
        &busbar_unit_transport_key::TlsLocations {
            cert: "secret://tls/cert",
            key: "secret://tls/key",
            client_ca: None,
        },
    )
    .expect("the unit resolves, journals and registers");

    assert_eq!(keys.slot(), 0);
    assert_eq!(
        journal.0.lock().unwrap().as_slice(),
        &[
            ("secret://tls/cert".to_string(), AccessPurpose::Cert),
            ("secret://tls/key".to_string(), AccessPurpose::Key),
        ],
        "one access entry per secret actually read, in the order they were read"
    );

    let cfg = TestCfg {
        bind: "127.0.0.1:0".to_string(),
    };
    let listener = server
        .listen(&cfg, &keys)
        .await
        .expect("the slot the handle names now resolves to a config");
    let addr = listener.local_addr();
    let accept_fut = tokio::spawn({
        let server = server.clone();
        async move { server.accept(&listener).await.unwrap() }
    });

    // A real client, trusting exactly the certificate the unit resolved.
    let mut roots = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
    {
        roots.add(c).unwrap();
    }
    let client_cfg = StdArc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let client = StdArc::new(TlsTransport::new());
    let client_keys = busbar_unit_transport_key::provision_client(
        &*client,
        &busbar_caps::TransportKeyToken::mint(&seal),
        busbar_unit_transport_key::Slot {
            index: 0,
            fingerprint: "fixture-client",
        },
        client_cfg,
    );
    let client_conn = client
        .dial(&upstream_dest(&addr), &client_keys)
        .await
        .expect("the handshake completes against the unit's material");
    let server_conn = accept_fut.await.unwrap();

    let payload = b"served under a key the unit resolved";
    server
        .write(&server_conn, StreamId(0), ArenaBytes::new(payload))
        .await
        .unwrap();
    let mut frames = client.frames(client_conn.clone());
    let (_s, frame) = frames.next().await.unwrap().unwrap();
    assert_eq!(frame.bytes.as_slice(), payload);
    client.close(client_conn, CloseReason::Normal);
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
            address: busbar_contract_transport::dest::UpstreamAddress::Socket {
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

    assert_eq!(
        server.arrival(&server_conn).sni.as_deref(),
        Some("localhost")
    );
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

    let client_conn = client
        .dial(&upstream_dest(&addr), &fixture_key(0))
        .await
        .unwrap();
    let server_conn = accept_fut.await.unwrap();

    // A dial to an IP literal offers no SNI at all on the wire, which is the correct reading of
    // "the address is the name": rustls does not send a server_name extension for an IP.
    assert_eq!(server.arrival(&server_conn).sni, None);
    client.close(client_conn, CloseReason::Normal);
}

/// The registration check: every reserved key this transport publishes is one it declares.
///
/// The declaration is what a boot compares a plane's expectations against, so a key written and not
/// declared is a value a plane reads that no boot check knows about. The published set is read off
/// a REAL arrival record rather than restated, so a handshake that starts carrying something new
/// fails here instead of in a deployment.
#[tokio::test]
async fn every_reserved_key_this_transport_publishes_is_declared() {
    use busbar_contract_transport::registry::facts;

    let (server, listener, client) = bound_pair().await;
    let addr = listener.local_addr();
    let key0 = fixture_key(0);
    let accept_fut = tokio::spawn({
        let server = server.clone();
        async move { server.accept(&listener).await }
    });
    let dialled = client.dial(&upstream_dest(&addr), &key0).await.unwrap();
    let accepted = accept_fut.await.unwrap().unwrap();

    let mut published: Vec<&'static str> = Vec::new();
    for (transport, conn) in [(server.as_ref(), &accepted), (client.as_ref(), &dialled)] {
        let record = transport.arrival(conn);
        if record.sni.is_some() {
            published.push(facts::SNI);
        }
        if record.alpn.is_some() {
            published.push(facts::ALPN);
        }
        if record.peer_cert.is_some() {
            published.push(facts::PEER);
        }
        // A source address is always known, so the peer key is always published.
        assert!(!record.source.is_empty());
        published.push(facts::PEER);
    }

    assert_eq!(
        facts::undeclared(<TlsTransport as TransportMeta>::TRANSPORT_FACTS, &published),
        None,
        "this transport publishes a reserved key it does not declare"
    );
}

/// A self-signed cert/key pair plus its own DER-encoded leaf, so a test can compute the exact
/// fingerprint it expects a handshake to serve — not just check that a handshake happened.
fn self_signed_with_der() -> (
    Arc<rustls::ServerConfig>,
    Arc<rustls::ClientConfig>,
    Vec<u8>,
) {
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
    let leaf_der = cert_der[0].as_ref().to_vec();

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

    (Arc::new(server_cfg), Arc::new(client_cfg), leaf_der)
}

/// R-03: `accept` must serve the config for the slot the *listener* was provisioned with, not a
/// fixed slot of its own. Slot 0 holds one certificate; the listener is provisioned at slot 7 with
/// a different one. If `accept` ever regresses to a hardcoded slot, this either fails the handshake
/// (the client trusts only the slot-7 cert's root) or, worse, silently serves the wrong identity —
/// so the served fingerprint is checked explicitly, and shown to differ from slot 0's, rather than
/// just checking that a handshake happened.
#[tokio::test]
async fn accept_serves_the_slot_the_listener_was_provisioned_with() {
    let (server_cfg_0, _client_cfg_0, cert_0_der) = self_signed_with_der();
    let (server_cfg_7, client_cfg_7, cert_7_der) = self_signed_with_der();
    assert_ne!(
        cert_0_der, cert_7_der,
        "the two slots must hold genuinely different certs"
    );

    let server = StdArc::new(TlsTransport::new());
    server.register_server_config(0, server_cfg_0);
    server.register_server_config(7, server_cfg_7);

    let cfg = TestCfg {
        bind: "127.0.0.1:0".to_string(),
    };
    // Provisioned at slot 7, not 0 — this is the case `A6`/`R-03` exists for: any listener whose
    // key landed in a non-zero slot.
    let listener = server.listen(&cfg, &fixture_key(7)).await.unwrap();
    let addr = listener.local_addr();

    let client = StdArc::new(TlsTransport::new());
    // The client trusts only the slot-7 cert's root, so a handshake against slot 0's cert (the old,
    // hardcoded `get(&0)` behavior) fails outright rather than merely serving a surprising cert.
    client.register_client_config(0, client_cfg_7);

    let accept_fut = tokio::spawn({
        let server = server.clone();
        async move { server.accept(&listener).await.unwrap() }
    });
    let client_conn = client
        .dial(&upstream_dest(&addr), &fixture_key(0))
        .await
        .expect("handshake against the slot-7 listener must succeed with the slot-7 trust root");
    let _server_conn = accept_fut.await.unwrap();

    let record = client.arrival(&client_conn);
    let served_fp = record
        .peer_cert
        .as_ref()
        .expect("the client sees the server's certificate as its peer cert")
        .fingerprint
        .clone();

    let fp_0 = format!("{:x?}", ring_fingerprint(&cert_0_der));
    let fp_7 = format!("{:x?}", ring_fingerprint(&cert_7_der));
    assert_eq!(
        served_fp, fp_7,
        "accept served the slot-7 certificate, byte for byte"
    );
    assert_ne!(
        served_fp, fp_0,
        "slot 0's certificate must not be what accept served"
    );
}

/// CG-49: multi-certificate SNI on one listener.
///
/// The transport-key unit's `provision_server_named` resolves a name's material, journals it, and
/// (unlike `provision_server`) builds one `ServerConfig` whose `ResolvesServerCert` picks the
/// certified key per `ClientHello` — so this crate needs no second registry and no change to
/// `listen`/`accept` at all: a listener provisioned this way is just a listener whose one
/// registered config happens to serve more than one identity.
mod cg_49_sni {
    use super::*;
    use busbar_unit_transport_key::{
        AccessJournal, AccessPurpose, NamedTlsLocations, SecretSource, Slot, TlsLocations,
    };
    use std::collections::HashMap as StdHashMap;
    use std::sync::Mutex as StdMutex;

    /// A permissive `ServerCertVerifier` that only checks the presented chain parses — no root-of-
    /// trust check, no hostname check. Used only for the two edge-case tests where the server
    /// deliberately serves a certificate that does not match the name the client asked for (no SNI
    /// at all, or an unrecognised one): a conformant client would refuse such a certificate, which
    /// is correct behaviour but not what those two tests are checking. What they check is which
    /// certificate the *resolver* served, read off the connection's own peer-cert fact — the same
    /// fingerprint assertion the honest-name tests make, just without asking rustls to also agree
    /// the name matches.
    #[derive(Debug)]
    struct AcceptAnyServerCert;
    impl rustls::client::danger::ServerCertVerifier for AcceptAnyServerCert {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &rustls_pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls_pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    fn accept_any_client_config() -> StdArc<rustls::ClientConfig> {
        StdArc::new(
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(StdArc::new(AcceptAnyServerCert))
                .with_no_client_auth(),
        )
    }

    struct MapSource(StdHashMap<&'static str, Vec<u8>>);
    impl SecretSource for MapSource {
        fn resolve(&self, location: &str) -> Result<Vec<u8>, String> {
            self.0
                .get(location)
                .cloned()
                .ok_or_else(|| format!("no secret at {location}"))
        }
    }

    #[derive(Default)]
    struct RecordingJournal(StdMutex<Vec<(String, AccessPurpose)>>);
    impl AccessJournal for RecordingJournal {
        fn record_access(&self, location: &str, purpose: AccessPurpose) {
            self.0.lock().unwrap().push((location.to_string(), purpose));
        }
    }

    /// A fresh self-signed cert/key for `name`, its PEM (for the fake secret source), its leaf DER
    /// (to compute the fingerprint a test expects), and a client trust store trusting exactly it.
    fn named_identity(name: &str) -> (String, String, Vec<u8>, StdArc<rustls::ClientConfig>) {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec![name.to_string()]).unwrap();
        let cert_pem = cert.pem();
        let key_pem = signing_key.serialize_pem();
        let cert_der = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let leaf_der = cert_der[0].as_ref().to_vec();
        let mut roots = rustls::RootCertStore::empty();
        for c in cert_der {
            roots.add(c).unwrap();
        }
        let client_cfg = StdArc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        (cert_pem, key_pem, leaf_der, client_cfg)
    }

    fn dial_dest(addr: &str, sni: &str) -> busbar_contract::VerifiedDestination {
        let leaked_addr: &'static str = Box::leak(addr.to_string().into_boxed_str());
        let leaked_sni: &'static str = Box::leak(sni.to_string().into_boxed_str());
        busbar_contract::VerifiedDestination::seal(
            &FixtureSeal,
            busbar_contract::DestinationFacts::Upstream {
                transport: "tls",
                address: busbar_contract_transport::dest::UpstreamAddress::Socket {
                    authority: leaked_addr,
                    sni: Some(leaked_sni),
                },
                lane: busbar_contract::LaneId::new("test"),
            },
            "tls",
            None,
        )
    }

    /// One listener, provisioned with two names plus a default; a fixture bundling the three
    /// identities and the journal that recorded provisioning it.
    struct Fixture {
        server: StdArc<TlsTransport>,
        listener: Listener,
        addr: String,
        fp_a: String,
        fp_b: String,
        fp_default: String,
        client_a: StdArc<rustls::ClientConfig>,
        client_b: StdArc<rustls::ClientConfig>,
        journal: RecordingJournal,
    }

    async fn provisioned_listener() -> Fixture {
        busbar_unit_transport_key::install_crypto_provider();
        let (cert_a, key_a, der_a, client_a) = named_identity("a.example");
        let (cert_b, key_b, der_b, client_b) = named_identity("b.example");
        let (cert_d, key_d, der_d, _client_default) = named_identity("default.example");

        let source = MapSource(
            [
                ("cert-a", cert_a.into_bytes()),
                ("key-a", key_a.into_bytes()),
                ("cert-b", cert_b.into_bytes()),
                ("key-b", key_b.into_bytes()),
                ("cert-default", cert_d.into_bytes()),
                ("key-default", key_d.into_bytes()),
            ]
            .into_iter()
            .collect(),
        );
        let journal = RecordingJournal::default();
        let seal = busbar_caps::KernelSeal::acquire_for_kernel();

        let server = StdArc::new(TlsTransport::new());
        let handle = busbar_unit_transport_key::provision_server_named(
            &source,
            &journal,
            &*server,
            &busbar_caps::TransportKeyToken::mint(&seal),
            Slot {
                index: 0,
                fingerprint: "fixture",
            },
            &[
                NamedTlsLocations {
                    sni: "a.example",
                    cert: "cert-a",
                    key: "key-a",
                },
                NamedTlsLocations {
                    sni: "b.example",
                    cert: "cert-b",
                    key: "key-b",
                },
            ],
            &TlsLocations {
                cert: "cert-default",
                key: "key-default",
                client_ca: None,
            },
        )
        .expect("names and default all resolve");

        let cfg = TestCfg {
            bind: "127.0.0.1:0".to_string(),
        };
        let listener = server.listen(&cfg, &handle).await.unwrap();
        let addr = listener.local_addr();

        Fixture {
            server,
            listener,
            addr,
            fp_a: format!("{:x?}", ring_fingerprint(&der_a)),
            fp_b: format!("{:x?}", ring_fingerprint(&der_b)),
            fp_default: format!("{:x?}", ring_fingerprint(&der_d)),
            client_a,
            client_b,
            journal,
        }
    }

    async fn served_fingerprint(
        fx: &Fixture,
        sni: Option<&str>,
        client_cfg: StdArc<rustls::ClientConfig>,
    ) -> String {
        let accept_fut = tokio::spawn({
            let server = fx.server.clone();
            let listener = fx.listener.clone();
            async move { server.accept(&listener).await.unwrap() }
        });
        let client = StdArc::new(TlsTransport::new());
        client.register_client_config(0, client_cfg);
        let dest = match sni {
            Some(name) => dial_dest(&fx.addr, name),
            None => upstream_dest(&fx.addr),
        };
        let client_conn = client
            .dial(&dest, &fixture_key(0))
            .await
            .expect("handshake completes");
        let _server_conn = accept_fut.await.unwrap();
        let record = client.arrival(&client_conn);
        record
            .peer_cert
            .expect("client sees the server's certificate")
            .fingerprint
    }

    #[tokio::test]
    async fn each_named_client_sees_its_own_names_fingerprint() {
        let fx = provisioned_listener().await;

        let served_a = served_fingerprint(&fx, Some("a.example"), fx.client_a.clone()).await;
        assert_eq!(served_a, fx.fp_a, "a.example got a.example's certificate");
        assert_ne!(served_a, fx.fp_b);
        assert_ne!(served_a, fx.fp_default);

        let served_b = served_fingerprint(&fx, Some("b.example"), fx.client_b.clone()).await;
        assert_eq!(served_b, fx.fp_b, "b.example got b.example's certificate");
        assert_ne!(served_b, fx.fp_a);
        assert_ne!(served_b, fx.fp_default);

        assert_eq!(
            fx.journal.0.lock().unwrap().as_slice(),
            &[
                ("cert-a".to_string(), AccessPurpose::Cert),
                ("key-a".to_string(), AccessPurpose::Key),
                ("cert-b".to_string(), AccessPurpose::Cert),
                ("key-b".to_string(), AccessPurpose::Key),
                ("cert-default".to_string(), AccessPurpose::Cert),
                ("key-default".to_string(), AccessPurpose::Key),
            ],
            "one access entry per secret actually read, in the order provisioned: names then default"
        );
    }

    #[tokio::test]
    async fn a_client_offering_no_sni_gets_the_default() {
        let fx = provisioned_listener().await;
        let served = served_fingerprint(&fx, None, accept_any_client_config()).await;
        assert_eq!(
            served, fx.fp_default,
            "no SNI offered: the default is served"
        );
    }

    /// 1.5.5 (`v1.5.5:crates/busbar/src/tls.rs`) never read `ClientHello::server_name` at all — it
    /// built exactly one `ServerConfig::with_single_cert` per listener and served it unconditionally
    /// regardless of what a client offered. Falling through to the default for a *recognised-format
    /// but unregistered* name, rather than refusing the handshake, is the parity choice: a client
    /// naming any name at all still gets *a* certificate, exactly as it would have from 1.5.5's one
    /// cert.
    #[tokio::test]
    async fn an_unknown_name_gets_the_default() {
        let fx = provisioned_listener().await;
        let served = served_fingerprint(
            &fx,
            Some("nobody-provisioned-this.example"),
            accept_any_client_config(),
        )
        .await;
        assert_eq!(
            served, fx.fp_default,
            "unknown name: the default is served, not a refusal"
        );
    }
}
