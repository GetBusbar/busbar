// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A BURST OF OPENS TO A DESTINATION WHOSE FAR END FAILS ITS PINNED KEY (P095-3, PROOF-093-B:112): the connector,
//! handed the linked http image as its HTTP carrier (as the root does at boot), opens several exchanges at once to a
//! TLS far end whose key is not the one the destination is pinned to. Every open fails, and the far end is sent no
//! byte of any request: not by the first dial, and not by any open that followed it while it was in flight.
//!
//! Today no open joins another's dial in flight (a connection is shared only once its own handshake, pin included,
//! has completed); each open of the burst is held to the pin by its own handshake. The control: the same burst
//! with no pin is served, so the far end, its chain and the trust are sound and only the pin refuses.

#![cfg(unix)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use busbar_contract::abi::host::conn::connector::{DIRECTION_OUTBOUND, EGRESS_DEFAULT, KEEP_NAMED};
use busbar_contract::abi::mechanism::rendering::{ReadBlob, ReadNeed};
use busbar_contract::conn::{
    ConnError, ConnId, Conns, DeclaredConns, InstanceId, NeedId, OpenDesc, PieceKind, PollConns,
};
use busbar_contract::crypto::testing::rcgen::{
    BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, PublicKeyData as _,
};
use busbar_contract::storage::{StorageAccount, StorageDenied, StorageSource};
use busbar_contract::transport::trust::{key_pin, Anchors, EgressTrust};
use busbar_core_connector::native_dial::NativeCarrier;
use busbar_core_connector::pool::PoolPosture;
use busbar_core_connector::{Connector, Judged, Verdict};
use busbar_plugin_abi::plane::CARRIER_HTTP;
use busbar_plugin_test::fake_needs::FakeNeeds;
use busbar_plugin_test::suites::harness::Harness;

const OWNER: InstanceId = InstanceId(13);
const NEED: NeedId = NeedId(1);
const BURST: usize = 4;
const BODY: &[u8] = br#"{"ok":1}"#;

struct Free;

impl StorageAccount for Free {
    fn try_reserve(&self, _: usize) -> Result<(), StorageDenied> {
        Ok(())
    }
    fn release(&self, _: usize) {}
}

/// A TLS far end at `127.0.0.1` answering every request 200 on a kept connection; it counts the handshakes it
/// completed and every byte of request it was sent after one.
struct FarEnd {
    addr: SocketAddr,
    ca_der: Vec<u8>,
    handshakes: Arc<AtomicUsize>,
    request_bytes: Arc<AtomicUsize>,
}

fn far_end() -> FarEnd {
    let ca_key = KeyPair::generate().expect("the CA key");
    let mut ca_params = CertificateParams::new(Vec::new()).expect("CA parameters");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).expect("the CA");
    let issuer = Issuer::new(ca_params, ca_key);
    let leaf_key = KeyPair::generate().expect("the leaf key");
    let leaf = CertificateParams::new(vec!["127.0.0.1".into()])
        .expect("the leaf's IP name")
        .signed_by(&leaf_key, &issuer)
        .expect("the leaf");
    let config = busbar_contract::crypto::tls::server_config(|b| {
        b.with_no_client_auth().with_single_cert(
            vec![leaf.der().clone()],
            rustls::pki_types::PrivateKeyDer::try_from(leaf_key.serialize_der())
                .expect("the leaf key DER"),
        )
    })
    .expect("the far end's TLS configuration");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the far end");
    let addr = listener.local_addr().expect("its address");
    let handshakes = Arc::new(AtomicUsize::new(0));
    let request_bytes = Arc::new(AtomicUsize::new(0));
    let (shook, sent) = (Arc::clone(&handshakes), Arc::clone(&request_bytes));
    std::thread::spawn(move || {
        for mut conn in listener.incoming().flatten() {
            let config = Arc::clone(&config);
            let (shook, sent) = (Arc::clone(&shook), Arc::clone(&sent));
            std::thread::spawn(move || {
                let _ = conn.set_read_timeout(Some(Duration::from_secs(20)));
                let Ok(mut session) = rustls::ServerConnection::new(config) else {
                    return;
                };
                while session.is_handshaking() {
                    if session.complete_io(&mut conn).is_err() {
                        return;
                    }
                }
                shook.fetch_add(1, Ordering::SeqCst);
                let mut tls = rustls::StreamOwned::new(session, conn);
                let mut seen = Vec::new();
                let mut chunk = [0_u8; 4096];
                loop {
                    let n = match tls.read(&mut chunk) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    sent.fetch_add(n, Ordering::SeqCst);
                    seen.extend_from_slice(&chunk[..n]);
                    // One answer per request head (the requests here carry no body).
                    while let Some(at) = seen.windows(4).position(|w| w == b"\r\n\r\n") {
                        seen.drain(..at + 4);
                        let _ = write!(
                            tls,
                            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
                            BODY.len()
                        );
                        let _ = tls.write_all(BODY);
                        let _ = tls.flush();
                    }
                }
            });
        }
    });
    FarEnd {
        addr,
        ca_der: ca.der().to_vec(),
        handshakes,
        request_bytes,
    }
}

fn loopback(target: &str, _: u32, _: Judged) -> Option<Result<SocketAddr, Verdict>> {
    Some(
        target
            .parse::<SocketAddr>()
            .ok()
            .filter(|address| address.ip().is_loopback())
            .ok_or(busbar_contract::abi::host::service::DEST_UNRESOLVABLE),
    )
}

fn need() -> ReadNeed {
    ReadNeed {
        direction: DIRECTION_OUTBOUND,
        egress_class: EGRESS_DEFAULT,
        transport: "https".into(),
        auth: String::new(),
        target_from: String::new(),
        trust_from: String::new(),
        details: ReadBlob {
            fmt: 0,
            flags: 0,
            bytes: Vec::new(),
        },
        timeout_ms: 0,
        keep_mode: KEEP_NAMED,
        keep_response_headers: Vec::new(),
        deny_response_headers: Vec::new(),
    }
}

struct Fixture {
    runtime: tokio::runtime::Runtime,
    connector: Connector,
    _harness: Harness,
}

/// The connector the root builds, trusting the far end's CA, keeping idle connections, handed the linked http
/// image as its HTTP carrier.
fn fixture(ca_der: Vec<u8>) -> Fixture {
    let harness = Harness::admit_linked(&busbar_transport_http::PLUGIN, FakeNeeds::new())
        .expect("the linked http image admits");
    let port = harness
        .open_transport("busbar-transport-http", b"{}")
        .expect("the linked http image opens");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("a runtime");
    busbar_core_connector::io::install_process_reactor(runtime.handle().clone());
    let connector = Connector::serving_with_trust(
        Arc::new(loopback),
        EgressTrust {
            extra_anchors: vec![ca_der],
            ..EgressTrust::default()
        },
        Arc::new(|_, _| {}),
    )
    .expect("the trust builds")
    .pooling(PoolPosture {
        max_idle_per_host: 8,
        idle_timeout: Duration::from_secs(60),
    });
    connector
        .carry_natively(
            vec![NativeCarrier {
                instance: Arc::from("busbar-transport-http"),
                port,
                carrier: CARRIER_HTTP,
                stall_ms: None,
            }],
            StorageSource::new(Arc::new(Free) as Arc<dyn StorageAccount>),
        )
        .expect("the boot hand-over");
    DeclaredConns::declare(&connector, OWNER, NEED, &need(), None, None)
        .expect("https is declared natively");
    Fixture {
        runtime,
        connector,
        _harness: harness,
    }
}

impl Fixture {
    /// `BURST` opens to `target`, all made before any is read: the far end's first handshake is still in flight
    /// when the last open is made.
    fn burst(&self, target: &str) -> Vec<Result<ConnId, ConnError>> {
        self.runtime.block_on(async {
            (0..BURST)
                .map(|_| {
                    self.connector.open(
                        OWNER,
                        NEED,
                        &OpenDesc {
                            target,
                            timeout_ms: 10_000,
                            method: b"GET",
                            head_target: b"/v1/models",
                            ..OpenDesc::default()
                        },
                    )
                })
                .collect()
        })
    }

    /// The exchange read to its end: its status, or the error that ended it.
    fn read(&self, conn: ConnId) -> Result<Option<u32>, ConnError> {
        self.runtime.block_on(async {
            let mut buf = vec![0_u8; 16 * 1024];
            let mut status = None;
            loop {
                let piece = tokio::time::timeout(
                    Duration::from_secs(20),
                    std::future::poll_fn(|cx| self.connector.poll_read(OWNER, conn, cx, &mut buf)),
                )
                .await
                .expect("an answer or an error within 20 s")?;
                match piece.kind {
                    PieceKind::Fields if status.is_none() => status = piece.status_code,
                    PieceKind::Completion => return Ok(status),
                    _ => {}
                }
            }
        })
    }

    fn close(&self, conn: ConnId) {
        let _ = self
            .runtime
            .block_on(async { self.connector.close(OWNER, conn) });
    }
}

#[test]
fn anchor_mismatch_burst_sends_no_follower_bytes() {
    let far = far_end();
    let fixture = fixture(far.ca_der.clone());
    let target = format!("https://{}/v1/models", far.addr);

    // The control: unpinned, the burst is served.
    for opened in fixture.burst(&target) {
        let conn = opened.expect("an unpinned open is made");
        assert_eq!(fixture.read(conn), Ok(Some(200)), "unpinned, the far end serves");
        fixture.close(conn);
    }
    assert!(far.request_bytes.load(Ordering::SeqCst) > 0);

    // Pinned to a key the far end does not hold.
    let other = KeyPair::generate().expect("another key");
    let anchors = Anchors {
        key_pin: Some(key_pin(&other.subject_public_key_info())),
        ..Anchors::default()
    };
    PollConns::anchor(&fixture.connector, OWNER, NEED, "", &target, &anchors)
        .expect("the destination is pinned");
    let handshakes = far.handshakes.load(Ordering::SeqCst);
    let request_bytes = far.request_bytes.load(Ordering::SeqCst);
    for opened in fixture.burst(&target) {
        match opened {
            // Refused at the open: nothing was dialled for it.
            Err(error) => assert_ne!(error, ConnError::Pending),
            Ok(conn) => {
                assert!(
                    fixture.read(conn).is_err(),
                    "every open of the burst fails at the pin"
                );
                fixture.close(conn);
            }
        }
    }
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        far.request_bytes.load(Ordering::SeqCst),
        request_bytes,
        "no byte of any request of the burst reached the far end (a connection the pin never checked included)"
    );
}
