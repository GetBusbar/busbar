// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PUBLISHED SUITE'S HOST CONNECTOR (Q-P4-4), against real local endpoints:
//!
//! * an `http` need goes through the linked http framer over the tcp carrier — the composition the
//!   root builds — and reaches a local HTTP listener, the answer coming back as its head and body;
//! * a stream's TLS upgrade is the HOST'S: it verifies against the suite's test trust anchors and
//!   round-trips; with the anchors withheld it is refused (RED);
//! * the suite binds a door declaring an `http` need over this host, on each leg.

#![cfg(feature = "conformance")]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::time::{Duration, Instant};

use busbar_contract::abi::host::conn::connector::{
    DIRECTION_OUTBOUND, EGRESS_LOOPBACK_ALLOWED, EGRESS_OPERATOR_INFRASTRUCTURE,
};
use busbar_contract::abi::mechanism::rendering::{ReadBlob, ReadNeed};
use busbar_contract::conn::{
    ConnError, ConnId, DeclaredConns, InstanceId, NeedId, OpenDesc, PieceKind, NO_TICKET,
};
use busbar_core_connector::conformance::host;

const OWNER: InstanceId = InstanceId(7);

fn need(transport: &str, class: u32) -> ReadNeed {
    ReadNeed {
        direction: DIRECTION_OUTBOUND,
        egress_class: class,
        transport: transport.to_owned(),
        auth: String::new(),
        target_from: String::new(),
        trust_from: String::new(),
        details: ReadBlob {
            fmt: 0,
            flags: 0,
            bytes: Vec::new(),
        },
        timeout_ms: 0,
    }
}

/// `f` until it answers other than PENDING, as a plugin's re-entries on its ticket would.
fn settle<T>(mut f: impl FnMut() -> Result<T, ConnError>) -> Result<T, ConnError> {
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        match f() {
            Err(ConnError::Pending) if Instant::now() < until => {
                std::thread::sleep(Duration::from_millis(2));
            }
            answered => return answered,
        }
    }
}

/// Read `id` to its completion (or `want` body bytes): its fields pieces' count and its body.
fn drain(c: &dyn DeclaredConns, id: ConnId, want: usize) -> (usize, Vec<u8>) {
    let (mut fields, mut body) = (0, Vec::new());
    let mut buf = [0_u8; 256];
    while body.len() < want {
        let Ok(p) = settle(|| c.read(OWNER, id, NO_TICKET, &mut buf)) else {
            break;
        };
        match p.kind {
            PieceKind::Fields => fields += 1,
            PieceKind::Body => body.extend_from_slice(&buf[..p.len]),
            PieceKind::Completion => break,
            PieceKind::HookReply => {}
        }
    }
    (fields, body)
}

/// AN `http` NEED THROUGH THE HOST'S FRAMER: declared on the suite's host, opened at a local HTTP
/// listener's URL, the request goes out framed by the linked http door over the tcp carrier and
/// the answer comes back as one head and its body.
#[test]
fn an_http_need_reaches_a_local_http_listener_through_the_hosts_framer() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a local listener");
    let at = listener.local_addr().expect("its address");
    let far = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().expect("the host dials it");
        let mut seen = Vec::new();
        let mut buf = [0_u8; 512];
        while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = s.read(&mut buf).expect("the request");
            assert!(n > 0, "the request ended early");
            seen.extend_from_slice(&buf[..n]);
        }
        s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello")
            .expect("the answer");
        String::from_utf8_lossy(&seen).into_owned()
    });

    let c = host(Arc::new(|_| {}), None);
    assert!(c.serves_scheme("http"), "the host serves http");
    c.declare(
        OWNER,
        NeedId(0),
        &need("http", EGRESS_LOOPBACK_ALLOWED),
        None,
        None,
    )
    .expect("the http need is declared");
    let target = format!("http://{at}/v1/probe");
    let id = settle(|| {
        c.open(
            OWNER,
            NeedId(0),
            &OpenDesc {
                target: &target,
                method: b"GET",
                head_target: b"/v1/probe",
                timeout_ms: 5_000,
                ..OpenDesc::default()
            },
        )
    })
    .expect("the need opens through the framer");
    let (fields, body) = drain(c.as_ref(), id, 5);
    let seen = far.join().expect("the listener answered");
    assert!(seen.starts_with("GET /v1/probe HTTP/1.1\r\n"), "{seen}");
    assert_eq!(fields, 1, "one head");
    assert_eq!(body, b"hello");
    c.close(OWNER, id).expect("closed");
}

/// A private CA and a `localhost` leaf it signed: (ca_pem, leaf_der, key_der).
fn private_ca() -> (String, Vec<u8>, Vec<u8>) {
    use rcgen::{CertificateParams, IsCa, Issuer, KeyPair};
    let ca_kp = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_kp).unwrap();
    let issuer = Issuer::from_params(&ca_params, ca_kp);
    let kp = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec!["localhost".to_owned()])
        .unwrap()
        .signed_by(&kp, &issuer)
        .unwrap();
    (ca.pem(), leaf.der().to_vec(), kp.serialize_der())
}

/// A TLS far end on loopback, TLS from its first byte, echoing five bytes; answers its address.
fn tls_far_end(leaf: Vec<u8>, key: Vec<u8>) -> String {
    busbar_core_connector::tls::install_crypto_provider();
    let config = Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf.into()],
                rustls_pki_types::PrivateKeyDer::try_from(key).unwrap(),
            )
            .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").expect("a local listener");
    let at = listener.local_addr().expect("its address").to_string();
    std::thread::spawn(move || {
        for s in listener.incoming() {
            let Ok(s) = s else { return };
            let config = Arc::clone(&config);
            std::thread::spawn(move || {
                let conn = rustls::ServerConnection::new(config).unwrap();
                let mut tls = rustls::StreamOwned::new(conn, s);
                let mut buf = [0_u8; 5];
                if tls.read_exact(&mut buf).is_ok() {
                    let _ = tls.write_all(&buf);
                    let _ = tls.flush();
                }
            });
        }
    });
    at
}

/// A raw `tcp` stream to the TLS far end, upgraded through the host's TLS: what came back.
fn upgraded_echo(c: &dyn DeclaredConns, far: &str) -> Result<Vec<u8>, ConnError> {
    c.declare(
        OWNER,
        NeedId(0),
        &need("tcp", EGRESS_OPERATOR_INFRASTRUCTURE),
        None,
        None,
    )?;
    let id = settle(|| {
        c.open(
            OWNER,
            NeedId(0),
            &OpenDesc {
                target: far,
                timeout_ms: 5_000,
                ..OpenDesc::default()
            },
        )
    })?;
    settle(|| c.upgrade_secure(OWNER, id, Some("localhost"), None, false, NO_TICKET))?;
    let mut at = 0;
    while at < 5 {
        at += settle(|| c.write(OWNER, id, &b"hello"[at..], false, false))?;
    }
    let (_, body) = drain(c, id, 5);
    let _ = c.close(OWNER, id);
    Ok(body)
}

/// THE HOST'S TLS TRUSTS THE SUITE'S TEST ANCHORS: a stream to a far end whose certificate chains
/// to the test CA is upgraded and round-trips (the anchors went to the host, never to a plugin).
#[test]
fn a_tls_upgrade_verifies_against_the_suites_test_anchors() {
    let (ca, leaf, key) = private_ca();
    let far = tls_far_end(leaf, key);
    let c = host(Arc::new(|_| {}), Some(&ca));
    assert_eq!(upgraded_echo(c.as_ref(), &far), Ok(b"hello".to_vec()));
}

/// RED: the same upgrade with the anchors withheld is refused: the public roots alone do not
/// trust the test CA.
#[test]
fn red_with_the_anchors_withheld_the_tls_upgrade_is_refused() {
    let (_, leaf, key) = private_ca();
    let far = tls_far_end(leaf, key);
    let c = host(Arc::new(|_| {}), None);
    let answer = upgraded_echo(c.as_ref(), &far);
    assert!(answer.is_err(), "upgraded over an untrusted CA: {answer:?}");
}

/// THE SUITE BINDS OVER THE HOST: a door declaring an `http` need (the loader's dispatch test door
/// is not reachable here, so the tcp transport's door, restated with one `http` need) is bound
/// over the host connector, on each leg's own, and its need is declared there.
#[test]
fn the_suite_binds_an_http_need_over_the_host_connector() {
    use busbar_contract::abi::host::conn::connector::{Need, KEEP_NAMED};
    use busbar_contract::abi::mechanism::call::{AbiStr, Blob, BLOB_ABSENT};
    use busbar_contract::abi::mechanism::door::{Door, Statement};
    use busbar_plugin_loader::conformance::{dispatcher, Subject};
    use busbar_plugin_loader::dispatch::ConnTable;
    use std::sync::atomic::{AtomicPtr, Ordering};

    static SLOT: AtomicPtr<Door> = AtomicPtr::new(std::ptr::null_mut());
    extern "C" fn restated() -> *const Door {
        SLOT.load(Ordering::SeqCst)
    }
    const NONE: AbiStr = AbiStr {
        ptr: std::ptr::null(),
        len: 0,
    };
    const HTTP: &str = "http";
    let needs: &'static [Need] = Box::leak(Box::new([Need {
        direction: DIRECTION_OUTBOUND,
        egress_class: EGRESS_LOOPBACK_ALLOWED,
        transport: AbiStr {
            ptr: HTTP.as_ptr(),
            len: HTTP.len(),
        },
        auth: NONE,
        target_from: NONE,
        trust_from: NONE,
        details: Blob {
            ptr: std::ptr::null(),
            len: 0,
            fmt: BLOB_ABSENT,
            flags: 0,
        },
        keep_response_headers: std::ptr::null(),
        keep_response_headers_len: 0,
        timeout_ms: 0,
        keep_mode: KEEP_NAMED,
        _reserved: 0,
        deny_response_headers: std::ptr::null(),
        deny_response_headers_len: 0,
    }]));
    #[allow(unsafe_code)]
    // SAFETY: a door function answers a `'static` door with a `'static` Statement.
    let (real, st): (Door, Statement) = unsafe {
        let d = busbar_transport_tcp::linked::door().read_unaligned();
        (d, d.statement.read_unaligned())
    };
    let st: &'static Statement = Box::leak(Box::new(Statement {
        needs: needs.as_ptr(),
        needs_len: needs.len(),
        ..st
    }));
    SLOT.store(
        Box::into_raw(Box::new(Door {
            statement: st,
            ..real
        })),
        Ordering::SeqCst,
    );

    let s = Subject::new(restated, "unused", "{}").with_host(host);
    for leg in ["linked", "dropped"] {
        let d = dispatcher();
        let b = s.bind(&d, leg);
        assert!(
            matches!(b.conns, ConnTable::Host(_)),
            "{leg}: {:?}",
            b.conns
        );
        let row = busbar_plugin_loader::dispatch::LinkedRow::of(restated).unwrap();
        busbar_plugin_loader::dispatch::load_linked::<
            busbar_plugin_loader::dispatch::kinds::transport::Transport,
        >(&row, b)
        .expect("the http need is served by the host: bound, not refused as unserved");
    }
    // Without the host, the loader's test table serves no http: bound as a probe (no table).
    let plain = Subject::new(restated, "unused", "{}");
    assert!(matches!(
        plain.bind(&dispatcher(), "plain").conns,
        ConnTable::Probe
    ));
}
