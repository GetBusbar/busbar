// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The connector over a real TCP carrier and a real HTTP/1.1 framer: real sockets, real TLS, the
//! production destination guard. The carrier and the framer are core's in-tree kind-level doubles
//! (`tcp_carrier_double`, `http_framer_double`), loaded through the loader's linked path and opened
//! as dispatched doors, so no plugin is built or loaded (owner ruling: "core knows nothing about
//! plugins just kinds, plugins test themselves and nothing else").

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use busbar_contract::conn::codes::{
    DIRECTION_OUTBOUND, EGRESS_DEFAULT, EGRESS_LOOPBACK_ALLOWED, EGRESS_OPERATOR_INFRASTRUCTURE,
};
use busbar_contract::conn::{
    ConnError, ConnId, Conns, DeclaredConns, InstanceId, NeedId, OpenDesc, PieceKind, NO_TICKET,
};
use busbar_contract::rendering::{ReadBlob, ReadNeed};
use busbar_contract::transport::{EgressTrust, TransportSettings};
#[path = "tcp_carrier_double.rs"]
mod tcp_carrier_double;

#[path = "http_framer_double.rs"]
mod http_framer_double;

use crate::registry::{Entry, Transports};
use crate::{Connector, DialJudge, Judged, Verdict};

const OWNER: InstanceId = InstanceId(1);

fn runtime() -> &'static tokio::runtime::Handle {
    static RUNTIME: OnceLock<tokio::runtime::Handle> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("the host I/O runtime");
        let handle = runtime.handle().clone();
        std::thread::spawn(move || runtime.block_on(std::future::pending::<()>()));
        handle
    })
}

fn loopback(target: &str, _: u32, _: Judged) -> Option<Result<SocketAddr, Verdict>> {
    Some(
        target
            .parse::<SocketAddr>()
            .ok()
            .filter(|address| address.ip().is_loopback())
            .ok_or(busbar_contract::services::codes::DEST_UNRESOLVABLE),
    )
}

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
        keep_mode: busbar_contract::conn::codes::KEEP_NAMED,
        keep_response_headers: Vec::new(),
        deny_response_headers: Vec::new(),
    }
}

fn settle<T>(call: impl FnMut() -> Result<T, ConnError>) -> Result<T, ConnError> {
    settle_until(Instant::now() + Duration::from_secs(10), call)
}

fn settle_until<T>(
    deadline: Instant,
    mut call: impl FnMut() -> Result<T, ConnError>,
) -> Result<T, ConnError> {
    loop {
        match call() {
            Err(ConnError::Pending) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(2));
            }
            answer => return answer,
        }
    }
}

fn accept(listener: &TcpListener) -> std::io::Result<TcpStream> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match listener.accept() {
            Ok((socket, _)) => {
                socket.set_nonblocking(false)?;
                socket.set_read_timeout(Some(Duration::from_secs(5)))?;
                socket.set_write_timeout(Some(Duration::from_secs(5)))?;
                return Ok(socket);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(std::io::ErrorKind::TimedOut.into());
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(error) => return Err(error),
        }
    }
}

fn tls_identity() -> (Vec<u8>, Arc<rustls::ServerConfig>) {
    use busbar_contract::crypto::testing::rcgen::{
        BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair,
    };
    let ca_key = KeyPair::generate().unwrap();
    let mut parameters = CertificateParams::new(Vec::new()).unwrap();
    parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = parameters.self_signed(&ca_key).unwrap();
    let issuer = Issuer::from_params(&parameters, ca_key);
    let key = KeyPair::generate().unwrap();
    let certificate = CertificateParams::new(vec!["localhost".to_owned()])
        .unwrap()
        .signed_by(&key, &issuer)
        .unwrap();
    let server = std::sync::Arc::unwrap_or_clone(
        busbar_contract::crypto::tls::server_config(|b| {
            b.with_no_client_auth().with_single_cert(
                vec![certificate.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
            )
        })
        .unwrap(),
    );
    (ca.der().to_vec(), Arc::new(server))
}

fn tls_listener(
    tls: Arc<rustls::ServerConfig>,
) -> (String, std::thread::JoinHandle<std::io::Result<bool>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let far = std::thread::spawn(move || {
        let socket = accept(&listener)?;
        let connection = rustls::ServerConnection::new(tls).map_err(std::io::Error::other)?;
        let mut stream = rustls::StreamOwned::new(connection, socket);
        let mut hello = [0_u8; 5];
        if stream.read_exact(&mut hello).is_err() {
            return Ok(false);
        }
        assert_eq!(&hello, b"hello");
        stream.write_all(&hello)?;
        stream.flush()?;
        stream.conn.send_close_notify();
        Ok(true)
    });
    (address, far)
}

fn upgraded_echo(connector: &Connector, target: &str) -> Result<Vec<u8>, ConnError> {
    DeclaredConns::declare(
        connector,
        OWNER,
        NeedId(0),
        &need("tcp", EGRESS_OPERATOR_INFRASTRUCTURE),
        None,
        None,
    )?;
    let id = settle(|| {
        connector.open(
            OWNER,
            NeedId(0),
            &OpenDesc {
                target,
                timeout_ms: 5_000,
                ..OpenDesc::default()
            },
        )
    })?;
    let answer = (|| {
        settle(|| connector.upgrade_secure(OWNER, id, Some("localhost"), None, false, NO_TICKET))?;
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut at = 0;
        while at < 5 {
            assert!(Instant::now() < deadline, "the complete TLS write finishes");
            let written = settle_until(deadline, || {
                connector.write(OWNER, id, &b"hello"[at..], false, false)
            })?;
            assert_ne!(written, 0, "a TLS write makes progress");
            assert!(
                written <= 5 - at,
                "the transport reports only written bytes"
            );
            at += written;
        }
        let mut body = Vec::new();
        let mut heads = 0;
        let mut buffer = [0_u8; 256];
        while body.len() < 5 {
            assert!(Instant::now() < deadline, "the complete TLS body arrives");
            let piece = settle_until(deadline, || {
                connector.read(OWNER, id, NO_TICKET, &mut buffer)
            })?;
            match piece.kind {
                PieceKind::Body => {
                    assert!(body.len() + piece.len <= 5, "the peer sends only hello");
                    body.extend_from_slice(&buffer[..piece.len]);
                }
                PieceKind::Completion => break,
                PieceKind::Fields => {
                    heads += 1;
                    assert!(heads <= 1, "the peer cannot send repeated heads");
                }
                PieceKind::HookReply => panic!("a TLS stream became a hook reply"),
            }
        }
        Ok(body)
    })();
    connector.close(OWNER, id).expect("the connection closes");
    answer
}

