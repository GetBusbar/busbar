// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use busbar_contract::abi::host::conn::connector::{
    DIRECTION_OUTBOUND, EGRESS_DEFAULT, EGRESS_LOOPBACK_ALLOWED, EGRESS_OPERATOR_INFRASTRUCTURE,
};
use busbar_contract::abi::mechanism::rendering::{ReadBlob, ReadNeed};
use busbar_contract::conn::{
    ConnError, ConnId, Conns, DeclaredConns, InstanceId, NeedId, OpenDesc, PieceKind, NO_TICKET,
};
use busbar_contract::transport::{EgressTrust, TransportSettings};
use busbar_plugin_loader::dispatch::kinds::transport::Transport;
use busbar_plugin_loader::dispatch::load::rendering_of_library;
use busbar_plugin_loader::dispatch::{
    load_dropped, Bind, ConnTable, DispatchConfig, Dispatcher, NoSink,
};

use crate::doors::Dispatched;
use crate::registry::{Entry, Transports};
use crate::{Connector, DialJudge, Judged, Verdict};

const OWNER: InstanceId = InstanceId(1);

fn dispatcher() -> &'static Arc<Dispatcher> {
    static DISPATCHER: OnceLock<Arc<Dispatcher>> = OnceLock::new();
    DISPATCHER.get_or_init(|| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("the host I/O runtime");
        let handle = runtime.handle().clone();
        std::thread::spawn(move || runtime.block_on(std::future::pending::<()>()));
        crate::io::install_process_reactor(handle.clone());
        let dispatcher = Dispatcher::new(DispatchConfig::default());
        dispatcher.install_runtime(handle);
        dispatcher.install_io(crate::hostio::process());
        Arc::new(dispatcher)
    })
}

fn actual_transport(variable: &str) -> Entry {
    static NEXT_INSTANCE: AtomicU64 = AtomicU64::new(1);
    let path = PathBuf::from(std::env::var_os(variable).expect(variable));
    let statement = rendering_of_library(&path)
        .expect("the actual transport image renders")
        .expect("the actual image exports a door");
    let dispatcher = dispatcher();
    let plugin = load_dropped::<Transport>(
        &path,
        &statement,
        Bind {
            instance: Arc::from(format!(
                "{variable}-{}",
                NEXT_INSTANCE.fetch_add(1, Ordering::Relaxed)
            )),
            max_inflight_cap: 1024,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: ConnTable::NoNeeds,
        },
    )
    .expect("the actual transport image loads");
    let door = Dispatched::open_on(
        plugin,
        &TransportSettings::default(),
        Arc::clone(dispatcher),
    )
    .expect("the actual transport opens");
    Entry {
        door: Arc::new(door),
        alpn: Vec::new(),
    }
}

fn connector(anchors: &[Vec<u8>], judge: Arc<dyn DialJudge>, http: bool) -> Connector {
    let mut entries = vec![actual_transport("BUSBAR_TEST_TCP_CDYLIB")];
    if http {
        entries.push(actual_transport("BUSBAR_TEST_HTTP_CDYLIB"));
    }
    let transports = Transports::new(entries).expect("the actual transport claims compose");
    let trust = EgressTrust {
        extra_anchors: anchors.to_vec(),
        ..EgressTrust::default()
    };
    let tls = crate::tls::client::build_client_config(&trust).expect("host TLS configuration");
    Connector::serving(transports, judge, Some(Arc::new(tls)), Arc::new(|_, _| {}))
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
        keep_mode: busbar_contract::abi::host::conn::connector::KEEP_NAMED,
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
    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
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
    let _ = crate::tls::installed_crypto();
    let server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )
        .unwrap();
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
    connector.declare(
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

#[test]
fn the_real_tcp_carrier_upgrades_with_the_hosts_configured_test_ca() {
    let (ca, tls) = tls_identity();
    let (target, far) = tls_listener(tls);
    let connector = connector(&[ca], Arc::new(loopback), false);
    let answer = upgraded_echo(&connector, &target);
    assert!(far
        .join()
        .unwrap()
        .expect("a real TCP dial reached the TLS server"));
    assert_eq!(answer, Ok(b"hello".to_vec()));
}

#[test]
fn the_real_tcp_carrier_refuses_a_tls_upgrade_without_the_test_ca() {
    let (_, tls) = tls_identity();
    let (target, far) = tls_listener(tls);
    let connector = connector(&[], Arc::new(loopback), false);
    let answer = upgraded_echo(&connector, &target);
    assert!(!far
        .join()
        .unwrap()
        .expect("a real TCP dial reached the TLS server"));
    assert!(answer.is_err(), "upgraded over an untrusted CA: {answer:?}");
}

#[test]
fn the_real_tcp_carrier_obeys_the_production_destination_guard() {
    let destinations = busbar_kernel::config::Destinations {
        block_private_addresses: busbar_kernel::config::sections::DEFAULT_BLOCK_PRIVATE_ADDRESSES,
        ..Default::default()
    };
    let guard = crate::process::dest_judge(&destinations).unwrap();
    let connector = connector(&[], crate::process::judge(guard, &[]), false);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let mut sequence = 0;
    let mut open = |class, target: &str| -> Result<ConnId, ConnError> {
        sequence += 1;
        connector.declare(OWNER, NeedId(sequence), &need("tcp", class), None, None)?;
        settle(|| {
            connector.open(
                OWNER,
                NeedId(sequence),
                &OpenDesc {
                    target,
                    timeout_ms: 2_000,
                    ..OpenDesc::default()
                },
            )
        })
    };
    assert_eq!(
        open(EGRESS_DEFAULT, "10.0.0.1:443"),
        Err(ConnError::Refused)
    );
    assert_eq!(open(EGRESS_DEFAULT, &address), Err(ConnError::Refused));
    assert_eq!(
        open(EGRESS_OPERATOR_INFRASTRUCTURE, "169.254.169.254:80"),
        Err(ConnError::Refused)
    );
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock,
        "a refused destination was dialled"
    );
    let id = open(EGRESS_OPERATOR_INFRASTRUCTURE, &address).unwrap();
    drop(accept(&listener).expect("the admitted dial reaches the listener"));
    connector.close(OWNER, id).unwrap();
}

#[test]
fn the_real_http_framer_delivers_one_head_and_the_exact_body() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let far = std::thread::spawn(move || {
        let mut socket = accept(&listener).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut seen = [0_u8; 512];
        let mut used = 0;
        while !seen[..used].windows(4).any(|w| w == b"\r\n\r\n") {
            assert!(
                Instant::now() < deadline,
                "the complete request head arrives"
            );
            assert!(
                used < seen.len(),
                "the short fixture GET fits its head buffer"
            );
            socket
                .set_read_timeout(Some(deadline.saturating_duration_since(Instant::now())))
                .unwrap();
            let read = socket.read(&mut seen[used..]).unwrap();
            assert_ne!(read, 0, "the request must have its complete head");
            used += read;
        }
        socket
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello")
            .unwrap();
        seen[..used].to_vec()
    });
    let connector = connector(
        &[],
        crate::process::judge(
            crate::process::dest_judge(&Default::default()).unwrap(),
            &[],
        ),
        true,
    );
    assert!(connector.serves_scheme("http"));
    connector
        .declare(
            OWNER,
            NeedId(0),
            &need("http", EGRESS_LOOPBACK_ALLOWED),
            None,
            None,
        )
        .unwrap();
    let target = format!("http://{address}/v1/probe");
    let id = settle(|| {
        connector.open(
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
    .unwrap();
    let mut heads = 0;
    let mut body = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut buffer = [0_u8; 512];
    while body.len() < 5 {
        assert!(Instant::now() < deadline, "the complete HTTP reply arrives");
        let piece = settle_until(deadline, || {
            connector.read(OWNER, id, NO_TICKET, &mut buffer)
        })
        .unwrap();
        match piece.kind {
            PieceKind::Fields => {
                heads += 1;
                assert!(heads <= 1, "one response head");
            }
            PieceKind::Body => {
                assert!(body.len() + piece.len <= 5, "the peer sends only hello");
                body.extend_from_slice(&buffer[..piece.len]);
            }
            PieceKind::Completion => break,
            PieceKind::HookReply => panic!("an HTTP reply became a hook reply"),
        }
    }
    connector.close(OWNER, id).unwrap();
    let seen = far.join().unwrap();
    assert!(seen.starts_with(b"GET /v1/probe HTTP/1.1\r\n"));
    assert_eq!(heads, 1);
    assert_eq!(body, b"hello");
}
