// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
// Real transport/Connector refusal controls from the former loader HTTPS simulator.
use busbar_contract::abi::host::conn::connector::{DIRECTION_OUTBOUND, EGRESS_LOOPBACK_ALLOWED};
use busbar_contract::abi::mechanism::rendering::{ReadBlob, ReadNeed};
use busbar_contract::conn::{ConnError, DeclaredConns, InstanceId, NeedId, OpenDesc};
use busbar_contract::transport::TransportSettings;
use busbar_core_connector::doors::Dispatched;
use busbar_core_connector::registry::{Entry, Transports};
use busbar_core_connector::{Connector, Judged, Verdict};
use busbar_plugin_loader::dispatch::kinds::transport::Transport;
use busbar_plugin_loader::dispatch::load::rendering_of_library;
use busbar_plugin_loader::dispatch::{
    load_dropped, Bind, ConnTable, DispatchConfig, Dispatcher, NoSink,
};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicU64, AtomicUsize, Ordering},
    Arc, OnceLock,
};
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

fn dispatcher() -> &'static Arc<Dispatcher> {
    static DISPATCHER: OnceLock<Arc<Dispatcher>> = OnceLock::new();
    DISPATCHER.get_or_init(|| {
        let dispatcher = Dispatcher::new(DispatchConfig::default());
        dispatcher.install_runtime(runtime().clone());
        dispatcher.install_io(busbar_core_connector::hostio::process());
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

#[test]
fn actual_secure_and_undeclared_refusals_happen_before_any_destination_open() {
    let _reactor = runtime().enter();
    let judged = Arc::new(AtomicUsize::new(0));
    let seen = judged.clone();
    let connector = Connector::serving(
        Transports::new(vec![
            actual_transport("BUSBAR_TEST_TCP_CDYLIB"),
            actual_transport("BUSBAR_TEST_HTTP_CDYLIB"),
        ])
        .expect("actual TCP and HTTP claims compose"),
        Arc::new(move |_: &str, _: u32, _: Judged| {
            seen.fetch_add(1, Ordering::SeqCst);
            Some(Err::<std::net::SocketAddr, Verdict>(
                busbar_contract::abi::host::service::DEST_UNRESOLVABLE,
            ))
        }),
        None,
        Arc::new(|_, _| {}),
    );
    DeclaredConns::declare(
        &connector,
        OWNER,
        NeedId(0),
        &need("http", EGRESS_LOOPBACK_ALLOWED),
        None,
        None,
    )
    .unwrap();
    let target = OpenDesc {
        target: "http://missing.example/reply",
        ..Default::default()
    };
    assert_eq!(
        connector.open_request(OWNER, NeedId(0), &target, true, 123),
        Err(ConnError::AuthRefused)
    );
    assert_eq!(
        judged.load(Ordering::SeqCst),
        0,
        "secure delivery is refused before any destination open"
    );
    assert_eq!(
        connector.open_request(OWNER, NeedId(8), &target, false, 123),
        Err(ConnError::UndeclaredNeed)
    );
    assert_eq!(
        judged.load(Ordering::SeqCst),
        0,
        "undeclared need is refused before any destination open"
    );
    assert_eq!(
        connector.open_request(OWNER, NeedId(0), &target, false, 123),
        Err(ConnError::Refused)
    );
    assert_eq!(
        judged.load(Ordering::SeqCst),
        1,
        "an admitted target crosses the real destination judge exactly once"
    );

    let mut trust = need("https", EGRESS_LOOPBACK_ALLOWED);
    trust.trust_from = "settings.ca".into();
    assert_eq!(
        DeclaredConns::declare(
            &connector,
            OWNER,
            NeedId(1),
            &trust,
            None,
            Some("invalid operator CA")
        ),
        Err(ConnError::Refused)
    );
    assert_eq!(
        judged.load(Ordering::SeqCst),
        1,
        "invalid trust never reaches a destination open"
    );
    assert_eq!(
        connector.open_request(
            OWNER,
            NeedId(1),
            &OpenDesc {
                target: "https://missing.example/reply",
                ..Default::default()
            },
            false,
            123
        ),
        Err(ConnError::Refused)
    );
    assert_eq!(judged.load(Ordering::SeqCst), 1);
}

#[test]
fn actual_http_target_and_request_path_reach_the_same_real_peer() {
    use busbar_contract::conn::{Conns, PieceKind, NO_TICKET};
    use std::io::{Read, Write};
    use std::time::{Duration, Instant};
    let _reactor = runtime().enter();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let peer = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(2))
                }
                other => panic!("actual HTTP peer not reached: {other:?}"),
            }
        };
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut bytes = Vec::new();
        let mut chunk = [0u8; 512];
        loop {
            let n = socket.read(&mut chunk).unwrap();
            assert_ne!(n, 0);
            bytes.extend_from_slice(&chunk[..n]);
            if bytes.windows(4).any(|w| w == b"\r\n\r\n") && bytes.ends_with(b"body") {
                break;
            }
            assert!(bytes.len() < 4096 && Instant::now() < deadline);
        }
        socket
            .write_all(b"HTTP/1.1 201 Created\r\ncontent-length: 6\r\n\r\nanswer")
            .unwrap();
        bytes
    });
    let connector = Connector::serving(
        Transports::new(vec![
            actual_transport("BUSBAR_TEST_TCP_CDYLIB"),
            actual_transport("BUSBAR_TEST_HTTP_CDYLIB"),
        ])
        .unwrap(),
        busbar_core_connector::process::judge(
            busbar_core_connector::process::dest_judge(&Default::default()).unwrap(),
            &[],
        ),
        None,
        Arc::new(|_, _| {}),
    );
    DeclaredConns::declare(
        &connector,
        OWNER,
        NeedId(0),
        &need("http", EGRESS_LOOPBACK_ALLOWED),
        None,
        None,
    )
    .unwrap();
    let target = format!("http://{address}/base");
    let desc = OpenDesc {
        target: &target,
        method: b"GET",
        head_target: b"/reply",
        body: Some(b"body".to_vec()),
        timeout_ms: 5_000,
        ..Default::default()
    };
    let connection = connector
        .open_request(OWNER, NeedId(0), &desc, false, 123)
        .expect("actual HTTP request opens");
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut body = Vec::new();
    let mut heads = 0;
    let mut buffer = [0u8; 512];
    while body.len() < 6 {
        match connector.read(OWNER, connection, NO_TICKET, &mut buffer) {
            Err(ConnError::Pending) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(2))
            }
            Ok(piece) => match piece.kind {
                PieceKind::Fields => heads += 1,
                PieceKind::Body => body.extend_from_slice(&buffer[..piece.len]),
                PieceKind::Completion => break,
                PieceKind::HookReply => panic!("HTTP reply became a hook reply"),
            },
            other => panic!("actual HTTP reply: {other:?}"),
        }
    }
    connector.close(OWNER, connection).unwrap();
    let request = peer.join().unwrap();
    assert!(request.starts_with(b"GET /reply HTTP/1.1\r\n"));
    assert!(request.ends_with(b"body"));
    assert_eq!(heads, 1);
    assert_eq!(body, b"answer");
}
