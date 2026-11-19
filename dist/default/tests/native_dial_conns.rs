// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CONNECTION TABLE'S NATIVE ENTRY THROUGH THE LINKED HTTP IMAGE (deletion plan E2, half B): the connector, handed
//! the default distribution's own http transport image as its HTTP carrier (`Connector::carry_natively`, as the root
//! does at boot), serves a need no old entry serves through the image: the open dials, the reads hand the far end's
//! answer up, the close keeps the connection for the next exchange to the same destination. Each test is one
//! loopback upstream that counts the connections it accepted and the requests it answered.
//!
//! - open and reuse: two exchanges ride one connection;
//! - a far end that closes an idle connection: the next exchange dials afresh and is served;
//! - a far end that cuts the answer mid-body: the reader is answered a fault, and the broken connection is never lent;
//! - a failed dial: the reader is answered a fault with the connect stage;
//! - an idle dialled connection holds no read buffer: after a 256 KiB answer it holds no more than after a tiny one.

#![cfg(unix)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use busbar_contract::abi::host::conn::connector::{DIRECTION_OUTBOUND, EGRESS_DEFAULT, KEEP_NAMED};
use busbar_contract::abi::mechanism::rendering::{ReadBlob, ReadNeed};
use busbar_contract::conn::{
    ConnError, ConnId, Conns, DeclaredConns, InstanceId, NeedId, OpenDesc, PieceKind, PollConns,
};
use busbar_contract::storage::{StorageAccount, StorageDenied, StorageSource};
use busbar_core_connector::native_dial::NativeCarrier;
use busbar_core_connector::pool::PoolPosture;
use busbar_core_connector::{Connector, Judged, Verdict};
use busbar_plugin_abi::plane::CARRIER_HTTP;
use busbar_plugin_test::fake_needs::FakeNeeds;
use busbar_plugin_test::suites::harness::Harness;

const OWNER: InstanceId = InstanceId(11);
const NEED: NeedId = NeedId(1);

/// A storage account that counts what is reserved and not yet released.
#[derive(Default)]
struct Counted(AtomicUsize);

impl StorageAccount for Counted {
    fn try_reserve(&self, bytes: usize) -> Result<(), StorageDenied> {
        self.0.fetch_add(bytes, Ordering::SeqCst);
        Ok(())
    }
    fn release(&self, bytes: usize) {
        self.0.fetch_sub(bytes, Ordering::SeqCst);
    }
}

/// How the upstream answers each request on a connection.
#[derive(Clone, Copy)]
enum Answer {
    /// 200 with a whole body; the connection is kept open for the next request.
    KeepAlive,
    /// 200 with a whole body, then the upstream closes the connection (it went idle on the dialler's side).
    CloseAfter,
    /// The first request's answer is cut mid-body (a head promising 100 bytes, 10 sent, then the connection
    /// closed); every later connection answers whole.
    CutFirst,
    /// As `KeepAlive`, but the second request is answered with a [`BIG`] body.
    GrowSecond,
}

/// A body far larger than any buffer a connection may keep while idle.
const BIG: usize = 256 * 1024;

struct Upstream {
    addr: SocketAddr,
    accepted: Arc<AtomicUsize>,
    answered: Arc<AtomicUsize>,
}

const BODY: &[u8] = br#"{"ok":1}"#;

fn read_request(stream: &mut TcpStream) -> bool {
    let mut buf = Vec::new();
    let mut chunk = [0_u8; 4096];
    let head_end = loop {
        if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return false,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_ascii_lowercase();
    let len = head
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(0);
    while buf.len() < head_end + len {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return false,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    true
}

fn upstream(answer: Answer) -> Upstream {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the upstream");
    let addr = listener.local_addr().expect("its address");
    let accepted = Arc::new(AtomicUsize::new(0));
    let answered = Arc::new(AtomicUsize::new(0));
    let (a, n) = (Arc::clone(&accepted), Arc::clone(&answered));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let first = a.fetch_add(1, Ordering::SeqCst) == 0;
            let n = Arc::clone(&n);
            std::thread::spawn(move || {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(20)));
                while read_request(&mut stream) {
                    n.fetch_add(1, Ordering::SeqCst);
                    if matches!(answer, Answer::CutFirst) && first {
                        let _ = stream.write_all(
                            b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 100\r\n\r\n0123456789",
                        );
                        let _ = stream.flush();
                        std::thread::sleep(Duration::from_millis(50));
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                        return;
                    }
                    let big;
                    let body =
                        if matches!(answer, Answer::GrowSecond) && n.load(Ordering::SeqCst) == 2 {
                            big = vec![b'x'; BIG];
                            big.as_slice()
                        } else {
                            BODY
                        };
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(body);
                    let _ = stream.flush();
                    if matches!(answer, Answer::CloseAfter) {
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                        return;
                    }
                }
            });
        }
    });
    Upstream {
        addr,
        accepted,
        answered,
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
        transport: "http".into(),
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

/// The connector the root builds, with no old transport entry, keeping idle connections, handed the linked http
/// image as its HTTP carrier; the runtime it dials on; the account its sessions are charged to.
struct Fixture {
    runtime: tokio::runtime::Runtime,
    connector: Connector,
    account: Arc<Counted>,
    _harness: Harness,
}

fn fixture() -> Fixture {
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
    let connector =
        Connector::serving(Arc::new(loopback), None, Arc::new(|_, _| {})).pooling(PoolPosture {
            max_idle_per_host: 4,
            idle_timeout: Duration::from_secs(60),
        });
    let account = Arc::new(Counted::default());
    connector
        .carry_natively(
            vec![NativeCarrier {
                instance: Arc::from("busbar-transport-http"),
                port,
                carrier: CARRIER_HTTP,
                stall_ms: None,
            }],
            StorageSource::new(Arc::clone(&account) as Arc<dyn StorageAccount>),
        )
        .expect("the boot hand-over");
    DeclaredConns::declare(&connector, OWNER, NEED, &need(), None, None)
        .expect("http is declared natively: no old entry serves it");
    Fixture {
        runtime,
        connector,
        account,
        _harness: harness,
    }
}

/// What one exchange read: its status, its body, or the error that ended it (and the pieces before it).
struct Answered {
    status: Option<u32>,
    body: Vec<u8>,
    ended: Result<(), ConnError>,
}

impl Fixture {
    fn open(&self, target: &str) -> Result<ConnId, ConnError> {
        self.open_with(target, true)
    }

    /// An open whose own plaintext acceptance is `plaintext_accepted`.
    fn open_with(&self, target: &str, plaintext_accepted: bool) -> Result<ConnId, ConnError> {
        // The request is opened from the core that runs the exchange, as the far end opens it.
        self.runtime.block_on(async {
            self.connector.open(
                OWNER,
                NEED,
                &OpenDesc {
                    target,
                    fields: &[("content-type", b"application/json".as_slice())],
                    body: bytes::Bytes::from_static(br#"{"a":1}"#),
                    timeout_ms: 20_000,
                    method: b"POST",
                    head_target: b"/v1/chat",
                    plaintext_accepted,
                    ..OpenDesc::default()
                },
            )
        })
    }

    fn read(&self, conn: ConnId) -> Answered {
        self.runtime.block_on(async {
            let mut buf = vec![0_u8; 64 * 1024];
            let mut read = Answered {
                status: None,
                body: Vec::new(),
                ended: Ok(()),
            };
            loop {
                let piece = tokio::time::timeout(
                    Duration::from_secs(20),
                    std::future::poll_fn(|cx| self.connector.poll_read(OWNER, conn, cx, &mut buf)),
                )
                .await
                .expect("an answer or an error within 20 s");
                match piece {
                    Err(error) => {
                        read.ended = Err(error);
                        return read;
                    }
                    Ok(piece) => match piece.kind {
                        PieceKind::Fields if read.status.is_none() => {
                            read.status = piece.status_code
                        }
                        PieceKind::Fields | PieceKind::HookReply => {}
                        PieceKind::Body => read.body.extend_from_slice(&buf[..piece.len]),
                        PieceKind::Completion => return read,
                    },
                }
            }
        })
    }

    fn close(&self, conn: ConnId) {
        self.runtime
            .block_on(async { self.connector.close(OWNER, conn) })
            .expect("the close");
    }

    /// One whole exchange to `target`: opened, read to its end, closed.
    fn exchange(&self, target: &str) -> Answered {
        let conn = self.open(target).expect("the open");
        let read = self.read(conn);
        self.close(conn);
        read
    }
}

fn served(read: &Answered) {
    assert_eq!(read.ended, Ok(()), "the exchange ended whole");
    assert_eq!(read.status, Some(200));
    assert_eq!(read.body, BODY);
}

#[test]
fn an_open_is_answered_and_its_connection_is_reused_by_the_next_exchange() {
    let fixture = fixture();
    let up = upstream(Answer::KeepAlive);
    let target = format!("http://{}/v1/chat", up.addr);
    served(&fixture.exchange(&target));
    served(&fixture.exchange(&target));
    assert_eq!(up.answered.load(Ordering::SeqCst), 2);
    assert_eq!(
        up.accepted.load(Ordering::SeqCst),
        1,
        "the second exchange rode the first one's connection"
    );
}

#[test]
fn a_far_end_that_closes_an_idle_connection_costs_the_next_exchange_only_a_fresh_dial() {
    let fixture = fixture();
    let up = upstream(Answer::CloseAfter);
    let target = format!("http://{}/v1/chat", up.addr);
    served(&fixture.exchange(&target));
    // The far end closed the idle connection; its FIN reaches the reactor.
    std::thread::sleep(Duration::from_millis(200));
    served(&fixture.exchange(&target));
    assert_eq!(
        up.accepted.load(Ordering::SeqCst),
        2,
        "the closed idle connection was not lent: the second exchange dialled"
    );
}

#[test]
fn a_far_end_that_cuts_the_answer_mid_body_faults_the_reader_and_its_connection_is_never_lent() {
    let fixture = fixture();
    let up = upstream(Answer::CutFirst);
    let target = format!("http://{}/v1/chat", up.addr);
    let cut = fixture.exchange(&target);
    assert_eq!(cut.status, Some(200), "the head came first");
    assert_eq!(
        cut.ended,
        Err(ConnError::Fault),
        "the cut answer ends in a fault, never in a short body passed as whole"
    );
    assert!(cut.body.len() < 100);
    served(&fixture.exchange(&target));
    assert_eq!(
        up.accepted.load(Ordering::SeqCst),
        2,
        "the cut connection was not lent to the next exchange"
    );
}

#[test]
fn a_failed_dial_answers_its_reader_a_fault_at_the_connect_stage() {
    let fixture = fixture();
    let closed = {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.local_addr().expect("its address")
    };
    let target = format!("http://{closed}/v1/chat");
    match fixture.open(&target) {
        // The socket refused at once: the open itself fails.
        Err(error) => assert!(matches!(error, ConnError::Fault | ConnError::Refused)),
        Ok(conn) => {
            let read = fixture.read(conn);
            assert_eq!(read.ended, Err(ConnError::Fault));
            let cause = fixture
                .connector
                .failure_cause(OWNER, conn)
                .expect("the failed dial keeps its cause");
            assert_eq!(
                cause.stage,
                busbar_core_connector::native_dial::stage::CONNECT
            );
            assert!(!cause.outbound, "a refused connect is no local fault");
            fixture.close(conn);
        }
    }
}

#[test]
fn an_idle_dialled_connection_holds_no_read_buffer() {
    let fixture = fixture();
    let up = upstream(Answer::GrowSecond);
    let target = format!("http://{}/v1/chat", up.addr);
    served(&fixture.exchange(&target));
    // The connection is idle in its core's set: what is still charged to its account is the framer session's own
    // state (its output block for the request it renders, wiped, and its action list), never an answer's bytes.
    let idle_small = fixture.account.0.load(Ordering::SeqCst);
    let big = fixture.exchange(&target);
    assert_eq!(big.ended, Ok(()));
    assert_eq!(big.body.len(), BIG, "the big answer came through whole");
    assert_eq!(
        up.accepted.load(Ordering::SeqCst),
        1,
        "it rode the idle connection"
    );
    let idle_big = fixture.account.0.load(Ordering::SeqCst);
    assert!(
        idle_big <= idle_small,
        "idle again after a {BIG}-byte answer, the connection holds nothing more than after a tiny one ({idle_big} \
         against {idle_small} bytes): no read buffer is kept"
    );
    assert!(
        idle_small <= 4096,
        "an idle connection's charge is the session's small fixed state ({idle_small} bytes)"
    );
}

#[test]
fn an_idle_plaintext_connection_is_never_lent_to_an_open_without_plaintext_acceptance() {
    let fixture = fixture();
    let up = upstream(Answer::KeepAlive);
    let target = format!("http://{}/v1/chat", up.addr);
    // Dialled in the clear under the opener's own acceptance, then idle.
    served(&fixture.exchange(&target));
    // An open of the same need and destination that does not accept plaintext: the plaintext rule refuses it, so it
    // is never handed the idle plaintext connection.
    assert_eq!(
        fixture.open_with(&target, false),
        Err(ConnError::Refused),
        "an open without plaintext acceptance is refused, not lent a plaintext connection"
    );
    assert_eq!(up.answered.load(Ordering::SeqCst), 1);
}
