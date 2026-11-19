// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SEALED CREDENTIALS ON THE NATIVE DIAL, THROUGH THE LINKED HTTP IMAGE: a provider credential core holds sealed (a
//! header value the opener names in `busbar-sealed-fields`, a query pair it hands as `busbar-sealed-query`) never
//! reaches the transport instance that frames the request. The connector, handed the default distribution's own
//! http image as its HTTP carrier (as the root does at boot), is given the image behind an observer that keeps every
//! byte core hands the instance (`begin`, `ingest`, `emit`) and can make the image's output misbehave.
//!
//! - the transport sees only filler, as long as the credential and fresh for every value of every request; the
//!   upstream receives each real credential exactly once, in its place (the header's value, the target's query), and
//!   none of the host's sealing metadata;
//! - a framer whose output drops, duplicates, re-encodes or splits a filler fails the exchange with the SEAL_BROKEN
//!   refusal (core's own fault, not the far end's), and not one byte reaches the upstream.

#![cfg(unix)]

use std::io::Read;
use std::io::Write as _;
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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
use busbar_plugin_abi::records::{tag, Records};
use busbar_plugin_abi::transport as wire;
use busbar_plugin_test::fake_needs::FakeNeeds;
use busbar_plugin_test::suites::harness::Harness;
use busbar_ports::transport::{
    ConnIn, TransportEvent, TransportOut, TransportPort, TransportSession,
};
use busbar_ports::PortError;

const OWNER: InstanceId = InstanceId(12);
const NEED: NeedId = NeedId(1);

/// The sealed header's name and its credential.
const KEY_NAME: &str = "x-api-key";
const KEY: &[u8] = b"HSECRETkeyHSECRETkeyHSECRET0123";
/// The sealed query pair's name and its credential (percent-encoded as the auth binding hands it).
const QUERY_NAME: &str = "api_key";
const QUERY: &[u8] = b"QSECRETqueryQSECRETquery987654";

/// The SEAL_BROKEN refusal's text (the connector's `SEAL_BROKEN`).
const SEAL_BROKEN: &str = "the framer did not render a sealed value verbatim exactly once";

/// A storage account that keeps no count.
struct Free;

impl StorageAccount for Free {
    fn try_reserve(&self, _: usize) -> Result<(), StorageDenied> {
        Ok(())
    }
    fn release(&self, _: usize) {}
}

/// What the observer does to the image's output bytes that carry the value the framer was handed for a sealed
/// credential.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Tamper {
    /// Nothing: the image's own output.
    None,
    /// The value is replaced by other bytes of its length.
    Drop,
    /// The value is written twice, back to back.
    Duplicate,
    /// The value's first byte is percent-encoded.
    ReEncode,
    /// The bytes are handed on as two WRITEs, cut in the middle of the value.
    Split,
}

/// Which sealed value the tampering works on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Aim {
    Header,
    Query,
}

/// The real image behind an observer: every byte core hands the instance is kept; the value the framer was handed
/// for each sealed credential is kept per request head; the image's WRITEs are tampered with as `tamper` says.
struct Observed {
    inner: Arc<dyn TransportPort>,
    seen: Mutex<Vec<u8>>,
    /// Per request head: the value the framer was handed for the sealed header, and the query value it was handed.
    handed: Mutex<Vec<(Vec<u8>, Vec<u8>)>>,
    tamper: Mutex<(Tamper, Aim)>,
}

impl Observed {
    fn keep(&self, bytes: &[u8]) {
        self.seen
            .lock()
            .expect("the observer")
            .extend_from_slice(bytes);
    }

    /// The value the last head handed the framer for the aimed credential.
    fn aimed(&self, aim: Aim) -> Option<Vec<u8>> {
        let handed = self.handed.lock().expect("the observer");
        let (header, query) = handed.last()?;
        Some(match aim {
            Aim::Header => header.clone(),
            Aim::Query => query.clone(),
        })
    }

    /// Read a request head's records: the sealed header's value and the target's `api_key` value.
    fn note_head(&self, records: &[u8]) {
        let mut header = Vec::new();
        let mut query = Vec::new();
        for record in Records::new(records).flatten() {
            if record.tag == tag::PAIR {
                if let Ok((name, value)) = record.pair() {
                    if name.eq_ignore_ascii_case(KEY_NAME) {
                        header = value.to_vec();
                    }
                }
            } else if record.tag == tag::H_PATH {
                if let Ok(path) = record.text() {
                    let needle = format!("{QUERY_NAME}=");
                    if let Some(at) = path.find(&needle) {
                        let rest = &path[at + needle.len()..];
                        let end = rest.find(['&', '#']).unwrap_or(rest.len());
                        query = rest.as_bytes()[..end].to_vec();
                    }
                }
            }
        }
        self.handed
            .lock()
            .expect("the observer")
            .push((header, query));
    }

    /// Hand `out` on, tampered with where it carries the aimed value.
    fn pass(&self, out: TransportOut<'_>, sink: &mut dyn FnMut(TransportOut<'_>)) {
        let (tamper, aim) = *self.tamper.lock().expect("the observer");
        let TransportOut::Write(bytes) = out else {
            sink(out);
            return;
        };
        let Some(value) = self.aimed(aim).filter(|v| !v.is_empty()) else {
            sink(TransportOut::Write(bytes));
            return;
        };
        let Some(at) = bytes.windows(value.len()).position(|w| w == value) else {
            sink(TransportOut::Write(bytes));
            return;
        };
        let end = at + value.len();
        let mut made = Vec::with_capacity(bytes.len() + value.len() + 2);
        match tamper {
            Tamper::None => {
                sink(TransportOut::Write(bytes));
                return;
            }
            Tamper::Drop => {
                made.extend_from_slice(&bytes[..at]);
                made.extend(std::iter::repeat_n(b'z', value.len()));
                made.extend_from_slice(&bytes[end..]);
            }
            Tamper::Duplicate => {
                made.extend_from_slice(&bytes[..end]);
                made.extend_from_slice(&value);
                made.extend_from_slice(&bytes[end..]);
            }
            Tamper::ReEncode => {
                made.extend_from_slice(&bytes[..at]);
                let _ = write!(made, "%{:02X}", value[0]);
                made.extend_from_slice(&bytes[at + 1..]);
            }
            Tamper::Split => {
                let cut = at + value.len() / 2;
                sink(TransportOut::Write(&bytes[..cut]));
                sink(TransportOut::Write(&bytes[cut..]));
                return;
            }
        }
        sink(TransportOut::Write(&made));
    }
}

impl TransportPort for Observed {
    fn alpn(&self, role: u32) -> &[Box<str>] {
        self.inner.alpn(role)
    }
    fn defaults(&self, role: u32) -> &[(Box<str>, Box<str>)] {
        self.inner.defaults(role)
    }
    fn protocols(&self) -> &[Box<str>] {
        self.inner.protocols()
    }
    fn listener_slots(&self) -> &[Box<str>] {
        self.inner.listener_slots()
    }
    fn facts(&self) -> u64 {
        self.inner.facts()
    }
    fn begin(
        &self,
        c: &ConnIn<'_>,
        sink: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<TransportSession, PortError> {
        for bytes in [
            c.alpn.as_bytes(),
            c.sni.as_bytes(),
            c.peer.as_bytes(),
            c.local.as_bytes(),
            c.tls_peer_cert,
            c.leftover,
            c.head,
            c.local_fingerprint.as_bytes(),
        ] {
            self.keep(bytes);
        }
        self.inner.begin(c, &mut |out| self.pass(out, sink))
    }
    fn ingest(
        &self,
        s: &mut TransportSession,
        bytes: &[u8],
        sink: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<(), PortError> {
        self.keep(bytes);
        self.inner.ingest(s, bytes, &mut |out| self.pass(out, sink))
    }
    fn emit(
        &self,
        s: &mut TransportSession,
        stream: u64,
        piece: u32,
        arg: u32,
        bytes: &[u8],
        sink: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<(), PortError> {
        self.keep(bytes);
        if piece == wire::E_HEAD {
            self.note_head(bytes);
        }
        self.inner.emit(s, stream, piece, arg, bytes, &mut |out| {
            self.pass(out, sink)
        })
    }
    fn timer(
        &self,
        s: &mut TransportSession,
        sink: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<(), PortError> {
        self.inner.timer(s, &mut |out| self.pass(out, sink))
    }
    fn datagram(
        &self,
        s: &mut TransportSession,
        path: u32,
        secured: bool,
        bytes: &[u8],
        sink: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<(), PortError> {
        self.keep(bytes);
        self.inner
            .datagram(s, path, secured, bytes, &mut |out| self.pass(out, sink))
    }
    fn event(
        &self,
        s: &mut TransportSession,
        ev: TransportEvent<'_>,
        sink: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<(), PortError> {
        self.inner.event(s, ev, &mut |out| self.pass(out, sink))
    }
}

/// A loopback upstream: every request it read (head and content-length body), every byte it was sent on every
/// connection, and the connections it accepted. Each request is answered 200 `{"ok":1}`; connections are kept.
struct Upstream {
    addr: SocketAddr,
    requests: Arc<Mutex<Vec<Vec<u8>>>>,
    received: Arc<AtomicUsize>,
    closed: Arc<AtomicUsize>,
}

fn upstream() -> Upstream {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the upstream");
    let addr = listener.local_addr().expect("its address");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let received = Arc::new(AtomicUsize::new(0));
    let closed = Arc::new(AtomicUsize::new(0));
    let (r, n, c) = (
        Arc::clone(&requests),
        Arc::clone(&received),
        Arc::clone(&closed),
    );
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let (r, n, c) = (Arc::clone(&r), Arc::clone(&n), Arc::clone(&c));
            std::thread::spawn(move || {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(20)));
                let mut buf: Vec<u8> = Vec::new();
                let mut chunk = [0_u8; 4096];
                loop {
                    let head_end = buf.windows(4).position(|w| w == b"\r\n\r\n");
                    if let Some(at) = head_end {
                        let head = String::from_utf8_lossy(&buf[..at]).to_ascii_lowercase();
                        let len = head
                            .lines()
                            .find_map(|line| line.strip_prefix("content-length:"))
                            .and_then(|v| v.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        if buf.len() >= at + 4 + len {
                            let request: Vec<u8> = buf.drain(..at + 4 + len).collect();
                            r.lock().expect("the requests").push(request);
                            let body = br#"{"ok":1}"#;
                            let _ = write!(
                                stream,
                                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
                                body.len()
                            );
                            let _ = stream.write_all(body);
                            let _ = stream.flush();
                            continue;
                        }
                    }
                    match stream.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(got) => {
                            n.fetch_add(got, Ordering::SeqCst);
                            buf.extend_from_slice(&chunk[..got]);
                        }
                    }
                }
                c.fetch_add(1, Ordering::SeqCst);
            });
        }
    });
    Upstream {
        addr,
        requests,
        received,
        closed,
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

/// The connector the root builds, keeping idle connections, its HTTP carrier the linked http image behind the
/// observer.
struct Fixture {
    runtime: tokio::runtime::Runtime,
    connector: Connector,
    observed: Arc<Observed>,
    _harness: Harness,
}

fn fixture() -> Fixture {
    let harness = Harness::admit_linked(&busbar_transport_http::PLUGIN, FakeNeeds::new())
        .expect("the linked http image admits");
    let inner = harness
        .open_transport("busbar-transport-http", b"{}")
        .expect("the linked http image opens");
    let observed = Arc::new(Observed {
        inner,
        seen: Mutex::new(Vec::new()),
        handed: Mutex::new(Vec::new()),
        tamper: Mutex::new((Tamper::None, Aim::Header)),
    });
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("a runtime");
    busbar_core_connector::io::install_process_reactor(runtime.handle().clone());
    let connector = Connector::serving(
        busbar_core_connector::registry::Transports::default(),
        Arc::new(loopback),
        None,
        Arc::new(|_, _| {}),
    )
    .pooling(PoolPosture {
        max_idle_per_host: 4,
        idle_timeout: Duration::from_secs(60),
    });
    connector
        .carry_natively(
            vec![NativeCarrier {
                instance: Arc::from("busbar-transport-http"),
                port: Arc::clone(&observed) as Arc<dyn TransportPort>,
                carrier: CARRIER_HTTP,
                stall_ms: None,
            }],
            StorageSource::new(Arc::new(Free) as Arc<dyn StorageAccount>),
        )
        .expect("the boot hand-over");
    DeclaredConns::declare(&connector, OWNER, NEED, &need(), None, None)
        .expect("http is declared natively");
    Fixture {
        runtime,
        connector,
        observed,
        _harness: harness,
    }
}

/// What one exchange read.
struct Answered {
    status: Option<u32>,
    ended: Result<(), ConnError>,
}

impl Fixture {
    /// Open an exchange whose head carries the sealed header and the sealed query pair, as the kernel's far end
    /// builds it for a route whose credential core holds.
    fn open(&self, target: &str) -> ConnId {
        let query = format!("{QUERY_NAME}={}", String::from_utf8_lossy(QUERY));
        let fields: [(&str, &[u8]); 4] = [
            ("content-type", b"application/json".as_slice()),
            (KEY_NAME, KEY),
            ("busbar-sealed-query", query.as_bytes()),
            ("busbar-sealed-fields", KEY_NAME.as_bytes()),
        ];
        self.runtime
            .block_on(async {
                self.connector.open(
                    OWNER,
                    NEED,
                    &OpenDesc {
                        target,
                        fields: &fields,
                        body: bytes::Bytes::from_static(br#"{"a":1}"#),
                        timeout_ms: 20_000,
                        method: b"POST",
                        head_target: b"/v1/chat",
                        plaintext_accepted: true,
                        ..OpenDesc::default()
                    },
                )
            })
            .expect("the open")
    }

    fn read(&self, conn: ConnId) -> Answered {
        self.runtime.block_on(async {
            let mut buf = vec![0_u8; 64 * 1024];
            let mut read = Answered {
                status: None,
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
                        PieceKind::Completion => return read,
                        _ => {}
                    },
                }
            }
        })
    }

    fn close(&self, conn: ConnId) {
        let _ = self
            .runtime
            .block_on(async { self.connector.close(OWNER, conn) });
    }

    fn transport_saw(&self, needle: &[u8]) -> bool {
        let seen = self.observed.seen.lock().expect("the observer");
        seen.windows(needle.len()).any(|w| w == needle)
    }
}

fn count(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .filter(|w| *w == needle)
        .count()
}

#[test]
fn a_sealed_credential_never_reaches_the_transport_and_reaches_the_upstream_once_in_its_place() {
    let fixture = fixture();
    let up = upstream();
    let target = format!("http://{}/v1/chat", up.addr);
    for _ in 0..2 {
        let conn = fixture.open(&target);
        let read = fixture.read(conn);
        fixture.close(conn);
        assert_eq!(read.ended, Ok(()), "the exchange ended whole");
        assert_eq!(read.status, Some(200));
    }
    let requests = up.requests.lock().expect("the requests").clone();
    let carried = |needle: &[u8]| {
        requests
            .iter()
            .map(|request| count(&request.to_ascii_lowercase(), needle))
            .sum::<usize>()
    };
    let (saw_key, saw_query) = (fixture.transport_saw(KEY), fixture.transport_saw(QUERY));
    let facts = format!(
        "the transport was handed the header credential: {saw_key}; the query credential: {saw_query}; the \
         upstream was sent busbar-sealed-query {} and busbar-sealed-fields {} times",
        carried(b"busbar-sealed-query"),
        carried(b"busbar-sealed-fields"),
    );
    assert!(
        !saw_key && !saw_query,
        "the transport instance was handed a sealed credential: {facts}"
    );
    let handed = fixture
        .observed
        .handed
        .lock()
        .expect("the observer")
        .clone();
    assert_eq!(handed.len(), 2, "two request heads");
    for (header, query) in &handed {
        assert_eq!(
            header.len(),
            KEY.len(),
            "the filler is as long as the credential"
        );
        assert_eq!(query.len(), QUERY.len());
    }
    assert_ne!(handed[0].0, handed[1].0, "a fresh filler per request");
    assert_ne!(handed[0].1, handed[1].1, "a fresh filler per request");
    assert_ne!(handed[0].0, handed[0].1, "a fresh filler per value");

    assert_eq!(requests.len(), 2);
    for request in &requests {
        let line = format!(
            "POST /v1/chat?{QUERY_NAME}={} HTTP/1.1\r\n",
            String::from_utf8_lossy(QUERY)
        );
        assert!(
            request.starts_with(line.as_bytes()),
            "the query credential is in the target: {}",
            String::from_utf8_lossy(request)
        );
        let header = format!("{KEY_NAME}: {}\r\n", String::from_utf8_lossy(KEY));
        assert_eq!(
            count(
                &request.to_ascii_lowercase(),
                header.to_ascii_lowercase().as_bytes()
            ),
            1,
            "the header credential is in its field: {}",
            String::from_utf8_lossy(request)
        );
        assert_eq!(count(request, KEY), 1, "the header credential once");
        assert_eq!(count(request, QUERY), 1, "the query credential once");
        assert_eq!(
            count(&request.to_ascii_lowercase(), b"busbar-sealed"),
            0,
            "none of the host's sealing metadata reaches the upstream: {}",
            String::from_utf8_lossy(request)
        );
    }
    assert_eq!(
        up.received.load(Ordering::SeqCst),
        requests.iter().map(Vec::len).sum::<usize>(),
        "nothing but the two requests"
    );
}

/// One exchange through a framer whose output is tampered with as `tamper` says: it fails with the SEAL_BROKEN
/// refusal, charged to core, and the upstream is sent nothing.
fn broken(tamper: Tamper, aim: Aim) {
    let fixture = fixture();
    *fixture.observed.tamper.lock().expect("the observer") = (tamper, aim);
    let up = upstream();
    let target = format!("http://{}/v1/chat", up.addr);
    let conn = fixture.open(&target);
    let read = fixture.read(conn);
    let cause = fixture.connector.failure_cause(OWNER, conn);
    fixture.close(conn);
    assert!(
        read.ended.is_err(),
        "{tamper:?} on the {aim:?} value: the exchange fails ({:?})",
        read.status
    );
    let cause = cause.expect("the failure keeps its cause");
    assert!(
        cause.text.contains(SEAL_BROKEN),
        "{tamper:?} on the {aim:?} value: refused SEAL_BROKEN, not {:?}",
        cause.text
    );
    assert!(
        cause.outbound,
        "core's own refusal: no destination is charged"
    );
    // The connection was dropped: the upstream sees its end, having been sent nothing.
    let waited = Instant::now();
    while up.closed.load(Ordering::SeqCst) == 0 && waited.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        up.received.load(Ordering::SeqCst),
        0,
        "{tamper:?} on the {aim:?} value: not one byte reached the upstream"
    );
    assert!(up.requests.lock().expect("the requests").is_empty());
}

#[test]
fn a_framer_that_drops_the_header_filler_is_refused_seal_broken_and_sends_nothing() {
    broken(Tamper::Drop, Aim::Header);
}

#[test]
fn a_framer_that_drops_the_query_filler_is_refused_seal_broken_and_sends_nothing() {
    broken(Tamper::Drop, Aim::Query);
}

#[test]
fn a_framer_that_duplicates_the_filler_is_refused_seal_broken_and_sends_nothing() {
    broken(Tamper::Duplicate, Aim::Header);
}

#[test]
fn a_framer_that_re_encodes_the_filler_is_refused_seal_broken_and_sends_nothing() {
    broken(Tamper::ReEncode, Aim::Query);
}

#[test]
fn a_framer_that_splits_the_filler_across_writes_is_refused_seal_broken_and_sends_nothing() {
    broken(Tamper::Split, Aim::Header);
}
