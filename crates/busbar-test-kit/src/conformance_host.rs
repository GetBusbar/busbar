// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SUITE'S HOST, ONCE FOR EVERY PLUGIN REPO: what implements the suite's `host:` seam
//! (`conformance::Host`), in one of two forms, by what the plugin's needs reach.
//!
//! * [`stream_host`]: a plugin whose needs are plain streams (`tcp`) is served by the test kit's
//!   stream table ([`TcpConns`](crate::tcp_conns::TcpConns)), upgraded with the connector's own
//!   client TLS. It links no transport plugin.
//! * [`host`]: a plugin whose needs are framed (`http`, `grpc`, ...) is served by busbar's own
//!   `Connector`, carrier -> [TLS] -> framer (`BUSBAR-1.6.0.md` THE DESIGN §5), over the
//!   transport doors the PLUGIN names (busbar links no transport plugin), each loaded through the
//!   loader's one load and opened as the root opens a transport door, with a dial judge that
//!   admits loopback only.
//!
//! Either way the TLS trusts the platform roots plus the suite's TEST trust anchors ([`anchors`]),
//! never handed to the plugin. [`far_end`] is a TLS far end whose certificate chains to the
//! anchors; [`tls_front`] fronts a plugin's live backend with them. A plugin repo states its far
//! end, and its doors where its needs are framed, once:
//!
//! ```ignore
//! // tests/support/conformance_host.rs: plain stream needs
//! busbar_test_kit::conformance_host! { far_end: "localhost:41859" }
//!
//! // framed needs
//! busbar_test_kit::conformance_host! {
//!     far_end: "localhost:52049",
//!     doors: [
//!         ("tcp", busbar_transport_tcp::door::MACRO_DOOR),
//!         ("http", busbar_transport_http::door::MACRO_DOOR),
//!     ],
//!     http_need: true,
//! }
//! ```
//!
//! which gives it `FAR_END`, `host`, `guarded_host`, `anchors`, `far_end(answer)`,
//! `tls_front(preamble, upstream)` and the host's own proof as its tests (`http_need: true` adds
//! the http framer's).
//!
//! `guarded_host` is THE GUARDED MODE: the same host, every dial judged by the production
//! destination guard (`busbar_core_connector::process::dest_judge`) at the deployment default
//! (`advanced.block_private_addresses: true`, nothing allowed), so a plugin's refusal cell proves
//! its outbound need is judged as a running busbar judges it. The suite's own runs keep `host`,
//! whose judge admits loopback only, because they dial the real local endpoints their settings
//! name.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use busbar_contract::abi::host::conn::connector::{
    DIRECTION_OUTBOUND, EGRESS_OPERATOR_INFRASTRUCTURE,
};
use busbar_contract::abi::mechanism::call::{Blob, Outcome};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
use busbar_contract::abi::mechanism::rendering::{ReadBlob, ReadNeed};
use busbar_contract::abi::sdk::door::{blank_in, blank_out, MacroDoor};
use busbar_contract::abi::transport::slot;
use busbar_contract::conn::{
    ConnError, ConnId, InstanceId, NeedId, OpenDesc, PieceKind, NO_TICKET,
};
pub use busbar_contract::conn::{ConnWake, DeclaredConns};
use busbar_contract::transport::EgressTrust;
use busbar_core_connector::framer::{Call, Crossed, DoorFacts, FramerDoor};
use busbar_core_connector::registry::{Entry, Transports};
use busbar_core_connector::test_support::{
    private_ca, ClientTls, ServerTls, StdClientSession, StdServerSession, TestCa,
};
use busbar_core_connector::{Connector, Judged, Verdict};
use busbar_plugin_loader::dispatch::kinds::transport::{Transport, TransportFacts};
use busbar_plugin_loader::dispatch::{
    load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, Frame, InFrame, LinkedRow, NoSink,
    OutFrame, Plugin,
};

/// The framer doors a host serves, as the root links them: (claim, door). The plugin names them
/// (the carrier and the framers its needs name), so busbar links no transport plugin.
pub type Doors = &'static [(&'static str, MacroDoor)];

/// The suite's `host:` seam, as the macro's `host` states it.
pub use crate::conformance::Host;

/// The suite's test CA: [`anchors`] is its certificate, [`far_end`] serves a leaf it signed.
fn ca() -> &'static TestCa {
    static CA: OnceLock<TestCa> = OnceLock::new();
    CA.get_or_init(private_ca)
}

/// THE SUITE'S TEST TRUST ANCHORS (PEM), for `conformance_suite!`'s `tls:`.
#[must_use]
pub fn anchors() -> &'static str {
    &ca().ca_pem
}

/// THE HOST CONNECTOR over `doors` (what [`conformance_host!`](crate::conformance_host)'s `host`
/// answers for the suite's `host:`, a `conformance::Host`): one per leg.
///
/// # Panics
/// The anchors do not parse, a transport door does not load or open, or the view does not compose.
#[must_use]
pub fn host(
    doors: Doors,
    wake: busbar_contract::conn::ConnWake,
    anchors: Option<&str>,
) -> Arc<dyn DeclaredConns> {
    // The reactor a socket a plugin opens from a dispatcher worker registers on, as the root
    // installs it (`root::connector::io_reactor`): the connector's own I/O thread.
    busbar_core_connector::io::install_process_reactor(io_reactor());
    let trust = EgressTrust {
        extra_anchors: anchors.map(pem_certs).unwrap_or_default(),
        ..EgressTrust::default()
    };
    let tls = busbar_core_connector::tls::client::build_client_config(&trust)
        .unwrap_or_else(|e| panic!("the host's connection security does not build: {e}"));
    let view = Transports::new(entries(doors))
        .unwrap_or_else(|e| panic!("the host's transport doors do not compose: {e}"));
    Arc::new(Connector::serving(
        view,
        Arc::new(loopback),
        Some(Arc::new(tls)),
        wake,
    ))
}

/// THE GUARDED HOST CONNECTOR over `doors`: [`host`], every dial judged by the production
/// destination guard at the deployment default (`busbar_core_connector::process`), so a plugin's
/// outbound need meets exactly the judgement it meets in a running busbar. A refusal cell opens a
/// plugin on it and names a destination the guard refuses.
#[must_use]
pub fn guarded_host(
    doors: Doors,
    wake: busbar_contract::conn::ConnWake,
    anchors: Option<&str>,
) -> Arc<dyn DeclaredConns> {
    host(doors, wake, anchors)
}

/// THE GUARDED STREAM HOST: [`stream_host`], every dial judged by the production destination
/// guard at the deployment default, the address it pinned dialled exactly.
#[must_use]
pub fn guarded_stream_host(wake: ConnWake, anchors: Option<&str>) -> Arc<dyn DeclaredConns> {
    stream_host(wake, anchors)
}

/// THE STREAM HOST (`conformance::Host`, for plain stream needs): the test kit's stream table,
/// each connection upgraded with the connector's client TLS. One per leg.
///
/// # Panics
/// The anchors do not parse, or the connector's client TLS does not build.
#[must_use]
pub fn stream_host(wake: ConnWake, anchors: Option<&str>) -> Arc<dyn DeclaredConns> {
    let trust = EgressTrust {
        extra_anchors: anchors.map(pem_certs).unwrap_or_default(),
        ..EgressTrust::default()
    };
    let tls = ClientTls::new(&trust)
        .unwrap_or_else(|e| panic!("the host's connection security does not build: {e}"));
    Arc::new(crate::tcp_conns::TcpConns::with_tls(
        wake,
        Arc::new(StreamTls(tls)),
    ))
}

/// The connector's client TLS as the stream table's dial: the handshake runs to completion on the
/// blocking socket, verified against the trust it was built with.
struct StreamTls(ClientTls);

impl crate::tcp_conns::SecureDial for StreamTls {
    fn secure(
        &self,
        server: &str,
        verify_off: bool,
        tcp: TcpStream,
    ) -> std::io::Result<Box<dyn crate::tcp_conns::SecuredSock>> {
        if verify_off {
            // The suite's needs always verify; an unverified upgrade is not served here.
            return Err(std::io::Error::other("an unverified upgrade is not served"));
        }
        Ok(Box::new(Secured(self.0.connect_std(server, tcp)?)))
    }
}

/// One secured stream.
struct Secured(StdClientSession);

impl Read for Secured {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for Secured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl crate::tcp_conns::SecuredSock for Secured {
    fn tcp(&self) -> &TcpStream {
        self.0.tcp()
    }

    fn close(&mut self) {
        self.0.close();
    }
}

/// The connector's I/O thread: a single-threaded runtime of its own whose reactor drives every
/// socket the plugin opens from a dispatcher worker. Built once.
fn io_reactor() -> tokio::runtime::Handle {
    static IO: OnceLock<tokio::runtime::Handle> = OnceLock::new();
    IO.get_or_init(|| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("the host's I/O runtime builds");
        let handle = rt.handle().clone();
        std::thread::Builder::new()
            .name("conformance-host-io".into())
            .spawn(move || rt.block_on(std::future::pending::<()>()))
            .expect("the host's I/O thread starts");
        handle
    })
    .clone()
}

/// THE DIAL JUDGE: a loopback address (a literal, or a name that resolves to one) and nothing else.
fn loopback(dest: &str, _class: u32, _done: Judged) -> Option<Result<SocketAddr, Verdict>> {
    let refused = busbar_contract::abi::host::service::DEST_UNRESOLVABLE;
    let at = dest
        .to_socket_addrs()
        .ok()
        .and_then(|mut a| a.find(|a| a.ip().is_loopback()));
    Some(at.ok_or(refused))
}

/// Every certificate in `pem`, DER.
fn pem_certs(pem: &str) -> Vec<Vec<u8>> {
    let certs = busbar_core_connector::test_support::certs_from_pem(pem);
    assert!(
        !certs.is_empty(),
        "the suite's trust anchors hold no certificate"
    );
    certs
}

/// The dispatcher the host's transport doors are adopted by. As the root's: its workers run inside
/// the connector's I/O runtime, and a CARRIER door moves its bytes over the process's one host I/O
/// (`io.*`, `busbar_core_connector::hostio::process`), the connector's.
fn transport_dispatcher() -> &'static Dispatcher {
    static ONE: OnceLock<Dispatcher> = OnceLock::new();
    ONE.get_or_init(|| {
        let d = Dispatcher::new(DispatchConfig::default());
        d.install_runtime(io_reactor());
        d.install_io(busbar_core_connector::hostio::process());
        d
    })
}

/// The framer entries: each door loaded through the one loader and opened with no settings, as
/// the root opens a transport door that declares none it reads.
fn entries(doors: Doors) -> Vec<Entry> {
    doors
        .iter()
        .map(|&(claim, door)| {
            let bind = Bind {
                instance: Arc::from(claim),
                max_inflight_cap: 1024,
                sink: Arc::new(NoSink),
                dispatcher: transport_dispatcher().adopter(),
                // A transport door is a framer the connector drives: it declares no need.
                conns: ConnTable::NoNeeds,
            };
            let plugin = LinkedRow::of_macro(door)
                .and_then(|row| load_linked::<Transport>(&row, bind))
                .unwrap_or_else(|e| panic!("the host's transport `{claim}` does not load: {e}"));
            Entry {
                door: Arc::new(Opened::open(plugin, claim)),
                alpn: Vec::new(),
            }
        })
        .collect()
}

/// One transport door, opened, as the connector reaches it (the root's `doors::Dispatched`).
struct Opened {
    plugin: Plugin<Transport>,
    facts: DoorFacts,
}

impl Opened {
    fn open(plugin: Plugin<Transport>, claim: &str) -> Self {
        let stated = plugin
            .context::<TransportFacts>()
            .cloned()
            .unwrap_or_else(|| panic!("the host's transport `{claim}` states no transport tail"));
        let mut i: OpenIn = blank_in();
        i.settings = Blob::ABSENT;
        let mut f = Frame::new(i, blank_out::<OpenOut>());
        let opened = plugin.call(life::OPEN, &mut f);
        assert_eq!(
            opened.outcome,
            Outcome::Ready,
            "the host's transport `{claim}` does not open"
        );
        plugin
            .ready(transport_dispatcher(), Duration::from_secs(10))
            .unwrap_or_else(|e| panic!("the host's transport `{claim}` is not ready: {e}"));
        let facts = DoorFacts {
            name: plugin.name().to_owned(),
            claims: stated.claims,
            role: stated.role,
            composes_over: stated.composes_over,
            ported: stated.ported,
            status_rows: stated.status_rows,
            datagram: stated.datagram,
            duplex: stated
                .upgrades
                .iter()
                .chain(&stated.sessions)
                .copied()
                .collect(),
        };
        Self { plugin, facts }
    }
}

/// One crossing through the dispatcher: the host's `in`/`out` copied in, the answer copied back.
fn go<I: InFrame, O: OutFrame>(p: &Plugin<Transport>, s: u32, i: &mut I, o: &mut O) -> Crossed {
    let mut f = Frame::new(*i, *o);
    let c = p.call(s, &mut f);
    *i = f.input;
    *o = f.out;
    Crossed {
        outcome: c.outcome,
        error: c.error,
    }
}

/// One side of a carried connection: an inline ticket of the transport dispatcher, the one every
/// transport door is adopted by (its wakes route there), as the root's.
struct InlineSide(busbar_plugin_loader::dispatch::InlineTicket);

impl busbar_core_connector::carrier::Side for InlineSide {
    fn ticket(&self) -> busbar_contract::abi::mechanism::ticket::Ticket {
        self.0.ticket()
    }

    fn register(&self, waker: &std::task::Waker) {
        self.0.register(waker);
    }
}

/// One INLINE crossing on `ticket` (a RESUME when `resume`): the host's `in`/`out` copied in, the
/// answer copied back.
fn go_inline<I: InFrame, O: OutFrame>(
    p: &Plugin<Transport>,
    ticket: busbar_contract::abi::mechanism::ticket::Ticket,
    resume: bool,
    s: u32,
    i: &mut I,
    o: &mut O,
) -> Crossed {
    let mut f = Frame::new(*i, *o);
    let c = p.call_inline(ticket, resume, s, &mut f);
    *i = f.input;
    *o = f.out;
    Crossed {
        outcome: c.outcome,
        error: c.error,
    }
}

impl FramerDoor for Opened {
    fn facts(&self) -> &DoorFacts {
        &self.facts
    }

    fn side(&self) -> Option<Box<dyn busbar_core_connector::carrier::Side>> {
        if self.facts.role != busbar_contract::abi::transport::ROLE_CARRIER {
            return None;
        }
        transport_dispatcher()
            .inline_ticket()
            .map(|t| Box::new(InlineSide(t)) as Box<dyn busbar_core_connector::carrier::Side>)
    }

    fn carry(
        &self,
        side: &dyn busbar_core_connector::carrier::Side,
        resume: bool,
        call: busbar_core_connector::carrier::Carry<'_>,
    ) -> Crossed {
        use busbar_core_connector::carrier::Carry;
        let (p, t) = (&self.plugin, side.ticket());
        match call {
            Carry::Listen(i, o) => go_inline(p, t, resume, slot::LISTEN, i, o),
            Carry::Accept(i, o) => go_inline(p, t, resume, slot::ACCEPT, i, o),
            Carry::Dial(i, o) => go_inline(p, t, resume, slot::DIAL, i, o),
            Carry::Read(i, o) => go_inline(p, t, resume, slot::READ, i, o),
            Carry::Write(i, o) => go_inline(p, t, resume, slot::WRITE, i, o),
            Carry::Flush(i, o) => go_inline(p, t, resume, slot::FLUSH, i, o),
            Carry::Shut(i, o) => go_inline(p, t, resume, slot::SHUT, i, o),
            // `cancel` is made on no ticket: the ticket it cancels rides its `in`.
            Carry::Cancel(i, o) => go(p, life::CANCEL, i, o),
        }
    }

    fn cross(&self, call: Call<'_>) -> Crossed {
        let p = &self.plugin;
        match call {
            Call::Locate(i, o) => go(p, slot::LOCATE, i, o),
            Call::Begin(i, o) => go(p, slot::BEGIN, i, o),
            Call::Ingest(i, o) => go(p, slot::INGEST, i, o),
            Call::Emit(i, o) => go(p, slot::EMIT, i, o),
            Call::Encode(i, o) => go(p, slot::ENCODE, i, o),
            Call::Refuse(i, o) => go(p, slot::REFUSE, i, o),
            Call::Finish(i, o) => go(p, slot::FINISH, i, o),
            Call::Detach(i, o) => go(p, slot::DETACH, i, o),
            Call::Adopt(i, o) => go(p, slot::ADOPT, i, o),
            Call::Timer(i, o) => go(p, slot::TIMER, i, o),
        }
    }
}

// ---- the far end ----

/// What a far end answers a connection: given every byte it has read so far, the bytes to send
/// back and close (`Some`), or `None` to read on.
pub type Answer = fn(&[u8]) -> Option<Vec<u8>>;

/// THE SUITE'S TLS FAR END at `at` (started once; later calls are no-ops): every connection's
/// handshake is busbar's test kit's, with a `localhost` certificate [`anchors`] trusts, and its
/// bytes are answered by `answer`.
///
/// # Panics
/// `at` cannot be bound.
pub fn far_end(at: &'static str, answer: Answer) {
    static STARTED: OnceLock<()> = OnceLock::new();
    STARTED.get_or_init(|| {
        let listener = TcpListener::bind(at)
            .unwrap_or_else(|e| panic!("the suite's far end cannot bind {at}: {e}"));
        serve(listener, answer);
    });
}

/// Serve `listener` over TLS with a leaf the test CA signed, answering each connection by `answer`.
fn serve(listener: TcpListener, answer: Answer) {
    let tls = ServerTls::new(&[ca().leaf_der.clone()], &ca().key_der, None, &[])
        .unwrap_or_else(|e| panic!("the suite's far end has no TLS identity: {e}"));
    std::thread::spawn(move || {
        for tcp in listener.incoming() {
            let Ok(tcp) = tcp else { return };
            let tls = tls.clone();
            std::thread::spawn(move || {
                if let Ok(mut s) = tls.accept_std(tcp) {
                    if s.handshake_ok() {
                        reply(&mut s, answer);
                    }
                }
            });
        }
    });
}

fn reply(s: &mut StdServerSession, answer: Answer) {
    let mut seen = Vec::new();
    let mut buf = [0_u8; 4096];
    loop {
        if let Some(out) = answer(&seen) {
            let _ = s.write_all(&out);
            let _ = s.flush();
            s.close();
            return;
        }
        match s.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => seen.extend_from_slice(&buf[..n]),
        }
    }
}

/// A far end's cleartext negotiation before TLS (a protocol's own StartTLS: Postgres's
/// `SSLRequest` answered `S`, LDAP's StartTLS extended operation, ...): `true` = go on to TLS.
pub type Preamble = fn(&mut TcpStream) -> bool;

/// THE SUITE'S TLS FRONT at `at` (started once; later calls are no-ops): each connection's
/// cleartext `preamble` runs, then the TLS handshake (busbar's test kit, a `localhost` certificate
/// [`anchors`] trusts), then its bytes are carried both ways to the REAL backend at `upstream`
/// (the plugin's live service, in the clear on loopback). What it proves: the plugin's own
/// connection is secured by the HOST's TLS against the suite's anchors.
///
/// # Panics
/// `at` cannot be bound.
pub fn tls_front(at: &'static str, preamble: Preamble, upstream: &'static str) {
    static STARTED: OnceLock<()> = OnceLock::new();
    STARTED.get_or_init(|| {
        let listener = TcpListener::bind(at)
            .unwrap_or_else(|e| panic!("the suite's TLS front cannot bind {at}: {e}"));
        let tls = ServerTls::new(&[ca().leaf_der.clone()], &ca().key_der, None, &[])
            .unwrap_or_else(|e| panic!("the suite's TLS front has no TLS identity: {e}"));
        std::thread::spawn(move || {
            for tcp in listener.incoming() {
                let Ok(tcp) = tcp else { return };
                let tls = tls.clone();
                std::thread::spawn(move || front(tcp, &tls, preamble, upstream));
            }
        });
    });
}

/// One connection through the TLS front: preamble, handshake, then both directions carried until
/// either side ends.
fn front(mut tcp: TcpStream, tls: &ServerTls, preamble: Preamble, upstream: &str) {
    if !preamble(&mut tcp) {
        return;
    }
    let Ok(ctl) = tcp.try_clone() else { return };
    let Ok(mut s) = tls.accept_std(tcp) else {
        return;
    };
    if !s.handshake_ok() {
        return;
    }
    let Ok(mut up) = TcpStream::connect(upstream) else {
        return;
    };
    let tick = Some(Duration::from_millis(2));
    if ctl.set_read_timeout(tick).is_err() || up.set_read_timeout(tick).is_err() {
        return;
    }
    let idle = |e: &std::io::Error| {
        matches!(
            e.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        )
    };
    let mut buf = [0_u8; 16 * 1024];
    loop {
        match s.read(&mut buf) {
            Ok(0) => return,
            Ok(n) => {
                if up.write_all(&buf[..n]).is_err() {
                    return;
                }
            }
            Err(e) if idle(&e) => {}
            Err(_) => return,
        }
        match up.read(&mut buf) {
            Ok(0) => {
                s.close();
                return;
            }
            Ok(n) => {
                if s.write_all(&buf[..n]).and_then(|()| s.flush()).is_err() {
                    return;
                }
            }
            Err(e) if idle(&e) => {}
            Err(_) => return,
        }
    }
}

// ---- the host's own proof, run with the suite (the macro's tests call these) ----

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

/// Five bytes back for five bytes in: the TLS echo the host's own proof dials.
fn echo(seen: &[u8]) -> Option<Vec<u8>> {
    (seen.len() >= 5).then(|| seen[..5].to_vec())
}

/// A raw `tcp` stream to a TLS echo, upgraded through the host's TLS: what came back.
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

/// A TLS echo on a port of its own; its address.
fn tls_echo() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a local listener");
    let at = listener.local_addr().expect("its address").to_string();
    serve(listener, echo);
    at
}

/// THE HOST'S TLS TRUSTS THE SUITE'S TEST ANCHORS: a stream to a far end whose certificate chains
/// to the test CA is upgraded and round-trips (the anchors went to the host, never to the plugin).
///
/// # Panics
/// When it does not.
pub fn the_hosts_tls_upgrade_verifies_against_the_suites_test_anchors(host: Host) {
    let c = host(Arc::new(|_, _| {}), Some(anchors()));
    assert_eq!(
        upgraded_echo(c.as_ref(), &tls_echo()),
        Ok(b"hello".to_vec())
    );
}

/// RED: the same upgrade with the anchors withheld is refused: the platform roots alone do not
/// trust the test CA.
///
/// # Panics
/// When it is not.
pub fn red_with_the_anchors_withheld_the_hosts_tls_upgrade_is_refused(host: Host) {
    let c = host(Arc::new(|_, _| {}), None);
    let answer = upgraded_echo(c.as_ref(), &tls_echo());
    assert!(answer.is_err(), "upgraded over an untrusted CA: {answer:?}");
}

/// AN `http` NEED THROUGH THE HOST'S FRAMER: declared on the host, opened at a local HTTP
/// listener's URL, the request goes out framed by the linked http door over the tcp carrier and the
/// answer comes back as one head and its body.
///
/// # Panics
/// When it does not.
pub fn an_http_need_reaches_a_local_http_listener_through_the_hosts_framer(host: Host) {
    use busbar_contract::abi::host::conn::connector::EGRESS_LOOPBACK_ALLOWED;

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

    let c = host(Arc::new(|_, _| {}), None);
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

/// THE GUARDED HOST JUDGES AS PRODUCTION DOES (website security.md: "one guard judges every
/// outbound connection"): on `guarded` (the macro's `guarded_host`), a private address and loopback
/// are refused under the default class, cloud metadata is refused even under operator
/// infrastructure (where private reach is allowed), and nothing refused is dialled; the control,
/// loopback under operator infrastructure, reaches the same listener.
///
/// # Panics
/// When it does not.
pub fn the_conformance_host_guard_refuses_a_private_destination(guarded: Host) {
    use busbar_contract::abi::host::conn::connector::EGRESS_DEFAULT;

    let listener = TcpListener::bind("127.0.0.1:0").expect("a local listener");
    listener.set_nonblocking(true).expect("a polled listener");
    let at = listener.local_addr().expect("its address").to_string();
    let c = guarded(Arc::new(|_, _| {}), Some(anchors()));
    let mut n = 0;
    let mut open = |class: u32, target: &str| -> Result<ConnId, ConnError> {
        n += 1;
        c.declare(OWNER, NeedId(n), &need("tcp", class), None, None)?;
        settle(|| {
            c.open(
                OWNER,
                NeedId(n),
                &OpenDesc {
                    target,
                    timeout_ms: 2_000,
                    ..OpenDesc::default()
                },
            )
        })
    };
    let refused = Err(ConnError::Refused);
    assert_eq!(
        open(EGRESS_DEFAULT, "10.0.0.1:443").map(|_| ()),
        refused,
        "a private address under the default class"
    );
    assert_eq!(
        open(EGRESS_DEFAULT, &at).map(|_| ()),
        refused,
        "loopback under the default class"
    );
    assert_eq!(
        open(EGRESS_OPERATOR_INFRASTRUCTURE, "169.254.169.254:80").map(|_| ()),
        refused,
        "cloud metadata under operator infrastructure"
    );
    assert!(
        listener.accept().is_err(),
        "a destination the guard refuses was dialled"
    );
    // CONTROL: operator infrastructure admits loopback, so the refusals above are the guard's.
    let id =
        open(EGRESS_OPERATOR_INFRASTRUCTURE, &at).expect("loopback under operator infrastructure");
    let until = Instant::now() + Duration::from_secs(5);
    while listener.accept().is_err() {
        assert!(
            Instant::now() < until,
            "the admitted dial never reached the listener"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
    let _ = c.close(OWNER, id);
}

/// A plugin repo's suite host, stated once: its far end, and its transport doors where its needs
/// are framed. Expands to `FAR_END`, `host` (the suite's `host:`), `anchors` (its `tls:`),
/// `far_end`, `tls_front`, and the host's own proof as `#[test]`s. With no `doors` the host is
/// [`stream_host`](crate::conformance_host::stream_host); with `doors` it is
/// [`host`](crate::conformance_host::host) over them, and `http_need: true` adds the http
/// framer's proof.
#[macro_export]
macro_rules! conformance_host {
    (far_end: $at:expr $(,)?) => {
        /// THE HOST (`busbar_test_kit::conformance::Host`): the stream table. One per leg.
        #[allow(dead_code)]
        #[must_use]
        pub fn host(
            wake: $crate::conformance_host::ConnWake,
            anchors: Option<&str>,
        ) -> std::sync::Arc<dyn $crate::conformance_host::DeclaredConns> {
            $crate::conformance_host::stream_host(wake, anchors)
        }

        /// THE GUARDED HOST: [`host`], every dial judged by the production destination guard at
        /// the deployment default. One per refusal cell.
        #[allow(dead_code)]
        #[must_use]
        pub fn guarded_host(
            wake: $crate::conformance_host::ConnWake,
            anchors: Option<&str>,
        ) -> std::sync::Arc<dyn $crate::conformance_host::DeclaredConns> {
            $crate::conformance_host::guarded_stream_host(wake, anchors)
        }

        $crate::conformance_host!(@common $at);
    };
    (far_end: $at:expr, doors: [$(($claim:expr, $door:expr)),+ $(,)?] $(,)?) => {
        $crate::conformance_host! { far_end: $at, doors: [$(($claim, $door)),+], http_need: false }
    };
    (far_end: $at:expr, doors: [$(($claim:expr, $door:expr)),+ $(,)?], http_need: $http:tt $(,)?) => {
        /// The transport doors the host serves: (claim, door).
        pub const DOORS: $crate::conformance_host::Doors = &[$(($claim, $door)),+];

        /// THE HOST CONNECTOR (`busbar_test_kit::conformance::Host`) over [`DOORS`]: one per leg.
        #[allow(dead_code)]
        #[must_use]
        pub fn host(
            wake: $crate::conformance_host::ConnWake,
            anchors: Option<&str>,
        ) -> std::sync::Arc<dyn $crate::conformance_host::DeclaredConns> {
            $crate::conformance_host::host(DOORS, wake, anchors)
        }

        /// THE GUARDED HOST over [`DOORS`]: [`host`], every dial judged by the production
        /// destination guard at the deployment default. One per refusal cell.
        #[allow(dead_code)]
        #[must_use]
        pub fn guarded_host(
            wake: $crate::conformance_host::ConnWake,
            anchors: Option<&str>,
        ) -> std::sync::Arc<dyn $crate::conformance_host::DeclaredConns> {
            $crate::conformance_host::guarded_host(DOORS, wake, anchors)
        }

        $crate::conformance_host!(@common $at);
        $crate::conformance_host!(@http $http);
    };
    (@common $at:expr) => {
        /// Where [`far_end`] listens: loopback, a port of this repo's own.
        #[allow(dead_code)]
        pub const FAR_END: &str = $at;
        #[allow(unused_imports)]
        pub use $crate::conformance_host::{anchors, Answer, Preamble};

        /// THE SUITE'S TLS FAR END at [`FAR_END`], answering by `answer`.
        #[allow(dead_code)]
        pub fn far_end(answer: Answer) {
            $crate::conformance_host::far_end(FAR_END, answer);
        }

        /// THE SUITE'S TLS FRONT at [`FAR_END`] before the live backend at `upstream`.
        #[allow(dead_code)]
        pub fn tls_front(preamble: Preamble, upstream: &'static str) {
            $crate::conformance_host::tls_front(FAR_END, preamble, upstream);
        }

        #[test]
        fn the_hosts_tls_upgrade_verifies_against_the_suites_test_anchors() {
            $crate::conformance_host::the_hosts_tls_upgrade_verifies_against_the_suites_test_anchors(host);
        }

        #[test]
        fn red_with_the_anchors_withheld_the_hosts_tls_upgrade_is_refused() {
            $crate::conformance_host::red_with_the_anchors_withheld_the_hosts_tls_upgrade_is_refused(host);
        }

        #[test]
        fn the_conformance_host_guard_refuses_a_private_destination() {
            $crate::conformance_host::the_conformance_host_guard_refuses_a_private_destination(guarded_host);
        }
    };
    (@http true) => {
        #[test]
        fn an_http_need_reaches_a_local_http_listener_through_the_hosts_framer() {
            $crate::conformance_host::an_http_need_reaches_a_local_http_listener_through_the_hosts_framer(host);
        }
    };
    (@http false) => {};
}
