// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WASTE-EGRESS W1, step 7 at the Connector: a prepared exchange on a SHARED h2 line. Its facts and
//! its commit answer from what the line published once it landed (the `prepared_landed` latch,
//! `Seen.ready`, `Held.ready`) while another holder has the connection out, and never before the
//! line landed: not while its connect, its client's final flight or its framing's `begin` is still
//! owed. A rejected line leaves the pool at once, even while another stream still rides it.
//!
//! The far ends run on a runtime of their own, so the test thread may block on a gate. A far end
//! records what each connection sent and answers `xe` (a one-byte message, then the end) for every
//! `!` it reads; the scripted `messages` framer hands that answer to the stream that emitted last.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::task::Waker;
use std::time::{Duration, Instant};

use busbar_contract::abi::mechanism::call::Outcome;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::*;
use crate::carrier::{Carry, Side};
use crate::framer::{Call, Crossed, DoorFacts};
use crate::registry::Entry;
use crate::support::{Knobs, TestDoor};

const OWNER: InstanceId = InstanceId(1);
const NEED: NeedId = NeedId(0);
const TICKET: Ticket = 7;
/// Every wait in these tests is bounded by this.
const BOUND: Duration = Duration::from_secs(5);

/// Poll `f` until it answers, failing (never hanging) past [`BOUND`].
fn until<T>(what: &str, mut f: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + BOUND;
    loop {
        if let Some(t) = f() {
            return t;
        }
        assert!(Instant::now() < deadline, "timed out: {what}");
        std::thread::sleep(Duration::from_millis(2));
    }
}

// ---------------------------------------------------------------------------------------------
// Far ends.

/// One accepted connection: what it read, and whether it ended.
#[derive(Default)]
struct Peer {
    got: Mutex<Vec<u8>>,
    ended: AtomicBool,
}

/// A far end on its own runtime: every connection it accepted, in order.
struct FarEnd {
    addr: String,
    peers: Arc<Mutex<Vec<Arc<Peer>>>>,
}

impl FarEnd {
    /// How many connections it accepted.
    fn accepted(&self) -> usize {
        self.peers.lock().unwrap().len()
    }

    fn peer(&self, k: usize) -> Option<Arc<Peer>> {
        self.peers.lock().unwrap().get(k).cloned()
    }

    /// What its `k`th connection read so far.
    fn got(&self, k: usize) -> Vec<u8> {
        self.peer(k)
            .map(|p| p.got.lock().unwrap().clone())
            .unwrap_or_default()
    }

    /// Whether its `k`th connection ended.
    fn ended(&self, k: usize) -> bool {
        self.peer(k).is_some_and(|p| p.ended.load(Ordering::SeqCst))
    }
}

/// Read what the near end sends, answering `xe` for every `!`, until it ends.
async fn serve<S: AsyncRead + AsyncWrite + Unpin>(mut s: S, peer: &Peer) {
    let mut buf = [0_u8; 512];
    loop {
        let n = match s.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        peer.got.lock().unwrap().extend_from_slice(&buf[..n]);
        for _ in buf[..n].iter().filter(|b| **b == b'!') {
            if s.write_all(b"xe").await.is_err() {
                return;
            }
        }
        if s.flush().await.is_err() {
            return;
        }
    }
}

/// A far end on `rt`. With `tls` it serves TLS, its `k`th accept with `tls[k]` (the last one past
/// the end); without, cleartext.
fn far_end(rt: &tokio::runtime::Runtime, tls: Vec<Arc<rustls::ServerConfig>>) -> FarEnd {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.set_nonblocking(true).unwrap();
    let addr = l.local_addr().unwrap().to_string();
    let peers: Arc<Mutex<Vec<Arc<Peer>>>> = Arc::default();
    let accepted = Arc::clone(&peers);
    rt.spawn(async move {
        let l = tokio::net::TcpListener::from_std(l).unwrap();
        while let Ok((s, _)) = l.accept().await {
            let peer = Arc::new(Peer::default());
            let k = {
                let mut all = accepted.lock().unwrap();
                all.push(Arc::clone(&peer));
                all.len() - 1
            };
            let config = tls.get(k).or(tls.last()).cloned();
            tokio::spawn(async move {
                match config {
                    Some(config) => {
                        if let Ok(s) = tokio_rustls::TlsAcceptor::from(config).accept(s).await {
                            serve(s, &peer).await;
                        }
                    }
                    None => serve(s, &peer).await,
                }
                peer.ended.store(true, Ordering::SeqCst);
            });
        }
    });
    FarEnd { addr, peers }
}

/// A private CA and the `localhost` leaf it signed: the CA (a trust anchor), the leaf and its
/// key, DER.
struct Cert {
    ca: Vec<u8>,
    leaf: Vec<u8>,
    key: Vec<u8>,
}

fn cert() -> Cert {
    let ca = crate::test_support::private_ca();
    Cert {
        ca: crate::test_support::certs_from_pem(&ca.ca_pem).remove(0),
        leaf: ca.leaf_der,
        key: ca.key_der,
    }
}

/// A TLS far end serving `cert`, agreeing `h2` by ALPN.
fn server(cert: &Cert) -> Arc<rustls::ServerConfig> {
    let mut s = std::sync::Arc::unwrap_or_clone(
        busbar_contract::crypto::tls::server_config(|b| {
            b.with_no_client_auth().with_single_cert(
                vec![cert.leaf.clone().into()],
                rustls_pki_types::PrivateKeyDer::try_from(cert.key.clone()).unwrap(),
            )
        })
        .unwrap(),
    );
    s.alpn_protocols = vec![b"h2".to_vec()];
    Arc::new(s)
}

/// `leaf`'s fingerprint as the connector states it (`ConnFacts::peer_cert`, RFC 5929
/// `tls-server-end-point`).
fn fingerprint(leaf: &[u8]) -> String {
    crate::tls::client::end_point_digest(leaf)
        .digest(leaf)
        .iter()
        .fold(String::new(), |mut hex, b| {
            let _ = write!(hex, "{b:02x}");
            hex
        })
}

fn peer_cert(facts: &ConnFacts) -> Option<String> {
    facts.peer_cert.as_ref().map(|c| c.fingerprint.clone())
}

/// The far ends' runtime.
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

// ---------------------------------------------------------------------------------------------
// Gates and doors.

/// A gate a crossing blocks its thread on, once armed.
#[derive(Default)]
struct Gate(Mutex<Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>>);

/// An armed [`Gate`], as the test holds it.
struct Armed {
    entered: mpsc::Receiver<()>,
    release: mpsc::Sender<()>,
}

impl Gate {
    /// Arm the gate: the next crossing through it says so and blocks its thread until the test
    /// releases it (or drops the release, as a failing test's unwinding does).
    fn arm(&self) -> Armed {
        let (entered_tx, entered) = mpsc::channel();
        let (release, held_back) = mpsc::channel();
        *self.0.lock().unwrap() = Some((entered_tx, held_back));
        Armed { entered, release }
    }

    /// The crossing through the gate: blocks here while it is armed.
    fn hold(&self) {
        let armed = self.0.lock().unwrap().take();
        if let Some((entered, release)) = armed {
            let _ = entered.send(());
            let _ = release.recv_timeout(Duration::from_secs(10));
        }
    }
}

impl Armed {
    /// Whether a crossing reached the gate within [`BOUND`].
    fn entered(&self) -> bool {
        self.entered.recv_timeout(BOUND).is_ok()
    }

    fn release(&self) {
        let _ = self.release.send(());
    }
}

/// The test carrier with its crossings gated: a WRITE or a FLUSH (a fresh dial's connect is its
/// first flush) blocks its thread on a test-held gate once armed, and a write may answer `Pending`
/// taking nothing.
struct GatedCarrier {
    inner: TestDoor,
    /// Blocks the next write crossing's thread.
    write: Gate,
    /// Blocks the next flush crossing's thread: on a fresh line, its connect.
    connect: Gate,
    /// While `Some(n)`: `n` more writes are taken, then every write answers `Pending`, taking
    /// nothing.
    pend_after: Mutex<Option<usize>>,
}

impl GatedCarrier {
    fn new() -> Self {
        Self {
            inner: TestDoor::identity("carrier"),
            write: Gate::default(),
            connect: Gate::default(),
            pend_after: Mutex::new(None),
        }
    }
}

impl FramerDoor for GatedCarrier {
    fn facts(&self) -> &DoorFacts {
        self.inner.facts()
    }

    fn io_owner(&self) -> Option<u64> {
        self.inner.io_owner()
    }

    fn cross(&self, call: Call<'_>) -> Crossed {
        self.inner.cross(call)
    }

    fn side(&self) -> Option<Box<dyn Side>> {
        self.inner.side()
    }

    fn carry(&self, side: &dyn Side, resume: bool, call: Carry<'_>) -> Crossed {
        match &call {
            Carry::Write(..) => {
                self.write.hold();
                let mut pend = self.pend_after.lock().unwrap();
                match pend.as_mut() {
                    Some(0) => {
                        return Crossed {
                            outcome: Outcome::Pending,
                            error: None,
                        }
                    }
                    Some(n) => *n -= 1,
                    None => {}
                }
            }
            Carry::Flush(..) => self.connect.hold(),
            _ => {}
        }
        self.inner.carry(side, resume, call)
    }
}

/// A framing ticket whose registered waker the test wakes.
struct ParkTicket {
    ticket: busbar_contract::abi::mechanism::ticket::Ticket,
    waker: Arc<Mutex<Option<Waker>>>,
}

impl Side for ParkTicket {
    fn ticket(&self) -> busbar_contract::abi::mechanism::ticket::Ticket {
        self.ticket
    }

    fn register(&self, waker: &Waker) {
        *self.waker.lock().unwrap() = Some(waker.clone());
    }
}

/// A ticketed framer whose `begin` (after the TLS handshake) PARKS on its ticket: each resume
/// answers `Pending` until the test lets it complete, and a resume blocks its thread on a gate once
/// armed. Every other op is the inner framer's.
struct ParkingBegin {
    inner: TestDoor,
    waker: Arc<Mutex<Option<Waker>>>,
    next: AtomicU32,
    /// Blocks the next resumed begin's thread.
    resume: Gate,
    /// The begin completes on its next resume.
    complete: AtomicBool,
    /// How many fresh `begin` crossings parked.
    parked: AtomicUsize,
}

impl ParkingBegin {
    fn new(inner: TestDoor) -> Self {
        Self {
            inner,
            waker: Arc::default(),
            next: AtomicU32::new(500),
            resume: Gate::default(),
            complete: AtomicBool::new(false),
            parked: AtomicUsize::new(0),
        }
    }

    /// The framing's ticket wakes.
    fn wake(&self) {
        let waker = self.waker.lock().unwrap().take();
        if let Some(w) = waker {
            w.wake();
        }
    }
}

impl FramerDoor for ParkingBegin {
    fn facts(&self) -> &DoorFacts {
        self.inner.facts()
    }

    fn io_owner(&self) -> Option<u64> {
        self.inner.io_owner()
    }

    fn cross(&self, call: Call<'_>) -> Crossed {
        self.inner.cross(call)
    }

    fn carry(&self, _side: &dyn Side, _resume: bool, _call: Carry<'_>) -> Crossed {
        Crossed {
            outcome: Outcome::Ready,
            error: None,
        }
    }

    fn framing_side(&self) -> Option<Box<dyn Side>> {
        Some(Box::new(ParkTicket {
            ticket: busbar_contract::abi::mechanism::ticket::Ticket {
                slot: self.next.fetch_add(1, Ordering::SeqCst),
                generation: 1,
            },
            waker: Arc::clone(&self.waker),
        }))
    }

    fn cross_on(&self, _side: &dyn Side, resume: bool, call: Call<'_>) -> Crossed {
        let parked = Crossed {
            outcome: Outcome::Pending,
            error: None,
        };
        match call {
            Call::Begin(..) if !resume => {
                self.parked.fetch_add(1, Ordering::SeqCst);
                parked
            }
            Call::Begin(i, o) => {
                self.resume.hold();
                if self.complete.load(Ordering::SeqCst) {
                    self.inner.cross(Call::Begin(i, o))
                } else {
                    parked
                }
            }
            other => self.inner.cross(other),
        }
    }
}

/// The scripted `messages` framer on an h2 line: over TLS (`localhost`, ALPN `h2`), or, without
/// TLS, prior-knowledge cleartext h2 (a single cleartext offer `h2`, agreed at the dial).
fn h2_door(tls: bool) -> TestDoor {
    TestDoor::new(
        "messages",
        &["messages"],
        &[],
        Knobs {
            secure_name: tls.then_some("localhost"),
            offer: Some(b"\x02h2"),
            messages: Some(EXCHANGE_STREAM),
            messages_follow_emit: true,
            ..Knobs::default()
        },
    )
}

/// A pooling connector serving `framer` over `carrier`, trusting `anchors` (none: no TLS), its
/// ticket wakes for [`TICKET`] counted in `wakes`.
fn connector(
    framer: Arc<dyn FramerDoor>,
    carrier: Arc<dyn FramerDoor>,
    anchors: Vec<Vec<u8>>,
    wakes: &Arc<AtomicUsize>,
) -> Arc<Connector> {
    let view = Transports::new(vec![
        Entry {
            door: framer,
            alpn: Arc::default(),
        },
        Entry {
            door: carrier,
            alpn: Arc::default(),
        },
    ])
    .unwrap();
    let tls = (!anchors.is_empty()).then(|| {
        Arc::new(
            crate::tls::client::build_client_config(
                &busbar_contract::transport::trust::EgressTrust {
                    extra_anchors: anchors,
                    ..Default::default()
                },
            )
            .expect("a usable client config"),
        )
    });
    let counted = Arc::clone(wakes);
    let c = Connector::serving(
        view,
        crate::tests::loopback_literals(),
        tls,
        Arc::new(move |_: InstanceId, ticket: Ticket| {
            if ticket == TICKET {
                counted.fetch_add(1, Ordering::SeqCst);
            }
        }),
    )
    .pooling(PoolPosture {
        max_idle_per_host: 8,
        idle_timeout: Duration::from_secs(60),
    });
    // The test owner carries `insecure_transport.accept: plaintext` (SEC-2, #297 model A).
    crate::tests::accept_plaintext(&c, &[OWNER]);
    c.declare_over(OWNER, NEED, "messages").unwrap();
    Arc::new(c)
}

// ---------------------------------------------------------------------------------------------
// Exchanges.

/// A request to `far` carrying `body`, bounded by `timeout_ms` (`0`: unbounded).
fn request<'a>(far: &'a str, body: &'static [u8], timeout_ms: u64) -> OpenDesc<'a> {
    OpenDesc {
        target: far,
        body: Bytes::from_static(body),
        timeout_ms,
        ..OpenDesc::default()
    }
}

/// The prepared request P every test commits: answered as soon as it is read.
fn prepared_request(far: &str) -> OpenDesc<'_> {
    request(far, b"p!", 5000)
}

fn prepare(c: &Connector, desc: &OpenDesc<'_>) -> ConnId {
    c.prepare_request(OWNER, NEED, desc, 5000)
        .expect("the prepare is taken")
}

/// The line `conn` rides.
fn line_of(c: &Connector, conn: ConnId) -> Arc<Line> {
    let (_, held) = c.slab.get(OWNER, conn).expect("the exchange is held");
    held.line().expect("the exchange rides a line").0
}

/// Whether `conn`'s dial bound is still armed (its line was never seen landed).
fn dial_due_armed(c: &Connector, conn: ConnId) -> bool {
    let (_, held) = c.slab.get(OWNER, conn).expect("the exchange is held");
    let armed = held.dial_due.lock().unwrap().is_some();
    armed
}

/// `conn` driven through `landed` until its line has landed.
fn land(c: &Connector, conn: ConnId) {
    until("the prepared line lands", || {
        match c.landed(OWNER, conn, TICKET) {
            Ok(()) => Some(()),
            Err(ConnError::Pending) => None,
            other => panic!("unexpected landing: {other:?}"),
        }
    });
}

/// `conn`'s facts, once its line has landed.
fn facts_landed(c: &Connector, conn: ConnId) -> ConnFacts {
    until("the prepared line's facts", || match c.facts(OWNER, conn) {
        Ok(facts) => Some(facts),
        Err(ConnError::Pending) => None,
        other => panic!("unexpected facts: {other:?}"),
    })
}

/// `conn`'s commit, once it goes out.
fn commit(c: &Connector, conn: ConnId, desc: &OpenDesc<'_>) {
    until("the commit goes out", || {
        match c.commit_request(OWNER, conn, desc, false) {
            Ok(()) => Some(()),
            Err(ConnError::Pending) => None,
            other => panic!("unexpected commit: {other:?}"),
        }
    });
}

/// `bytes` written whole on `conn`.
fn write(c: &Connector, conn: ConnId, bytes: &[u8], end: bool) {
    until("the write is taken", || {
        match c.write(OWNER, conn, bytes, end, false) {
            Ok(n) if n == bytes.len() => Some(()),
            Ok(0) | Err(ConnError::Pending) => None,
            other => panic!("unexpected write: {other:?}"),
        }
    });
}

/// Read `conn` (nothing answered yet) until `ready` holds: what drives its line meanwhile.
fn pending_until(c: &Connector, conn: ConnId, what: &str, ready: impl Fn() -> bool) {
    let mut buf = [0_u8; 64];
    until(what, || {
        match c.read(OWNER, conn, TICKET, &mut buf) {
            Err(ConnError::Pending) => {}
            other => panic!("unexpected read before any answer: {other:?}"),
        }
        ready().then_some(())
    });
}

/// `conn`'s whole answer: its bytes, whether it ended whole, and the error that ended it.
fn answer(c: &Connector, conn: ConnId) -> (Vec<u8>, bool, Option<ConnError>) {
    let mut buf = [0_u8; 64];
    let mut got = Vec::new();
    let deadline = Instant::now() + BOUND;
    while Instant::now() < deadline {
        match c.read(OWNER, conn, TICKET, &mut buf) {
            Ok(p) if p.kind == PieceKind::Completion => {
                return (got, p.stream != StreamId(0), None);
            }
            Ok(p) => got.extend_from_slice(&buf[..p.len]),
            Err(ConnError::Pending) => std::thread::sleep(Duration::from_millis(2)),
            Err(e) => return (got, false, Some(e)),
        }
    }
    panic!("the answer did not end in time: {got:?}");
}

/// The whole answer `xe` every exchange here is given.
fn whole() -> (Vec<u8>, bool, Option<ConnError>) {
    (b"x".to_vec(), true, None)
}

/// Run `f` on a thread of its own (thread T), inside `rt`: its answer, when it returns.
fn on_thread<T: Send + 'static>(
    rt: &tokio::runtime::Runtime,
    f: impl FnOnce() -> T + Send + 'static,
) -> mpsc::Receiver<T> {
    let (tx, rx) = mpsc::channel();
    let handle = rt.handle().clone();
    std::thread::spawn(move || {
        let _in = handle.enter();
        let _ = tx.send(f());
    });
    rx
}

/// One worker thread T, as a worker makes its exchanges: lines are pooled per thread (each
/// thread's pool shard), so P's prepare and S's open are made on T, S's when the test says go.
struct Worker {
    p: ConnId,
    go: mpsc::Sender<()>,
    s: mpsc::Receiver<Option<Result<ConnId, ConnError>>>,
}

impl Worker {
    /// Prepare `desc` on a new thread T; T then waits for [`Worker::open_s`].
    fn prepare(rt: &tokio::runtime::Runtime, c: &Arc<Connector>, far: &str) -> Self {
        let (p_tx, p_rx) = mpsc::channel();
        let (go, wait) = mpsc::channel::<()>();
        let s = on_thread(rt, {
            let c = Arc::clone(c);
            let far = far.to_owned();
            move || {
                let _ = p_tx.send(c.prepare_request(OWNER, NEED, &prepared_request(&far), 5000));
                wait.recv_timeout(BOUND).ok()?;
                Some(c.open(OWNER, NEED, &request(&far, b"s", 0)))
            }
        });
        let p = p_rx
            .recv_timeout(BOUND)
            .expect("T prepares")
            .expect("the prepare is taken");
        Self { p, go, s }
    }

    /// T opens S (its drive may block on an armed gate).
    fn open_s(&self) {
        let _ = self.go.send(());
    }

    /// S, once T's open returned.
    fn s(&self) -> ConnId {
        self.s
            .recv_timeout(BOUND)
            .expect("S's open on T returns")
            .expect("T was told to open S")
            .expect("S opens")
    }
}

// ---------------------------------------------------------------------------------------------
// The tests.

/// Facts served on a SHARED h2 line, then dropped uncommitted (a rejection of cert A): the line
/// leaves the pool at once, though S still rides it, so the retry dials fresh and observes cert B.
/// S still completes whole on the first line, which closes once S leaves. RED before W1 (every
/// prepare dials its own line: accepts=3) and against a close that only taints (prepare 2 is lent
/// the first line again and sees cert A).
#[test]
fn abandoned_after_facts_redials_h2_shared() {
    let (a, b) = (cert(), cert());
    let rt = runtime();
    let _in = rt.enter();
    let far = far_end(&rt, vec![server(&a), server(&b)]);
    let c = connector(
        Arc::new(h2_door(true)),
        Arc::new(TestDoor::identity("carrier")),
        vec![a.ca.clone(), b.ca.clone()],
        &Arc::default(),
    );

    let s = c.open(OWNER, NEED, &request(&far.addr, b"s", 0)).unwrap();
    pending_until(&c, s, "S's opening reaches the first connection", || {
        far.got(0) == b"s"
    });
    let first = line_of(&c, s);

    let desc = prepared_request(&far.addr);
    let p1 = prepare(&c, &desc);
    let p1_line = line_of(&c, p1);
    let p1_facts = facts_landed(&c, p1);
    c.close(OWNER, p1).unwrap();

    let p2 = prepare(&c, &desc);
    let p2_facts = facts_landed(&c, p2);
    commit(&c, p2, &desc);
    let second = line_of(&c, p2);
    assert_eq!(answer(&c, p2), whole(), "prepare 2 is answered whole");
    c.close(OWNER, p2).unwrap();

    assert_eq!(
        peer_cert(&p2_facts),
        Some(fingerprint(&b.leaf)),
        "prepare 2's facts are the second connection's (cert B): the rejected line was not lent"
    );
    assert_eq!(
        far.accepted(),
        2,
        "prepare 1 rode S's line, prepare 2 dialled the second"
    );
    assert_eq!(
        peer_cert(&p1_facts),
        Some(fingerprint(&a.leaf)),
        "prepare 1 observed the first connection (cert A)"
    );
    assert!(
        Arc::ptr_eq(&p1_line, &first),
        "prepare 1 was lent S's in-use h2 line"
    );

    write(&c, s, b"!", true);
    assert_eq!(answer(&c, s), whole(), "S completes whole");
    assert_eq!(far.got(0), b"s!", "S completed on the first line");
    c.close(OWNER, s).unwrap();
    assert_eq!(first.users(), 0, "nobody holds the first line");
    assert!(
        first.target().is_none(),
        "the first line is closed once S leaves"
    );
    until("the first connection's far end sees it close", || {
        far.ended(0).then_some(())
    });

    let p3 = prepare(&c, &desc);
    assert!(
        Arc::ptr_eq(&line_of(&c, p3), &second),
        "the pool holds the second line, and only it"
    );
    assert_eq!(peer_cert(&facts_landed(&c, p3)), Some(fingerprint(&b.leaf)));
    assert_eq!(far.accepted(), 2, "nothing else was dialled");
    c.close(OWNER, p3).unwrap();
}

/// A prepare lent an in-use h2 line while S's drive on thread T holds the connection out (T's
/// write is blocked in the carrier): facts answer at once (cert A), never `Pending`, and the commit
/// is taken, its opening queued for T. Once T is let go it opens the queued exchange, which is
/// answered whole well inside its deadline, on the one connection. RED before W1 (the prepare dials
/// its own line: accepts=2) and against W1 without step 7 (facts `Pending` while T holds the line).
#[test]
fn prepared_on_shared_h2_line_while_out_completes() {
    let a = cert();
    let rt = runtime();
    let _in = rt.enter();
    let far = far_end(&rt, vec![server(&a)]);
    let carrier = Arc::new(GatedCarrier::new());
    let c = connector(
        Arc::new(h2_door(true)),
        Arc::clone(&carrier) as Arc<dyn FramerDoor>,
        vec![a.ca.clone()],
        &Arc::default(),
    );

    let s = c.open(OWNER, NEED, &request(&far.addr, b"s", 0)).unwrap();
    pending_until(&c, s, "S's opening reaches the far end", || {
        far.got(0) == b"s"
    });

    let gate = carrier.write.arm();
    let t = on_thread(&rt, {
        let c = Arc::clone(&c);
        move || c.write(OWNER, s, b"t", false, false)
    });
    assert!(gate.entered(), "S's drive on T reaches the write gate");

    let desc = prepared_request(&far.addr);
    let p = prepare(&c, &desc);
    assert!(
        Arc::ptr_eq(&line_of(&c, p), &line_of(&c, s)),
        "the prepare was lent S's in-use h2 line (before W1 it dials its own: accepts=2)"
    );
    let facts = c
        .facts(OWNER, p)
        .expect("facts answer while T holds the connection out, never Pending");
    assert_eq!(peer_cert(&facts), Some(fingerprint(&a.leaf)), "cert A");
    assert_eq!(facts.alpn.as_deref(), Some("h2"));
    assert_eq!(
        c.commit_request(OWNER, p, &desc, false),
        Ok(()),
        "the commit is taken while T holds the connection out (its opening queued for T)"
    );

    let released = Instant::now();
    gate.release();
    assert_eq!(t.recv_timeout(BOUND).expect("T's write returns"), Ok(1));
    assert_eq!(
        answer(&c, p),
        whole(),
        "the prepared exchange is answered whole"
    );
    assert!(
        released.elapsed() < Duration::from_secs(1),
        "answered well inside its deadline: {:?}",
        released.elapsed()
    );
    assert_eq!(far.accepted(), 1, "one connection");

    write(&c, s, b"!", true);
    assert_eq!(answer(&c, s), whole(), "S completes whole");
    c.close(OWNER, p).unwrap();
    c.close(OWNER, s).unwrap();
}

/// The fresh-line half of [`prepared_on_shared_h2_line_while_out_completes`], over `tls` or
/// prior-knowledge cleartext h2: P's fresh line is driven to `Ready` through `landed`, S is lent
/// the same line and its drive on thread T holds the connection out, then P's facts and commit are
/// answered at once. Answers P's facts and the scheme its line established.
fn fresh_line_shared_before_facts(tls: bool) -> (ConnFacts, u8) {
    let a = cert();
    let rt = runtime();
    let _in = rt.enter();
    let far = far_end(&rt, if tls { vec![server(&a)] } else { Vec::new() });
    let carrier = Arc::new(GatedCarrier::new());
    let c = connector(
        Arc::new(h2_door(tls)),
        Arc::clone(&carrier) as Arc<dyn FramerDoor>,
        if tls { vec![a.ca.clone()] } else { Vec::new() },
        &Arc::default(),
    );

    let desc = prepared_request(&far.addr);
    let p = prepare(&c, &desc);
    land(&c, p);

    let s = c.open(OWNER, NEED, &request(&far.addr, b"s", 0)).unwrap();
    assert!(
        Arc::ptr_eq(&line_of(&c, s), &line_of(&c, p)),
        "S was lent the prepared line"
    );
    pending_until(&c, s, "S's opening reaches the far end", || {
        far.got(0) == b"s"
    });

    let gate = carrier.write.arm();
    let t = on_thread(&rt, {
        let c = Arc::clone(&c);
        move || c.write(OWNER, s, b"t", false, false)
    });
    assert!(gate.entered(), "S's drive on T reaches the write gate");

    let facts = c
        .facts(OWNER, p)
        .expect("facts answer while S holds the connection out, never Pending");
    assert_eq!(
        c.commit_request(OWNER, p, &desc, false),
        Ok(()),
        "the commit is taken while S holds the connection out"
    );
    if tls {
        assert_eq!(peer_cert(&facts), Some(fingerprint(&a.leaf)), "cert A");
    }
    let scheme = line_of(&c, p)
        .established()
        .expect("the line is open")
        .scheme;

    gate.release();
    assert_eq!(t.recv_timeout(BOUND).expect("T's write returns"), Ok(1));
    assert_eq!(
        answer(&c, p),
        whole(),
        "the prepared exchange is answered whole"
    );
    write(&c, s, b"!", true);
    assert_eq!(answer(&c, s), whole(), "S completes whole");
    assert_eq!(far.accepted(), 1, "one connection");
    c.close(OWNER, p).unwrap();
    c.close(OWNER, s).unwrap();
    (facts, scheme)
}

/// A fresh prepared TLS h2 line, landed, then lent to S whose drive holds it out: facts and the
/// commit answer at once from what the line published (`seen.ready`) and what the Held already
/// knows (`Held.ready`).
#[test]
fn prepared_fresh_line_shared_before_facts_completes() {
    let (facts, scheme) = fresh_line_shared_before_facts(true);
    assert_eq!(facts.alpn.as_deref(), Some("h2"));
    assert_eq!(scheme, busbar_contract::abi::host::service::SCHEME_SECURE);
}

/// The same on a PRIOR-KNOWLEDGE CLEARTEXT h2 line (a single cleartext offer `h2`): readiness is
/// published on a line with no TLS, never read off `secured`.
#[test]
fn prepared_fresh_line_shared_before_facts_completes_h2c() {
    let (facts, scheme) = fresh_line_shared_before_facts(false);
    assert_eq!(facts.alpn.as_deref(), Some("h2"));
    assert_eq!(
        scheme,
        busbar_contract::abi::host::service::SCHEME_PLAIN,
        "cleartext"
    );
    assert!(facts.peer_cert.is_none(), "no certificate in the clear");
    assert_eq!(facts.sni, None, "no name offered in the clear");
}

/// A fresh PRIOR-KNOWLEDGE CLEARTEXT h2 line multiplexes from its dial, so it is lent to S while
/// its connect has not landed; S's drive on thread T holds it out at the carrier's connect gate.
/// Meanwhile P's `landed` and facts wait (`Pending`, its ticket waker armed, its dial bound still
/// armed). Once the connect lands the ticket waker fires and both exchanges complete on the one
/// connection. RED before W1 (the prepared line is not pooled: S dials its own, accepts=2) and
/// against a step 7 keyed on `seen.multiplexes` (P answers `Ready` while the connect is gated).
#[test]
fn prepared_fresh_h2c_line_lent_while_connecting_waits() {
    let rt = runtime();
    let _in = rt.enter();
    let far = far_end(&rt, Vec::new());
    let carrier = Arc::new(GatedCarrier::new());
    let wakes = Arc::new(AtomicUsize::new(0));
    let c = connector(
        Arc::new(h2_door(false)),
        Arc::clone(&carrier) as Arc<dyn FramerDoor>,
        Vec::new(),
        &wakes,
    );

    let desc = prepared_request(&far.addr);
    let t = Worker::prepare(&rt, &c, &far.addr);
    let p = t.p;
    let line = line_of(&c, p);
    assert!(line.multiplexes(), "prior knowledge: h2 from the dial");

    let gate = carrier.connect.arm();
    t.open_s();
    let entered = gate.entered();
    assert_eq!(
        line.users(),
        2,
        "S was lent the prepared line while it connects (before W1 S dials its own: accepts=2)"
    );
    assert!(entered, "S's drive on T reaches the connect gate");

    let before = wakes.load(Ordering::SeqCst);
    assert_eq!(
        c.landed(OWNER, p, TICKET),
        Err(ConnError::Pending),
        "P has not landed while its connect is gated"
    );
    assert_eq!(
        c.facts(OWNER, p).map(|_| ()),
        Err(ConnError::Pending),
        "no facts before the line landed"
    );
    assert!(dial_due_armed(&c, p), "P's dial bound is still armed");

    gate.release();
    let s = t.s();
    until("the ticket waker fires once the connect lands", || {
        (wakes.load(Ordering::SeqCst) > before).then_some(())
    });
    land(&c, p);
    assert!(!dial_due_armed(&c, p), "landing spends the dial bound");
    let facts = facts_landed(&c, p);
    assert_eq!(facts.alpn.as_deref(), Some("h2"));
    commit(&c, p, &desc);
    assert_eq!(
        answer(&c, p),
        whole(),
        "the prepared exchange is answered whole"
    );
    write(&c, s, b"!", true);
    assert_eq!(answer(&c, s), whole(), "S completes whole");
    assert_eq!(far.accepted(), 1, "one connection");
    c.close(OWNER, p).unwrap();
    c.close(OWNER, s).unwrap();
}

/// P's fresh TLS h2 line finishes its handshake locally while the carrier takes no bytes, so the
/// client's final flight stays queued; S is lent the line (its opening queued behind the flight)
/// and the line comes home unflushed. S's next drive on thread T holds it out on a blocking gate.
/// P's `landed` and facts wait (`Pending`, its dial bound still armed) until the flight is flushed;
/// then the ticket waker fires and both exchanges complete on the one connection. RED against a
/// readiness latched from `Phase::Open && !handshaking() && !opening_owed`.
#[test]
fn prepared_facts_wait_for_final_flight_flush() {
    let a = cert();
    let rt = runtime();
    let _in = rt.enter();
    let far = far_end(&rt, vec![server(&a)]);
    let carrier = Arc::new(GatedCarrier::new());
    let wakes = Arc::new(AtomicUsize::new(0));
    let c = connector(
        Arc::new(h2_door(true)),
        Arc::clone(&carrier) as Arc<dyn FramerDoor>,
        vec![a.ca.clone()],
        &wakes,
    );

    // The ClientHello is taken; every later write (the client's final flight first) is not.
    *carrier.pend_after.lock().unwrap() = Some(1);
    let desc = prepared_request(&far.addr);
    let p = prepare(&c, &desc);
    let line = line_of(&c, p);
    until("P's handshake completes locally", || {
        match c.landed(OWNER, p, TICKET) {
            Err(ConnError::Pending) => {}
            other => panic!("P landed with its final flight unflushed: {other:?}"),
        }
        line.multiplexes().then_some(())
    });

    let s = c.open(OWNER, NEED, &request(&far.addr, b"s", 0)).unwrap();
    assert!(
        Arc::ptr_eq(&line_of(&c, s), &line),
        "S was lent the prepared line"
    );

    let gate = carrier.write.arm();
    let t = on_thread(&rt, {
        let c = Arc::clone(&c);
        move || c.write(OWNER, s, b"t", false, false)
    });
    assert!(gate.entered(), "S's drive on T reaches the blocking gate");

    let before = wakes.load(Ordering::SeqCst);
    assert_eq!(
        c.landed(OWNER, p, TICKET),
        Err(ConnError::Pending),
        "P has not landed while its final flight is unflushed"
    );
    assert_eq!(
        c.facts(OWNER, p).map(|_| ()),
        Err(ConnError::Pending),
        "no facts while the final flight is unflushed"
    );
    assert!(dial_due_armed(&c, p), "P's dial bound is still armed");

    *carrier.pend_after.lock().unwrap() = None;
    gate.release();
    assert_eq!(t.recv_timeout(BOUND).expect("T's write returns"), Ok(1));
    until("the ticket waker fires once the flight is flushed", || {
        (wakes.load(Ordering::SeqCst) > before).then_some(())
    });
    land(&c, p);
    let facts = facts_landed(&c, p);
    assert_eq!(peer_cert(&facts), Some(fingerprint(&a.leaf)), "cert A");
    commit(&c, p, &desc);
    assert_eq!(
        answer(&c, p),
        whole(),
        "the prepared exchange is answered whole"
    );
    write(&c, s, b"!", true);
    assert_eq!(answer(&c, s), whole(), "S completes whole");
    assert_eq!(far.accepted(), 1, "one connection");
    c.close(OWNER, p).unwrap();
    c.close(OWNER, s).unwrap();
}

/// P's fresh TLS h2 line agreed h2, but its framing's `begin` is PARKED on its ticket. S is lent
/// the line and its drive on thread T holds it out (blocked in the begin's resume). P's `landed`
/// and facts stay `Pending` while T holds it, and after (at home) until the ticket wakes and the
/// begin completes; then both exchanges complete on the one connection. RED against a readiness
/// gate that omits `!begin_parked()`.
#[test]
fn prepared_facts_wait_while_begin_parked() {
    let a = cert();
    let rt = runtime();
    let _in = rt.enter();
    let far = far_end(&rt, vec![server(&a)]);
    let door = Arc::new(ParkingBegin::new(h2_door(true)));
    let wakes = Arc::new(AtomicUsize::new(0));
    let c = connector(
        Arc::clone(&door) as Arc<dyn FramerDoor>,
        Arc::new(TestDoor::identity("carrier")),
        vec![a.ca.clone()],
        &wakes,
    );

    let desc = prepared_request(&far.addr);
    let t = Worker::prepare(&rt, &c, &far.addr);
    let p = t.p;
    let line = line_of(&c, p);
    until("P's handshake completes and its begin parks", || {
        match c.landed(OWNER, p, TICKET) {
            Err(ConnError::Pending) => {}
            other => panic!("P landed with its begin parked: {other:?}"),
        }
        (line.multiplexes() && door.parked.load(Ordering::SeqCst) == 1).then_some(())
    });
    assert_eq!(
        c.facts(OWNER, p).map(|_| ()),
        Err(ConnError::Pending),
        "no facts while the begin is parked"
    );

    let gate = door.resume.arm();
    t.open_s();
    assert!(gate.entered(), "S's drive on T reaches the parked begin");
    assert_eq!(line.users(), 2, "S was lent the prepared line");

    assert_eq!(
        c.landed(OWNER, p, TICKET),
        Err(ConnError::Pending),
        "P has not landed while S holds the line out with the begin parked"
    );
    assert_eq!(
        c.facts(OWNER, p).map(|_| ()),
        Err(ConnError::Pending),
        "no facts while S holds the line out with the begin parked"
    );
    assert!(dial_due_armed(&c, p), "P's dial bound is still armed");

    gate.release();
    let s = t.s();
    assert_eq!(
        c.landed(OWNER, p, TICKET),
        Err(ConnError::Pending),
        "P has not landed until the begin's ticket wakes"
    );
    assert_eq!(
        c.facts(OWNER, p).map(|_| ()),
        Err(ConnError::Pending),
        "no facts until the begin's ticket wakes"
    );

    door.complete.store(true, Ordering::SeqCst);
    door.wake();
    land(&c, p);
    let facts = facts_landed(&c, p);
    assert_eq!(peer_cert(&facts), Some(fingerprint(&a.leaf)), "cert A");
    commit(&c, p, &desc);
    assert_eq!(
        answer(&c, p),
        whole(),
        "the prepared exchange is answered whole"
    );
    write(&c, s, b"!", true);
    assert_eq!(answer(&c, s), whole(), "S completes whole");
    assert_eq!(far.accepted(), 1, "one connection");
    c.close(OWNER, p).unwrap();
    c.close(OWNER, s).unwrap();
}
