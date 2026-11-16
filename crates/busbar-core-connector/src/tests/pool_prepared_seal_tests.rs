// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WASTE-EGRESS W1 §8, the lost-wire tests: an opening whose wire was lost after the framer took
//! it (a sealed value the framer rendered twice or never, or an out-of-range `agreed`) fails its
//! connection, so its line is never lent again; and a connection failed while its carrier still
//! held unsent bytes is never redialled from, so no request reaches two far ends.
//!
//! The far ends are TLS stubs on loopback (`h2` agreed through ALPN where a test needs a
//! multiplexing line). Each request carries its id in its body, `<n>` (answered `n` then the
//! exchange's end) or `[n]` (answered `n` only, so the exchange stays in flight); every stub counts
//! the connections it accepted and records every id it decoded.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::task::Waker;
use std::time::{Duration, Instant};

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::mechanism::ticket::Ticket as OpTicket;
use busbar_contract::abi::transport::FramerOut;
use busbar_contract::conn::SEALED_FIELDS_FIELD;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::*;
use crate::carrier::{Carry, Side};
use crate::framer::{Call, Crossed, DoorFacts};
use crate::registry::{Entry, Transports};
use crate::support::{Knobs, TestDoor};

const OWNER: InstanceId = InstanceId(1);
const NEED: NeedId = NeedId(0);
const TICKET: Ticket = 7;
/// Every wait in these tests is bounded by this.
const BOUND: Duration = Duration::from_secs(5);
/// The sealed credential.
const SECRET: &[u8] = b"Bearer-sealed-credential-0123";
/// The rendered head of the sealed field: what marks an opening the breaking door breaks.
const MARK: &[u8] = b"authorization: ";
/// A sealed opening's fields: the credential, sealed.
static SEALED: [(&str, &[u8]); 2] = [
    ("authorization", SECRET),
    (SEALED_FIELDS_FIELD, b"authorization".as_slice()),
];

/// A runtime whose workers serve the far ends while the test thread blocks on a gate.
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

/// CAs the connector trusts, and one `localhost` leaf (certificate, key) under each.
struct Pki {
    cas: Vec<Vec<u8>>,
    leaves: Vec<(Vec<u8>, Vec<u8>)>,
}

fn pki(n: usize) -> Pki {
    let mut pki = Pki {
        cas: Vec::new(),
        leaves: Vec::new(),
    };
    for _ in 0..n {
        let ca = crate::test_support::private_ca();
        pki.cas
            .push(crate::test_support::certs_from_pem(&ca.ca_pem).remove(0));
        pki.leaves.push((ca.leaf_der, ca.key_der));
    }
    pki
}

/// A counting TLS far end: the connections it accepted, and every request id it decoded.
struct Stub {
    addr: String,
    accepted: Arc<AtomicUsize>,
    decoded: Arc<Mutex<Vec<String>>>,
}

impl Stub {
    fn accepts(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }

    /// How many times it decoded the request id `id`.
    fn decoded(&self, id: &str) -> usize {
        self.decoded
            .lock()
            .unwrap()
            .iter()
            .filter(|d| d.as_str() == id)
            .count()
    }
}

/// A TLS far end serving its `n`th accepted connection under `leaves[n]` (the last leaf for every
/// later one), agreeing `h2` when `h2`.
async fn stub(leaves: &[(Vec<u8>, Vec<u8>)], h2: bool) -> Stub {
    let acceptors: Vec<tokio_rustls::TlsAcceptor> = leaves
        .iter()
        .map(|(leaf, key)| {
            let mut server = std::sync::Arc::unwrap_or_clone(
                busbar_contract::crypto::tls::server_config(|b| {
                    b.with_no_client_auth().with_single_cert(
                        vec![rustls_pki_types::CertificateDer::from(leaf.clone())],
                        rustls_pki_types::PrivateKeyDer::try_from(key.clone()).unwrap(),
                    )
                })
                .unwrap(),
            );
            if h2 {
                server.alpn_protocols = vec![b"h2".to_vec()];
            }
            tokio_rustls::TlsAcceptor::from(Arc::new(server))
        })
        .collect();
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap().to_string();
    let accepted = Arc::new(AtomicUsize::new(0));
    let decoded = Arc::new(Mutex::new(Vec::new()));
    let (count, seen) = (Arc::clone(&accepted), Arc::clone(&decoded));
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            let n = count.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptors[n.min(acceptors.len() - 1)].clone();
            let seen = Arc::clone(&seen);
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(s).await else {
                    return;
                };
                serve(&mut tls, &seen).await;
            });
        }
    });
    Stub {
        addr,
        accepted,
        decoded,
    }
}

/// Answer every request id read on `tls`, until it ends.
async fn serve<S: AsyncRead + AsyncWrite + Unpin>(tls: &mut S, decoded: &Mutex<Vec<String>>) {
    let mut pending = Vec::new();
    let mut buf = vec![0_u8; 4096];
    loop {
        let n = match tls.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        pending.extend_from_slice(&buf[..n]);
        let mut answers = Vec::new();
        while let Some((id, whole)) = take_id(&mut pending) {
            answers.extend_from_slice(id.as_bytes());
            if whole {
                answers.push(b'e');
            }
            decoded.lock().unwrap().push(id);
        }
        if !answers.is_empty()
            && (tls.write_all(&answers).await.is_err() || tls.flush().await.is_err())
        {
            return;
        }
    }
}

/// The next whole request id in `pending` (`<n>` answered whole, `[n]` left in flight), taken out
/// with what precedes it.
fn take_id(pending: &mut Vec<u8>) -> Option<(String, bool)> {
    loop {
        let Some(open) = pending.iter().position(|b| matches!(b, b'<' | b'[')) else {
            pending.clear();
            return None;
        };
        pending.drain(..open);
        let whole = pending[0] == b'<';
        let close = if whole { b'>' } else { b']' };
        let end = pending.iter().position(|b| *b == close)?;
        let id = pending[1..end].to_vec();
        if !id.is_empty() && id.iter().all(u8::is_ascii_digit) {
            pending.drain(..=end);
            return Some((String::from_utf8(id).unwrap(), whole));
        }
        pending.drain(..1);
    }
}

/// A test-held gate: armed with the channel it announces entry on and the one it waits on.
type Gate = Mutex<Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>>;

/// Wait at `gate` if it is armed (once): say it was entered, then wait for its release.
fn wait_at(gate: &Gate) {
    let armed = gate.lock().unwrap().take();
    if let Some((entered, release)) = armed {
        let _ = entered.send(());
        let _ = release.recv_timeout(Duration::from_secs(10));
    }
}

/// THE GATED CARRIER: the test carrier, gating only the first connection it dialled (line 1). Its
/// writes take nothing and answer `Pending` while `hold_writes` is set (the write-gated carrier);
/// its next write or read once `block_write` or `block_read` is armed blocks the calling thread
/// until the test releases it (the gated carrier).
struct GateCarrier {
    inner: TestDoor,
    first: Mutex<Option<u64>>,
    hold_writes: AtomicBool,
    block_write: Gate,
    block_read: Gate,
}

impl GateCarrier {
    fn new() -> Self {
        Self {
            inner: TestDoor::identity("carrier"),
            first: Mutex::new(None),
            hold_writes: AtomicBool::new(false),
            block_write: Mutex::new(None),
            block_read: Mutex::new(None),
        }
    }

    fn is_first(&self, conn: u64) -> bool {
        *self.first.lock().unwrap() == Some(conn)
    }

    fn hold(&self, held: bool) {
        self.hold_writes.store(held, Ordering::SeqCst);
    }
}

impl FramerDoor for GateCarrier {
    fn io_owner(&self) -> Option<u64> {
        self.inner.io_owner()
    }
    fn facts(&self) -> &DoorFacts {
        self.inner.facts()
    }
    fn cross(&self, call: Call<'_>) -> Crossed {
        self.inner.cross(call)
    }
    fn side(&self) -> Option<Box<dyn Side>> {
        self.inner.side()
    }
    fn carry(&self, side: &dyn Side, resume: bool, call: Carry<'_>) -> Crossed {
        match call {
            Carry::Dial(i, o) => {
                let crossed = self.inner.carry(side, resume, Carry::Dial(i, &mut *o));
                if crossed.outcome == Outcome::Ready && o.conn != 0 {
                    self.first.lock().unwrap().get_or_insert(o.conn);
                }
                crossed
            }
            Carry::Write(i, o) => {
                if self.is_first(i.conn) {
                    wait_at(&self.block_write);
                    if self.hold_writes.load(Ordering::SeqCst) {
                        return Crossed {
                            outcome: Outcome::Pending,
                            error: None,
                        };
                    }
                }
                self.inner.carry(side, resume, Carry::Write(i, o))
            }
            Carry::Read(i, o) => {
                if self.is_first(i.conn) {
                    wait_at(&self.block_read);
                }
                self.inner.carry(side, resume, Carry::Read(i, o))
            }
            other => self.inner.carry(side, resume, other),
        }
    }
}

/// How the breaking door breaks a sealed opening's emit.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Effect {
    /// Its wire repeats itself, so the sealed filler is in it twice: `seals.splice` refuses it
    /// with `SEAL_BROKEN`.
    Repeat,
    /// Its wire is overwritten, so the filler is never in it: `sealed_sent` fails the connection.
    Blank,
    /// Its wire is whole, with an `agreed` position past the offer: `check_agreed_position` fails
    /// after the wire was written.
    Agreed,
}

/// A parked emit's ticket: its waker is the door's, so releasing the door wakes it.
struct ParkTicket {
    ticket: OpTicket,
    waker: Arc<Mutex<Option<Waker>>>,
}

impl Side for ParkTicket {
    fn ticket(&self) -> OpTicket {
        self.ticket
    }
    fn register(&self, waker: &Waker) {
        *self.waker.lock().unwrap() = Some(waker.clone());
    }
}

/// THE BREAKING (REPEATING) DOOR: the scripted `messages` framer over TLS, rendering each opening's
/// fields and sealing values, which breaks every emit carrying the sealed field ([`MARK`]) as its
/// [`Effect`] says; unsealed openings pass untouched. With `park`, its framings run on tickets and
/// such an emit PARKS on its ticket, yielding nothing, until the test releases the door; its
/// resumed emit then yields the broken wire (inside `drive`, through `resume`).
struct BreakingDoor {
    inner: TestDoor,
    effect: Effect,
    park: bool,
    released: AtomicBool,
    waker: Arc<Mutex<Option<Waker>>>,
    stash: Mutex<HashMap<u32, Vec<u8>>>,
    next: AtomicU32,
    parked: AtomicUsize,
    broken: AtomicUsize,
}

impl BreakingDoor {
    fn new(h2: bool, effect: Effect, park: bool) -> Self {
        let knobs = Knobs {
            secure_name: Some("localhost"),
            seals: true,
            render_fields: true,
            messages: Some(crate::compose::EXCHANGE_STREAM),
            messages_follow_emit: true,
            offer: h2.then_some(b"\x02h2".as_slice()),
            ..Knobs::default()
        };
        Self {
            inner: TestDoor::new("sec", &["sec"], &[], knobs),
            effect,
            park,
            released: AtomicBool::new(false),
            waker: Arc::new(Mutex::new(None)),
            stash: Mutex::new(HashMap::new()),
            next: AtomicU32::new(500),
            parked: AtomicUsize::new(0),
            broken: AtomicUsize::new(0),
        }
    }

    /// The parked emit may resume: its ticket is woken.
    fn release(&self) {
        self.released.store(true, Ordering::SeqCst);
        let waker = self.waker.lock().unwrap().take();
        if let Some(w) = waker {
            w.wake();
        }
    }

    /// Break what the emit yielded into the host's wire sink (`wire`, `cap` bytes).
    fn broke(&self, crossed: Crossed, wire: *mut u8, cap: usize, o: &mut FramerOut) -> Crossed {
        if crossed.outcome != Outcome::Ready {
            return crossed;
        }
        let len = usize::try_from(o.yielded.wire_len).unwrap();
        assert!(len > 0, "the sealed opening's emit yielded its wire");
        match self.effect {
            Effect::Repeat => {
                assert!(2 * len <= cap, "the repeated wire fits the sink");
                // SAFETY: the host's sink holds `cap` bytes, the emit initialized its first `len`,
                // and `2 * len <= cap`, so the copy stays inside it and does not overlap.
                unsafe { std::ptr::copy_nonoverlapping(wire, wire.add(len), len) };
                o.yielded.wire_len = (2 * len) as u64;
            }
            Effect::Blank => {
                // SAFETY: the emit initialized the first `len` bytes of the host's sink.
                unsafe { std::ptr::write_bytes(wire, b'!', len) };
            }
            Effect::Agreed => o.yielded.agreed = 9,
        }
        self.broken.fetch_add(1, Ordering::SeqCst);
        crossed
    }
}

/// Whether the emitted bytes carry the sealed field.
fn marked(bytes: *const u8, len: usize) -> bool {
    crate::support::lent(bytes, len)
        .windows(MARK.len())
        .any(|w| w == MARK)
}

impl FramerDoor for BreakingDoor {
    fn io_owner(&self) -> Option<u64> {
        self.inner.io_owner()
    }
    fn facts(&self) -> &DoorFacts {
        self.inner.facts()
    }
    fn seals_values(&self) -> bool {
        self.inner.seals_values()
    }
    fn cross(&self, call: Call<'_>) -> Crossed {
        match call {
            Call::Emit(i, o) => {
                if !marked(i.bytes, i.len) {
                    return self.inner.cross(Call::Emit(i, o));
                }
                let (wire, cap) = (i.sink.wire, i.sink.wire_cap);
                let crossed = self.inner.cross(Call::Emit(i, &mut *o));
                self.broke(crossed, wire, cap, o)
            }
            other => self.inner.cross(other),
        }
    }
    fn framing_side(&self) -> Option<Box<dyn Side>> {
        if !self.park {
            return None;
        }
        Some(Box::new(ParkTicket {
            ticket: OpTicket {
                slot: self.next.fetch_add(1, Ordering::SeqCst),
                generation: 1,
            },
            waker: Arc::clone(&self.waker),
        }))
    }
    fn cross_on(&self, side: &dyn Side, resume: bool, call: Call<'_>) -> Crossed {
        match call {
            Call::Emit(i, o) => {
                let slot = side.ticket().slot;
                if !resume {
                    if !marked(i.bytes, i.len) {
                        return self.inner.cross(Call::Emit(i, o));
                    }
                    self.stash
                        .lock()
                        .unwrap()
                        .insert(slot, crate::support::lent(i.bytes, i.len));
                    self.parked.fetch_add(1, Ordering::SeqCst);
                    return Crossed {
                        outcome: Outcome::Pending,
                        error: None,
                    };
                }
                if !self.stash.lock().unwrap().contains_key(&slot) {
                    return self.inner.cross(Call::Emit(i, o));
                }
                if !self.released.load(Ordering::SeqCst) {
                    return Crossed {
                        outcome: Outcome::Pending,
                        error: None,
                    };
                }
                let bytes = self.stash.lock().unwrap().remove(&slot).unwrap();
                i.bytes = bytes.as_ptr();
                i.len = bytes.len();
                i.end_of_frame = 1;
                let (wire, cap) = (i.sink.wire, i.sink.wire_cap);
                let crossed = self.inner.cross(Call::Emit(i, &mut *o));
                self.broke(crossed, wire, cap, o)
            }
            other => self.inner.cross(other),
        }
    }
}

/// A connector serving the breaking door over the gated carrier, trusting `cas`, keeping finished
/// lines idle, dialling where `judge` says.
struct Rig {
    c: Arc<Connector>,
    door: Arc<BreakingDoor>,
    carrier: Arc<GateCarrier>,
}

fn rig(door: BreakingDoor, cas: &[Vec<u8>], judge: Arc<dyn crate::DialJudge>) -> Rig {
    let door = Arc::new(door);
    let carrier = Arc::new(GateCarrier::new());
    let view = Transports::new(vec![
        Entry {
            door: Arc::clone(&door) as Arc<dyn FramerDoor>,
            alpn: Vec::new(),
        },
        Entry {
            door: Arc::clone(&carrier) as Arc<dyn FramerDoor>,
            alpn: Vec::new(),
        },
    ])
    .unwrap();
    let tls =
        crate::tls::client::build_client_config(&busbar_contract::transport::trust::EgressTrust {
            extra_anchors: cas.to_vec(),
            ..Default::default()
        })
        .unwrap();
    let c = Connector::serving(view, judge, Some(Arc::new(tls)), Arc::new(|_, _| {})).pooling(
        crate::pool::PoolPosture {
            max_idle_per_host: 8,
            idle_timeout: Duration::from_secs(60),
        },
    );
    c.declare_over(OWNER, NEED, "sec").unwrap();
    Rig {
        c: Arc::new(c),
        door,
        carrier,
    }
}

/// THE TEST RESOLVER of two stubs on one key: the first dial reaches `first`, any later one
/// (a new line, a redial) reaches `then`.
fn switching(first: &str, then: &str) -> Arc<dyn crate::DialJudge> {
    let first: SocketAddr = first.parse().unwrap();
    let then: SocketAddr = then.parse().unwrap();
    let calls = AtomicUsize::new(0);
    Arc::new(
        move |_: &str, _: u32, _: crate::Judged| -> Option<Result<SocketAddr, crate::Verdict>> {
            Some(Ok(if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                first
            } else {
                then
            }))
        },
    )
}

/// An unsealed request carrying `body`.
fn plain<'a>(target: &'a str, body: &'static [u8]) -> OpenDesc<'a> {
    OpenDesc {
        target,
        body: Bytes::from_static(body),
        ..OpenDesc::default()
    }
}

/// A request carrying `body` and the sealed credential.
fn sealed<'a>(target: &'a str, body: &'static [u8]) -> OpenDesc<'a> {
    OpenDesc {
        target,
        fields: &SEALED,
        body: Bytes::from_static(body),
        ..OpenDesc::default()
    }
}

/// `poll` until it answers other than `Pending`, or [`BOUND`] passes (then its `Pending`).
async fn settle<T>(mut poll: impl FnMut() -> Result<T, ConnError>) -> Result<T, ConnError> {
    let deadline = Instant::now() + BOUND;
    loop {
        match poll() {
            Err(ConnError::Pending) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            other => return other,
        }
    }
}

/// `conn`'s answer: its bytes, whether it ended whole, and the error that ended it (`Pending` if
/// nothing ended it within [`BOUND`]).
async fn answer(c: &Connector, conn: ConnId) -> (Vec<u8>, bool, Option<ConnError>) {
    let mut buf = [0_u8; 64];
    let mut got = Vec::new();
    let deadline = Instant::now() + BOUND;
    loop {
        match c.read(OWNER, conn, TICKET, &mut buf) {
            Ok(p) if p.kind == PieceKind::Completion => {
                return (got, p.stream != StreamId(0), None);
            }
            Ok(p) => got.extend_from_slice(&buf[..p.len]),
            Err(ConnError::Pending) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            Err(e) => return (got, false, Some(e)),
        }
    }
}

/// The first bytes of `conn`'s answer (its exchange still in flight).
async fn in_flight(c: &Connector, conn: ConnId) -> Result<Vec<u8>, ConnError> {
    let mut buf = [0_u8; 64];
    let deadline = Instant::now() + BOUND;
    loop {
        match c.read(OWNER, conn, TICKET, &mut buf) {
            Ok(p) if p.kind != PieceKind::Completion && p.len > 0 => {
                return Ok(buf[..p.len].to_vec());
            }
            Ok(_) => {}
            Err(ConnError::Pending) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            Err(e) => return Err(e),
        }
    }
}

/// One whole prepared exchange of `desc`: prepare, facts, commit, its whole answer, close.
async fn prepared_whole(c: &Connector, desc: &OpenDesc<'_>) -> Vec<u8> {
    let conn = c.prepare_request(OWNER, NEED, desc, 5000).unwrap();
    settle(|| c.facts(OWNER, conn))
        .await
        .expect("the line lands");
    settle(|| c.commit_request(OWNER, conn, desc, false))
        .await
        .expect("the commit goes out");
    let (got, whole, failed) = answer(c, conn).await;
    assert_eq!((whole, failed), (true, None), "the answer ends whole");
    c.close(OWNER, conn).unwrap();
    got
}

/// A prepared exchange of `desc`, landed (`ready`): its facts and commit answer at once from then
/// on, whoever has its line out.
async fn landed_prepared(c: &Connector, desc: &OpenDesc<'_>) -> ConnId {
    let conn = c.prepare_request(OWNER, NEED, desc, 5000).unwrap();
    settle(|| c.landed(OWNER, conn, TICKET))
        .await
        .expect("the prepared exchange lands");
    conn
}

/// The line `conn` rides.
fn line_of(c: &Connector, conn: ConnId) -> Arc<Line> {
    let (_, held) = c.slab.get(OWNER, conn).unwrap();
    let (line, _) = held.line().expect("the exchange rides a line");
    line
}

/// `line` is closed, and nothing (the pool included) holds it any more.
fn assert_gone(line: Arc<Line>) {
    assert!(line.target().is_none(), "line 1 is closed");
    assert_eq!(
        Arc::strong_count(&line),
        1,
        "the pool holds no entry for line 1"
    );
}

/// `conn`'s read fails with its connection's cause: `error`, its cause text naming `why`.
async fn fails_with_cause(c: &Connector, conn: ConnId, error: ConnError, why: &str, who: &str) {
    let (got, whole, failed) = answer(c, conn).await;
    assert_eq!(
        (got.as_slice(), whole, failed),
        (&b""[..], false, Some(error)),
        "{who} fails with the connection's cause"
    );
    let cause = c.cause(OWNER, conn).expect("its line failed");
    assert!(cause.text.contains(why), "{who}'s cause: {cause:?}");
}

/// Arm `gate`, then run `drive` on a thread T that holds line 1's connection out inside the gated
/// carrier crossing: answered once T is inside it, with the gate's release and T's result.
fn held_out<R: Send + 'static>(
    gate: &Gate,
    c: &Arc<Connector>,
    drive: impl FnOnce(&Connector) -> R + Send + 'static,
) -> (mpsc::Sender<()>, mpsc::Receiver<R>) {
    let (entered_tx, entered) = mpsc::channel();
    let (release, held_back) = mpsc::channel();
    *gate.lock().unwrap() = Some((entered_tx, held_back));
    let (done_tx, done) = mpsc::channel();
    let handle = tokio::runtime::Handle::current();
    let c = Arc::clone(c);
    std::thread::spawn(move || {
        let _rt = handle.enter();
        let _ = done_tx.send(drive(&c));
    });
    entered
        .recv_timeout(BOUND)
        .expect("T holds line 1's connection out inside the carrier");
    (release, done)
}

/// RED on the pre-W1 commit (every prepare dials its own line: accepts=2 at prepare 2) and against
/// r10's W1 (no `handed`: the failed commit closes as whole and line 1 goes back idle). A prepared
/// commit whose opening crossed into the framer and then failed (its sealed value repeated, so the
/// splice refuses it) leaves a line that may carry a partial request: it is never pooled again.
#[test]
fn prepared_commit_failed_after_handoff_drops_line() {
    runtime().block_on(async {
        let pki = pki(1);
        let far = stub(&pki.leaves, false).await;
        let rig = rig(
            BreakingDoor::new(false, Effect::Repeat, false),
            &pki.cas,
            crate::tests::loopback_literals(),
        );
        let c = &rig.c;
        let target = far.addr.clone();
        assert_eq!(prepared_whole(c, &plain(&target, b"<1>")).await, b"1");

        let two = sealed(&target, b"<2>");
        let p2 = c.prepare_request(OWNER, NEED, &two, 5000).unwrap();
        let line1 = line_of(c, p2);
        let committed = settle(|| c.commit_request(OWNER, p2, &two, false)).await;
        assert_eq!(far.accepts(), 1, "prepare 2 was lent line 1");
        assert_eq!(
            committed,
            Err(ConnError::Refused),
            "commit 2 fails with the absorb error"
        );
        assert_eq!(
            rig.door.broken.load(Ordering::SeqCst),
            1,
            "its wire was broken"
        );
        c.close(OWNER, p2).unwrap();
        assert_gone(line1);

        assert_eq!(
            prepared_whole(c, &plain(&target, b"<3>")).await,
            b"3",
            "prepare 3's answer is its own"
        );
        assert_eq!(far.accepts(), 2, "prepare 3 rode a new connection");
    });
}

/// The h2 variant: an unsealed stream S holds line 1 in flight through the failed commit. Prepare 3
/// is not lent line 1, and S fails with the connection's cause (its frames may have been in the
/// lost wire). RED on the pre-W1 commit (prepare 2 dials its own line) and against r10's W1 (prepare
/// 3 is lent line 1).
#[test]
fn prepared_commit_failed_after_handoff_drops_line_h2() {
    runtime().block_on(async {
        let pki = pki(1);
        let far = stub(&pki.leaves, true).await;
        let rig = rig(
            BreakingDoor::new(true, Effect::Repeat, false),
            &pki.cas,
            crate::tests::loopback_literals(),
        );
        let c = &rig.c;
        let target = far.addr.clone();
        assert_eq!(prepared_whole(c, &plain(&target, b"<1>")).await, b"1");
        let s = c.open(OWNER, NEED, &plain(&target, b"[5]")).unwrap();
        assert_eq!(
            in_flight(c, s).await,
            Ok(b"5".to_vec()),
            "S is in flight on line 1"
        );
        let line1 = line_of(c, s);

        let two = sealed(&target, b"<2>");
        let p2 = c.prepare_request(OWNER, NEED, &two, 5000).unwrap();
        let committed = settle(|| c.commit_request(OWNER, p2, &two, false)).await;
        assert_eq!(far.accepts(), 1, "prepare 2 was lent line 1 beside S");
        assert_eq!(
            committed,
            Err(ConnError::Refused),
            "commit 2 fails with the absorb error"
        );
        c.close(OWNER, p2).unwrap();

        let three = plain(&target, b"<3>");
        let p3 = c.prepare_request(OWNER, NEED, &three, 5000).unwrap();
        settle(|| c.facts(OWNER, p3))
            .await
            .expect("prepare 3 lands");
        assert_eq!(far.accepts(), 2, "prepare 3 is not lent line 1");
        settle(|| c.commit_request(OWNER, p3, &three, false))
            .await
            .expect("commit 3 goes out");
        assert_eq!(
            answer(c, p3).await,
            (b"3".to_vec(), true, None),
            "prepare 3's answer is its own"
        );
        c.close(OWNER, p3).unwrap();

        fails_with_cause(c, s, ConnError::Refused, crate::seal::SEAL_BROKEN, "S").await;
        c.close(OWNER, s).unwrap();
        assert_gone(line1);
    });
}

/// RED against r11's W1 (no step 9: an absorb error on a queued opening leaves the connection
/// live). S holds line 1's connection out on thread T (its write blocked in the carrier); prepare 1
/// is lent the line, served facts from what the line published, and its sealed commit is queued;
/// T's `bring_back` opens it and the absorb fails. Line 1 then never multiplexes again: prepare 2
/// dials a second connection, and S fails with the connection's cause.
#[test]
fn prepared_commit_queued_open_failed_never_lent() {
    runtime().block_on(async {
        let pki = pki(2);
        let far = stub(&pki.leaves, true).await;
        let rig = rig(
            BreakingDoor::new(true, Effect::Repeat, false),
            &pki.cas,
            crate::tests::loopback_literals(),
        );
        let c = &rig.c;
        let target = far.addr.clone();
        let s = c.open(OWNER, NEED, &plain(&target, b"[5]")).unwrap();
        assert_eq!(
            in_flight(c, s).await,
            Ok(b"5".to_vec()),
            "S is in flight on line 1"
        );
        let line1 = line_of(c, s);

        let (release, t) = held_out(&rig.carrier.block_write, &rig.c, move |c| {
            c.write(OWNER, s, b"zz", false, false)
        });
        let one = sealed(&target, b"<2>");
        let p1 = c.prepare_request(OWNER, NEED, &one, 5000).unwrap();
        let facts1 = c
            .facts(OWNER, p1)
            .expect("facts answer while T holds line 1 out");
        assert_eq!(
            c.commit_request(OWNER, p1, &one, false),
            Ok(()),
            "the commit is queued for T"
        );
        release.send(()).unwrap();
        let _ = t.recv_timeout(BOUND).expect("T brings line 1 back");
        assert_eq!(
            rig.door.broken.load(Ordering::SeqCst),
            1,
            "its wire was broken"
        );

        let (_, whole, failed) = answer(c, p1).await;
        assert_eq!(
            (whole, failed),
            (false, Some(ConnError::Refused)),
            "prepare 1 fails at its read"
        );
        c.close(OWNER, p1).unwrap();
        assert!(!line1.multiplexes(), "line 1 no longer multiplexes");

        let two = plain(&target, b"<3>");
        let p2 = c.prepare_request(OWNER, NEED, &two, 5000).unwrap();
        let facts2 = settle(|| c.facts(OWNER, p2))
            .await
            .expect("prepare 2 lands");
        assert_eq!(far.accepts(), 2, "prepare 2 is not lent line 1");
        assert_ne!(
            facts2.peer_key_pin, facts1.peer_key_pin,
            "prepare 2's facts are the second connection's"
        );
        settle(|| c.commit_request(OWNER, p2, &two, false))
            .await
            .expect("commit 2 goes out");
        assert_eq!(
            answer(c, p2).await,
            (b"3".to_vec(), true, None),
            "prepare 2's answer is its own"
        );
        c.close(OWNER, p2).unwrap();

        fails_with_cause(c, s, ConnError::Refused, crate::seal::SEAL_BROKEN, "S").await;
        c.close(OWNER, s).unwrap();
        assert_gone(line1);
    });
}

/// RED without step 9 (the parity hole): a plain open lent line 1 while T holds its connection
/// out queues its sealed opening; T's `bring_back` opens it and the absorb fails. The next open on
/// the key is not lent line 1, and line 1 is closed once its users leave.
#[test]
fn attach_queued_open_failed_never_lent() {
    runtime().block_on(async {
        let pki = pki(1);
        let far = stub(&pki.leaves, true).await;
        let rig = rig(
            BreakingDoor::new(true, Effect::Repeat, false),
            &pki.cas,
            crate::tests::loopback_literals(),
        );
        let c = &rig.c;
        let target = far.addr.clone();
        let s = c.open(OWNER, NEED, &plain(&target, b"[5]")).unwrap();
        assert_eq!(
            in_flight(c, s).await,
            Ok(b"5".to_vec()),
            "S is in flight on line 1"
        );
        let line1 = line_of(c, s);

        let (release, t) = held_out(&rig.carrier.block_write, &rig.c, move |c| {
            c.write(OWNER, s, b"zz", false, false)
        });
        let b = c
            .open(OWNER, NEED, &sealed(&target, b"<2>"))
            .expect("the open is lent line 1 and its opening queued");
        assert!(Arc::ptr_eq(&line_of(c, b), &line1), "B rides line 1");
        release.send(()).unwrap();
        let _ = t.recv_timeout(BOUND).expect("T brings line 1 back");
        assert_eq!(
            rig.door.broken.load(Ordering::SeqCst),
            1,
            "its wire was broken"
        );

        let (_, whole, failed) = answer(c, b).await;
        assert_eq!(
            (whole, failed),
            (false, Some(ConnError::Refused)),
            "the queued open fails at its read"
        );

        let next = c.open(OWNER, NEED, &plain(&target, b"<3>")).unwrap();
        assert_eq!(
            answer(c, next).await,
            (b"3".to_vec(), true, None),
            "the next open is answered"
        );
        assert_eq!(far.accepts(), 2, "the next open is not lent line 1");
        c.close(OWNER, next).unwrap();

        c.close(OWNER, b).unwrap();
        c.close(OWNER, s).unwrap();
        assert_gone(line1);
    });
}

/// `lost_wire_fail_never_redials_queued_stream`: two counting TLS h2 stubs on one key, the
/// write-gated carrier, and the breaking door. Line 1 is warm and pooled; with its writes gated,
/// stream A (a plain open, id `7`) is lent it (`attach`, a `Redial` marked at `flushed()`), and
/// its frames stay queued. Then line 1 fails while those frames are still with its carrier. A's
/// read fails with the connection's cause; stub 2 accepted nothing; once the gate is released and
/// line 1's users leave (`close()` still flushes what was queued), A's id was decoded at most once
/// across both stubs. Cases (a)-(c) are RED without step 10 (`wire_kept` never set, so A
/// redials: stub 2 decodes A, and stub 1 decodes it again at the close); case (d) is RED against
/// r16's per-arm rule (only the splice and TLS arms of `absorb` set `wire_kept`).
mod lost_wire_fail_never_redials_queued_stream {
    use super::*;

    /// A's request id.
    const A: &str = "7";

    /// The two stubs, and the rig whose line 1 (to stub 1) is warm and idle.
    async fn warm(effect: Effect, park: bool) -> (Rig, Stub, Stub, String) {
        let pki = pki(1);
        let one = stub(&pki.leaves, true).await;
        let two = stub(&pki.leaves, true).await;
        let rig = rig(
            BreakingDoor::new(true, effect, park),
            &pki.cas,
            switching(&one.addr, &two.addr),
        );
        let target = one.addr.clone();
        let w = rig.c.open(OWNER, NEED, &plain(&target, b"<1>")).unwrap();
        assert_eq!(
            answer(&rig.c, w).await,
            (b"1".to_vec(), true, None),
            "line 1 is warm"
        );
        rig.c.close(OWNER, w).unwrap();
        (rig, one, two, target)
    }

    /// Gate line 1's writes and lend A the line: its frames stay queued.
    fn queue_a(rig: &Rig, target: &str, line1: Option<&Arc<Line>>) -> ConnId {
        rig.carrier.hold(true);
        let a = rig.c.open(OWNER, NEED, &plain(target, b"<7>")).unwrap();
        if let Some(line1) = line1 {
            assert!(Arc::ptr_eq(&line_of(&rig.c, a), line1), "A was lent line 1");
        }
        a
    }

    /// A fails with the connection's cause and nothing redialled it; then, the gate released and
    /// line 1's users gone, A was decoded at most once in all.
    async fn delivered_at_most_once(
        rig: &Rig,
        (one, two): (&Stub, &Stub),
        a: ConnId,
        others: &[ConnId],
        (error, why): (ConnError, &str),
    ) {
        fails_with_cause(&rig.c, a, error, why, "A").await;
        assert_eq!(
            two.accepts(),
            0,
            "stub 2 accepted no connection: A was not redialled"
        );
        rig.carrier.hold(false);
        for conn in others {
            rig.c.close(OWNER, *conn).unwrap();
        }
        rig.c.close(OWNER, a).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while one.decoded(A) == 0 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(two.decoded(A), 0, "stub 2 never decoded A");
        assert!(
            one.decoded(A) + two.decoded(A) <= 1,
            "A was decoded at most once in all: stub 1 {}, stub 2 {}",
            one.decoded(A),
            two.decoded(A)
        );
    }

    /// Case (a): prepared P (landed before the gate) is lent line 1, and its sealed commit is
    /// queued while thread T holds the connection out (blocked in a read); T's `bring_back` opens
    /// it and the splice refuses it (`SEAL_BROKEN`, step 9) with A's frames still queued.
    #[test]
    fn a_prepared_seal_broken_at_commit() {
        runtime().block_on(async {
            let (rig, one, two, target) = warm(Effect::Repeat, false).await;
            let desc = sealed(&target, b"<8>");
            let p = landed_prepared(&rig.c, &desc).await;
            let line1 = line_of(&rig.c, p);
            let a = queue_a(&rig, &target, Some(&line1));
            let (release, t) = held_out(&rig.carrier.block_read, &rig.c, move |c| {
                let mut buf = [0_u8; 64];
                c.read(OWNER, a, TICKET, &mut buf).map(|_| ())
            });
            assert_eq!(
                rig.c.commit_request(OWNER, p, &desc, false),
                Ok(()),
                "P's commit is queued for T"
            );
            release.send(()).unwrap();
            let _ = t.recv_timeout(BOUND).expect("T brings line 1 back");
            assert_eq!(
                rig.door.broken.load(Ordering::SeqCst),
                1,
                "P's wire was broken"
            );
            delivered_at_most_once(
                &rig,
                (&one, &two),
                a,
                &[p],
                (ConnError::Refused, crate::seal::SEAL_BROKEN),
            )
            .await;
        });
    }

    /// The at-home variant of case (a): A is opened at home, then P's sealed commit at home fails
    /// in its absorb (`SEAL_BROKEN`, step 9).
    #[test]
    fn a_prepared_seal_broken_at_home() {
        runtime().block_on(async {
            let (rig, one, two, target) = warm(Effect::Repeat, false).await;
            let desc = sealed(&target, b"<8>");
            let p = landed_prepared(&rig.c, &desc).await;
            let line1 = line_of(&rig.c, p);
            let a = queue_a(&rig, &target, Some(&line1));
            assert_eq!(
                rig.c.commit_request(OWNER, p, &desc, false),
                Err(ConnError::Refused),
                "P's commit fails in its absorb"
            );
            assert_eq!(
                rig.door.broken.load(Ordering::SeqCst),
                1,
                "P's wire was broken"
            );
            delivered_at_most_once(
                &rig,
                (&one, &two),
                a,
                &[p],
                (ConnError::Refused, crate::seal::SEAL_BROKEN),
            )
            .await;
        });
    }

    /// Case (b): a sealed attach whose filler the framer never renders, so `sealed_sent` fails the
    /// connection with A's frames still queued.
    #[test]
    fn b_sealed_attach_filler_never_completed() {
        runtime().block_on(async {
            let (rig, one, two, target) = warm(Effect::Blank, false).await;
            let a = queue_a(&rig, &target, None);
            let line1 = line_of(&rig.c, a);
            let b = rig
                .c
                .open(OWNER, NEED, &sealed(&target, b"<8>"))
                .expect("the sealed open is held on the failed line");
            assert_eq!(
                rig.door.broken.load(Ordering::SeqCst),
                1,
                "B's filler was never sent"
            );
            assert!(
                line1
                    .cause()
                    .is_some_and(|c| c.text.contains(crate::seal::SEAL_BROKEN)),
                "sealed_sent failed line 1"
            );
            delivered_at_most_once(
                &rig,
                (&one, &two),
                a,
                &[b],
                (ConnError::Refused, crate::seal::SEAL_BROKEN),
            )
            .await;
        });
    }

    /// Case (c): P's sealed emit parks on its ticket (`put_opening_marked` absorbs an empty
    /// `Yielded`, `sealed_sent` defers on `holds(P)`), so its commit answers Ok; once the ticket is
    /// woken the resumed wire repeats P's filler, and `resume`'s absorb refuses it inside `drive`.
    #[test]
    fn c_parked_emit_resumed_seal_broken() {
        runtime().block_on(async {
            let (rig, one, two, target) = warm(Effect::Repeat, true).await;
            let desc = sealed(&target, b"<8>");
            let p = landed_prepared(&rig.c, &desc).await;
            let line1 = line_of(&rig.c, p);
            let a = queue_a(&rig, &target, Some(&line1));
            assert_eq!(
                rig.c.commit_request(OWNER, p, &desc, false),
                Ok(()),
                "P's emit parks: its commit is taken"
            );
            assert_eq!(rig.door.parked.load(Ordering::SeqCst), 1, "P's emit parked");
            assert!(
                line1.cause().is_none(),
                "line 1 is still live while P is parked"
            );
            rig.door.release();
            delivered_at_most_once(
                &rig,
                (&one, &two),
                a,
                &[p],
                (ConnError::Refused, crate::seal::SEAL_BROKEN),
            )
            .await;
            assert_eq!(
                rig.door.broken.load(Ordering::SeqCst),
                1,
                "P's resumed wire was broken"
            );
        });
    }

    /// Case (d1): P's synchronous emit yields its wire with an `agreed` position past the offer:
    /// `absorb` queues the wire, then `check_agreed_position` fails it, through
    /// `put_opening_marked` (step 9).
    #[test]
    fn d1_agreed_out_of_range_sync() {
        runtime().block_on(async {
            let (rig, one, two, target) = warm(Effect::Agreed, false).await;
            let desc = sealed(&target, b"<8>");
            let p = landed_prepared(&rig.c, &desc).await;
            let line1 = line_of(&rig.c, p);
            let a = queue_a(&rig, &target, Some(&line1));
            assert_eq!(
                rig.c.commit_request(OWNER, p, &desc, false),
                Err(ConnError::Fault),
                "P's commit fails at its agreed position"
            );
            assert_eq!(
                rig.door.broken.load(Ordering::SeqCst),
                1,
                "P's agreed was out of range"
            );
            delivered_at_most_once(
                &rig,
                (&one, &two),
                a,
                &[p],
                (ConnError::Fault, "agreed protocol"),
            )
            .await;
        });
    }

    /// Case (d2): the same, but P's emit parks on its ticket, so the wire and the bad `agreed` come
    /// out of `resume`'s absorb inside `drive`.
    #[test]
    fn d2_agreed_out_of_range_parked() {
        runtime().block_on(async {
            let (rig, one, two, target) = warm(Effect::Agreed, true).await;
            let desc = sealed(&target, b"<8>");
            let p = landed_prepared(&rig.c, &desc).await;
            let line1 = line_of(&rig.c, p);
            let a = queue_a(&rig, &target, Some(&line1));
            assert_eq!(
                rig.c.commit_request(OWNER, p, &desc, false),
                Ok(()),
                "P's emit parks: its commit is taken"
            );
            assert_eq!(rig.door.parked.load(Ordering::SeqCst), 1, "P's emit parked");
            rig.door.release();
            delivered_at_most_once(
                &rig,
                (&one, &two),
                a,
                &[p],
                (ConnError::Fault, "agreed protocol"),
            )
            .await;
            assert_eq!(
                rig.door.broken.load(Ordering::SeqCst),
                1,
                "P's agreed was out of range"
            );
        });
    }
}
