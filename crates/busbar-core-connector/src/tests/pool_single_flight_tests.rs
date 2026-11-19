// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WASTE-EGRESS r8 §8 (LEDGER W-021): THE SINGLE-FLIGHT h2 DIAL. Opens that arrive while the
//! first h2 connection for a key is still being set up join its dial instead of each dialling
//! their own: one shard, one key, one accept.
//!
//! The caller is the kernel-shaped one, `open_owned` (an upstream exchange carrying its owned
//! head): the only open that claims its key's dial. The test thread is the one shard; the far ends
//! run on a runtime of their own. A far end counts the connections it accepted, records what each
//! read, and answers `xe` (a one-byte message, then the end) for every `!` it reads; the scripted
//! `messages` framer hands that answer to the stream that emitted last, so the exchanges of a
//! burst, opened together, are read one after another.
//!
//! Last, R62 `fill-without-claim` (LINT-RULES §28, WASTE-EGRESS §11): the source law that keeps
//! every pooled line behind a token [`Pools::take`] minted, and the claim with the core-paced open.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::*;
use crate::registry::{Entry, Transports};
use crate::support::{Knobs, TestDoor};

const OWNER: InstanceId = InstanceId(1);
const NEED: NeedId = NeedId(0);
const TICKET: Ticket = 7;
/// Every wait in these tests is bounded by this.
const BOUND: Duration = Duration::from_secs(5);
/// A cold burst's concurrency.
const BURST: usize = 16;
/// The h2 offer, as a ProtocolNameList.
const H2: &[u8] = b"\x02h2";
/// An offer of h2, then http/1.1.
const H2_H1: &[u8] = b"\x02h2\x08http/1.1";

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

    /// How many bytes its connections read, in all.
    fn read(&self) -> usize {
        self.peers
            .lock()
            .unwrap()
            .iter()
            .map(|p| p.got.lock().unwrap().len())
            .sum()
    }

    /// Whether its `k`th connection ended.
    fn ended(&self, k: usize) -> bool {
        self.peers
            .lock()
            .unwrap()
            .get(k)
            .is_some_and(|p| p.ended.load(Ordering::SeqCst))
    }
}

/// Read what the near end sends, answering `xe` for every `!`, until it ends or (`answers`) it
/// has answered that many.
async fn serve<S: AsyncRead + AsyncWrite + Unpin>(mut s: S, peer: &Peer, answers: Option<usize>) {
    let mut buf = [0_u8; 512];
    let mut answered = 0_usize;
    loop {
        if answers.is_some_and(|n| answered >= n) {
            return;
        }
        let n = match s.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        peer.got.lock().unwrap().extend_from_slice(&buf[..n]);
        for _ in buf[..n].iter().filter(|b| **b == b'!') {
            if s.write_all(b"xe").await.is_err() {
                return;
            }
            answered += 1;
        }
        if s.flush().await.is_err() {
            return;
        }
    }
}

/// A far end on `rt`: TLS under `tls`, else cleartext. With `first_answers`, its first connection
/// answers that many requests and then closes.
fn far_end(
    rt: &tokio::runtime::Runtime,
    tls: Option<Arc<rustls::ServerConfig>>,
    first_answers: Option<usize>,
) -> FarEnd {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.set_nonblocking(true).unwrap();
    let addr = l.local_addr().unwrap().to_string();
    let peers: Arc<Mutex<Vec<Arc<Peer>>>> = Arc::default();
    let accepted = Arc::clone(&peers);
    rt.spawn(async move {
        let l = tokio::net::TcpListener::from_std(l).unwrap();
        while let Ok((s, _)) = l.accept().await {
            let peer = Arc::new(Peer::default());
            let first = {
                let mut all = accepted.lock().unwrap();
                all.push(Arc::clone(&peer));
                all.len() == 1
            };
            let answers = first_answers.filter(|_| first);
            let tls = tls.clone();
            tokio::spawn(async move {
                match tls {
                    Some(tls) => {
                        if let Ok(s) = tokio_rustls::TlsAcceptor::from(tls).accept(s).await {
                            serve(s, &peer, answers).await;
                        }
                    }
                    None => serve(s, &peer, answers).await,
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

/// A TLS far end's config serving `cert`, agreeing one of `alpn` by ALPN.
fn server(cert: &Cert, alpn: &[&[u8]]) -> Arc<rustls::ServerConfig> {
    let mut s = std::sync::Arc::unwrap_or_clone(
        busbar_contract::crypto::tls::server_config(|b| {
            b.with_no_client_auth().with_single_cert(
                vec![cert.leaf.clone().into()],
                rustls_pki_types::PrivateKeyDer::try_from(cert.key.clone()).unwrap(),
            )
        })
        .unwrap(),
    );
    s.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Arc::new(s)
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
// The connector.

/// The scripted `messages` framer, over TLS (`localhost`) when `tls`, offering `offer`.
fn door(tls: bool, offer: Option<&'static [u8]>) -> TestDoor {
    TestDoor::new(
        "messages",
        &["messages"],
        &[],
        Knobs {
            secure_name: tls.then_some("localhost"),
            offer,
            messages: Some(EXCHANGE_STREAM),
            messages_follow_emit: true,
            ..Knobs::default()
        },
    )
}

/// A pooling connector serving `framer` over the test carrier, dialling where `judge` says, its
/// client trusting `anchors` (none: no client TLS).
fn connector(
    framer: TestDoor,
    judge: Arc<dyn crate::DialJudge>,
    anchors: Vec<Vec<u8>>,
) -> Arc<Connector> {
    let view = Transports::new(vec![
        Entry {
            door: Arc::new(framer),
            alpn: Arc::default(),
        },
        Entry {
            door: Arc::new(TestDoor::identity("carrier")),
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
    let c = Connector::serving(view, judge, tls, Arc::new(|_, _| {})).pooling(PoolPosture {
        max_idle_per_host: 8,
        idle_timeout: Duration::from_secs(60),
    });
    // The test owner carries `insecure_transport.accept: plaintext` (SEC-2, #297 model A).
    crate::tests::accept_plaintext(&c, &[OWNER]);
    c.declare_over(OWNER, NEED, "messages").unwrap();
    Arc::new(c)
}

/// The h2 rig every burst here starts from: a TLS far end agreeing `alpn`, and a connector
/// offering `offer`, trusting it, dialling literals.
fn tls_rig(
    rt: &tokio::runtime::Runtime,
    alpn: &[&[u8]],
    offer: &'static [u8],
) -> (FarEnd, Arc<Connector>) {
    let cert = cert();
    let far = far_end(rt, Some(server(&cert, alpn)), None);
    let c = connector(
        door(true, Some(offer)),
        crate::tests::loopback_literals(),
        vec![cert.ca.clone()],
    );
    (far, c)
}

// ---------------------------------------------------------------------------------------------
// Exchanges.

/// A request to `target` whose body is one `!`, bounded by `timeout_ms` (`0`: unbounded).
fn request(target: &str, timeout_ms: u64) -> OpenDesc<'_> {
    OpenDesc {
        target,
        body: Bytes::from_static(b"!"),
        timeout_ms,
        ..OpenDesc::default()
    }
}

/// THE KERNEL-SHAPED OPEN on `need`: an upstream exchange carrying its owned head (`open_owned`).
fn owned_on(c: &Connector, need: NeedId, desc: &OpenDesc<'_>) -> ConnId {
    c.open_owned(OWNER, need, desc, OwnedHead::with_capacity(0), false, None)
        .expect("the open is taken")
}

/// [`owned_on`] the test need.
fn owned(c: &Connector, desc: &OpenDesc<'_>) -> ConnId {
    owned_on(c, NEED, desc)
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

/// Every exchange of `burst` answered whole, read one after another, then closed.
fn read_whole(c: &Connector, burst: &[ConnId]) {
    for (n, conn) in burst.iter().enumerate() {
        assert_eq!(
            answer(c, *conn),
            whole(),
            "exchange {n} of the burst completes whole"
        );
    }
    for conn in burst {
        c.close(OWNER, *conn).unwrap();
    }
}

/// Whether `conn` follows another open's claimed dial.
fn follows(c: &Connector, conn: ConnId) -> bool {
    let (_, held) = c.slab.get(OWNER, conn).expect("the exchange is held");
    let following = held.following.lock().unwrap().is_some();
    following
}

/// `conn`'s pool shard and key.
fn pooled(c: &Connector, conn: ConnId) -> (usize, crate::pool::PoolKey) {
    let (_, held) = c.slab.get(OWNER, conn).expect("the exchange is held");
    held.pooled.clone().expect("the exchange is pooled")
}

/// The line `conn` rides.
fn line_of(c: &Connector, conn: ConnId) -> Option<Arc<Line>> {
    let (_, held) = c.slab.get(OWNER, conn).expect("the exchange is held");
    held.line().map(|(line, _)| line)
}

/// A waker that says it was woken.
#[derive(Default)]
struct Woken {
    woke: Mutex<bool>,
    signal: Condvar,
}

impl std::task::Wake for Woken {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        *self.woke.lock().unwrap() = true;
        self.signal.notify_all();
    }
}

impl Woken {
    /// Whether it was woken within [`BOUND`] (and it is armed again).
    fn wait(&self) -> bool {
        let woke = self.woke.lock().unwrap();
        let (mut woke, _) = self
            .signal
            .wait_timeout_while(woke, BOUND, |w| !*w)
            .unwrap();
        std::mem::replace(&mut *woke, false)
    }
}

/// `conn`'s whole answer, polled ONLY when its own waker wakes (a task's read): nothing else
/// polls it, so a parked follower is answered only if something wakes it.
fn answer_woken(c: &Connector, conn: ConnId) -> (Vec<u8>, bool, Option<ConnError>) {
    let woken = Arc::new(Woken::default());
    let waker = Waker::from(Arc::clone(&woken));
    let mut cx = Context::from_waker(&waker);
    let mut buf = [0_u8; 64];
    let mut got = Vec::new();
    for _ in 0..2000 {
        match c.poll_read(OWNER, conn, &mut cx, &mut buf) {
            Poll::Ready(Ok(p)) if p.kind == PieceKind::Completion => {
                return (got, p.stream != StreamId(0), None);
            }
            Poll::Ready(Ok(p)) => got.extend_from_slice(&buf[..p.len]),
            Poll::Ready(Err(e)) => return (got, false, Some(e)),
            Poll::Pending => assert!(
                woken.wait(),
                "a pending exchange is woken, though nothing else polls it: {got:?}"
            ),
        }
    }
    panic!("the answer did not end: {got:?}");
}

/// A JUDGE THAT HOLDS ITS ANSWER: the first `held` judgements pend, counted, until the test
/// answers them; every later one answers `at` at once.
struct HeldJudge {
    calls: AtomicUsize,
    held: usize,
    at: Mutex<Option<std::net::SocketAddr>>,
    waiting: Mutex<Vec<crate::Judged>>,
}

impl HeldJudge {
    fn new(held: usize) -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
            held,
            at: Mutex::new(None),
            waiting: Mutex::new(Vec::new()),
        })
    }

    fn judge(self: &Arc<Self>) -> Arc<dyn crate::DialJudge> {
        let held = Arc::clone(self);
        Arc::new(
            move |_: &str,
                  _: u32,
                  done: crate::Judged|
                  -> Option<Result<std::net::SocketAddr, crate::Verdict>> {
                if held.calls.fetch_add(1, Ordering::SeqCst) < held.held {
                    held.waiting.lock().unwrap().push(done);
                    return None;
                }
                (*held.at.lock().unwrap()).map(Ok)
            },
        )
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    /// Every later judgement answers `at` at once.
    fn then(&self, at: &str) {
        *self.at.lock().unwrap() = Some(at.parse().unwrap());
    }

    /// Answer every judgement held so far with `verdict`.
    fn answer(&self, verdict: Result<&str, crate::Verdict>) {
        let waiting = std::mem::take(&mut *self.waiting.lock().unwrap());
        for done in waiting {
            done(verdict.map(|at| at.parse().unwrap()));
        }
    }
}

/// A hostname target at `far`'s port: judged by the test's judge, never a literal.
fn hostname(far: &FarEnd) -> String {
    let port = far.addr.rsplit_once(':').unwrap().1;
    format!("far.invalid:{port}")
}

// ---------------------------------------------------------------------------------------------
// The tests.

/// RED (the red-proof): sixteen concurrent upstream exchanges on a cold h2 key each dialled their
/// own connection (sixteen accepts: sixteen handshakes, fifteen surplus pooled lines). With the
/// single-flight dial, the first leads the key's one dial and the rest join it: one accept, and
/// all sixteen complete.
#[test]
fn h2_burst_dials_once() {
    let rt = runtime();
    let _in = rt.enter();
    let (far, c) = tls_rig(&rt, &[b"h2"], H2);

    let desc = request(&far.addr, 0);
    let burst: Vec<ConnId> = (0..BURST).map(|_| owned(&c, &desc)).collect();
    read_whole(&c, &burst);

    assert_eq!(
        far.accepted(),
        1,
        "the burst's sixteen exchanges ride the key's one dial"
    );
}

/// RED: a cold HOSTNAME key whose judgement pends (the DNS wait). The key had no pool entry at all
/// while its first open waited, so every open of the burst was judged and dialled on its own
/// (sixteen judgements, sixteen accepts). The claim keeps the key's slot through the wait: one
/// judgement, one accept.
#[test]
fn deferred_judgement_burst_dials_once() {
    let rt = runtime();
    let _in = rt.enter();
    let cert = cert();
    let far = far_end(&rt, Some(server(&cert, &[b"h2"])), None);
    let judge = HeldJudge::new(usize::MAX);
    let c = connector(door(true, Some(H2)), judge.judge(), vec![cert.ca.clone()]);

    let target = hostname(&far);
    let desc = request(&target, 0);
    let burst: Vec<ConnId> = (0..BURST).map(|_| owned(&c, &desc)).collect();
    let judged = judge.calls();
    judge.answer(Ok(&far.addr));
    read_whole(&c, &burst);

    assert_eq!(
        judged, 1,
        "only the claimed dial is judged: the burst waits on its one judgement"
    );
    assert_eq!(far.accepted(), 1, "the burst rides the key's one dial");
}

/// PIN (W-022's carry): cleartext h2 by prior knowledge, the dial's offer exactly `h2`, agreed at
/// the dial, multiplexes from its dial on: its burst rides one dial. (Its exchanges share the line
/// from their opens, so the scripted far end, which answers the stream that emitted last, is only
/// counted here, never read.)
#[test]
fn h2c_prior_knowledge_burst_dials_once() {
    let rt = runtime();
    let _in = rt.enter();
    let far = far_end(&rt, None, None);
    let c = connector(
        door(false, Some(H2)),
        crate::tests::loopback_literals(),
        Vec::new(),
    );

    let desc = request(&far.addr, 0);
    let burst: Vec<ConnId> = (0..BURST).map(|_| owned(&c, &desc)).collect();
    until("the burst's dial is accepted", || {
        (far.accepted() > 0).then_some(())
    });
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(far.accepted(), 1, "the cleartext h2 burst rides one dial");
    for conn in burst {
        c.close(OWNER, conn).unwrap();
    }
}

/// The leader is dropped before its handshake: its followers learn "lost" at once, one of them
/// leads the next dial and the rest ride it (two accepts in all), and the dropped leader's
/// in-use line never stands in the way.
#[test]
fn leader_dropped_before_handshake_reforms_once() {
    let rt = runtime();
    let _in = rt.enter();
    let (far, c) = tls_rig(&rt, &[b"h2"], H2);

    let desc = request(&far.addr, 0);
    let burst: Vec<ConnId> = (0..BURST).map(|_| owned(&c, &desc)).collect();
    assert!(
        burst[1..].iter().all(|conn| follows(&c, *conn)),
        "the rest of the burst joined the leader's dial"
    );
    until("the leader's connect is accepted", || {
        (far.accepted() == 1).then_some(())
    });
    c.close(OWNER, burst[0]).unwrap();
    read_whole(&c, &burst[1..]);

    assert_eq!(
        far.accepted(),
        2,
        "the dropped leader's dial and the one its followers re-formed"
    );
}

/// The leader is REFUSED (its judgement answers a refusal): every follower ends inside its own
/// deadline, the next claimed dial is judged once, and the burst rides it.
#[test]
fn leader_refused_followers_bounded() {
    let rt = runtime();
    let _in = rt.enter();
    let cert = cert();
    let far = far_end(&rt, Some(server(&cert, &[b"h2"])), None);
    let judge = HeldJudge::new(1);
    let c = connector(door(true, Some(H2)), judge.judge(), vec![cert.ca.clone()]);

    let target = hostname(&far);
    let leader = owned(&c, &request(&target, 0));
    let bound = 3000;
    let desc = request(&target, bound);
    let opened = Instant::now();
    let followers: Vec<ConnId> = (1..BURST).map(|_| owned(&c, &desc)).collect();
    judge.then(&far.addr);
    judge.answer(Err(busbar_contract::services::codes::DEST_METADATA));

    let (_, _, refused) = answer(&c, leader);
    assert!(refused.is_some(), "the refused leader's exchange fails");
    read_whole(&c, &followers);

    assert!(
        opened.elapsed() < Duration::from_millis(bound),
        "every follower ended inside its own deadline"
    );
    assert_eq!(
        judge.calls(),
        2,
        "the refused claim, and the one claim its followers re-formed"
    );
    assert_eq!(far.accepted(), 1, "the followers ride the re-formed dial");
}

/// The leader's driver STALLS (it is never polled after its open), and the followers are polled
/// only by their own wakers: the join cap's timer wakes each, and each dials its own and
/// completes, never a Timeout caused by the leader.
#[test]
fn follower_survives_stalled_leader() {
    let rt = runtime();
    let _in = rt.enter();
    let (far, c) = tls_rig(&rt, &[b"h2"], H2);

    let _leader = owned(&c, &request(&far.addr, 0));
    let desc = request(&far.addr, 2000);
    let followers = [owned(&c, &desc), owned(&c, &desc)];
    for follower in followers {
        assert!(follows(&c, follower), "it joined the stalled leader's dial");
        assert_eq!(
            answer_woken(&c, follower),
            whole(),
            "woken at its cap, the follower dials its own and completes"
        );
    }
}

/// A HUNG leader (no bound of its own) and a follower with a short one: the follower completes on
/// its own dial, inside its own deadline, with no Timeout.
#[test]
fn hung_leader_short_timeout_follower() {
    let rt = runtime();
    let _in = rt.enter();
    let (far, c) = tls_rig(&rt, &[b"h2"], H2);

    let _leader = owned(&c, &request(&far.addr, 0));
    let follower = owned(&c, &request(&far.addr, 600));
    assert!(follows(&c, follower), "it joined the hung leader's dial");
    assert_eq!(
        answer(&c, follower),
        whole(),
        "the follower completes on its own dial"
    );
}

/// The far end agrees http/1.1: the leader settles `solo` at its handshake, its followers each
/// dial their own (sixteen accepts), and a second burst never parks.
#[test]
fn h1_server_burst_dials_each_then_solo() {
    let rt = runtime();
    let _in = rt.enter();
    let (far, c) = tls_rig(&rt, &[b"http/1.1"], H2_H1);

    let desc = request(&far.addr, 0);
    let burst: Vec<ConnId> = (0..BURST).map(|_| owned(&c, &desc)).collect();
    let (shard, key) = pooled(&c, burst[0]);
    read_whole(&c, &burst);
    assert_eq!(
        far.accepted(),
        BURST,
        "an http/1.1 line carries one exchange"
    );
    assert_eq!(
        c.pools.claimed(shard, &key),
        (false, true),
        "no claim in flight, and the key is solo"
    );

    let again: Vec<ConnId> = (0..BURST).map(|_| owned(&c, &desc)).collect();
    assert!(
        again.iter().all(|conn| !follows(&c, *conn)),
        "a solo key's second burst never parks"
    );
    read_whole(&c, &again);
}

/// No plugin-paced open claims: `open`, `open_with_security`, `open_located`, `open_request` and a
/// prepared exchange, all with an h2 offer, each dial their own and never park.
#[test]
fn plugin_opens_never_claim() {
    let rt = runtime();
    let _in = rt.enter();
    let (far, c) = tls_rig(&rt, &[b"h2"], H2);

    let desc = request(&far.addr, 0);
    let opened = [
        c.open(OWNER, NEED, &desc),
        c.open_with_security(OWNER, NEED, &desc, false),
        c.open_located(OWNER, NEED, &desc, false, None),
        c.open_request(OWNER, NEED, &desc, false, 0),
        c.prepare_request(OWNER, NEED, &desc, 5000),
    ]
    .map(|conn| conn.expect("the open is taken"));
    let (shard, key) = pooled(&c, opened[0]);
    for conn in opened {
        assert!(!follows(&c, conn), "a plugin-paced open never parks");
    }
    assert_eq!(
        c.pools.claimed(shard, &key),
        (false, false),
        "nothing claimed the key"
    );
    until("every plugin-paced open dialled its own", || {
        (far.accepted() == opened.len()).then_some(())
    });
    for conn in opened {
        c.close(OWNER, conn).unwrap();
    }
}

/// Two needs to the same authority never share a claimed dial or a line.
#[test]
fn two_needs_one_authority_never_share() {
    let rt = runtime();
    let _in = rt.enter();
    let (far, c) = tls_rig(&rt, &[b"h2"], H2);
    let other = NeedId(1);
    c.declare_over(OWNER, other, "messages").unwrap();

    let desc = request(&far.addr, 0);
    let first = owned_on(&c, NEED, &desc);
    let second = owned_on(&c, other, &desc);
    assert!(
        !follows(&c, second),
        "the other need's open does not join this need's dial"
    );
    assert_ne!(pooled(&c, first).1, pooled(&c, second).1, "two keys");
    read_whole(&c, &[first, second]);
    assert_eq!(far.accepted(), 2, "each need dials its own line");
}

/// Idle expiry (the sweep) and `drop_line` during an opening keep the key's slot: later opens
/// still join the claimed dial in flight.
#[test]
fn slot_survives_expiry_during_opening() {
    let rt = runtime();
    let _in = rt.enter();
    let cert = cert();
    let far = far_end(&rt, Some(server(&cert, &[b"h2"])), None);
    let judge = HeldJudge::new(1);
    let c = connector(door(true, Some(H2)), judge.judge(), vec![cert.ca.clone()]);

    let target = hostname(&far);
    let desc = request(&target, 0);
    let leader = owned(&c, &desc);
    let (shard, key) = pooled(&c, leader);
    crate::off_path::lines::sweep_idle_lines(&c.pools, Duration::ZERO, crate::framer::now())
        .close();
    let swept = owned(&c, &desc);
    assert!(
        follows(&c, swept),
        "the sweep kept the slot of a claimed dial in flight"
    );

    judge.then(&far.addr);
    judge.answer(Ok(&far.addr));
    // One read dials the leader (its handshake is still owed) and holds its line in the slot.
    let _ = c.read(OWNER, leader, TICKET, &mut [0_u8; 8]);
    let line = line_of(&c, leader).expect("the leader's line");
    let live = c.pools.claimed(shard, &key).0;
    assert!(
        live,
        "the leader's handshake is owed: its claim is in flight"
    );
    c.pools.drop_line(shard, &key, &line);
    assert_eq!(
        c.pools.claimed(shard, &key).0,
        live,
        "drop_line keeps the slot while its claimed dial is in flight"
    );
    let dropped = owned(&c, &desc);
    assert!(follows(&c, dropped), "a later open still joins it");
    read_whole(&c, &[leader, swept, dropped]);
}

/// A flush (`forget`) during an opening wakes every follower parked on it, and each ends.
#[test]
fn flush_wakes_followers() {
    let rt = runtime();
    let _in = rt.enter();
    let cert = cert();
    let far = far_end(&rt, Some(server(&cert, &[b"h2"])), None);
    let judge = HeldJudge::new(1);
    let c = connector(door(true, Some(H2)), judge.judge(), vec![cert.ca.clone()]);

    let target = hostname(&far);
    let desc = request(&target, 0);
    let leader = owned(&c, &desc);
    let followers: Vec<ConnId> = (0..3).map(|_| owned(&c, &desc)).collect();
    let parked: Vec<(ConnId, Arc<Woken>)> = followers
        .iter()
        .map(|conn| {
            let woken = Arc::new(Woken::default());
            let waker = Waker::from(Arc::clone(&woken));
            let polled = c.poll_read(
                OWNER,
                *conn,
                &mut Context::from_waker(&waker),
                &mut [0_u8; 8],
            );
            assert!(polled.is_pending(), "the follower parks");
            (*conn, woken)
        })
        .collect();

    c.pools.forget(OWNER);
    for (conn, woken) in &parked {
        assert!(woken.wait(), "the flush woke follower {conn:?}");
    }

    judge.then(&far.addr);
    judge.answer(Ok(&far.addr));
    for conn in std::iter::once(leader).chain(followers) {
        let _ended = answer(&c, conn);
        c.close(OWNER, conn).unwrap();
    }
}

/// The leader's line fails the destination's sealed anchors: no follower byte reaches the far
/// end, the followers learn "lost" without waiting for the leader's close, and the key is never
/// `solo`.
#[test]
fn anchor_mismatch_burst_sends_no_follower_bytes() {
    use busbar_contract::crypto::testing::rcgen::{KeyPair, PublicKeyData as _};
    use busbar_contract::transport::trust::{key_pin, Anchors};

    let rt = runtime();
    let _in = rt.enter();
    let (far, c) = tls_rig(&rt, &[b"h2"], H2);
    let other = KeyPair::generate().unwrap();
    let anchors = Anchors {
        extra_anchors: Vec::new(),
        key_pin: Some(key_pin(&other.subject_public_key_info())),
        client_identity: None,
        private_reach: false,
    };
    c.anchor(OWNER, NEED, "", &far.addr, &anchors)
        .expect("sealed");

    let desc = request(&far.addr, 0);
    let burst: Vec<ConnId> = (0..BURST).map(|_| owned(&c, &desc)).collect();
    let (shard, key) = pooled(&c, burst[0]);
    for (n, conn) in burst.iter().enumerate() {
        let (got, _, failed) = answer(&c, *conn);
        assert!(
            got.is_empty() && failed.is_some(),
            "exchange {n} fails at the anchors, the leader still open"
        );
    }
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(far.read(), 0, "no request byte reached the far end");
    assert!(
        !c.pools.claimed(shard, &key).1,
        "an anchor failure is lost, never solo"
    );
    for conn in burst {
        c.close(OWNER, conn).unwrap();
    }
}

/// MULTI-THREAD: eight worker threads (each its own pool shard) burst on one key at once: at most
/// one dial per shard.
#[test]
fn multi_thread_burst_dials_once_per_shard() {
    const THREADS: usize = 8;
    let rt = runtime();
    let _in = rt.enter();
    let (far, c) = tls_rig(&rt, &[b"h2"], H2);

    let go = Arc::new(std::sync::Barrier::new(THREADS));
    let workers: Vec<_> = (0..THREADS)
        .map(|_| {
            let (c, go, addr) = (Arc::clone(&c), Arc::clone(&go), far.addr.clone());
            let handle = rt.handle().clone();
            std::thread::spawn(move || {
                let _in = handle.enter();
                go.wait();
                let desc = request(&addr, 0);
                (0..4).map(|_| owned(&c, &desc)).collect::<Vec<_>>()
            })
        })
        .collect();
    let opened: Vec<ConnId> = workers
        .into_iter()
        .flat_map(|w| w.join().expect("the worker opened its burst"))
        .collect();
    std::thread::sleep(Duration::from_millis(200));

    let shards = c.pools.shards.len().min(THREADS);
    assert!(
        (1..=shards).contains(&far.accepted()),
        "at most one dial per shard: {} accepts, {shards} shards",
        far.accepted()
    );
    for conn in opened {
        c.close(OWNER, conn).unwrap();
    }
}

/// An exchange whose idle line failed meanwhile completes on a second line taken through the
/// pool (a redial goes through `take` too), redialled once only: the next exchange rides that
/// second line.
#[test]
fn redial_on_failed_lent_line_once() {
    let rt = runtime();
    let _in = rt.enter();
    let far = far_end(&rt, None, Some(1));
    let c = connector(
        door(false, None),
        crate::tests::loopback_literals(),
        Vec::new(),
    );

    let desc = request(&far.addr, 0);
    read_whole(&c, &[owned(&c, &desc)]);
    until("the first connection closes", || far.ended(0).then_some(()));
    // Its end reaches the idle line before the next take reads it.
    std::thread::sleep(Duration::from_millis(100));
    read_whole(&c, &[owned(&c, &desc)]);
    read_whole(&c, &[owned(&c, &desc)]);

    assert_eq!(
        far.accepted(),
        2,
        "the failed line, then one more, kept for the next exchange"
    );
}

// ---------------------------------------------------------------------------------------------
// R62 `fill-without-claim`: the source law.

/// The open that claims, the follower arm, and the redial: the only fns that call the pool's take.
const TAKERS: [&str; 3] = ["dial_exchange_pooling", "follow", "redial"];
/// The one binding of the open's claim.
const CLAIM: &str = "let claim = owned.is_some();";

/// Every non-test source file of the crate, by its path under `src` (`/`-separated), and its text.
fn sources(src: &Path) -> Vec<(String, String)> {
    fn walk(dir: &Path, src: &Path, out: &mut Vec<(String, String)>) {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        entries.sort();
        for path in entries {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if path.is_dir() {
                if name != "tests" {
                    walk(&path, src, out);
                }
                continue;
            }
            let test = name == "tests.rs"
                || name.ends_with("_tests.rs")
                || name.starts_with("test_support");
            if !name.ends_with(".rs") || test {
                continue;
            }
            let rel = path
                .strip_prefix(src)
                .unwrap()
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            out.push((rel, std::fs::read_to_string(&path).unwrap()));
        }
    }
    let mut out = Vec::new();
    walk(src, src, &mut out);
    out
}

fn ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Every position of `word` in `text` as a whole identifier.
fn word_at(text: &str, word: &str) -> Vec<usize> {
    let bytes = text.as_bytes();
    text.match_indices(word)
        .map(|(at, _)| at)
        .filter(|at| {
            let before = at.checked_sub(1).is_none_or(|b| !ident(bytes[b]));
            let after = bytes.get(at + word.len()).is_none_or(|b| !ident(*b));
            before && after
        })
        .collect()
}

/// The name of the fn whose text holds position `at` (the last `fn` before it).
fn enclosing_fn(text: &str, at: usize) -> String {
    let head = &text[..at];
    let Some(fn_at) = word_at(head, "fn").last().copied() else {
        return String::new();
    };
    head[fn_at + 2..]
        .trim_start()
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect()
}

/// The body of method `name` (rustfmt's shape: it ends at its own four-space `}` line).
fn method_body<'t>(text: &'t str, name: &str) -> Option<&'t str> {
    let start = text.find(&format!("fn {name}("))?;
    let len = text[start..].find("\n    }\n")?;
    Some(&text[start..start + len])
}

/// Every call of the pool's take in `text` (`pools.take(`, its receiver spelled across lines or
/// not, and `Pools::take(`): its position and its arguments.
fn take_calls(text: &str) -> Vec<(usize, Vec<String>)> {
    let mut calls = Vec::new();
    for (at, _) in text.match_indices(".take(") {
        if text[..at].trim_end().ends_with("pools") {
            calls.push((at, call_args(&text[at + ".take(".len()..])));
        }
    }
    for (at, _) in text.match_indices("Pools::take(") {
        calls.push((at, call_args(&text[at + "Pools::take(".len()..])));
    }
    calls
}

/// The top-level arguments of a call whose text (after its `(`) is `rest`.
fn call_args(rest: &str) -> Vec<String> {
    let mut args = vec![String::new()];
    let mut depth = 0_usize;
    for c in rest.chars() {
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' if depth == 0 => break,
            ')' | ']' | '}' => depth -= 1,
            ',' if depth == 0 => {
                args.push(String::new());
                continue;
            }
            _ => {}
        }
        if let Some(arg) = args.last_mut() {
            arg.push(c);
        }
    }
    args.into_iter()
        .map(|a| a.split_whitespace().collect::<String>())
        .filter(|a| !a.is_empty())
        .collect()
}

/// Every binding or assignment of the identifier `claim` in `body` (`let claim`, `let mut claim`,
/// `claim =`).
fn claim_assignments(body: &str) -> usize {
    word_at(body, "claim")
        .into_iter()
        .filter(|at| {
            let before = body[..*at].trim_end();
            let bound = before.ends_with("let") || before.ends_with("let mut");
            let rest = body[at + "claim".len()..].trim_start();
            bound || (rest.starts_with('=') && !rest.starts_with("=="))
        })
        .count()
}

/// What R62 refuses in `files`.
fn breaches(files: &[(String, String)]) -> Vec<String> {
    let mut found = Vec::new();
    for (path, text) in files {
        if path != "pool.rs" {
            for token in ["Leader", "Fill"] {
                for at in word_at(text, token) {
                    if text[at + token.len()..].trim_start().starts_with('{') {
                        found.push(format!("{path}: `{token} {{` built outside pool.rs"));
                    }
                }
            }
        }
        if path != "pool.rs" && path != "off_path/lines.rs" && !word_at(text, "shards").is_empty() {
            found.push(format!(
                "{path}: the pools' `shards` reached outside the pool"
            ));
        }
        if path == "pool.rs" {
            let pools = text
                .find("\nimpl Pools {\n")
                .map(|at| &text[at..at + text[at..].find("\n}\n").unwrap_or(text.len() - at)]);
            for regained in ["fn lend(", "fn hold("] {
                if pools.is_some_and(|block| block.contains(regained)) {
                    found.push(format!("pool.rs: `Pools` regained `{regained}`"));
                }
            }
        }
        for (at, args) in take_calls(text) {
            let caller = enclosing_fn(text, at);
            if path != "conns.rs" || !TAKERS.contains(&caller.as_str()) {
                found.push(format!("{path}: the pool's take called from `{caller}`"));
            }
            match caller.as_str() {
                "dial_exchange_pooling" if args.get(2).map(String::as_str) != Some("claim") => {
                    found.push(format!(
                        "{path}: the open's take passes {args:?}, not `claim`"
                    ));
                }
                "redial" if args.get(2).map(String::as_str) != Some("false") => {
                    found.push(format!("{path}: the redial's take claims: {args:?}"));
                }
                _ => {}
            }
        }
        if path == "conns.rs" {
            match method_body(text, "dial_exchange_pooling") {
                Some(body) if body.contains(CLAIM) => {
                    if claim_assignments(body) != 1 {
                        found.push("conns.rs: the open's `claim` is assigned again".to_owned());
                    }
                }
                _ => found.push(format!("conns.rs: `{CLAIM}` is missing from the open")),
            }
            for taker in ["follow", "redial"] {
                if method_body(text, taker).is_some_and(|body| claim_assignments(body) > 0) {
                    found.push(format!("conns.rs: `{taker}` binds a `claim` of its own"));
                }
            }
        }
    }
    found
}

/// One planted breach: what it plants, the file it plants it in, how, and the words its refusal names.
type Arm = (
    &'static str,
    &'static str,
    Box<dyn Fn(&str) -> String>,
    &'static str,
);

/// `files` with `path`'s text changed by `plant`.
fn planted(
    files: &[(String, String)],
    path: &str,
    plant: impl Fn(&str) -> String,
) -> Vec<(String, String)> {
    files
        .iter()
        .map(|(p, text)| {
            let text = if p == path { plant(text) } else { text.clone() };
            (p.clone(), text)
        })
        .collect()
}

/// R62 `fill-without-claim` (LINT-RULES §28): a line enters a pool slot only through a token
/// `Pools::take` minted (`Leader`, `Fill`, built nowhere else; the shards reached by the pool
/// alone; no `lend`/`hold` on `Pools`); the take is called only by the open, the follower arm and
/// the redial; the open passes its one `claim` binding (`let claim = owned.is_some();`), the redial
/// passes `false`, and nothing else binds a `claim`. Each planted breach proves its matcher fires.
#[test]
fn pool_fills_through_take() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let files = sources(&src);
    for read in ["pool.rs", "conns.rs", "off_path/lines.rs"] {
        assert!(
            files.iter().any(|(p, _)| p == read),
            "the walk reads {read}"
        );
    }
    assert_eq!(breaches(&files), Vec::<String>::new(), "R62 holds");

    let open_take = "self.pools.take(*shard, key, claim, candidate)";
    let redial_take = "self.pools.take(*shard, key, false, false)";
    let arms: [Arm; 9] = [
        (
            "a leader built outside pool.rs",
            "conns.rs",
            Box::new(|t: &str| format!("{t}\nfn planted() {{ let _ = Leader {{ }}; }}\n")),
            "built outside",
        ),
        (
            "a fill built outside pool.rs",
            "off_path/lines.rs",
            Box::new(|t: &str| format!("{t}\nfn planted() {{ let _ = Fill {{ }}; }}\n")),
            "built outside",
        ),
        (
            "the shards reached outside the pool",
            "conns.rs",
            Box::new(|t: &str| {
                format!("{t}\nfn planted(p: &Pools) -> usize {{ p.shards.len() }}\n")
            }),
            "`shards`",
        ),
        (
            "a lend regained",
            "pool.rs",
            Box::new(|t: &str| {
                t.replacen(
                    "\nimpl Pools {\n",
                    "\nimpl Pools {\n    fn lend(&self) {}\n",
                    1,
                )
            }),
            "regained",
        ),
        (
            "a take from elsewhere",
            "conns.rs",
            Box::new(|t: &str| {
                format!("{t}\nfn elsewhere(c: &Connector) {{ c.pools.take(0, k, true, true); }}\n")
            }),
            "called from `elsewhere`",
        ),
        (
            "the open passing another claim",
            "conns.rs",
            Box::new(move |t: &str| {
                t.replacen(
                    open_take,
                    "self.pools.take(*shard, key, true, candidate)",
                    1,
                )
            }),
            "not `claim`",
        ),
        (
            "the open's binding gone",
            "conns.rs",
            Box::new(|t: &str| t.replacen(CLAIM, "let claim = true;", 1)),
            "missing",
        ),
        (
            "the follower arm binding a claim",
            "conns.rs",
            Box::new(|t: &str| {
                t.replacen(
                    "fn follow(&self, held: &Held, waker: Option<&Waker>) -> Result<bool, ConnError> {\n",
                    "fn follow(&self, held: &Held, waker: Option<&Waker>) -> Result<bool, ConnError> {\n        let claim = true;\n",
                    1,
                )
            }),
            "binds a `claim`",
        ),
        (
            "the redial claiming",
            "conns.rs",
            Box::new(move |t: &str| {
                t.replacen(redial_take, "self.pools.take(*shard, key, true, false)", 1)
            }),
            "redial's take claims",
        ),
    ];
    for (what, path, plant, says) in arms {
        let changed = planted(&files, path, plant);
        assert!(
            changed != files,
            "{what}: the plant changed the text (its anchor is still in the source)"
        );
        let found = breaches(&changed);
        assert!(
            found.iter().any(|f| f.contains(says)),
            "{what}: the matcher fires ({found:?})"
        );
    }
}
