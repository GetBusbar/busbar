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

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
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

// ---------------------------------------------------------------------------------------------
// Far ends.

/// One accepted connection: what it read.
#[derive(Default)]
struct Peer {
    got: Mutex<Vec<u8>>,
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

/// A far end on `rt`, serving TLS under `tls`.
fn far_end(rt: &tokio::runtime::Runtime, tls: Arc<rustls::ServerConfig>) -> FarEnd {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.set_nonblocking(true).unwrap();
    let addr = l.local_addr().unwrap().to_string();
    let peers: Arc<Mutex<Vec<Arc<Peer>>>> = Arc::default();
    let accepted = Arc::clone(&peers);
    rt.spawn(async move {
        let l = tokio::net::TcpListener::from_std(l).unwrap();
        while let Ok((s, _)) = l.accept().await {
            let peer = Arc::new(Peer::default());
            accepted.lock().unwrap().push(Arc::clone(&peer));
            let tls = Arc::clone(&tls);
            tokio::spawn(async move {
                if let Ok(s) = tokio_rustls::TlsAcceptor::from(tls).accept(s).await {
                    serve(s, &peer).await;
                }
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

/// A TLS far end's config serving `cert`, agreeing `h2` by ALPN.
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

/// The scripted `messages` framer over TLS (`localhost`), offering `offer`.
fn door(offer: &'static [u8]) -> TestDoor {
    TestDoor::new(
        "messages",
        &["messages"],
        &[],
        Knobs {
            secure_name: Some("localhost"),
            offer: Some(offer),
            messages: Some(EXCHANGE_STREAM),
            messages_follow_emit: true,
            ..Knobs::default()
        },
    )
}

/// A pooling connector serving `framer` over the test carrier, dialling where `judge` says, its
/// client trusting `anchors`.
fn connector(
    framer: TestDoor,
    judge: Arc<dyn crate::DialJudge>,
    anchors: Vec<Vec<u8>>,
) -> Arc<Connector> {
    let view = Transports::new(vec![
        Entry {
            door: Arc::new(framer),
            alpn: Vec::new(),
        },
        Entry {
            door: Arc::new(TestDoor::identity("carrier")),
            alpn: Vec::new(),
        },
    ])
    .unwrap();
    let tls = Arc::new(
        crate::tls::client::build_client_config(&busbar_contract::transport::trust::EgressTrust {
            extra_anchors: anchors,
            ..Default::default()
        })
        .expect("a usable client config"),
    );
    let c = Connector::serving(view, judge, Some(tls), Arc::new(|_, _| {})).pooling(PoolPosture {
        max_idle_per_host: 8,
        idle_timeout: Duration::from_secs(60),
    });
    c.declare_over(OWNER, NEED, "messages").unwrap();
    Arc::new(c)
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

/// THE KERNEL-SHAPED OPEN: an upstream exchange carrying its owned head (`open_owned`).
fn owned(c: &Connector, desc: &OpenDesc<'_>) -> ConnId {
    c.open_owned(OWNER, NEED, desc, OwnedHead::with_capacity(0), false, None)
        .expect("the open is taken")
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
    let cert = cert();
    let far = far_end(&rt, server(&cert));
    let c = connector(
        door(H2),
        crate::tests::loopback_literals(),
        vec![cert.ca.clone()],
    );

    let desc = request(&far.addr, 0);
    let burst: Vec<ConnId> = (0..BURST).map(|_| owned(&c, &desc)).collect();
    read_whole(&c, &burst);

    assert_eq!(
        far.accepted(),
        1,
        "the burst's sixteen exchanges ride the key's one dial"
    );
}

/// A JUDGE THAT HOLDS ITS ANSWER: every judgement pends, counted, until the test answers it.
#[derive(Default)]
struct HeldJudge {
    calls: AtomicUsize,
    waiting: Mutex<Vec<crate::Judged>>,
}

impl HeldJudge {
    fn judge(self: &Arc<Self>) -> Arc<dyn crate::DialJudge> {
        let held = Arc::clone(self);
        Arc::new(move |_: &str, _: u32, done: crate::Judged| {
            held.calls.fetch_add(1, Ordering::SeqCst);
            held.waiting.lock().unwrap().push(done);
            None
        })
    }

    /// Answer every judgement held so far with `at`.
    fn answer(&self, at: &str) {
        let at: std::net::SocketAddr = at.parse().unwrap();
        let waiting = std::mem::take(&mut *self.waiting.lock().unwrap());
        for done in waiting {
            done(Ok(at));
        }
    }
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
    let far = far_end(&rt, server(&cert));
    let judge = Arc::new(HeldJudge::default());
    let c = connector(door(H2), judge.judge(), vec![cert.ca.clone()]);

    let port = far.addr.rsplit_once(':').unwrap().1;
    let target = format!("far.invalid:{port}");
    let desc = request(&target, 0);
    let burst: Vec<ConnId> = (0..BURST).map(|_| owned(&c, &desc)).collect();
    let judged = judge.calls.load(Ordering::SeqCst);
    judge.answer(&far.addr);
    read_whole(&c, &burst);

    assert_eq!(
        judged, 1,
        "only the claimed dial is judged: the burst waits on its one judgement"
    );
    assert_eq!(far.accepted(), 1, "the burst rides the key's one dial");
}
