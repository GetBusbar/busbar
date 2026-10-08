// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PRODUCTION FAR END over kind-neutral doubles of its ports: a scripted connection table, a
//! breaker that classifies by 1.5.5's status table and records what it is told, an auth binding
//! that counts its calls. Proven: one attempt end to end (the joined target, the head the framer
//! gets with the ONE auth call's fields after the plane's, the success recorded and its budget unit
//! spent); the step-24 Disposition (529 fails over with its Retry-After, 401 takes the member down,
//! a caller fault is relayed); the exhaustion terminal's Retry-After floor; the attempt cap; the
//! unit deadline stamped from the plane's stated stream ceiling.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use crate::proxy::egress_unit::{
    ports::{
        Admit, BoxFut, Breaker, Capacity, Classified, Clock, DestinationId, Dispatched,
        Disposition, DurabilityUnavailable, Journal, Outcome, Permit, PermitHandle, Telemetry,
        Unavailable, UpstreamStatus,
    },
    Failover, Member, OnExhausted, Pool, WeightedFloor,
};
use busbar_contract::auth_calls::{AuthField, Fielding, Fields, FieldsRequest, OutboundAuth};
use busbar_contract::caps::{Pass, Route};
use busbar_contract::conn::{
    ConnError, ConnId, Conns, InstanceId, NeedId, OpenDesc, Piece, PieceKind, PollConns, Ticket,
};
use busbar_contract::ids::StreamId;
use busbar_contract::transport::wire::WireStatusClass;
use busbar_contract::transport::ConnFacts;

use super::*;
use crate::plane_driver::{FarEnd, OutboundRequest, Pick};

// ── the doubles ─────────────────────────────────────────────────────────────────────────────────

/// What a scripted far end answers: its status and body pieces, or nothing at all.
#[derive(Clone)]
enum Script {
    Answer(u32, Option<u64>, Vec<&'static [u8]>),
    /// An answer whose body is followed by the far end's trailers.
    Trailed(u32, Vec<&'static [u8]>, &'static [u8]),
    Silent,
    Refused,
}

/// One open: its target, head, body and timeout.
type Opened = (String, Vec<(String, Vec<u8>)>, Vec<u8>, u64);
/// One open's head words: its method and its head target.
type Words = (Vec<u8>, Vec<u8>);
/// The facts one auth call saw: method, authority, path.
type Facts = (Vec<u8>, String, Vec<u8>);

/// A connection table whose far ends answer from `scripts`, by the target's host.
#[derive(Default)]
struct Table {
    scripts: HashMap<&'static str, Script>,
    opened: Mutex<Vec<Opened>>,
    words: Mutex<Vec<Words>>,
    live: Mutex<HashMap<u64, VecDeque<Piece>>>,
    bytes: Mutex<HashMap<u64, VecDeque<Vec<u8>>>>,
    next: AtomicU64,
    closed: AtomicU64,
    /// The need every open was made on.
    needs: Mutex<Vec<u32>>,
    /// Whether each write was a text message.
    texts: Mutex<Vec<bool>>,
    /// Every write: the connection, the bytes, and whether they completed the caller's message.
    written: Mutex<Vec<(u64, Vec<u8>, bool)>>,
}

fn piece(kind: PieceKind, len: usize, status: Option<(u32, Option<u64>)>) -> Piece {
    Piece {
        kind,
        stream: StreamId(0),
        len,
        end: kind == PieceKind::Completion,
        status: status.map(|(c, _)| match c {
            200..=299 => WireStatusClass::Success,
            400..=499 => WireStatusClass::CallerFault,
            _ => WireStatusClass::FarEndFault,
        }),
        status_code: status.map(|(c, _)| c),
        status_namespace: None,
        retry_after_secs: status.and_then(|(_, r)| r),
        reason: None,
    }
}

impl Conns for Table {
    fn open(&self, _: InstanceId, need: NeedId, d: &OpenDesc<'_>) -> Result<ConnId, ConnError> {
        self.needs.lock().unwrap().push(need.0);
        let host = d
            .target
            .split("://")
            .nth(1)
            .and_then(|r| r.split('/').next())
            .unwrap_or_default()
            .to_string();
        self.opened.lock().unwrap().push((
            d.target.to_string(),
            d.fields
                .iter()
                .map(|(n, v)| ((*n).to_string(), v.to_vec()))
                .collect(),
            d.body.to_vec(),
            d.timeout_ms,
        ));
        self.words
            .lock()
            .unwrap()
            .push((d.method.to_vec(), d.head_target.to_vec()));
        let script = self
            .scripts
            .iter()
            .find(|(h, _)| **h == host)
            .map(|(_, s)| s.clone())
            .unwrap_or(Script::Refused);
        let id = self.next.fetch_add(1, Ordering::SeqCst) + 1;
        let (pieces, bytes) = match script {
            Script::Refused => return Err(ConnError::Refused),
            Script::Silent => (VecDeque::new(), VecDeque::new()),
            Script::Trailed(status, chunks, trailers) => {
                let mut pieces = VecDeque::new();
                let mut bytes = VecDeque::new();
                for (k, c) in chunks.iter().enumerate() {
                    let s = (k == 0).then_some((status, None));
                    pieces.push_back(piece(PieceKind::Body, c.len(), s));
                    bytes.push_back(c.to_vec());
                }
                pieces.push_back(piece(PieceKind::Fields, trailers.len(), None));
                bytes.push_back(trailers.to_vec());
                pieces.push_back(piece(PieceKind::Completion, 0, None));
                bytes.push_back(Vec::new());
                (pieces, bytes)
            }
            Script::Answer(status, retry, chunks) => {
                let mut pieces = VecDeque::new();
                let mut bytes = VecDeque::new();
                for (k, c) in chunks.iter().enumerate() {
                    let s = (k == 0).then_some((status, retry));
                    pieces.push_back(piece(PieceKind::Body, c.len(), s));
                    bytes.push_back(c.to_vec());
                }
                pieces.push_back(piece(PieceKind::Completion, 0, None));
                bytes.push_back(Vec::new());
                (pieces, bytes)
            }
        };
        self.live.lock().unwrap().insert(id, pieces);
        self.bytes.lock().unwrap().insert(id, bytes);
        Ok(ConnId(id))
    }
    fn write(
        &self,
        _: InstanceId,
        c: ConnId,
        b: &[u8],
        end: bool,
        text: bool,
    ) -> Result<usize, ConnError> {
        self.written.lock().unwrap().push((c.0, b.to_vec(), end));
        self.texts.lock().unwrap().push(text);
        Ok(b.len())
    }
    fn read(&self, _: InstanceId, _: ConnId, _: Ticket, _: &mut [u8]) -> Result<Piece, ConnError> {
        Err(ConnError::Pending)
    }
    fn wait(&self, _: InstanceId, _: &[ConnId], _: Ticket) -> Result<usize, ConnError> {
        Err(ConnError::Pending)
    }
    fn facts(&self, _: InstanceId, _: ConnId) -> Result<ConnFacts, ConnError> {
        Ok(ConnFacts::default())
    }
    fn close(&self, _: InstanceId, _: ConnId) -> Result<(), ConnError> {
        self.closed.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

impl PollConns for Table {
    fn poll_read(
        &self,
        _: InstanceId,
        conn: ConnId,
        _: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<Piece, ConnError>> {
        let Some(p) = self
            .live
            .lock()
            .unwrap()
            .get_mut(&conn.0)
            .and_then(VecDeque::pop_front)
        else {
            // A silent far end never answers (and never wakes).
            return Poll::Pending;
        };
        let b = self
            .bytes
            .lock()
            .unwrap()
            .get_mut(&conn.0)
            .and_then(VecDeque::pop_front)
            .unwrap_or_default();
        buf[..b.len()].copy_from_slice(&b);
        Poll::Ready(Ok(p))
    }
}

/// A breaker that classifies by 1.5.5's status table and records every outcome it is told.
#[derive(Default)]
struct Book {
    observed: Mutex<Vec<(DestinationId, Outcome)>>,
    /// Every health probe's answer, as the far end told it; a success ends a cooldown.
    probed: Mutex<Vec<(DestinationId, Outcome)>>,
    cooldown: Mutex<HashMap<DestinationId, u64>>,
    spent: AtomicU64,
    refunded: AtomicU64,
}

impl Breaker for Book {
    fn try_admit(&self, _: &str, d: DestinationId, _: u64) -> Result<Admit, Unavailable> {
        match self.cooldown.lock().unwrap().get(&d) {
            Some(until) => Err(Unavailable::BreakerOpen { until: *until }),
            None => Ok(Admit { probe_epoch: None }),
        }
    }
    fn ready(&self, _: &str, _: DestinationId, _: u64, _: &Pass<Route>) -> bool {
        true
    }
    fn admissible(&self, _: DestinationId) -> bool {
        true
    }
    fn cooldown_remaining(&self, _: &str, d: DestinationId, _: u64, _: &Pass<Route>) -> u64 {
        self.cooldown.lock().unwrap().get(&d).copied().unwrap_or(0)
    }
    fn classify(&self, _: DestinationId, s: UpstreamStatus) -> Classified {
        let code = s
            .code
            .and_then(|c| c.in_namespace(status_ns::RESERVED[0]))
            .unwrap_or(500);
        let (disposition, outcome, label) = match code {
            401 | 403 => (Disposition::HardDown, Outcome::HardDown, "hard_down"),
            413 => (
                Disposition::ContextLength,
                Outcome::RecordNothing,
                "context_length",
            ),
            408 | 429 | 500..=599 => (
                Disposition::TransientUpstream,
                Outcome::Transient {
                    retry_after: s.retry_after,
                },
                "transient",
            ),
            _ => (
                Disposition::ClientFault,
                Outcome::RecordNothing,
                "client_fault",
            ),
        };
        Classified {
            disposition,
            outcome,
            label,
        }
    }
    fn observe(&self, _: &str, d: DestinationId, o: Outcome, _: u64, _: &Pass<Route>) -> bool {
        self.observed.lock().unwrap().push((d, o));
        false
    }
    fn suppressing(&self, d: DestinationId, _: u64) -> bool {
        self.cooldown.lock().unwrap().contains_key(&d)
    }
    fn probed(&self, d: DestinationId, o: Outcome, _: u64, _: &Pass<Route>) {
        if o == Outcome::Success {
            self.cooldown.lock().unwrap().remove(&d);
        }
        self.probed.lock().unwrap().push((d, o));
    }
    fn release_probe(&self, _: &str, _: DestinationId, _: u64, _: u64) {}
    fn spend_budget(&self, _: DestinationId) -> bool {
        self.spent.fetch_add(1, Ordering::SeqCst);
        true
    }
    fn refund_budget(&self, _: DestinationId) {
        self.refunded.fetch_add(1, Ordering::SeqCst);
    }
}

#[derive(Debug)]
struct Slot(DestinationId);
impl PermitHandle for Slot {
    fn destination(&self) -> DestinationId {
        self.0
    }
}

struct Free;
impl Capacity for Free {
    fn try_acquire(&self, d: DestinationId) -> Option<Permit> {
        Some(Permit::new(Box::new(Slot(d))))
    }
    fn acquire_any<'a>(
        &'a self,
        _: &'a [DestinationId],
    ) -> BoxFut<'a, Option<(DestinationId, Permit)>> {
        Box::pin(async { None })
    }
}

struct Wall;
impl Clock for Wall {
    fn now_secs(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
    fn now_millis(&self) -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    }
    fn sleep(&self, ms: u64) -> BoxFut<'_, ()> {
        Box::pin(tokio::time::sleep(std::time::Duration::from_millis(ms)))
    }
}

struct Quiet;

/// The write-ahead records the walk made, in order.
#[derive(Default)]
struct Kept(Mutex<Vec<Dispatched>>);
impl Journal for Kept {
    fn dispatched(&self, record: &Dispatched) -> Result<(), DurabilityUnavailable> {
        self.0.lock().unwrap().push(record.clone());
        Ok(())
    }
    fn abandoned(&self, _: &Dispatched) {}
}
impl Telemetry for Quiet {
    fn upstream_attempt(&self, _: &str, _: DestinationId) {}
    fn upstream_failure(&self, _: &str, _: DestinationId, _: &'static str) {}
    fn failover(&self, _: &str, _: &'static str) {}
    fn breaker_trip(&self, _: &str, _: DestinationId) {}
    fn queued(&self, _: &str, _: i64) {}
}

/// An auth binding answering `authorization: Bearer <credential>`, counting its calls.
#[derive(Default)]
struct Bearer {
    calls: AtomicU64,
    /// The caller credential each call carried.
    callers: Mutex<Vec<Option<Vec<u8>>>>,
    /// Never answers on the spot, and its submitted call never answers at all.
    stall: std::sync::atomic::AtomicBool,
    /// Refuses to field the attempt.
    refuse: std::sync::atomic::AtomicBool,
    facts: Mutex<Vec<Facts>>,
    /// The point each call was made at and the body it lent.
    points: Mutex<Vec<(AuthPoint, Option<Vec<u8>>)>>,
    /// The extensions blob each call lent.
    extensions: Mutex<Vec<Vec<u8>>>,
}
struct Done(Fields);
/// A submitted call that never answers.
struct Never;
impl std::future::Future for Never {
    type Output = Fields;
    fn poll(self: std::pin::Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Fields> {
        Poll::Pending
    }
}
impl Fielding for Never {
    fn settled(&mut self) -> Option<Fields> {
        None
    }
}
impl std::future::Future for Done {
    type Output = Fields;
    fn poll(self: std::pin::Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Fields> {
        Poll::Ready(self.0.clone())
    }
}
impl Fielding for Done {
    fn settled(&mut self) -> Option<Fields> {
        Some(self.0.clone())
    }
}
impl OutboundAuth for Bearer {
    fn open_outbound(&self, _: &str, _: &[u8], _: &serde_json::Value) -> Result<u64, String> {
        Ok(1)
    }
    fn fields_now(&self, _: u64, r: &FieldsRequest) -> Option<Fields> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.stall.load(Ordering::SeqCst) {
            return None;
        }
        if self.refuse.load(Ordering::SeqCst) {
            return Some(Fields::Refused);
        }
        self.callers.lock().unwrap().push(
            r.caller_credential
                .as_ref()
                .map(|c| c.expose_secret().clone()),
        );
        self.facts
            .lock()
            .unwrap()
            .push((r.method.clone(), r.authority.clone(), r.path.clone()));
        self.points.lock().unwrap().push((r.point, r.body.clone()));
        self.extensions.lock().unwrap().push(r.extensions.clone());
        Some(Fields::Ready(vec![AuthField {
            name: b"authorization".to_vec(),
            value: b"Bearer sk-test".to_vec().into(),
            sensitive: true,
        }]))
    }
    fn fields(&self, h: u64, r: FieldsRequest, _: u64) -> Box<dyn Fielding> {
        if self.stall.load(Ordering::SeqCst) {
            return Box::new(Never);
        }
        Box::new(Done(self.fields_now(h, &r).unwrap_or(Fields::Failed)))
    }
}

// ── the rig ─────────────────────────────────────────────────────────────────────────────────────

const POOL: &str = "p";

struct Rig {
    table: Arc<Table>,
    book: Arc<Book>,
    auth: Arc<Bearer>,
    journal: Arc<Kept>,
    egress: Egress,
}

/// A pool of `hosts`, one member each (`m0`, `m1`, ...), with `attempt_ms` as every member's cap.
fn rig(
    hosts: &[(&'static str, Script)],
    on_exhausted: OnExhausted,
    attempt_ms: Option<u64>,
) -> Rig {
    let table = Arc::new(Table {
        scripts: hosts.iter().cloned().collect(),
        ..Table::default()
    });
    let book = Arc::new(Book::default());
    let auth = Arc::new(Bearer::default());
    let journal = Arc::new(Kept::default());
    let members: Vec<Member> = hosts
        .iter()
        .enumerate()
        .map(|(k, _)| Member {
            attempt_timeout_ms: attempt_ms,
            // The first host weighs most, so the weighted walk tries it first.
            ..Member::new(
                DestinationId::new(k as u64 + 1),
                format!("m{k}"),
                (hosts.len() - k) as u32,
            )
        })
        .collect();
    let routes = hosts
        .iter()
        .enumerate()
        .map(|(k, (host, _))| {
            (
                DestinationId::new(k as u64 + 1),
                MemberRoute {
                    need: NeedId(0),
                    base_url: format!("https://{host}/v1/"),
                    provider: format!("p{k}"),
                    keep: super::ResponseKeep::default(),
                    rides: Vec::new(),
                    spelled: Vec::new(),
                    anchors: Default::default(),
                    auth: Some(AuthBinding {
                        auth: auth.clone() as Arc<dyn OutboundAuth>,
                        handle: 1,
                        style_flags: 0,
                        // m1's style signs the body (`HeadBody`); every other is over the head.
                        points: if k == 1 {
                            AuthPoints::HEAD_BODY
                        } else {
                            AuthPoints::HEAD
                        },
                        passthrough: k == 1,
                    }),
                },
            )
        })
        .collect();
    let pool = Pool {
        name: POOL.into(),
        members,
        failover: Failover {
            timeout_secs: 30,
            max_hops: 3,
            exclusions: Vec::new(),
        },
        on_exhausted,
    };
    let egress = Egress {
        caller: InstanceId(9),
        conns: table.clone(),
        breaker: book.clone(),
        capacity: Arc::new(Free),
        clock: Arc::new(Wall),
        journal: Arc::clone(&journal) as Arc<dyn Journal>,
        telemetry: Arc::new(Quiet),
        floor: WeightedFloor::new(),
        pools: HashMap::from([(POOL.to_string(), pool)]),
        routes,
        stream_ceiling_secs: 600,
        stated_ceiling_secs: 0,
        error_body_max: DEFAULT_ERROR_BODY_MAX,
    };
    Rig {
        table,
        book,
        auth,
        journal,
        egress,
    }
}

fn token() -> Pass<Route> {
    let kernel = crate::teller::Kernel::new();
    Pass::mint(kernel.seal())
}

fn request() -> OutboundRequest {
    OutboundRequest {
        text: false,
        member: String::new(),
        pool: String::new(),
        attempt_no: 1,
        verb: b"POST".to_vec(),
        target: b"/chat".to_vec(),
        fields: vec![(b"content-type".to_vec(), b"application/json".to_vec())],
        body: b"{}".to_vec(),
        need: 0,
    }
}

/// Drain one attempt's answer: its pieces until the last.
async fn drain(far: &EgressFarEnd<'_>, t: &Pass<Route>) -> Vec<FarPiece> {
    let mut out = Vec::new();
    while let Some(p) = far.next(t).await {
        let last = p.last;
        out.push(p);
        if last {
            break;
        }
    }
    out
}

fn route() -> UnitRoute {
    UnitRoute {
        pool: POOL.into(),
        ..UnitRoute::default()
    }
}

// ── the cases ───────────────────────────────────────────────────────────────────────────────────

/// One attempt, kernel to wire: the joined target, the plane's head then the ONE auth call's
/// fields, the body; the success recorded and one budget unit spent; the pieces relayed.
#[tokio::test]
async fn one_attempt_end_to_end() {
    let r = rig(
        &[("a.test", Script::Answer(200, None, vec![b"hel", b"lo"]))],
        OnExhausted::Status503,
        None,
    );
    let t = token();
    let far = r.egress.unit(route());
    assert_eq!(
        far.member(&t, 1).await,
        Pick::Member {
            name: "m0".into(),
            pool: POOL.into(),
            passthrough: false,
            provider: "p0".into(),
        }
    );
    assert!(far.send(&t, request()).await);
    let pieces = drain(&far, &t).await;
    assert_eq!(pieces[0].status, Some((200, 1)));
    assert!(!pieces[0].fail_over);
    let body: Vec<u8> = pieces.iter().flat_map(|p| p.bytes.clone()).collect();
    assert_eq!(body, b"hello");
    assert!(pieces.last().unwrap().last);
    let opened = r.table.opened.lock().unwrap().clone();
    assert_eq!(opened.len(), 1);
    let (target, head, body, _) = &opened[0];
    assert_eq!(
        target, "https://a.test/v1/chat",
        "base_url joined with the plane's path"
    );
    let names: Vec<&str> = head.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        names,
        ["authorization", "content-type"],
        "1.5.5's egress order: the auth fields before the plane's"
    );
    assert_eq!(head[0].1, b"Bearer sk-test");
    assert_eq!(
        r.table.words.lock().unwrap()[0],
        (b"POST".to_vec(), b"/v1/chat".to_vec()),
        "the method and the path ride as the head words"
    );
    assert_eq!(body, b"{}");
    assert_eq!(
        r.auth.calls.load(Ordering::SeqCst),
        1,
        "ONE auth call per attempt"
    );
    assert_eq!(
        r.auth.facts.lock().unwrap()[0],
        (b"POST".to_vec(), "a.test".to_string(), b"/v1/chat".to_vec())
    );
    assert_eq!(
        *r.book.observed.lock().unwrap(),
        vec![(DestinationId::new(1), Outcome::Success)]
    );
    assert_eq!(r.book.spent.load(Ordering::SeqCst), 1);
    assert_eq!(
        r.book.refunded.load(Ordering::SeqCst),
        0,
        "a clean end keeps the charge"
    );
    drop(far);
    assert_eq!(r.table.closed.load(Ordering::SeqCst), 1);
}

/// STEP 24, CAP 529: an overloaded far end is a transient failure with its Retry-After recorded,
/// and the attempt fails over to the next member; the next attempt re-calls auth once more.
#[tokio::test]
async fn a_529_fails_over_with_its_retry_after() {
    let r = rig(
        &[
            ("a.test", Script::Answer(529, Some(7), vec![b"overloaded"])),
            ("b.test", Script::Answer(200, None, vec![b"ok"])),
        ],
        OnExhausted::Status503,
        None,
    );
    let t = token();
    let far = r.egress.unit(route());
    let Pick::Member { name: first, .. } = far.member(&t, 1).await else {
        panic!("a member")
    };
    assert!(far.send(&t, request()).await);
    let p = far.next(&t).await.expect("a piece");
    assert!(p.fail_over && p.last, "{p:?}");
    assert!(p.bytes.is_empty(), "the 529's bytes never reach the plane");
    let Pick::Member { name: second, .. } = far.member(&t, 2).await else {
        panic!("a second member")
    };
    assert_ne!(first, second, "a tried member is never offered again");
    assert!(far.send(&t, request()).await);
    let pieces = drain(&far, &t).await;
    assert_eq!(pieces[0].status, Some((200, 1)));
    let observed = r.book.observed.lock().unwrap().clone();
    assert!(observed.contains(&(
        DestinationId::new(if first == "m0" { 1 } else { 2 }),
        Outcome::Transient {
            retry_after: Some(7)
        }
    )));
    assert_eq!(
        r.auth.calls.load(Ordering::SeqCst),
        2,
        "one auth call per attempt"
    );
}

/// AT MOST ONCE (ARCHITECT round 4 Q-L3B-SURFACES (h), the walk does repeatable): a unit whose
/// operation is performed at most once has a member's ANSWERED failure reach the plane as it came,
/// never retried on another member; the breaker still records it. The same answer without the flag
/// fails over (above).
#[tokio::test]
async fn an_answered_failure_of_an_at_most_once_operation_is_not_retried_elsewhere() {
    let r = rig(
        &[
            ("a.test", Script::Answer(529, Some(7), vec![b"overloaded"])),
            ("b.test", Script::Answer(529, Some(7), vec![b"overloaded"])),
        ],
        OnExhausted::Status503,
        None,
    );
    let t = token();
    let far = r.egress.unit(UnitRoute {
        once: true,
        ..route()
    });
    let Pick::Member { .. } = far.member(&t, 1).await else {
        panic!("a member")
    };
    assert!(far.send(&t, request()).await);
    let pieces = drain(&far, &t).await;
    assert!(
        pieces.iter().all(|p| !p.fail_over),
        "an at-most-once operation is not failed over once answered: {pieces:?}"
    );
    assert_eq!(pieces[0].status.map(|s| s.0), Some(529), "{pieces:?}");
    let observed = r.book.observed.lock().unwrap().clone();
    assert!(
        observed
            .iter()
            .any(|(_, o)| matches!(o, Outcome::Transient { .. })),
        "the breaker still records the answered failure: {observed:?}"
    );
}

/// STEP 24, member-401 (1.5.5 `route.failover|fb|member-401`: ONE egress, the 401 to the caller,
/// the member hard-down in every pool): a rejected key takes the member down (HardDown) and the
/// answer is relayed to the plane, whose verdict renders it — it is NOT failed over, so the next
/// member is never tried and no fallback pool is spilled into.
#[tokio::test]
async fn a_401_takes_the_member_down_and_is_relayed_to_the_plane() {
    let r = rig(
        &[
            ("a.test", Script::Answer(401, None, vec![b"no"])),
            ("b.test", Script::Answer(200, None, vec![b"ok"])),
        ],
        OnExhausted::Status503,
        None,
    );
    let t = token();
    let far = r.egress.unit(route());
    assert_eq!(
        far.member(&t, 1).await,
        Pick::Member {
            name: "m0".into(),
            pool: POOL.into(),
            passthrough: false,
            provider: "p0".into(),
        }
    );
    assert!(far.send(&t, request()).await);
    let p = far.next(&t).await.expect("a piece");
    assert!(!p.fail_over, "a hard-down is the plane's to render: {p:?}");
    assert_eq!(p.status, Some((401, 2)));
    assert_eq!(p.bytes, b"no", "the answer reaches the plane as it came");
    assert_eq!(
        *r.book.observed.lock().unwrap(),
        vec![(DestinationId::new(1), Outcome::HardDown)]
    );
    assert_eq!(
        r.table.opened.lock().unwrap().len(),
        1,
        "one egress: the next member is never dialled"
    );
}

/// A PASSTHROUGH member's 401 is the caller's own key failing (1.5.5's attempt classifier): nothing
/// is recorded against the member, and the answer is relayed to the plane as it came.
#[tokio::test]
async fn a_passthrough_members_401_records_nothing_and_is_relayed() {
    // m0 (own credential) is overloaded and fails over; m1 is the rig's passthrough member.
    let r = rig(
        &[
            ("a.test", Script::Answer(529, None, vec![b"busy"])),
            ("b.test", Script::Answer(401, None, vec![b"your key"])),
        ],
        OnExhausted::Status503,
        None,
    );
    let t = token();
    let far = r.egress.unit(UnitRoute {
        caller_credential: Some(b"caller-key".to_vec().into()),
        ..route()
    });
    let Pick::Member { passthrough, .. } = far.member(&t, 1).await else {
        panic!("a member")
    };
    assert!(!passthrough);
    assert!(far.send(&t, request()).await);
    assert!(far.next(&t).await.expect("a piece").fail_over);
    let Pick::Member { passthrough, .. } = far.member(&t, 2).await else {
        panic!("a second member")
    };
    assert!(passthrough);
    assert!(far.send(&t, request()).await);
    let p = far.next(&t).await.expect("a piece");
    assert!(!p.fail_over, "{p:?}");
    assert_eq!(p.status, Some((401, 2)));
    assert_eq!(p.bytes, b"your key");
    assert_eq!(
        *r.book.observed.lock().unwrap(),
        vec![(
            DestinationId::new(1),
            Outcome::Transient { retry_after: None }
        )],
        "the passthrough member's rejected key records nothing"
    );
}

/// A caller fault is not the destination's: nothing is recorded against it, and the far end's
/// answer reaches the plane as it came, with its status.
#[tokio::test]
async fn a_caller_fault_is_relayed_as_it_came() {
    let r = rig(
        &[("a.test", Script::Answer(400, None, vec![b"bad request"]))],
        OnExhausted::Status503,
        None,
    );
    let t = token();
    let far = r.egress.unit(route());
    let _ = far.member(&t, 1).await;
    assert!(far.send(&t, request()).await);
    let p = far.next(&t).await.expect("a piece");
    assert!(!p.fail_over);
    assert_eq!(p.status, Some((400, 2)));
    assert_eq!(p.bytes, b"bad request");
    assert_eq!(
        *r.book.observed.lock().unwrap(),
        vec![(DestinationId::new(1), Outcome::RecordNothing)]
    );
}

/// STEP 24, exhausted-retry-after-floor: with every member spent the pool's shed answers 503 and a
/// Retry-After of at least the floor (2 s with no cooldown to quote), or the soonest genuine
/// cooldown when one is running.
#[tokio::test]
async fn exhaustion_sheds_with_the_retry_after_floor() {
    let r = rig(
        &[("a.test", Script::Answer(503, None, vec![b"x"]))],
        OnExhausted::Status503,
        None,
    );
    let t = token();
    let far = r.egress.unit(route());
    let _ = far.member(&t, 1).await;
    assert!(far.send(&t, request()).await);
    assert!(far.next(&t).await.unwrap().fail_over);
    assert_eq!(
        far.member(&t, 2).await,
        Pick::Exhausted {
            status: 503,
            retry_after: Some(2)
        }
    );
    // A genuine cooldown is quoted instead of the floor.
    r.book
        .cooldown
        .lock()
        .unwrap()
        .insert(DestinationId::new(1), 9);
    let far = r.egress.unit(route());
    assert_eq!(
        far.member(&t, 1).await,
        Pick::Exhausted {
            status: 503,
            retry_after: Some(9)
        }
    );
}

/// The member's attempt cap bounds the wait for the first answer: a silent far end is a transient
/// failure and the attempt fails over; a refused dial likewise, never reaching the plane.
#[tokio::test]
async fn the_attempt_cap_and_a_refused_dial_fail_over() {
    let r = rig(
        &[("a.test", Script::Silent), ("b.test", Script::Refused)],
        OnExhausted::Status503,
        Some(50),
    );
    let t = token();
    let far = r.egress.unit(route());
    let mut failed = 0;
    for n in 1..=2 {
        let Pick::Member { .. } = far.member(&t, n).await else {
            panic!("a member")
        };
        if far.send(&t, request()).await {
            let p = far.next(&t).await.expect("a piece");
            assert!(p.fail_over, "{p:?}");
        }
        failed += 1;
    }
    assert_eq!(failed, 2);
    let observed = r.book.observed.lock().unwrap().clone();
    assert_eq!(observed.len(), 2, "{observed:?}");
    assert!(observed
        .iter()
        .all(|(_, o)| *o == Outcome::Transient { retry_after: None }));
    let opened = r.table.opened.lock().unwrap().clone();
    assert!(
        opened.iter().all(|o| o.3 <= 50),
        "the open is bounded by the attempt cap: {:?}",
        opened.iter().map(|o| o.3).collect::<Vec<_>>()
    );
}

/// THE UNIT'S DEADLINE IS THE PLANE'S STATED STREAM CEILING ALONE (ARCHITECT ruling 2026-10-07,
/// STREAM-CEILING, superseding Q5's pool timeout, which production never stamped): a streamed answer
/// on a plane that states a ceiling is bounded by it from the moment the route is known, and through
/// the far end the driver reads it from; a buffered answer, and any answer on a plane that states
/// none, has no unit deadline (the walk's budget and the deployment's stream ceiling bound the far
/// end's reads, as before). RED: the pool's request timeout stamped every unit, and a plane's
/// stated ceiling was read nowhere.
#[test]
fn the_unit_deadline_is_the_planes_stated_stream_ceiling_alone() {
    let mut r = rig(&[("a.test", Script::Silent)], OnExhausted::Status503, None);
    let now = 5_000_000_000;
    let streamed = UnitRoute {
        wants_stream: true,
        ..route()
    };
    assert_eq!(r.egress.deadline_ns(&route(), now), 0, "a buffered answer");
    assert_eq!(
        r.egress.deadline_ns(&streamed, now),
        0,
        "a plane that states no ceiling: no deadline, as the previous release"
    );
    r.egress.stated_ceiling_secs = 600;
    assert_eq!(
        r.egress.deadline_ns(&route(), now),
        0,
        "still none unbuffered"
    );
    assert_eq!(
        r.egress.deadline_ns(&streamed, now),
        now + 600 * 1_000_000_000
    );
    assert_eq!(
        FarEnd::deadline_ns(&r.egress.unit(streamed), now),
        now + 600 * 1_000_000_000,
        "the far end states it to the driver"
    );
    assert_eq!(FarEnd::deadline_ns(&r.egress.unit(route()), now), 0);
}

/// THE HEAD WORDS (P1 HEAD-FIELDS): the plane's verb and the joined path, its query kept, reach the
/// upstream request as the open's head words (`OpenDesc::method`, `OpenDesc::head_target`), byte
/// for byte; neither rides as a field, which a field block refuses to carry.
#[tokio::test]
async fn the_method_and_path_arrive_as_the_upstream_requests_head_words() {
    let r = rig(
        &[("a.test", Script::Answer(200, None, vec![b"ok"]))],
        OnExhausted::Status503,
        None,
    );
    let t = token();
    let far = r.egress.unit(route());
    assert!(matches!(far.member(&t, 1).await, Pick::Member { .. }));
    let mut req = request();
    req.verb = b"GET".to_vec();
    req.target = b"/models?limit=2&after=m%201".to_vec();
    assert!(far.send(&t, req).await);
    let _ = drain(&far, &t).await;
    assert_eq!(
        *r.table.words.lock().unwrap(),
        vec![(b"GET".to_vec(), b"/v1/models?limit=2&after=m%201".to_vec())]
    );
    let opened = r.table.opened.lock().unwrap().clone();
    assert_eq!(opened[0].0, "https://a.test/v1/models?limit=2&after=m%201");
    let names: Vec<&str> = opened[0].1.iter().map(|(n, _)| n.as_str()).collect();
    assert!(
        names
            .iter()
            .all(|n| *n != "method" && *n != "path" && !n.starts_with(':')),
        "no head word rides as a field: {names:?}"
    );
}

/// BUSBAR IS INVISIBLE TO UPSTREAMS (OWNER HARD RULE 2026-10-02): every field the plane hands over
/// goes out, except the per-connection mechanics the connection re-derives (hop-by-hop fields, one
/// a `connection` field nominates, `host`, `content-length`) and a field naming an auth field, which
/// the auth binding's own stands for.
#[tokio::test]
async fn the_planes_fields_go_out_but_the_per_connection_mechanics() {
    let r = rig(
        &[("a.test", Script::Answer(200, None, vec![b"ok"]))],
        OnExhausted::Status503,
        None,
    );
    let t = token();
    let far = r.egress.unit(route());
    assert!(matches!(far.member(&t, 1).await, Pick::Member { .. }));
    let mut req = request();
    for (n, v) in [
        ("x-client-trace", "abc"),
        ("Connection", "keep-alive, x-nominated"),
        ("x-nominated", "1"),
        ("keep-alive", "timeout=5"),
        ("transfer-encoding", "chunked"),
        ("Host", "client.example"),
        ("content-length", "9999"),
        ("Authorization", "Bearer caller"),
        ("X-Busbar-Made-Up", "busbar's own"),
    ] {
        req.fields
            .push((n.as_bytes().to_vec(), v.as_bytes().to_vec()));
    }
    assert!(far.send(&t, req).await);
    let _ = drain(&far, &t).await;
    let opened = r.table.opened.lock().unwrap().clone();
    let head: Vec<(&str, &[u8])> = opened[0]
        .1
        .iter()
        .map(|(n, v)| (n.as_str(), v.as_slice()))
        .collect();
    assert_eq!(
        head,
        [
            ("authorization", b"Bearer sk-test".as_slice()),
            ("content-type", b"application/json".as_slice()),
            ("x-client-trace", b"abc".as_slice()),
        ]
    );
}

/// A target that is not a path never leaves: joined onto the base it could move the authority
/// (`api.host@evil.test`) and carry the member's auth fields there. Nothing is opened, the auth
/// binding is never called, nothing is recorded against the member.
#[tokio::test]
async fn a_target_that_is_not_a_path_is_refused_before_the_dial() {
    let r = rig(
        &[("a.test", Script::Answer(200, None, vec![b"ok"]))],
        OnExhausted::Status503,
        None,
    );
    let t = token();
    for target in [&b"@evil.test/x"[..], b"evil.test/x", b""] {
        let far = r.egress.unit(route());
        let _ = far.member(&t, 1).await;
        let request = OutboundRequest {
            target: target.to_vec(),
            ..request()
        };
        assert!(!far.send(&t, request).await, "{target:?}");
    }
    assert!(r.table.opened.lock().unwrap().is_empty());
    assert_eq!(r.auth.calls.load(Ordering::SeqCst), 0);
    assert!(r.book.observed.lock().unwrap().is_empty());
}

/// An auth binding that must wait (a refresh that never comes back) is awaited no longer than the
/// attempt's cap: the attempt ends without a dial, nothing recorded against the member.
#[tokio::test]
async fn a_stalled_auth_call_is_bounded_by_the_attempt_cap() {
    let r = rig(
        &[("a.test", Script::Answer(200, None, vec![b"ok"]))],
        OnExhausted::Status503,
        Some(50),
    );
    r.auth.stall.store(true, Ordering::SeqCst);
    let t = token();
    let far = r.egress.unit(route());
    let _ = far.member(&t, 1).await;
    let started = std::time::Instant::now();
    let sent = tokio::time::timeout(std::time::Duration::from_secs(5), far.send(&t, request()))
        .await
        .expect("the auth wait is bounded");
    assert!(!sent);
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
    assert!(r.table.opened.lock().unwrap().is_empty());
    assert!(r.book.observed.lock().unwrap().is_empty());
}

/// A request whose auth fields cannot be assembled is never sent and records nothing against the
/// member: the binding's refusal is not the destination's fault (the push attempt's
/// could-not-be-assembled case, on the far end's one assembly step).
#[tokio::test]
async fn an_attempt_whose_auth_refuses_records_nothing_against_the_member() {
    let r = rig(
        &[("a.test", Script::Answer(200, None, vec![b"ok"]))],
        OnExhausted::Status503,
        None,
    );
    r.auth.refuse.store(true, Ordering::SeqCst);
    let t = token();
    let far = r.egress.unit(route());
    let _ = far.member(&t, 1).await;
    assert!(!far.send(&t, request()).await);
    assert_eq!(r.auth.calls.load(Ordering::SeqCst), 1, "the one auth call");
    assert!(r.table.opened.lock().unwrap().is_empty(), "nothing dialled");
    assert!(
        r.book.observed.lock().unwrap().is_empty(),
        "nothing recorded against the member"
    );
}

/// The head the framer encodes carries the auth values: it wipes them when it drops.
#[test]
fn the_head_wipes_its_auth_values() {
    let mut head = Head(vec![
        ("authorization".into(), b"Bearer sk-test".to_vec()),
        ("content-type".into(), b"application/json".to_vec()),
    ]);
    head.wipe();
    assert!(head.0.iter().all(|(_, v)| v.iter().all(|b| *b == 0)));
}

/// An auth field and a request print no credential.
#[test]
fn auth_material_never_prints() {
    let field = AuthField {
        name: b"authorization".to_vec(),
        value: b"Bearer sk-test".to_vec().into(),
        sensitive: true,
    };
    let request = FieldsRequest {
        caller_credential: Some(b"caller-key".to_vec().into()),
        ..FieldsRequest::default()
    };
    let printed = format!("{field:?} {request:?}");
    assert!(
        !printed.contains("sk-test") && !printed.contains("caller-key"),
        "{printed}"
    );
}

/// The far end's trailers are handed on, flagged as fields, never dropped: the plane decides.
#[tokio::test]
async fn trailers_are_handed_to_the_plane() {
    let r = rig(
        &[(
            "a.test",
            Script::Trailed(200, vec![b"ok"], b"far-status: 0"),
        )],
        OnExhausted::Status503,
        None,
    );
    let t = token();
    let far = r.egress.unit(route());
    let _ = far.member(&t, 1).await;
    assert!(far.send(&t, request()).await);
    let pieces = drain(&far, &t).await;
    let trailers: Vec<&FarPiece> = pieces.iter().filter(|p| p.fields).collect();
    assert_eq!(trailers.len(), 1, "{pieces:?}");
    assert_eq!(trailers[0].bytes, b"far-status: 0");
    assert!(pieces.last().unwrap().last);
}

/// THE PER-CALL SCOPE (ARCHITECT round 5 Q-L3B-EXCHANGE (B)): a plane's attempt that states its
/// scope in the host's own request field has that field taken out of the request before anything
/// is encoded (the far end never hears it) and its value lent to the member's ONE auth call in the
/// call's extensions blob; an attempt that states none lends none.
#[tokio::test]
async fn a_stated_scope_reaches_the_auth_call_and_never_the_wire() {
    use busbar_contract::abi::auth::{EXT_SCOPE, SCOPE_REQUEST_FIELD};
    use busbar_contract::abi::mechanism::extensions;
    let r = rig(
        &[("a.test", Script::Answer(200, None, vec![b"ok"]))],
        OnExhausted::Status503,
        None,
    );
    let t = token();
    for scope in [Some("fs_read_file fs_write_file"), None] {
        let far = r.egress.unit(route());
        let _ = far.member(&t, 1).await;
        let mut req = request();
        if let Some(scope) = scope {
            req.fields.push((
                SCOPE_REQUEST_FIELD.as_bytes().to_vec(),
                scope.as_bytes().to_vec(),
            ));
        }
        assert!(far.send(&t, req).await);
        let _ = drain(&far, &t).await;
    }
    let lent = r.auth.extensions.lock().unwrap().clone();
    assert_eq!(lent.len(), 2);
    assert_eq!(
        extensions::get(&lent[0], EXT_SCOPE),
        Some(&b"fs_read_file fs_write_file"[..])
    );
    assert!(lent[1].is_empty(), "no scope stated, no extensions lent");
    for (_, head, _, _) in r.table.opened.lock().unwrap().iter() {
        assert!(
            head.iter().all(|(n, _)| n != SCOPE_REQUEST_FIELD),
            "the host's field never reaches the wire: {head:?}"
        );
    }
}

/// PASSTHROUGH: a member configured `upstream_credentials: passthrough` has its one auth call carry
/// the caller's own credential; a member that is not is never handed it.
#[tokio::test]
async fn passthrough_hands_the_callers_credential_only_to_its_member() {
    // m0 is an own-credential member, m1 a passthrough one (the rig's binding for member 1).
    let r = rig(
        &[
            ("a.test", Script::Answer(503, None, vec![b"x"])),
            ("b.test", Script::Answer(200, None, vec![b"ok"])),
        ],
        OnExhausted::Status503,
        None,
    );
    let t = token();
    let far = r.egress.unit(UnitRoute {
        caller_credential: Some(b"caller-key".to_vec().into()),
        ..route()
    });
    let mut relays = Vec::new();
    for n in 1..=2 {
        let Pick::Member { passthrough, .. } = far.member(&t, n).await else {
            panic!("a member");
        };
        relays.push(passthrough);
        assert!(far.send(&t, request()).await);
        let _ = drain(&far, &t).await;
    }
    assert_eq!(
        *r.auth.callers.lock().unwrap(),
        vec![None, Some(b"caller-key".to_vec())]
    );
    // The pick says so, and the plane is told: only the passthrough member relays.
    assert_eq!(relays, vec![false, true]);
}

/// PASSTHROUGH THROUGH A POOL: a member its pool reaches with the caller's own credential (the
/// pool's `upstream_credentials: passthrough`) has its one auth call lent the caller's credential,
/// though its binding is its provider's own; and a caller who presented none lends an empty one, so
/// nothing is presented (never the operator's key), as 1.5.5's `present_caller` did.
#[tokio::test]
async fn a_passthrough_pool_member_is_lent_the_callers_credential_or_an_empty_one() {
    let mut r = rig(
        &[
            ("a.test", Script::Answer(200, None, vec![b"ok"])),
            ("b.test", Script::Answer(200, None, vec![b"ok"])),
        ],
        OnExhausted::Status503,
        None,
    );
    for member in &mut r.egress.pools.get_mut(POOL).unwrap().members {
        member.passthrough = true;
    }
    let t = token();
    for credential in [Some(b"caller-key".to_vec()), None] {
        let far = r.egress.unit(UnitRoute {
            caller_credential: credential.clone().map(Into::into),
            ..route()
        });
        let Pick::Member {
            name, passthrough, ..
        } = far.member(&t, 1).await
        else {
            panic!("a member");
        };
        assert!(passthrough, "{name}: the plane is told the member relays");
        assert!(far.send(&t, request()).await);
        let _ = drain(&far, &t).await;
    }
    let lent = r.auth.callers.lock().unwrap().clone();
    let presented: Vec<Option<Vec<u8>>> = lent.into_iter().collect();
    assert_eq!(
        presented,
        vec![Some(b"caller-key".to_vec()), Some(Vec::new())]
    );
}

/// AUTH POINTS: a member whose style signs the body (`HeadBody`) has its one auth call made at
/// `HeadBody` with the whole body, the bytes the framer sends; a member whose style is over the
/// head is called at `Head` and lent no body.
#[tokio::test]
async fn a_body_signing_style_is_called_at_head_body_with_the_whole_body() {
    // m0's style is over the head, m1's signs the body (the rig's binding for member 1).
    let r = rig(
        &[
            ("a.test", Script::Answer(503, None, vec![b"x"])),
            ("b.test", Script::Answer(200, None, vec![b"ok"])),
        ],
        OnExhausted::Status503,
        None,
    );
    let t = token();
    let far = r.egress.unit(route());
    for n in 1..=2 {
        let _ = far.member(&t, n).await;
        assert!(far.send(&t, request()).await);
        let _ = drain(&far, &t).await;
    }
    assert_eq!(
        *r.auth.points.lock().unwrap(),
        vec![
            (AuthPoint::Head, None),
            (AuthPoint::HeadBody, Some(request().body)),
        ]
    );
}

/// THE ERROR-BODY CAP (1.5.5's `limits.upstream_error_body_max_bytes`): a relayed failure's body is
/// handed to the plane up to the cap, the piece that overruns it is cut there and ends the answer,
/// and the connection closes; a success's body passes whole.
#[tokio::test]
async fn a_relayed_failures_body_is_capped_and_a_success_is_not() {
    let mut r = rig(
        &[(
            "a.test",
            Script::Answer(400, None, vec![b"0123", b"4567", b"89"]),
        )],
        OnExhausted::Status503,
        None,
    );
    r.egress.error_body_max = 6;
    let t = token();
    let far = r.egress.unit(route());
    let _ = far.member(&t, 1).await;
    assert!(far.send(&t, request()).await);
    let pieces = drain(&far, &t).await;
    let body: Vec<u8> = pieces.iter().flat_map(|p| p.bytes.clone()).collect();
    assert_eq!(body, b"012345", "cut at the cap");
    assert!(pieces.last().unwrap().last, "the cut ends the answer");
    assert_eq!(
        r.table.closed.load(Ordering::SeqCst),
        1,
        "its connection closed"
    );
    assert!(far.next(&t).await.is_none(), "nothing more is read");

    let mut r = rig(
        &[(
            "a.test",
            Script::Answer(200, None, vec![b"0123", b"4567", b"89"]),
        )],
        OnExhausted::Status503,
        None,
    );
    r.egress.error_body_max = 6;
    let far = r.egress.unit(route());
    let _ = far.member(&t, 1).await;
    assert!(far.send(&t, request()).await);
    let body: Vec<u8> = drain(&far, &t)
        .await
        .iter()
        .flat_map(|p| p.bytes.clone())
        .collect();
    assert_eq!(body, b"0123456789", "a success is never capped");
}

/// A context-length refusal excludes the pool's ADMISSIBLE members whose window is no larger, the
/// walk's own exclusion: a member the pool's blocklist keeps out is never part of it, and a larger
/// window stays in the walk.
#[tokio::test]
async fn a_context_length_refusal_excludes_only_admissible_smaller_windows() {
    let mut r = rig(
        &[
            ("a.test", Script::Answer(413, None, vec![b"too long"])),
            ("b.test", Script::Answer(200, None, vec![b"ok"])),
            ("c.test", Script::Answer(200, None, vec![b"ok"])),
        ],
        OnExhausted::Status503,
        None,
    );
    let pool = r.egress.pools.get_mut(POOL).expect("the pool");
    for (member, window) in pool.members.iter_mut().zip([8_000, 4_000, 16_000]) {
        member.context_max = Some(window);
    }
    pool.failover.exclusions = vec!["m1".into()];
    let t = token();
    let far = r.egress.unit(route());
    assert!(
        matches!(far.member(&t, 1).await, Pick::Member { ref name, .. } if name == "m0"),
        "the heaviest admissible member first"
    );
    assert!(far.send(&t, request()).await);
    assert!(far.next(&t).await.expect("a piece").fail_over);
    let w = far.lock();
    assert!(
        w.walk.ctx().is_excluded(DestinationId::new(1)),
        "the member that refused"
    );
    assert!(
        !w.walk.ctx().is_excluded(DestinationId::new(2)),
        "a blocklisted member is not the exclusion's to record"
    );
    assert!(
        !w.walk.ctx().is_excluded(DestinationId::new(3)),
        "a larger window stays in the walk"
    );
}

#[allow(unsafe_code)]
#[path = "probe_unit_tests.rs"]
mod probe_unit;

/// THE DISPATCH RECORD NAMES ITS UNIT (ARCHITECT P3 (c), 2026-10-02): the write-ahead record the walk
/// makes before each dial carries the unit the walk serves, so the root writes it under that unit's
/// facts on the book.
#[tokio::test]
async fn every_dispatch_is_recorded_under_its_unit() {
    let r = rig(
        &[("a.test", Script::Answer(200, None, vec![b"ok"]))],
        OnExhausted::Status503,
        None,
    );
    let t = token();
    let far = r.egress.unit(UnitRoute {
        unit: busbar_contract::UnitKey::new(77),
        ..route()
    });
    let _member = far.member(&t, 1).await;
    assert!(far.send(&t, request()).await);
    let kept = r.journal.0.lock().unwrap().clone();
    assert_eq!(kept.len(), 1, "one record, before the dial");
    assert_eq!(kept[0].unit, busbar_contract::UnitKey::new(77));
}

/// MULTI-NEED (ARCHITECT Q-L5B-NEEDS 2026-10-03): a member binds every need its auth names; a far
/// request that names one (its declared index plus one) opens on it, one that names none on the
/// member's own, and one naming a need the member has no binding for is refused before any record
/// or dial.
#[tokio::test]
async fn a_far_request_opens_on_the_need_it_names() {
    let mut r = rig(
        &[("a.test", Script::Answer(200, None, vec![b"ok"]))],
        OnExhausted::Status503,
        None,
    );
    for route in r.egress.routes.values_mut() {
        route.rides = vec![(NeedId(3), super::ResponseKeep::default())];
    }
    let t = token();
    for (named, opened) in [(4, Some(3)), (0, Some(0)), (1, Some(0)), (9, None)] {
        let far = r.egress.unit(route());
        assert!(matches!(far.member(&t, 1).await, Pick::Member { .. }));
        let before = r.table.needs.lock().unwrap().len();
        let sent = far
            .send(
                &t,
                OutboundRequest {
                    need: named,
                    ..request()
                },
            )
            .await;
        assert_eq!(sent, opened.is_some(), "named {named}");
        let needs = r.table.needs.lock().unwrap().clone();
        assert_eq!(needs.get(before).copied(), opened, "named {named}");
        drop(far);
    }
}

/// SEAM-L(n), A NEED DIALS THE BASE URL IT SPELLS: a member whose second need spells its base URL in
/// another scheme (the root composes `spelled` from the linked framers) opens a far request naming
/// that need at the spelled base, joined with the plane's path; a request on its own need dials the
/// operator's base URL as written. RED: every need dialled the provider's own base URL.
#[tokio::test]
async fn a_far_request_on_a_spelled_need_dials_that_needs_base_url() {
    let mut r = rig(
        &[("a.test", Script::Answer(200, None, vec![b"ok"]))],
        OnExhausted::Status503,
        None,
    );
    for route in r.egress.routes.values_mut() {
        route.rides = vec![(NeedId(3), super::ResponseKeep::default())];
        route.spelled = vec![(NeedId(3), "wss://a.test/v1/".to_string())];
    }
    let t = token();
    for (named, dialled) in [(4, "wss://a.test/v1/chat"), (0, "https://a.test/v1/chat")] {
        let far = r.egress.unit(route());
        assert!(matches!(far.member(&t, 1).await, Pick::Member { .. }));
        let before = r.table.opened.lock().unwrap().len();
        let sent = far
            .send(
                &t,
                OutboundRequest {
                    need: named,
                    ..request()
                },
            )
            .await;
        assert!(sent, "named {named}");
        let opened = r.table.opened.lock().unwrap().clone();
        assert_eq!(opened[before].0, dialled, "named {named}");
        drop(far);
    }
}

/// A HELD FAR END (ARCHITECT Q-L5-FAR (A)): once the attempt's far end has answered, a later
/// turn's frame is written into the SAME connection as one whole message, never a second open; a
/// frame before the answer, or after the answer ended, is refused (nothing holds it).
#[tokio::test]
async fn a_held_far_ends_frame_goes_into_the_answered_connection() {
    let r = rig(
        &[("a.test", Script::Answer(200, None, vec![b"hel", b"lo"]))],
        OnExhausted::Status503,
        None,
    );
    let t = token();
    let far = r.egress.unit(route());
    let frame = |body: &[u8]| OutboundRequest {
        body: body.to_vec(),
        ..request()
    };
    assert!(
        !far.write(&t, frame(b"early")).await,
        "nothing is held before a dial"
    );
    assert!(matches!(far.member(&t, 1).await, Pick::Member { .. }));
    assert!(far.send(&t, request()).await);
    assert!(
        !far.write(&t, frame(b"unanswered")).await,
        "a dial its far end has not answered holds nothing"
    );
    let first = far.next(&t).await.expect("the answer's first piece");
    assert_eq!(first.status, Some((200, 1)));
    assert!(far.write(&t, frame(b"two")).await);
    assert_eq!(
        *r.table.written.lock().unwrap(),
        vec![(1, b"two".to_vec(), true)],
        "into the answered connection, as one message"
    );
    assert_eq!(
        r.table.opened.lock().unwrap().len(),
        1,
        "never a second open"
    );
    let rest = drain(&far, &t).await;
    assert!(rest.last().is_some_and(|p| p.last));
    assert!(
        !far.write(&t, frame(b"late")).await,
        "an ended answer holds nothing"
    );
    assert_eq!(r.table.written.lock().unwrap().len(), 1);
}

/// Q-L5B-WS-DIAL: a far request the plane marked text opens its connection bare (no opening body,
/// which carries no text bit) and is written to it as ONE text message; an unmarked one rides its
/// opening as before and writes nothing.
#[tokio::test]
async fn a_text_request_opens_bare_and_is_written_as_text() {
    let r = rig(
        &[("a.test", Script::Answer(200, None, vec![b"ok"]))],
        OnExhausted::Status503,
        None,
    );
    let t = token();
    let far = r.egress.unit(route());
    assert!(matches!(far.member(&t, 1).await, Pick::Member { .. }));
    let sent = far
        .send(
            &t,
            OutboundRequest {
                text: true,
                ..request()
            },
        )
        .await;
    assert!(sent);
    let opened = r.table.opened.lock().unwrap().clone();
    assert!(opened[0].2.is_empty(), "the opening carries no body");
    assert_eq!(
        r.table.written.lock().unwrap().clone(),
        [(1, b"{}".to_vec(), true)],
        "the body is written, whole"
    );
    assert_eq!(r.table.texts.lock().unwrap().clone(), [true]);
    drop(far);

    let far = r.egress.unit(route());
    assert!(matches!(far.member(&t, 1).await, Pick::Member { .. }));
    assert!(far.send(&t, request()).await);
    assert_eq!(r.table.opened.lock().unwrap()[1].2, b"{}");
    assert_eq!(
        r.table.written.lock().unwrap().len(),
        1,
        "no write of its own"
    );
}
