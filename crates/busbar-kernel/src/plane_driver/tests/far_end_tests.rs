// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use busbar_contract::abi::transport::{
    FAULT_CALLER, FAULT_HARD, FAULT_HEALTHY, FAULT_NONE, FAULT_TRANSIENT,
};
use busbar_contract::auth_calls::{AuthField, Fielding, Fields, FieldsRequest, OutboundAuth};
use busbar_contract::caps::{Pass, Route};
use busbar_contract::conn::{
    ConnError, ConnId, Conns, HeadDefaults, InstanceId, NeedId, OpenDesc, Piece, PieceKind,
    PollConns, Ticket,
};
use busbar_contract::ids::StreamId;
use busbar_contract::transport::wire::{WireFault, WireStatusClass};
use busbar_contract::transport::ConnFacts;
use busbar_kernel_egress::{
    ports::{
        Admit, BoxFut, Breaker, Capacity, Classified, Clock, DestinationId, Dispatched,
        Disposition, DurabilityUnavailable, Journal, Outcome, Permit, PermitHandle, Telemetry,
        Unavailable, UpstreamStatus,
    },
    Failover, Member, OnExhausted, Pool,
};

use super::*;
use crate::plane_driver::{FarEnd, OutboundRequest, Pick};

/// What a scripted far end answers: its status and body pieces, or nothing at all.
#[derive(Clone)]
enum Script {
    Answer(u32, Option<u64>, Vec<&'static [u8]>),
    /// An answer whose body is followed by the far end's trailers.
    Trailed(u32, Vec<&'static [u8]>, &'static [u8]),
    /// An answer whose connection fails after its body's pieces, before it completes.
    Broken(u32, Vec<&'static [u8]>),
    /// A far end that states its answer's status at the END (`STATUS_AT_TERMINAL`): a head with
    /// no status, its messages, then its trailers carrying the status (its number, its class and
    /// the transport's fault reading of it); a success then completes, any other status then FAILS
    /// the stream, as such a transport reports a non-success end.
    Ended(u32, WireStatusClass, Option<WireFault>, Vec<&'static [u8]>),
    Silent,
    Refused,
    /// The open answers this error, after the dial was asked for.
    OpenFails(ConnError),
}

type Opened = (String, Vec<(String, Vec<u8>)>, Vec<u8>, u64);

type Words = (Vec<u8>, Vec<u8>);

type Facts = (Vec<u8>, String, Vec<u8>);

type Lines = Vec<(Vec<u8>, Vec<u8>)>;

/// A connection table whose far ends answer from `scripts`, by the target's host.
#[derive(Default)]
struct Table {
    scripts: HashMap<&'static str, Script>,
    opened: Mutex<Vec<Opened>>,
    /// What each open's host sealed-fields field named (`conn::SEALED_FIELDS_FIELD`), taken out of
    /// its head as the connector takes it out.
    sealed: Mutex<Vec<Option<Vec<u8>>>>,
    /// The address set every open was pinned to (`OpenDesc::within`).
    withins: Mutex<Vec<Vec<std::net::IpAddr>>>,
    words: Mutex<Vec<Words>>,
    live: Mutex<HashMap<u64, VecDeque<Piece>>>,
    bytes: Mutex<HashMap<u64, VecDeque<Vec<u8>>>>,
    next: AtomicU64,
    closed: AtomicU64,
    on_close: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    /// The need every open was made on.
    needs: Mutex<Vec<u32>>,
    /// Whether each write was a text message.
    texts: Mutex<Vec<bool>>,
    /// Every write: the connection, the bytes, and whether they completed the caller's message.
    written: Mutex<Vec<(u64, Vec<u8>, bool)>>,
    /// The connections whose read fails once their scripted pieces are spent.
    broken: Mutex<std::collections::HashSet<u64>>,
    /// The connections whose stream FAILS once their scripted pieces are read.
    failing: Mutex<Vec<u64>>,
    /// The head lines the framer states for every target (`PollConns::head_defaults`).
    defaults: Mutex<Vec<(Vec<u8>, Vec<u8>)>>,
    /// Whether the framer's head states the body's length (`HeadDefaults::states_length`).
    states_length: std::sync::atomic::AtomicBool,
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

        fault: status.and_then(|(c, _)| match c {
            401 | 403 => Some(WireFault::Hard),
            408 | 429 | 500..=599 => Some(WireFault::Transient),
            400..=499 => Some(WireFault::Caller),
            _ => None,
        }),
        reason: None,
        declared_len: None,
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
        self.sealed.lock().unwrap().push(
            d.fields
                .iter()
                .find(|(n, _)| busbar_contract::conn::is_sealed_fields_field(n.as_bytes()))
                .map(|(_, v)| v.to_vec()),
        );
        self.withins.lock().unwrap().push(d.within.to_vec());
        self.opened.lock().unwrap().push((
            d.target.to_string(),
            d.fields
                .iter()
                .filter(|(n, _)| !busbar_contract::conn::is_sealed_fields_field(n.as_bytes()))
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
            Script::OpenFails(err) => return Err(err),
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
            Script::Ended(code, class, fault, messages) => {
                let mut pieces = VecDeque::new();
                let mut bytes = VecDeque::new();
                pieces.push_back(piece(PieceKind::Fields, 0, None));
                bytes.push_back(Vec::new());
                for m in &messages {
                    pieces.push_back(piece(PieceKind::Body, m.len(), None));
                    bytes.push_back(m.to_vec());
                }
                let trailers = b"far-detail: 1";
                pieces.push_back(Piece {
                    status: Some(class),
                    status_code: Some(code),
                    fault,
                    ..piece(PieceKind::Fields, trailers.len(), None)
                });
                bytes.push_back(trailers.to_vec());
                if class == WireStatusClass::Success {
                    pieces.push_back(piece(PieceKind::Completion, 0, None));
                    bytes.push_back(Vec::new());
                } else {
                    self.failing.lock().unwrap().push(id);
                }
                (pieces, bytes)
            }
            Script::Broken(status, chunks) => {
                self.broken.lock().unwrap().insert(id);
                let mut pieces = VecDeque::new();
                let mut bytes = VecDeque::new();
                for (k, chunk) in chunks.iter().enumerate() {
                    let s = (k == 0).then_some((status, None));
                    pieces.push_back(piece(PieceKind::Body, chunk.len(), s));
                    bytes.push_back(chunk.to_vec());
                }
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
        let callback = self.on_close.lock().unwrap().clone();
        if let Some(callback) = callback {
            callback();
        }
        Ok(())
    }
}

impl PollConns for Table {
    fn head_defaults(&self, _: InstanceId, _: NeedId, _: &str) -> HeadDefaults {
        HeadDefaults {
            lines: self.defaults.lock().unwrap().clone(),
            states_length: self.states_length.load(std::sync::atomic::Ordering::SeqCst),
        }
    }

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
            let mut failing = self.failing.lock().unwrap();
            if let Some(at) = failing.iter().position(|c| *c == conn.0) {
                failing.remove(at);
                return Poll::Ready(Err(ConnError::Fault));
            }

            if self.broken.lock().unwrap().contains(&conn.0) {
                return Poll::Ready(Err(ConnError::Refused));
            }
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

/// A breaker that classifies by the transport's fault reading and records every outcome it is told.
#[derive(Default)]
struct Book {
    /// The members whose caller-fault answer the plane read as a request too large for the
    /// window: the fixture's stand-in for the plane's context-length verdict.
    too_long: Mutex<Vec<DestinationId>>,
    observed: Mutex<Vec<(DestinationId, Outcome)>>,
    /// Every health probe's answer, as the far end told it; a success ends a cooldown.
    probed: Mutex<Vec<(DestinationId, Outcome)>>,
    cooldown: Mutex<HashMap<DestinationId, u64>>,
    spent: AtomicU64,
    refunded: AtomicU64,
    on_refund: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

impl Breaker for Book {
    fn try_admit(&self, _: &str, d: DestinationId, _: u64) -> Result<Admit, Unavailable> {
        match self.cooldown.lock().unwrap().get(&d) {
            Some(until) => Err(Unavailable::BreakerOpen { until: *until }),
            None => Ok(Admit { probe_epoch: None }),
        }
    }
    fn unavailable(
        &self,
        pool: &str,
        destination: DestinationId,
        now: u64,
        token: &Pass<Route>,
    ) -> Option<Unavailable> {
        let _ = (pool, now, token);
        self.cooldown
            .lock()
            .unwrap()
            .get(&destination)
            .copied()
            .map(|until| Unavailable::BreakerOpen { until })
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
    fn classify(&self, d: DestinationId, s: UpstreamStatus) -> Classified {
        let too_long = self.too_long.lock().unwrap().contains(&d);
        let (disposition, outcome, label) = match s.fault {
            Some(WireFault::Hard) => (Disposition::HardDown, Outcome::HardDown, "hard_down"),
            Some(WireFault::Caller) if too_long => (
                Disposition::ContextLength,
                Outcome::RecordNothing,
                "context_length",
            ),
            Some(WireFault::Transient) => (
                Disposition::TransientUpstream,
                Outcome::Transient {
                    retry_after: s.retry_after,
                },
                "transient",
            ),
            Some(WireFault::Caller) | None => (
                Disposition::ClientFault,
                Outcome::RecordNothing,
                "client_fault",
            ),
            Some(WireFault::Healthy) => (Disposition::ClientFault, Outcome::Success, "healthy"),
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
        let callback = self.on_refund.lock().unwrap().clone();
        if let Some(callback) = callback {
            callback();
        }
    }
}

#[allow(unsafe_code)]
#[path = "retirement_tests.rs"]
mod retirement_tests;

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
    require_secure: std::sync::atomic::AtomicBool,
    query: std::sync::atomic::AtomicBool,
    /// Refuses to field the attempt.
    refuse: std::sync::atomic::AtomicBool,
    facts: Mutex<Vec<Facts>>,
    /// The point each call was made at and the body it lent.
    points: Mutex<Vec<(AuthPoint, Option<Vec<u8>>)>>,
    /// The extensions blob each call lent.
    extensions: Mutex<Vec<Vec<u8>>>,
    /// The head each call was handed to sign (`FieldsRequest::headers`).
    heads: Mutex<Vec<Lines>>,
}
struct Done(Fields);

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
                .map(|c| c.expose(&crate::seal::lend()).clone()),
        );
        self.facts
            .lock()
            .unwrap()
            .push((r.method.clone(), r.authority.clone(), r.path.clone()));
        self.points.lock().unwrap().push((r.point, r.body.clone()));
        self.extensions.lock().unwrap().push(r.extensions.clone());
        self.heads.lock().unwrap().push(r.headers.clone());
        Some(Fields::Ready(vec![AuthField {
            name: b"authorization".to_vec(),
            value: b"Bearer sk-test".to_vec().into(),
            sensitive: true,
            query: self.query.load(Ordering::SeqCst),
            require_secure: self.require_secure.load(Ordering::SeqCst),
        }]))
    }
    fn fields(&self, h: u64, r: FieldsRequest, _: u64) -> Box<dyn Fielding> {
        if self.stall.load(Ordering::SeqCst) {
            return Box::new(Never);
        }
        Box::new(Done(self.fields_now(h, &r).unwrap_or(Fields::Failed)))
    }
}

const POOL: &str = "p";

struct Rig {
    table: Arc<Table>,
    book: Arc<Book>,
    auth: Arc<Bearer>,
    journal: Arc<Kept>,
    egress: Egress,
}

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

                        style_flags: busbar_contract::abi::auth::STYLE_NEEDS_HEADERS,

                        points: if k == 1 {
                            AuthPoints::HEAD_BODY
                        } else {
                            AuthPoints::HEAD
                        },
                        passthrough: k == 1,
                        per_request: None,
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
        floor: Default::default(),
    };
    let egress = Egress {
        caller: InstanceId(9),
        conns: table.clone(),
        breaker: crate::plane_driver::fixed_breaker(book.clone()),
        capacity: Arc::new(Free),
        clock: Arc::new(Wall),
        journal: Arc::clone(&journal) as Arc<dyn Journal>,
        telemetry: Arc::new(Quiet),
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

async fn drain(far: &EgressFarEnd<'_>, t: &Pass<Route>) -> Vec<FarPiece> {
    let mut out = Vec::new();
    while let Some(p) = far.next(t).await {
        far.judged(t, FAULT_NONE);
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

async fn read_out(far: &EgressFarEnd<'_>, t: &Pass<Route>) {
    loop {
        let p = far.next(t).await.expect("a piece through the last");
        far.judged(t, FAULT_NONE);
        if p.last {
            return;
        }
    }
}

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

#[tokio::test]
async fn every_read_is_lent_the_units_one_buffer() {
    let r = rig(
        &[(
            "a.test",
            Script::Answer(200, None, vec![b"hel", b"lo", b"!"]),
        )],
        OnExhausted::Status503,
        None,
    );
    let t = token();
    let far = r.egress.unit(route());
    assert!(
        far.scratch.lock().unwrap().is_empty(),
        "no buffer before the first read"
    );
    assert!(matches!(far.member(&t, 1).await, Pick::Member { .. }));
    assert!(far.send(&t, request()).await);
    let mut held: Option<*const u8> = None;
    let mut body = Vec::new();
    loop {
        let p = far.next(&t).await.expect("a piece through the last");
        far.judged(&t, FAULT_NONE);
        let at = {
            let buf = far.scratch.lock().unwrap();
            assert_eq!(
                buf.len(),
                READ_BYTES,
                "the buffer is back with the far end after the read"
            );
            buf.as_ptr()
        };
        assert_eq!(
            *held.get_or_insert(at),
            at,
            "the same buffer, read after read"
        );
        assert_eq!(
            p.bytes.capacity(),
            p.bytes.len(),
            "a piece is a copy of its own length, never the read buffer"
        );
        body.extend_from_slice(&p.bytes);
        if p.last {
            break;
        }
    }
    assert_eq!(body, b"hello!");
}

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

    far.judged(&t, FAULT_NONE);
    assert!(
        r.book.observed.lock().unwrap().is_empty(),
        "the plane's reading is awaited"
    );
    read_out(&far, &t).await;
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

#[tokio::test]
async fn the_least_bad_terminals_answer_is_relayed_and_an_ordinary_attempts_is_not() {
    let r = rig(
        &[("a.test", Script::Answer(503, None, vec![b"down"]))],
        OnExhausted::LeastBad,
        None,
    );
    let t = token();
    let far = r.egress.unit(route());
    assert!(matches!(far.member(&t, 1).await, Pick::Member { .. }));
    assert!(far.send(&t, request()).await);
    let first = far.next(&t).await.expect("a piece");
    assert!(
        first.fail_over,
        "the walk's own attempt fails over: {first:?}"
    );
    assert!(!first.relayed);
    assert!(
        matches!(far.member(&t, 2).await, Pick::Member { .. }),
        "the least-bad terminal takes the member again"
    );
    assert!(far.send(&t, request()).await);
    let relayed = far.next(&t).await.expect("a piece");
    assert!(!relayed.fail_over, "{relayed:?}");
    assert!(
        relayed.relayed,
        "the terminal's answer is the unit's: {relayed:?}"
    );
    assert_eq!(relayed.status.map(|(s, _)| s), Some(503));
    assert_eq!(relayed.bytes, b"down");
}

#[tokio::test]
async fn a_passthrough_members_401_records_nothing_and_is_relayed() {
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

    far.judged(&t, FAULT_NONE);
    read_out(&far, &t).await;
    assert_eq!(
        *r.book.observed.lock().unwrap(),
        vec![(DestinationId::new(1), Outcome::RecordNothing)]
    );
}

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
            retry_after: Some(2),
            detail: busbar_kernel_egress::wire::DETAIL_OVERLOADED,
        }
    );

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
            retry_after: Some(9),
            detail: busbar_kernel_egress::wire::DETAIL_OVERLOADED,
        }
    );
}

#[tokio::test]
async fn the_attempt_cap_and_a_refused_dial_fail_over() {
    let r = rig(
        &[("a.test", Script::Silent), ("b.test", Script::Refused)],
        OnExhausted::Status503,
        Some(50),
    );
    let t = token();
    let far = r.egress.unit(route());
    let mut members = Vec::new();
    for n in 1..=2 {
        let Pick::Member { name, .. } = far.member(&t, n).await else {
            panic!("a member")
        };
        let sent = far.send(&t, request()).await;
        match name.as_str() {
            "m0" => {
                assert!(
                    sent,
                    "the silent connection opens before its answer times out"
                );
                let p = far.next(&t).await.expect("the attempt-cap refusal");
                assert!(p.fail_over, "{p:?}");
            }
            "m1" => assert!(!sent, "the refused dial sends nothing"),
            _ => panic!("unexpected member {name}"),
        }
        members.push(name);
    }
    members.sort();
    assert_eq!(members, ["m0", "m1"]);
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

#[tokio::test]
async fn hop_by_hop_host_and_length_are_re_derived() {
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
        ("connection", "keep-alive, x-nominated"),
        ("x-nominated", "1"),
        ("keep-alive", "timeout=5"),
        ("te", "trailers"),
        ("upgrade", "websocket"),
        ("proxy-authorization", "Basic Zm9v"),
        ("host", "client.example"),
        ("content-length", "9999"),
        ("x-client-trace", "abc"),
    ] {
        req.fields
            .push((n.as_bytes().to_vec(), v.as_bytes().to_vec()));
    }
    assert!(far.send(&t, req).await);
    let _ = drain(&far, &t).await;
    let opened = r.table.opened.lock().unwrap().clone();
    assert_eq!(opened.len(), 1);
    let (target, fields, _, _) = &opened[0];
    for gone in [
        "connection",
        "x-nominated",
        "keep-alive",
        "te",
        "upgrade",
        "proxy-authorization",
        "host",
        "content-length",
    ] {
        assert!(
            !fields.iter().any(|(n, _)| n.eq_ignore_ascii_case(gone)),
            "{gone} is per-connection: {fields:?}"
        );
    }
    assert!(
        !fields
            .iter()
            .any(|(_, v)| v.as_slice() == b"client.example"),
        "the caller's host never goes upstream"
    );
    assert!(
        !fields.iter().any(|(_, v)| v.as_slice() == b"9999"),
        "the caller's length never goes upstream"
    );
    assert_eq!(
        target, "https://a.test/v1/chat",
        "the connection dials the member's own host"
    );
    let head: Vec<(&str, &[u8])> = fields
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

/// The pool labels the walk's telemetry was handed, attempt by attempt.
#[derive(Default)]
struct Labels(Mutex<Vec<(String, DestinationId)>>);
impl Telemetry for Labels {
    fn upstream_attempt(&self, pool: &str, d: DestinationId) {
        self.0.lock().unwrap().push((pool.to_string(), d));
    }
    fn upstream_failure(&self, _: &str, _: DestinationId, _: &'static str) {}
    fn failover(&self, _: &str, _: &'static str) {}
    fn breaker_trip(&self, _: &str, _: DestinationId) {}
    fn queued(&self, _: &str, _: i64) {}
}

#[tokio::test]
async fn test_metric_pool_label_resolves_model_for_default_cell() {
    let mut r = rig(
        &[
            ("a.test", Script::Answer(200, None, vec![b"ok"])),
            ("b.test", Script::Answer(200, None, vec![b"ok"])),
        ],
        OnExhausted::Status503,
        None,
    );
    let labels = Arc::new(Labels::default());
    r.egress.telemetry = Arc::clone(&labels) as Arc<dyn Telemetry>;
    let t = token();
    let direct = || UnitRoute {
        pool: String::new(),
        ..UnitRoute::default()
    };

    r.egress.pools.insert(
        String::new(),
        Pool::new(
            String::new(),
            vec![Member::new(DestinationId::new(1), "claude-sonnet", 1)],
        ),
    );
    {
        let far = r.egress.unit(direct());
        assert!(matches!(far.member(&t, 1).await, Pick::Member { .. }));
        assert!(far.send(&t, request()).await);
        let _ = drain(&far, &t).await;
    }

    r.egress.pools.insert(
        String::new(),
        Pool::new(
            String::new(),
            vec![Member::new(DestinationId::new(2), "gpt-4o", 1)],
        ),
    );
    {
        let far = r.egress.unit(direct());
        assert!(matches!(far.member(&t, 1).await, Pick::Member { .. }));
        assert!(far.send(&t, request()).await);
        let _ = drain(&far, &t).await;
    }

    r.egress.pools.insert(
        "prod-pool".to_string(),
        Pool::new(
            "prod-pool",
            vec![Member::new(DestinationId::new(1), "claude-sonnet", 1)],
        ),
    );
    {
        let far = r.egress.unit(UnitRoute {
            pool: "prod-pool".into(),
            ..UnitRoute::default()
        });
        assert!(matches!(far.member(&t, 1).await, Pick::Member { .. }));
        assert!(far.send(&t, request()).await);
        let _ = drain(&far, &t).await;
    }
    assert_eq!(
        labels.0.lock().unwrap().clone(),
        vec![
            ("claude-sonnet".to_string(), DestinationId::new(1)),
            ("gpt-4o".to_string(), DestinationId::new(2)),
            ("prod-pool".to_string(), DestinationId::new(1)),
        ]
    );
}

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

#[tokio::test]
async fn a_plane_field_name_that_is_not_a_token_is_refused_before_the_dial() {
    let r = rig(
        &[("a.test", Script::Answer(200, None, vec![b"ok"]))],
        OnExhausted::Status503,
        None,
    );
    let t = token();
    for name in ["authorization:x", "a b", ""] {
        let far = r.egress.unit(route());
        let _ = far.member(&t, 1).await;
        let mut req = request();
        req.fields.push((name.as_bytes().to_vec(), b"v".to_vec()));
        assert!(!far.send(&t, req).await, "{name:?}");
    }
    assert!(
        r.table.opened.lock().unwrap().is_empty(),
        "no head with a second authorization reached the wire"
    );
    assert_eq!(r.auth.calls.load(Ordering::SeqCst), 0);
    assert!(r.book.observed.lock().unwrap().is_empty());
}

#[tokio::test]
async fn test_host_from_base_backslash_authority_matches_wire_host() {
    for (base, script_host, authority, host, port, head_path) in [
        (
            "https://evil.example.com\\@victim.example/path",
            "evil.example.com",
            "evil.example.com",
            "evil.example.com",
            None,
            "/@victim.example/path/chat",
        ),
        (
            "https://host.example.com\\some\\path",
            "host.example.com",
            "host.example.com",
            "host.example.com",
            None,
            "/some/path/chat",
        ),
        (
            "https://host.example.com:8443\\v1\\foo",
            "host.example.com:8443",
            "host.example.com:8443",
            "host.example.com",
            Some(8443),
            "/v1/foo/chat",
        ),
    ] {
        let mut r = rig(
            &[(script_host, Script::Answer(200, None, vec![b"ok"]))],
            OnExhausted::Status503,
            None,
        );
        r.egress
            .routes
            .get_mut(&DestinationId::new(1))
            .expect("m0's route")
            .base_url = base.to_string();
        let t = token();
        let far = r.egress.unit(route());
        assert!(matches!(far.member(&t, 1).await, Pick::Member { .. }));
        assert!(far.send(&t, request()).await, "{base}");
        let pieces = drain(&far, &t).await;
        assert_eq!(pieces[0].status, Some((200, 1)), "{base}");
        drop(far);

        let signed = r.auth.facts.lock().unwrap()[0].1.clone();
        assert_eq!(signed, authority, "{base}: the signed host");
        let opened = r.table.opened.lock().unwrap().clone();
        assert_eq!(opened.len(), 1, "{base}");
        let dialled =
            busbar_contract::net::parse_url(&opened[0].0).unwrap_or_else(|e| panic!("{base}: {e}"));
        assert_eq!(
            (dialled.host.as_str(), dialled.port),
            (host, port),
            "{base}: the dialled host"
        );
        let dialled_authority = match dialled.port {
            Some(p) => format!("{}:{p}", dialled.host),
            None => dialled.host.clone(),
        };
        assert_eq!(
            signed, dialled_authority,
            "{base}: the signed host is the dialled host"
        );
        assert_eq!(
            r.table.words.lock().unwrap()[0],
            (b"POST".to_vec(), head_path.as_bytes().to_vec()),
            "{base}: the head's path"
        );
        assert_eq!(
            r.auth.facts.lock().unwrap()[0].2,
            head_path.as_bytes().to_vec(),
            "{base}: the signed path is the head's path"
        );
    }
}

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

#[tokio::test]
async fn a_dial_whose_auth_refuses_or_fails_records_nothing_against_the_destination() {
    for err in [ConnError::AuthRefused, ConnError::AuthFailed] {
        let r = rig(
            &[("a.test", Script::OpenFails(err))],
            OnExhausted::Status503,
            None,
        );
        let t = token();
        let far = r.egress.unit(route());
        let _ = far.member(&t, 1).await;
        assert!(!far.send(&t, request()).await, "{err:?}: nothing was sent");
        assert_eq!(
            r.table.opened.lock().unwrap().len(),
            1,
            "{err:?}: the dial was asked"
        );
        assert!(
            r.book.observed.lock().unwrap().is_empty(),
            "{err:?}: nothing recorded against the destination"
        );
    }
    let r = rig(
        &[("a.test", Script::OpenFails(ConnError::Refused))],
        OnExhausted::Status503,
        None,
    );
    let t = token();
    let far = r.egress.unit(route());
    let _ = far.member(&t, 1).await;
    assert!(!far.send(&t, request()).await);
    assert!(
        !r.book.observed.lock().unwrap().is_empty(),
        "the far end's refusal is recorded against it"
    );
}

#[test]
fn the_head_wipes_its_auth_values() {
    let mut head = Head(vec![
        ("authorization".into(), b"Bearer sk-test".to_vec()),
        ("content-type".into(), b"application/json".to_vec()),
    ]);
    head.wipe();
    assert!(head.0.iter().all(|(_, v)| v.iter().all(|b| *b == 0)));
}

#[test]
fn auth_material_never_prints() {
    let field = AuthField {
        name: b"authorization".to_vec(),
        value: b"Bearer sk-test".to_vec().into(),
        sensitive: true,
        query: false,
        require_secure: false,
    };
    let request = FieldsRequest {
        caller_credential: Some(b"caller-key".to_vec().into()),
        body: Default::default(),
        method: Default::default(),
        authority: Default::default(),
        path: Default::default(),
        query: Default::default(),
        headers: Default::default(),
        extensions: Default::default(),
        ..FieldsRequest::default()
    };
    let printed = format!("{field:?} {request:?}");
    assert!(
        !printed.contains("sk-test") && !printed.contains("caller-key"),
        "{printed}"
    );
}

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

#[tokio::test]
async fn a_status_stated_in_the_trailers_is_the_answer_never_a_cut() {
    use busbar_contract::abi::transport::{STATUS_CALLER_FAULT, STATUS_SUCCESS};
    let r = rig(
        &[(
            "a.test",
            Script::Ended(
                5,
                WireStatusClass::CallerFault,
                Some(WireFault::Caller),
                vec![],
            ),
        )],
        OnExhausted::Status503,
        None,
    );
    let t = token();
    let far = r.egress.unit(route());
    let _ = far.member(&t, 1).await;
    assert!(far.send(&t, request()).await);
    let pieces = drain(&far, &t).await;
    assert!(pieces.iter().all(|p| !p.fail_over), "{pieces:?}");
    assert_eq!(pieces[0].status, Some((0, u32::from(STATUS_SUCCESS))));
    let end = pieces.last().expect("the trailers");
    assert!(end.fields && end.last, "{pieces:?}");
    assert_eq!(end.bytes, b"far-detail: 1");
    assert_eq!(end.status, Some((5, u32::from(STATUS_CALLER_FAULT))));
    assert!(far.next(&t).await.is_none(), "nothing is read past the end");
    let observed = r.book.observed.lock().unwrap().clone();
    assert!(
        !observed
            .iter()
            .any(|(_, o)| matches!(o, Outcome::Transient { .. })),
        "no transient against the member: {observed:?}"
    );
    assert_eq!(observed[0], (DestinationId::new(1), Outcome::Success));
    assert_eq!(
        r.book.refunded.load(Ordering::SeqCst),
        0,
        "an answer, not a cut"
    );
    assert_eq!(r.table.opened.lock().unwrap().len(), 1, "never failed over");
    drop(far);
    assert_eq!(r.table.closed.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_non_success_end_stated_in_the_trailers_keeps_the_budget_unit_its_head_spent() {
    for (code, class, fault) in [
        (5, WireStatusClass::CallerFault, WireFault::Caller),
        (14, WireStatusClass::FarEndFault, WireFault::Transient),
    ] {
        for read in [true, false] {
            let r = rig(
                &[(
                    "a.test",
                    Script::Ended(code, class, Some(fault), vec![b"msg"]),
                )],
                OnExhausted::Status503,
                None,
            );
            let t = token();
            let far = r.egress.unit(route());
            let _ = far.member(&t, 1).await;
            assert!(far.send(&t, request()).await);
            loop {
                let p = far.next(&t).await.expect("a piece through the last");
                if read || !p.last {
                    far.judged(&t, FAULT_NONE);
                }
                if p.last {
                    break;
                }
            }
            drop(far);
            assert_eq!(r.book.spent.load(Ordering::SeqCst), 1, "{code} read={read}");
            assert_eq!(
                r.book.refunded.load(Ordering::SeqCst),
                0,
                "{code} read={read}: the unit is kept"
            );
        }
    }
}

#[tokio::test]
async fn the_trailers_status_is_judged_plane_first_and_a_success_ends_as_it_ends() {
    use busbar_contract::abi::transport::STATUS_SUCCESS;
    let ended = |code, class, fault| {
        rig(
            &[("a.test", Script::Ended(code, class, fault, vec![b"msg"]))],
            OnExhausted::Status503,
            None,
        )
    };

    let r = ended(5, WireStatusClass::CallerFault, Some(WireFault::Caller));
    let t = token();
    let far = r.egress.unit(route());
    let _ = far.member(&t, 1).await;
    assert!(far.send(&t, request()).await);
    loop {
        let p = far.next(&t).await.expect("a piece through the last");
        far.judged(&t, if p.fields { FAULT_HEALTHY } else { FAULT_NONE });
        if p.last {
            break;
        }
    }
    assert_eq!(
        *r.book.observed.lock().unwrap(),
        vec![(DestinationId::new(1), Outcome::Success)],
        "one answer, one success"
    );
    drop(far);

    let r = ended(14, WireStatusClass::FarEndFault, Some(WireFault::Transient));
    let far = r.egress.unit(route());
    let _ = far.member(&t, 1).await;
    assert!(far.send(&t, request()).await);
    let pieces = drain(&far, &t).await;
    assert!(pieces.iter().all(|p| !p.fail_over), "{pieces:?}");
    assert!(pieces.last().is_some_and(|p| p.fields && p.last));
    assert_eq!(
        *r.book.observed.lock().unwrap(),
        vec![
            (DestinationId::new(1), Outcome::Success),
            (
                DestinationId::new(1),
                Outcome::Transient { retry_after: None }
            ),
        ]
    );
    assert_eq!(r.table.opened.lock().unwrap().len(), 1, "never failed over");
    drop(far);

    let r = ended(0, WireStatusClass::Success, None);
    let far = r.egress.unit(route());
    let _ = far.member(&t, 1).await;
    assert!(far.send(&t, request()).await);
    let pieces = drain(&far, &t).await;
    let trailers: Vec<&FarPiece> = pieces.iter().filter(|p| p.fields).collect();
    assert_eq!(trailers.len(), 1, "{pieces:?}");
    assert_eq!(trailers[0].status, Some((0, u32::from(STATUS_SUCCESS))));
    assert!(!trailers[0].last, "a success's end is its completion");
    assert!(pieces.last().is_some_and(|p| p.last && !p.fields));
    assert_eq!(
        *r.book.observed.lock().unwrap(),
        vec![(DestinationId::new(1), Outcome::Success)]
    );
}

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

#[tokio::test]
async fn passthrough_hands_the_callers_credential_only_to_its_member() {
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

    assert_eq!(relays, vec![false, true]);
}

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

#[tokio::test]
async fn a_body_signing_style_is_called_at_head_body_with_the_whole_body() {
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

    r.book.too_long.lock().unwrap().push(DestinationId::new(1));
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

#[tokio::test]
async fn the_hooks_constraint_orders_and_restricts_the_pick() {
    use crate::plane_driver::{Constraint, MemberFacts};
    let r = rig(
        &[
            ("a.test", Script::Answer(200, None, vec![b"ok"])),
            ("b.test", Script::Answer(200, None, vec![b"ok"])),
            ("c.test", Script::Answer(200, None, vec![b"ok"])),
        ],
        OnExhausted::Status503,
        None,
    );
    let t = token();
    let described = Arc::new(HashMap::from([(
        "m2".to_string(),
        MemberFacts {
            tags: vec!["baa".to_string()],
            tier: Some("gold".to_string()),
            ..MemberFacts::default()
        },
    )]));
    let far = r.egress.unit(route()).described(described);
    let candidates = far
        .candidates(&t)
        .expect("the walk names its pool's members");
    assert_eq!(candidates.pool, POOL);
    let names: Vec<(usize, &str, &str)> = candidates
        .members
        .iter()
        .map(|c| (c.idx, c.model.as_str(), c.provider.as_str()))
        .collect();
    assert_eq!(names, [(0, "m0", "p0"), (1, "m1", "p1"), (2, "m2", "p2")]);
    assert_eq!(candidates.members[2].tags, ["baa"]);
    assert_eq!(candidates.members[2].tier.as_deref(), Some("gold"));

    far.constrain(
        &t,
        Constraint {
            keep: Some(vec![1, 2]),
            order: Some(vec![2]),
            ..Constraint::default()
        },
    );
    let picked = |p: Pick| match p {
        Pick::Member { name, .. } => name,
        other => panic!("{other:?}"),
    };
    assert_eq!(
        picked(far.member(&t, 1).await),
        "m2",
        "the hooks' order first"
    );
    assert!(far.send(&t, request()).await);
    let _ = drain(&far, &t).await;
    assert_eq!(
        picked(far.member(&t, 2).await),
        "m1",
        "then what the hooks kept"
    );
}

#[tokio::test]
async fn a_required_restrict_refuses_at_the_fallback_pool() {
    use crate::plane_driver::{Constraint, Restrict};
    let mut r = rig(
        &[("a.test", Script::Refused)],
        OnExhausted::FallbackPool("fb".into()),
        None,
    );
    let fallback = Pool {
        name: "fb".into(),
        members: vec![Member::new(DestinationId::new(1), "m0", 1)],
        failover: Failover {
            timeout_secs: 30,
            max_hops: 3,
            exclusions: Vec::new(),
        },
        on_exhausted: OnExhausted::Status503,
        floor: Default::default(),
    };
    r.egress.pools.insert("fb".to_string(), fallback);
    let t = token();
    let far = r.egress.unit(route());
    far.constrain(
        &t,
        Constraint {
            restricts: vec![Restrict {
                tags_any: vec!["baa".to_string()],
                on_empty: crate::config::PolicyOnError::Reject,
                name: "compliance".into(),
            }],
            ..Constraint::default()
        },
    );
    assert!(matches!(far.member(&t, 1).await, Pick::Member { .. }));
    assert!(!far.send(&t, request()).await, "the dial is refused");
    assert_eq!(
        far.member(&t, 2).await,
        Pick::Vetoed {
            status: 503,
            text: "No upstream satisfies a required gate's restriction. Please retry shortly."
                .to_string(),
        }
    );
}

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

#[allow(unsafe_code)]
#[path = "probe_unit_tests.rs"]
mod probe_unit;

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

#[tokio::test]
async fn the_planes_transient_reading_outranks_the_transports_callers_fault() {
    let r = rig(
        &[("a.test", Script::Answer(400, Some(9), vec![b"slow down"]))],
        OnExhausted::Status503,
        None,
    );
    let t = token();
    let far = r.egress.unit(route());
    assert!(matches!(far.member(&t, 1).await, Pick::Member { .. }));
    assert!(far.send(&t, request()).await);
    let p = far.next(&t).await.expect("a piece");
    assert!(
        !p.fail_over,
        "the caller's fault is relayed to the plane: {p:?}"
    );
    assert!(
        r.book.observed.lock().unwrap().is_empty(),
        "nothing is recorded until the plane has read the answer"
    );
    far.judged(&t, FAULT_TRANSIENT);
    assert_eq!(
        *r.book.observed.lock().unwrap(),
        vec![(
            DestinationId::new(1),
            Outcome::Transient {
                retry_after: Some(9)
            }
        )],
        "the plane's reading is the one recorded"
    );

    far.judged(&t, FAULT_HARD);
    assert_eq!(r.book.observed.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn the_planes_callers_reading_outranks_the_transports_hard_down() {
    let r = rig(
        &[("a.test", Script::Answer(401, None, vec![b"no"]))],
        OnExhausted::Status503,
        None,
    );
    let t = token();
    let far = r.egress.unit(route());
    assert!(matches!(far.member(&t, 1).await, Pick::Member { .. }));
    assert!(far.send(&t, request()).await);
    let _ = far.next(&t).await.expect("a piece");
    far.judged(&t, FAULT_CALLER);
    assert_eq!(
        *r.book.observed.lock().unwrap(),
        vec![(DestinationId::new(1), Outcome::RecordNothing)],
        "the plane said the caller's: nothing is held against the destination"
    );
}

#[tokio::test]
async fn an_answer_the_plane_never_reads_is_recorded_with_the_transports_reading() {
    let r = rig(
        &[("a.test", Script::Answer(403, None, vec![b"no"]))],
        OnExhausted::Status503,
        None,
    );
    let t = token();
    let far = r.egress.unit(route());
    assert!(matches!(far.member(&t, 1).await, Pick::Member { .. }));
    assert!(far.send(&t, request()).await);
    let _ = far.next(&t).await.expect("a piece");
    drop(far);
    assert_eq!(
        *r.book.observed.lock().unwrap(),
        vec![(DestinationId::new(1), Outcome::HardDown)],
        "the transport's reading, recorded as the attempt settled"
    );
}

#[tokio::test]
async fn a_failed_over_answer_is_recorded_at_once_with_the_transports_reading() {
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
    assert!(matches!(far.member(&t, 1).await, Pick::Member { .. }));
    assert!(far.send(&t, request()).await);
    let p = far.next(&t).await.expect("a piece");
    assert!(p.fail_over);
    assert_eq!(
        *r.book.observed.lock().unwrap(),
        vec![(
            DestinationId::new(1),
            Outcome::Transient { retry_after: None }
        )]
    );
}

async fn relayed_502(fault: Option<u8>) -> Vec<(DestinationId, Outcome)> {
    let r = rig(
        &[(
            "a.test",
            Script::Answer(502, None, vec![b"{\"error\":\"upstream\"}"]),
        )],
        OnExhausted::Status503,
        None,
    );
    let t = token();
    let far = r.egress.unit(UnitRoute {
        once: true,
        ..route()
    });
    assert!(matches!(far.member(&t, 1).await, Pick::Member { .. }));
    assert!(far.send(&t, request()).await);
    let p = far.next(&t).await.expect("a piece");
    assert!(!p.fail_over, "{p:?}");
    assert_eq!(p.status.map(|s| s.0), Some(502));

    far.judged(&t, FAULT_NONE);
    assert!(
        r.book.observed.lock().unwrap().is_empty(),
        "a non-success head's record waits for the plane's reading"
    );
    loop {
        let p = far.next(&t).await.expect("a piece through the last");
        far.judged(
            &t,
            if p.last {
                fault.unwrap_or(FAULT_NONE)
            } else {
                FAULT_NONE
            },
        );
        if p.last {
            break;
        }
    }
    let observed = r.book.observed.lock().unwrap().clone();
    observed
}

#[tokio::test]
async fn a_502_the_plane_reads_healthy_records_success() {
    assert_eq!(
        relayed_502(Some(FAULT_HEALTHY)).await,
        vec![(DestinationId::new(1), Outcome::Success)]
    );
}

#[tokio::test]
async fn a_502_the_plane_reads_transient_records_a_failure() {
    assert_eq!(
        relayed_502(Some(FAULT_TRANSIENT)).await,
        vec![(
            DestinationId::new(1),
            Outcome::Transient { retry_after: None }
        )]
    );
}

#[tokio::test]
async fn a_502_with_no_plane_reading_falls_back_to_the_status_table() {
    assert_eq!(
        relayed_502(None).await,
        vec![(
            DestinationId::new(1),
            Outcome::Transient { retry_after: None }
        )]
    );
}

#[tokio::test]
async fn a_401_the_plane_reads_hard_records_hard_down() {
    let r = rig(
        &[("a.test", Script::Answer(401, None, vec![b"refused"]))],
        OnExhausted::Status503,
        None,
    );
    let t = token();
    let far = r.egress.unit(route());
    assert!(matches!(far.member(&t, 1).await, Pick::Member { .. }));
    assert!(far.send(&t, request()).await);
    let p = far.next(&t).await.expect("a piece");
    assert!(!p.fail_over, "{p:?}");
    far.judged(&t, FAULT_HARD);
    assert_eq!(
        *r.book.observed.lock().unwrap(),
        vec![(DestinationId::new(1), Outcome::HardDown)]
    );
}

fn head_then_body_502() -> Rig {
    rig(
        &[(
            "a.test",
            Script::Answer(502, None, vec![b"", b"{\"error\":\"upstream\"}"]),
        )],
        OnExhausted::Status503,
        None,
    )
}

#[tokio::test]
async fn a_502_head_with_no_reading_then_a_healthy_body_records_success() {
    let r = head_then_body_502();
    let t = token();
    let far = r.egress.unit(UnitRoute {
        once: true,
        ..route()
    });
    assert!(matches!(far.member(&t, 1).await, Pick::Member { .. }));
    assert!(far.send(&t, request()).await);
    let head = far.next(&t).await.expect("the head");
    assert_eq!(head.status.map(|s| s.0), Some(502));
    assert!(head.bytes.is_empty(), "{head:?}");
    far.judged(&t, FAULT_NONE);
    assert!(
        r.book.observed.lock().unwrap().is_empty(),
        "a head read with no reading keeps the hold"
    );
    let body = far.next(&t).await.expect("the body");
    assert!(!body.bytes.is_empty() && !body.last, "{body:?}");
    far.judged(&t, FAULT_HEALTHY);
    assert_eq!(
        *r.book.observed.lock().unwrap(),
        vec![(DestinationId::new(1), Outcome::Success)]
    );
}

#[tokio::test]
async fn a_502_head_with_no_reading_settled_unread_records_by_the_table() {
    let r = head_then_body_502();
    let t = token();
    let far = r.egress.unit(UnitRoute {
        once: true,
        ..route()
    });
    assert!(matches!(far.member(&t, 1).await, Pick::Member { .. }));
    assert!(far.send(&t, request()).await);
    let _ = far.next(&t).await.expect("the head");
    far.judged(&t, FAULT_NONE);
    assert!(r.book.observed.lock().unwrap().is_empty());
    drop(far);
    assert_eq!(
        *r.book.observed.lock().unwrap(),
        vec![(
            DestinationId::new(1),
            Outcome::Transient { retry_after: None }
        )]
    );
}

struct Resolving {
    answers: Mutex<VecDeque<Option<u64>>>,
    asked: AtomicU64,
}

impl busbar_contract::auth_calls::PerRequestHandle for Resolving {
    fn handle_now(&self) -> Option<u64> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        self.answers.lock().unwrap().pop_front().flatten()
    }
}

/// An auth binding presenting the handle it is asked on (`authorization: Bearer h<handle>`), so
/// the wire shows which opened credential a request carried.
#[derive(Default)]
struct ByHandle {
    calls: AtomicU64,
}

impl OutboundAuth for ByHandle {
    fn open_outbound(&self, _: &str, _: &[u8], _: &serde_json::Value) -> Result<u64, String> {
        Ok(1)
    }
    fn fields_now(&self, handle: u64, _: &FieldsRequest) -> Option<Fields> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Some(Fields::Ready(vec![AuthField {
            name: b"authorization".to_vec(),
            value: format!("Bearer h{handle}").into_bytes().into(),
            sensitive: true,
            query: false,
            require_secure: false,
        }]))
    }
    fn fields(&self, h: u64, r: FieldsRequest, _: u64) -> Box<dyn Fielding> {
        Box::new(Done(self.fields_now(h, &r).unwrap_or(Fields::Failed)))
    }
}

fn resolving(r: &mut Rig, answers: &[Option<u64>]) -> (Arc<Resolving>, Arc<ByHandle>) {
    let per = Arc::new(Resolving {
        answers: Mutex::new(answers.iter().copied().collect()),
        asked: AtomicU64::new(0),
    });
    let auth = Arc::new(ByHandle::default());
    r.egress
        .routes
        .get_mut(&DestinationId::new(1))
        .expect("m0's route")
        .auth = Some(AuthBinding {
        auth: Arc::clone(&auth) as Arc<dyn OutboundAuth>,
        handle: 1,
        style_flags: 0,
        points: AuthPoints::HEAD,
        passthrough: false,
        per_request: Some(
            Arc::clone(&per) as Arc<dyn busbar_contract::auth_calls::PerRequestHandle>
        ),
    });
    (per, auth)
}

fn authorizations(r: &Rig) -> Vec<Option<Vec<u8>>> {
    r.table
        .opened
        .lock()
        .unwrap()
        .iter()
        .map(|(_, head, _, _)| {
            head.iter()
                .find(|(n, _)| n == "authorization")
                .map(|(_, v)| v.clone())
        })
        .collect()
}

#[tokio::test]
async fn each_attempt_presents_the_handle_its_credential_resolves_to_now() {
    let mut r = rig(
        &[("a.test", Script::Answer(200, None, vec![b"ok"]))],
        OnExhausted::Status503,
        None,
    );
    let (per, auth) = resolving(&mut r, &[Some(7), Some(8)]);
    let t = token();
    for _ in 0..2 {
        let far = r.egress.unit(route());
        let _ = far.member(&t, 1).await;
        assert!(far.send(&t, request()).await);
        let _ = drain(&far, &t).await;
    }
    assert_eq!(
        authorizations(&r),
        vec![Some(b"Bearer h7".to_vec()), Some(b"Bearer h8".to_vec())],
        "each request carried the handle resolved for it, not the sealed one (h1)"
    );
    assert_eq!(
        per.asked.load(Ordering::SeqCst),
        2,
        "asked once per request"
    );
    assert_eq!(auth.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn an_unavailable_credential_refuses_the_unit_before_the_dial() {
    let mut r = rig(
        &[
            ("a.test", Script::Answer(200, None, vec![b"ok"])),
            ("b.test", Script::Answer(200, None, vec![b"ok"])),
        ],
        OnExhausted::Status503,
        None,
    );
    let (per, auth) = resolving(&mut r, &[None]);
    let t = token();
    let far = r.egress.unit(route());
    assert!(matches!(far.member(&t, 1).await, Pick::Member { ref name, .. } if name == "m0"));
    assert!(!far.send(&t, request()).await, "nothing was sent");
    assert_eq!(
        far.member(&t, 2).await,
        Pick::Refused(busbar_contract::caps::ReasonCode::CredentialUnavailable),
        "the unit is refused, not failed over"
    );
    assert!(r.table.opened.lock().unwrap().is_empty(), "nothing dialled");
    assert_eq!(auth.calls.load(Ordering::SeqCst), 0, "nothing presented");
    assert_eq!(per.asked.load(Ordering::SeqCst), 1);
    assert!(
        r.book.observed.lock().unwrap().is_empty(),
        "nothing recorded against the member"
    );
}

#[tokio::test]
async fn a_waived_request_carries_no_member_auth_and_the_waiver_never_reaches_the_wire() {
    use busbar_contract::abi::auth::NO_MEMBER_AUTH_FIELD;
    let mut r = rig(
        &[("a.test", Script::Answer(200, None, vec![b"ok"]))],
        OnExhausted::Status503,
        None,
    );
    let (per, auth) = resolving(&mut r, &[Some(5)]);
    let t = token();
    for waived in [true, false] {
        let far = r.egress.unit(route());
        let _ = far.member(&t, 1).await;
        let mut req = request();
        if waived {
            req.fields
                .push((NO_MEMBER_AUTH_FIELD.as_bytes().to_vec(), b"1".to_vec()));
        }
        assert!(far.send(&t, req).await);
        let _ = drain(&far, &t).await;
    }
    assert_eq!(
        authorizations(&r),
        vec![None, Some(b"Bearer h5".to_vec())],
        "the waived request presented nothing; the other its member's credential"
    );
    assert_eq!(
        per.asked.load(Ordering::SeqCst),
        1,
        "only the unwaived asked"
    );
    assert_eq!(auth.calls.load(Ordering::SeqCst), 1);
    for (_, head, _, _) in r.table.opened.lock().unwrap().iter() {
        assert!(
            head.iter()
                .all(|(n, _)| !n.eq_ignore_ascii_case(NO_MEMBER_AUTH_FIELD)),
            "the host's field never reaches the wire: {head:?}"
        );
    }
}

#[tokio::test]
async fn an_answer_cut_after_its_head_ends_on_a_cut_piece_and_a_complete_one_does_not() {
    let r = rig(
        &[("a.test", Script::Broken(200, vec![b"data: one\n\n"]))],
        OnExhausted::Status503,
        None,
    );
    let t = token();
    let far = r.egress.unit(route());
    let Pick::Member { .. } = far.member(&t, 1).await else {
        panic!("a member")
    };
    assert!(far.send(&t, request()).await);
    let pieces = drain(&far, &t).await;
    let last = pieces.last().expect("a last piece");
    assert!(last.last && last.cut, "{pieces:?}");
    assert!(
        pieces[..pieces.len() - 1].iter().all(|p| !p.cut),
        "only the last piece is cut: {pieces:?}"
    );
    assert!(r.book.observed.lock().unwrap().contains(&(
        DestinationId::new(1),
        Outcome::Transient { retry_after: None }
    )));

    let r = rig(
        &[("a.test", Script::Answer(200, None, vec![b"whole"]))],
        OnExhausted::Status503,
        None,
    );
    let far = r.egress.unit(route());
    let Pick::Member { .. } = far.member(&t, 1).await else {
        panic!("a member")
    };
    assert!(far.send(&t, request()).await);
    let pieces = drain(&far, &t).await;
    assert!(
        pieces.iter().all(|p| !p.cut),
        "a complete answer is not cut: {pieces:?}"
    );
}

/// The upstream-failure dispositions the far end counted, in order.
#[derive(Default)]
struct Failures {
    failed: Mutex<Vec<&'static str>>,
}
impl Telemetry for Failures {
    fn upstream_attempt(&self, _: &str, _: DestinationId) {}
    fn upstream_failure(&self, _: &str, _: DestinationId, disposition: &'static str) {
        self.failed.lock().unwrap().push(disposition);
    }
    fn failover(&self, _: &str, _: &'static str) {}
    fn breaker_trip(&self, _: &str, _: DestinationId) {}
    fn queued(&self, _: &str, _: i64) {}
}

async fn read_last_as(
    script: Script,
    fault: u8,
) -> (Vec<(DestinationId, Outcome)>, Vec<&'static str>) {
    let mut r = rig(&[("a.test", script)], OnExhausted::Status503, None);
    let failures = Arc::new(Failures::default());
    r.egress.telemetry = Arc::clone(&failures) as Arc<dyn Telemetry>;
    let t = token();
    let far = r.egress.unit(UnitRoute {
        once: true,
        ..route()
    });
    assert!(matches!(far.member(&t, 1).await, Pick::Member { .. }));
    assert!(far.send(&t, request()).await);
    loop {
        let p = far.next(&t).await.expect("a piece through the last");
        far.judged(&t, if p.last { fault } else { FAULT_NONE });
        if p.last {
            break;
        }
    }
    drop(far);
    let observed = r.book.observed.lock().unwrap().clone();
    let failed = failures.failed.lock().unwrap().clone();
    (observed, failed)
}

#[tokio::test]
async fn a_fault_read_inside_a_success_records_the_breaker_and_counts_no_upstream_failure() {
    let (observed, failed) = read_last_as(
        Script::Answer(
            200,
            None,
            vec![b"data: {\"a\":1}\n\n", b"data: {\"error\":{}}\n\n"],
        ),
        FAULT_TRANSIENT,
    )
    .await;
    assert_eq!(
        observed,
        vec![
            (DestinationId::new(1), Outcome::Success),
            (
                DestinationId::new(1),
                Outcome::Transient { retry_after: None }
            ),
        ],
        "the head's success, then the compensating transient the plane's reading states"
    );
    assert!(
        failed.is_empty(),
        "a fault inside a success counts no upstream failure (1.5.5): {failed:?}"
    );
}

#[tokio::test]
async fn a_relayed_failure_the_plane_reads_transient_counts_its_upstream_failure() {
    let (observed, failed) = read_last_as(
        Script::Answer(502, None, vec![b"{\"error\":\"upstream\"}"]),
        FAULT_TRANSIENT,
    )
    .await;
    assert_eq!(
        observed,
        vec![(
            DestinationId::new(1),
            Outcome::Transient { retry_after: None }
        )]
    );
    assert_eq!(failed, vec!["transient"]);
}

async fn unsent_after(r: &Rig, pick: bool, request: OutboundRequest) -> Option<RefusalCode> {
    let t = token();
    let far = r.egress.unit(route());
    assert_eq!(far.unsent(&t), None, "no attempt yet, nothing to say");
    if pick {
        assert!(matches!(far.member(&t, 1).await, Pick::Member { .. }));
    }
    assert!(!far.send(&t, request).await, "nothing was sent");
    far.unsent(&t)
}

fn one_member() -> Rig {
    rig(
        &[("a.test", Script::Answer(200, None, vec![b"ok"]))],
        OnExhausted::Status503,
        None,
    )
}

#[tokio::test]
async fn a_send_with_no_member_in_hand_says_nothing_was_attempted() {
    let r = one_member();
    assert_eq!(
        unsent_after(&r, false, request()).await,
        Some(RefusalCode::UnsentNoAttempt)
    );
    assert!(r.table.opened.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_member_with_no_route_says_nothing_left() {
    let mut r = one_member();
    r.egress.routes.remove(&DestinationId::new(1));
    assert_eq!(
        unsent_after(&r, true, request()).await,
        Some(RefusalCode::UnsentNoRoute)
    );
    assert!(r.table.opened.lock().unwrap().is_empty());
}

#[tokio::test]
async fn an_unbound_need_says_nothing_left() {
    let mut r = one_member();
    for route in r.egress.routes.values_mut() {
        route.rides = vec![(NeedId(3), super::ResponseKeep::default())];
    }
    let request = OutboundRequest {
        need: 9,
        ..request()
    };
    assert_eq!(
        unsent_after(&r, true, request).await,
        Some(RefusalCode::UnsentNeedUnbound)
    );
    assert!(r.table.opened.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_target_that_is_not_a_path_says_nothing_left() {
    let r = one_member();
    let request = OutboundRequest {
        target: b"@evil.test/x".to_vec(),
        ..request()
    };
    assert_eq!(
        unsent_after(&r, true, request).await,
        Some(RefusalCode::UnsentTargetNotPath)
    );
    assert!(r.table.opened.lock().unwrap().is_empty());
    assert_eq!(r.auth.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_field_name_that_is_not_a_token_says_nothing_left() {
    let r = one_member();
    let mut request = request();
    request
        .fields
        .push((b"authorization:x".to_vec(), b"v".to_vec()));
    assert_eq!(
        unsent_after(&r, true, request).await,
        Some(RefusalCode::UnsentFieldName)
    );
    assert!(r.table.opened.lock().unwrap().is_empty());
    assert_eq!(r.auth.calls.load(Ordering::SeqCst), 0);
}

struct Unwritable;
impl Journal for Unwritable {
    fn dispatched(&self, _: &Dispatched) -> Result<(), DurabilityUnavailable> {
        Err(DurabilityUnavailable)
    }
    fn abandoned(&self, _: &Dispatched) {}
}

#[tokio::test]
async fn an_unrecordable_dispatch_says_nothing_left() {
    let mut r = one_member();
    r.egress.journal = Arc::new(Unwritable);
    assert_eq!(
        unsent_after(&r, true, request()).await,
        Some(RefusalCode::UnsentUnrecorded)
    );
    assert!(r.table.opened.lock().unwrap().is_empty());
    assert_eq!(r.auth.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_failed_auth_call_says_nothing_left() {
    let r = one_member();
    r.auth.refuse.store(true, Ordering::SeqCst);
    assert_eq!(
        unsent_after(&r, true, request()).await,
        Some(RefusalCode::UnsentAuthFailed)
    );
    assert_eq!(r.auth.calls.load(Ordering::SeqCst), 1, "the one auth call");
    assert!(r.table.opened.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_refused_open_says_nothing_left() {
    let r = rig(&[("a.test", Script::Refused)], OnExhausted::Status503, None);
    assert_eq!(
        unsent_after(&r, true, request()).await,
        Some(RefusalCode::UnsentOpenRefused)
    );
    assert_eq!(
        r.book.observed.lock().unwrap().clone(),
        vec![(
            DestinationId::new(1),
            Outcome::Transient { retry_after: None }
        )],
        "the refused dial is the member's transient, as before"
    );
}

#[tokio::test]
async fn a_sent_attempt_that_fails_over_carries_no_pre_byte_reason() {
    let r = rig(
        &[("a.test", Script::Silent), ("b.test", Script::Refused)],
        OnExhausted::Status503,
        Some(50),
    );
    let t = token();
    let far = r.egress.unit(route());
    assert!(matches!(far.member(&t, 1).await, Pick::Member { .. }));
    assert!(far.send(&t, request()).await, "the first attempt is sent");
    let p = far.next(&t).await.expect("a piece");
    assert!(p.fail_over, "{p:?}");
    assert_eq!(far.unsent(&t), None, "a sent attempt says nothing left");
    assert!(matches!(far.member(&t, 2).await, Pick::Member { .. }));
    assert!(!far.send(&t, request()).await, "the refused dial");
    assert_eq!(
        far.unsent(&t),
        None,
        "a walk that sent an attempt names no pre-byte reason"
    );

    let r = rig(
        &[("a.test", Script::Refused), ("b.test", Script::Silent)],
        OnExhausted::Status503,
        Some(50),
    );
    let far = r.egress.unit(route());
    assert!(matches!(far.member(&t, 1).await, Pick::Member { .. }));
    assert!(!far.send(&t, request()).await, "the refused dial");
    assert_eq!(
        far.unsent(&t),
        Some(RefusalCode::UnsentOpenRefused),
        "RED arm: nothing has left yet"
    );
    assert!(matches!(far.member(&t, 2).await, Pick::Member { .. }));
    assert!(far.send(&t, request()).await, "the second attempt is sent");
    let p = far.next(&t).await.expect("a piece");
    assert!(p.fail_over, "{p:?}");
    assert_eq!(far.unsent(&t), None, "the sent attempt clears it");
}

#[tokio::test]
async fn the_framers_own_head_lines_follow_the_planes_fields_in_the_head_that_goes_out() {
    let r = rig(
        &[("a.test", Script::Answer(200, None, vec![b"ok"]))],
        OnExhausted::Status503,
        None,
    );
    *r.table.defaults.lock().unwrap() = vec![
        (b"accept".to_vec(), b"*/*".to_vec()),
        (b"host".to_vec(), b"a.test".to_vec()),
    ];
    let t = token();
    let far = r.egress.unit(route());
    assert!(matches!(far.member(&t, 1).await, Pick::Member { .. }));
    assert!(far.send(&t, request()).await);
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
            ("accept", b"*/*".as_slice()),
            ("host", b"a.test".as_slice()),
        ]
    );

    let far = r.egress.unit(route());
    assert!(matches!(far.member(&t, 1).await, Pick::Member { .. }));
    let mut req = request();
    req.fields
        .push((b"Accept".to_vec(), b"text/plain".to_vec()));
    assert!(far.send(&t, req).await);
    let _ = drain(&far, &t).await;
    let opened = r.table.opened.lock().unwrap().clone();
    let head: Vec<&str> = opened[1].1.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(head, ["authorization", "content-type", "Accept", "host"]);
}

#[tokio::test]
async fn a_framer_that_states_its_length_has_the_bodys_length_last_in_the_head() {
    let r = rig(
        &[("a.test", Script::Answer(200, None, vec![b"ok"]))],
        OnExhausted::Status503,
        None,
    );
    *r.table.defaults.lock().unwrap() = vec![
        (b"accept".to_vec(), b"*/*".to_vec()),
        (b"host".to_vec(), b"a.test".to_vec()),
    ];
    r.table
        .states_length
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let t = token();
    let names =
        |n: usize| -> Vec<(String, Vec<u8>)> { r.table.opened.lock().unwrap()[n].1.clone() };
    let signed = |n: usize| -> Vec<(String, String)> {
        r.auth.heads.lock().unwrap()[n]
            .iter()
            .map(|(k, v)| {
                (
                    String::from_utf8_lossy(k).into_owned(),
                    String::from_utf8_lossy(v).into_owned(),
                )
            })
            .collect()
    };
    let pairs = |p: &[(&str, &str)]| -> Vec<(String, String)> {
        p.iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    };
    let far = r.egress.unit(route());
    assert!(matches!(far.member(&t, 1).await, Pick::Member { .. }));
    assert!(far.send(&t, request()).await);
    let _ = drain(&far, &t).await;

    assert_eq!(
        signed(0),
        pairs(&[
            ("content-type", "application/json"),
            ("accept", "*/*"),
            ("host", "a.test"),
            ("content-length", "2"),
        ])
    );

    let head = names(0);
    let head: Vec<(&str, &[u8])> = head
        .iter()
        .map(|(n, v)| (n.as_str(), v.as_slice()))
        .collect();
    assert_eq!(
        head,
        [
            ("authorization", b"Bearer sk-test".as_slice()),
            ("content-type", b"application/json".as_slice()),
            ("accept", b"*/*".as_slice()),
            ("host", b"a.test".as_slice()),
        ]
    );

    let far = r.egress.unit(route());
    assert!(matches!(far.member(&t, 1).await, Pick::Member { .. }));
    let mut req = request();
    req.body.clear();
    assert!(far.send(&t, req).await);
    let _ = drain(&far, &t).await;
    assert_eq!(
        signed(1),
        pairs(&[
            ("content-type", "application/json"),
            ("accept", "*/*"),
            ("host", "a.test"),
        ])
    );
    let head: Vec<String> = names(1).into_iter().map(|(n, _)| n).collect();
    assert_eq!(head, ["authorization", "content-type", "accept", "host"]);

    r.table
        .states_length
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let far = r.egress.unit(route());
    assert!(matches!(far.member(&t, 1).await, Pick::Member { .. }));
    assert!(far.send(&t, request()).await);
    let _ = drain(&far, &t).await;
    assert_eq!(
        signed(2),
        pairs(&[
            ("content-type", "application/json"),
            ("accept", "*/*"),
            ("host", "a.test"),
        ])
    );
    let head: Vec<String> = names(2).into_iter().map(|(n, _)| n).collect();
    assert_eq!(head, ["authorization", "content-type", "accept", "host"]);
}

#[tokio::test]
async fn a_far_request_names_its_auth_fields_sealed_to_the_connector() {
    use busbar_contract::abi::auth::NO_MEMBER_AUTH_FIELD;
    let mut r = rig(
        &[("a.test", Script::Answer(200, None, vec![b"ok"]))],
        OnExhausted::Status503,
        None,
    );
    let _ = resolving(&mut r, &[Some(5)]);
    let t = token();
    for waived in [false, true] {
        let far = r.egress.unit(route());
        let _ = far.member(&t, 1).await;
        let mut req = request();
        if waived {
            req.fields
                .push((NO_MEMBER_AUTH_FIELD.as_bytes().to_vec(), b"1".to_vec()));
        }
        assert!(far.send(&t, req).await);
        let _ = drain(&far, &t).await;
    }
    let sealed = r.table.sealed.lock().unwrap().clone();
    assert_eq!(
        sealed,
        vec![Some(b"authorization".to_vec()), None],
        "the credential's field is named sealed; a request presenting none names none"
    );
}

#[tokio::test]
async fn a_far_query_credential_preserves_the_signed_target_and_same_named_plane_header() {
    let r = rig(
        &[("a.test", Script::Answer(200, None, vec![b"ok"]))],
        OnExhausted::Status503,
        None,
    );
    r.auth.query.store(true, Ordering::SeqCst);
    let t = token();
    let far = r.egress.unit(route());
    let _ = far.member(&t, 1).await;
    let mut req = request();
    req.target = b"/call?existing=1".to_vec();
    req.fields
        .push((b"authorization".to_vec(), b"plane-header".to_vec()));
    req.fields
        .push((b"busbar-sealed-query".to_vec(), b"forged=value".to_vec()));
    assert!(far.send(&t, req).await);
    let _ = drain(&far, &t).await;
    let opened = r.table.opened.lock().unwrap();
    assert_eq!(opened.len(), 1);
    let (target, fields, _, _) = &opened[0];
    assert!(!target.contains("sk-test"));
    assert!(fields
        .iter()
        .any(|(n, v)| n == "authorization" && v == b"plane-header"));
    assert_eq!(
        fields
            .iter()
            .filter(|(n, _)| n == "busbar-sealed-query")
            .map(|(_, v)| v.as_slice())
            .collect::<Vec<_>>(),
        [b"authorization=Bearer%20sk-test".as_slice()]
    );
    assert_eq!(*r.table.sealed.lock().unwrap(), [None]);
    assert!(!r.table.words.lock().unwrap()[0]
        .1
        .windows(7)
        .any(|w| w == b"sk-test"));
    let signed = r.auth.facts.lock().unwrap();
    assert_eq!(
        signed.len(),
        1,
        "auth signs exactly once, before query injection"
    );
    assert!(!signed[0].2.windows(7).any(|w| w == b"sk-test"));
    let signed_heads = r.auth.heads.lock().unwrap();
    assert!(!signed_heads[0]
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case(b"busbar-sealed-query")));
    assert!(signed_heads[0]
        .iter()
        .any(|(name, value)| name == b"authorization" && value == b"plane-header"));
}

#[tokio::test]
async fn a_far_request_is_dialled_within_the_address_set_its_plane_judged() {
    use busbar_contract::abi::host::conn::connector::WITHIN_REQUEST_FIELD;
    let r = rig(
        &[("a.test", Script::Answer(200, None, vec![b"ok"]))],
        OnExhausted::Status503,
        None,
    );
    let t = token();
    let pinned: Vec<std::net::IpAddr> = vec![
        "203.0.113.7".parse().unwrap(),
        "2001:db8::1".parse().unwrap(),
    ];
    for stated in [Some(&b"203.0.113.7, 2001:db8::1"[..]), None] {
        let far = r.egress.unit(route());
        let _ = far.member(&t, 1).await;
        let mut req = request();
        if let Some(v) = stated {
            req.fields
                .push((WITHIN_REQUEST_FIELD.as_bytes().to_vec(), v.to_vec()));
        }
        assert!(far.send(&t, req).await);
        let _ = drain(&far, &t).await;
    }
    assert_eq!(
        *r.table.withins.lock().unwrap(),
        vec![pinned, Vec::new()],
        "the stated set pins the dial; none states no pin"
    );
    for (_, head, _, _) in r.table.opened.lock().unwrap().iter() {
        assert!(
            head.iter()
                .all(|(n, _)| !n.eq_ignore_ascii_case(WITHIN_REQUEST_FIELD)),
            "the host's field never reaches the wire: {head:?}"
        );
    }
    let far = r.egress.unit(route());
    let _ = far.member(&t, 1).await;
    let mut req = request();
    req.fields
        .push((WITHIN_REQUEST_FIELD.as_bytes().to_vec(), b"a.test".to_vec()));
    assert!(!far.send(&t, req).await, "an unreadable pin sends nothing");
    assert_eq!(r.table.opened.lock().unwrap().len(), 2, "nothing dialled");
}

#[tokio::test]
async fn protected_auth_never_uses_a_raw_connector_and_does_not_blame_the_destination() {
    let r = rig(
        &[("a.test", Script::Answer(200, None, vec![b"ok"]))],
        OnExhausted::Status503,
        None,
    );
    r.auth.require_secure.store(true, Ordering::SeqCst);
    let t = token();
    for query in [false, true] {
        r.auth.query.store(query, Ordering::SeqCst);
        let far = r.egress.unit(route());
        let _ = far.member(&t, 1).await;
        assert!(!far.send(&t, request()).await);
    }
    assert!(r.table.opened.lock().unwrap().is_empty());
    assert!(r.book.observed.lock().unwrap().is_empty());
}
