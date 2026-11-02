// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::{HashMap, HashSet, VecDeque};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::Body as AxumBody;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, Uri, Version};
use axum::Router;
use busbar_contract::abi::transport::{
    fields, CLOSE_DRAIN, CLOSE_NORMAL, ROLE_FRAMER, SIDE_ACCEPT,
};
use busbar_core_connector::framer::{
    self, Established, FramerDoor, Framing, Got, GuestLines, Head, Yielded,
};
use bytes::Bytes;
use http_body::{Body as _, Frame};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot};

pub const DATA_SCHEME: &str = "http";

const UPGRADE_CLAIMS: [&str; 2] = ["ws", "wss"];

pub const DATA_LINE: u32 = 1;

pub const DATA_LINE_REF: u64 = 0x6461_7461_6c69_6e65;

const READ_CHUNK: usize = 16 * 1024;

const WRITE_ROOM: usize = 256 * 1024;

pub const FIRST_BYTE_BOUND: std::time::Duration = std::time::Duration::from_secs(30);

const SWITCHING_PROTOCOLS: u16 = 101;

const BODY_LIMIT_REFUSAL: u32 = axum::http::StatusCode::PAYLOAD_TOO_LARGE.as_u16() as u32;

pub type FramerFor = Arc<dyn Fn(&str) -> Option<Arc<dyn FramerDoor>> + Send + Sync>;

/// THE DATA LISTENER'S FRAMER: the framer entry, its instance, and the protocols its accepting
/// side offers (what its stated agreed position names).
#[derive(Clone)]
pub struct DataFramer {
    door: Arc<dyn FramerDoor>,
    owner: u64,
    scheme: String,
    listener: Arc<crate::root::inbound::ListenerRegistration>,
    offer: Vec<Vec<u8>>,
    upgrade: FramerFor,
}

impl std::fmt::Debug for DataFramer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DataFramer")
            .field("entry", &self.door.facts().name)
            .field("owner", &self.owner)
            .finish_non_exhaustive()
    }
}

pub fn data_framer(framer_for: FramerFor) -> Option<DataFramer> {
    configured_framer(framer_for, DATA_SCHEME, None)
}

pub fn listener_framer(
    framer_for: FramerFor,
    scheme: &str,
    policy: crate::root::inbound::ListenerPolicy,
) -> Option<DataFramer> {
    configured_framer(framer_for, scheme, Some(policy))
}

fn configured_framer(
    framer_for: FramerFor,
    scheme: &str,
    policy: Option<crate::root::inbound::ListenerPolicy>,
) -> Option<DataFramer> {
    let door = framer_for(scheme)?;
    let facts = door.facts();
    if facts.role != ROLE_FRAMER || facts.datagram || !door.accepts() {
        return None;
    }
    let owner = door.instance().filter(|o| *o != 0)?;
    static LISTENERS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let listener = LISTENERS
        .fetch_update(
            std::sync::atomic::Ordering::Relaxed,
            std::sync::atomic::Ordering::Relaxed,
            |n| n.checked_add(1),
        )
        .ok()?;
    let offer = framer::accept_offer(door.as_ref()).unwrap_or_default();
    Some(DataFramer {
        door,
        owner,
        scheme: scheme.to_owned(),
        listener: match policy {
            Some(policy) => crate::root::inbound::ListenerRegistration::with_policy(
                owner,
                listener,
                Some(policy),
            ),
            None => crate::root::inbound::ListenerRegistration::new(owner, listener),
        },
        offer,
        upgrade: framer_for,
    })
}

impl DataFramer {
    pub fn validate_policy(&self) -> Result<(), String> {
        self.listener.validate()
    }

    #[must_use]
    pub fn door(&self) -> &Arc<dyn FramerDoor> {
        &self.door
    }

    pub(in crate::root) fn guests(&self) -> Option<Arc<GuestLines>> {
        self.listener.guests()
    }

    fn is_h2(&self, position: u32) -> bool {
        position != 0
            && self
                .offer
                .get(position as usize - 1)
                .is_some_and(|p| p.as_slice() == b"h2")
    }
}

enum Op {
    Head {
        status: u32,
        fields: Vec<u8>,
        end: bool,
        done: oneshot::Sender<bool>,
    },

    Data {
        bytes: Bytes,
        end: bool,
        done: oneshot::Sender<bool>,
    },

    Trailers {
        fields: Vec<u8>,
        done: oneshot::Sender<bool>,
    },

    Admit {
        reply: oneshot::Sender<bool>,
    },

    Refuse {
        status: u32,
        head_sent: bool,
    },

    Switch {
        pipe: busbar_kernel::plane_routes::SessionPipe,
    },

    Ended {
        scope: Option<Arc<dyn busbar_contract::framing_scope::FramingScope>>,
    },
}

/// A stream task's end of its connection.
#[derive(Clone)]
struct Emitter {
    stream: u64,
    tx: mpsc::UnboundedSender<(u64, Op)>,
}

impl Emitter {
    async fn ask(&self, op: Op, said: oneshot::Receiver<bool>) -> bool {
        if self.tx.send((self.stream, op)).is_err() {
            return false;
        }
        said.await.unwrap_or(false)
    }

    async fn head(&self, status: u32, fields: Vec<u8>, end: bool) -> bool {
        let (done, said) = oneshot::channel();
        let op = Op::Head {
            status,
            fields,
            end,
            done,
        };
        self.ask(op, said).await
    }

    async fn data(&self, bytes: Bytes, end: bool) -> bool {
        let (done, said) = oneshot::channel();
        self.ask(Op::Data { bytes, end, done }, said).await
    }

    async fn trailers(&self, fields: Vec<u8>) -> bool {
        let (done, said) = oneshot::channel();
        self.ask(Op::Trailers { fields, done }, said).await
    }

    fn send(&self, op: Op) {
        let _ = self.tx.send((self.stream, op));
    }
}

struct StreamEnd(
    Emitter,
    Option<Arc<dyn busbar_contract::framing_scope::FramingScope>>,
);

impl Drop for StreamEnd {
    fn drop(&mut self) {
        self.0.send(Op::Ended {
            scope: self.1.take(),
        });
    }
}

type BodyError = Box<dyn std::error::Error + Send + Sync>;

struct Inflow {
    body: Option<mpsc::UnboundedSender<Result<Bytes, BodyError>>>,
    task: tokio::task::AbortHandle,
    body_limit: u64,
    received: u64,
    refused: bool,
    refusal_sent: bool,
    head_sent: bool,
}

struct InboundBody {
    pieces: mpsc::UnboundedReceiver<Result<Bytes, BodyError>>,
    ended: bool,
}

impl http_body::Body for InboundBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        if self.ended {
            return Poll::Ready(None);
        }
        match self.pieces.poll_recv(cx) {
            Poll::Ready(Some(Ok(bytes))) => Poll::Ready(Some(Ok(Frame::data(bytes)))),
            Poll::Ready(Some(Err(e))) => {
                self.ended = true;
                Poll::Ready(Some(Err(e)))
            }
            Poll::Ready(None) => {
                self.ended = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.ended
    }

    fn size_hint(&self) -> http_body::SizeHint {
        if self.ended {
            http_body::SizeHint::with_exact(0)
        } else {
            http_body::SizeHint::default()
        }
    }
}

type SessionSlot = busbar_kernel::plane_routes::FramedSession;

struct Session {
    stream: u64,
    from: Option<mpsc::Sender<Vec<u8>>>,
    message: Vec<u8>,
    messages: VecDeque<Vec<u8>>,
    sending: Option<Pin<Box<dyn std::future::Future<Output = bool> + Send>>>,
    closing: bool,
    body_limit: u64,
    to: mpsc::Receiver<busbar_kernel::plane_routes::SessionOut>,
    writing: Option<(Bytes, bool)>,
}

impl Session {
    fn over(stream: u64, pipe: busbar_kernel::plane_routes::SessionPipe) -> Self {
        let busbar_kernel::plane_routes::SessionPipe {
            from_caller,
            to_caller,
        } = pipe;
        Self {
            stream,
            from: Some(from_caller),
            message: Vec::new(),
            messages: VecDeque::new(),
            sending: None,
            closing: false,
            body_limit: configured_body_limit(),
            to: to_caller,
            writing: None,
        }
    }

    fn deliver(&mut self, cx: &mut Context<'_>) -> Option<bool> {
        let mut moved = false;
        loop {
            if let Some(send) = self.sending.as_mut() {
                match send.as_mut().poll(cx) {
                    Poll::Pending => return Some(moved),
                    Poll::Ready(false) => {
                        self.from = None;
                        self.messages.clear();
                        self.message.clear();
                        self.closing = true;
                        self.sending = None;
                        return None;
                    }
                    Poll::Ready(true) => {}
                }
                self.sending = None;
                moved = true;
            }
            let from = self.from.as_ref()?;
            if let Some(message) = self.messages.pop_front() {
                let from = from.clone();
                self.sending = Some(Box::pin(async move { from.send(message).await.is_ok() }));
                continue;
            }
            if self.closing {
                self.from = None;
                return None;
            }
            return Some(moved);
        }
    }

    fn read_blocked(&self) -> bool {
        self.closing || self.sending.is_some() || !self.messages.is_empty()
    }
}

fn configured_body_limit() -> u64 {
    busbar_kernel::config::limits::installed().map_or(
        busbar_kernel::config::limits::DEFAULT_REQUEST_BODY_MAX_BYTES as u64,
        |limits| limits.request_body_max_bytes as u64,
    )
}

pub(super) async fn serve<I>(
    io: I,
    framer: DataFramer,
    router: Router,
    secured: bool,
    timeout: std::time::Duration,
    mut stop: tokio::sync::watch::Receiver<bool>,
) where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let established = Established {
        scheme: Established::scheme_of(secured),
        claim: Some(framer.scheme.clone()),
        ..Established::default()
    };
    let Some(guests) = framer.guests() else {
        tracing::debug!("data door: no guest list could be lent; the connection is dropped");
        return;
    };
    let (framing, y) = match Framing::begin_lent(
        Arc::clone(&framer.door),
        SIDE_ACCEPT,
        "",
        &established,
        Some(guests),
    ) {
        Ok(begun) => begun,
        Err(e) => {
            tracing::debug!(error = %e, "data door: the framer would not frame the connection");
            return;
        }
    };
    let (tx, ops) = mpsc::unbounded_channel();
    let (admission_tx, admissions) = mpsc::unbounded_channel();
    let mut conn = Conn {
        io: super::Lingering(Some(io)),
        framing: Some(framing),
        framer,
        router,
        secured,
        established,
        timeout,
        out: VecDeque::new(),
        read_done: false,
        ended: false,
        heads: HashMap::new(),
        inflows: HashMap::new(),
        tasks: tokio::task::JoinSet::new(),
        ops,
        tx,
        pending: VecDeque::new(),
        admission_tx,
        admissions,
        staged: None,
        full: HashSet::new(),
        deadline: None,
        session: None,
        agreed: 0,
        stopping: *stop.borrow(),
        failed: false,
        first_byte: Some(Box::pin(tokio::time::sleep(FIRST_BYTE_BOUND))),
    };
    conn.absorb(y);
    loop {
        tokio::select! {
            () = std::future::poll_fn(|cx| conn.poll(cx)) => break,
            changed = stop.changed(), if !conn.stopping => {
                conn.stopping = changed.is_err() || *stop.borrow();
            }
        }
    }
}

struct Conn<I: AsyncRead + AsyncWrite + Unpin + Send + 'static> {
    io: super::Lingering<I>,
    framing: Option<Framing>,
    framer: DataFramer,
    router: Router,
    secured: bool,
    established: Established,
    timeout: std::time::Duration,

    out: VecDeque<u8>,

    read_done: bool,

    ended: bool,

    heads: HashMap<u64, Head>,
    inflows: HashMap<u64, Inflow>,
    tasks: tokio::task::JoinSet<()>,
    ops: mpsc::UnboundedReceiver<(u64, Op)>,
    tx: mpsc::UnboundedSender<(u64, Op)>,
    pending: VecDeque<(u64, Op)>,

    admission_tx: mpsc::UnboundedSender<busbar_kernel::plane_routes::SessionAdmission>,
    admissions: mpsc::UnboundedReceiver<busbar_kernel::plane_routes::SessionAdmission>,
    staged: Option<StagedUpgrade>,

    full: HashSet<u64>,
    deadline: Option<Pin<Box<tokio::time::Sleep>>>,
    session: Option<Session>,

    agreed: u32,
    stopping: bool,

    failed: bool,

    first_byte: Option<Pin<Box<tokio::time::Sleep>>>,
}

struct StagedUpgrade {
    stream: u64,
    yielded: Yielded,
    incoming: Vec<u8>,
    bound: Pin<Box<tokio::time::Sleep>>,
}

enum Step {
    Done,
    Wait,
}

impl<I: AsyncRead + AsyncWrite + Unpin + Send + 'static> Conn<I> {
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        loop {
            let mut moved = false;
            if self.stopping && self.staged.is_some() {
                self.abandon_stage();
            }
            while let Poll::Ready(Some(admission)) = self.admissions.poll_recv(cx) {
                self.pending.push_back((
                    admission.stream,
                    Op::Admit {
                        reply: admission.reply,
                    },
                ));
            }
            while let Poll::Ready(Some(op)) = self.ops.poll_recv(cx) {
                self.pending.push_back(op);
            }
            while let Poll::Ready(Some(_)) = self.tasks.poll_join_next(cx) {
                moved = true;
            }
            if self.failed || self.framing.is_none() {
                self.tasks.abort_all();
                return self.close(cx);
            }
            moved |= self.parked(cx);
            while !self.pending.is_empty() {
                match self.apply_front() {
                    Step::Done => moved = true,
                    Step::Wait => break,
                }
            }
            if self.session.is_some() {
                match self.pump_session(cx) {
                    Some(m) => moved |= m,
                    None => {
                        self.ended = true;
                        self.session = None;
                        self.tasks.abort_all();

                        return self.close(cx);
                    }
                }
            }
            moved |= self.flush(cx);
            if !self.read_done && self.out.len() < 2 * WRITE_ROOM {
                moved |= self.read(cx);
            }
            moved |= self.timer(cx);
            if let Some(bound) = self.first_byte.as_mut() {
                if std::future::Future::poll(bound.as_mut(), cx).is_ready() {
                    tracing::debug!("data door: no byte arrived within the first-byte bound");
                    self.first_byte = None;
                    self.failed = true;
                    continue;
                }
            }
            let idle = self.tasks.is_empty()
                && self.pending.is_empty()
                && self.session.is_none()
                && self.staged.is_none()
                && !self.framing.as_ref().is_some_and(Framing::parked);
            if self.failed || (idle && (self.ended || self.read_done || self.stopping)) {
                return self.close(cx);
            }
            if !moved {
                return Poll::Pending;
            }
        }
    }

    fn close(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if let Some(framing) = self.framing.take() {
            let reason = if self.stopping {
                CLOSE_DRAIN
            } else {
                CLOSE_NORMAL
            };
            let y = framing.finish(reason);
            if self.staged.take().is_none() {
                self.out.extend(y.wire.iter().copied());
            }
        }
        while !self.out.is_empty() && !self.failed {
            match self.write_some(cx) {
                Poll::Ready(true) => {}
                Poll::Ready(false) => break,
                Poll::Pending => return Poll::Pending,
            }
        }
        if !self.failed && Pin::new(&mut self.io).poll_flush(cx).is_pending() {
            return Poll::Pending;
        }
        Poll::Ready(())
    }

    fn absorb(&mut self, mut y: Yielded) {
        self.out.extend(y.wire.iter().copied());
        for head in std::mem::take(&mut y.heads) {
            self.heads.insert(head.stream, head);
        }
        if y.agreed != 0 {
            self.agreed = y.agreed;
        }
        for flow in &y.flow {
            match flow {
                framer::StreamFlow::Full(stream) => {
                    self.full.insert(*stream);
                }
                framer::StreamFlow::Writable(stream) => {
                    self.full.remove(stream);
                }
            }
        }
        for g in y.pieces.iter().filter(|g| g.ends_stream() || g.failed) {
            self.full.remove(&g.stream);
        }
        for piece in std::mem::take(&mut y.pieces) {
            self.piece(piece);
        }
        self.deadline = y.deadline_ns.map(|ns| {
            Box::pin(tokio::time::sleep_until(tokio::time::Instant::from_std(
                framer::instant_of(ns),
            )))
        });
        if y.ended {
            self.ended = true;
        }
    }

    fn took(&mut self, r: Result<Yielded, framer::Refused>) -> bool {
        match r {
            Ok(y) => {
                self.absorb(y);
                true
            }
            Err(e) => {
                tracing::debug!(error = %e, "data door: the framing failed");
                self.failed = true;
                false
            }
        }
    }

    fn parked(&mut self, cx: &mut Context<'_>) -> bool {
        let Some(framing) = self.framing.as_mut().filter(|f| f.parked()) else {
            return false;
        };
        match framing.poll_parked(cx) {
            Poll::Ready(r) => self.took(r),
            Poll::Pending => false,
        }
    }

    fn read(&mut self, cx: &mut Context<'_>) -> bool {
        if self.staged.is_some() {
            return self.read_staged(cx);
        }
        if self.framing.as_ref().is_some_and(Framing::begin_parked)
            || self.session.as_ref().is_some_and(Session::read_blocked)
        {
            return false;
        }
        let mut buf = [0_u8; READ_CHUNK];
        let mut rb = ReadBuf::new(&mut buf);
        match Pin::new(&mut self.io).poll_read(cx, &mut rb) {
            Poll::Ready(Ok(())) => {
                let n = rb.filled().len();
                let end = n == 0;
                if n > 0 {
                    self.first_byte = None;
                }
                self.read_done = end;
                let Some(framing) = self.framing.as_mut() else {
                    return false;
                };
                let r = framing.ingest(&buf[..n], end);
                self.took(r);
                if end {
                    for inflow in self.inflows.values_mut() {
                        inflow.body = None;
                    }
                    if let Some(s) = self.session.as_mut() {
                        s.closing = true;
                    }
                }
                true
            }
            Poll::Ready(Err(e)) => {
                tracing::debug!(error = %e, "data door: the connection failed");
                self.failed = true;
                true
            }
            Poll::Pending => false,
        }
    }

    fn read_staged(&mut self, cx: &mut Context<'_>) -> bool {
        if self
            .staged
            .as_ref()
            .is_none_or(|stage| stage.incoming.len() >= WRITE_ROOM)
        {
            return false;
        }
        let remaining = self
            .staged
            .as_ref()
            .map_or(0, |stage| WRITE_ROOM - stage.incoming.len());
        let mut bytes = [0_u8; READ_CHUNK];
        let mut buffer = ReadBuf::new(&mut bytes[..remaining.min(READ_CHUNK)]);
        match Pin::new(&mut self.io).poll_read(cx, &mut buffer) {
            Poll::Ready(Ok(())) if buffer.filled().is_empty() => {
                self.read_done = true;
                self.abandon_stage();
                true
            }
            Poll::Ready(Ok(())) => {
                if let Some(stage) = self.staged.as_mut() {
                    stage.incoming.extend_from_slice(buffer.filled());
                }
                true
            }
            Poll::Ready(Err(_)) => {
                self.abandon_stage();
                true
            }
            Poll::Pending => false,
        }
    }

    fn abandon_stage(&mut self) {
        self.staged.take();
        if let Some(framing) = self.framing.take() {
            // No handshake was published, so none of the provisional finish bytes may escape.
            let _ = framing.finish(CLOSE_NORMAL);
        }
        self.ended = true;
    }

    fn flush(&mut self, cx: &mut Context<'_>) -> bool {
        let mut moved = false;
        while !self.out.is_empty() {
            match self.write_some(cx) {
                Poll::Ready(true) => moved = true,
                Poll::Ready(false) => return true,
                Poll::Pending => return moved,
            }
        }
        if moved {
            let _ = Pin::new(&mut self.io).poll_flush(cx);
        }
        moved
    }

    fn write_some(&mut self, cx: &mut Context<'_>) -> Poll<bool> {
        let (front, _) = self.out.as_slices();
        match Pin::new(&mut self.io).poll_write(cx, front) {
            Poll::Ready(Ok(0)) | Poll::Ready(Err(_)) => {
                self.failed = true;
                self.out.clear();
                Poll::Ready(false)
            }
            Poll::Ready(Ok(n)) => {
                self.out.drain(..n);
                Poll::Ready(true)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn timer(&mut self, cx: &mut Context<'_>) -> bool {
        if let Some(stage) = self.staged.as_mut() {
            if std::future::Future::poll(stage.bound.as_mut(), cx).is_ready() {
                self.abandon_stage();
                return true;
            }
            return false;
        }
        let Some(sleep) = self.deadline.as_mut() else {
            return false;
        };
        if std::future::Future::poll(sleep.as_mut(), cx).is_pending() {
            return false;
        }
        self.deadline = None;
        let Some(framing) = self.framing.as_mut() else {
            return false;
        };
        let r = framing.timer();
        self.took(r);
        true
    }

    fn piece(&mut self, piece: Got) {
        if self.failed {
            return;
        }
        if let Some(session) = self.session.as_mut() {
            session.stream = piece.stream;
            if piece.failed {
                session.from = None;
                session.messages.clear();
                session.sending = None;
                session.message.clear();
                session.closing = true;
                return;
            }
            if session.closing {
                return;
            }
            let size = session.message.len().checked_add(piece.bytes.len());
            if size.is_none_or(|size| session.body_limit != 0 && size as u64 > session.body_limit) {
                self.failed = true;
                return;
            }
            session.message.extend_from_slice(&piece.bytes);
            if piece.end_of_frame {
                let message = std::mem::take(&mut session.message);
                session.messages.push_back(message);
            }
            session.closing |= piece.end;
            return;
        }
        match self.inflows.get_mut(&piece.stream) {
            None if piece.fields && !piece.failed => self.head(&piece),
            None if piece.failed => {
                self.heads.remove(&piece.stream);
                if let Some(scope) = self.framing.as_ref().and_then(Framing::scope) {
                    scope.stream_ended(piece.stream);
                }
            }

            None => {}
            Some(inflow) => {
                if inflow.refused {
                    return;
                }
                if piece.failed {
                    if let Some(body) = inflow.body.take() {
                        let reason = String::from_utf8_lossy(&piece.bytes).into_owned();
                        let _ = body.send(Err(BodyError::from(reason)));
                    }
                    inflow.task.abort();
                    return;
                }

                if !piece.fields && !piece.bytes.is_empty() {
                    if inflow
                        .body
                        .as_ref()
                        .is_none_or(mpsc::UnboundedSender::is_closed)
                    {
                        return;
                    }
                    let received = inflow.received.checked_add(piece.bytes.len() as u64);
                    if received.is_none_or(|n| inflow.body_limit != 0 && n > inflow.body_limit) {
                        inflow.refused = true;
                        inflow.body = None;
                        inflow.task.abort();
                        self.pending.push_back((
                            piece.stream,
                            Op::Refuse {
                                status: BODY_LIMIT_REFUSAL,
                                head_sent: inflow.head_sent,
                            },
                        ));
                        return;
                    }
                    inflow.received = received.expect("checked above");
                    if let Some(body) = &inflow.body {
                        let _ = body.send(Ok(Bytes::from(piece.bytes)));
                    }
                }
                if piece.end {
                    inflow.body = None;
                }
            }
        }
    }

    fn head(&mut self, piece: &Got) {
        let stream = piece.stream;
        let mut body_limit = configured_body_limit();
        let head = self.heads.remove(&stream).unwrap_or_default();
        let h2 = self.framer.is_h2(self.agreed);
        let (body_tx, body_rx) = mpsc::unbounded_channel();
        let end = piece.end;
        let body = InboundBody {
            pieces: body_rx,
            ended: end,
        };
        let out = Emitter {
            stream,
            tx: self.tx.clone(),
        };
        let slot = SessionSlot::with_admission(self.admission_tx.clone(), stream);
        let scope = self.framing.as_ref().and_then(Framing::scope).cloned();
        let request = request_of(
            &head,
            &piece.bytes,
            h2,
            self.secured,
            AxumBody::new(super::TimeoutBody::new(body, self.timeout)),
        );
        let task = match request {
            Some(mut req) => {
                if let Some(scope) = scope.as_ref().filter(|scope| scope.listener() != 0) {
                    let request_head = busbar_kernel::inbound::Head {
                        method: req.method().as_str().to_owned(),
                        target: req.uri().path().to_owned(),
                        authority: head
                            .authority
                            .as_deref()
                            .and_then(|bytes| std::str::from_utf8(bytes).ok())
                            .map(str::to_owned)
                            .unwrap_or_else(|| {
                                req.headers()
                                    .get(axum::http::header::HOST)
                                    .and_then(|value| value.to_str().ok())
                                    .unwrap_or_default()
                                    .to_owned()
                            }),
                        query: req.uri().query().map(str::to_owned),
                        fields: req
                            .headers()
                            .iter()
                            .map(|(name, value)| {
                                (name.as_str().to_owned(), value.as_bytes().to_vec())
                            })
                            .collect(),
                    };
                    match crate::root::inbound::host().claim_request(
                        scope.owner(),
                        scope.leg(),
                        stream,
                        &request_head,
                    ) {
                        Ok(admission) => {
                            body_limit = admission.body_limit();
                            scope.admit_stream(stream);
                            req.extensions_mut().insert(admission);
                        }
                        Err(_) => {
                            out.send(Op::Refuse {
                                status: 401,
                                head_sent: false,
                            });
                            out.send(Op::Ended {
                                scope: Some(Arc::clone(scope)),
                            });
                            return;
                        }
                    }
                }
                req.extensions_mut()
                    .insert(super::listener_scheme(self.secured));
                req.extensions_mut().insert(slot.clone());

                let defer = h2
                    && !end
                    && matches!(
                        *req.method(),
                        Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
                    );

                let end = StreamEnd(out.clone(), scope);
                self.tasks.spawn(serve_stream(
                    self.router.clone(),
                    req,
                    defer,
                    slot,
                    out,
                    end,
                ))
            }
            None => {
                out.send(Op::Refuse {
                    status: 400,
                    head_sent: false,
                });
                out.send(Op::Ended { scope });
                return;
            }
        };
        self.inflows.insert(
            stream,
            Inflow {
                body: (!end).then_some(body_tx),
                task,
                body_limit,
                received: 0,
                refused: false,
                refusal_sent: false,
                head_sent: false,
            },
        );
    }

    fn apply_front(&mut self) -> Step {
        let mut blocked = HashSet::new();
        let mut next = None;
        let framing = self.framing.as_ref();
        for (index, (stream, op)) in self.pending.iter().enumerate() {
            if self
                .inflows
                .get(stream)
                .is_some_and(|inflow| inflow.refused)
                && matches!(
                    op,
                    Op::Head { .. } | Op::Data { .. } | Op::Trailers { .. } | Op::Switch { .. }
                )
            {
                next = Some(index);
                break;
            }

            if matches!(op, Op::Switch { .. } | Op::Admit { .. }) {
                if index == 0 && !framing.is_some_and(Framing::parked) {
                    next = Some(index);
                }
                break;
            }
            let waits = framing.is_some_and(|framing| framing.holds(*stream))
                || matches!(op, Op::Head { .. } | Op::Data { .. } | Op::Trailers { .. })
                    && (self.out.len() >= WRITE_ROOM || self.full.contains(stream));
            if waits || blocked.contains(stream) {
                blocked.insert(*stream);
                continue;
            }
            next = Some(index);
            break;
        }
        let Some(index) = next else {
            return Step::Wait;
        };
        let Some((stream, op)) = self.pending.remove(index) else {
            return Step::Wait;
        };
        if self
            .inflows
            .get(&stream)
            .is_some_and(|inflow| inflow.refused)
        {
            match op {
                Op::Head { done, .. } | Op::Data { done, .. } | Op::Trailers { done, .. } => {
                    let _ = done.send(false);
                    return Step::Done;
                }
                Op::Switch { .. } => return Step::Done,
                Op::Admit { reply } => {
                    let _ = reply.send(false);
                    return Step::Done;
                }
                _ => {}
            }
        }
        if let Op::Admit { reply } = op {
            let admitted = self.stage_upgrade(stream);
            if reply.send(admitted).is_err() && admitted {
                self.abandon_stage();
            }
            return Step::Done;
        }
        if matches!(op, Op::Head { .. } | Op::Refuse { .. }) {
            // A plane response replaces the withheld transport handshake.
            self.staged.take();
        }
        let Some(framing) = self.framing.as_mut() else {
            return Step::Done;
        };
        match op {
            Op::Admit { .. } => unreachable!("admission is processed before the framing borrow"),
            Op::Head {
                status,
                fields,
                end,
                done,
            } => {
                let r = framing.emit_head(stream, &fields, end, status);
                let ok = self.took(r);
                if ok {
                    if let Some(inflow) = self.inflows.get_mut(&stream) {
                        inflow.head_sent = true;
                    }
                }
                let _ = done.send(ok);
            }
            Op::Data { bytes, end, done } => {
                let r = framing.emit(stream, &bytes, end, false);
                let ok = self.took(r);
                let _ = done.send(ok);
            }
            Op::Trailers { fields, done } => {
                let r = framing.emit_trailers(stream, &fields);
                let ok = self.took(r);
                let _ = done.send(ok);
            }
            Op::Refuse { status, head_sent } => {
                if let Some(inflow) = self.inflows.get_mut(&stream).filter(|i| i.refused) {
                    if status != BODY_LIMIT_REFUSAL || inflow.refusal_sent {
                        return Step::Done;
                    }
                    inflow.refusal_sent = true;
                }
                let r = framing.refuse(Some(stream), &[], status, head_sent);
                self.took(r);
            }
            Op::Switch { pipe } => self.switch(stream, pipe),
            Op::Ended { scope } => {
                if self
                    .staged
                    .as_ref()
                    .is_some_and(|stage| stage.stream == stream)
                {
                    self.abandon_stage();
                }
                self.inflows.remove(&stream);
                self.full.remove(&stream);
                if let Some(scope) = scope {
                    scope.stream_ended(stream);
                }
            }
        }
        Step::Done
    }

    fn stage_upgrade(&mut self, stream: u64) -> bool {
        if self.staged.is_some() || self.session.is_some() {
            return false;
        }
        let claim = UPGRADE_CLAIMS[usize::from(self.secured)];
        let Some(door) = (self.framer.upgrade)(claim) else {
            return false;
        };
        let Some(framing) = self.framing.take() else {
            return false;
        };
        let leftover = match framing.detach() {
            Ok(left) => left,
            Err(e) => {
                tracing::debug!(error = %e, "data door: the framer would not release the opening");
                self.failed = true;
                return false;
            }
        };
        self.established.claim = door.facts().claims.first().map(|c| (*c).to_owned());
        match Framing::adopt_detached(door, SIDE_ACCEPT, leftover, &self.established) {
            Ok((framing, mut yielded)) => {
                self.framing = Some(framing);
                let accepted = !yielded.ended
                    && yielded.pieces.iter().any(|piece| {
                        piece.stream == stream
                            && piece.fields
                            && piece.status_code == Some(u32::from(SWITCHING_PROTOCOLS))
                            && piece.status_class == busbar_contract::abi::transport::STATUS_SUCCESS
                            && !piece.failed
                    });
                if !accepted {
                    // The transport owns malformed-opening responses. No plane is entered.
                    if let Some(inflow) = self.inflows.get_mut(&stream) {
                        inflow.refused = true;
                    }
                    if yielded.ended {
                        self.absorb(yielded);
                    } else {
                        self.failed = true;
                    }
                    return false;
                }
                // This head is the transport's admission receipt, not an application message.
                yielded.pieces.retain(|piece| !piece.fields);
                yielded.heads.clear();
                self.deadline = None;
                self.staged = Some(StagedUpgrade {
                    stream,
                    yielded,
                    incoming: Vec::new(),
                    bound: Box::pin(tokio::time::sleep(self.timeout)),
                });
                true
            }
            Err(e) => {
                tracing::debug!(error = %e, "data door: the session opening was refused");
                self.failed = true;
                false
            }
        }
    }

    fn switch(&mut self, stream: u64, pipe: busbar_kernel::plane_routes::SessionPipe) {
        let Some(staged) = self.staged.take().filter(|staged| staged.stream == stream) else {
            // Only a route that awaited this request's admission may publish a session.
            self.failed = true;
            return;
        };
        let Some(framing) = self.framing.as_mut() else {
            self.failed = true;
            return;
        };
        let committed = framing.emit_head(stream, &[], true, u32::from(SWITCHING_PROTOCOLS));
        let Ok(committed) = committed else {
            self.failed = true;
            return;
        };
        self.heads.clear();
        self.full.clear();
        let mut session = Session::over(stream, pipe);
        if let Some(inflow) = self.inflows.get(&stream) {
            session.body_limit = inflow.body_limit;
        }
        self.session = Some(session);
        self.absorb(staged.yielded);
        self.absorb(committed);
        if !staged.incoming.is_empty() {
            if let Some(framing) = self.framing.as_mut() {
                let received = framing.ingest(&staged.incoming, false);
                self.took(received);
            }
        }
    }

    fn pump_session(&mut self, cx: &mut Context<'_>) -> Option<bool> {
        let mut moved = self.session.as_mut()?.deliver(cx)?;
        loop {
            if self.out.len() >= WRITE_ROOM {
                return Some(moved);
            }
            let session = self.session.as_mut()?;
            let framing = self.framing.as_mut()?;
            if framing.begin_parked()
                || framing.holds(session.stream)
                || self.full.contains(&session.stream)
            {
                return Some(moved);
            }
            if let Some((bytes, text)) = session.writing.take() {
                let stream = session.stream;
                let r = framing.emit(stream, &bytes, true, text);
                if !self.took(r) {
                    return None;
                }
                moved = true;
                continue;
            }
            match session.to.poll_recv(cx) {
                Poll::Ready(Some(out)) => {
                    session.writing = Some((Bytes::from(out.bytes), out.text));
                    moved = true;
                }
                Poll::Ready(None) => return None,
                Poll::Pending => return Some(moved),
            }
        }
    }
}

fn request_of(
    head: &Head,
    block: &[u8],
    h2: bool,
    secured: bool,
    body: AxumBody,
) -> Option<Request<AxumBody>> {
    let method = Method::from_bytes(head.method.as_deref()?).ok()?;
    let target = std::str::from_utf8(head.target.as_deref()?).ok()?;
    let mut headers = HeaderMap::new();
    for (name, value) in fields::lines(block) {
        if let (Ok(name), Ok(value)) =
            (HeaderName::from_bytes(name), HeaderValue::from_bytes(value))
        {
            headers.append(name, value);
        }
    }
    let authority = head
        .authority
        .as_deref()
        .and_then(|a| std::str::from_utf8(a).ok())
        .filter(|a| !a.is_empty());
    let uri = match authority {
        Some(a) if h2 && !headers.contains_key(axum::http::header::HOST) => {
            let scheme = if secured { "https" } else { "http" };
            Uri::try_from(format!("{scheme}://{a}{target}")).ok()?
        }
        _ => Uri::try_from(target).ok()?,
    };
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .version(if h2 {
            Version::HTTP_2
        } else {
            Version::HTTP_11
        })
        .body(body)
        .ok()?;
    *req.headers_mut() = headers;
    Some(req)
}

async fn serve_stream(
    router: Router,
    req: Request<AxumBody>,
    defer: bool,
    slot: SessionSlot,
    out: Emitter,
    _end: StreamEnd,
) {
    let req = if defer {
        let (parts, body) = req.into_parts();
        match read_whole(body).await {
            Ok(bytes) => Request::from_parts(parts, AxumBody::from(bytes)),
            Err(status) => {
                respond(&out, super::status_response(status)).await;
                return;
            }
        }
    } else {
        req
    };
    let Ok(response) = {
        use hyper::service::Service as _;
        hyper_util::service::TowerToHyperService::new(router)
            .call(req)
            .await
    };
    if response.status().as_u16() == SWITCHING_PROTOCOLS {
        if let Some(pipe) = slot.take() {
            out.send(Op::Switch { pipe });
            return;
        }
    }
    respond(&out, response).await;
}

async fn read_whole(mut body: AxumBody) -> Result<Bytes, axum::http::StatusCode> {
    let cap = busbar_kernel_egress::upstream::max_translate_body_bytes();
    let mut whole = bytes::BytesMut::new();
    loop {
        match std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await {
            None => return Ok(whole.freeze()),
            Some(Err(_)) => return Err(axum::http::StatusCode::BAD_REQUEST),
            Some(Ok(frame)) => {
                if let Ok(data) = frame.into_data() {
                    if whole.len() + data.len() > cap {
                        return Err(axum::http::StatusCode::PAYLOAD_TOO_LARGE);
                    }
                    whole.extend_from_slice(&data);
                }
            }
        }
    }
}

fn head_block(status: u16, headers: &HeaderMap, exact: Option<u64>) -> Vec<u8> {
    let mut block = field_block(headers);
    let bodyless = status < 200 || status == 204 || status == 304;
    let stated = headers.contains_key(axum::http::header::CONTENT_LENGTH)
        || headers.contains_key(axum::http::header::TRANSFER_ENCODING);
    if let Some(len) =
        exact.filter(|_| !bodyless && !stated && !headers.contains_key(axum::http::header::TRAILER))
    {
        block.extend_from_slice(b"content-length");
        block.extend_from_slice(fields::SEPARATOR);
        block.extend_from_slice(len.to_string().as_bytes());
        block.extend_from_slice(fields::LINE_END);
    }
    block
}

fn field_block(headers: &HeaderMap) -> Vec<u8> {
    let mut block = Vec::new();
    for (name, value) in headers {
        block.extend_from_slice(name.as_str().as_bytes());
        block.extend_from_slice(fields::SEPARATOR);
        block.extend_from_slice(value.as_bytes());
        block.extend_from_slice(fields::LINE_END);
    }
    block
}

async fn respond(out: &Emitter, response: Response<AxumBody>) {
    let (parts, mut body) = response.into_parts();
    let status = parts.status.as_u16();
    let block = head_block(status, &parts.headers, body.size_hint().exact());
    let end = body.is_end_stream();
    if !out.head(u32::from(status), block, end).await || end {
        return;
    }
    loop {
        match std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await {
            None => {
                let _ = out.data(Bytes::new(), true).await;
                return;
            }
            Some(Ok(frame)) => match frame.into_data() {
                Ok(data) => {
                    if !data.is_empty() && !out.data(data, false).await {
                        return;
                    }
                }
                Err(frame) => {
                    if let Ok(trailers) = frame.into_trailers() {
                        let _ = out.trailers(field_block(&trailers)).await;
                        return;
                    }
                }
            },
            Some(Err(e)) => {
                tracing::debug!(error = %e, "data door: an answer's body failed after its head");
                out.send(Op::Refuse {
                    status: u32::from(status),
                    head_sent: true,
                });
                return;
            }
        }
    }
}

#[cfg(test)]
#[path = "tests/listener_framed_tests.rs"]
mod tests;
