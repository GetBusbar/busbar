// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DATA LISTENER SERVED THROUGH ITS FRAMER'S ACCEPT SIDE (`BUSBAR-1.6.0.md`, inbound
//! listeners: per accepted connection the framer's accept side runs, under the connection security
//! the connector prepared; INBOUND-LISTEN).
//!
//! The data listener's framer is found by facts ([`data_framer`]): the framer the connector serves
//! the listener's scheme with, whose tail states it accepts (`FACT_ACCEPTS`). Each connection the
//! listener admits is secured as before (the connector's prepared connection security), then
//! FRAMED: its bytes go to the framer's `ingest`, the framer's wire bytes go back to the socket, and
//! the framer's pieces are the requests. The framing is begun on `SIDE_ACCEPT`, lent the listener's
//! guest list: ONE line whose auth is `none`, taking every method on every path, whose ref is the
//! host's ([`busbar_plugin_loader::dispatch::auth_handle::lend_none_line`]). The data router's own
//! auth judges every request, as it always has.
//!
//! Each request's head comes up as one field block with its method, target and authority in the
//! stream's head slots; its body as the pieces that follow. The request is served by the data
//! router in process, on its own task, and its answer goes down through the framer: the head as a
//! field block with the status on the same emit, then the body bytes, the last ending the frame.
//! An answer that switches protocols to an admitted session hands the connection, as it was sent,
//! to the framer that claims the upgrade (`detach`, then that framer's `adopt`), and the session's
//! messages ride it.
//!
//! The body time bounds are the listener's ([`super::TimeoutBody`]), the close lingers as the hyper
//! loop's did ([`super::Lingering`]), and a draining listener ends each connection once nothing is
//! in flight on it.

use std::collections::{HashMap, HashSet, VecDeque};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::Body as AxumBody;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, Uri, Version};
use axum::Router;
use busbar_contract::abi::transport::route::{METHOD_ANY, PATH_CONTAINS};
use busbar_contract::abi::transport::{
    fields, CLOSE_DRAIN, CLOSE_NORMAL, ROLE_FRAMER, SIDE_ACCEPT,
};
use busbar_core_connector::framer::{
    self, Established, FramerDoor, Framing, Got, GuestLine, GuestLines, Head, Yielded,
};
use bytes::Bytes;
use http_body::{Body as _, Frame};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot};

/// The scheme the data listener is framed under, by the claim its framer answers.
pub const DATA_SCHEME: &str = "http";

/// The claim of the framer an admitted session's upgrade is handed to, in the clear and secured.
const UPGRADE_CLAIMS: [&str; 2] = ["ws", "wss"];

/// The one guest-list line the data listener lends its framer.
pub const DATA_LINE: u32 = 1;

/// The id of that line's auth ref: the host's, owner-scoped to the framer's instance.
pub const DATA_LINE_REF: u64 = 0x6461_7461_6c69_6e65;

/// How many socket bytes one read takes.
const READ_CHUNK: usize = 16 * 1024;

/// The most bytes held for the socket before the next answer is framed: past it, answers wait for
/// the socket to drain.
const WRITE_ROOM: usize = 256 * 1024;

/// THE FIRST-BYTE BOUND: a connection that sends no byte within it is closed, unanswered, as the
/// hyper loop's HTTP/1 header read bound (30 s) closed one. An accepting framer states no deadline
/// at `begin`, so the bound is the listener's.
pub const FIRST_BYTE_BOUND: std::time::Duration = std::time::Duration::from_secs(30);

/// The status an answer that switches protocols carries.
const SWITCHING_PROTOCOLS: u16 = 101;

/// The framer the connector serves a scheme with, where it serves one.
pub type FramerFor = Arc<dyn Fn(&str) -> Option<Arc<dyn FramerDoor>> + Send + Sync>;

/// THE DATA LISTENER'S FRAMER: the framer entry, its instance, and the protocols its accepting
/// side offers (what its stated agreed position names).
#[derive(Clone)]
pub struct DataFramer {
    door: Arc<dyn FramerDoor>,
    owner: u64,
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

/// THE DATA LISTENER'S FRAMER, FOUND BY FACTS: the framer `framer_for` answers [`DATA_SCHEME`]
/// with, a stream FRAMER whose tail states it accepts, opened by the host (it has an instance).
/// `None` = the build serves no such framer.
pub fn data_framer(framer_for: FramerFor) -> Option<DataFramer> {
    let door = framer_for(DATA_SCHEME)?;
    let facts = door.facts();
    if facts.role != ROLE_FRAMER || facts.datagram || !door.accepts() {
        return None;
    }
    let owner = door.instance().filter(|o| *o != 0)?;
    let offer = framer::accept_offer(door.as_ref()).unwrap_or_default();
    Some(DataFramer {
        door,
        owner,
        offer,
        upgrade: framer_for,
    })
}

impl DataFramer {
    /// The framer entry.
    #[must_use]
    pub fn door(&self) -> &Arc<dyn FramerDoor> {
        &self.door
    }

    /// The listener's guest list, lent at each accept: its one `none` line, its ref minted at the
    /// generation published now. `None` when the host's key cannot be drawn.
    fn guests(&self) -> Option<Arc<GuestLines>> {
        let auth =
            crate::root::loader::dispatch::auth_handle::lend_none_line(self.owner, DATA_LINE_REF)?;
        Some(Arc::new(GuestLines::new(vec![GuestLine {
            line: DATA_LINE,
            points: 0,
            auth,
            body_limit: 0,
            methods: METHOD_ANY,
            path_form: PATH_CONTAINS,
            path: "/".to_owned(),
            fields: Vec::new(),
            rung: 0,
        }])))
    }

    /// Whether the protocol at 1-based `position` of the accepting offer is HTTP/2.
    fn is_h2(&self, position: u32) -> bool {
        position != 0
            && self
                .offer
                .get(position as usize - 1)
                .is_some_and(|p| p.as_slice() == b"h2")
    }
}

// ── one stream's asks of its connection ──────────────────────────────────────────────────────────

/// What a stream's task asks of its connection, in order.
enum Op {
    /// The answer's head: its status and field block; `end` = no body follows.
    Head {
        status: u32,
        fields: Vec<u8>,
        end: bool,
        done: oneshot::Sender<bool>,
    },
    /// Body bytes; `end` = the answer is whole.
    Data {
        bytes: Bytes,
        end: bool,
        done: oneshot::Sender<bool>,
    },
    /// The stream failed before or after its head: the framer ends it.
    Refuse { status: u32, head_sent: bool },
    /// The connection switches to the upgrade's framer, the admitted session carried over it.
    Switch {
        pipe: busbar_kernel::plane_routes::SessionPipe,
    },
    /// The stream's task ended.
    Ended,
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

    fn send(&self, op: Op) {
        let _ = self.tx.send((self.stream, op));
    }
}

/// A stream's end, however its task ends (answered, failed, or aborted).
struct StreamEnd(Emitter);

impl Drop for StreamEnd {
    fn drop(&mut self) {
        self.0.send(Op::Ended);
    }
}

/// A request body's error, as the router reads one.
type BodyError = Box<dyn std::error::Error + Send + Sync>;

/// One request's inflow: where its body pieces go, and its task.
struct Inflow {
    body: Option<mpsc::UnboundedSender<Result<Bytes, BodyError>>>,
    task: tokio::task::AbortHandle,
}

/// A REQUEST BODY as its pieces arrive on the connection.
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

/// WHERE AN ADMITTED SESSION'S PIPE IS LEFT for the framed connection to carry
/// ([`busbar_kernel::plane_routes::FramedSession`]), one per request.
type SessionSlot = busbar_kernel::plane_routes::FramedSession;

/// A connection SWITCHED to a session's framer: the caller's messages on their way to the session,
/// the frames the session writes toward the caller, and the frame being written.
struct Session {
    stream: u64,
    from: Option<mpsc::UnboundedSender<Vec<u8>>>,
    message: Vec<u8>,
    to: mpsc::Receiver<busbar_kernel::plane_routes::SessionOut>,
    writing: Option<(Bytes, bool)>,
}

impl Session {
    fn over(stream: u64, pipe: busbar_kernel::plane_routes::SessionPipe) -> Self {
        let busbar_kernel::plane_routes::SessionPipe {
            from_caller,
            to_caller,
        } = pipe;
        let (from, mut messages) = mpsc::unbounded_channel::<Vec<u8>>();
        drop(tokio::spawn(async move {
            while let Some(message) = messages.recv().await {
                if from_caller.send(message).await.is_err() {
                    break;
                }
            }
        }));
        Self {
            stream,
            from: Some(from),
            message: Vec::new(),
            to: to_caller,
            writing: None,
        }
    }
}

// ── one connection ───────────────────────────────────────────────────────────────────────────────

/// SERVE ONE CONNECTION'S (already secured) bytes `io` through `framer`'s accept side, each request
/// by `router`, until the connection ends; `stop` flips when the listener drains.
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
        claim: Some(DATA_SCHEME.to_owned()),
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

/// One connection's serving state ([`serve`]).
struct Conn<I: AsyncRead + AsyncWrite + Unpin + Send + 'static> {
    io: super::Lingering<I>,
    framing: Option<Framing>,
    framer: DataFramer,
    router: Router,
    secured: bool,
    established: Established,
    timeout: std::time::Duration,
    /// Bytes owed to the socket.
    out: VecDeque<u8>,
    /// The far end ended its side.
    read_done: bool,
    /// The framer said no frame follows.
    ended: bool,
    /// Each stream's head slots, until its head piece is served.
    heads: HashMap<u64, Head>,
    inflows: HashMap<u64, Inflow>,
    tasks: tokio::task::JoinSet<()>,
    ops: mpsc::UnboundedReceiver<(u64, Op)>,
    tx: mpsc::UnboundedSender<(u64, Op)>,
    pending: VecDeque<(u64, Op)>,
    /// The streams the framer answered full.
    full: HashSet<u64>,
    deadline: Option<Pin<Box<tokio::time::Sleep>>>,
    session: Option<Session>,
    /// The protocol the framer last stated it agreed (a 1-based position in its offer).
    agreed: u32,
    stopping: bool,
    /// The framing or the socket failed: the connection is over.
    failed: bool,
    /// The first-byte bound ([`FIRST_BYTE_BOUND`]), until the far end sends a byte.
    first_byte: Option<Pin<Box<tokio::time::Sleep>>>,
}

/// What applying one op came to.
enum Step {
    Done,
    Wait,
}

impl<I: AsyncRead + AsyncWrite + Unpin + Send + 'static> Conn<I> {
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        loop {
            let mut moved = false;
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
                match self.apply_front(cx) {
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
            let idle = self.tasks.is_empty() && self.pending.is_empty() && self.session.is_none();
            if self.failed || (idle && (self.ended || self.read_done || self.stopping)) {
                return self.close(cx);
            }
            if !moved {
                return Poll::Pending;
            }
        }
    }

    /// Close: the framing finishes, what it still owes is written, the socket shut (lingering).
    fn close(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if let Some(framing) = self.framing.take() {
            let reason = if self.stopping {
                CLOSE_DRAIN
            } else {
                CLOSE_NORMAL
            };
            let y = framing.finish(reason);
            self.out.extend(y.wire);
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

    /// Take what the framer answered: wire bytes to the socket, head slots and pieces to the
    /// streams, its deadline to the timer, its end to the connection.
    fn absorb(&mut self, y: Yielded) {
        self.out.extend(y.wire);
        for head in y.heads {
            self.heads.insert(head.stream, head);
        }
        if y.agreed != 0 {
            self.agreed = y.agreed;
        }
        for stream in &y.writable {
            self.full.remove(stream);
        }
        for g in y.pieces.iter().filter(|g| g.ends_stream() || g.failed) {
            self.full.remove(&g.stream);
        }
        for piece in y.pieces {
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

    /// A framer op's answer: absorbed, or the connection failed.
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

    /// Re-drive the ops parked on their tickets.
    fn parked(&mut self, cx: &mut Context<'_>) -> bool {
        let Some(framing) = self.framing.as_mut().filter(|f| f.parked()) else {
            return false;
        };
        match framing.poll_parked(cx) {
            Poll::Ready(r) => self.took(r),
            Poll::Pending => false,
        }
    }

    /// Read what the socket holds into the framer.
    fn read(&mut self, cx: &mut Context<'_>) -> bool {
        if self.framing.as_ref().is_some_and(Framing::begin_parked) {
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
                if end {
                    // Nothing more arrives: every body still open ends here.
                    for inflow in self.inflows.values_mut() {
                        inflow.body = None;
                    }
                    if let Some(s) = self.session.as_mut() {
                        s.from = None;
                    }
                }
                self.took(r);
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

    /// Write what the socket will take now.
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

    /// One socket write: `Ready(true)` = some went, `Ready(false)` = the socket failed.
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

    /// The framer's deadline: at it, its `timer`.
    fn timer(&mut self, cx: &mut Context<'_>) -> bool {
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

    /// One frame piece off the framer.
    fn piece(&mut self, piece: Got) {
        if let Some(session) = self.session.as_mut() {
            session.stream = piece.stream;
            if piece.failed || piece.end {
                session.from = None;
                return;
            }
            session.message.extend_from_slice(&piece.bytes);
            if piece.end_of_frame {
                let message = std::mem::take(&mut session.message);
                if let Some(from) = &session.from {
                    let _ = from.send(message);
                }
            }
            return;
        }
        match self.inflows.get_mut(&piece.stream) {
            None if piece.fields && !piece.failed => self.head(&piece),
            // A piece of a stream no task holds (answered, or never served): dropped.
            None => {}
            Some(inflow) => {
                if piece.failed {
                    // The far side gave the stream up: its body fails and its task ends.
                    if let Some(body) = inflow.body.take() {
                        let reason = String::from_utf8_lossy(&piece.bytes).into_owned();
                        let _ = body.send(Err(BodyError::from(reason)));
                    }
                    inflow.task.abort();
                    return;
                }
                // A trailer block of the request is not read: the router reads data.
                if !piece.fields && !piece.bytes.is_empty() {
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

    /// A request head on `piece`'s stream: the request built and served on its own task.
    fn head(&mut self, piece: &Got) {
        let stream = piece.stream;
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
        let slot = SessionSlot::default();
        let request = request_of(
            &head,
            &piece.bytes,
            h2,
            self.secured,
            AxumBody::new(super::TimeoutBody::new(body, self.timeout)),
        );
        let task = match request {
            Some(mut req) => {
                req.extensions_mut()
                    .insert(super::listener_scheme(self.secured));
                req.extensions_mut().insert(slot.clone());
                // An HTTP/2 request of a method whose body has no defined meaning, its stream still
                // open, is not dispatched until its stream is complete (as the hyper loop held it).
                let defer = h2
                    && !end
                    && matches!(
                        *req.method(),
                        Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
                    );
                self.tasks
                    .spawn(serve_stream(self.router.clone(), req, defer, slot, out))
            }
            None => {
                out.send(Op::Refuse {
                    status: 400,
                    head_sent: false,
                });
                return;
            }
        };
        self.inflows.insert(
            stream,
            Inflow {
                body: (!end).then_some(body_tx),
                task,
            },
        );
    }

    /// Apply the first pending op, as far as the socket's room allows.
    fn apply_front(&mut self, cx: &mut Context<'_>) -> Step {
        let Some((stream, op)) = self.pending.front() else {
            return Step::Done;
        };
        let stream = *stream;
        let waits = match op {
            Op::Head { .. } | Op::Data { .. } => {
                self.out.len() >= WRITE_ROOM || self.full.contains(&stream)
            }
            _ => false,
        };
        if waits {
            // The socket drains, or the framer hands the stream's writable piece: a read or a
            // write wakes the connection.
            let _ = cx;
            return Step::Wait;
        }
        let Some((stream, op)) = self.pending.pop_front() else {
            return Step::Done;
        };
        let Some(framing) = self.framing.as_mut() else {
            return Step::Done;
        };
        match op {
            Op::Head {
                status,
                fields,
                end,
                done,
            } => {
                let r = framing.emit_head(stream, &fields, end, status);
                let full = r.as_ref().is_ok_and(|y| y.full);
                let ok = self.took(r);
                if full {
                    self.full.insert(stream);
                }
                let _ = done.send(ok);
            }
            Op::Data { bytes, end, done } => {
                let r = framing.emit(stream, &bytes, end, false);
                let full = r.as_ref().is_ok_and(|y| y.full);
                let ok = self.took(r);
                if full {
                    self.full.insert(stream);
                }
                let _ = done.send(ok);
            }
            Op::Refuse { status, head_sent } => {
                let r = framing.refuse(Some(stream), &[], status, head_sent);
                if let Ok(y) = r {
                    self.absorb(y);
                }
            }
            Op::Switch { pipe } => self.switch(stream, pipe),
            Op::Ended => {
                self.inflows.remove(&stream);
                self.full.remove(&stream);
            }
        }
        Step::Done
    }

    /// SWITCH the connection to the framer that claims the upgrade: the data framing detaches,
    /// handing back the connection as it was sent (the upgrade request first, unanswered), and
    /// the upgrade's framer adopts it, answers the upgrade itself and frames the session.
    fn switch(&mut self, stream: u64, pipe: busbar_kernel::plane_routes::SessionPipe) {
        let claim = UPGRADE_CLAIMS[usize::from(self.secured)];
        let Some(door) = (self.framer.upgrade)(claim) else {
            tracing::debug!(claim, "data door: no framer claims the session's upgrade");
            self.failed = true;
            return;
        };
        let Some(framing) = self.framing.take() else {
            return;
        };
        let leftover = match framing.detach() {
            Ok(left) => left,
            Err(e) => {
                tracing::debug!(error = %e, "data door: the framer would not let the connection go");
                self.failed = true;
                return;
            }
        };
        self.heads.clear();
        self.full.clear();
        self.deadline = None;
        self.established.claim = door.facts().claims.first().map(|c| (*c).to_owned());
        match Framing::adopt(door, SIDE_ACCEPT, &leftover, &self.established) {
            Ok((framing, y)) => {
                self.framing = Some(framing);
                self.session = Some(Session::over(stream, pipe));
                self.absorb(y);
            }
            Err(e) => {
                tracing::debug!(error = %e, "data door: the upgrade's framer would not adopt");
                self.failed = true;
            }
        }
    }

    /// Pump a switched connection's session: the frames it writes go out as the socket's room
    /// allows. `Some(moved)` while it runs; `None` once the session has ended.
    fn pump_session(&mut self, cx: &mut Context<'_>) -> Option<bool> {
        let mut moved = false;
        loop {
            if self.out.len() >= WRITE_ROOM {
                return Some(moved);
            }
            let session = self.session.as_mut()?;
            if let Some((bytes, text)) = session.writing.take() {
                let stream = session.stream;
                let framing = self.framing.as_mut()?;
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

// ── one stream ───────────────────────────────────────────────────────────────────────────────────

/// THE REQUEST a head states: its method, its target, its field lines in order, `body`. With an
/// authority and no `host` line (an HTTP/2 head), the target is made absolute under the listener's
/// scheme, as the hyper loop read it. `None` = a head no request can carry.
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

/// ONE STREAM, SERVED: its request by the data router in process, its answer written through the
/// connection; an admitted session's answer switches the connection.
async fn serve_stream(
    router: Router,
    req: Request<AxumBody>,
    defer: bool,
    slot: SessionSlot,
    out: Emitter,
) {
    let _end = StreamEnd(out.clone());
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

/// Read a deferred request's body to its end, at most the translate cap.
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

/// THE ANSWER'S HEAD as the framer is handed it: every field line in the answer's order, with the
/// length the body states where its size is known and no line states one, as the hyper loop stated
/// it (never on a `1xx`, `204` or `304`, or beside a `transfer-encoding`).
fn head_block(status: u16, headers: &HeaderMap, exact: Option<u64>) -> Vec<u8> {
    let mut block = Vec::new();
    for (name, value) in headers {
        block.extend_from_slice(name.as_str().as_bytes());
        block.extend_from_slice(fields::SEPARATOR);
        block.extend_from_slice(value.as_bytes());
        block.extend_from_slice(fields::LINE_END);
    }
    let bodyless = status < 200 || status == 204 || status == 304;
    let stated = headers.contains_key(axum::http::header::CONTENT_LENGTH)
        || headers.contains_key(axum::http::header::TRANSFER_ENCODING);
    if let Some(len) = exact.filter(|_| !bodyless && !stated) {
        block.extend_from_slice(b"content-length");
        block.extend_from_slice(fields::SEPARATOR);
        block.extend_from_slice(len.to_string().as_bytes());
        block.extend_from_slice(fields::LINE_END);
    }
    block
}

/// Write `response` through the connection: its head, then its body as it comes; a body that
/// fails after the head ends the stream failed.
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
            Some(Ok(frame)) => {
                if let Ok(data) = frame.into_data() {
                    if !data.is_empty() && !out.data(data, false).await {
                        return;
                    }
                }
            }
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
