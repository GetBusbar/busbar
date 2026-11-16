// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::Router;
use busbar_contract::abi::transport::{fields, CLOSE_DRAIN, CLOSE_NORMAL, SIDE_ACCEPT};
use busbar_core_connector::framer::{
    self, Established, FramerDoor, Framing, Got, GuestLines, Head, Yielded,
};
use busbar_core_connector::secure_vec::SecureVec;
use bytes::Bytes;
use foldhash::{HashMap, HashSet};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot};

#[cfg(test)]
#[path = "tests/listener_framed_fixture.rs"]
mod fixture;
#[cfg(test)]
pub use fixture::{data_framer, DATA_SCHEME};

const READ_CHUNK: usize = 16 * 1024;

/// Process-wide payload admission across every framed listener; no configuration override.
const INBOUND_BODY_BUDGET_BYTES: usize = 256 * 1024 * 1024;
const BODY_BUDGET_REFUSAL: u32 = 503;
static INBOUND_BODY_BUDGET: std::sync::LazyLock<Arc<tokio::sync::Semaphore>> =
    std::sync::LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(INBOUND_BODY_BUDGET_BYTES)));

#[derive(Default)]
struct BodyCharge(std::sync::Mutex<Option<tokio::sync::OwnedSemaphorePermit>>);

impl BodyCharge {
    fn take(&self, budget: &Arc<tokio::sync::Semaphore>, bytes: usize) -> bool {
        let Ok(bytes) = u32::try_from(bytes) else {
            return false;
        };
        let Ok(permit) = Arc::clone(budget).try_acquire_many_owned(bytes) else {
            return false;
        };
        let mut held = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match held.as_mut() {
            Some(held) => held.merge(permit),
            None => *held = Some(permit),
        }
        true
    }
}

const WRITE_ROOM: usize = 256 * 1024;

/// The capacity a drained reply buffer keeps; above it, a drained buffer gives its memory back.
const OUT_KEEP: usize = 64 * 1024;

pub(crate) const FIRST_BYTE_BOUND: std::time::Duration = std::time::Duration::from_secs(30);

const BODY_LIMIT_REFUSAL: u32 =
    busbar_kernel::plane_driver::class_status(busbar_contract::abi::plane::RefusalClass::TooLarge);

pub(crate) type FramerFor = Arc<dyn Fn(&str) -> Option<Arc<dyn FramerDoor>> + Send + Sync>;
pub(crate) type DispatchFor = Arc<
    dyn Fn(&busbar_kernel::inbound::RequestAdmission) -> Option<Arc<crate::root::serve::DataRoutes>>
        + Send
        + Sync,
>;

/// THE DATA LISTENER'S FRAMER: the framer entry, its instance, and the protocols its accepting
/// side offers (what its stated agreed position names).
#[derive(Clone)]
pub struct DataFramer {
    pub(in crate::root) door: Arc<dyn FramerDoor>,
    pub(in crate::root) owner: u64,
    pub(in crate::root) scheme: String,
    pub(in crate::root) listener: Arc<crate::root::inbound::ListenerRegistration>,
    pub(in crate::root) dispatch: Option<DispatchFor>,
    pub(in crate::root) inbound_limit: Option<Arc<tokio::sync::Semaphore>>,
    pub(in crate::root) upgrade: FramerFor,
}

impl std::fmt::Debug for DataFramer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DataFramer")
            .field("entry", &self.door.facts().name)
            .field("owner", &self.owner)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
pub(crate) use crate::root::off_path::listener::configured_framer;
pub use crate::root::off_path::listener::listener_framer;

impl DataFramer {
    #[cfg(test)]
    pub(crate) fn validate_policy(&self) -> Result<(), String> {
        self.listener.validate()
    }

    #[must_use]
    pub fn door(&self) -> &Arc<dyn FramerDoor> {
        &self.door
    }

    pub(in crate::root) fn guests(&self) -> Option<Arc<GuestLines>> {
        self.listener.guests()
    }

    pub(crate) fn with_dispatch(mut self, dispatch: DispatchFor) -> Self {
        self.dispatch = Some(dispatch);
        self
    }

    pub(crate) fn with_inbound_limit(mut self, limit: usize) -> Self {
        self.inbound_limit = (limit != 0).then(|| Arc::new(tokio::sync::Semaphore::new(limit)));
        self
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

    /// A head whose field list the stream task moved to its connection, which encodes it into
    /// its thread's reused block buffer: `timing` replaces every same-named field, written last.
    FieldHead {
        status: u32,
        fields: busbar_kernel::plane_driver::HeadFields,
        timing: Option<String>,
        end: bool,
        done: oneshot::Sender<bool>,
    },

    /// Trailers as a moved field list, encoded like [`Op::FieldHead`].
    FieldTrailers {
        fields: busbar_kernel::plane_driver::HeadFields,
        done: oneshot::Sender<bool>,
    },

    /// A queued op already taken out of the middle of the pending queue: the slot it leaves, so
    /// a take never shifts the queue. The queue's front is never `Taken`.
    Taken,

    Admit {
        permit: Option<busbar_kernel::inbound::UpgradePermit>,
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

thread_local! {
    /// The block a moved field list is encoded into for the framer, reused by every connection
    /// this thread drives (the framer copies what it keeps before the call returns).
    static BLOCK: std::cell::Cell<Vec<u8>> = const { std::cell::Cell::new(Vec::new()) };
}

/// A field list's wire block written into `block` (cleared first): a `Server-Timing` value
/// replaces every same-named field and is written last.
fn encode_fields(
    block: &mut Vec<u8>,
    fields: &busbar_kernel::plane_driver::HeadFields,
    timing: Option<&str>,
) {
    let timing_name = busbar_kernel::router::ServerTiming::HEADER.as_bytes();
    block.clear();
    for (name, value) in fields {
        if timing.is_none() || !name.eq_ignore_ascii_case(timing_name) {
            put_field(block, name, value);
        }
    }
    if let Some(value) = timing {
        put_field(block, timing_name, value.as_bytes());
    }
}

/// Hand `emit` the wire block of a moved field list, encoded into this thread's reused buffer.
fn with_block<R>(
    fields: &busbar_kernel::plane_driver::HeadFields,
    timing: Option<&str>,
    emit: impl FnOnce(&[u8]) -> R,
) -> R {
    // Taken, not borrowed: a nested use (never expected) encodes into a fresh buffer instead.
    let mut block = BLOCK.take();
    encode_fields(&mut block, fields, timing);
    let r = emit(block.as_slice());
    BLOCK.set(block);
    r
}

fn put_field(block: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    block.extend_from_slice(name);
    block.extend_from_slice(fields::SEPARATOR);
    block.extend_from_slice(value);
    block.extend_from_slice(fields::LINE_END);
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
    Option<Arc<BodyCharge>>,
);

impl Drop for StreamEnd {
    fn drop(&mut self) {
        self.0.send(Op::Ended {
            scope: self.1.take(),
        });
        self.2.take();
    }
}

type BodyError = Box<dyn std::error::Error + Send + Sync>;

struct Inflow {
    body_charge: Arc<BodyCharge>,
    admission: Option<busbar_kernel::inbound::RequestAdmission>,
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

async fn gather_body(
    mut body: InboundBody,
    body_limit: u64,
    timeout: std::time::Duration,
) -> Result<Bytes, busbar_contract::caps::ReasonCode> {
    use busbar_contract::caps::ReasonCode;
    let mut whole = Gathered::default();
    let started = tokio::time::Instant::now();
    let deadline = started + super::total_body_deadline();
    while !body.ended {
        let piece_deadline = (tokio::time::Instant::now() + timeout).min(deadline);
        match tokio::time::timeout_at(piece_deadline, body.pieces.recv()).await {
            Ok(Some(Ok(bytes))) => {
                let oversized = whole
                    .len()
                    .checked_add(bytes.len())
                    .is_none_or(|size| body_limit != 0 && size as u64 > body_limit);
                if oversized {
                    return Err(ReasonCode::BodyTooLarge);
                }
                whole.push(bytes);
            }
            Ok(None) => body.ended = true,
            Ok(Some(Err(_))) => return Err(ReasonCode::DecodeFailed),
            Err(_) => return Err(ReasonCode::DeadlineExceeded),
        }
        let elapsed = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        if super::check_body_bounds(0, elapsed, whole.len() as u64).is_some() {
            return Err(ReasonCode::DeadlineExceeded);
        }
    }
    Ok(whole.into_bytes())
}

/// A request body gathered from its pieces: a body that arrives in one piece is kept as received
/// (no copy); only one that arrives in several is joined.
#[derive(Default)]
struct Gathered {
    /// The single piece so far; empty once `joined` holds the body.
    first: Bytes,
    joined: Option<bytes::BytesMut>,
}

impl Gathered {
    fn len(&self) -> usize {
        self.first.len() + self.joined.as_ref().map_or(0, bytes::BytesMut::len)
    }

    fn push(&mut self, piece: Bytes) {
        if piece.is_empty() {
            return;
        }
        if let Some(joined) = self.joined.as_mut() {
            joined.extend_from_slice(&piece);
        } else if self.first.is_empty() {
            self.first = piece;
        } else {
            let first = std::mem::take(&mut self.first);
            let mut joined = bytes::BytesMut::with_capacity(first.len() + piece.len());
            joined.extend_from_slice(&first);
            joined.extend_from_slice(&piece);
            self.joined = Some(joined);
        }
    }

    fn into_bytes(self) -> Bytes {
        self.joined.map_or(self.first, bytes::BytesMut::freeze)
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
    peer: Option<std::net::SocketAddr>,
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
        peer,
        out: SecureVec::new(),
        read_done: false,
        ended: false,
        heads: HashMap::default(),
        inflows: HashMap::default(),
        tasks: tokio::task::JoinSet::new(),
        ops,
        tx,
        pending: VecDeque::new(),
        admission_tx,
        admissions,
        staged: None,
        prewire: false,
        full: HashSet::default(),
        deadline: None,
        session: None,
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
    /// The connection's socket peer, stamped on every operator request it carries.
    peer: Option<std::net::SocketAddr>,

    /// Reply bytes for the peer: one contiguous run whose written prefix is wiped (T7b).
    out: SecureVec,

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
    prewire: bool,

    full: HashSet<u64>,
    deadline: Option<Pin<Box<tokio::time::Sleep>>>,
    session: Option<Session>,

    stopping: bool,

    failed: bool,

    first_byte: Option<Pin<Box<tokio::time::Sleep>>>,
}

enum UpgradePhase {
    Adopting(oneshot::Sender<bool>),
    Admitted,
    Committing(busbar_kernel::plane_routes::SessionPipe),
}

struct StagedUpgrade {
    phase: UpgradePhase,
    stream: u64,
    yielded: Vec<Yielded>,
    /// How many leading `yielded` batches lost their heads and field pieces when the opening was
    /// accepted: they are skipped where those batches are read, never swept out.
    stripped: usize,
    /// Bytes read ahead of the commit, in one buffer that grows by replacement (never by an
    /// in-place reallocation that would leave an un-zeroized copy behind).
    incoming: busbar_contract::secure::SecureVec,
    opening_status: Option<u32>,
    bound: Pin<Box<tokio::time::Sleep>>,
}

impl StagedUpgrade {
    fn take_incoming(&mut self) -> busbar_contract::secure::SecureVec {
        std::mem::take(&mut self.incoming)
    }

    fn stage_incoming(&mut self, bytes: &[u8]) {
        let len = self.incoming.len() + bytes.len();
        if len > self.incoming.capacity() {
            let capacity = (self.incoming.capacity() * 2)
                .max(len)
                .min(WRITE_ROOM.max(len));
            let held = std::mem::replace(
                &mut self.incoming,
                busbar_contract::secure::SecureVec::from(Vec::with_capacity(capacity)),
            );
            self.incoming.extend_from_slice(&held);
        }
        self.incoming.extend_from_slice(bytes);
    }
}

enum Step {
    Done,
    Wait,
}

impl<I: AsyncRead + AsyncWrite + Unpin + Send + 'static> Conn<I> {
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        loop {
            let mut moved = false;
            let abandoned = self
                .staged
                .as_mut()
                .is_some_and(|stage| match &mut stage.phase {
                    UpgradePhase::Adopting(reply) => reply.poll_closed(cx).is_ready(),
                    _ => false,
                });
            if (self.stopping || abandoned) && self.staged.is_some() {
                self.abandon_stage();
            }
            while let Poll::Ready(Some(admission)) = self.admissions.poll_recv(cx) {
                self.pending.push_back((
                    admission.stream,
                    Op::Admit {
                        permit: admission.permit,
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
            while !self.failed && self.framing.is_some() && !self.pending.is_empty() {
                match self.apply_front() {
                    Step::Done => moved = true,
                    Step::Wait => break,
                }
            }
            // A failed command (including a dropped upgrade acknowledgement) is terminal.
            // Do not process its queued response or publish any bytes in this same poll.
            if self.failed || self.framing.is_none() {
                self.tasks.abort_all();
                return self.close(cx);
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
            let staged = self.staged.take().is_some();
            if !self.prewire && !staged {
                absorb_wire(&mut self.out, &mut self.failed, &y.wire);
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

    fn absorb(&mut self, y: Yielded) {
        self.absorb_from(y, false);
    }

    /// Absorb a batch; a `stripped` staged batch contributes no heads and no field pieces.
    fn absorb_from(&mut self, mut y: Yielded, stripped: bool) {
        absorb_wire(&mut self.out, &mut self.failed, &y.wire);
        if !stripped {
            for head in std::mem::take(&mut y.heads) {
                self.heads.insert(head.stream, head);
            }
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
        let kept = |g: &Got| !(stripped && g.fields);
        for g in y
            .pieces
            .iter()
            .filter(|g| kept(g) && (g.ends_stream() || g.failed))
        {
            self.full.remove(&g.stream);
        }
        for piece in std::mem::take(&mut y.pieces) {
            if kept(&piece) {
                self.piece(piece);
            }
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
                if self.staged.is_some() {
                    self.receive_stage(y);
                } else {
                    self.absorb(y);
                }
                true
            }
            Err(e) => {
                if self.staged.is_some() {
                    self.abandon_stage();
                }
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
        let progressed = match framing.poll_parked(cx) {
            Poll::Ready(r) => self.took(r),
            Poll::Pending => false,
        };
        self.finish_read_bodies();
        progressed
    }

    fn finish_read_bodies(&mut self) {
        if !self.read_done
            || self.staged.is_some()
            || self.framing.as_ref().is_some_and(Framing::parked)
        {
            return;
        }

        for inflow in self.inflows.values_mut() {
            if let Some(body) = inflow.body.take() {
                let error = std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed before the request body ended",
                );
                let _ = body.send(Err(error.into()));
            }
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
        let mut buf = [std::mem::MaybeUninit::<u8>::uninit(); READ_CHUNK];
        let mut rb = ReadBuf::uninit(&mut buf);
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
                let r = framing.ingest(rb.filled(), end);
                self.took(r);
                if end {
                    self.finish_read_bodies();
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
        let adopting = self
            .staged
            .as_ref()
            .is_some_and(|stage| matches!(stage.phase, UpgradePhase::Adopting(_)));
        let writable = !self.framing.as_ref().is_some_and(Framing::parked);
        if adopting && writable {
            let incoming = self
                .staged
                .as_mut()
                .map(StagedUpgrade::take_incoming)
                .unwrap_or_default();
            if !incoming.is_empty() {
                if let Some(framing) = self.framing.as_mut() {
                    let received = framing.ingest(&incoming, false);
                    self.took(received);
                }
                return true;
            }
        }
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
        let mut bytes = [std::mem::MaybeUninit::<u8>::uninit(); READ_CHUNK];
        let mut buffer = ReadBuf::uninit(&mut bytes[..remaining.min(READ_CHUNK)]);
        match Pin::new(&mut self.io).poll_read(cx, &mut buffer) {
            Poll::Ready(Ok(())) if buffer.filled().is_empty() => {
                self.read_done = true;
                self.abandon_stage();
                true
            }
            Poll::Ready(Ok(())) => {
                if let Some(stage) = self.staged.as_mut() {
                    stage.stage_incoming(buffer.filled());
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
            let _ = framing.finish(CLOSE_NORMAL);
        }
        self.ended = true;
    }

    fn flush(&mut self, cx: &mut Context<'_>) -> bool {
        let mut moved = false;
        while !self.out.is_empty() && !self.failed {
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
        write_some(&mut self.out, &mut self.failed, Pin::new(&mut self.io), cx)
    }

    fn timer(&mut self, cx: &mut Context<'_>) -> bool {
        if let Some(stage) = self.staged.as_mut() {
            if std::future::Future::poll(stage.bound.as_mut(), cx).is_ready() {
                self.abandon_stage();
                return true;
            }
            if self.framing.as_ref().is_some_and(Framing::parked) {
                return false;
            }
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
                        let reason = crate::root::cold::failed_piece_reason(&piece.bytes);
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
                    if !inflow
                        .body_charge
                        .take(&INBOUND_BODY_BUDGET, piece.bytes.len())
                    {
                        inflow.refused = true;
                        inflow.body = None;
                        inflow.task.abort();
                        if let Some(admission) = &inflow.admission {
                            admission.refuse(
                                busbar_contract::caps::StepName::Arrival,
                                busbar_contract::caps::ReasonCode::InFlightCap,
                            );
                        }
                        self.pending.push_back((
                            piece.stream,
                            Op::Refuse {
                                status: BODY_BUDGET_REFUSAL,
                                head_sent: inflow.head_sent,
                            },
                        ));
                        return;
                    }
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
        let (body_tx, body_rx) = mpsc::unbounded_channel();
        let body = InboundBody {
            pieces: body_rx,
            ended: piece.end,
        };
        let out = Emitter {
            stream,
            tx: self.tx.clone(),
        };
        let scope = self.framing.as_ref().and_then(Framing::scope).cloned();
        let mut admission = None;
        let mut slot = SessionSlot::default();
        if let Some(scope) = scope.as_ref().filter(|scope| scope.listener() != 0) {
            let claimed = decoded_head(&head, &piece.bytes).and_then(|head| {
                crate::root::inbound::host()
                    .claim_request(scope.owner(), scope.leg(), stream, &head)
                    .ok()
            });
            let Some(request) = claimed else {
                out.send(Op::Refuse {
                    status: 401,
                    head_sent: false,
                });
                out.send(Op::Ended {
                    scope: Some(Arc::clone(scope)),
                });
                return;
            };
            body_limit = request.body_limit();
            slot = SessionSlot::with_request_admission(self.admission_tx.clone(), stream, &request);
            scope.admit_stream(stream);
            admission = Some(request);
        }
        let body_charge = Arc::new(BodyCharge::default());
        let ended = StreamEnd(out.clone(), scope, Some(Arc::clone(&body_charge)));
        let permit = self
            .framer
            .inbound_limit
            .as_ref()
            .map(|limit| Arc::clone(limit).try_acquire_owned());
        if permit.as_ref().is_some_and(Result::is_err) {
            metrics::counter!(busbar_kernel::snapshot::ADMISSION_DENIED_TOTAL, "gate" => "inbound")
                .increment(1);
            let rendered = admission.as_ref().and_then(|request| {
                request.refuse(
                    busbar_contract::caps::StepName::Arrival,
                    busbar_contract::caps::ReasonCode::InFlightCap,
                );
                self.framer
                    .dispatch
                    .as_ref()
                    .and_then(|dispatch| dispatch(request))
                    .and_then(|dispatcher| dispatcher.capacity_refusal(request))
            });
            if let Some(rendered) = rendered {
                // Queue only the bounded refusal, never an overflow execution task. The
                // StreamEnd below follows these messages in the same stream's FIFO.
                queue_whole(&out, rendered);
                return;
            }
            out.send(Op::Refuse {
                status: 503,
                head_sent: false,
            });
            return;
        }
        let task = if let Some(request) = admission.as_ref().filter(|request| {
            matches!(
                request.selected_line().claimant,
                busbar_kernel::guest::Claimant::Plane(_)
            )
        }) {
            let dispatcher = self
                .framer
                .dispatch
                .as_ref()
                .and_then(|dispatch| dispatch(request));
            let Some(dispatcher) = dispatcher else {
                // A plane admission can never fall through to the operator HTTP router.
                out.send(Op::Refuse {
                    status: 503,
                    head_sent: false,
                });
                return;
            };
            self.tasks.spawn(serve_data(
                dispatcher,
                request.clone(),
                body,
                slot,
                out,
                ended,
                Established::scheme_of(self.secured),
                self.timeout,
                permit.and_then(Result::ok),
                busbar_kernel::router::ServerTiming::start(),
            ))
        } else {
            let request = operator::request(&head, &piece.bytes, self.secured, body, self.timeout);
            let Some(mut request) = request else {
                out.send(Op::Refuse {
                    status: 400,
                    head_sent: false,
                });
                return;
            };
            if let Some(admission) = &admission {
                request.extensions_mut().insert(admission.clone());
            }
            request
                .extensions_mut()
                .insert(super::listener_scheme(self.secured));
            if let Some(peer) = self.peer {
                request
                    .extensions_mut()
                    .insert(busbar_kernel::auth::login_limits::ClientAddr(peer));
            }
            request.extensions_mut().insert(slot.clone());
            self.tasks.spawn(operator::serve(
                self.router.clone(),
                request,
                slot,
                out,
                ended,
                permit.and_then(Result::ok),
            ))
        };
        self.inflows.insert(
            stream,
            Inflow {
                body_charge,
                admission,
                body: (!piece.end).then_some(body_tx),
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
        let mut blocked = HashSet::default();
        let mut next = None;
        let framing = self.framing.as_ref();
        for (index, (stream, op)) in self.pending.iter().enumerate() {
            if matches!(op, Op::Taken) {
                continue;
            }
            if self
                .inflows
                .get(stream)
                .is_some_and(|inflow| inflow.refused)
                && matches!(
                    op,
                    Op::Head { .. }
                        | Op::FieldHead { .. }
                        | Op::Data { .. }
                        | Op::Trailers { .. }
                        | Op::FieldTrailers { .. }
                        | Op::Switch { .. }
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
                || matches!(
                    op,
                    Op::Head { .. }
                        | Op::FieldHead { .. }
                        | Op::Data { .. }
                        | Op::Trailers { .. }
                        | Op::FieldTrailers { .. }
                ) && (self.out.len() >= WRITE_ROOM || self.full.contains(stream));
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
        // Take the op out of its slot without shifting the queue; the front stays live.
        let Some((stream, slot)) = self.pending.get_mut(index) else {
            return Step::Wait;
        };
        let stream = *stream;
        let op = std::mem::replace(slot, Op::Taken);
        while matches!(self.pending.front(), Some((_, Op::Taken))) {
            self.pending.pop_front();
        }
        if self
            .inflows
            .get(&stream)
            .is_some_and(|inflow| inflow.refused)
        {
            match op {
                Op::Head { done, .. }
                | Op::FieldHead { done, .. }
                | Op::Data { done, .. }
                | Op::Trailers { done, .. }
                | Op::FieldTrailers { done, .. } => {
                    let _ = done.send(false);
                    return Step::Done;
                }
                Op::Switch { .. } => return Step::Done,
                Op::Admit { reply, .. } => {
                    let _ = reply.send(false);
                    return Step::Done;
                }
                _ => {}
            }
        }
        if let Op::Admit { reply, permit } = op {
            self.stage_upgrade(stream, permit.as_ref(), reply);
            return Step::Done;
        }
        if matches!(
            op,
            Op::Head { .. } | Op::FieldHead { .. } | Op::Refuse { .. }
        ) {
            self.staged.take();
        }
        let Some(framing) = self.framing.as_mut() else {
            return Step::Done;
        };
        match op {
            Op::Admit { .. } => unreachable!("admission is processed before the framing borrow"),
            Op::Taken => unreachable!("a taken slot is skipped, never chosen"),
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
            Op::FieldHead {
                status,
                fields,
                timing,
                end,
                done,
            } => {
                let r = with_block(&fields, timing.as_deref(), |block| {
                    framing.emit_head(stream, block, end, status)
                });
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
            Op::FieldTrailers { fields, done } => {
                let r = with_block(&fields, None, |block| framing.emit_trailers(stream, block));
                let ok = self.took(r);
                let _ = done.send(ok);
            }
            Op::Refuse { status, head_sent } => {
                if let Some(inflow) = self.inflows.get_mut(&stream).filter(|i| i.refused) {
                    if !matches!(status, BODY_LIMIT_REFUSAL | BODY_BUDGET_REFUSAL)
                        || inflow.refusal_sent
                    {
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

    fn stage_upgrade(
        &mut self,
        stream: u64,
        permit: Option<&busbar_kernel::inbound::UpgradePermit>,
        reply: oneshot::Sender<bool>,
    ) {
        if reply.is_closed() {
            self.failed = true;
            return;
        }
        if self.staged.is_some() || self.session.is_some() {
            let _ = reply.send(false);
            return;
        }
        let claim = permit.and_then(|permit| {
            let admission = self.inflows.get(&stream)?.admission.as_ref()?;
            let scope = self.framing.as_ref()?.scope()?;
            permit.consume(admission, scope.owner(), scope.leg(), stream)
        });
        let Some(claim) = claim else {
            let _ = reply.send(false);
            return;
        };
        let Some(door) = (self.framer.upgrade)(claim) else {
            let _ = reply.send(false);
            return;
        };
        if !self.framer.door.detaches() || !door.adopts() {
            let _ = reply.send(false);
            return;
        }
        let Some(framing) = self.framing.as_mut() else {
            let _ = reply.send(false);
            return;
        };
        let leftover = match framing.try_detach() {
            Ok(left) => left,
            Err(e)
                if e.outcome == busbar_contract::abi::mechanism::call::Outcome::Refused
                    && framing.token() != 0 =>
            {
                if let Some(inflow) = self.inflows.get_mut(&stream) {
                    inflow.refused = true;
                }
                let refused = framing.refuse(Some(stream), &[], 400, false);
                self.took(refused);
                let _ = reply.send(false);
                return;
            }
            Err(e) => {
                tracing::debug!(error = %e, "data door: the framer would not release the opening");
                self.failed = true;
                return;
            }
        };
        drop(self.framing.take());
        // The connection's claim string is rewritten in place: no fresh String per upgrade.
        let mut held = self.established.claim.take().unwrap_or_default();
        held.clear();
        held.push_str(claim);
        self.established.claim = Some(held);
        match Framing::adopt_detached_staged(door, SIDE_ACCEPT, leftover, &self.established) {
            Ok((framing, yielded)) => {
                self.framing = Some(framing);
                self.prewire = true;
                self.deadline = None;
                self.staged = Some(StagedUpgrade {
                    phase: UpgradePhase::Adopting(reply),
                    stream,
                    yielded: Vec::new(),
                    stripped: 0,
                    incoming: busbar_contract::secure::SecureVec::new(),
                    opening_status: None,
                    bound: Box::pin(tokio::time::sleep(self.timeout)),
                });
                self.receive_stage(yielded);
            }
            Err(e) => {
                tracing::debug!(error = %e, "data door: the session opening was refused");
                self.failed = true;
            }
        }
    }

    fn receive_stage(&mut self, yielded: Yielded) {
        let Some(stage) = self.staged.as_mut() else {
            return;
        };
        if let Some(deadline) = yielded.deadline_ns {
            self.deadline = Some(Box::pin(tokio::time::sleep_until(
                tokio::time::Instant::from_std(framer::instant_of(deadline)),
            )));
        }

        stage.yielded.push(yielded);
        if self.framing.as_ref().is_some_and(Framing::parked) {
            return;
        }
        let accepted = stage
            .yielded
            .iter()
            .skip(stage.stripped)
            .flat_map(|batch| &batch.pieces)
            .find(|piece| {
                piece.stream == stage.stream
                    && piece.fields
                    && piece.end_of_frame
                    && piece.status_class == busbar_contract::abi::transport::STATUS_SUCCESS
                    && !piece.failed
            });
        if let Some(piece) = accepted {
            stage.opening_status = piece.status_code;
        }
        let accepted = accepted.is_some();
        if stage.yielded.iter().any(|batch| batch.ended) {
            if matches!(stage.phase, UpgradePhase::Adopting(_)) && !accepted {
                let Some(stage) = self.staged.take() else {
                    return;
                };
                if let Some(inflow) = self.inflows.get_mut(&stage.stream) {
                    inflow.refused = true;
                }
                if let UpgradePhase::Adopting(reply) = stage.phase {
                    let _ = reply.send(false);
                }

                for batch in stage.yielded {
                    self.absorb(batch);
                }
            } else {
                self.abandon_stage();
            }
            return;
        }
        if matches!(stage.phase, UpgradePhase::Adopting(_)) {
            if !accepted {
                return;
            }
            stage.stripped = stage.yielded.len();
            let phase = std::mem::replace(&mut stage.phase, UpgradePhase::Admitted);
            if let UpgradePhase::Adopting(reply) = phase {
                if reply.send(true).is_err() {
                    self.abandon_stage();
                }
            }
            return;
        }
        if matches!(stage.phase, UpgradePhase::Committing(_)) {
            let Some(mut stage) = self.staged.take() else {
                return;
            };
            let incoming = stage.take_incoming();
            let UpgradePhase::Committing(pipe) = stage.phase else {
                return;
            };
            self.heads.clear();
            self.full.clear();
            let mut session = Session::over(stage.stream, pipe);
            if let Some(inflow) = self.inflows.get(&stage.stream) {
                session.body_limit = inflow.body_limit;
            }
            self.session = Some(session);
            self.prewire = false;
            for (index, batch) in stage.yielded.into_iter().enumerate() {
                self.absorb_from(batch, index < stage.stripped);
            }
            if !incoming.is_empty() {
                if let Some(framing) = self.framing.as_mut() {
                    let received = framing.ingest(&incoming, false);
                    self.took(received);
                }
            }
        }
    }

    fn switch(&mut self, stream: u64, pipe: busbar_kernel::plane_routes::SessionPipe) {
        let Some(stage) = self.staged.as_mut().filter(|stage| {
            stage.stream == stream && matches!(stage.phase, UpgradePhase::Admitted)
        }) else {
            self.failed = true;
            return;
        };
        stage.phase = UpgradePhase::Committing(pipe);
        let status = stage.opening_status.unwrap_or_default();
        let Some(framing) = self.framing.as_mut() else {
            self.abandon_stage();
            return;
        };
        let committed = framing.emit_head(stream, &[], true, status);
        self.took(committed);
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

/// Decode the shared transport head representation, without HTTP method, URI or field parsing.
fn decoded_head(head: &Head, block: &[u8]) -> Option<busbar_kernel::inbound::Head> {
    let method = std::str::from_utf8(head.method.as_deref()?)
        .ok()?
        .to_owned();
    let target = std::str::from_utf8(head.target.as_deref()?).ok()?;
    let (target, query) = target
        .split_once('?')
        .map_or((target, None), |(path, query)| {
            (path, Some(query.to_owned()))
        });
    let mut read = 0;
    let fields = fields::lines(block)
        .map(|(name, value)| {
            read += name.len() + fields::SEPARATOR.len() + value.len() + fields::LINE_END.len();
            Some((std::str::from_utf8(name).ok()?.to_owned(), value.to_vec()))
        })
        .collect::<Option<Vec<_>>>()?;
    if read != block.len() {
        return None;
    }
    Some(busbar_kernel::inbound::Head {
        method,
        target: target.to_owned(),
        query,
        fields,
        authority: head
            .authority
            .as_deref()
            .map(std::str::from_utf8)
            .transpose()
            .ok()?
            .unwrap_or_default()
            .to_owned(),
    })
}

/// A WHOLE answer of `len` body bytes on the HTTP door states its length, as the operator
/// adapter's `head_block` does, unless its fields already state framing or a trailer, or its
/// status carries no body.
fn state_whole_length(
    status: u32,
    fields: &mut busbar_kernel::plane_driver::HeadFields,
    len: usize,
) {
    if len == 0 {
        return;
    }
    let named = |n: &[u8]| fields.iter().any(|(f, _)| f.eq_ignore_ascii_case(n));
    let stated = named(b"content-length") || named(b"transfer-encoding");
    if operator::length_due(status, stated, named(b"trailer")) {
        fields.push((b"content-length".to_vec(), len.to_string().into_bytes()));
    }
}

/// Queues a whole rendered answer on `out` without waiting for the writer: its head, stating its
/// length, then its body as the stream's last data.
fn queue_whole(out: &Emitter, rendered: busbar_kernel::plane_driver::Rendered) {
    let mut fields = rendered.fields;
    state_whole_length(rendered.status, &mut fields, rendered.body.len());
    let (done, _) = oneshot::channel();
    out.send(Op::FieldHead {
        status: rendered.status,
        fields,
        timing: None,
        end: rendered.body.is_empty(),
        done,
    });
    if !rendered.body.is_empty() {
        let (done, _) = oneshot::channel();
        out.send(Op::Data {
            bytes: Bytes::from(rendered.body),
            end: true,
            done,
        });
    }
}

struct ActorCaller {
    out: Emitter,
    stated: std::sync::Mutex<Option<u32>>,
    body: std::sync::Mutex<Option<Bytes>>,
    ended: std::sync::atomic::AtomicBool,
}

impl ActorCaller {
    fn response_head(
        &self,
        status: u32,
        fields: busbar_kernel::plane_driver::HeadFields,
        end: bool,
    ) {
        let mut stated = self
            .stated
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if stated.is_some() {
            return;
        }
        *stated = Some(status);
        if end {
            self.ended.store(true, std::sync::atomic::Ordering::Release);
        }
        // A head written while `serve_data` measures the request carries its `Server-Timing`, in
        // place of any same-named field (the connection writes it last when it encodes the block).
        let timing = busbar_kernel::router::ServerTiming::current_value();
        let (done, _) = oneshot::channel();
        self.out.send(Op::FieldHead {
            status,
            fields,
            timing,
            end,
            done,
        });
    }
}

impl busbar_kernel::plane_driver::CallerEnd for ActorCaller {
    fn head(&self, status: u32, fields: busbar_kernel::plane_driver::HeadFields) {
        self.response_head(status, fields, false);
    }
    /// A whole answer on the HTTP door states its length, as the operator adapter's
    /// `head_block` does, unless its fields already state framing or a trailer.
    fn head_whole(
        &self,
        status: u32,
        mut fields: busbar_kernel::plane_driver::HeadFields,
        len: usize,
    ) {
        state_whole_length(status, &mut fields, len);
        self.response_head(status, fields, false);
    }
    async fn write(&self, bytes: &[u8]) -> bool {
        self.out.data(Bytes::copy_from_slice(bytes), false).await
    }
}

impl busbar_kernel::plane_driver::SessionCaller for ActorCaller {
    async fn read(&self) -> Option<Vec<u8>> {
        let first = self
            .body
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(body) = first {
            // A uniquely held body hands over its allocation; a shared one is copied once.
            return Some(Vec::from(body));
        }
        // Request-body completion does not close the response-side session.
        // Stream cancellation aborts its inflow task; connection closure drops the receiver.
        self.out.tx.closed().await;
        None
    }
}
impl crate::root::serve::Stated for ActorCaller {
    fn stated(&self) -> Option<u32> {
        *self
            .stated
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    fn ended(&self, outcome: Option<busbar_contract::caps::Outcome>) {
        use busbar_contract::caps::{Abort, Outcome};
        let reason = match outcome {
            Some(
                Outcome::Refused(_, reason)
                | Outcome::Failed(_, reason)
                | Outcome::Aborted(Abort::Kernel { reason }),
            ) => Some(reason),
            Some(Outcome::TimedOut(_)) => Some(busbar_contract::caps::ReasonCode::DeadlineExceeded),
            Some(Outcome::Aborted(_)) => Some(busbar_contract::caps::ReasonCode::PlanePanic),
            _ => None,
        };
        if let Some(reason) = reason.filter(|_| self.stated().is_some()) {
            self.ended.store(true, std::sync::atomic::Ordering::Release);
            self.out.send(Op::Refuse {
                status: busbar_kernel::plane_driver::refusal_status(reason),
                head_sent: true,
            });
        }
    }
}
impl crate::root::serve::neutral::Output for ActorCaller {
    fn complete_head(&self, status: u32, fields: busbar_kernel::plane_driver::HeadFields) {
        self.response_head(status, fields, true);
    }
    async fn write_owned(&self, bytes: Bytes) -> bool {
        self.out.data(bytes, false).await
    }
    fn trailers(&self, fields: busbar_kernel::plane_driver::HeadFields) {
        if self.ended.swap(true, std::sync::atomic::Ordering::AcqRel) {
            return;
        }
        let (done, _) = oneshot::channel();
        self.out.send(Op::FieldTrailers { fields, done });
    }
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub(in crate::root) async fn serve_governed_test<I>(
    io: I,
    framer: DataFramer,
    secured: bool,
    timeout: std::time::Duration,
    stop: tokio::sync::watch::Receiver<bool>,
) where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    serve(io, framer, Router::new(), secured, timeout, stop, None).await;
}

/// One response op the admitted request actor sent, as the connection writer receives it.
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::root) enum WireOp {
    Head {
        status: u32,
        fields: Vec<u8>,
        end: bool,
    },
    Data {
        bytes: Bytes,
        end: bool,
    },
    Trailers,
    Refuse {
        status: u32,
        head_sent: bool,
    },
}

/// Exercise the production admitted request actor with decoded body frames.
#[cfg(test)]
pub(in crate::root) async fn serve_admitted_body_test(
    routes: Arc<crate::root::serve::DataRoutes>,
    admission: busbar_kernel::inbound::RequestAdmission,
    pieces: Vec<Result<Bytes, &'static str>>,
) -> Option<u32> {
    serve_admitted_wire_test(routes, admission, pieces)
        .await
        .iter()
        .rev()
        .find_map(|op| match op {
            WireOp::Head { status, .. } | WireOp::Refuse { status, .. } => Some(*status),
            _ => None,
        })
}

/// The same production admitted request actor, returning every response op it sent in order.
#[cfg(test)]
pub(in crate::root) async fn serve_admitted_wire_test(
    routes: Arc<crate::root::serve::DataRoutes>,
    admission: busbar_kernel::inbound::RequestAdmission,
    pieces: Vec<Result<Bytes, &'static str>>,
) -> Vec<WireOp> {
    let (body_tx, body_rx) = mpsc::unbounded_channel();
    for piece in pieces {
        body_tx.send(piece.map_err(BodyError::from)).unwrap();
    }
    drop(body_tx);
    let (tx, mut rx) = mpsc::unbounded_channel();
    let emitter = Emitter { stream: 1, tx };
    let collect = async move {
        let mut wire = Vec::new();
        while let Some((_, op)) = rx.recv().await {
            match op {
                Op::Head {
                    status,
                    fields,
                    end,
                    done,
                } => {
                    wire.push(WireOp::Head {
                        status,
                        fields,
                        end,
                    });
                    let _ = done.send(true);
                }
                Op::Data { bytes, end, done } => {
                    wire.push(WireOp::Data { bytes, end });
                    let _ = done.send(true);
                }
                Op::FieldHead {
                    status,
                    fields,
                    timing,
                    end,
                    done,
                } => {
                    let mut block = Vec::new();
                    encode_fields(&mut block, &fields, timing.as_deref());
                    wire.push(WireOp::Head {
                        status,
                        fields: block,
                        end,
                    });
                    let _ = done.send(true);
                }
                Op::Trailers { done, .. } | Op::FieldTrailers { done, .. } => {
                    wire.push(WireOp::Trailers);
                    let _ = done.send(true);
                }
                Op::Refuse { status, head_sent } => {
                    wire.push(WireOp::Refuse { status, head_sent });
                }
                Op::Ended { .. } => break,
                _ => {}
            }
        }
        wire
    };
    let (_, wire) = tokio::join!(
        serve_data(
            routes,
            admission,
            InboundBody {
                pieces: body_rx,
                ended: false
            },
            SessionSlot::default(),
            emitter.clone(),
            StreamEnd(emitter, None, None),
            busbar_contract::abi::host::service::SCHEME_SECURE,
            std::time::Duration::from_secs(1),
            None,
            None
        ),
        collect
    );
    wire
}

#[expect(
    clippy::too_many_arguments,
    reason = "one admitted stream's parts, moved into its actor"
)]
async fn serve_data(
    routes: Arc<crate::root::serve::DataRoutes>,
    admission: busbar_kernel::inbound::RequestAdmission,
    body: InboundBody,
    slot: SessionSlot,
    out: Emitter,
    _end: StreamEnd,
    scheme: u8,
    timeout: std::time::Duration,
    _permit: Option<tokio::sync::OwnedSemaphorePermit>,
    timing: Option<busbar_kernel::router::ServerTiming>,
) {
    use crate::root::serve::Stated as _;
    use busbar_contract::caps::ReasonCode;
    let caller = Arc::new(ActorCaller {
        out: out.clone(),
        stated: std::sync::Mutex::new(None),
        body: std::sync::Mutex::new(None),
        ended: std::sync::atomic::AtomicBool::new(false),
    });
    // Boxed once: the request's whole future is too large to move through the measurement and
    // deadline wrappers by value.
    let work = Box::pin(async {
        let context = match busbar_kernel::auth::admitted_context(&admission).await {
            Ok(context) => context,
            Err(refused) => {
                if let Some(rendered) = refused
                    .challenge(&admission)
                    .or_else(|| routes.refusal(&admission, ReasonCode::Unauthenticated))
                {
                    routes.auth_completion(&admission, rendered.status);
                    crate::root::serve::neutral::render(&*caller, rendered).await;
                }
                return None;
            }
        };
        let body = match gather_body(body, admission.body_limit(), timeout).await {
            Ok(body) => body,
            Err(reason) => {
                refuse_data(&routes, &admission, &caller, reason).await;
                return None;
            }
        };
        *caller
            .body
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(body.clone());
        routes
            .serve_admitted(&admission, context, body, scheme, slot, Arc::clone(&caller))
            .await
    });
    // With `Server-Timing` on, the request is served under its measurement, so the forward path
    // records the upstream round trip the header subtracts and its head carries the header
    // (`ActorCaller::response_head`).
    let work = async {
        match &timing {
            Some(timing) => timing.measure(work).await,
            None => work.await,
        }
    };
    let pipe = match admission.deadline() {
        Some(deadline) => {
            match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), work).await {
                Ok(pipe) => pipe,
                Err(_) => {
                    admission.refuse(
                        busbar_contract::caps::StepName::Arrival,
                        ReasonCode::DeadlineExceeded,
                    );
                    out.send(Op::Refuse {
                        status: busbar_kernel::plane_driver::refusal_status(
                            ReasonCode::DeadlineExceeded,
                        ),
                        head_sent: caller.stated().is_some(),
                    });
                    return;
                }
            }
        }
        None => work.await,
    };
    if let Some(pipe) = pipe {
        out.send(Op::Switch { pipe });
        return;
    }
    if caller.stated().is_none() {
        out.send(Op::Refuse {
            status: busbar_kernel::plane_driver::refusal_status(ReasonCode::PlanePanic),
            head_sent: false,
        });
    } else if !caller.ended.load(std::sync::atomic::Ordering::Acquire) {
        let _ = out.data(Bytes::new(), true).await;
    }
}

async fn refuse_data(
    routes: &crate::root::serve::DataRoutes,
    admission: &busbar_kernel::inbound::RequestAdmission,
    caller: &ActorCaller,
    reason: busbar_contract::caps::ReasonCode,
) {
    use busbar_kernel::plane_driver::CallerEnd;
    admission.refuse(busbar_contract::caps::StepName::Arrival, reason);
    if let Some(rendered) = routes.refusal(admission, reason) {
        crate::root::serve::neutral::render(caller, rendered).await;
    } else {
        caller.head(
            busbar_kernel::plane_driver::refusal_status(reason),
            Vec::new(),
        );
    }
}

/// Queue a framer's reply wire. A buffer that cannot grow fails the connection: `failed` is set,
/// one WARN is logged, and what was queued is wiped, so no partial reply is ever written (the
/// peer sees a reset, never a truncated reply that looks complete).
fn absorb_wire(out: &mut SecureVec, failed: &mut bool, wire: &[u8]) {
    if *failed {
        return;
    }
    if let Err(e) = out.extend(wire) {
        tracing::warn!(
            target: "busbar::listener",
            error = %e,
            "reply buffer allocation failed; connection closed"
        );
        *failed = true;
        out.clear();
    }
}

/// One write of the reply buffer's contiguous run; what the peer took is wiped. `false` = the
/// connection failed.
fn write_some<W: AsyncWrite + Unpin>(
    out: &mut SecureVec,
    failed: &mut bool,
    io: Pin<&mut W>,
    cx: &mut Context<'_>,
) -> Poll<bool> {
    match io.poll_write(cx, out.as_slice()) {
        Poll::Ready(Ok(0)) | Poll::Ready(Err(_)) => {
            *failed = true;
            out.clear();
            Poll::Ready(false)
        }
        Poll::Ready(Ok(n)) => {
            out.consume(n);
            if out.is_empty() {
                out.shrink_when_empty(OUT_KEEP);
            }
            Poll::Ready(true)
        }
        Poll::Pending => Poll::Pending,
    }
}

#[cfg(test)]
#[path = "tests/listener_out_tests.rs"]
mod out_tests;

#[path = "listener_operator.rs"]
mod operator;

// These tests cover the explicitly retained operator response adapter.
#[cfg(test)]
use operator::{field_block, head_block, respond};

#[cfg(test)]
#[path = "tests/listener_framed_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/listener_empty_response_tests.rs"]
mod empty_response_tests;
