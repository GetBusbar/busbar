// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ACCEPTED DATA DOOR'S ANSWER (`BUSBAR-1.6.0.md` l.475-484, INBOUND-LISTEN; status row 192 C):
//! the ONE place a driven unit's reply is shaped for its caller.
//!
//! A unit states its head once and writes its body piece by piece ([`Reply`] is the handler's end
//! of that). Whether the answer goes out WHOLE (collected and sent under the length of what was
//! written), STREAMED (piece by piece as the unit writes, the unit running on its own task once its
//! head is stated), CLOSED BEFORE ITS BODY (a framer's close rendered before the first byte, sent as
//! one header block), or UNRENDERED (the unit ended with no head) is decided here, by
//! [`Reply::shape`], and nowhere else. Where the chosen shape is written is an [`Answer`] sink: the
//! hyper response the old path serves, or the accepted connection's own emits. Both read one
//! choice, so the bytes either path writes for a unit are the same by construction.

use std::future::Future;
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::http::HeaderMap;
use axum::response::Response;
use busbar_core_connector::compose::{Connection, Failure, Via};
use busbar_core_connector::framer::FramerDoor;
use busbar_core_connector::listen::{Accepted, Admitted, Composer, Listening};
/// The stream `Content-Type` every declared protocol states, folded at boot.
use busbar_kernel::ingress::protocols::streaming_content_types as declared_stream_media;
use busbar_kernel::plane_driver::{HeadFields, Rendered};
use tokio::sync::{mpsc, oneshot};

use crate::root::serve::{DataRoutes, DoorRequest, HandedDoor};

/// A reply head: the status number and the head fields.
pub(crate) type Head = (u32, HeadFields);

/// A unit the data door drives: what it rendered for its caller when it ended before any byte.
pub type DrivenUnit = std::pin::Pin<Box<dyn Future<Output = Option<Rendered>> + Send>>;

/// The handler's end of a caller side: the reply, once the unit states its head.
#[derive(Debug)]
pub struct Reply {
    pub(crate) head: oneshot::Receiver<Head>,
    pub(crate) body: mpsc::Receiver<Bytes>,
    /// The answer's trailers, where a framer renders a close after its body (ARCHITECT 4l).
    pub(crate) trailers: Option<oneshot::Receiver<HeaderMap>>,
}

/// A STREAMED answer's body as the sink is handed it: the pieces the unit writes, in order; the
/// unit's own task once its head is stated ([`Running`]; `None` when the unit already ended); and
/// the trailers a framer's close renders after the last piece, where the answer has them.
pub(crate) struct Streamed {
    pub(crate) body: mpsc::Receiver<Bytes>,
    pub(crate) running: Option<Running>,
    pub(crate) trailers: Option<oneshot::Receiver<HeaderMap>>,
}

/// WHERE ONE SHAPED ANSWER IS WRITTEN: each arm is one of the shapes [`Reply::shape`] chooses.
pub(crate) trait Answer: Send {
    /// What writing the answer comes to.
    type Out: Send;
    /// A WHOLE answer: `head` (its stated length taken out) and every byte the unit wrote.
    fn whole(self, head: Head, body: Vec<u8>) -> impl Future<Output = Self::Out> + Send;
    /// A framed answer CLOSED BEFORE ITS FIRST BODY BYTE: `head` and the framer's closing block,
    /// as ONE header block, no body.
    fn closed(self, head: Head, block: HeaderMap) -> impl Future<Output = Self::Out> + Send;
    /// A STREAMED answer: `head`, then the body piece by piece.
    fn streamed(self, head: Head, body: Streamed) -> impl Future<Output = Self::Out> + Send;
    /// The unit ended with NO HEAD: what it rendered (a refusal or failure before any byte), or
    /// nothing.
    fn unrendered(self, rendered: Option<Rendered>) -> impl Future<Output = Self::Out> + Send;
}

impl Reply {
    /// The same reply, its body followed by the trailers `trailers` delivers (a framer's close).
    #[must_use]
    pub fn with_trailers(mut self, trailers: oneshot::Receiver<HeaderMap>) -> Self {
        self.trailers = Some(trailers);
        self
    }

    /// THE UNIT, ANSWERED THROUGH `sink`: `unit` runs here until it states its head, then (a
    /// streamed answer) on its own task, so a caller that goes away drops it (the driver's
    /// client-drop path). The one choice, written to whichever sink serves the caller.
    pub(crate) async fn shape<A: Answer>(self, mut unit: DrivenUnit, sink: A) -> A::Out {
        let Reply {
            mut head,
            body,
            mut trailers,
        } = self;
        let first = tokio::select! {
            biased;
            h = &mut head => Ok(h.ok()),
            rendered = &mut unit => Err(rendered),
        };
        match first {
            // A WHOLE ANSWER goes out whole: an answer whose head states its length (one the plane
            // rendered in full) is collected to its end and sent under the length of what was
            // written, as the previous release sent a buffered answer; any other answer goes out
            // piece by piece as the unit writes it.
            Ok(Some(h)) if whole_answer(&h.1) => {
                let whole = collect(body, unit).await;
                sink.whole(unlengthed(h), whole).await
            }
            // A STREAMED ANSWER: the unit runs on, on its own task, once its head is stated
            // (ARCHITECT ruling 2026-10-07, STREAM-CEILING); the body only drains what it writes.
            // A framed answer already closed before its first body byte goes out whole instead,
            // the unit run to its end.
            Ok(Some(h)) => {
                if let Some(block) = closed_before_body(&body, trailers.as_mut()) {
                    let _ = unit.await;
                    return sink.closed(h, block).await;
                }
                let running = Running(tokio::spawn(unit));
                sink.streamed(
                    h,
                    Streamed {
                        body,
                        running: Some(running),
                        trailers,
                    },
                )
                .await
            }
            Ok(None) => {
                let rendered = unit.await;
                sink.unrendered(rendered).await
            }
            Err(rendered) => match head.try_recv() {
                // The unit ended in the poll that stated its head: a whole answer is every piece it
                // wrote, sent under its length.
                Ok(h) if whole_answer(&h.1) => {
                    let mut body = body;
                    let mut whole = Vec::new();
                    while let Ok(bytes) = body.try_recv() {
                        whole.extend_from_slice(&bytes);
                    }
                    sink.whole(unlengthed(h), whole).await
                }
                Ok(h) => {
                    if let Some(block) = closed_before_body(&body, trailers.as_mut()) {
                        return sink.closed(h, block).await;
                    }
                    sink.streamed(
                        h,
                        Streamed {
                            body,
                            running: None,
                            trailers,
                        },
                    )
                    .await
                }
                Err(_) => sink.unrendered(rendered).await,
            },
        }
    }
}

/// A FRAMED ANSWER THAT CLOSED BEFORE ITS FIRST BODY BYTE (ARCHITECT ruling on #787): its close is
/// already rendered and nothing of its body was written. The closing block, taken; `None` when the
/// body holds bytes or the answer is still open.
///
/// The probe takes the trailers only when they are ready (`try_recv` leaves an open answer's where
/// it is), and a body with bytes is never asked for its close.
pub(crate) fn closed_before_body(
    body: &mpsc::Receiver<Bytes>,
    trailers: Option<&mut oneshot::Receiver<HeaderMap>>,
) -> Option<HeaderMap> {
    if !body.is_empty() {
        return None;
    }
    trailers?.try_recv().ok()
}

/// Whether a reply head is a WHOLE answer's: it states its length and is no stream (one of the
/// [`streamed_media`] types, which the previous release relayed piece by piece).
pub(crate) fn whole_answer(fields: &HeadFields) -> bool {
    let named = |field: &[u8]| {
        fields
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(field))
            .map(|(_, value)| String::from_utf8_lossy(value).to_ascii_lowercase())
    };
    named(b"content-length").is_some()
        && !named(b"content-type").is_some_and(|v| streamed_media(&v))
}

/// Whether `content_type` is a stream's, read off the DECLARED ROWS and never spelled here (Law 1;
/// BUSBAR-1.6.0.md: "Dialects are internal to their plane"): the event stream the contract names,
/// or the stream `Content-Type` a declared protocol states on its `ProtocolDecl` row, folded at
/// boot.
pub(crate) fn streamed_media(content_type: &str) -> bool {
    std::iter::once(busbar_contract::protocol::TEXT_EVENT_STREAM)
        .chain(declared_stream_media().iter().copied())
        .any(|media| {
            content_type
                .get(..media.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(media))
        })
}

/// A whole answer's head without its stated length: the answer states the length of what was
/// written.
pub(crate) fn unlengthed((status, mut fields): Head) -> Head {
    fields.retain(|(name, _)| !name.eq_ignore_ascii_case(b"content-length"));
    (status, fields)
}

/// Every piece the unit writes until it ends, the unit driven meanwhile (its writes wait on this
/// side), then whatever it wrote last.
pub(crate) async fn collect(mut body: mpsc::Receiver<Bytes>, mut unit: DrivenUnit) -> Vec<u8> {
    let mut whole = Vec::new();
    loop {
        tokio::select! {
            biased;
            piece = body.recv() => match piece {
                Some(bytes) => whole.extend_from_slice(&bytes),
                None => {
                    let _ = unit.await;
                    break;
                }
            },
            _ = &mut unit => {
                while let Ok(bytes) = body.try_recv() {
                    whole.extend_from_slice(&bytes);
                }
                break;
            }
        }
    }
    whole
}

/// A UNIT RUNNING ON ITS OWN TASK after its head (ARCHITECT ruling 2026-10-07, STREAM-CEILING): it
/// is driven whether or not its body is read, so a caller that stops reading with its socket open
/// leaves the unit's own deadline able to fire (a plane's stated ceiling) instead of freezing it
/// until the socket closes. Dropping it aborts the task, which drops the unit there: the answer's
/// body was dropped, so its caller is gone, and the unit ends on the driver's client-drop path as
/// it did when the body owned it.
pub(crate) struct Running(pub(crate) tokio::task::JoinHandle<Option<Rendered>>);

impl Drop for Running {
    fn drop(&mut self) {
        self.0.abort();
    }
}

// ── THE INTERNAL SWITCH ──────────────────────────────────────────────────────────────────────────

/// WHICH PATH SERVES THE DATA DOOR, read here and nowhere else. Framed (`true`): the connector's
/// listener, bound to the data listener's own framer, frames every accepted connection and the
/// units its transport hands in are served here ([`serve_door`]). Handed up (`false`, the
/// `data-door-handup` build feature): each accepted socket is handed up to the kernel's hyper loop
/// as before. A build feature, never an environment variable: the oracle recorder strips the
/// environment. Both arms compile in every build.
pub const DATA_DOOR_FRAMED: bool = !cfg!(feature = "data-door-handup");

// ── THE ROUTES THE DOOR DRIVES ───────────────────────────────────────────────────────────────────

fn routes_slot() -> std::sync::MutexGuard<'static, Option<Arc<DataRoutes>>> {
    static ROUTES: Mutex<Option<Arc<DataRoutes>>> = Mutex::new(None);
    ROUTES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Stage the door planes' routes where they are built (`root::serve::door_mounts`), for the
/// accepted data door to drive the units its transport hands in.
pub(crate) fn stage_routes(routes: Arc<DataRoutes>) {
    *routes_slot() = Some(routes);
}

/// The door planes' routes staged last; `None` when no plane claims a route.
pub(crate) fn staged_routes() -> Option<Arc<DataRoutes>> {
    routes_slot().clone()
}

// ── THE DOOR ─────────────────────────────────────────────────────────────────────────────────────

/// A framer door, as the data door finds the one a switch hands a connection to.
pub type FramerFor = Arc<dyn Fn(&str) -> Option<Arc<dyn FramerDoor>> + Send + Sync>;

/// WHAT THE ACCEPTED DATA DOOR SERVES WITH: the door planes' routes (none when no plane claims a
/// route), the kernel's data router (the residual line's claimant, its own gate around its routes,
/// called in process), the generation handle the router's layers read, the instance identity of
/// the transport the listener is bound to (its guest list's owner), whether the listener is
/// secured, whether `Server-Timing` is stamped, and where a switch finds its framer.
pub struct DataDoor {
    routes: Option<Arc<DataRoutes>>,
    router: axum::Router,
    handle: Arc<busbar_kernel::state::AppHandle>,
    owner: u64,
    secured: bool,
    server_timing: bool,
    framer_for: FramerFor,
}

impl std::fmt::Debug for DataDoor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DataDoor")
            .field("owner", &self.owner)
            .field("secured", &self.secured)
            .finish_non_exhaustive()
    }
}

impl DataDoor {
    /// The door over the kernel's data `router` and its `handle`, its guest list owned by the
    /// transport instance `owner`, the door planes' routes as staged, switches finding their
    /// framer on the process's connector.
    #[must_use]
    pub fn new(
        router: axum::Router,
        handle: Arc<busbar_kernel::state::AppHandle>,
        owner: u64,
        secured: bool,
        server_timing: bool,
    ) -> Self {
        Self {
            routes: staged_routes(),
            router,
            handle,
            owner,
            secured,
            server_timing,
            framer_for: Arc::new(|scheme: &str| crate::root::connector::the().framer_for(scheme)),
        }
    }

    /// THE DOOR A CELL BINDS: over the door planes' `routes`, the data `router` (without its
    /// admission cap), its `handle`, its guest list owned by `owner`; in the clear, no timing field,
    /// no switch target.
    #[cfg(test)]
    pub(crate) fn over(
        routes: Option<Arc<DataRoutes>>,
        router: axum::Router,
        handle: Arc<busbar_kernel::state::AppHandle>,
        owner: u64,
    ) -> Self {
        Self {
            routes,
            router,
            handle,
            owner,
            secured: false,
            server_timing: false,
            framer_for: Arc::new(|_: &str| -> Option<Arc<dyn FramerDoor>> { None }),
        }
    }

    /// The same door, a switch finding its framer through `framer_for`.
    #[must_use]
    pub fn finding_framers(mut self, framer_for: FramerFor) -> Self {
        self.framer_for = framer_for;
        self
    }

    /// The scheme every request on the listener states.
    fn scheme(&self) -> busbar_kernel::plane_routes::ListenerScheme {
        busbar_kernel::plane_routes::ListenerScheme(if self.secured {
            busbar_contract::abi::host::service::SCHEME_SECURE
        } else {
            busbar_contract::abi::host::service::SCHEME_PLAIN
        })
    }
}

/// THE FRAMED DATA DOOR as each data worker binds it: the data listener's own framer, the
/// instance identity its guest list is owned by, and the door its connections are served with.
#[derive(Clone)]
pub struct FramedDoor {
    /// The data listener's framer (`root::boot::data_door_framer`).
    pub framer: Arc<dyn FramerDoor>,
    /// Its instance identity (`root::doors::owner_of`), entered with `root::inbound::serve_under`.
    pub owner: u64,
    /// What its connections are served with.
    pub door: Arc<DataDoor>,
}

impl std::fmt::Debug for FramedDoor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FramedDoor")
            .field("framer", &self.framer.facts().name)
            .field("owner", &self.owner)
            .finish_non_exhaustive()
    }
}

/// THE REFUSAL OF A FRAMER THE LOADER NAMES NO INSTANCE FOR: its guest list has no owner to be
/// installed under, so the data listener is not bound.
pub const FRAMER_UNOWNED: &str =
    "listen: the data listener's framer names no instance its guest list could be lent under";

/// THE FRAMED DATA DOOR over `framer` (found by `root::boot::data_door_framer`): its owner entered
/// as one the data listener's table is installed under at every generation, and the door its
/// connections are served with.
///
/// # Errors
///
/// [`FRAMER_UNOWNED`]; the kernel refused the listener's table.
pub fn framed_door(
    framer: Arc<dyn FramerDoor>,
    router: axum::Router,
    handle: Arc<busbar_kernel::state::AppHandle>,
    secured: bool,
    server_timing: bool,
) -> Result<FramedDoor, String> {
    let owner = crate::root::doors::owner_of(framer.as_ref()).ok_or(FRAMER_UNOWNED)?;
    crate::root::inbound::serve_under(owner).map_err(|e| format!("listen: {e}"))?;
    let door = Arc::new(DataDoor::new(router, handle, owner, secured, server_timing));
    Ok(FramedDoor {
        framer,
        owner,
        door,
    })
}

// ── THE ACCEPT LOOP ──────────────────────────────────────────────────────────────────────────────

/// SERVE THE DATA DOOR on `listener` (bound framed, lending the guest list of `door`'s owner)
/// until `shutdown` resolves, then drain: each admitted connection placed by `balancer` (served
/// here, or handed bare to the least-loaded worker before any handshake, `via` the carrier that
/// adopts what another worker hands here), composed (`carrier -> [TLS] -> framer`) where it runs,
/// and served by [`serve_conn`]. A listener that frames nothing is refused at its first accept and
/// serves nothing: the hand-up is never this door's fallback.
pub async fn serve_door(
    mut listener: Listening,
    via: Option<Via>,
    door: Arc<DataDoor>,
    shutdown: impl Future<Output = ()> + Send + 'static,
    mut balancer: Option<crate::root::listener::ConnBalancer>,
) {
    use crate::root::listener::Placed;
    let composer = listener.composer();
    let (stop_tx, stop) = tokio::sync::watch::channel(false);
    let mut conns: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
    let mut shutdown = std::pin::pin!(shutdown);
    loop {
        tokio::select! {
            biased;
            () = &mut shutdown => break,
            handed = async { balancer.as_mut().expect("guarded by if").handed().await },
                if balancer.is_some() =>
            {
                let Some((a, guard)) = handed else { continue };
                if let Some((accepted, hold)) = adopted(via.as_ref(), &composer, a) {
                    spawn_conn(&mut conns, accepted, &door, &stop, Box::new((guard, hold)));
                }
            }
            arrived = std::future::poll_fn(|cx| listener.poll_admit(cx)) => {
                let Ok(arrived) = arrived else {
                    tracing::error!("the data listener frames nothing; it serves no connection");
                    break;
                };
                let Some(b) = balancer.as_ref() else {
                    let (carried, peer) = (arrived.carried, arrived.peer);
                    let accepted = composer.compose(carried, peer, Some(arrived.slot));
                    spawn_conn(&mut conns, accepted, &door, &stop, Box::new(()));
                    continue;
                };
                match b.place_arrived(arrived) {
                    Placed::Here(a, guard) => {
                        let a = *a;
                        let accepted = composer.compose(a.carried, a.peer, Some(a.slot));
                        spawn_conn(&mut conns, accepted, &door, &stop, Box::new(guard));
                    }
                    Placed::Moved => {}
                    Placed::Back(a, guard) => {
                        if let Some((accepted, hold)) = adopted(via.as_ref(), &composer, a) {
                            spawn_conn(&mut conns, accepted, &door, &stop, Box::new((guard, hold)));
                        }
                    }
                }
            }
            Some(_) = conns.join_next(), if !conns.is_empty() => {}
        }
    }
    // Connections another worker placed here before it saw the shutdown are served all the same.
    if let Some(b) = balancer.as_mut() {
        for (a, guard) in b.drain_handed() {
            if let Some((accepted, hold)) = adopted(via.as_ref(), &composer, a) {
                spawn_conn(&mut conns, accepted, &door, &stop, Box::new((guard, hold)));
            }
        }
    }
    // Stop taking requests; drain the ones in flight.
    let _ = stop_tx.send(true);
    while conns.join_next().await.is_some() {}
}

/// A composed connection, or why it could not be composed.
type Composed = Result<Accepted, Failure>;

/// Serve `accepted` on its own task in `conns`, holding `keep` for its life.
fn spawn_conn(
    conns: &mut tokio::task::JoinSet<()>,
    accepted: Composed,
    door: &Arc<DataDoor>,
    stop: &tokio::sync::watch::Receiver<bool>,
    keep: Box<dyn Send>,
) {
    if let Ok(accepted) = accepted {
        conns.spawn(serve_conn(
            accepted.conn,
            Arc::clone(door),
            stop.clone(),
            keep,
        ));
    }
}

/// A connection another worker handed here bare, adopted by the carrier `via` names and composed
/// here, with what its listener holds for it.
fn adopted(
    via: Option<&Via>,
    composer: &Composer,
    a: Admitted,
) -> Option<(Composed, Option<Box<dyn Send>>)> {
    let via = via?;
    let carried = busbar_core_connector::carrier::Carried::adopted(
        Arc::clone(&via.door),
        Arc::clone(&via.io),
        a.stream,
    )?;
    Some((composer.compose(carried, a.peer, None), a.hold))
}

// ── ONE CONNECTION ───────────────────────────────────────────────────────────────────────────────

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
    /// The stream refused: `bytes` at `status` before its head went, its answer broken after.
    Refuse {
        bytes: Vec<u8>,
        status: u32,
        head_sent: bool,
    },
    /// The connection switched to `door` on this stream's upgrade, the admitted session's pipe
    /// carried over it.
    Switch {
        door: Arc<dyn FramerDoor>,
        pipe: busbar_kernel::plane_routes::SessionPipe,
        done: oneshot::Sender<bool>,
    },
    /// The stream's task ended: its inflow goes.
    Ended,
}

/// A stream task's end of its connection.
#[derive(Clone)]
struct Emitter {
    stream: u64,
    tx: mpsc::UnboundedSender<(u64, Op)>,
}

impl Emitter {
    async fn ask(&self, op: Op, done: oneshot::Receiver<bool>) -> bool {
        if self.tx.send((self.stream, op)).is_err() {
            return false;
        }
        done.await.unwrap_or(false)
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

    fn refuse(&self, bytes: Vec<u8>, status: u32, head_sent: bool) {
        let op = Op::Refuse {
            bytes,
            status,
            head_sent,
        };
        let _ = self.tx.send((self.stream, op));
    }

    async fn switch(
        &self,
        door: Arc<dyn FramerDoor>,
        pipe: busbar_kernel::plane_routes::SessionPipe,
    ) -> bool {
        let (done, said) = oneshot::channel();
        self.ask(Op::Switch { door, pipe, done }, said).await
    }
}

/// A STREAM'S END, however its task ends (answered, failed, or aborted when its caller gave the
/// stream up): its inflow goes from the connection, and its unit leaves the kernel's table
/// (`Inbound::exit`: its credential zeroised, its admission slot given back).
struct StreamEnd {
    out: Emitter,
    unit: u64,
}

impl Drop for StreamEnd {
    fn drop(&mut self) {
        let _ = self.out.tx.send((self.out.stream, Op::Ended));
        crate::root::inbound::host().exit(self.unit);
    }
}

/// A request body's error, as the kernel's router reads one.
type BodyError = Box<dyn std::error::Error + Send + Sync>;

/// One request's inflow: where its body pieces go, how many bytes went, and its task.
struct Inflow {
    body: Option<mpsc::UnboundedSender<Result<Bytes, BodyError>>>,
    sent: usize,
    task: tokio::task::AbortHandle,
    /// Whether whoever answered the request read its body to its end.
    drained: Arc<std::sync::atomic::AtomicBool>,
}

/// A connection SWITCHED to a session's framer: the session's stream, the caller's messages on
/// their way to the session, the frames the session writes toward the caller, and the frame being
/// written.
struct Session {
    stream: u64,
    from: Option<mpsc::UnboundedSender<Vec<u8>>>,
    message: Vec<u8>,
    to: mpsc::Receiver<busbar_kernel::plane_routes::SessionOut>,
    writing: Option<(Bytes, bool)>,
}

/// The stream refused because no admitted unit was handed in for it.
const UNHANDED_STATUS: u32 = 500;

/// ONE ACCEPTED CONNECTION, SERVED: its frame pieces demultiplexed by stream. A head piece takes
/// up the unit its transport handed in on that stream (`Inbound::take_handed`, keyed by the
/// framing's identity) and starts the stream's task ([`serve_stream`]); each body piece goes to
/// its stream's request body. What the tasks ask (heads, body bytes, refusals, a switch) is
/// applied in order, as the connection's room allows. `stop` ends the connection once nothing is
/// in flight; `keep` (its listener slot and placement count) is held for its life.
async fn serve_conn(
    conn: Connection,
    door: Arc<DataDoor>,
    mut stop: tokio::sync::watch::Receiver<bool>,
    keep: Box<dyn Send>,
) {
    let (tx, ops) = mpsc::unbounded_channel();
    let mut served = Conn {
        conn: Some(conn),
        door,
        ops,
        tx,
        pending: std::collections::VecDeque::new(),
        inflows: std::collections::HashMap::new(),
        tasks: tokio::task::JoinSet::new(),
        session: None,
        read_done: false,
        closing: false,
        multiplexed: false,
        stopping: *stop.borrow(),
    };
    loop {
        tokio::select! {
            () = std::future::poll_fn(|cx| served.poll(cx)) => break,
            changed = stop.changed(), if !served.stopping => {
                served.stopping = changed.is_err() || *stop.borrow();
            }
        }
    }
    drop(keep);
}

/// One connection's serving state ([`serve_conn`]).
struct Conn {
    conn: Option<Connection>,
    door: Arc<DataDoor>,
    ops: mpsc::UnboundedReceiver<(u64, Op)>,
    tx: mpsc::UnboundedSender<(u64, Op)>,
    pending: std::collections::VecDeque<(u64, Op)>,
    inflows: std::collections::HashMap<u64, Inflow>,
    tasks: tokio::task::JoinSet<()>,
    session: Option<Session>,
    read_done: bool,
    stopping: bool,
    /// A request was answered with its body not read to its end: the connection closes once
    /// nothing is in flight, as the hyper loop closed one whose request body was left unread.
    closing: bool,
    /// The connection carries concurrent streams (h2): it is never closed for one stream's unread
    /// body.
    multiplexed: bool,
}

/// What applying one op came to.
enum Step {
    /// Applied (or failed): the next op goes.
    Done,
    /// The connection has no room yet: the op waits, its waker armed.
    Wait,
}

impl Conn {
    fn poll(&mut self, cx: &mut std::task::Context<'_>) -> std::task::Poll<()> {
        use std::task::Poll;
        loop {
            let mut moved = false;
            while let Poll::Ready(Some(op)) = self.ops.poll_recv(cx) {
                self.pending.push_back(op);
            }
            while let Poll::Ready(Some(_)) = self.tasks.poll_join_next(cx) {
                moved = true;
            }
            if self.conn.is_none() {
                return Poll::Ready(());
            }
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
                        self.close();
                        return Poll::Ready(());
                    }
                }
            }
            if !self.read_done {
                let Some(conn) = self.conn.as_mut() else {
                    return Poll::Ready(());
                };
                match conn.poll_piece(cx) {
                    Poll::Ready(Ok(Some(piece))) => {
                        self.piece(piece);
                        moved = true;
                    }
                    Poll::Ready(Ok(None)) => {
                        self.read_done = true;
                        // Nothing more arrives: every body still open ends here, and a session's
                        // caller has closed.
                        for inflow in self.inflows.values_mut() {
                            inflow.body = None;
                        }
                        if let Some(s) = self.session.as_mut() {
                            s.from = None;
                        }
                        moved = true;
                    }
                    Poll::Ready(Err(failure)) => {
                        tracing::debug!(%failure, "data door: the connection failed");
                        self.tasks.abort_all();
                        self.conn = None;
                        return Poll::Ready(());
                    }
                    Poll::Pending => {}
                }
            }
            let idle = self.tasks.is_empty() && self.pending.is_empty() && self.session.is_none();
            if idle && (self.read_done || self.stopping || self.closing) {
                self.close();
                return Poll::Ready(());
            }
            if !moved {
                return Poll::Pending;
            }
        }
    }

    /// Close the connection: the framing finishes, connection security says goodbye.
    fn close(&mut self) {
        if let Some(conn) = self.conn.take() {
            conn.close();
        }
    }

    /// One frame piece off the connection.
    fn piece(&mut self, piece: busbar_core_connector::framer::Got) {
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
        let cap = busbar_kernel_egress::upstream::max_translate_body_bytes();
        match self.inflows.get_mut(&piece.stream) {
            None if piece.fields && !piece.failed => self.head(piece.stream, piece.end),
            // A piece of a stream no task holds (answered, or never handed in): dropped.
            None => {}
            Some(inflow) => {
                if piece.failed {
                    // The far side gave the stream up: its task ends on the driver's
                    // client-drop path, as the hyper loop dropped a reset stream's service.
                    if let Some(body) = inflow.body.take() {
                        let reason = String::from_utf8_lossy(&piece.bytes).into_owned();
                        let _ = body.send(Err(BodyError::from(reason)));
                    }
                    inflow.task.abort();
                    return;
                }
                // A trailer block of the request is not read: the router's body read takes data.
                if !piece.fields && !piece.bytes.is_empty() && inflow.sent <= cap {
                    inflow.sent += piece.bytes.len();
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

    /// A request head on `stream`: the unit its transport handed in there, taken up and served on
    /// its own task. `end` = the request has no body.
    fn head(&mut self, stream: u64, end: bool) {
        let Some(conn) = self.conn.as_mut() else {
            return;
        };
        let handed = conn.framing_id().and_then(|framing| {
            crate::root::inbound::host().take_handed(self.door.owner, framing, stream)
        });
        let Some(handed) = handed else {
            // No admitted unit was handed in for it: nothing serves it.
            let _ = conn.refuse_stream(stream, &[], UNHANDED_STATUS, false);
            return;
        };
        let (body_tx, body_rx) = mpsc::unbounded_channel();
        let out = Emitter {
            stream,
            tx: self.tx.clone(),
        };
        let body = InboundBody::new(body_rx, end);
        let drained = Arc::clone(&body.drained);
        let task = self
            .tasks
            .spawn(serve_stream(Arc::clone(&self.door), handed, body, out));
        self.inflows.insert(
            stream,
            Inflow {
                body: (!end).then_some(body_tx),
                sent: 0,
                task,
                drained,
            },
        );
    }

    /// Apply the first pending op, as far as the connection's room allows.
    fn apply_front(&mut self, cx: &mut std::task::Context<'_>) -> Step {
        let Some(conn) = self.conn.as_mut() else {
            self.pending.clear();
            return Step::Done;
        };
        let Some((stream, op)) = self.pending.front_mut() else {
            return Step::Done;
        };
        let stream = *stream;
        let ok = match op {
            Op::Head {
                status,
                fields,
                end,
                ..
            } => conn
                .emit_head(stream, *status, &fields[..], *end, cx)
                .is_ok(),
            Op::Data { bytes, end, .. } => loop {
                match conn.emit(stream, &bytes[..], *end, false, cx) {
                    Ok(n) if n >= bytes.len() => break true,
                    Ok(0) => return Step::Wait,
                    Ok(n) => {
                        let rest = bytes.slice(n..);
                        *bytes = rest;
                    }
                    Err(_) => break false,
                }
            },
            Op::Refuse {
                bytes,
                status,
                head_sent,
            } => conn
                .refuse_stream(stream, &bytes[..], *status, *head_sent)
                .is_ok(),
            Op::Switch { door, .. } => conn.switch(stream, Arc::clone(door)).is_ok(),
            Op::Ended => {
                // h1: a request answered with its body unread closes the connection once idle, as
                // the hyper loop closed one. A connection whose framer states it agreed the
                // offer's multiplexed protocol (`Connection::agreed`): the stream ends on its own
                // (its answer whole, the rest of its body dropped as it arrives) and the connection
                // and its other streams serve on, as the hyper loop's h2 reset the one stream. A
                // framer that states none is held to the h1 rule.
                let multiplexed = busbar_core_connector::tls::multiplexed_alpn();
                self.multiplexed |= conn.agreed() == Some(multiplexed);
                if let Some(inflow) = self.inflows.remove(&stream) {
                    let drained = inflow.drained.load(std::sync::atomic::Ordering::Acquire);
                    self.closing |= !drained && !self.multiplexed;
                }
                true
            }
        };
        let Some((stream, op)) = self.pending.pop_front() else {
            return Step::Done;
        };
        match op {
            Op::Head { done, .. } | Op::Data { done, .. } => {
                let _ = done.send(ok);
            }
            Op::Switch { pipe, done, .. } => {
                if ok {
                    self.session = Some(Session::over(stream, pipe));
                }
                let _ = done.send(ok);
            }
            Op::Refuse { .. } | Op::Ended => {}
        }
        Step::Done
    }

    /// Pump a switched connection's session: the frames it writes go out as the connection's room
    /// allows. `Some(moved)` while it runs; `None` once the session has ended (its connection
    /// closes).
    fn pump_session(&mut self, cx: &mut std::task::Context<'_>) -> Option<bool> {
        use std::task::Poll;
        let (Some(conn), Some(session)) = (self.conn.as_mut(), self.session.as_mut()) else {
            return None;
        };
        let mut moved = false;
        loop {
            if let Some((bytes, text)) = session.writing.as_mut() {
                match conn.emit(session.stream, &bytes[..], true, *text, cx) {
                    Ok(n) if n >= bytes.len() => session.writing = None,
                    Ok(0) => return Some(moved),
                    Ok(n) => {
                        let rest = bytes.slice(n..);
                        *bytes = rest;
                        continue;
                    }
                    Err(_) => return None,
                }
                moved = true;
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

impl Session {
    /// The session `pipe` carries over the connection switched on `stream`: the caller's messages
    /// are handed to the session in order, each awaited, off the connection's task.
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

// ── ONE REQUEST'S BODY ───────────────────────────────────────────────────────────────────────────

/// A REQUEST BODY as its pieces arrive on the connection, held to the kernel's one body time
/// policy (`busbar_kernel::limits::body`) as the hyper loop's body is: no piece within the read
/// timeout is [`busbar_kernel::limits::body::BodyBound::Idle`]; past the total deadline, or under
/// the throughput floor after its grace, fails too. The words are the policy's, so a body that
/// fails is answered as the router's body read answers it.
struct InboundBody {
    pieces: mpsc::UnboundedReceiver<Result<Bytes, BodyError>>,
    timeout: std::time::Duration,
    sleep: Option<std::pin::Pin<Box<tokio::time::Sleep>>>,
    started: Option<std::time::Instant>,
    bytes: u64,
    ended: bool,
    /// Raised when the body was read to its end (at once, for a request that carries none).
    drained: Arc<std::sync::atomic::AtomicBool>,
}

impl InboundBody {
    /// The body `pieces` deliver; `ended` = the request carried none.
    fn new(pieces: mpsc::UnboundedReceiver<Result<Bytes, BodyError>>, ended: bool) -> Self {
        Self {
            pieces,
            timeout: busbar_kernel::limits::body::read_timeout(),
            sleep: None,
            started: None,
            bytes: 0,
            ended,
            drained: Arc::new(std::sync::atomic::AtomicBool::new(ended)),
        }
    }
}

impl http_body::Body for InboundBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Bytes>, BodyError>>> {
        use std::task::Poll;
        let this = self.get_mut();
        if this.ended {
            return Poll::Ready(None);
        }
        let started = *this.started.get_or_insert_with(std::time::Instant::now);
        if let Some(bound) = busbar_kernel::limits::body::bounds(
            started.elapsed(),
            this.bytes,
            busbar_kernel::limits::body::total_deadline(),
        ) {
            this.ended = true;
            return Poll::Ready(Some(Err(Box::new(bound) as BodyError)));
        }
        match this.pieces.poll_recv(cx) {
            Poll::Ready(Some(Ok(bytes))) => {
                this.sleep = None;
                this.bytes = this.bytes.saturating_add(bytes.len() as u64);
                Poll::Ready(Some(Ok(http_body::Frame::data(bytes))))
            }
            Poll::Ready(Some(Err(e))) => {
                this.ended = true;
                Poll::Ready(Some(Err(e)))
            }
            Poll::Ready(None) => {
                this.ended = true;
                this.drained
                    .store(true, std::sync::atomic::Ordering::Release);
                Poll::Ready(None)
            }
            Poll::Pending => {
                let timeout = this.timeout;
                let sleep = this
                    .sleep
                    .get_or_insert_with(|| Box::pin(tokio::time::sleep(timeout)));
                match sleep.as_mut().poll(cx) {
                    Poll::Ready(()) => {
                        this.ended = true;
                        let idle = busbar_kernel::limits::body::BodyBound::Idle;
                        Poll::Ready(Some(Err(Box::new(idle) as BodyError)))
                    }
                    Poll::Pending => Poll::Pending,
                }
            }
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

/// What reading a request body under the body cap came to, as the route's body read answers.
enum BodyRead {
    /// Past the cap: the over-gate refusal answers it.
    Over,
    /// The body failed (a bound broke, or the caller gave it up): the router's `400` with the
    /// failure's words (boxed: a response is large).
    Failed(Box<Response>),
}

/// THE BODY, READ WHOLE UNDER `cap` bytes, as the data router's body read does (its body limit,
/// then its buffer): past the cap is [`BodyRead::Over`]; a failure is answered with the words the
/// router's buffer error names.
async fn read_body(mut body: axum::body::Body, cap: usize) -> Result<Bytes, BodyRead> {
    let mut whole = Vec::new();
    loop {
        let frame = std::future::poll_fn(|cx| {
            http_body::Body::poll_frame(std::pin::Pin::new(&mut body), cx)
        })
        .await;
        match frame {
            None => return Ok(Bytes::from(whole)),
            Some(Ok(frame)) => {
                if let Ok(data) = frame.into_data() {
                    if whole.len().saturating_add(data.len()) > cap {
                        return Err(BodyRead::Over);
                    }
                    whole.extend_from_slice(&data);
                }
            }
            Some(Err(e)) => {
                return Err(BodyRead::Failed(Box::new(
                    axum::response::IntoResponse::into_response((
                        axum::http::StatusCode::BAD_REQUEST,
                        format!("Failed to buffer the request body: {e}"),
                    )),
                )))
            }
        }
    }
}

// ── ONE STREAM ───────────────────────────────────────────────────────────────────────────────────

/// THE REQUEST a handed-in unit's head states, as the kernel's router reads one: its method, its
/// target and query, its field lines in order (what the line's auths named already stripped by
/// its transport), `body`, and the listener's scheme. `None` = a head no request can carry.
fn request_of(
    head: &busbar_kernel::inbound::Head,
    body: axum::body::Body,
    scheme: busbar_kernel::plane_routes::ListenerScheme,
) -> Option<axum::http::Request<axum::body::Body>> {
    let target = match &head.query {
        Some(q) => format!("{}?{q}", head.target),
        None => head.target.clone(),
    };
    let mut req = axum::http::Request::builder()
        .method(axum::http::Method::from_bytes(head.method.as_bytes()).ok()?)
        .uri(axum::http::Uri::try_from(target).ok()?)
        .body(body)
        .ok()?;
    let headers = req.headers_mut();
    for (name, value) in &head.fields {
        if let (Ok(name), Ok(value)) = (
            axum::http::HeaderName::from_bytes(name.as_bytes()),
            axum::http::HeaderValue::from_bytes(value),
        ) {
            headers.append(name, value);
        }
    }
    req.extensions_mut().insert(scheme);
    Some(req)
}

/// ONE STREAM, SERVED: the request its unit was handed in with, dispatched by its line's claimant
/// (a door plane's claim driven under the unit's own key, an upgrade line's session, or the
/// kernel's data router in process), its answer written through the connection ([`ConnAnswer`]).
/// The unit leaves the kernel's table when the stream ends ([`StreamEnd`]).
async fn serve_stream(
    door: Arc<DataDoor>,
    handed: busbar_kernel::inbound::Handed,
    body: InboundBody,
    out: Emitter,
) {
    let _end = StreamEnd {
        out: out.clone(),
        unit: handed.unit,
    };
    let answer = ConnAnswer { out: out.clone() };
    let request = crate::root::inbound::host()
        .head_of(handed.unit)
        .and_then(|head| request_of(&head, axum::body::Body::new(body), door.scheme()));
    let Some(request) = request else {
        out.refuse(Vec::new(), UNHANDED_STATUS, false);
        return;
    };
    let doorway = door
        .routes
        .as_ref()
        .map_or(HandedDoor::Router, |r| r.door_of_line(handed.line));
    match doorway {
        HandedDoor::Router => {
            use hyper::service::Service as _;
            let service = hyper_util::service::TowerToHyperService::new(door.router.clone());
            let Ok(response) = service.call(request).await;
            answer.respond(response).await;
        }
        HandedDoor::Request { .. } | HandedDoor::Catalog { .. } => {
            let response = door
                .layered(request, |req| door.plane(req, &doorway, handed))
                .await;
            answer.respond(response).await;
        }
        HandedDoor::Session {
            plane,
            claim,
            ref carrier,
        } => {
            let Some(routes) = door.routes.clone() else {
                return;
            };
            let mut pipe = None;
            let admitted_into = &mut pipe;
            let this: &DataDoor = &door;
            let response = this
                .layered(request, move |req| async move {
                    let req = match this.door_request(req, handed).await {
                        Ok(req) => req,
                        Err(response) => return *response,
                    };
                    let key = busbar_contract::UnitKey::new(handed.unit);
                    let opened = routes.open_session_keyed(plane, claim, req, Some(key));
                    match opened.await {
                        busbar_kernel::plane_routes::SessionAnswer::Refused(response) => {
                            routed(response, false)
                        }
                        busbar_kernel::plane_routes::SessionAnswer::Accepted(admitted) => {
                            *admitted_into = Some(admitted);
                            Response::default()
                        }
                    }
                })
                .await;
            match pipe {
                // ADMITTED: the connection switches to the framer the line's carrier names, which
                // writes its own answer to the upgrade; the session runs over it.
                Some(pipe) => match (door.framer_for)(carrier.as_str()) {
                    Some(framer) => {
                        let _ = out.switch(framer, pipe).await;
                    }
                    None => out.refuse(Vec::new(), UNHANDED_STATUS, false),
                },
                None => {
                    answer.respond(response).await;
                }
            }
        }
    }
}

impl DataDoor {
    /// THE ROUTER'S LAYERS AROUND ONE REQUEST the root serves itself, from the kernel's one source
    /// for each (row 192 C): the request-panic boundary outermost
    /// (`busbar_kernel::router::catch_request_panic`, the one request's `500`), then the
    /// `Server-Timing` field where it is on, the activity tick, and the plane ingress boundary's
    /// finish (`busbar_kernel::ingress::observe::finish`) on what `serve` answered.
    async fn layered<F, Fut>(
        &self,
        request: axum::http::Request<axum::body::Body>,
        serve: F,
    ) -> Response
    where
        F: FnOnce(axum::http::Request<axum::body::Body>) -> Fut,
        Fut: Future<Output = Response>,
    {
        let method = request.method().clone();
        let uri = request.uri().clone();
        let handle = Arc::clone(&self.handle);
        let timing = self.server_timing;
        let path = uri.path().to_owned();
        let served = async move {
            let start = std::time::Instant::now();
            busbar_kernel::router::request_activity();
            let app = handle.load();
            let observed = async {
                let begun = std::time::Instant::now();
                let response = serve(request).await;
                if response
                    .extensions()
                    .get::<busbar_kernel::ingress::observe::Counted>()
                    .is_none()
                {
                    let _ = busbar_kernel::ingress::observe::finish(
                        &app,
                        &path,
                        response.status().as_u16(),
                        begun.elapsed(),
                    );
                }
                response
            };
            if !timing {
                return observed.await;
            }
            let mut response = observed.await;
            if let Some((name, value)) = busbar_kernel::router::server_timing_field(
                start,
                busbar_kernel::router::NO_UPSTREAM_RTT,
            ) {
                response.headers_mut().insert(name, value);
            }
            response
        };
        match busbar_kernel::router::catch_request_panic(move || served).await {
            Ok(response) => response,
            Err(payload) => busbar_kernel::router::request_panicked(
                &self.handle,
                &method,
                &uri,
                payload.as_ref(),
            ),
        }
    }

    /// A DOOR PLANE'S CLAIM, as its route served it: the body read under the cap (over it, the
    /// over-gate refusal), the caller the unit was admitted as, and the unit driven under its own
    /// key (a catalog claim answered by the plane's pure `catalog`, no unit driven).
    async fn plane(
        &self,
        request: axum::http::Request<axum::body::Body>,
        doorway: &HandedDoor,
        handed: busbar_kernel::inbound::Handed,
    ) -> Response {
        let Some(routes) = self.routes.clone() else {
            return crate::root::serve::unrendered_response(None);
        };
        let head = request.method() == axum::http::Method::HEAD;
        let req = match self.door_request(request, handed).await {
            Ok(req) => req,
            Err(response) => return *response,
        };
        let response = match *doorway {
            HandedDoor::Catalog { plane } => routes.catalog(plane, &req),
            HandedDoor::Request { plane, claim } => {
                let key = busbar_contract::UnitKey::new(handed.unit);
                routes.answer_keyed(plane, claim, req, Some(key)).await
            }
            HandedDoor::Session { .. } | HandedDoor::Router => {
                crate::root::serve::unrendered_response(None)
            }
        };
        routed(response, head)
    }

    /// THE DOOR REQUEST a handed-in unit's request becomes: its body read whole under the body cap
    /// (over it, the over-gate refusal the router's layer answers with; a failed body, the
    /// router's `400`), the caller the kernel admitted it as (`Inbound::door_ctx`), over the
    /// generation now serving.
    async fn door_request(
        &self,
        request: axum::http::Request<axum::body::Body>,
        handed: busbar_kernel::inbound::Handed,
    ) -> Result<DoorRequest, Box<Response>> {
        let (parts, body) = request.into_parts();
        let path = parts.uri.path().to_owned();
        let target = parts
            .uri
            .path_and_query()
            .map_or_else(|| path.clone(), |t| t.as_str().to_owned());
        let cap = busbar_kernel_egress::upstream::max_translate_body_bytes();
        let head = parts.method == axum::http::Method::HEAD;
        let bytes = match read_body(body, cap).await {
            Ok(bytes) => bytes,
            Err(BodyRead::Over) => {
                return Err(Box::new(busbar_kernel::router::oversized_refusal(
                    &self.handle,
                    &path,
                    &target,
                )))
            }
            Err(BodyRead::Failed(response)) => return Err(Box::new(routed(*response, head))),
        };
        let app = self.handle.load();
        let (_, gov, credential) = crate::root::inbound::host()
            .door_ctx(handed.unit, &app)
            .map_err(|_| Box::new(routed(crate::root::serve::unrendered_response(None), head)))?;
        let mut headers = parts.headers;
        headers.remove(busbar_contract::abi::host::service::CARRIER_SESSION_FIELD);
        Ok(DoorRequest {
            method: parts.method,
            uri: parts.uri,
            headers,
            body: bytes,
            gov,
            credential,
            app,
            scheme: self.scheme().0,
            // The framer stripped the fields the line's auths named before it handed the head up
            // (`Inbound::head_of`), and the unit keeps their names only, not their scheme words:
            // a handed-up request states none.
            consumed_fields: Vec::new(),
        })
    }
}

/// THE ROUTE'S OWN FINISH on what a door route answered, as the router's route does it: the
/// length a body of known size states, where the answer states none, and a `HEAD` answered with
/// no body.
fn routed(mut response: Response, head: bool) -> Response {
    use axum::http::header::CONTENT_LENGTH;
    if !response.headers().contains_key(CONTENT_LENGTH) {
        if let Some(size) = http_body::Body::size_hint(response.body()).exact() {
            if let Ok(value) = axum::http::HeaderValue::from_str(&size.to_string()) {
                response.headers_mut().insert(CONTENT_LENGTH, value);
            }
        }
    }
    if head {
        *response.body_mut() = axum::body::Body::empty();
    }
    response
}

// ── THE ANSWER, WRITTEN ──────────────────────────────────────────────────────────────────────────

/// THE ACCEPTED CONNECTION'S SINK: an answer written through the connection's own emits, the head
/// and its status in one emit, then the body piece by piece, then its end. The field block is the
/// answer's own fields in their order, and the length the hyper loop would state for a body of
/// known size where the answer states none, so the framer's server frames it as the hyper loop
/// did.
pub(crate) struct ConnAnswer {
    out: Emitter,
}

impl ConnAnswer {
    /// Write `response`. `false` = the connection or the stream went before it was whole.
    async fn respond(&self, response: Response) -> bool {
        use axum::http::header::CONTENT_LENGTH;
        use axum::http::StatusCode;
        let (parts, mut body) = response.into_parts();
        let mut block = Vec::new();
        let mut field = |name: &[u8], value: &[u8]| {
            block.extend_from_slice(name);
            block.extend_from_slice(busbar_contract::abi::transport::fields::SEPARATOR);
            block.extend_from_slice(value);
            block.extend_from_slice(busbar_contract::abi::transport::fields::LINE_END);
        };
        for (name, value) in &parts.headers {
            field(name.as_str().as_bytes(), value.as_bytes());
        }
        let bodiless = parts.status.is_informational() || parts.status == StatusCode::NO_CONTENT;
        let size = http_body::Body::size_hint(&body).exact();
        if !bodiless && !parts.headers.contains_key(CONTENT_LENGTH) {
            if let Some(size) = size {
                field(
                    CONTENT_LENGTH.as_str().as_bytes(),
                    size.to_string().as_bytes(),
                );
            }
        }
        let end = http_body::Body::is_end_stream(&body) || size == Some(0);
        if !self
            .out
            .head(u32::from(parts.status.as_u16()), block, end)
            .await
        {
            return false;
        }
        if end {
            return true;
        }
        loop {
            // A unit that panicked panics where its body is read: the answer breaks, its stream
            // refused after its head, never the connection's other requests.
            let frame = std::future::poll_fn(|cx| {
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    http_body::Body::poll_frame(std::pin::Pin::new(&mut body), cx)
                })) {
                    Ok(polled) => polled.map(Ok::<_, ()>),
                    Err(_) => std::task::Poll::Ready(Err(())),
                }
            })
            .await;
            match frame {
                Ok(Some(Ok(frame))) => {
                    // An answer's trailer block is the framer's to render; the data is written.
                    if let Ok(data) = frame.into_data() {
                        if !data.is_empty() && !self.out.data(data, false).await {
                            return false;
                        }
                    }
                }
                Ok(None) => return self.out.data(Bytes::new(), true).await,
                Ok(Some(Err(_))) | Err(()) => {
                    self.out.refuse(Vec::new(), 0, true);
                    return false;
                }
            }
        }
    }
}

/// The accepted connection's sink as an [`Answer`]: each shape built as the old path's sink builds
/// it, then written through the connection, so both paths write one choice's bytes.
impl Answer for ConnAnswer {
    type Out = bool;

    async fn whole(self, head: Head, body: Vec<u8>) -> bool {
        let response = crate::root::serve::HyperAnswer(crate::root::serve::unrendered_response)
            .whole(head, body)
            .await;
        self.respond(response).await
    }

    async fn closed(self, head: Head, block: HeaderMap) -> bool {
        let response = crate::root::serve::HyperAnswer(crate::root::serve::unrendered_response)
            .closed(head, block)
            .await;
        self.respond(response).await
    }

    async fn streamed(self, head: Head, body: Streamed) -> bool {
        let response = crate::root::serve::HyperAnswer(crate::root::serve::unrendered_response)
            .streamed(head, body)
            .await;
        self.respond(response).await
    }

    async fn unrendered(self, rendered: Option<Rendered>) -> bool {
        self.respond(crate::root::serve::unrendered_response(rendered))
            .await
    }
}
