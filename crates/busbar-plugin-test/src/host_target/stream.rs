// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STREAM TARGET (SDK-SAFE-TEST-HOST §11.1-11.3, Part A): a stream framer
//! (`FRAMING_STREAM`, `FACT_ACCEPTS`: ws) served on loopback TCP, on `std::net` only. Each image
//! is opened on its own [`PluginThread`] with the driver's host, and each accepted connection
//! gets a thread that reads its socket and drives the framer through the loader's real
//! dispatcher, exactly as the connector drives one (§11.2):
//!
//! - **Accept:** BEGIN on `SIDE_ACCEPT`, with the scheme ([`Framer::scheme`]) and the facts
//!   ([`Framer::facts`]).
//! - **Read:** INGEST each read, then act on every answer's yield flags: `YIELD_MORE` re-calls the
//!   same op with no new bytes (a BEGIN's re-call is TIMER, as the connector's is);
//!   `YIELD_HAS_DEADLINE` arms TIMER at `next_deadline_ns`; `YIELD_ENDED` FINISHes.
//! - **Write:** `wire` bytes go to the socket as each answer hands them; payload pieces are
//!   assembled into whole messages for the handler ([`Framer::handler`], default [`echo`]), and
//!   each [`Emit`] becomes an EMIT on its stream. Field blocks (a head, trailers) are never a
//!   message.
//! - **Stream flow:** an EMIT answered `YIELD_STREAM_FULL` holds every later message of its
//!   stream until the framer hands a `PIECE_WRITABLE` piece on it (or the stream's end or
//!   failure), as the contract's stream flow says and the connector does.
//! - **EOF:** INGEST with `end = 1`, then FINISH with `CLOSE_PEER_CLOSED`.
//!
//! The sink lends the connector's real initial sizes ([`WIRE_CAP`], [`FRAME_CAP`],
//! [`PIECES_CAP`], [`HEADS_CAP`]). The run fails (§10.3) when a framer answers SHORT, or FAULT
//! (a ticket-less PENDING is judged FAULT), when a message grows past [`Framer::max_message`]
//! (the connection is FINISHed, never truncated), when a framer owes more [`MORE_STALLS`] times in
//! a row and writes nothing, and when an image's plugin thread or a connection's thread is gone.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use busbar_contract::abi::host::service::SCHEME_PLAIN;
use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::mechanism::door::DoorFn;
use busbar_contract::abi::sdk::test_support::loans::{Buf, Loans};
use busbar_contract::abi::sdk::test_support::mutant::Mutant;
use busbar_contract::abi::transport::{
    slot, BeginIn, ConnFacts, EmitIn, FinishIn, FramePiece, FramerOut, FramerSink, FramerYield,
    FramingIn, IngestIn, CLOSE_CAPACITY_EXHAUSTED, CLOSE_DRAIN, CLOSE_NORMAL, CLOSE_PEER_CLOSED,
    CLOSE_TRANSPORT_FAILED, EMIT_TEXT, PIECE_END, PIECE_END_OF_FRAME, PIECE_FIELDS,
    PIECE_STREAM_FAILED, PIECE_TEXT, PIECE_WRITABLE, SIDE_ACCEPT, YIELD_ENDED, YIELD_HAS_DEADLINE,
    YIELD_MORE, YIELD_STREAM_FULL,
};
use busbar_plugin_loader::dispatch::kinds::transport::Transport;
use busbar_plugin_loader::test_host::{Called, Host, Image, Opened};

use super::{Binding, Listening, PluginThread, Refused, Report, Subject};

/// The wire buffer every framer op is lent: the connector's initial size.
pub const WIRE_CAP: usize = 64 * 1024;
/// The frame buffer every framer op is lent: the connector's initial size.
pub const FRAME_CAP: usize = 64 * 1024;
/// The frame pieces every framer op is lent: the connector's initial count.
pub const PIECES_CAP: usize = 64;
/// The head slots every framer op is lent: the connector's initial count.
pub const HEADS_CAP: usize = 16;
/// The default bound on one message under assembly (§11.3): Autobahn's largest case is 16 MiB.
const MAX_MESSAGE: usize = 64 * 1024 * 1024;
/// `YIELD_MORE` answers in a row that write nothing before the run fails: the connector's bound.
pub const MORE_STALLS: usize = 64;
/// One socket read.
const READ_BUF: usize = 64 * 1024;
/// `ConnFacts::size`, stated at construction.
const CONN_FACTS_SIZE: u32 = std::mem::size_of::<ConnFacts>() as u32;

/// Builds each image's host on its plugin thread.
type MakeHost = dyn Fn() -> Host + Send + Sync;
/// Writes what connection security established into BEGIN's facts.
type FactsFn = dyn Fn(&mut Loans<ConnFacts>) + Send + Sync;
/// Answers one whole message with what to emit.
type HandlerFn = dyn Fn(Message<'_>) -> Vec<Emit> + Send + Sync;

/// One whole message the framer handed up, as the handler sees it.
#[derive(Debug, Clone, Copy)]
pub struct Message<'a> {
    /// The stream it arrived on.
    pub stream: u64,
    /// Its bytes, every piece of it in order.
    pub bytes: &'a [u8],
    /// The framer marked it text (`PIECE_TEXT`).
    pub text: bool,
}

/// One message to hand the framer: an EMIT on `stream`, the whole frame in one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Emit {
    /// The stream.
    pub stream: u64,
    /// The bytes.
    pub bytes: Vec<u8>,
    /// A text message (`EMIT_TEXT`).
    pub text: bool,
}

/// The default handler (§11.3): each whole message back on its stream, in order, with its text
/// flag kept. It never validates UTF-8 and never looks inside a payload: validation is the
/// framer's, which is what a conformance suite judges.
#[must_use]
pub fn echo(m: Message<'_>) -> Vec<Emit> {
    vec![Emit {
        stream: m.stream,
        bytes: m.bytes.to_vec(),
        text: m.text,
    }]
}

/// A stream framer target: this plugin's own framer door, linked and as its cdylib, each image on
/// its own loopback TCP listener.
pub struct Framer {
    lib: String,
    door: DoorFn,
    host: Arc<MakeHost>,
    settings: Arc<[u8]>,
    scheme: u8,
    facts: Option<Arc<FactsFn>>,
    handler: Arc<HandlerFn>,
    max_message: usize,
    mutant: Option<Box<Mutant>>,
    armed: bool,
}

impl From<Framer> for Subject {
    fn from(framer: Framer) -> Self {
        Self::Stream(framer)
    }
}

impl Framer {
    /// The framer `door`, whose cdylib is built from `lib_name`, opened on the host `host` builds
    /// (`Host::new(test_caller_binding())`, the binding behind the contract's dev-only
    /// `test-seal`, which the repository enables in its own `[dev-dependencies]`). OPEN settings
    /// `{}`, scheme plain, no facts, [`echo`], and a 64 MiB message bound.
    #[must_use]
    pub fn new(
        lib_name: &str,
        door: DoorFn,
        host: impl Fn() -> Host + Send + Sync + 'static,
    ) -> Self {
        Self {
            lib: lib_name.to_owned(),
            door,
            host: Arc::new(host),
            settings: Arc::from(&b"{}"[..]),
            scheme: SCHEME_PLAIN,
            facts: None,
            handler: Arc::new(echo),
            max_message: MAX_MESSAGE,
            mutant: None,
            armed: false,
        }
    }

    /// The OPEN settings (JSON).
    #[must_use]
    pub fn settings(mut self, json: &[u8]) -> Self {
        self.settings = Arc::from(json);
        self
    }

    /// BEGIN's scheme (`SCHEME_*`); default `SCHEME_PLAIN`.
    #[must_use]
    pub fn scheme(mut self, code: u8) -> Self {
        self.scheme = code;
        self
    }

    /// Writes what connection security established into each BEGIN's facts (`size` is set).
    #[must_use]
    pub fn facts(mut self, f: impl Fn(&mut Loans<ConnFacts>) + Send + Sync + 'static) -> Self {
        self.facts = Some(Arc::new(f));
        self
    }

    /// Answers each whole message; default [`echo`].
    #[must_use]
    pub fn handler(mut self, f: impl Fn(Message<'_>) -> Vec<Emit> + Send + Sync + 'static) -> Self {
        self.handler = Arc::new(f);
        self
    }

    /// The most bytes one message may grow to under assembly; past it the connection is
    /// FINISHed and the run fails (§11.3). `main`: `--max-message BYTES`.
    #[must_use]
    pub fn max_message(mut self, bytes: usize) -> Self {
        self.max_message = bytes;
        self
    }

    /// The negative-control leg's mutant (§11.6): a forged door stating what the door states,
    /// served in place of the linked door once the run is armed ([`Framer::arm`]; `main`:
    /// `--mutant`). Unarmed, the run serves the door itself.
    #[must_use]
    pub fn mutant(mut self, m: Mutant) -> Self {
        self.mutant = Some(Box::new(m));
        self
    }

    /// Arms the mutant leg in-process: what `--mutant` does for `main`.
    #[must_use]
    pub fn arm(mut self) -> Self {
        self.armed = true;
        self
    }

    /// Opens `image` on its own plugin thread and serves it on a loopback TCP listener at the
    /// address [`Binding::addr`] hands out.
    ///
    /// # Errors
    /// When the image does not load, open or ready, when the run is armed with no mutant, and
    /// when the listener or its thread cannot start.
    ///
    /// # Panics
    /// When `image` is `"cdylib"` and no such library exists (the panic names where it looked).
    pub fn bind(&self, image: &'static str, at: &Binding<'_>) -> Result<Listening, Refused> {
        let img = match (image, self.armed, self.mutant.as_deref()) {
            (_, true, None) => {
                return Err(Refused::Args(
                    "--mutant: this target registers no mutant".to_owned(),
                ))
            }
            ("linked", true, Some(m)) => Image::mutant_as(*m, self.door),
            _ => super::image::<Transport>(image, &self.lib, self.door),
        };
        let host = Arc::clone(&self.host);
        let plugin = PluginThread::open(
            move || make_host(&*host),
            img,
            &format!("{image}-framer"),
            &self.settings,
        )
        .map_err(|why| Refused::Image(image, why))?;
        let bind = |e: std::io::Error| Refused::Bind(format!("{image}: {e}"));
        let listener = TcpListener::bind(at.addr()).map_err(bind)?;
        let addr = listener.local_addr().map_err(bind)?;
        let shared = Arc::new(Shared {
            image,
            plugin,
            scheme: self.scheme,
            facts: self.facts.clone(),
            handler: Arc::clone(&self.handler),
            max_message: self.max_message,
            report: at.report().clone(),
            stopping: AtomicBool::new(false),
            live: Mutex::new(Vec::new()),
        });
        let accepting = Arc::clone(&shared);
        let accept = std::thread::Builder::new()
            .name(format!("stream-{image}"))
            .spawn(move || accept_loop(&listener, &accepting))
            .map_err(bind)?;
        let stop = Box::new(move || {
            shared.stopping.store(true, Ordering::SeqCst);
            // Wakes the accept; it sees `stopping` and ends.
            drop(TcpStream::connect(addr));
            drop(accept.join());
            let live = std::mem::take(&mut *shared.live());
            for conn in &live {
                drop(conn.socket.shutdown(Shutdown::Both));
            }
            for conn in live {
                shared.joined(conn.thread);
            }
        });
        Ok(Listening {
            addr,
            admin: None,
            stop,
        })
    }

    /// The stream target's one flag with a value, `--max-message BYTES`.
    ///
    /// # Errors
    /// When `flag` is not `--max-message`, or its value is not a byte count.
    pub fn flag(&mut self, flag: &str, value: &str) -> Result<(), Refused> {
        if flag != "--max-message" {
            return Err(Refused::Args(format!("unknown flag {flag} {value}")));
        }
        self.max_message = value
            .parse()
            .map_err(|_| Refused::Args(format!("--max-message {value}: not a byte count")))?;
        Ok(())
    }

    /// The stream target's one flag with no value, `--mutant`: arms the mutant leg. Whether
    /// `flag` was it.
    pub fn switch(&mut self, flag: &str) -> bool {
        if flag == "--mutant" {
            self.armed = true;
            true
        } else {
            false
        }
    }
}

/// The host `host` builds, on the plugin thread that calls it.
fn make_host(host: &MakeHost) -> Host {
    host()
}

/// One live connection: a handle to shut its socket, and its thread.
struct Live {
    socket: TcpStream,
    thread: JoinHandle<()>,
}

/// What one image's connections share.
struct Shared {
    image: &'static str,
    plugin: PluginThread<Transport>,
    scheme: u8,
    facts: Option<Arc<FactsFn>>,
    handler: Arc<HandlerFn>,
    max_message: usize,
    report: Report,
    stopping: AtomicBool,
    live: Mutex<Vec<Live>>,
}

impl Shared {
    fn live(&self) -> MutexGuard<'_, Vec<Live>> {
        self.live.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Records `what` as not served by this image: the run fails.
    fn record(&self, what: &str) {
        self.report
            .record_unserved(format!("{}: {what}", self.image));
    }

    /// Joins a connection's thread; one that panicked fails the run.
    fn joined(&self, thread: JoinHandle<()>) {
        if thread.join().is_err() {
            self.record("a connection's thread panicked");
        }
    }

    /// One crossing of `op` on the image's plugin thread; `None` when that thread is gone.
    fn call(&self, op: Op, fresh: bool, framing: u64) -> Option<Answered> {
        let scheme = self.scheme;
        let facts = self.facts.clone();
        self.plugin
            .run(move |t| cross_once(t, &op, fresh, framing, scheme, facts.as_deref()))
    }
}

/// Accepts until the target stops, one thread per connection.
fn accept_loop(listener: &TcpListener, shared: &Arc<Shared>) {
    for socket in listener.incoming() {
        if shared.stopping.load(Ordering::SeqCst) {
            return;
        }
        let Ok(socket) = socket else {
            std::thread::sleep(Duration::from_millis(10));
            continue;
        };
        let Ok(handle) = socket.try_clone() else {
            continue;
        };
        let serving = Arc::clone(shared);
        let Ok(thread) = std::thread::Builder::new()
            .name(format!("stream-{}-conn", shared.image))
            .spawn(move || serve_conn(&serving, socket))
        else {
            shared.record("a connection's thread could not start");
            continue;
        };
        let mut live = shared.live();
        let mut i = 0;
        while i < live.len() {
            if live[i].thread.is_finished() {
                let done = live.swap_remove(i);
                shared.joined(done.thread);
            } else {
                i += 1;
            }
        }
        live.push(Live {
            socket: handle,
            thread,
        });
    }
}

/// Serves one connection: BEGIN, read and drive until it ends, FINISH, close.
fn serve_conn(shared: &Shared, socket: TcpStream) {
    let mut conn = Conn {
        shared,
        socket,
        framing: None,
        assembling: HashMap::new(),
        outbox: VecDeque::new(),
        full: HashSet::new(),
        deadline: None,
        ended: false,
    };
    let reason = conn.run();
    conn.finish(reason);
    drop(conn.socket.shutdown(Shutdown::Both));
}

/// A framer op, as the target asks it.
#[derive(Debug, Clone)]
enum Op {
    Begin,
    Ingest { bytes: Vec<u8>, end: bool },
    Emit(Emit),
    Timer,
    Finish { reason: u32 },
}

impl Op {
    fn name(&self) -> &'static str {
        match self {
            Self::Begin => "begin",
            Self::Ingest { .. } => "ingest",
            Self::Emit(_) => "emit",
            Self::Timer => "timer",
            Self::Finish { .. } => "finish",
        }
    }

    /// The op a `YIELD_MORE` answer asks for next: the same op, lent no new bytes; after BEGIN,
    /// TIMER (the connector's `more_with_recalls(Again::Timer)`).
    fn again(&self) -> Self {
        match self {
            Self::Begin => Self::Timer,
            Self::Ingest { .. } => Self::Ingest {
                bytes: Vec::new(),
                end: false,
            },
            Self::Emit(e) => Self::Emit(Emit {
                stream: e.stream,
                bytes: Vec::new(),
                text: false,
            }),
            other => other.clone(),
        }
    }
}

/// What one crossing answered, copied off the plugin thread.
enum Answered {
    Ready(Yielded),
    /// Any other outcome, and its error text (`": <text>"`, or empty).
    Declined {
        outcome: Outcome,
        error: String,
    },
    /// The dispatcher's SHORT re-call: no accept-side framer op earns one.
    Short,
}

/// A READY framer answer: what it wrote into the sink, and its yield.
struct Yielded {
    wire: Vec<u8>,
    pieces: Vec<Piece>,
    flags: u32,
    deadline: u64,
    framing: u64,
    /// It wrote anything (the connector's `wrote`): a stall is a `YIELD_MORE` that did not.
    wrote: bool,
}

/// One frame piece, its bytes copied out of the frame buffer.
struct Piece {
    stream: u64,
    flags: u16,
    bytes: Vec<u8>,
}

/// The keys to the sink's buffers a crossing reads back.
struct Keys {
    wire: Buf<u8>,
    frame: Buf<u8>,
    pieces: Buf<FramePiece>,
}

/// The host's monotonic clock, nanoseconds, never zero (a zero deadline means none).
fn now_ns() -> u64 {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    let since = EPOCH.get_or_init(Instant::now).elapsed().as_nanos();
    u64::try_from(since).unwrap_or(u64::MAX).saturating_add(1)
}

/// The wall clock, nanoseconds since the Unix epoch.
fn unix_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
}

/// One crossing of `op` on the image's own thread, its `in` built from loans: on a re-call
/// (`!fresh`) no bytes are lent. The sink is the connector's sizes.
fn cross_once(
    t: &mut Opened<Transport>,
    op: &Op,
    fresh: bool,
    framing: u64,
    scheme: u8,
    facts: Option<&FactsFn>,
) -> Answered {
    let (now, unix) = (now_ns(), unix_ns());
    let mut keys = None;
    let sink = |s: &mut Loans<FramerSink>| {
        keys = Some(Keys {
            wire: s.wire(WIRE_CAP),
            frame: s.frame(FRAME_CAP),
            pieces: s.pieces(PIECES_CAP),
        });
        s.heads(HEADS_CAP);
        s.now_monotonic_ns(now).now_unix_ns(unix);
    };
    match op {
        Op::Begin => {
            let mut i = Loans::<BeginIn>::new();
            i.side(SIDE_ACCEPT).scheme(scheme).sink(sink);
            i.facts(|l| {
                l.push(|f| {
                    f.size(CONN_FACTS_SIZE);
                    if let Some(facts) = facts {
                        facts(f);
                    }
                });
            });
            answered(t.call::<{ slot::BEGIN }>(i), keys)
        }
        Op::Ingest { bytes, end } => {
            let mut i = Loans::<IngestIn>::new();
            i.framing(framing).sink(sink);
            if fresh {
                i.bytes(bytes);
                i.end(u32::from(*end));
            }
            answered(t.call::<{ slot::INGEST }>(i), keys)
        }
        Op::Emit(e) => {
            let mut i = Loans::<EmitIn>::new();
            i.framing(framing).stream(e.stream).sink(sink);
            if fresh {
                i.bytes(&e.bytes);
                i.end_of_frame(1).flags(if e.text { EMIT_TEXT } else { 0 });
            }
            answered(t.call::<{ slot::EMIT }>(i), keys)
        }
        Op::Timer => {
            let mut i = Loans::<FramingIn>::new();
            i.framing(framing).sink(sink);
            answered(t.call::<{ slot::TIMER }>(i), keys)
        }
        Op::Finish { reason } => {
            let mut i = Loans::<FinishIn>::new();
            i.framing(framing).reason(*reason).sink(sink);
            answered(t.call::<{ slot::FINISH }>(i), keys)
        }
    }
}

/// The first `n` of `values`; empty when `n` is past them (the dispatcher's own checks hold a
/// READY answer's lengths to its buffers, so that never happens on one).
fn first<T>(values: &[T], n: u64) -> &[T] {
    usize::try_from(n)
        .ok()
        .and_then(|n| values.get(..n))
        .unwrap_or_default()
}

/// Copies what a framer answer wrote, while its lease is held.
fn answered<In>(called: Called<'_, In, FramerOut>, keys: Option<Keys>) -> Answered {
    let a = match called {
        Called::Ready(a) => a,
        Called::Pending(p) => {
            p.leak_loans();
            return Answered::Short;
        }
    };
    let outcome = a.outcome();
    let error = a
        .error()
        .map_or_else(String::new, |e| format!(": {}", String::from_utf8_lossy(e)));
    let Some(keys) = keys.filter(|_| outcome == Outcome::Ready) else {
        return Answered::Declined { outcome, error };
    };
    let y: FramerYield = a.get(|o| o.yielded);
    let frame = first(a.read(&keys.frame), y.frame_len);
    let pieces = first(a.read(&keys.pieces), u64::from(y.pieces_len))
        .iter()
        .map(|p| Piece {
            stream: p.stream,
            flags: p.flags,
            bytes: usize::try_from(p.offset)
                .ok()
                .zip(usize::try_from(p.len).ok())
                .and_then(|(at, len)| frame.get(at..at.checked_add(len)?))
                .unwrap_or_default()
                .to_vec(),
        })
        .collect();
    Answered::Ready(Yielded {
        wire: first(a.read(&keys.wire), y.wire_len).to_vec(),
        pieces,
        flags: y.flags,
        deadline: y.next_deadline_ns,
        framing: a.get(|o| o.framing),
        wrote: y.wire_len != 0
            || y.frame_len != 0
            || y.pieces_len != 0
            || y.heads_len != 0
            || y.flags & YIELD_STREAM_FULL != 0,
    })
}

/// One connection, driven on its own thread.
struct Conn<'a> {
    shared: &'a Shared,
    socket: TcpStream,
    /// The framing BEGIN answered; `None` before it, and after FINISH.
    framing: Option<u64>,
    /// Each stream's message under assembly, and whether it is text.
    assembling: HashMap<u64, (Vec<u8>, bool)>,
    /// Messages to EMIT, in order; a full stream's wait here.
    outbox: VecDeque<Emit>,
    /// Streams an EMIT answered full, until the framer hands them writable.
    full: HashSet<u64>,
    /// When to call TIMER, on the host's monotonic clock.
    deadline: Option<u64>,
    /// The framer said no frame follows (`YIELD_ENDED`).
    ended: bool,
}

impl Conn<'_> {
    /// Drives the connection until it ends, and answers the FINISH reason.
    fn run(&mut self) -> u32 {
        if let Err(reason) = self.step(Op::Begin) {
            return reason;
        }
        let mut buf = vec![0u8; READ_BUF];
        loop {
            if self.ended {
                return CLOSE_NORMAL;
            }
            if let Some(at) = self.deadline {
                let left = at.saturating_sub(now_ns());
                if left == 0 {
                    self.deadline = None;
                    if let Err(reason) = self.step(Op::Timer) {
                        return reason;
                    }
                    continue;
                }
                let wait = Duration::from_nanos(left).max(Duration::from_millis(1));
                drop(self.socket.set_read_timeout(Some(wait)));
            } else {
                drop(self.socket.set_read_timeout(None));
            }
            match self.socket.read(&mut buf) {
                Ok(0) if self.shared.stopping.load(Ordering::SeqCst) => return CLOSE_DRAIN,
                Ok(0) => {
                    let eof = Op::Ingest {
                        bytes: Vec::new(),
                        end: true,
                    };
                    return self.step(eof).err().unwrap_or(CLOSE_PEER_CLOSED);
                }
                Ok(n) => {
                    let read = Op::Ingest {
                        bytes: buf[..n].to_vec(),
                        end: false,
                    };
                    if let Err(reason) = self.step(read) {
                        return reason;
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                    ) => {}
                Err(_) if self.shared.stopping.load(Ordering::SeqCst) => return CLOSE_DRAIN,
                Err(_) => return CLOSE_TRANSPORT_FAILED,
            }
        }
    }

    /// FINISHes the framing with `reason`, once, and writes what it owes.
    fn finish(&mut self, reason: u32) {
        if self.framing.is_some() {
            drop(self.cross(Op::Finish { reason }));
            self.framing = None;
        }
    }

    /// One op, then every message it made ready that its stream can take.
    fn step(&mut self, op: Op) -> Result<(), u32> {
        self.cross(op)?;
        while let Some(at) = self
            .outbox
            .iter()
            .position(|e| !self.full.contains(&e.stream))
        {
            let Some(emit) = self.outbox.remove(at) else {
                break;
            };
            self.cross(Op::Emit(emit))?;
        }
        Ok(())
    }

    /// Records `what` and answers the FINISH reason of a connection that failed.
    fn fail(&self, what: &str) -> u32 {
        self.shared.record(what);
        CLOSE_TRANSPORT_FAILED
    }

    /// One op and its `YIELD_MORE` re-calls, each answer taken as it comes. An EMIT or FINISH
    /// the framer declines ends that op only; any other op it declines ends the connection.
    fn cross(&mut self, op: Op) -> Result<(), u32> {
        let name = op.name();
        let begin = matches!(op, Op::Begin);
        let soft = matches!(op, Op::Emit(_) | Op::Finish { .. });
        let emitted_on = match &op {
            Op::Emit(e) => Some(e.stream),
            _ => None,
        };
        let mut call = op;
        let mut fresh = true;
        let mut stalls = 0;
        loop {
            let again = call.again();
            let framing = self.framing.unwrap_or(0);
            let y = match self.shared.call(call, fresh, framing) {
                None => return Err(self.fail(&format!("the plugin thread is gone ({name})"))),
                Some(Answered::Short) => {
                    return Err(self.fail(&format!(
                        "the framer answered SHORT on {name}, which no accept-side op may"
                    )))
                }
                Some(Answered::Declined {
                    outcome: Outcome::Fault,
                    error,
                }) => return Err(self.fail(&format!("the framer answered FAULT on {name}{error}"))),
                Some(Answered::Declined { .. }) if soft => return Ok(()),
                Some(Answered::Declined { .. }) => return Err(CLOSE_TRANSPORT_FAILED),
                Some(Answered::Ready(y)) => y,
            };
            if begin && fresh {
                self.framing = Some(y.framing);
            }
            if let Some(stream) = emitted_on.filter(|_| y.flags & YIELD_STREAM_FULL != 0) {
                self.full.insert(stream);
            }
            self.deadline = (y.flags & YIELD_HAS_DEADLINE != 0).then_some(y.deadline);
            self.ended |= y.flags & YIELD_ENDED != 0;
            let (more, wrote) = (y.flags & YIELD_MORE != 0, y.wrote);
            self.absorb(y)?;
            if !more {
                return Ok(());
            }
            stalls = if wrote { 0 } else { stalls + 1 };
            if stalls >= MORE_STALLS {
                return Err(self.fail(&format!(
                    "the framer owed more {MORE_STALLS} times in a row on {name} and wrote nothing"
                )));
            }
            call = again;
            fresh = false;
        }
    }

    /// Writes an answer's wire bytes to the socket, then takes its pieces.
    fn absorb(&mut self, y: Yielded) -> Result<(), u32> {
        if !y.wire.is_empty() && self.socket.write_all(&y.wire).is_err() {
            return Err(CLOSE_TRANSPORT_FAILED);
        }
        for piece in y.pieces {
            self.piece(piece)?;
        }
        Ok(())
    }

    /// One piece: a stream's flow or end, a field block (never a message), or payload, which a
    /// piece ending its frame hands to the handler whole.
    fn piece(&mut self, p: Piece) -> Result<(), u32> {
        if p.flags & PIECE_WRITABLE != 0 {
            self.full.remove(&p.stream);
            return Ok(());
        }
        if p.flags & (PIECE_END | PIECE_STREAM_FAILED) != 0 {
            self.full.remove(&p.stream);
            self.assembling.remove(&p.stream);
            return Ok(());
        }
        if p.flags & PIECE_FIELDS != 0 {
            return Ok(());
        }
        let max = self.shared.max_message;
        let (message, _) = self
            .assembling
            .entry(p.stream)
            .or_insert_with(|| (Vec::new(), p.flags & PIECE_TEXT != 0));
        if message.len().saturating_add(p.bytes.len()) > max {
            self.assembling.remove(&p.stream);
            self.shared.record(&format!(
                "a message over max_message ({max} bytes) on stream {}",
                p.stream
            ));
            return Err(CLOSE_CAPACITY_EXHAUSTED);
        }
        message.extend_from_slice(&p.bytes);
        if p.flags & PIECE_END_OF_FRAME != 0 {
            if let Some((message, text)) = self.assembling.remove(&p.stream) {
                let emits = (self.shared.handler)(Message {
                    stream: p.stream,
                    bytes: &message,
                    text,
                });
                self.outbox.extend(emits);
            }
        }
        Ok(())
    }
}
