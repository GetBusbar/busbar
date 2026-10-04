// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! COMPOSE: one connection, `socket -> [TLS] -> framer` (`BUSBAR-1.6.0.md` THE DESIGN, §5), dialled
//! ([`Connection::dial`], the framing begun on `SIDE_DIAL`) or accepted ([`Connection::accepted`],
//! the server-side mirror: TLS as the server, the framing begun on `SIDE_ACCEPT`); or a PROGRAM's
//! pipes ([`Connection::spawn`]: `child stdin/stdout -> framer`), the child spawned here with no
//! shell and only the environment its settings state, and killed when the connection closes or is
//! dropped.
//!
//! The socket is the host's, non-blocking, its readiness on the dialling worker's reactor
//! ([`crate::io`]); connection security is `rustls` driven sans-IO here, with the protocol offer
//! (ALPN) the entry's `locate` answered (THE DESIGN, connections: "the ALPN offer is the
//! framer's"; the registration's offer stands only for an entry that answers none); the framer is
//! the entry's table ([`crate::framer`]).
//! The connection is a state machine the caller polls — it holds no thread and no task, and every
//! wait is Pending with the caller's waker registered on the socket or the timer:
//!
//! * the bytes the socket reads go through TLS to the framer's `ingest`;
//! * the framer's wire bytes go through TLS to the socket;
//! * a deadline the framer states is a timer on the worker's clock, and at it the framer's `timer`
//!   runs; the open itself is bounded by the dial's own timeout;
//! * the frame pieces come out per stream, in order; `YIELD_ENDED` ends the connection.

use std::collections::VecDeque;
use std::future::Future;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use busbar_contract::abi::transport::{CLOSE_NORMAL, SIDE_ACCEPT, SIDE_DIAL};

use crate::endpoint;
use crate::framer::{self, Established, FramerDoor, Framing, Got, Yielded};
use crate::io::{self as reactor, Direction, Registered};
use crate::socket::{self, Sock};

/// How much one socket read takes.
const READ_CHUNK: usize = 16 * 1024;

/// The open's bound when the caller states none.
pub const DEFAULT_OPEN_TIMEOUT: Duration = Duration::from_secs(10);

/// The stream a dialled connection's own exchange rides.
pub const EXCHANGE_STREAM: u64 = 1;

/// THE WRITE BUFFER CAP: the most bytes one connection holds on a caller's behalf and not yet on the
/// socket (writes made before the framing began, and framed bytes the socket has not taken). A write
/// past it is taken short, and a write with no room is taken not at all, so a caller that writes
/// faster than its far end reads cannot grow the host's memory.
pub const WRITE_BUFFER_BYTES: usize = 256 * 1024;

/// Why a connection did not answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// The target was refused before any dial (a cloud metadata host, a name the connector does
    /// not resolve, a target the entry does not locate) or the far end said no.
    Refused(String),
    /// The open, or a deadline the framer stated, passed.
    Timeout,
    /// The connection is closed.
    Closed,
    /// The socket, connection security or the framer failed the connection.
    Failed(String),
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(why) => write!(f, "refused: {why}"),
            Self::Timeout => f.write_str("the connection's deadline passed"),
            Self::Closed => f.write_str("the connection is closed"),
            Self::Failed(why) => write!(f, "failed: {why}"),
        }
    }
}

impl std::error::Error for Failure {}

/// A first message: its envelope fields and its body.
pub type Opening = (Vec<(String, Vec<u8>)>, Vec<u8>);

/// What a dial asks for.
#[derive(Clone)]
pub struct Dial {
    /// The target, as the entry's `locate` reads it.
    pub target: String,
    /// The client TLS config, where the target asks for connection security (its ALPN offer is
    /// set per dial: the entry's own, else `alpn`).
    pub tls: Option<Arc<rustls::ClientConfig>>,
    /// The protocols offered in the TLS handshake, most preferred first, where the entry's
    /// `locate` answers no offer of its own.
    pub alpn: Vec<Vec<u8>>,
    /// The bound on the open: connect and handshake.
    pub open_timeout: Duration,
    /// The first message, as envelope fields and a body; `None` sends nothing first.
    pub opening: Option<Opening>,
    /// The first message's head words, method and target (`framer::encode_head`); empty = none.
    pub head_words: HeadWords,
}

/// A message's head words, method and target; empty = none.
pub type HeadWords = (Vec<u8>, Vec<u8>);

impl std::fmt::Debug for Dial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dial")
            .field("target", &self.target)
            .field("tls", &self.tls.is_some())
            .field("open_timeout", &self.open_timeout)
            .finish_non_exhaustive()
    }
}

enum Phase {
    Connecting,
    Handshaking,
    Open,
    Ended,
    Failed(Failure),
}

/// What a connection's bytes ride: the host's socket, or a program's pipes.
enum Wire {
    Socket(Registered<Sock>),
    Program(Box<Pipes>),
}

/// A spawned program: the child the connection owns, and the host's ends of the two pipes that
/// are its input and its output, on the calling worker's reactor.
struct Pipes {
    child: tokio::process::Child,
    stdin: tokio::net::unix::pipe::Sender,
    stdout: tokio::net::unix::pipe::Receiver,
}

/// One composed connection.
pub struct Connection {
    door: Arc<dyn FramerDoor>,
    wire: Wire,
    target: String,
    /// `SIDE_DIAL` | `SIDE_ACCEPT`.
    side: u32,
    /// Client TLS on a dialled connection, server TLS on an accepted one.
    tls: Option<rustls::Connection>,
    framing: Option<Framing>,
    established: Established,
    phase: Phase,
    /// Bytes for the socket (ciphertext under TLS).
    out: VecDeque<u8>,
    /// Frame pieces the caller has not taken.
    inbox: VecDeque<Got>,
    /// The first message, sent once the framing begins.
    opening: Option<Opening>,
    /// Its head words.
    head_words: HeadWords,
    /// Writes the caller made before the framing began, in order: `(stream, bytes, end)`.
    early: Vec<(u64, Vec<u8>, bool, bool)>,
    /// Every byte the socket has taken, for the life of the connection.
    flushed: u64,
    open_deadline: Option<Instant>,
    framer_deadline: Option<Instant>,
    sleep: Option<(Instant, Pin<Box<tokio::time::Sleep>>)>,
    /// The listener's hold on one of its connection slots, freed when the connection is dropped.
    _slot: Option<Slot>,
    /// Connection security was asked for mid-stream ([`Connection::upgrade_secure`]), not at the
    /// dial.
    upgraded: bool,
}

/// One of a listener's connection slots, held by the connection it admitted and freed on drop.
#[derive(Debug)]
pub struct Slot(Arc<std::sync::atomic::AtomicUsize>);

impl Slot {
    /// Take a slot of `live` when fewer than `max` are held; `None` = the listener is full.
    #[must_use]
    pub fn take(live: &Arc<std::sync::atomic::AtomicUsize>, max: usize) -> Option<Self> {
        use std::sync::atomic::Ordering;
        live.fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
            (n < max).then_some(n + 1)
        })
        .ok()
        .map(|_| Self(Arc::clone(live)))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

/// What an accept asks for: the server TLS (its protocol offer set per accept from `alpn`) and the
/// bound on the handshake.
#[derive(Clone)]
pub struct Accept {
    /// The server TLS config; `None` = the listener is in the clear.
    pub tls: Option<Arc<rustls::ServerConfig>>,
    /// The protocols the server agrees to, most preferred first (the claiming framer's offer).
    pub alpn: Vec<Vec<u8>>,
    /// The bound on the handshake; the framer's own deadlines bound the rest.
    pub handshake_timeout: Duration,
}

impl std::fmt::Debug for Accept {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Accept")
            .field("tls", &self.tls.is_some())
            .field("handshake_timeout", &self.handshake_timeout)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("entry", &self.door.facts().name)
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

fn failed(e: impl std::fmt::Display) -> Failure {
    Failure::Failed(e.to_string())
}

impl Connection {
    /// Dial `dial.target` through `door`: the endpoint check, the entry's `locate`, a second
    /// endpoint check on the authority it named, then a non-blocking connect registered on the
    /// calling worker's reactor. The connection comes back at once, its open in flight.
    ///
    /// # Errors
    ///
    /// [`Failure::Refused`] before any socket exists; [`Failure::Failed`] off a worker or when the
    /// socket cannot be made.
    pub fn dial(door: Arc<dyn FramerDoor>, dial: Dial) -> Result<Self, Failure> {
        let planned = Planned::locate(door, dial)?;
        let addr = socket::address_of(planned.authority()).ok_or_else(|| {
            Failure::Refused(format!(
                "`{}` is not an address the connector dials without resolving a name",
                planned.authority()
            ))
        })?;
        planned.dial_at(addr)
    }
}

/// A dial located but not yet dialled: the target and the authority the entry named passed the
/// endpoint check, and the address to dial is still to be judged.
pub struct Planned {
    door: Arc<dyn FramerDoor>,
    dial: Dial,
    located: framer::Located,
}

impl std::fmt::Debug for Planned {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Planned")
            .field("target", &self.dial.target)
            .finish_non_exhaustive()
    }
}

impl Planned {
    /// The endpoint check, the entry's `locate`, and a second endpoint check on the authority it
    /// named.
    ///
    /// # Errors
    ///
    /// [`Failure::Refused`]: the target or the authority is refused, or the entry locates nothing.
    pub fn locate(door: Arc<dyn FramerDoor>, dial: Dial) -> Result<Self, Failure> {
        endpoint::check(&dial.target).map_err(|e| Failure::Refused(e.to_string()))?;
        let located = framer::locate(door.as_ref(), &dial.target)
            .map_err(|e| Failure::Refused(e.to_string()))?;
        endpoint::check(&located.authority).map_err(|e| Failure::Refused(e.to_string()))?;
        Ok(Self {
            door,
            dial,
            located,
        })
    }

    /// The authority the entry named (`host:port`), as the judge reads it.
    #[must_use]
    pub fn authority(&self) -> &str {
        &self.located.authority
    }

    /// Whether the entry located a target asking for connection security.
    #[must_use]
    pub fn secure(&self) -> bool {
        self.located.secure
    }

    /// The name the entry located for connection security, where it names one.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.located.name.as_deref()
    }

    /// The dial this plan was located for.
    #[must_use]
    pub fn dial(&self) -> &Dial {
        &self.dial
    }

    /// This dial's first message and its head words, taken out (a reuse sends them on a pooled
    /// connection instead of dialling).
    #[must_use]
    pub fn into_opening(self) -> (Option<Opening>, HeadWords) {
        (self.dial.opening, self.dial.head_words)
    }

    /// Dial exactly `addr` — the address judged for [`Self::authority`] — with the name the entry
    /// located offered to connection security: a non-blocking connect registered on the calling
    /// worker's reactor. The connection comes back at once, its open in flight.
    ///
    /// # Errors
    ///
    /// [`Failure::Refused`] when security is asked for and none is set; [`Failure::Failed`] off a
    /// worker or when the socket cannot be made.
    pub fn dial_at(self, addr: std::net::SocketAddr) -> Result<Connection, Failure> {
        let Self {
            door,
            dial,
            located,
        } = self;
        let tls = if located.secure {
            let base = dial.tls.clone().ok_or_else(|| {
                Failure::Refused("the target asks for connection security and none is set".into())
            })?;
            let mut config = (*base).clone();
            // THE OFFER IS THE FRAMER'S: what its `locate` answered, most preferred first; the
            // registration's stands only for an entry that answers none.
            config.alpn_protocols = if located.offer.is_empty() {
                dial.alpn.clone()
            } else {
                located.offer.clone()
            };
            let host = located.name.clone().unwrap_or_else(|| {
                located
                    .authority
                    .rsplit_once(':')
                    .map_or(located.authority.clone(), |(h, _)| h.to_owned())
            });
            let name = rustls::pki_types::ServerName::try_from(
                host.trim_start_matches('[')
                    .trim_end_matches(']')
                    .to_owned(),
            )
            .map_err(|e| Failure::Refused(format!("the name offered is not a server name: {e}")))?;
            Some(rustls::Connection::Client(
                rustls::ClientConnection::new(Arc::new(config), name).map_err(failed)?,
            ))
        } else {
            None
        };
        let sock = Sock::Tcp(socket::connect(addr).map_err(failed)?);
        let offered_name = tls.as_ref().and(located.name.clone());
        // No handshake to agree a protocol in the clear: an entry that offers exactly one
        // protocol speaks it by prior knowledge, and it is recorded as agreed
        // (`LocateOut::alpn_written`).
        let prior = match located.offer.as_slice() {
            [one] if tls.is_none() => Some(one.clone()),
            _ => None,
        };
        Connection::over_socket(door, sock, dial, tls, offered_name, prior)
    }
}

impl Connection {
    /// Dial the UNIX-DOMAIN socket at `path` (the target `unix:<path>`, [`socket::unix_path`]) as a
    /// raw stream through `door`: no name, no address to judge, no connection security at the dial
    /// (a later [`Connection::upgrade_secure`] secures it as it would a TCP stream). The caller
    /// admits the target first (operator-infrastructure needs only); the endpoint check and the
    /// entry's `locate`, which read hosts, are not asked. The connection comes back at once, its
    /// open in flight.
    ///
    /// # Errors
    ///
    /// [`Failure::Refused`] when no socket listens at `path`; [`Failure::Failed`] off a worker or
    /// when the socket cannot be made.
    pub fn dial_unix(door: Arc<dyn FramerDoor>, dial: Dial, path: &str) -> Result<Self, Failure> {
        let stream = socket::connect_unix(path).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => {
                Failure::Refused(format!("no socket listens at `{path}`: {e}"))
            }
            _ => failed(e),
        })?;
        Self::over_socket(door, Sock::Unix(stream), dial, None, None, None)
    }

    /// A dialled connection over `sock`, its connect in flight; `prior` is the protocol it speaks
    /// by prior knowledge, recorded as agreed.
    fn over_socket(
        door: Arc<dyn FramerDoor>,
        sock: Sock,
        dial: Dial,
        tls: Option<rustls::Connection>,
        offered_name: Option<String>,
        prior: Option<Vec<u8>>,
    ) -> Result<Self, Failure> {
        let sock = reactor::register(sock).map_err(failed)?;
        let established = Established {
            offered_name,
            agreed_protocol: prior,
            claim: door.facts().claims.first().map(|c| (*c).to_owned()),
        };
        Ok(Self {
            door,
            wire: Wire::Socket(sock),
            target: dial.target,
            side: SIDE_DIAL,
            tls,
            framing: None,
            established,
            phase: Phase::Connecting,
            out: VecDeque::new(),
            inbox: VecDeque::new(),
            opening: dial.opening,
            head_words: dial.head_words,
            early: Vec::new(),
            flushed: 0,
            open_deadline: Some(Instant::now() + dial.open_timeout),
            framer_deadline: None,
            sleep: None,
            _slot: None,
            upgraded: false,
        })
    }
}

impl Connection {
    /// SPAWN `program` and frame its pipes through `door` (a byte-stream framer): no shell, its
    /// absolute path executed with its arguments and ONLY the environment it states, its input and
    /// output the connection, its error output the host's; the child killed when the connection
    /// closes or is dropped. The framing begins at once (`SIDE_DIAL`), with `dial`'s opening message and
    /// head words; the dial's target names the program for the framer, never its environment.
    ///
    /// # Errors
    ///
    /// [`Failure::Refused`] for a command that is not an absolute path; [`Failure::Failed`] off a
    /// worker or when the program cannot be spawned.
    pub fn spawn(
        door: Arc<dyn FramerDoor>,
        program: &busbar_contract::conn::Program,
        dial: Dial,
    ) -> Result<Self, Failure> {
        if !program.command.starts_with('/') {
            return Err(Failure::Refused(
                "a program is spawned by its absolute path only".into(),
            ));
        }
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(Failure::Failed(reactor::NOT_ON_A_WORKER.into()));
        }
        // Two OS pipes: the child reads one and writes the other; the host keeps the far ends.
        // The child's error output is the host's own (a spawned command inherits it).
        let (child_reads, host_writes) = std::io::pipe().map_err(failed)?;
        let (host_reads, child_writes) = std::io::pipe().map_err(failed)?;
        // The command (and the child's ends of the pipes it holds) is dropped with this statement,
        // so the child sees the end of its input when the host closes its end.
        let child = tokio::process::Command::new(&program.command)
            .args(&program.args)
            .env_clear()
            .envs(program.env.iter().map(|(k, v)| (k, v)))
            .stdin(child_reads)
            .stdout(child_writes)
            .kill_on_drop(true)
            .spawn()
            .map_err(failed)?;
        let stdin =
            tokio::net::unix::pipe::Sender::from_owned_fd(host_writes.into()).map_err(failed)?;
        let stdout =
            tokio::net::unix::pipe::Receiver::from_owned_fd(host_reads.into()).map_err(failed)?;
        let established = Established {
            offered_name: None,
            agreed_protocol: None,
            claim: door.facts().claims.first().map(|c| (*c).to_owned()),
        };
        let mut conn = Self {
            door,
            wire: Wire::Program(Box::new(Pipes {
                child,
                stdin,
                stdout,
            })),
            target: dial.target,
            side: SIDE_DIAL,
            tls: None,
            upgraded: false,
            framing: None,
            established,
            phase: Phase::Connecting,
            out: VecDeque::new(),
            inbox: VecDeque::new(),
            opening: dial.opening,
            head_words: dial.head_words,
            early: Vec::new(),
            flushed: 0,
            open_deadline: None,
            framer_deadline: None,
            sleep: None,
            _slot: None,
        };
        conn.begin()?;
        Ok(conn)
    }

    /// The process id of the program a spawned connection runs; `None` for a socket, or once the
    /// child was reaped.
    #[must_use]
    pub fn program_id(&self) -> Option<u32> {
        match &self.wire {
            Wire::Program(p) => p.child.id(),
            Wire::Socket(_) => None,
        }
    }

    /// Take `stream`, accepted by a listener, on the calling worker's reactor: server TLS first when
    /// `accept.tls` is set (bounded by the handshake timeout, the protocol agreed off
    /// `accept.alpn`), then the framing begun on `SIDE_ACCEPT`. `slot` is the listener's hold,
    /// freed when the connection is dropped.
    ///
    /// # Errors
    ///
    /// [`Failure::Failed`] off a worker or when the socket or TLS cannot be set up;
    /// [`Failure::Refused`] when the framer will not frame a clear connection.
    pub fn accepted(
        door: Arc<dyn FramerDoor>,
        stream: TcpStream,
        accept: &Accept,
        slot: Option<Slot>,
    ) -> Result<Self, Failure> {
        stream.set_nonblocking(true).map_err(failed)?;
        let _ = stream.set_nodelay(true);
        let tls = match &accept.tls {
            None => None,
            Some(base) => {
                let mut config = (**base).clone();
                config.alpn_protocols.clone_from(&accept.alpn);
                Some(rustls::Connection::Server(
                    rustls::ServerConnection::new(Arc::new(config)).map_err(failed)?,
                ))
            }
        };
        let sock = reactor::register(Sock::Tcp(stream)).map_err(failed)?;
        let established = Established {
            offered_name: None,
            agreed_protocol: None,
            claim: door.facts().claims.first().map(|c| (*c).to_owned()),
        };
        let mut conn = Self {
            door,
            wire: Wire::Socket(sock),
            target: String::new(),
            side: SIDE_ACCEPT,
            tls,
            framing: None,
            established,
            phase: Phase::Handshaking,
            out: VecDeque::new(),
            inbox: VecDeque::new(),
            opening: None,
            head_words: HeadWords::default(),
            early: Vec::new(),
            flushed: 0,
            open_deadline: Some(Instant::now() + accept.handshake_timeout),
            framer_deadline: None,
            sleep: None,
            _slot: slot,
            upgraded: false,
        };
        if conn.tls.is_none() {
            conn.begin()?;
        }
        Ok(conn)
    }

    /// Whether the connection is past its handshake and framing.
    #[must_use]
    pub fn is_open(&self) -> bool {
        matches!(self.phase, Phase::Open)
    }

    /// Whether this connection was dialled (its exchanges are the caller's requests), not accepted.
    #[must_use]
    pub fn dialled(&self) -> bool {
        self.side == SIDE_DIAL
    }

    /// Whether the connection has neither ended nor failed.
    #[must_use]
    pub fn live(&self) -> bool {
        !matches!(self.phase, Phase::Ended | Phase::Failed(_))
    }

    /// Whether the connection carries CONCURRENT exchanges, one stream each: the protocol agreed
    /// (in the handshake, or by prior knowledge) is `h2` (RFC 9113; ARCHITECT ruling Q-L18-MUX
    /// 2026-10-03: concurrent requests to one origin share an h2 connection, h1 stays one request
    /// per connection).
    #[must_use]
    pub fn multiplexes(&self) -> bool {
        self.dialled() && self.live() && self.established.agreed_protocol.as_deref() == Some(b"h2")
    }

    /// Every byte the socket has taken so far.
    #[must_use]
    pub fn flushed(&self) -> u64 {
        self.flushed
    }

    /// Whether the connection can carry another exchange now: dialled, framed and open, with
    /// nothing left unread and nothing held back for the socket.
    #[must_use]
    pub fn reusable(&self) -> bool {
        self.dialled()
            && self.framing.is_some()
            && matches!(self.phase, Phase::Open)
            && self.inbox.is_empty()
            && self.early.is_empty()
    }

    /// Take in whatever the far end sent while the connection sat idle (its goodbye, a closed
    /// socket, a settings change), without waiting, and answer whether it can still carry an
    /// exchange.
    pub fn fresh(&mut self, cx: &mut Context<'_>) -> bool {
        loop {
            match self.drive(cx) {
                Ok(true) if self.inbox.is_empty() => {}
                Ok(_) => return self.reusable(),
                Err(f) => {
                    self.phase = Phase::Failed(f);
                    return false;
                }
            }
        }
    }

    /// Open a NEW exchange on this dialled connection, on `stream`: `opening`, encoded with its
    /// head words by the entry, emitted now if the framing has begun and with the early writes
    /// once it does. The framer speaks whatever the connection agreed (on HTTP/2, a new stream of
    /// the same connection).
    ///
    /// # Errors
    ///
    /// The connection ended or failed, or the entry refused the message.
    pub fn open_exchange(
        &mut self,
        stream: u64,
        opening: Option<Opening>,
        head_words: HeadWords,
        cx: &mut Context<'_>,
    ) -> Result<(), Failure> {
        match &self.phase {
            Phase::Failed(f) => return Err(f.clone()),
            Phase::Ended => return Err(Failure::Closed),
            _ => {}
        }
        let Some(message) = self.encode_opening(opening, head_words)? else {
            return Ok(());
        };
        match self.phase {
            Phase::Open => {
                let framing = self.framing.as_mut().ok_or(Failure::Closed)?;
                let y = framing
                    .emit(stream, &message, true, false)
                    .map_err(failed)?;
                self.absorb(y)?;
            }
            _ => self.early.push((stream, message, true, false)),
        }
        if let Err(f) = self.drive(cx) {
            self.phase = Phase::Failed(f.clone());
            return Err(f);
        }
        Ok(())
    }

    /// `opening` as the entry's wire message with its head words; `None` = nothing to send.
    fn encode_opening(
        &self,
        opening: Option<Opening>,
        (method, target): HeadWords,
    ) -> Result<Option<Vec<u8>>, Failure> {
        let Some((fields, body)) = opening else {
            return Ok(None);
        };
        if fields.is_empty() && body.is_empty() && method.is_empty() && target.is_empty() {
            return Ok(None);
        }
        let fields: Vec<(&str, &[u8])> = fields
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_slice()))
            .collect();
        framer::encode_head(self.door.as_ref(), &method, &target, &fields, &body)
            .map(Some)
            .map_err(|e| Failure::Refused(e.to_string()))
    }
}

impl Connection {
    /// What connection security established (the agreed protocol, the name offered).
    #[must_use]
    pub fn established(&self) -> &Established {
        &self.established
    }

    /// THE MID-STREAM SECURITY UPGRADE (`UPGRADE_SECURE`): secure this dialled connection with
    /// `config`, offering `name`, from the next byte on. Whatever the connection already queued for
    /// the socket goes out in the clear first (a StartTLS request), then the client handshake; from
    /// then on every byte both ways crosses TLS, and the framing that already began is kept. A
    /// connection still connecting (TLS from the first byte, ldaps) takes the same path the dial's
    /// own security does. The first call starts it; every call drives it: `Ready(Ok)` once the
    /// handshake completed, `Pending` with `cx`'s waker registered while it runs. Bounded by
    /// `timeout`.
    ///
    /// # Errors
    ///
    /// [`Failure::Refused`]: the connection is an accepted one, was secured at its dial, the name
    /// is not a server name, or the far end's certificate or handshake was refused.
    pub fn upgrade_secure(
        &mut self,
        config: &Arc<rustls::ClientConfig>,
        name: &str,
        timeout: Duration,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Failure>> {
        if !self.upgraded {
            if self.side != SIDE_DIAL || self.tls.is_some() {
                return Poll::Ready(Err(Failure::Refused(
                    "the stream is already secure, or is not a dialled one".into(),
                )));
            }
            let mut config = (**config).clone();
            config.alpn_protocols.clear();
            let server = rustls::pki_types::ServerName::try_from(
                name.trim_start_matches('[')
                    .trim_end_matches(']')
                    .to_owned(),
            )
            .map_err(|e| Failure::Refused(format!("the name offered is not a server name: {e}")));
            let client = match server
                .and_then(|n| rustls::ClientConnection::new(Arc::new(config), n).map_err(failed))
            {
                Ok(c) => c,
                Err(f) => return Poll::Ready(Err(f)),
            };
            self.tls = Some(rustls::Connection::Client(client));
            self.upgraded = true;
            self.established.offered_name = Some(name.to_owned());
            self.open_deadline = Some(Instant::now() + timeout);
            if !matches!(self.phase, Phase::Connecting) {
                if let Err(f) = self.tls_out() {
                    self.phase = Phase::Failed(f.clone());
                    return Poll::Ready(Err(f));
                }
            }
        }
        loop {
            match &self.phase {
                Phase::Failed(f) => return Poll::Ready(Err(f.clone())),
                Phase::Ended => return Poll::Ready(Err(Failure::Closed)),
                Phase::Open if !self.handshaking() => return Poll::Ready(Ok(())),
                _ => {}
            }
            match self.drive(cx) {
                Ok(true) => {}
                Ok(false) => return Poll::Pending,
                Err(f) => self.phase = Phase::Failed(f),
            }
        }
    }

    /// The target the connection was dialled to.
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }

    /// Whether connection security is set and its handshake has not completed.
    fn handshaking(&self) -> bool {
        self.tls.as_ref().is_some_and(|t| t.is_handshaking())
    }

    /// The SHA-256 of the far end's certificate (the channel-binding input), lower-case hex, once a
    /// handshake completed; `None` on a connection in the clear or still handshaking.
    #[must_use]
    pub fn peer_cert_hash(&self) -> Option<String> {
        use std::fmt::Write as _;
        let tls = self.tls.as_ref().filter(|t| !t.is_handshaking())?;
        let leaf = tls.peer_certificates()?.first()?;
        let digest = ring::digest::digest(&ring::digest::SHA256, leaf.as_ref());
        Some(
            digest
                .as_ref()
                .iter()
                .fold(String::with_capacity(64), |mut hex, b| {
                    let _ = write!(hex, "{b:02x}");
                    hex
                }),
        )
    }

    /// The next frame piece: `Ready(Ok(Some))` a piece, `Ready(Ok(None))` the connection ended,
    /// `Pending` with `cx`'s waker on the socket and the timer.
    ///
    /// # Errors
    ///
    /// Why the connection failed.
    pub fn poll_piece(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Got>, Failure>> {
        loop {
            if let Some(p) = self.inbox.pop_front() {
                return Poll::Ready(Ok(Some(p)));
            }
            match &self.phase {
                Phase::Ended => return Poll::Ready(Ok(None)),
                Phase::Failed(f) => return Poll::Ready(Err(f.clone())),
                _ => {}
            }
            match self.drive(cx) {
                Ok(true) => {}
                Ok(false) => return Poll::Pending,
                Err(f) => self.phase = Phase::Failed(f),
            }
        }
    }

    /// Whether a piece (or the end) is ready, without taking it.
    pub fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        loop {
            if !self.inbox.is_empty() || matches!(self.phase, Phase::Ended | Phase::Failed(_)) {
                return Poll::Ready(());
            }
            match self.drive(cx) {
                Ok(true) => {}
                Ok(false) => return Poll::Pending,
                Err(f) => self.phase = Phase::Failed(f),
            }
        }
    }

    /// The bytes held for the socket: early writes and framed bytes it has not taken.
    fn buffered(&self) -> usize {
        self.out.len() + self.early.iter().map(|(_, b, _, _)| b.len()).sum::<usize>()
    }

    /// Offer `bytes` on the connection's exchange (`end` = the caller's message is complete, `text` =
    /// it is a text message),
    /// answering how many were taken: framed now if the framing has begun, else once it does; the
    /// socket takes them as its readiness allows, driven by `cx`. At most the room left under
    /// [`WRITE_BUFFER_BYTES`] is taken (`end` holds only when all of `bytes` was), so `Ok(0)` for a
    /// non-empty `bytes` means the buffer is full until the socket drains it.
    ///
    /// # Errors
    ///
    /// The connection is closed or failed, or the framer refused the bytes.
    pub fn write(
        &mut self,
        bytes: &[u8],
        end: bool,
        text: bool,
        cx: &mut Context<'_>,
    ) -> Result<usize, Failure> {
        self.emit(EXCHANGE_STREAM, bytes, end, text, cx)
    }

    /// Offer `bytes` on `stream` (`end` = the stream's message is complete, `text` = it is a text
    /// message): the framer's `emit`
    /// on that stream, now if the framing has begun, else once it does. An accepted connection
    /// answers each piece on the stream the piece came on.
    ///
    /// # Errors
    ///
    /// The connection is closed or failed, or the framer refused the bytes.
    pub fn emit(
        &mut self,
        stream: u64,
        bytes: &[u8],
        end: bool,
        text: bool,
        cx: &mut Context<'_>,
    ) -> Result<usize, Failure> {
        match &self.phase {
            Phase::Failed(f) => return Err(f.clone()),
            Phase::Ended => return Err(Failure::Closed),
            _ => {}
        }
        // Let the socket take what it can before measuring the room.
        if let Err(f) = self.drive(cx) {
            self.phase = Phase::Failed(f.clone());
            return Err(f);
        }
        let take = bytes
            .len()
            .min(WRITE_BUFFER_BYTES.saturating_sub(self.buffered()));
        if take == 0 && !bytes.is_empty() {
            return Ok(0);
        }
        let (bytes, end) = (&bytes[..take], end && take == bytes.len());
        match &self.phase {
            Phase::Failed(f) => return Err(f.clone()),
            Phase::Ended => return Err(Failure::Closed),
            Phase::Open => {
                let framing = self.framing.as_mut().ok_or(Failure::Closed)?;
                let y = framing.emit(stream, bytes, end, text).map_err(failed)?;
                self.absorb(y)?;
            }
            Phase::Connecting | Phase::Handshaking => {
                self.early.push((stream, bytes.to_vec(), end, text));
            }
        }
        if let Err(f) = self.drive(cx) {
            self.phase = Phase::Failed(f.clone());
            return Err(f);
        }
        Ok(take)
    }

    /// One pass: connect, handshake, flush, read, and keep the deadlines. `Ok(true)` = something
    /// moved; `Ok(false)` = nothing can until a waker fires.
    fn drive(&mut self, cx: &mut Context<'_>) -> Result<bool, Failure> {
        let mut moved = false;
        if matches!(self.phase, Phase::Connecting) {
            let connected = match &self.wire {
                Wire::Socket(sock) => socket::poll_connected(sock, cx),
                // A spawned program's pipes are open from the spawn.
                Wire::Program(_) => Poll::Ready(Ok(())),
            };
            match connected {
                Poll::Ready(Ok(())) => {
                    moved = true;
                    if self.tls.is_some() {
                        self.phase = Phase::Handshaking;
                        self.tls_out()?;
                    } else {
                        self.begin()?;
                    }
                }
                Poll::Ready(Err(e)) => return Err(Failure::Refused(e.to_string())),
                Poll::Pending => {}
            }
        }
        if !matches!(self.phase, Phase::Connecting) {
            moved |= self.flush(cx)?;
            moved |= self.read(cx)?;
        }
        moved |= self.keep_deadlines(cx)?;
        Ok(moved)
    }

    /// Write what the socket owes, as far as its readiness allows.
    fn flush(&mut self, cx: &mut Context<'_>) -> Result<bool, Failure> {
        let mut moved = false;
        while !self.out.is_empty() {
            let (a, _) = self.out.as_slices();
            let wrote = match &mut self.wire {
                Wire::Socket(sock) => sock.poll_io(Direction::Write, cx, |mut s| s.write(a)),
                Wire::Program(p) => {
                    tokio::io::AsyncWrite::poll_write(Pin::new(&mut p.stdin), cx, a)
                }
            };
            match wrote {
                Poll::Ready(Ok(0)) => return Err(Failure::Closed),
                Poll::Ready(Ok(n)) => {
                    self.out.drain(..n);
                    self.flushed += n as u64;
                    moved = true;
                }
                Poll::Ready(Err(e)) => return Err(failed(e)),
                Poll::Pending => break,
            }
        }
        Ok(moved)
    }

    /// Read what the socket has, and hand it on.
    fn read(&mut self, cx: &mut Context<'_>) -> Result<bool, Failure> {
        let mut buf = [0_u8; READ_CHUNK];
        let read = match &mut self.wire {
            Wire::Socket(sock) => sock.poll_io(Direction::Read, cx, |mut s| s.read(&mut buf)),
            Wire::Program(p) => {
                let mut into = tokio::io::ReadBuf::new(&mut buf);
                tokio::io::AsyncRead::poll_read(Pin::new(&mut p.stdout), cx, &mut into)
                    .map_ok(|()| into.filled().len())
            }
        };
        match read {
            Poll::Ready(Ok(0)) => {
                self.feed(&[], true)?;
                Ok(true)
            }
            Poll::Ready(Ok(n)) => {
                self.feed(&buf[..n], false)?;
                Ok(true)
            }
            Poll::Ready(Err(e)) => Err(failed(e)),
            Poll::Pending => Ok(false),
        }
    }

    /// The open's bound and the framer's deadline: the earlier is a timer on the worker's clock.
    fn keep_deadlines(&mut self, cx: &mut Context<'_>) -> Result<bool, Failure> {
        let now = Instant::now();
        if matches!(self.phase, Phase::Connecting | Phase::Handshaking) || self.handshaking() {
            if self.open_deadline.is_some_and(|at| at <= now) {
                return Err(Failure::Timeout);
            }
        } else {
            self.open_deadline = None;
        }
        let mut moved = false;
        if self.framer_deadline.is_some_and(|at| at <= now) {
            self.framer_deadline = None;
            if let Some(framing) = self.framing.as_mut() {
                let y = framing.timer().map_err(|e| match e.outcome {
                    busbar_contract::abi::mechanism::call::Outcome::Failed => Failure::Timeout,
                    _ => failed(e),
                })?;
                self.absorb(y)?;
                moved = true;
            }
        }
        let next = match (self.open_deadline, self.framer_deadline) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        match next {
            None => self.sleep = None,
            Some(at) => {
                if self.sleep.as_ref().is_none_or(|(when, _)| *when != at) {
                    // A conn driven from a dispatcher worker arms its deadline on the process's
                    // runtime timer, as its socket is on that runtime's reactor.
                    let _entered = crate::io::enter_process_runtime();
                    self.sleep = Some((
                        at,
                        Box::pin(tokio::time::sleep_until(tokio::time::Instant::from_std(at))),
                    ));
                }
                if let Some((_, sleep)) = self.sleep.as_mut() {
                    if sleep.as_mut().poll(cx).is_ready() {
                        self.sleep = None;
                        moved = true;
                    }
                }
            }
        }
        Ok(moved)
    }

    /// Begin the framing over what the open established, then send the first message and any
    /// early writes.
    fn begin(&mut self) -> Result<(), Failure> {
        let (framing, y) = Framing::begin(
            Arc::clone(&self.door),
            self.side,
            &self.target,
            &self.established,
        )
        .map_err(|e| Failure::Refused(e.to_string()))?;
        self.framing = Some(framing);
        self.phase = Phase::Open;
        self.absorb(y)?;
        self.send_opening()?;
        for (stream, bytes, end, text) in std::mem::take(&mut self.early) {
            let framing = self.framing.as_mut().ok_or(Failure::Closed)?;
            let y = framing.emit(stream, &bytes, end, text).map_err(failed)?;
            self.absorb(y)?;
        }
        Ok(())
    }

    /// Send the dial's first message, if one is held, on [`EXCHANGE_STREAM`].
    fn send_opening(&mut self) -> Result<(), Failure> {
        let opening = self.opening.take();
        let words = std::mem::take(&mut self.head_words);
        if let Some(message) = self.encode_opening(opening, words)? {
            let framing = self.framing.as_mut().ok_or(Failure::Closed)?;
            let y = framing
                .emit(EXCHANGE_STREAM, &message, true, false)
                .map_err(failed)?;
            self.absorb(y)?;
        }
        Ok(())
    }

    /// What the socket read: through TLS (finishing its handshake) to the framer.
    fn feed(&mut self, bytes: &[u8], end: bool) -> Result<(), Failure> {
        let Some(tls) = self.tls.as_mut() else {
            return self.ingest(bytes, end);
        };
        let mut rest = bytes;
        while !rest.is_empty() {
            tls.read_tls(&mut rest).map_err(failed)?;
            tls.process_new_packets()
                .map_err(|e| Failure::Refused(format!("tls: {e}")))?;
        }
        if matches!(self.phase, Phase::Handshaking) {
            if end {
                return Err(Failure::Refused(
                    "tls: the far end closed the handshake".into(),
                ));
            }
            if !self.tls.as_ref().is_some_and(|t| t.is_handshaking()) {
                self.established.agreed_protocol = self
                    .tls
                    .as_ref()
                    .and_then(|t| t.alpn_protocol().map(<[u8]>::to_vec));
                if let Some(rustls::Connection::Server(s)) = self.tls.as_ref() {
                    self.established.offered_name = s.server_name().map(str::to_owned);
                }
                self.begin()?;
            }
        }
        let mut plain = Vec::new();
        let mut closed = end;
        if let Some(tls) = self.tls.as_mut() {
            let mut buf = [0_u8; READ_CHUNK];
            loop {
                match tls.reader().read(&mut buf) {
                    Ok(0) => {
                        closed = true;
                        break;
                    }
                    Ok(n) => plain.extend_from_slice(&buf[..n]),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(failed(e)),
                }
            }
        }
        self.tls_out()?;
        if matches!(self.phase, Phase::Open) && (!plain.is_empty() || closed) {
            self.ingest(&plain, closed)?;
        }
        Ok(())
    }

    fn ingest(&mut self, bytes: &[u8], end: bool) -> Result<(), Failure> {
        let Some(framing) = self.framing.as_mut() else {
            return if end { Err(Failure::Closed) } else { Ok(()) };
        };
        let y = framing.ingest(bytes, end).map_err(failed)?;
        self.absorb(y)
    }

    /// Take what the framer answered: its wire bytes to the socket (through TLS), its pieces to
    /// the inbox, its deadline to the timer, its end to the connection.
    fn absorb(&mut self, y: Yielded) -> Result<(), Failure> {
        if !y.wire.is_empty() {
            match self.tls.as_mut() {
                Some(tls) => {
                    tls.writer().write_all(&y.wire).map_err(failed)?;
                    self.tls_out()?;
                }
                None => self.out.extend(y.wire),
            }
        }
        self.inbox.extend(y.pieces);
        self.framer_deadline = y.deadline_ns.map(framer::instant_of);
        if y.ended {
            self.phase = Phase::Ended;
        }
        Ok(())
    }

    /// Move whatever TLS owes the far side into the socket's queue.
    fn tls_out(&mut self) -> Result<(), Failure> {
        if let Some(tls) = self.tls.as_mut() {
            let mut bytes = Vec::new();
            while tls.wants_write() {
                tls.write_tls(&mut bytes).map_err(failed)?;
            }
            self.out.extend(bytes);
        }
        Ok(())
    }

    /// Close: the framing finishes, TLS says goodbye, and what that owes is written as far as the
    /// socket takes it now.
    pub fn close(mut self) {
        let framed = self.framing.is_some();
        if let Some(framing) = self.framing.take() {
            let y = framing.finish(CLOSE_NORMAL);
            let _ = self.absorb(y);
        }
        // A handshake that never finished is dropped, not said goodbye to (1.5.5's handshake
        // timeout drops the connection).
        if let Some(tls) = self.tls.as_mut().filter(|_| framed) {
            tls.send_close_notify();
            let _ = self.tls_out();
        }
        let waker = std::task::Waker::noop();
        let _ = self.flush(&mut Context::from_waker(waker));
        // A program is the connection's own: it ends with it.
        if let Wire::Program(p) = &mut self.wire {
            let _ = p.child.start_kill();
        }
    }
}

#[cfg(test)]
#[path = "tests/compose_tests.rs"]
mod tests;
