// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! COMPOSE: one connection, `carrier -> [TLS] -> framer` (`BUSBAR-1.6.0.md` THE DESIGN, §5;
//! TRANSPORT-STACK (2)), dialled ([`Connection::dial`], the framing begun on `SIDE_DIAL`) or accepted
//! ([`Connection::accepted`], the server-side mirror: TLS as the server, the framing begun on
//! `SIDE_ACCEPT`); or a PROGRAM ([`Connection::spawn`]: the carrier spawns it, through the host,
//! with no shell and only the environment its settings state; it is killed when the connection
//! closes or is dropped).
//!
//! THE CARRIER is the bottom of every connection ([`crate::carrier`]): it dials, accepts, reads and
//! writes over the host's I/O, and this module reaches the wire through its slots and nothing else.
//! A connection over a carrier's OWN claim (a raw stream, a program's lines) has no framer above
//! it: the carrier frames itself, every read a frame piece and every frame's end handed to it with
//! the frame's last bytes (`READ_END_OF_FRAME` / `WRITE_END_OF_FRAME`). Connection security is
//! `rustls` driven sans-IO here, with the protocol offer
//! (ALPN) the entry's `locate` answered (THE DESIGN, connections: "the ALPN offer is the
//! framer's"; the registration's offer stands only for an entry that answers none); the framer is
//! the entry's table ([`crate::framer`]).
//! The connection is a state machine the caller polls — it holds no thread and no task, and every
//! wait is Pending with the caller's waker registered on the carrier's side or the timer:
//!
//! * the bytes the carrier reads go through TLS to the framer's `ingest`;
//! * the framer's wire bytes go through TLS to the carrier;
//! * a deadline the framer states is a timer on the worker's clock, and at it the framer's `timer`
//!   runs; the open itself is bounded by the dial's own timeout;
//! * the frame pieces come out per stream, in order; `YIELD_ENDED` ends the connection.

use std::collections::VecDeque;
use std::future::Future;
use std::io::{self, Read, Write};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use busbar_contract::abi::host::conn::connector::{
    CAUSE_CONNECT, CAUSE_DEADLINE, CAUSE_EXCHANGE, CAUSE_FRAMER, CAUSE_SECURITY,
};
use busbar_contract::abi::transport::{CLOSE_NORMAL, FAULT_NONE, SIDE_ACCEPT, SIDE_DIAL};
use busbar_contract::conn::ConnCause;

use crate::carrier::{Carried, Dest, DialFailure};
use crate::endpoint;
use crate::framer::{self, Established, FramerDoor, Framing, Got, Yielded};
use crate::hostio::HostIo;

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
    /// The destination's sealed trust anchors (the transport pin, ARCHITECT 2026-10-03): the far end's key pin the
    /// handshake is held to and the client identity it presents; `None` = none sealed.
    pub anchors: Option<Arc<crate::tls::client::Sealed>>,
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

/// Connection security's error when the far end closes during the handshake (the words the
/// TLS stack's own handshake reports for it).
const HANDSHAKE_EOF: &str = "tls handshake eof";

enum Phase {
    Connecting,
    Handshaking,
    Open,
    Ended,
    Failed(Failure),
}

/// THE CARRIER a connection rides: its entry, and the host I/O the entry is served from.
#[derive(Clone)]
pub struct Via {
    /// The carrier entry.
    pub door: Arc<dyn FramerDoor>,
    /// The host's I/O.
    pub io: Arc<HostIo>,
}

impl std::fmt::Debug for Via {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Via")
            .field("carrier", &self.door.facts().name)
            .finish_non_exhaustive()
    }
}

fn dial_failure(f: DialFailure) -> Failure {
    match f {
        DialFailure::Refused(t) => Failure::Refused(t),
        DialFailure::Failed(t) => Failure::Failed(t),
    }
}

/// One composed connection.
pub struct Connection {
    /// The framer's entry; `None` = the carrier is carried as itself (a raw stream, a program's
    /// lines): it frames itself.
    door: Option<Arc<dyn FramerDoor>>,
    /// The carrier the bytes ride.
    carried: Carried,
    target: String,
    /// `SIDE_DIAL` | `SIDE_ACCEPT`.
    side: u32,
    /// Client TLS on a dialled connection, server TLS on an accepted one.
    tls: Option<rustls::Connection>,
    framing: Option<Framing>,
    established: Established,
    phase: Phase,
    /// Bytes for the carrier (ciphertext under TLS).
    out: VecDeque<u8>,
    /// Where a frame of the carrier's own wire ends in what was queued for it, as counts of every
    /// byte ever queued (a connection with no framer above its carrier).
    ends: VecDeque<u64>,
    /// Every byte ever queued for the carrier.
    queued: u64,
    /// Bytes the carrier took since its last `flush` answered READY.
    unflushed: bool,
    /// Frame pieces the caller has not taken.
    inbox: VecDeque<Got>,
    /// The first message, sent once the framing begins.
    opening: Option<Opening>,
    /// Its head words.
    head_words: HeadWords,
    /// Writes the caller made before the framing began, in order: `(stream, bytes, end)`.
    early: Vec<(u64, Vec<u8>, bool, bool)>,
    /// Every byte the carrier has taken, for the life of the connection.
    flushed: u64,
    /// The far side ENDED its stream (a read answered end of file) and the framer was told, once.
    /// Nothing more can be read: the socket is never read again, and its end is not news again.
    read_end: bool,
    open_deadline: Option<Instant>,
    framer_deadline: Option<Instant>,
    sleep: Option<(Instant, Pin<Box<tokio::time::Sleep>>)>,
    /// The listener's hold on one of its connection slots, freed when the connection is dropped.
    _slot: Option<Slot>,
    /// Connection security was asked for mid-stream ([`Connection::upgrade_secure`]), not at the
    /// dial.
    upgraded: bool,
    /// The framer's own error, when it is what failed the open connection.
    framer_error: Option<String>,
    /// The far end's key the handshake is held to (the dial's sealed anchors); `None` = no pin.
    key_pin: Option<String>,
    /// Raised when the handshake presented busbar's client identity.
    presented: Arc<std::sync::atomic::AtomicBool>,
    /// Connection security's own error, when it is what failed the connection.
    security_error: Option<String>,
    /// Why the connection failed, once it has (its stage and the underlying error's own text).
    cause: Option<ConnCause>,
}

/// THE REFUSAL OF A FAR END WHOSE KEY IS NOT THE PINNED ONE (the transport pin, ARCHITECT 2026-10-03): the handshake's chain
/// and name check passed and the leaf certificate's key is another, so the connection is refused
/// before a request byte is written. The connection's facts still name the key it served.
pub const PIN_REFUSED: &str =
    "tls: the far end's key is not the one its trust anchors pin; refused before any request byte";

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
            .field(
                "entry",
                &self
                    .door
                    .as_ref()
                    .unwrap_or(self.carried.door())
                    .facts()
                    .name,
            )
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
    pub fn dial(door: Arc<dyn FramerDoor>, via: &Via, dial: Dial) -> Result<Self, Failure> {
        let planned = Planned::locate(door, via.clone(), dial)?;
        let addr = crate::socket::address_of(planned.authority()).ok_or_else(|| {
            Failure::Refused(format!(
                "`{}` is not an address the connector dials without resolving a name",
                planned.authority()
            ))
        })?;
        planned.dial_at(addr)
    }
}

/// Where a dial over a carrier CARRIED AS ITSELF goes: its target is an authority, `host:port`, or
/// `<claim>://host:port` (`claim` the carrier's own); nothing is offered and no connection security
/// is asked for at the dial.
///
/// # Errors
///
/// [`Failure::Refused`]: the target is no authority.
pub fn carried_at(claim: &str, target: &str) -> Result<framer::Located, Failure> {
    let authority = target
        .strip_prefix(claim)
        .and_then(|t| t.strip_prefix("://"))
        .unwrap_or(target);
    if authority.is_empty() || authority.contains('/') {
        return Err(Failure::Refused("the target is not host:port".into()));
    }
    Ok(framer::Located {
        authority: authority.to_owned(),
        name: None,
        secure: false,
        offer: Vec::new(),
    })
}

/// A dial located but not yet dialled: the target and the authority the entry named passed the
/// endpoint check, and the address to dial is still to be judged.
pub struct Planned {
    /// The framer; `None` = the carrier carried as itself.
    door: Option<Arc<dyn FramerDoor>>,
    /// The carrier the dial rides.
    via: Via,
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
    pub fn locate(door: Arc<dyn FramerDoor>, via: Via, dial: Dial) -> Result<Self, Failure> {
        endpoint::check(&dial.target).map_err(|e| Failure::Refused(e.to_string()))?;
        let located = framer::locate(door.as_ref(), &dial.target)
            .map_err(|e| Failure::Refused(e.to_string()))?;
        endpoint::check(&located.authority).map_err(|e| Failure::Refused(e.to_string()))?;
        Ok(Self {
            door: Some(door),
            via,
            dial,
            located,
        })
    }

    /// A dial over a carrier CARRIED AS ITSELF (a need over the carrier's own claim, `claim`): its
    /// target is an authority, `host:port`, or `<claim>://host:port`; nothing is offered, and no
    /// connection security is asked for at the dial. The endpoint check, then the authority's.
    ///
    /// # Errors
    ///
    /// [`Failure::Refused`]: the target or the authority is refused, or the target is no authority.
    pub fn carried(via: Via, dial: Dial) -> Result<Self, Failure> {
        endpoint::check(&dial.target).map_err(|e| Failure::Refused(e.to_string()))?;
        let claim = via.door.facts().claims.first().copied().unwrap_or_default();
        let located = carried_at(claim, &dial.target)?;
        endpoint::check(&located.authority).map_err(|e| Failure::Refused(e.to_string()))?;
        Ok(Self {
            door: None,
            via,
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

    /// The same dial held to the destination's sealed trust anchors (`None` = none sealed).
    #[must_use]
    pub fn anchored(mut self, anchors: Option<Arc<crate::tls::client::Sealed>>) -> Self {
        self.dial.anchors = anchors;
        self
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
            via,
            dial,
            located,
        } = self;
        let presented = Arc::new(std::sync::atomic::AtomicBool::new(false));
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
            // A PINNED DESTINATION IS VERIFIED ON EVERY CONNECTION: no session is resumed, so each
            // handshake carries the far end's certificate and its key is held to the pin afresh
            // (a resumed session would present the key of the handshake it resumed).
            if dial.anchors.as_ref().is_some_and(|a| a.key_pin.is_some()) {
                config.resumption = rustls::client::Resumption::disabled();
            }
            // THE DESTINATION'S CLIENT IDENTITY, presented when the far end asks, and recorded.
            if let Some(identity) = dial.anchors.as_ref().and_then(|a| a.identity.clone()) {
                config.client_auth_cert_resolver = Arc::new(crate::tls::client::Presenting::new(
                    identity,
                    Arc::clone(&presented),
                ));
            }
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
        let carried = Carried::dial(
            Arc::clone(&via.door),
            Arc::clone(&via.io),
            &Dest::Authority(addr.to_string()),
        )
        .map_err(dial_failure)?;
        let offered_name = tls.as_ref().and(located.name.clone());
        Connection::open_dialled(
            door,
            carried,
            dial,
            (tls, presented),
            offered_name,
            &located.offer,
        )
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
    pub fn dial_unix(
        door: Option<Arc<dyn FramerDoor>>,
        via: &Via,
        dial: Dial,
        path: &str,
    ) -> Result<Self, Failure> {
        let carried = Carried::dial(
            Arc::clone(&via.door),
            Arc::clone(&via.io),
            &Dest::Authority(format!("{}{path}", crate::socket::UNIX_TARGET)),
        )
        .map_err(dial_failure)?;
        Self::open_dialled(
            door,
            carried,
            dial,
            (None, Arc::new(std::sync::atomic::AtomicBool::new(false))),
            None,
            &[],
        )
    }

    /// A dialled connection over `carried`, its connect in flight. `offer` is the protocols the
    /// entry's `locate` offered (none for a unix-domain dial, which asks no `locate`).
    fn open_dialled(
        door: Option<Arc<dyn FramerDoor>>,
        carried: Carried,
        dial: Dial,
        (tls, presented): (
            Option<rustls::Connection>,
            Arc<std::sync::atomic::AtomicBool>,
        ),
        offered_name: Option<String>,
        offer: &[Vec<u8>],
    ) -> Result<Self, Failure> {
        // No handshake to agree a protocol in the clear: an entry that offers exactly one
        // protocol speaks it by prior knowledge, and it is recorded as agreed
        // (`LocateOut::alpn_written`).
        let prior = match offer {
            [one] if tls.is_none() => Some(one.clone()),
            _ => None,
        };
        let established = Established {
            offered_name,
            agreed_protocol: prior,
            claim: door
                .as_ref()
                .unwrap_or(carried.door())
                .facts()
                .claims
                .first()
                .map(|c| (*c).to_owned()),
            ..Established::default()
        };
        let key_pin = dial.anchors.as_ref().and_then(|a| a.key_pin.clone());
        Ok(Self {
            door,
            carried,
            target: dial.target,
            side: SIDE_DIAL,
            tls,
            framing: None,
            established,
            phase: Phase::Connecting,
            out: VecDeque::new(),
            ends: VecDeque::new(),
            queued: 0,
            unflushed: false,
            inbox: VecDeque::new(),
            opening: dial.opening,
            head_words: dial.head_words,
            early: Vec::new(),
            flushed: 0,
            read_end: false,
            open_deadline: Some(Instant::now() + dial.open_timeout),
            framer_deadline: None,
            sleep: None,
            _slot: None,
            upgraded: false,
            framer_error: None,
            key_pin,
            presented,
            security_error: None,
            cause: None,
        })
    }
}

impl Connection {
    /// SPAWN `program` through the carrier `via` (the host spawns it: no shell, its absolute path
    /// executed with its arguments and ONLY the environment it states, its input and output the
    /// connection, its error output the host's; the child killed when the connection closes or is
    /// dropped), carried as itself: the carrier frames the program's lines. The connection opens at
    /// once (`SIDE_DIAL`), with `dial`'s opening message and head words.
    ///
    /// # Errors
    ///
    /// [`Failure::Refused`] for a command that is not an absolute path; [`Failure::Failed`] off a
    /// worker or when the program cannot be spawned.
    pub fn spawn(
        via: &Via,
        program: &busbar_contract::conn::Program,
        dial: Dial,
    ) -> Result<Self, Failure> {
        if !program.command.starts_with('/') {
            return Err(Failure::Refused(
                "a program is spawned by its absolute path only".into(),
            ));
        }
        let carried = Carried::dial(
            Arc::clone(&via.door),
            Arc::clone(&via.io),
            &Dest::Program(program.clone()),
        )
        .map_err(dial_failure)?;
        let established = Established {
            client_identity: false,
            peer_key_pin: None,
            offered_name: None,
            agreed_protocol: None,
            claim: carried
                .door()
                .facts()
                .claims
                .first()
                .map(|c| (*c).to_owned()),
        };
        let mut conn = Self {
            framer_error: None,
            cause: None,
            security_error: None,
            key_pin: None,
            presented: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            door: None,
            carried,
            target: dial.target,
            side: SIDE_DIAL,
            tls: None,
            upgraded: false,
            framing: None,
            established,
            phase: Phase::Connecting,
            out: VecDeque::new(),
            ends: VecDeque::new(),
            queued: 0,
            unflushed: false,
            inbox: VecDeque::new(),
            opening: dial.opening,
            head_words: dial.head_words,
            early: Vec::new(),
            flushed: 0,
            read_end: false,
            open_deadline: None,
            framer_deadline: None,
            sleep: None,
            _slot: None,
        };
        // A program's pipes are open from the spawn: the connection is open at once.
        conn.begin()?;
        Ok(conn)
    }

    /// Whether the program a spawned connection runs has exited (without waiting for it); `false`
    /// for a socket.
    pub fn program_exited(&mut self) -> bool {
        self.carried.program_exited()
    }

    /// Offer ONE WHOLE MESSAGE on the exchange: framed and queued all at once, or not at all while
    /// what is already queued would leave it past [`WRITE_BUFFER_BYTES`] (`Ok(false)`, nothing
    /// taken). A message alone in an empty queue is always taken, however long. Several writers
    /// sharing one connection never interleave part of one message with another's.
    ///
    /// # Errors
    ///
    /// The connection is closed or failed, or the framer refused the bytes.
    pub fn write_whole(&mut self, bytes: &[u8], cx: &mut Context<'_>) -> Result<bool, Failure> {
        match &self.phase {
            Phase::Failed(f) => return Err(f.clone()),
            Phase::Ended => return Err(Failure::Closed),
            _ => {}
        }
        if let Err(f) = self.drive(cx) {
            self.phase = Phase::Failed(f.clone());
            return Err(f);
        }
        let queued = self.buffered();
        if queued > 0 && queued.saturating_add(bytes.len()) > WRITE_BUFFER_BYTES {
            return Ok(false);
        }
        match &self.phase {
            Phase::Failed(f) => return Err(f.clone()),
            Phase::Ended => return Err(Failure::Closed),
            Phase::Open => self.put(EXCHANGE_STREAM, bytes, true, false)?,
            Phase::Connecting | Phase::Handshaking => {
                self.early
                    .push((EXCHANGE_STREAM, bytes.to_vec(), true, false));
            }
        }
        if let Err(f) = self.drive(cx) {
            self.phase = Phase::Failed(f.clone());
            return Err(f);
        }
        Ok(true)
    }

    /// The process id of the program a spawned connection runs; `None` for a socket, or once the
    /// child was reaped.
    #[must_use]
    pub fn program_id(&self) -> Option<u32> {
        self.carried.program_id()
    }

    /// Take the connection `carried`, accepted by a listener's carrier: server TLS first when
    /// `accept.tls` is set (bounded by the handshake timeout, the protocol agreed off
    /// `accept.alpn`), then the framing begun on `SIDE_ACCEPT`. `slot` is the listener's hold,
    /// freed when the connection is dropped.
    ///
    /// # Errors
    ///
    /// [`Failure::Failed`] off a worker or when the socket or TLS cannot be set up;
    /// [`Failure::Refused`] when the framer will not frame a clear connection.
    pub fn accepted(
        door: Option<Arc<dyn FramerDoor>>,
        carried: Carried,
        accept: &Accept,
        slot: Option<Slot>,
    ) -> Result<Self, Failure> {
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
        let established = Established {
            offered_name: None,
            agreed_protocol: None,
            claim: door
                .as_ref()
                .unwrap_or(carried.door())
                .facts()
                .claims
                .first()
                .map(|c| (*c).to_owned()),
            ..Established::default()
        };
        let mut conn = Self {
            door,
            carried,
            target: String::new(),
            side: SIDE_ACCEPT,
            tls,
            framing: None,
            established,
            phase: Phase::Handshaking,
            out: VecDeque::new(),
            ends: VecDeque::new(),
            queued: 0,
            unflushed: false,
            inbox: VecDeque::new(),
            opening: None,
            head_words: HeadWords::default(),
            early: Vec::new(),
            flushed: 0,
            read_end: false,
            open_deadline: Some(Instant::now() + accept.handshake_timeout),
            framer_deadline: None,
            sleep: None,
            _slot: slot,
            upgraded: false,
            framer_error: None,
            key_pin: None,
            presented: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            security_error: None,
            cause: None,
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
            && !self.read_end
            && self.inbox.is_empty()
            && self.early.is_empty()
    }

    /// Take in whatever the far end sent while the connection sat idle (its goodbye, a closed
    /// socket, a settings change), without waiting, and answer whether it can still carry an
    /// exchange.
    pub fn fresh(&mut self, cx: &mut Context<'_>) -> bool {
        loop {
            match self.drive(cx) {
                // Something moved and nothing arrived: drive again, while the connection is live.
                // One the framer ended (the far end closed it) is spent, whatever else moved.
                Ok(true) if self.inbox.is_empty() && self.live() => {}
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
            Phase::Open => self.put(stream, &message, true, false)?,
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
        let Some(door) = self.door.as_ref() else {
            // A carrier carried as itself has no head: an opening is its body, and fields are not
            // its to carry.
            if !fields.is_empty() {
                return Err(Failure::Refused(
                    "a carrier carried as itself carries no fields".into(),
                ));
            }
            return Ok(Some(body));
        };
        let fields: Vec<(&str, &[u8])> = fields
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_slice()))
            .collect();
        framer::encode_head(door.as_ref(), &method, &target, &fields, &body)
            .map(Some)
            .map_err(|e| Failure::Refused(e.to_string()))
    }

    /// Hand `bytes` on `stream` to the wire: through the framing (`emit`); or, for a carrier carried
    /// as itself, queued for the carrier as they are, `end` marking the end of a frame of its wire
    /// (through connection security when the stream was secured mid-way).
    fn put(&mut self, stream: u64, bytes: &[u8], end: bool, text: bool) -> Result<(), Failure> {
        if let Some(framing) = self.framing.as_mut() {
            let y = framing.emit(stream, bytes, end, text).map_err(failed)?;
            return self.absorb(y);
        }
        if self.door.is_some() {
            return Err(Failure::Closed);
        }
        match self.tls.as_mut() {
            Some(tls) => {
                tls.writer().write_all(bytes).map_err(failed)?;
                self.tls_out()?;
            }
            None => self.queue(bytes, end),
        }
        Ok(())
    }

    /// Queue `bytes` for the carrier; `end` = they end a frame of the carrier's own wire.
    fn queue(&mut self, bytes: &[u8], end: bool) {
        self.out.extend(bytes);
        self.queued += bytes.len() as u64;
        if end {
            self.ends.push_back(self.queued);
        }
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

    /// Why the connection failed, once it has: the stage it failed in (the socket's open,
    /// connection security, or the open connection; a deadline whatever the stage) and the
    /// underlying error's own text.
    #[must_use]
    pub fn cause(&self) -> Option<&ConnCause> {
        self.cause.as_ref()
    }

    /// The connection fails with `f`, in the stage it is in.
    fn fail(&mut self, f: Failure) {
        let framer = self.framer_error.take();
        let stage = match (&f, &self.phase) {
            (Failure::Timeout, _) => CAUSE_DEADLINE,
            (_, Phase::Open) if framer.is_some() => CAUSE_FRAMER,
            (_, Phase::Connecting) => CAUSE_CONNECT,
            (_, Phase::Handshaking) => CAUSE_SECURITY,
            _ => CAUSE_EXCHANGE,
        };
        let text = match &f {
            Failure::Refused(t) | Failure::Failed(t) => framer
                .or_else(|| self.security_error.take())
                .unwrap_or_else(|| t.clone()),
            Failure::Timeout | Failure::Closed => String::new(),
        };
        if !matches!(self.phase, Phase::Failed(_)) {
            self.cause = Some(ConnCause { stage, text });
        }
        self.phase = Phase::Failed(f);
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
                // The far side ended and the framer answered all it had: nothing more can arrive.
                Ok(false) if self.read_end && self.inbox.is_empty() => {
                    return Poll::Ready(Ok(None))
                }
                Ok(false) => return Poll::Pending,
                Err(f) => self.fail(f),
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
                Ok(false) if self.read_end => return Poll::Ready(()),
                Ok(false) => return Poll::Pending,
                Err(f) => self.fail(f),
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
        // The far side's FRAMES ended (`YIELD_ENDED`: no frame follows), not this side's writes:
        // while the framing stands, an answer to a frame handed up before the end still goes out,
        // ahead of the close the framing writes when the connection closes (a ws peer that broke
        // the protocol right after a message hears that message answered first; Autobahn 3.2,
        // 4.1.3, 5.15). Only a closed or failed connection refuses.
        match &self.phase {
            Phase::Failed(f) => return Err(f.clone()),
            Phase::Ended if self.framing.is_none() => return Err(Failure::Closed),
            _ => {}
        }
        // Let the socket take what it can before measuring the room.
        if let Err(f) = self.drive(cx) {
            self.fail(f.clone());
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
            Phase::Ended if self.framing.is_none() => return Err(Failure::Closed),
            Phase::Open | Phase::Ended => self.put(stream, bytes, end, text)?,
            Phase::Connecting | Phase::Handshaking => {
                self.early.push((stream, bytes.to_vec(), end, text));
            }
        }
        if let Err(f) = self.drive(cx) {
            self.fail(f.clone());
            return Err(f);
        }
        Ok(take)
    }

    /// One pass: connect, handshake, flush, read, and keep the deadlines. `Ok(true)` = something
    /// moved; `Ok(false)` = nothing can until a waker fires.
    fn drive(&mut self, cx: &mut Context<'_>) -> Result<bool, Failure> {
        let mut moved = false;
        if matches!(self.phase, Phase::Connecting) {
            // The carrier's `flush` on a fresh dial: its connect settled (or the far end refused).
            match self.carried.poll_connected(cx) {
                Poll::Ready(Ok(())) => {
                    moved = true;
                    if self.tls.is_some() {
                        self.phase = Phase::Handshaking;
                        self.tls_out()?;
                    } else {
                        self.begin()?;
                    }
                }
                Poll::Ready(Err(e)) => return Err(Failure::Refused(e)),
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

    /// Write what the carrier owes, as far as it takes it; once it took everything, its `flush`.
    /// A frame of the carrier's own wire is offered up to its end, with the end marked.
    fn flush(&mut self, cx: &mut Context<'_>) -> Result<bool, Failure> {
        let mut moved = false;
        loop {
            // A flush the write side pended finishes before more is offered; once the carrier took
            // everything, its flush puts it on the wire.
            if self.carried.flushing() || (self.out.is_empty() && self.unflushed) {
                match self.carried.poll_flush(cx) {
                    Poll::Pending => return Ok(moved),
                    Poll::Ready(Ok(())) => self.unflushed = false,
                    Poll::Ready(Err(e)) => return Err(failed(e)),
                }
            }
            if self.out.is_empty() {
                return Ok(moved);
            }
            let (a, _) = self.out.as_slices();
            // Up to the next frame's end, and that end marked when the offer reaches it.
            let (a, end) = match self.ends.front() {
                Some(&at) => {
                    let left =
                        usize::try_from(at.saturating_sub(self.flushed)).unwrap_or(usize::MAX);
                    if left <= a.len() {
                        (&a[..left], true)
                    } else {
                        (a, false)
                    }
                }
                None => (a, false),
            };
            match self.carried.poll_write(cx, a, end) {
                Poll::Ready(Ok(0)) if !a.is_empty() => return Err(Failure::Closed),
                Poll::Ready(Ok(n)) => {
                    if end && n == a.len() {
                        self.ends.pop_front();
                    }
                    self.out.drain(..n);
                    self.flushed += n as u64;
                    self.unflushed = true;
                    moved = true;
                }
                Poll::Ready(Err(e)) => return Err(failed(e)),
                Poll::Pending => return Ok(moved),
            }
        }
    }

    /// Read what the carrier has, and hand it on.
    fn read(&mut self, cx: &mut Context<'_>) -> Result<bool, Failure> {
        // THE FAR SIDE'S END IS NEWS ONCE. A socket that answered end of file answers it to every
        // later read, so re-reading it would hand the framer the same end again and report it as
        // movement every pass: a framer that does not end the connection on it (an idle HTTP/1.1
        // line whose far end closed) would then keep `fresh` and every reader's drive loop
        // spinning inside one crossing, until the dispatcher's watchdog faults the caller.
        if self.read_end {
            return Ok(false);
        }
        let mut buf = [0_u8; READ_CHUNK];
        match self.carried.poll_read(cx, &mut buf) {
            Poll::Ready(Ok((0, false))) => {
                self.read_end = true;
                self.feed(&[], true, false)?;
                Ok(true)
            }
            Poll::Ready(Ok((n, end_of_frame))) => {
                self.feed(&buf[..n], false, end_of_frame)?;
                Ok(true)
            }
            Poll::Ready(Err(e)) => {
                // A carrier carried as itself frames its own wire: what broke its read is the
                // framing's failure, in its words.
                if self.door.is_none() && self.tls.is_none() {
                    self.framer_error = Some(e.to_string());
                }
                Err(failed(e))
            }
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
        // A dial hands its opening head fields to the framing's begin too, for a wire that
        // carries them on the connection's opening (ARCHITECT Q-L5B-WS-DIAL).
        let opening: &[(String, Vec<u8>)] = match &self.opening {
            Some((fields, _)) if self.side == SIDE_DIAL => fields,
            _ => &[],
        };
        // A carrier carried as itself has no framing to begin: it is open.
        if let Some(door) = self.door.as_ref() {
            let (framing, y) = Framing::begin_with(
                Arc::clone(door),
                self.side,
                &self.target,
                &self.established,
                opening,
            )
            .map_err(|e| Failure::Refused(e.to_string()))?;
            self.framing = Some(framing);
            self.phase = Phase::Open;
            self.absorb(y)?;
        } else {
            self.phase = Phase::Open;
        }
        self.send_opening()?;
        for (stream, bytes, end, text) in std::mem::take(&mut self.early) {
            self.put(stream, &bytes, end, text)?;
        }
        Ok(())
    }

    /// Send the dial's first message, if one is held, on [`EXCHANGE_STREAM`].
    fn send_opening(&mut self) -> Result<(), Failure> {
        let opening = self.opening.take();
        let words = std::mem::take(&mut self.head_words);
        // A wire whose envelope renders nothing of an opening (its fields rode the framing's
        // begin) sends no opening message.
        if let Some(message) = self
            .encode_opening(opening, words)?
            .filter(|m| !m.is_empty())
        {
            self.put(EXCHANGE_STREAM, &message, true, false)?;
        }
        Ok(())
    }

    /// THE TRANSPORT PIN, held on a dialled connection whose handshake just completed: the far end's
    /// key read off its leaf certificate (already verified for its chain and name) and whether
    /// busbar presented its client identity go into the connection's facts, and a key that is not
    /// the pinned one refuses the connection before the framing begins, so no request byte leaves.
    fn hold_to_anchors(&mut self) -> Result<(), Failure> {
        let Some(rustls::Connection::Client(c)) = self.tls.as_ref() else {
            return Ok(());
        };
        self.established.peer_key_pin = c
            .peer_certificates()
            .and_then(|chain| chain.first())
            .and_then(|leaf| crate::tls::client::peer_key_pin(leaf.as_ref()));
        self.established.client_identity = self.presented.load(std::sync::atomic::Ordering::SeqCst);
        match &self.key_pin {
            Some(pin) if self.established.peer_key_pin.as_deref() != Some(pin.as_str()) => {
                Err(Failure::Refused(PIN_REFUSED.into()))
            }
            _ => Ok(()),
        }
    }

    /// What the carrier read (`end` = its clean end; `end_of_frame` = the bytes complete a frame of
    /// its own wire): through TLS (finishing its handshake) to the framer.
    fn feed(&mut self, bytes: &[u8], end: bool, end_of_frame: bool) -> Result<(), Failure> {
        let Some(tls) = self.tls.as_mut() else {
            return self.ingest(bytes, end, end_of_frame);
        };
        let mut rest = bytes;
        while !rest.is_empty() {
            tls.read_tls(&mut rest).map_err(failed)?;
            if let Err(e) = tls.process_new_packets() {
                self.security_error = Some(e.to_string());
                return Err(Failure::Refused(format!("tls: {e}")));
            }
        }
        if matches!(self.phase, Phase::Handshaking) {
            if end {
                self.security_error = Some(HANDSHAKE_EOF.into());
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
                self.hold_to_anchors()?;
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
            // Under connection security a carrier's frames are a stream's: each read is one.
            self.ingest(&plain, closed, true)?;
        }
        Ok(())
    }

    fn ingest(&mut self, bytes: &[u8], end: bool, end_of_frame: bool) -> Result<(), Failure> {
        let Some(framing) = self.framing.as_mut() else {
            if self.door.is_some() || !matches!(self.phase, Phase::Open) {
                return if end { Err(Failure::Closed) } else { Ok(()) };
            }
            // A CARRIER CARRIED AS ITSELF frames its own wire: each read is a piece of its frame,
            // on the one stream, the frame's end where the carrier marked it; its clean end ends the
            // connection.
            if !bytes.is_empty() || end_of_frame {
                self.inbox.push_back(Got {
                    stream: 0,
                    bytes: bytes.to_vec(),
                    end_of_frame,
                    status_code: None,
                    status_class: 0,
                    fault: FAULT_NONE,
                    retry_after_secs: None,
                    fields: false,
                    text: false,
                    reason: None,
                    failed: false,
                });
            }
            if end {
                self.phase = Phase::Ended;
            }
            return Ok(());
        };
        let y = match framing.ingest(bytes, end) {
            Ok(y) => y,
            Err(e) => {
                // What the far end sent (or its end) failed the framing: the framer's own words.
                self.framer_error = Some(e.error.clone());
                return Err(failed(e));
            }
        };
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
                None => self.queue(&y.wire, false),
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
            self.queue(&bytes, false);
        }
        Ok(())
    }

    /// Close: the framing finishes, TLS says goodbye, and what that owes is written as far as the
    /// socket takes it now.
    pub fn close(mut self) {
        // Framed: a framing begun, or a carrier carried as itself past its open.
        let framed = self.framing.is_some()
            || (self.door.is_none()
                && !matches!(self.phase, Phase::Connecting | Phase::Handshaking));
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
        // The carrier's connection ends with it (a program is the connection's own: it is killed).
        self.carried.close();
    }
}

#[cfg(test)]
#[path = "tests/compose_tests.rs"]
mod tests;
