// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! COMPOSE: one connection, `carrier -> [TLS] -> framer` (`BUSBAR-1.6.0.md` THE DESIGN, §5;

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
use busbar_contract::abi::transport::sensitive_fields::{SensitiveFields, REQUEST_TARGET_FIELD};
use busbar_contract::abi::transport::{CLOSE_NORMAL, FAULT_NONE, SIDE_ACCEPT, SIDE_DIAL};
use busbar_contract::conn::{Bytes, ConnCause};
use busbar_contract::secure::SecureString;

use crate::carrier::{Carried, Dest, DialFailure};
use crate::endpoint;
use crate::framer::{self, Established, FramerDoor, Framing, Got, Yielded};
use crate::hostio::HostIo;
use crate::secure_vec::{Scratch, SecureVec, Tail, READ_SCRATCH, TLS_PLAIN};

/// How much one socket read takes.
const READ_CHUNK: usize = 16 * 1024;

/// The open's bound when the caller states none.
pub const DEFAULT_OPEN_TIMEOUT: Duration = Duration::from_secs(10);

/// The most name lookups the host keeps in flight at once. A lookup that outlives its bound is let
pub const MAX_PENDING_LOOKUPS: usize = 64;

/// The stream a dialled connection's own exchange rides.
pub const EXCHANGE_STREAM: u64 = 1;

/// THE WRITE BUFFER CAP: the most bytes one connection holds on a caller's behalf and not yet on the
pub const WRITE_BUFFER_BYTES: usize = 256 * 1024;

/// The capacity a drained `out` keeps; above it, a drained buffer gives its memory back.
const OUT_KEEP: usize = 64 * 1024;

/// THE RECEIVE BUFFER CAP: the most bytes the far end sent that one connection holds read off its
pub const RECEIVE_BUFFER_BYTES: usize = 1024 * 1024;

/// Why a connection did not answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// The write took nothing; retry after the connection's next readiness wake.
    Pending,
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
            Self::Pending => f.write_str("the connection's write is pending"),
            Self::Refused(why) => write!(f, "refused: {why}"),
            Self::Timeout => f.write_str("the connection's deadline passed"),
            Self::Closed => f.write_str("the connection is closed"),
            Self::Failed(why) => write!(f, "failed: {why}"),
        }
    }
}

impl std::error::Error for Failure {}

/// A first message: its envelope fields and its body (frozen by its opener, kept without a copy).
pub type Opening = (Vec<(String, Vec<u8>)>, Bytes);

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
    /// The destination's sealed trust anchors (the transport pin): the far end's key pin the
    /// handshake is held to and the client identity it presents; `None` = none sealed.
    pub anchors: Option<Arc<crate::tls::client::Sealed>>,
    /// The opener's core-held acceptance admits plaintext to `target`
    /// ([`busbar_contract::conn::OpenDesc::plaintext_accepted`]): a dial not secured from its first
    /// byte is admitted and is not held to a cleartext window. `false` = only an exact
    /// `advanced.tls.destinations` plaintext entry admits one; no loopback address or name does.
    pub plaintext_accepted: bool,
}

/// A message's head words, method and target; empty = none.
pub type HeadWords = (Vec<u8>, Vec<u8>);

/// Wipe the opening's fields and the head's target: each is adopted, without a copy, by the secure
/// type that wipes it as it is dropped.
fn wipe_opening(opening: &mut Option<Opening>, words: &mut HeadWords) {
    if let Some((fields, _)) = opening.as_mut() {
        for (name, value) in fields.drain(..) {
            drop(SecureString::from(name));
            drop(SecureVec::from(value));
        }
    }
    drop(SecureVec::from(std::mem::take(&mut words.1)));
}

/// An opening's fields, held while they are encoded: each value is adopted, without a copy, by the
/// secure buffer that wipes it as the fields are dropped, on every exit.
struct WipedValues(Vec<(String, Vec<u8>)>);

impl Drop for WipedValues {
    fn drop(&mut self) {
        for (_, value) in self.0.drain(..) {
            drop(SecureVec::from(value));
        }
    }
}

impl Drop for Dial {
    fn drop(&mut self) {
        wipe_opening(&mut self.opening, &mut self.head_words);
    }
}

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

/// `rustls::Connection::write_tls`'s sink: TLS records appended to the connection's `out`.
struct OutSink<'a> {
    out: &'a mut SecureVec,
    queued: &'a mut u64,
}

impl Write for OutSink<'_> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.out
            .extend(b)
            .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
        *self.queued += b.len() as u64;
        Ok(b.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// One composed connection.
pub struct Connection {
    /// The framer's entry; `None` = the carrier is carried as itself (a raw stream, a program's
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
    /// Bytes for the carrier (ciphertext under TLS). A [`SecureVec`]: one contiguous run, and
    /// what the carrier took is wiped (request heads carry the injected `Authorization`).
    out: SecureVec,
    /// Where a frame of the carrier's own wire ends in what was queued for it, as counts of every
    ends: VecDeque<(u64, bool)>,
    /// Every byte ever queued for the carrier.
    queued: u64,
    /// Bytes the carrier took since its last `flush` answered READY.
    unflushed: bool,
    /// Frame pieces the caller has not taken.
    inbox: VecDeque<Got>,
    /// The bytes the pieces in `inbox` carry, kept as they come and go.
    inbox_bytes: usize,
    receive_held: usize,
    /// The first message, sent once the framing begins.
    opening: Option<Opening>,
    /// The initial opening's credential names, retained while Begin is parked.
    opening_sensitive: SensitiveFields,
    /// Its head words.
    head_words: HeadWords,
    /// Writes held back, in order: those the caller made before the framing began, and those on a
    early: EarlyWrites,
    /// Every byte the carrier has taken, for the life of the connection.
    flushed: u64,
    /// The far side ENDED its stream (a read answered end of file) and the framer was told, once.
    read_end: bool,
    open_deadline: Option<Instant>,
    framer_deadline: Option<Instant>,
    sleep: Option<(Instant, Pin<Box<tokio::time::Sleep>>)>,
    /// The listener's hold on one of its connection slots, freed when the connection is dropped.
    _slot: Option<Slot>,
    /// Connection security was asked for mid-stream ([`Connection::upgrade_secure`]), not at the
    upgraded: bool,
    /// The framer's own error, when it is what failed the open connection.
    framer_error: Option<String>,
    /// The framer's own error and the exact [`Failure`] it became, when the host's OUTBOUND emit of
    /// an opening is what the framer refused: a local fault, not the far end's. [`Self::fail`]
    /// honours it only for that same failure, so a later fault is never misread as local.
    emit_fault: Option<(String, Failure)>,
    /// The far end's key the handshake is held to (the dial's sealed anchors), in its canonical
    /// spelling: the anchors are kept (shared, not copied) only when they pin a key.
    pinned: Option<Arc<crate::tls::client::Sealed>>,
    /// Raised when the handshake presented busbar's client identity.
    presented: Arc<std::sync::atomic::AtomicBool>,
    /// Connection security's own error, when it is what failed the connection.
    security_error: Option<String>,
    /// Why the connection failed, once it has (its stage and the underlying error's own text).
    cause: Option<ConnCause>,
    /// THE PROXY TUNNEL a dial through a proxy asks for before anything else rides the socket
    tunnel: Option<Tunnel>,
    /// The connection failed while its proxy tunnel was still pending: the proxy hop, not the
    /// target, is what failed (its connect, its CONNECT answer, or its deadline).
    failed_at_proxy: bool,
    /// The framing's `begin` is parked on its ticket (an auth call it made is not ready): the
    opening_owed: bool,
    /// What the carrier read while the framing's `begin` was parked, in order, for the framer
    unfed: VecDeque<(Vec<u8>, bool, bool)>,
    /// THE NAME'S OTHER ADMITTED ADDRESSES, in the resolver's order: a connect the far end refuses
    fallback: Option<Fallback>,
    /// The protocols connection security offered (a dial) or agrees to (an accept), in the
    alpn_offer: Vec<u8>,
    /// THE LISTENER'S PROTOCOL OFFER ([`Accept::alpn`], the framer's accepting offer), in order:
    offer: Vec<Vec<u8>>,
    /// The 1-based position in `offer` the framer last stated it agreed (`FramerYield::agreed`);
    agreed: u32,
    /// A STREAM'S OWN BACKPRESSURE (`busbar_contract::abi::transport`): the streams whose last
    full: foldhash::HashSet<u64>,
    /// SEALED CREDENTIAL VALUES (TSEAL, [`crate::seal`]): the real bytes of the fillers the framer
    seals: crate::seal::Seals,
    /// THE PLAINTEXT RULE ON A CARRIER THAT UPGRADES LATER ([`Connection::hold_clear_window`]):
    /// `Some(n)` = before connection security is set, at most `n` more cleartext writes, each at
    /// most [`CLEAR_WINDOW_BYTES`], are taken (the protocol's own negotiation: a postgres
    /// SSLRequest, an LDAP StartTLS request, a MySQL SSLRequest); `None` = no window (secured from
    /// the first byte, a framed dial, or a destination plaintext is admitted to).
    clear_window: Option<u8>,
    /// STICKY: [`Connection::poll_prepared`] answered `Ready(Ok)`, or [`Connection::latch_prepared`]
    /// found the same condition at home ([`Connection::prepared_now`]). What a line answers a
    /// prepared exchange from while another holder has the connection out.
    prepared_landed: bool,
    /// STICKY: the connection failed while its carrier could still deliver bytes it already held
    /// (queued and unflushed, owed by TLS, or a parked emit's): `close()` may still send them, so no
    /// exchange queued on it is ever redialled ([`Connection::fail`]).
    wire_kept: bool,
    /// The carrier can no longer take or give bytes: a write or flush failed, it took nothing, or
    /// the far end ended the stream.
    carrier_lost: bool,
}

/// The largest cleartext write a carrier that must upgrade may make before it does
/// ([`Connection::hold_clear_window`]): every negotiation request busbar's carriers make fits.
const CLEAR_WINDOW_BYTES: usize = 64;

/// The refusal of a cleartext write past the negotiation window on a connection that must be
/// secured before it carries anything else.
const CLEAR_WINDOW_REFUSED: &str = "BUSBAR-3141: plaintext is not admitted to this destination: \
     it is neither loopback nor an exact advanced.tls.destinations entry with plaintext: true, so \
     the connection must be secured before it carries application bytes";

/// One write held back until the framing takes it: its stream, bytes, whether they end the
struct Early {
    stream: u64,
    bytes: SecureVec,
    end: bool,
    text: bool,
    body_len: Option<u64>,
    sensitive: SensitiveFields,
    /// The hold on its stream it was made under ([`HeldOn::epoch`]): a write whose stream failed
    /// after it was held no longer matches its stream's hold, and is let go.
    epoch: u64,
}

/// One stream's held writes: whether its newest carries no bytes, the bytes they carry, and the
/// hold they were made under.
#[derive(Clone, Copy)]
struct HeldOn {
    newest_empty: bool,
    bytes: usize,
    epoch: u64,
}

/// The writes held back, in order, with what is asked of them (does a stream have one held, is a
/// stream's newest one empty, how many bytes they hold) kept up to date as they are held and let go.
/// A failed stream's writes are let go by key: its hold is removed, and its writes, no longer
/// matching a hold, are passed over when the writes are taken (those at the tail go at once).
#[derive(Default)]
struct EarlyWrites {
    writes: Vec<Early>,
    /// Each stream with a write held.
    streams: foldhash::HashMap<u64, HeldOn>,
    /// The bytes the held writes carry.
    bytes: usize,
    /// The holds made so far: each new hold on a stream is the next.
    epochs: u64,
}

/// The writes held back, taken out in order: those whose stream failed after they were held are
/// passed over (and wiped as they go).
struct TakenWrites {
    writes: std::vec::IntoIter<Early>,
    streams: foldhash::HashMap<u64, HeldOn>,
}

impl Iterator for TakenWrites {
    type Item = Early;

    fn next(&mut self) -> Option<Early> {
        loop {
            let e = self.writes.next()?;
            if live(&self.streams, &e) {
                return Some(e);
            }
        }
    }
}

/// Whether `e` still matches its stream's hold in `streams` (its stream did not fail after it).
fn live(streams: &foldhash::HashMap<u64, HeldOn>, e: &Early) -> bool {
    streams.get(&e.stream).is_some_and(|h| h.epoch == e.epoch)
}

impl EarlyWrites {
    fn push(&mut self, mut e: Early) {
        let epochs = &mut self.epochs;
        let held = self.streams.entry(e.stream).or_insert_with(|| {
            *epochs += 1;
            HeldOn {
                newest_empty: false,
                bytes: 0,
                epoch: *epochs,
            }
        });
        held.newest_empty = e.bytes.is_empty();
        held.bytes += e.bytes.len();
        e.epoch = held.epoch;
        self.bytes += e.bytes.len();
        self.writes.push(e);
    }

    /// Every held write, in order; none is held after.
    fn take(&mut self) -> TakenWrites {
        self.bytes = 0;
        TakenWrites {
            writes: std::mem::take(&mut self.writes).into_iter(),
            streams: std::mem::take(&mut self.streams),
        }
    }

    /// Hold `writes` after those held now, in order.
    fn extend(&mut self, writes: TakenWrites) {
        for e in writes {
            self.push(e);
        }
    }

    fn is_empty(&self) -> bool {
        self.writes.is_empty()
    }

    fn holds(&self, stream: u64) -> bool {
        self.streams.contains_key(&stream)
    }

    /// Whether the newest held write (on `stream`; on any stream when `None`) carries no bytes.
    /// The newest write is always a live one: a failed stream's writes at the tail go at once.
    fn newest_empty(&self, stream: Option<u64>) -> bool {
        match stream {
            None => self.writes.last().is_some_and(|e| e.bytes.is_empty()),
            Some(s) => self.streams.get(&s).is_some_and(|h| h.newest_empty),
        }
    }

    /// `stream` failed: its held writes go. Its hold is removed by key; the writes it held at the
    /// tail are let go now, each popped once, and the rest are passed over when the writes are
    /// taken.
    fn drop_stream(&mut self, stream: u64) {
        let Some(held) = self.streams.remove(&stream) else {
            return;
        };
        self.bytes -= held.bytes;
        while self.writes.last().is_some_and(|e| !live(&self.streams, e)) {
            self.writes.pop();
        }
    }
}

impl Early {
    fn of(stream: u64, bytes: &[u8], end: bool, text: bool) -> Self {
        Self {
            stream,
            bytes: SecureVec::from(bytes),
            end,
            text,
            body_len: None,
            sensitive: SensitiveFields::default(),
            epoch: 0,
        }
    }
}

/// A dial's first message as it goes to the wire: the entry's encoding of it (wiped on drop), or,
/// over a carrier carried as itself, the body as the caller handed it.
enum Message {
    Encoded(SecureVec),
    Body(Bytes),
}

impl std::ops::Deref for Message {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        match self {
            Self::Encoded(bytes) => bytes,
            Self::Body(bytes) => bytes,
        }
    }
}

/// A CONNECT exchange in flight: the request (until it is queued), the proxy's answer so far, and
struct Tunnel {
    request: Vec<u8>,
    asked: bool,
    deadline: Option<Instant>,
    head: Vec<u8>,
    authority: String,
}

/// THE REFUSAL OF A FAR END WHOSE KEY IS NOT THE PINNED ONE (the transport pin): the handshake's
pub const PIN_REFUSED: &str =
    "tls: the far end's key is not the one its trust anchors pin; refused before any request byte";

/// THE REFUSAL OF AN UPGRADE OVER UNREAD CLEAR BYTES (STARTTLS response injection, the class of
pub const UPGRADE_OVER_CLEAR_BYTES: &str =
    "tls: bytes the far end sent in the clear are still unread; the upgrade is refused";

/// One of a listener's connection slots, held by the connection it admitted and freed on drop.
#[derive(Debug)]
pub struct Slot(Arc<std::sync::atomic::AtomicUsize>);

impl Slot {
    /// Take a slot of `live` when fewer than `max` are held; `None` = the listener is full.
    // `fetch_update`, not `try_update`: this crate's MSRV floor predates `try_update`. (The
    // toolchain this tree builds with raises no deprecation on it, so nothing is allowed here.)
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
                    .unwrap_or_else(|| self.carried.door())
                    .facts()
                    .name,
            )
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        wipe_opening(&mut self.opening, &mut self.head_words);
    }
}

fn failed(e: impl std::fmt::Display) -> Failure {
    Failure::Failed(crate::cold::framing::display(&e))
}

/// A refusal, keeping its reason's text.
fn refused(e: impl std::fmt::Display) -> Failure {
    Failure::Refused(crate::cold::framing::display(&e))
}

/// THE DRIVE'S CLOCK: `now`, read the first time the drive compares or arms a deadline and kept
/// for the rest of it, so a drive reads the clock at most once, and not at all when no deadline is
/// set. A reading taken earlier in the drive is a few µs early: it can only judge a deadline not yet
/// due, never fire one late, and the timer [`Connection::keep_deadlines`] arms wakes the drive for it.
fn clock(now: &mut Option<Instant>) -> Instant {
    *now.get_or_insert_with(|| {
        busbar_contract::work_count::tally(busbar_contract::work_count::Work::ClockRead);
        #[cfg(test)]
        clock_reads::read();
        framer::now()
    })
}

#[cfg(test)]
pub(crate) mod tls_probe {
    //! T6 test hooks: `ingest` calls counted per thread, and an injected disagreement between the
    //! plaintext count rustls states and what its reader gives.
    use std::cell::Cell;

    thread_local! {
        static INGESTS: Cell<u64> = const { Cell::new(0) };
        static ENDS: Cell<u64> = const { Cell::new(0) };
        static INFLATE: Cell<bool> = const { Cell::new(false) };
    }

    pub(crate) fn ingested(end: bool) {
        INGESTS.with(|n| n.set(n.get() + 1));
        if end {
            ENDS.with(|n| n.set(n.get() + 1));
        }
    }

    /// `(ingest calls, of which ended)` on this thread so far.
    pub(crate) fn ingests() -> (u64, u64) {
        (INGESTS.with(Cell::get), ENDS.with(Cell::get))
    }

    /// While set, `feed` believes one plaintext byte more than rustls holds (only when it holds any).
    pub(crate) fn inflate(on: bool) {
        INFLATE.with(|f| f.set(on));
    }

    pub(crate) fn inflation(plaintext: usize) -> usize {
        usize::from(plaintext > 0 && INFLATE.with(Cell::get))
    }
}

/// What the drives on this thread did with the clock (tests only): how many drives ran, how many
/// clock reads they made, and the most any one drive made.
#[cfg(test)]
pub(crate) mod clock_reads {
    use std::cell::Cell;

    thread_local! {
        static DRIVES: Cell<u64> = const { Cell::new(0) };
        static READS: Cell<u64> = const { Cell::new(0) };
        static THIS_DRIVE: Cell<u64> = const { Cell::new(0) };
        static MOST: Cell<u64> = const { Cell::new(0) };
    }

    /// The counts since the last [`take`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) struct Counted {
        pub(crate) drives: u64,
        pub(crate) reads: u64,
        pub(crate) most_in_one_drive: u64,
    }

    /// A drive starts.
    pub(crate) fn drove() {
        DRIVES.with(|n| n.set(n.get() + 1));
        THIS_DRIVE.with(|n| n.set(0));
    }

    /// The drive under way read the clock.
    pub(crate) fn read() {
        READS.with(|n| n.set(n.get() + 1));
        let this = THIS_DRIVE.with(|n| {
            n.set(n.get() + 1);
            n.get()
        });
        MOST.with(|n| n.set(n.get().max(this)));
    }

    /// The counts so far, starting them again from zero.
    pub(crate) fn take() -> Counted {
        THIS_DRIVE.with(|n| n.set(0));
        Counted {
            drives: DRIVES.with(|n| n.replace(0)),
            reads: READS.with(|n| n.replace(0)),
            most_in_one_drive: MOST.with(|n| n.replace(0)),
        }
    }
}

/// `protocols`, most preferred first, in the handshake's ProtocolNameList encoding (one length
/// byte each), written after what `list` holds: the connection's own stored offer.
fn write_protocol_names(protocols: &[Vec<u8>], list: &mut Vec<u8>) {
    for id in protocols {
        if let Ok(n @ 1..=u8::MAX) = u8::try_from(id.len()) {
            list.push(n);
            list.extend_from_slice(id);
        }
    }
}

/// [`write_protocol_names`] into a list of its own (tests only).
#[cfg(test)]
fn protocol_name_list(protocols: &[Vec<u8>]) -> Vec<u8> {
    let mut list = Vec::new();
    write_protocol_names(protocols, &mut list);
    list
}

/// THE AGREED PROTOCOL IS ONE THE HANDSHAKE OFFERED (`check_agreed`, before the framer is handed
fn agreed_was_offered(offer: &[u8], agreed: Option<&[u8]>) -> Result<(), Failure> {
    busbar_contract::abi::transport::check::check_agreed(offer, agreed.unwrap_or_default())
        .map_err(|f| {
            crate::cold::framing::refused(format_args!(
                "connection security: the protocol agreed breaks {:?} at {}",
                f.rule, f.field
            ))
        })?;
    Ok(())
}

impl Connection {
    /// Keep the original dial bound after a pended judgement; the TLS clock cannot restart at
    pub(crate) fn bound_open(&mut self, at: Instant) {
        if let Some(existing) = self.open_deadline {
            self.open_deadline = Some(existing.min(at));
        }
    }

    /// Dial `dial.target` through `door`, an IP literal dialled as written and judged by no
    pub fn dial(door: Arc<dyn FramerDoor>, via: &Via, dial: Dial) -> Result<Self, Failure> {
        endpoint::check(&dial.target).map_err(refused)?;
        let planned = Planned::locate(door, via.clone(), dial)?;
        endpoint::check(planned.authority()).map_err(refused)?;
        let addr = crate::socket::address_of(planned.authority()).ok_or_else(|| {
            crate::cold::framing::refused(format_args!(
                "`{}` is not an address the connector dials without resolving a name",
                planned.authority()
            ))
        })?;
        planned.dial_at(addr)
    }
}

/// THE HEAD THE FRAMER WAS PROMISED (THE DESIGN section 6, step 5): the dial's opening completed
fn complete_opening(dial: &mut Dial, located: &mut framer::Located) {
    let Some((fields, body)) = dial.opening.as_mut() else {
        return;
    };
    let (method, target) = &dial.head_words;
    if fields.is_empty() && body.is_empty() && method.is_empty() && target.is_empty() {
        return;
    }
    // The located defaults are lent to the head for the completion and handed back after.
    let head = busbar_contract::conn::HeadDefaults {
        lines: std::mem::take(&mut located.defaults),
        states_length: located.states_length,
    };
    let added = head.completing(
        |name| {
            fields
                .iter()
                .any(|(n, _)| n.as_bytes().eq_ignore_ascii_case(name))
        },
        body.len(),
    );
    located.defaults = head.lines;
    // Each added name becomes its text in place (only a name that is not UTF-8 is rewritten,
    // lossily, as before).
    fields.extend(added.into_iter().map(|(n, v)| {
        (
            String::from_utf8(n).unwrap_or_else(|e| framer::lossy(e.as_bytes())),
            v,
        )
    }));
}

/// Where a dial over a carrier CARRIED AS ITSELF goes: its target is an authority, `host:port`, or
pub fn carried_at(claim: &str, target: &str) -> Result<framer::Located, Failure> {
    let authority = target
        .strip_prefix(claim)
        .and_then(|t| t.strip_prefix("://"))
        .unwrap_or(target);
    if authority.is_empty() || authority.contains('/') {
        return Err(Failure::Refused("the target is not host:port".into()));
    }
    let authority = crate::off_path::compose::owned(authority);
    Ok(framer::Located {
        authority,
        name: None,
        secure: false,
        offer: Vec::new(),
        defaults: Vec::new(),
        states_length: false,
    })
}

/// A dial located but not yet dialled: the target and the authority the entry named each name a
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
    /// The target names a host, the entry's `locate`, and the authority it named names one too.
    pub fn locate(door: Arc<dyn FramerDoor>, via: Via, dial: Dial) -> Result<Self, Failure> {
        Self::locate_carried(door, via, dial, None)
    }

    /// [`Planned::locate`], with the entry's answer already `carried` for this dial's target
    /// (the one the attempt's head was completed with): the target was parsed and the entry
    /// asked once, so neither repeats. `None` locates as [`Planned::locate`] does.
    pub fn locate_carried(
        door: Arc<dyn FramerDoor>,
        via: Via,
        dial: Dial,
        carried: Option<framer::Located>,
    ) -> Result<Self, Failure> {
        let located = match carried {
            Some(located) => located,
            None => {
                endpoint::named(&dial.target).map_err(refused)?;
                framer::locate(door.as_ref(), &dial.target).map_err(refused)?
            }
        };
        Self::checked(door, via, dial, located)
    }

    /// [`Planned::locate`] with the entry's answer already in hand (a declared target's kept
    /// place, located by this very entry at deadline 0): the same checks, the same head.
    pub fn located(
        door: Arc<dyn FramerDoor>,
        via: Via,
        dial: Dial,
        located: framer::Located,
    ) -> Result<Self, Failure> {
        endpoint::named(&dial.target).map_err(refused)?;
        Self::checked(door, via, dial, located)
    }

    /// The located authority names a host, and the dial's opening is completed from the answer.
    fn checked(
        door: Arc<dyn FramerDoor>,
        via: Via,
        mut dial: Dial,
        mut located: framer::Located,
    ) -> Result<Self, Failure> {
        endpoint::named(&located.authority).map_err(refused)?;
        complete_opening(&mut dial, &mut located);
        Ok(Self {
            door: Some(door),
            via,
            dial,
            located,
        })
    }

    /// A dial over a carrier CARRIED AS ITSELF (a need over the carrier's own claim, `claim`): its
    pub fn carried(via: Via, dial: Dial) -> Result<Self, Failure> {
        endpoint::named(&dial.target).map_err(refused)?;
        let claim = via.door.facts().claims.first().copied().unwrap_or_default();
        let located = carried_at(claim, &dial.target)?;
        endpoint::named(&located.authority).map_err(refused)?;
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

    /// Whether the opener's core-held acceptance admits plaintext to this dial ([`Dial::plaintext_accepted`]).
    #[must_use]
    pub fn plaintext_accepted(&self) -> bool {
        self.dial.plaintext_accepted
    }

    /// Whether a framer rides the dial (an application protocol over the stream), not a carrier
    #[must_use]
    pub fn framed(&self) -> bool {
        self.door.is_some()
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

    /// The protocols this plan's connection offers, as its dial uses them: secured, the entry's
    /// located offer, else the dial's own; in the clear, the located offer, whose single protocol
    /// is the agreed one (WASTE-EGRESS rule 2).
    #[must_use]
    pub fn offer(&self) -> &[Vec<u8>] {
        if self.located.secure && self.located.offer.is_empty() {
            &self.dial.alpn
        } else {
            &self.located.offer
        }
    }

    /// This dial's first message and its head words, taken out (a reuse sends them on a pooled
    #[must_use]
    pub fn into_opening(mut self) -> (Option<Opening>, HeadWords) {
        (
            self.dial.opening.take(),
            std::mem::take(&mut self.dial.head_words),
        )
    }

    /// The same dial held to the destination's sealed trust anchors (`None` = none sealed).
    #[must_use]
    pub fn anchored(mut self, anchors: Option<Arc<crate::tls::client::Sealed>>) -> Self {
        self.dial.anchors = anchors;
        self
    }

    /// Dial exactly `addr` — the address judged for [`Self::authority`] — with the name the entry
    pub fn dial_at(self, addr: std::net::SocketAddr) -> Result<Connection, Failure> {
        self.dial_via(addr, None).map_err(|(_, f)| f)
    }

    /// [`Self::dial_at`] `addr`, a connect the far end refuses moving on to each of `also` in
    pub fn dial_at_any(
        self,
        addr: std::net::SocketAddr,
        also: Vec<std::net::SocketAddr>,
    ) -> Result<Connection, Failure> {
        let via = (Arc::clone(&self.via.door), Arc::clone(&self.via.io));
        let mut conn = self.dial_via(addr, None).map_err(|(_, f)| f)?;
        if !also.is_empty() {
            conn.fallback = Some(Fallback {
                door: via.0,
                io: via.1,
                next: also.into(),
            });
        }
        Ok(conn)
    }

    /// Dial the PROXY at `proxy` and, once it connects, ask it for a tunnel to this plan's
    /// A failure names the hop that failed: the target's own connection-security setup, or the
    /// dial to the proxy.
    pub(crate) fn dial_through(
        self,
        proxy: std::net::SocketAddr,
        connect: Vec<u8>,
    ) -> Result<Connection, (Hop, Failure)> {
        self.dial_via(proxy, Some(connect))
    }

    /// Dial `addr`; with `connect`, `addr` is a proxy and `connect` the tunnel request.
    fn dial_via(
        self,
        addr: std::net::SocketAddr,
        connect: Option<Vec<u8>>,
    ) -> Result<Connection, (Hop, Failure)> {
        let dialled = if connect.is_some() {
            Hop::Proxy
        } else {
            Hop::Target
        };
        let target = |f: Failure| (Hop::Target, f);
        let authority_for_tunnel = self.located.authority.clone();
        let Self {
            door,
            via,
            mut dial,
            mut located,
        } = self;
        let presented = Arc::new(std::sync::atomic::AtomicBool::new(false));
        // The client config the handshake is set up with: its protocol offer is the one the
        // connection keeps, encoded, to hold the agreed protocol to.
        let mut offered: Option<Arc<rustls::ClientConfig>> = None;
        let tls = if located.secure {
            let base = dial
                .anchors
                .as_ref()
                .and_then(|a| a.tls.clone())
                .or_else(|| dial.tls.clone())
                .ok_or_else(|| {
                    Failure::Refused(
                        "the target asks for connection security and none is set".into(),
                    )
                })
                .map_err(target)?;
            let mut config = (*base).clone();

            // rustls owns the protocol offer of the client config each connection's handshake is
            // set up with: the dial's own list (or the entry's) is moved into it, not copied. A
            // secured dial reads neither again (a single located protocol is the agreed one only
            // in the clear).
            let protocols = if located.offer.is_empty() {
                std::mem::take(&mut dial.alpn)
            } else {
                std::mem::take(&mut located.offer)
            };
            config.alpn_protocols = protocols;

            if dial.anchors.as_ref().is_some_and(|a| a.key_pin.is_some()) {
                config.resumption = rustls::client::Resumption::disabled();
            }

            if let Some(identity) = dial.anchors.as_ref().and_then(|a| a.identity.clone()) {
                config.client_auth_cert_resolver = Arc::new(crate::tls::client::Presenting::new(
                    identity,
                    Arc::clone(&presented),
                ));
            }
            let host = offered_host(&located);
            let name = rustls::pki_types::ServerName::try_from(
                host.trim_start_matches('[').trim_end_matches(']'),
            )
            .map(|name| name.to_owned())
            .map_err(|e| {
                crate::cold::framing::refused(format_args!(
                    "the name offered is not a server name: {e}"
                ))
            })
            .map_err(target)?;
            let config = Arc::new(config);
            offered = Some(Arc::clone(&config));
            Some(rustls::Connection::Client(
                rustls::ClientConnection::new(config, name)
                    .map_err(failed)
                    .map_err(target)?,
            ))
        } else {
            None
        };
        let carried = Carried::dial(
            Arc::clone(&via.door),
            Arc::clone(&via.io),
            &Dest::Authority(crate::off_path::compose::display_text(&addr)),
        )
        .map_err(dial_failure)
        .map_err(|f| (dialled, f))?;
        // When TLS is active the SNI may come from located.name or, if that is None,
        // from the authority host (see the `host` fallback above).  Record whichever
        // name was actually offered so ConnFacts.sni is accurate.
        let offered_name = tls
            .as_ref()
            .map(|_| crate::off_path::compose::owned(offered_host(&located)));
        let mut conn = Connection::open_dialled(
            door,
            carried,
            dial,
            (tls, presented),
            offered_name,
            &located.offer,
        )
        .map_err(|f| (dialled, f))?;
        if let Some(config) = &offered {
            write_protocol_names(&config.alpn_protocols, &mut conn.alpn_offer);
        }
        conn.tunnel = connect.map(|request| Tunnel {
            request,
            asked: false,
            deadline: None,
            head: Vec::new(),
            authority: authority_for_tunnel,
        });
        Ok(conn)
    }
}

/// The name a secured dial offers the far end: the entry's located name, else the authority's host.
fn offered_host(located: &framer::Located) -> &str {
    located.name.as_deref().unwrap_or_else(|| {
        located
            .authority
            .rsplit_once(':')
            .map_or(located.authority.as_str(), |(h, _)| h)
    })
}

/// WHICH HOP OF A PROXIED DIAL FAILED: the target's own setup (its connection security), or the
/// dial to the proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Hop {
    /// The target: its connection-security setup failed before any connect.
    Target,
    /// The proxy: the dial to it failed.
    Proxy,
}

/// A dial's remaining addresses ([`Connection::fallback`]) and the carrier that dials them.
struct Fallback {
    door: Arc<dyn FramerDoor>,
    io: Arc<HostIo>,
    next: VecDeque<std::net::SocketAddr>,
}

impl Connection {
    /// Dial the UNIX-DOMAIN socket at `path` (the target `unix:<path>`, [`socket::unix_path`]) as a
    pub fn dial_unix(
        door: Option<Arc<dyn FramerDoor>>,
        via: &Via,
        dial: Dial,
        path: &str,
    ) -> Result<Self, Failure> {
        let carried = Carried::dial(
            Arc::clone(&via.door),
            Arc::clone(&via.io),
            &Dest::Authority(crate::off_path::compose::unix_authority(path)),
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
    fn open_dialled(
        door: Option<Arc<dyn FramerDoor>>,
        carried: Carried,
        mut dial: Dial,
        (tls, presented): (
            Option<rustls::Connection>,
            Arc<std::sync::atomic::AtomicBool>,
        ),
        offered_name: Option<String>,
        offer: &[Vec<u8>],
    ) -> Result<Self, Failure> {
        let prior = match offer {
            [one] if tls.is_none() => Some(one.clone()),
            _ => None,
        };
        let established = Established {
            offered_name,
            agreed_protocol: prior,
            scheme: Established::scheme_of(tls.is_some()),
            claim: door
                .as_ref()
                .unwrap_or_else(|| carried.door())
                .facts()
                .claims
                .first()
                .copied()
                .map(crate::off_path::compose::owned),
            ..Established::default()
        };
        let pinned = dial.anchors.take().filter(|a| a.key_pin.is_some());
        Ok(Self {
            door,
            carried,
            target: std::mem::take(&mut dial.target),
            side: SIDE_DIAL,
            tls,
            framing: None,
            established,
            phase: Phase::Connecting,
            out: SecureVec::new(),
            ends: VecDeque::new(),
            queued: 0,
            unflushed: false,
            inbox: VecDeque::new(),
            inbox_bytes: 0,
            receive_held: 0,
            opening: dial.opening.take(),
            head_words: std::mem::take(&mut dial.head_words),
            early: EarlyWrites::default(),
            flushed: 0,
            read_end: false,
            prepared_landed: false,
            wire_kept: false,
            carrier_lost: false,

            open_deadline: framer::now().checked_add(dial.open_timeout),
            framer_deadline: None,
            sleep: None,
            _slot: None,
            upgraded: false,
            framer_error: None,
            emit_fault: None,
            pinned,
            presented,
            security_error: None,
            cause: None,
            opening_owed: false,
            unfed: VecDeque::new(),
            tunnel: None,
            failed_at_proxy: false,
            clear_window: None,
            fallback: None,
            alpn_offer: Vec::new(),
            offer: Vec::new(),
            agreed: 0,
            full: foldhash::HashSet::default(),
            seals: crate::seal::Seals::default(),
            opening_sensitive: SensitiveFields::default(),
        })
    }
}

/// How a program's environment references resolve: at config time, held for its spawns
pub use crate::spawn_env::SpawnSecretFn;

impl Connection {
    /// SPAWN `program` through the carrier `via` (the host spawns it: no shell, its absolute path
    pub fn spawn(
        via: &Via,
        program: &busbar_contract::conn::Program,
        env: &crate::spawn_env::HeldEnv,
        mut dial: Dial,
        supervision_key: u64,
    ) -> Result<Self, Failure> {
        if !std::path::Path::new(&program.command).is_absolute() {
            return Err(Failure::Refused(
                "a program is spawned by its absolute path only".into(),
            ));
        }
        let carried = Carried::dial(
            Arc::clone(&via.door),
            Arc::clone(&via.io),
            &Dest::Program(program.clone(), env.clone(), supervision_key),
        )
        .map_err(dial_failure)?;
        let established = Established {
            scheme: Established::scheme_of(false),
            client_identity: false,
            peer_key_pin: None,
            offered_name: None,
            agreed_protocol: None,
            claim: carried
                .door()
                .facts()
                .claims
                .first()
                .copied()
                .map(crate::off_path::compose::owned),
        };
        let mut conn = Self {
            framer_error: None,
            emit_fault: None,
            cause: None,
            opening_owed: false,
            unfed: VecDeque::new(),
            tunnel: None,
            failed_at_proxy: false,
            clear_window: None,
            fallback: None,
            alpn_offer: Vec::new(),
            offer: Vec::new(),
            agreed: 0,
            full: foldhash::HashSet::default(),
            seals: crate::seal::Seals::default(),
            opening_sensitive: SensitiveFields::default(),
            security_error: None,
            pinned: None,
            presented: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            door: None,
            carried,
            target: std::mem::take(&mut dial.target),
            side: SIDE_DIAL,
            tls: None,
            upgraded: false,
            framing: None,
            established,
            phase: Phase::Connecting,
            out: SecureVec::new(),
            ends: VecDeque::new(),
            queued: 0,
            unflushed: false,
            inbox: VecDeque::new(),
            inbox_bytes: 0,
            receive_held: 0,
            opening: dial.opening.take(),
            head_words: std::mem::take(&mut dial.head_words),
            early: EarlyWrites::default(),
            flushed: 0,
            read_end: false,
            prepared_landed: false,
            wire_kept: false,
            carrier_lost: false,
            open_deadline: framer::now().checked_add(dial.open_timeout),
            framer_deadline: None,
            sleep: None,
            _slot: None,
        };

        conn.begin()?;
        Ok(conn)
    }

    /// Whether the program a spawned connection runs has exited (without waiting for it); `false`
    pub fn program_exited(&mut self) -> bool {
        self.carried.program_exited()
    }

    /// Offer ONE WHOLE MESSAGE on the exchange: framed and queued all at once, or not at all while
    pub fn write_whole(&mut self, bytes: &[u8], cx: &mut Context<'_>) -> Result<bool, Failure> {
        match &self.phase {
            Phase::Failed(f) => return Err(f.clone()),
            Phase::Ended => return Err(Failure::Closed),
            _ => {}
        }
        if let Err(f) = self.drive(cx) {
            self.fail(f.clone());
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
                    .push(Early::of(EXCHANGE_STREAM, bytes, true, false));
            }
        }
        if let Err(f) = self.drive(cx) {
            self.fail(f.clone());
            return Err(f);
        }
        Ok(true)
    }

    /// The process id of the program a spawned connection runs; `None` for a socket, or once the
    #[must_use]
    pub fn program_id(&self) -> Option<u32> {
        self.carried.program_id()
    }

    /// Take the connection `carried`, accepted by a listener's carrier: server TLS first when
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
            scheme: Established::scheme_of(tls.is_some()),
            claim: door
                .as_ref()
                .unwrap_or_else(|| carried.door())
                .facts()
                .claims
                .first()
                .copied()
                .map(crate::off_path::compose::owned),
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
            out: SecureVec::new(),
            ends: VecDeque::new(),
            queued: 0,
            unflushed: false,
            inbox: VecDeque::new(),
            inbox_bytes: 0,
            receive_held: 0,
            opening: None,
            head_words: HeadWords::default(),
            early: EarlyWrites::default(),
            flushed: 0,
            read_end: false,
            prepared_landed: false,
            wire_kept: false,
            carrier_lost: false,
            open_deadline: framer::now().checked_add(accept.handshake_timeout),
            framer_deadline: None,
            sleep: None,
            _slot: slot,
            upgraded: false,
            framer_error: None,
            emit_fault: None,
            pinned: None,
            presented: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            security_error: None,
            cause: None,
            opening_owed: false,
            unfed: VecDeque::new(),
            tunnel: None,
            failed_at_proxy: false,
            clear_window: None,
            fallback: None,
            alpn_offer: Vec::new(),
            offer: crate::off_path::compose::offer_of(&accept.alpn),
            agreed: 0,
            full: foldhash::HashSet::default(),
            seals: crate::seal::Seals::default(),
            opening_sensitive: SensitiveFields::default(),
        };
        if accept.tls.is_some() {
            write_protocol_names(&accept.alpn, &mut conn.alpn_offer);
        }
        if conn.tls.is_none() {
            conn.begin()?;
        }
        Ok(conn)
    }

    /// Whether the connection is past its handshake and framing.
    #[must_use]
    pub fn is_open(&self) -> bool {
        matches!(self.phase, Phase::Open) && !self.opening_owed
    }

    /// THE PROTOCOL THE CONNECTION AGREED, as its framer last stated it on an accepted connection
    #[must_use]
    pub fn agreed(&self) -> Option<&[u8]> {
        let at = usize::try_from(self.agreed).ok()?.checked_sub(1)?;
        self.offer.get(at).map(Vec::as_slice)
    }

    /// Whether an op is parked on the framing's ticket, waiting for its wake.
    fn parked(&self) -> bool {
        self.framing.as_ref().is_some_and(Framing::parked)
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
    #[must_use]
    pub fn multiplexes(&self) -> bool {
        self.dialled() && self.live() && self.established.agreed_protocol.as_deref() == Some(b"h2")
    }

    /// Every byte the socket has taken so far.
    #[must_use]
    pub fn flushed(&self) -> u64 {
        self.flushed
    }

    /// Whether the connection failed with bytes it held still deliverable by its carrier (see
    /// [`Connection::fail`]): nothing queued on it may be sent again on another connection.
    #[must_use]
    pub(crate) fn wire_kept(&self) -> bool {
        self.wire_kept
    }

    /// Whether a prepared exchange's facts have been published on this connection: sticky, set
    /// only where [`Connection::poll_prepared`] answers (or would answer) `Ready(Ok)`.
    #[must_use]
    pub(crate) fn prepared_landed(&self) -> bool {
        self.prepared_landed
    }

    /// THE ONE READINESS CONDITION a prepared exchange's facts wait for, as
    /// [`Connection::poll_prepared`] tests it after its flush: open past its handshake and framing
    /// begin (a parked begin owes its opening, which [`Connection::is_open`] already refuses), and
    /// every byte of protocol output gone to the carrier and flushed.
    fn prepared_now(&self) -> bool {
        self.is_open()
            && !self.handshaking()
            && self.out.is_empty()
            && self.ends.is_empty()
            && !self.unflushed
            && !self.carried.flushing()
    }

    /// Latch [`Connection::prepared_landed`] when [`Connection::prepared_now`] holds (no flush, no
    /// I/O): the connection is at home after its holder's own drive flushed.
    pub(crate) fn latch_prepared(&mut self) {
        if self.prepared_now() {
            self.prepared_landed = true;
        }
    }

    /// Whether the connection can carry another exchange now: dialled, framed and open, with
    #[must_use]
    pub fn reusable(&self) -> bool {
        self.dialled()
            && self.framing.is_some()
            && matches!(self.phase, Phase::Open)
            && !self.read_end
            && self.inbox.is_empty()
            && self.early.is_empty()
            && !self.parked()
            && self.unfed.is_empty()
    }

    /// Take in whatever the far end sent while the connection sat idle (its goodbye, a closed
    pub fn fresh(&mut self, cx: &mut Context<'_>) -> bool {
        loop {
            match self.drive(cx) {
                Ok(true) if self.inbox.is_empty() && self.live() => {}
                Ok(_) => return self.reusable(),
                Err(f) => {
                    self.fail(f);
                    return false;
                }
            }
        }
    }

    /// Open a NEW exchange on this dialled connection, on `stream`: `opening`, encoded with its
    pub fn open_exchange(
        &mut self,
        stream: u64,
        mut opening: Option<Opening>,
        mut head_words: HeadWords,
        cx: &mut Context<'_>,
    ) -> Result<(), Failure> {
        match &self.phase {
            Phase::Failed(f) => {
                wipe_opening(&mut opening, &mut head_words);
                return Err(f.clone());
            }
            Phase::Ended => {
                wipe_opening(&mut opening, &mut head_words);
                return Err(Failure::Closed);
            }
            _ => {}
        }
        let sensitive = match self.seal(stream, &mut opening, &mut head_words) {
            Ok(sensitive) => sensitive,
            Err(error) => {
                wipe_opening(&mut opening, &mut head_words);
                return Err(error);
            }
        };
        let body_len = self.opening_body_len(opening.as_ref());
        let Some(message) = self.encode_opening(opening, head_words)? else {
            return Ok(());
        };
        match self.phase {
            Phase::Open => {
                self.put_opening_marked(stream, &message, true, false, body_len, sensitive)?;
                self.sealed_sent(stream)?;
            }
            _ => {
                self.early.push(Early {
                    body_len,
                    sensitive,
                    ..Early::of(stream, &message, true, false)
                });
            }
        }
        if let Err(f) = self.drive(cx) {
            self.fail(f.clone());
            return Err(f);
        }
        Ok(())
    }

    /// `opening` as the entry's wire message with its head words; `None` = nothing to send.
    fn encode_opening(
        &self,
        opening: Option<Opening>,
        (method, target): HeadWords,
    ) -> Result<Option<Message>, Failure> {
        let target = SecureVec::from(target);
        let Some((fields, body)) = opening else {
            return Ok(None);
        };
        let fields = WipedValues(fields);
        if fields.0.is_empty() && body.is_empty() && method.is_empty() && target.is_empty() {
            return Ok(None);
        }
        let Some(door) = self.door.as_ref() else {
            if !fields.0.is_empty() {
                return Err(Failure::Refused(
                    "a carrier carried as itself carries no fields".into(),
                ));
            }
            return Ok(Some(Message::Body(body)));
        };
        let mut lent: smallvec::SmallVec<[(&str, &[u8]); framer::FIELDS_INLINE]> =
            smallvec::SmallVec::new();
        lent.extend(fields.0.iter().map(|(n, v)| (n.as_str(), v.as_slice())));
        let encoded =
            framer::encode_head(door.as_ref(), &method, &target, &lent, &body).map_err(refused)?;
        Ok(Some(Message::Encoded(SecureVec::from(encoded))))
    }

    /// The length of the body a DIALLED request opens with, for the framer's emit of its head
    fn opening_body_len(&self, opening: Option<&Opening>) -> Option<u64> {
        let (_, body) = opening?;
        (self.side == SIDE_DIAL && self.door.is_some()).then_some(body.len() as u64)
    }

    /// Hand `bytes` on `stream` to the wire: through the framing (`emit`); or, for a carrier carried
    fn put(&mut self, stream: u64, bytes: &[u8], end: bool, text: bool) -> Result<(), Failure> {
        self.put_opening(stream, bytes, end, text, None)
    }

    /// [`Self::put`], with the opening body's length on a dialled request's head emit.
    fn put_opening(
        &mut self,
        stream: u64,
        bytes: &[u8],
        end: bool,
        text: bool,
        body_len: Option<u64>,
    ) -> Result<(), Failure> {
        self.put_opening_marked(
            stream,
            bytes,
            end,
            text,
            body_len,
            SensitiveFields::default(),
        )
    }

    fn put_opening_marked(
        &mut self,
        stream: u64,
        bytes: &[u8],
        end: bool,
        text: bool,
        body_len: Option<u64>,
        sensitive: SensitiveFields,
    ) -> Result<(), Failure> {
        if let Some(framing) = self.framing.as_ref() {
            if framing.holds(stream) || self.early.holds(stream) {
                self.early.push(Early {
                    body_len,
                    sensitive,
                    ..Early::of(stream, bytes, end, text)
                });
                return Ok(());
            }
        }
        if let Some(framing) = self.framing.as_mut() {
            let y = match framing
                .emit_opening_sensitive(stream, bytes, end, text, body_len, &sensitive)
            {
                Ok(y) => y,
                Err(e) => {
                    let text = e.error.clone();
                    let f = failed(e);
                    self.emit_fault = Some((text, f.clone()));
                    return Err(f);
                }
            };
            // Once the framer took the emit, its wire (other streams' frames too) is the
            // session's: losing it fails the connection, so it is never lent again.
            if let Err(f) = self.absorb(y) {
                self.fail(f.clone());
                return Err(f);
            }
            return Ok(());
        }
        if self.door.is_some() {
            return Err(Failure::Closed);
        }
        if self.tls.is_some() {
            if let Err(f) = self.tls_write(bytes) {
                self.fail(f.clone());
                return Err(f);
            }
        } else {
            self.queue(bytes, end)?;
        }
        Ok(())
    }

    /// Queue `bytes` for the carrier; `end` = they end a frame of the carrier's own wire. A buffer
    /// that cannot grow fails this connection (`write buffer`), never another.
    fn queue(&mut self, bytes: &[u8], end: bool) -> Result<(), Failure> {
        if let Err(e) = self.out.extend(bytes) {
            tracing::warn!(
                dest = %self.target,
                error = %e,
                "connector write buffer allocation failed; connection closed"
            );
            return Err(Failure::Refused("write buffer".into()));
        }
        self.queued += bytes.len() as u64;
        if end {
            self.ends.push_back((self.queued, bytes.is_empty()));
        }
        Ok(())
    }
}

impl Connection {
    /// What connection security established (the agreed protocol, the name offered).
    #[must_use]
    pub fn established(&self) -> &Established {
        &self.established
    }

    /// THE MID-STREAM SECURITY UPGRADE (`UPGRADE_SECURE`): secure this dialled connection with
    pub fn upgrade_secure(
        &mut self,
        config: &Arc<rustls::ClientConfig>,
        name: &str,
        timeout: Duration,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Failure>> {
        self.upgrade_secure_over(config, name, timeout, false, cx)
    }

    /// [`Self::upgrade_secure`] for a connection whose reader above (`unread_above`) still keeps
    pub(crate) fn upgrade_secure_over(
        &mut self,
        config: &Arc<rustls::ClientConfig>,
        name: &str,
        timeout: Duration,
        unread_above: bool,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Failure>> {
        if !self.upgraded {
            if self.side != SIDE_DIAL || self.tls.is_some() {
                return Poll::Ready(Err(Failure::Refused(
                    "the stream is already secure, or is not a dialled one".into(),
                )));
            }
            if unread_above || !self.inbox.is_empty() {
                let f = Failure::Refused(UPGRADE_OVER_CLEAR_BYTES.into());
                self.inbox.clear();
                self.inbox_bytes = 0;
                self.fail(f.clone());
                return Poll::Ready(Err(f));
            }
            let mut config = (**config).clone();
            config.alpn_protocols.clear();
            self.alpn_offer.clear();
            let server = rustls::pki_types::ServerName::try_from(
                name.trim_start_matches('[').trim_end_matches(']'),
            )
            .map(|name| name.to_owned())
            .map_err(|e| {
                crate::cold::framing::refused(format_args!(
                    "the name offered is not a server name: {e}"
                ))
            });
            let client = match server
                .and_then(|n| rustls::ClientConnection::new(Arc::new(config), n).map_err(failed))
            {
                Ok(c) => c,
                Err(f) => return Poll::Ready(Err(f)),
            };
            self.tls = Some(rustls::Connection::Client(client));
            self.upgraded = true;
            let offered = Some(crate::off_path::compose::owned(name));
            self.established.offered_name = offered;
            self.established.scheme = Established::scheme_of(true);
            self.open_deadline = framer::now().checked_add(timeout);
            if !matches!(self.phase, Phase::Connecting) {
                if let Err(f) = self.tls_out() {
                    self.fail(f.clone());
                    return Poll::Ready(Err(f));
                }
            }
        }
        loop {
            match &self.phase {
                Phase::Failed(f) => return Poll::Ready(Err(f.clone())),
                Phase::Ended => return Poll::Ready(Err(Failure::Closed)),
                Phase::Open if !self.handshaking() && !self.opening_owed => {
                    return Poll::Ready(Ok(()));
                }
                _ => {}
            }
            match self.drive(cx) {
                Ok(true) => {}
                Ok(false) => return Poll::Pending,
                Err(f) => self.fail(f),
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

    /// Whether connection security is set and its handshake has completed: what
    pub(crate) fn secured(&self) -> bool {
        self.tls.as_ref().is_some_and(|t| !t.is_handshaking())
    }

    /// The far end's certificate hashed as RFC 5929 section 4.1 `tls-server-end-point` hashes it
    #[must_use]
    pub fn peer_cert_hash(&self) -> Option<String> {
        let tls = self.tls.as_ref().filter(|t| !t.is_handshaking())?;
        let leaf = tls.peer_certificates()?.first()?;
        let digest = crate::tls::client::end_point_digest(leaf.as_ref()).digest(leaf.as_ref());
        Some(hex::encode(digest))
    }

    /// Why the connection failed, once it has: the stage it failed in (the socket's open,
    #[must_use]
    pub fn cause(&self) -> Option<&ConnCause> {
        self.cause.as_ref()
    }

    /// The connection fails with `f`, in the stage it is in. Failed while its carrier could still
    /// deliver bytes it held (queued and not yet taken, owed by TLS, or a parked emit's), it keeps
    /// them ([`Connection::wire_kept`]): `close()` may still send them, so no exchange on it is ever
    /// sent again elsewhere.
    fn fail(&mut self, f: Failure) {
        if !self.carrier_lost
            && (self.queued > self.flushed
                || self.tls.as_ref().is_some_and(|t| t.wants_write())
                || self.parked())
        {
            self.wire_kept = true;
        }
        let emitted = self
            .emit_fault
            .take()
            .and_then(|(text, sent)| (sent == f).then_some(text));
        let outbound = emitted.is_some();
        // The framer's own error is let go either way; the outbound emit's, when held, wins.
        let framer_error = self.framer_error.take();
        let framer = emitted.or(framer_error);
        let stage = match (&f, &self.phase) {
            (Failure::Timeout, _) => CAUSE_DEADLINE,
            (_, Phase::Open) if framer.is_some() => CAUSE_FRAMER,
            (_, Phase::Connecting) => CAUSE_CONNECT,
            (_, Phase::Handshaking) => CAUSE_SECURITY,

            _ if self.handshaking() => CAUSE_SECURITY,
            _ => CAUSE_EXCHANGE,
        };
        let text = match &f {
            Failure::Refused(t) | Failure::Failed(t) => framer
                .or_else(|| self.security_error.take())
                .unwrap_or_else(|| t.clone()),
            Failure::Pending | Failure::Timeout | Failure::Closed => String::new(),
        };
        if !matches!(self.phase, Phase::Failed(_)) {
            self.cause = Some(ConnCause {
                stage,
                text,
                outbound: outbound && stage == CAUSE_FRAMER,
            });
            self.failed_at_proxy = self.tunnel.is_some();
        }
        self.phase = Phase::Failed(f);
    }

    /// Whether the connection failed before its proxy opened the tunnel (the proxy hop failed).
    pub(crate) fn failed_at_proxy(&self) -> bool {
        self.failed_at_proxy
    }

    /// The next frame piece: `Ready(Ok(Some))` a piece, `Ready(Ok(None))` the connection ended,
    pub fn poll_piece(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Got>, Failure>> {
        loop {
            if let Some(p) = self.inbox.pop_front() {
                self.inbox_bytes = self.inbox_bytes.saturating_sub(p.bytes.len());
                return Poll::Ready(Ok(Some(p)));
            }
            match &self.phase {
                Phase::Ended => return Poll::Ready(Ok(None)),
                Phase::Failed(f) => return Poll::Ready(Err(f.clone())),
                _ => {}
            }
            match self.drive(cx) {
                Ok(true) => {}

                Ok(false) if self.read_end && self.inbox.is_empty() => {
                    return Poll::Ready(Ok(None));
                }
                Ok(false) => return Poll::Pending,
                Err(f) => self.fail(f),
            }
        }
    }

    /// WHETHER THE DIAL HAS LANDED: the far end took the connect (through the proxy's tunnel,
    pub fn poll_landed(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Failure>> {
        loop {
            match &self.phase {
                Phase::Failed(f) => return Poll::Ready(Err(f.clone())),
                Phase::Connecting => {}
                _ if self.tunnel.as_ref().is_some_and(|t| t.asked) => {}
                _ => return Poll::Ready(Ok(())),
            }
            match self.drive(cx) {
                Ok(true) => {}
                Ok(false) => return Poll::Pending,
                Err(f) => self.fail(f),
            }
        }
    }

    /// Finish connection security and framing without opening an application exchange.
    pub(crate) fn poll_prepared(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Failure>> {
        loop {
            match &self.phase {
                Phase::Failed(f) => return Poll::Ready(Err(f.clone())),
                Phase::Ended => return Poll::Ready(Err(Failure::Closed)),
                _ if self.is_open() && !self.handshaking() && !self.begin_parked() => {
                    // feed() can finish the local TLS handshake while queueing the
                    // client's final flight. The peer cannot finish its handshake until
                    // those bytes reach the carrier, even though rustls is no longer
                    // handshaking locally. Flush protocol output before publishing facts.
                    if let Err(f) = self.flush(cx) {
                        self.fail(f.clone());
                        return Poll::Ready(Err(f));
                    }
                    return if self.prepared_now() {
                        self.prepared_landed = true;
                        Poll::Ready(Ok(()))
                    } else {
                        Poll::Pending
                    };
                }
                _ => {}
            }
            match self.drive(cx) {
                Ok(true) => {}
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
        self.out.len() + self.early.bytes
    }

    /// Offer `bytes` on the connection's exchange (`end` = the caller's message is complete, `text` =
    pub fn write(
        &mut self,
        bytes: &[u8],
        end: bool,
        text: bool,
        cx: &mut Context<'_>,
    ) -> Result<usize, Failure> {
        self.emit(EXCHANGE_STREAM, bytes, end, text, cx)
    }

    /// HOLD THIS CARRIER TO THE PLAINTEXT RULE: until connection security is set
    /// ([`Connection::upgrade_secure`]), it takes one cleartext write of at most
    /// `CLEAR_WINDOW_BYTES` (the protocol's request to negotiate security) and refuses any other.
    pub fn hold_clear_window(&mut self) {
        if self.tls.is_none() {
            self.clear_window = Some(1);
        }
    }

    /// Offer `bytes` on `stream` (`end` = the stream's message is complete, `text` = it is a text
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
            Phase::Ended if self.framing.is_none() => return Err(Failure::Closed),
            _ => {}
        }
        if self.tls.is_none() && !bytes.is_empty() {
            if let Some(left) = self.clear_window.as_mut() {
                if *left == 0 || bytes.len() > CLEAR_WINDOW_BYTES {
                    crate::egress_audit::dial_refused(&self.target, None, "plaintext-window", None);
                    return Err(Failure::Refused(CLEAR_WINDOW_REFUSED.into()));
                }
                *left -= 1;
            }
        }

        if let Err(f) = self.drive(cx) {
            self.fail(f.clone());
            return Err(f);
        }

        let tail_of = if matches!(self.phase, Phase::Connecting | Phase::Handshaking) {
            None
        } else {
            Some(stream)
        };
        if self.early.newest_empty(tail_of) {
            return Err(Failure::Pending);
        }

        if self.door.is_none() && self.ends.back().is_some_and(|(_, empty)| *empty) {
            return Err(Failure::Pending);
        }

        if self.full.contains(&stream) && !bytes.is_empty() {
            return Ok(0);
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
                self.early.push(Early::of(stream, bytes, end, text));
            }
        }
        if let Err(f) = self.drive(cx) {
            self.fail(f.clone());
            return Err(f);
        }
        Ok(take)
    }

    /// The connect was refused: dial the name's next admitted address in its place, the
    fn redial_next(&mut self) -> Option<Result<(), Failure>> {
        let f = self.fallback.as_mut()?;
        let next = f.next.pop_front()?;
        let redialled = Carried::dial(
            Arc::clone(&f.door),
            Arc::clone(&f.io),
            &Dest::Authority(crate::off_path::compose::display_text(&next)),
        );
        Some(
            redialled
                .map(|carried| self.carried = carried)
                .map_err(dial_failure),
        )
    }

    /// One pass: connect, handshake, flush, read, and keep the deadlines. `Ok(true)` = something
    fn drive(&mut self, cx: &mut Context<'_>) -> Result<bool, Failure> {
        #[cfg(test)]
        clock_reads::drove();
        let mut now = None;
        self.check_open_deadlines(&mut now)?;
        let mut moved = false;
        if self.tunnel.as_ref().is_some_and(|t| t.asked) {
            moved |= self.flush(cx)?;
            moved |= self.tunnel_read(cx)?;
        } else if matches!(self.phase, Phase::Connecting) {
            match self.carried.poll_connected(cx) {
                Poll::Ready(Ok(())) => {
                    moved = true;
                    if let Some(t) = self.tunnel.as_mut() {
                        t.asked = true;
                        t.deadline = Some(clock(&mut now) + crate::proxy::CONNECT_HANDSHAKE);
                        let request = std::mem::take(&mut t.request);
                        self.queue(&request, false)?;
                        moved |= self.flush(cx)?;
                    } else {
                        self.connected()?;
                    }
                }
                Poll::Ready(Err(e)) => match self.redial_next() {
                    Some(Ok(())) => moved = true,
                    Some(Err(f)) => return Err(f),
                    None => return Err(Failure::Refused(e)),
                },
                Poll::Pending => {}
            }
        }
        if !matches!(self.phase, Phase::Connecting) {
            moved |= self.resume(cx)?;
            moved |= self.flush(cx)?;

            if !self.begin_parked()
                && self.buffered_input().saturating_add(self.receive_held) < RECEIVE_BUFFER_BYTES
                && self.out.len() < 2 * WRITE_BUFFER_BYTES
            {
                moved |= self.read(cx)?;
            }
        }
        moved |= self.keep_deadlines(cx, &mut now)?;
        Ok(moved)
    }

    /// The socket reaches the far end: connection security's handshake starts, or the framing
    fn connected(&mut self) -> Result<(), Failure> {
        if self.tls.is_some() {
            self.phase = Phase::Handshaking;
            self.tls_out()
        } else {
            self.begin()
        }
    }

    /// Read the proxy's answer to the tunnel request: once its head is whole and 2xx the socket is
    fn tunnel_read(&mut self, cx: &mut Context<'_>) -> Result<bool, Failure> {
        let mut buf = [0_u8; 256];
        let n = match self.carried.poll_read(cx, &mut buf) {
            Poll::Pending => return Ok(false),
            Poll::Ready(Err(e)) => return Err(failed(e)),
            Poll::Ready(Ok((0, _))) => {
                return Err(Failure::Failed(
                    "proxy closed the connection during CONNECT".into(),
                ));
            }
            Poll::Ready(Ok((n, _))) => n,
        };
        let Some(t) = self.tunnel.as_mut() else {
            return Ok(false);
        };
        t.head.extend_from_slice(&buf[..n]);
        let Some(end) =
            crate::proxy::connect_answer(&t.head, &t.authority).map_err(Failure::Refused)?
        else {
            return Ok(true);
        };
        // The tunnel's head buffer leaves with the tunnel; bytes past the proxy's answer are the far
        // end's first bytes, fed from that buffer in place (no copy of the tail).
        let head = std::mem::take(&mut t.head);
        self.tunnel = None;
        self.connected()?;
        if let Some(rest) = head.get(end..).filter(|rest| !rest.is_empty()) {
            self.feed(rest, false, false)?;
        }
        Ok(true)
    }

    /// Undelivered input held here or by the current framer. Line-owned pieces are accounted
    pub(crate) fn buffered_input(&self) -> usize {
        self.framing
            .as_ref()
            .map_or(0, Framing::retained_input)
            .saturating_add(self.inbox_bytes)
    }

    pub(crate) fn set_receive_held(&mut self, bytes: usize) {
        self.receive_held = bytes;
    }

    /// Write what the carrier owes, as far as it takes it; once it took everything, its `flush`.
    fn flush(&mut self, cx: &mut Context<'_>) -> Result<bool, Failure> {
        let mut moved = false;
        loop {
            if self.carried.flushing() || (self.out.is_empty() && self.unflushed) {
                match self.carried.poll_flush(cx) {
                    Poll::Pending => return Ok(moved),
                    Poll::Ready(Ok(())) => self.unflushed = false,
                    Poll::Ready(Err(e)) => {
                        self.carrier_lost = true;
                        return Err(failed(e));
                    }
                }
            }
            if self.out.is_empty() && self.ends.is_empty() {
                return Ok(moved);
            }
            let a = self.out.as_slice();

            let (a, end) = match self.ends.front() {
                Some(&(at, _)) => {
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
                Poll::Ready(Ok(0)) if !a.is_empty() => {
                    self.carrier_lost = true;
                    return Err(Failure::Closed);
                }
                Poll::Ready(Ok(n)) => {
                    if end && n == a.len() {
                        self.ends.pop_front();
                    }
                    self.out.consume(n);
                    if self.out.is_empty() {
                        self.out.shrink_when_empty(OUT_KEEP);
                    }
                    self.flushed += n as u64;
                    self.unflushed = true;
                    moved = true;
                }
                Poll::Ready(Err(e)) => {
                    self.carrier_lost = true;
                    return Err(failed(e));
                }
                Poll::Pending => return Ok(moved),
            }
        }
    }

    /// Read what the carrier has, and hand it on.
    fn read(&mut self, cx: &mut Context<'_>) -> Result<bool, Failure> {
        if self.read_end {
            return Ok(false);
        }
        // T11-dev: the carrier (a plugin door on dev) reads into this thread's wiping scratch,
        // never a stack buffer left holding the response. `Tail::Wipe`: core trusts no plugin to
        // have written nothing past the count it reports. The guard wipes and returns the slot.
        let mut scratch = Scratch::take(&READ_SCRATCH);
        let (mut pending, mut end_of_frame) = (false, false);
        let carried = &mut self.carried;
        let got = scratch
            .read_into(READ_CHUNK, Tail::Wipe, |dst| {
                match carried.poll_read(cx, dst) {
                    Poll::Ready(Ok((n, eof))) => {
                        end_of_frame = eof;
                        Ok(n)
                    }
                    Poll::Ready(Err(e)) => Err(e),
                    Poll::Pending => {
                        pending = true;
                        Ok(0)
                    }
                }
            })
            .map_err(|_| Failure::Refused("read buffer".into()))?;
        match got {
            _ if pending => Ok(false),
            Ok(0) if !end_of_frame => {
                self.read_end = true;
                self.carrier_lost = true;
                self.feed(&[], true, false)?;
                Ok(true)
            }
            Ok(_) => {
                self.feed(scratch.as_slice(), false, end_of_frame)?;
                Ok(true)
            }
            Err(e) => {
                if self.door.is_none() && self.tls.is_none() {
                    self.framer_error = Some(crate::cold::framing::display(&e));
                }
                Err(failed(e))
            }
        }
    }

    /// Check opening bounds before advancing their stages, and again when arming their timer.
    fn check_open_deadlines(&self, now: &mut Option<Instant>) -> Result<(), Failure> {
        let opening =
            matches!(self.phase, Phase::Connecting | Phase::Handshaking) || self.handshaking();
        let open_deadline = self.open_deadline.filter(|_| opening);
        if open_deadline.is_some_and(|at| at <= clock(now)) {
            return Err(Failure::Timeout);
        }
        let tunnel_deadline = self.tunnel.as_ref().and_then(|t| t.deadline);
        if tunnel_deadline.is_some_and(|at| at <= clock(now)) {
            return Err(Failure::Timeout);
        }
        Ok(())
    }

    /// The overall open, CONNECT exchange and framer bounds share the earliest worker timer.
    fn keep_deadlines(
        &mut self,
        cx: &mut Context<'_>,
        now: &mut Option<Instant>,
    ) -> Result<bool, Failure> {
        self.check_open_deadlines(now)?;
        if !matches!(self.phase, Phase::Connecting | Phase::Handshaking) && !self.handshaking() {
            self.open_deadline = None;
        }
        let tunnel_deadline = self.tunnel.as_ref().and_then(|t| t.deadline);
        let mut moved = false;

        let framer_deadline = self.framer_deadline.filter(|_| !self.begin_parked());
        if framer_deadline.is_some_and(|at| at <= clock(now)) {
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
        let framer_deadline = self.framer_deadline.filter(|_| !self.begin_parked());
        let next = [self.open_deadline, tunnel_deadline, framer_deadline]
            .into_iter()
            .flatten()
            .min();
        match next {
            None => self.sleep = None,
            Some(at) => {
                if self.sleep.as_ref().is_none_or(|(when, _)| *when != at) {
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

    /// RE-DRIVE THE OPS PARKED on the framing's tickets (`cx`'s waker registered on each ticket):
    fn resume(&mut self, cx: &mut Context<'_>) -> Result<bool, Failure> {
        let Some(framing) = self.framing.as_mut().filter(|f| f.parked()) else {
            return Ok(false);
        };
        let y = match framing.poll_parked(cx) {
            Poll::Pending => return Ok(false),
            Poll::Ready(Ok(y)) => y,
            Poll::Ready(Err(e)) => {
                self.framer_error = Some(e.error.clone());
                return Err(failed(e));
            }
        };
        self.absorb(y)?;
        if self.begin_parked() {
            return Ok(true);
        }
        if std::mem::take(&mut self.opening_owed) {
            self.send_opening()?;
        }
        self.put_early()?;
        for stream in self.seals.streams() {
            self.sealed_sent(stream)?;
        }
        while !self.begin_parked() {
            let Some((bytes, end, end_of_frame)) = self.unfed.pop_front() else {
                break;
            };
            self.ingest(&bytes, end, end_of_frame)?;
        }
        Ok(true)
    }

    /// Hand the writes held back to the framing, in order; a write on a stream still held waits
    fn put_early(&mut self) -> Result<(), Failure> {
        for e in self.early.take() {
            self.put_opening_marked(e.stream, &e.bytes, e.end, e.text, e.body_len, e.sensitive)?;
            self.sealed_sent(e.stream)?;
        }
        Ok(())
    }

    /// Whether the framing's `begin` is parked on its ticket.
    fn begin_parked(&self) -> bool {
        self.framing.as_ref().is_some_and(Framing::begin_parked)
    }

    /// Begin the framing over what the open established, then send the first message and any
    fn begin(&mut self) -> Result<(), Failure> {
        let mut opening = self.opening.take();
        let mut words = std::mem::take(&mut self.head_words);
        let sealed = self.seal(EXCHANGE_STREAM, &mut opening, &mut words);
        self.head_words = words;
        self.opening = opening;
        self.opening_sensitive = sealed?;

        let opening: &[(String, Vec<u8>)] = match &self.opening {
            Some((fields, _)) if self.side == SIDE_DIAL => fields,
            _ => &[],
        };

        if let Some(door) = self.door.as_ref() {
            let (framing, y) = Framing::begin_ticketed(
                Arc::clone(door),
                self.side,
                &self.target,
                &self.established,
                opening,
            )
            .map_err(refused)?;
            let parked = framing.parked();
            self.framing = Some(framing);
            self.phase = Phase::Open;
            self.absorb(y)?;
            if parked {
                self.opening_owed = true;
                return Ok(());
            }
        } else {
            self.phase = Phase::Open;
        }
        self.send_opening()?;
        self.put_early()
    }

    /// Send the dial's first message, if one is held, on [`EXCHANGE_STREAM`].
    fn send_opening(&mut self) -> Result<(), Failure> {
        let opening = self.opening.take();
        let words = std::mem::take(&mut self.head_words);
        let body_len = self.opening_body_len(opening.as_ref());
        let sensitive = std::mem::take(&mut self.opening_sensitive);

        if let Some(message) = self
            .encode_opening(opening, words)?
            .filter(|m| !m.is_empty())
        {
            let held = self.early.take();
            let sent = self.put_opening_marked(
                EXCHANGE_STREAM,
                &message,
                true,
                false,
                body_len,
                sensitive,
            );
            let sealed = sent.and_then(|()| self.sealed_sent(EXCHANGE_STREAM));
            self.early.extend(held);
            sealed?;
        } else {
            self.sealed_sent(EXCHANGE_STREAM)?;
        }
        Ok(())
    }

    /// SEAL `opening` (TSEAL, [`crate::seal`]): its sealed-fields field taken out; over a framer
    fn seal(
        &mut self,
        stream: u64,
        opening: &mut Option<Opening>,
        words: &mut HeadWords,
    ) -> Result<SensitiveFields, Failure> {
        let sealing = self.door.as_ref().is_some_and(|d| d.seals_values());
        let secured = self.tls.is_some();
        let mut names = opening.as_mut().map_or_else(Vec::new, |(fields, _)| {
            crate::seal::take_sealed_names(fields)
        });
        let query = self
            .seals
            .seal_queries(stream, opening, &mut words.1, sealing, secured)
            .map_err(refused)?;
        if query {
            if self.door.is_none() {
                return Err(Failure::Refused(
                    "a carrier carried as itself carries no query target".into(),
                ));
            }
            names.push(crate::off_path::compose::owned(REQUEST_TARGET_FIELD));
        }
        let sensitive =
            SensitiveFields::new(names.clone()).map_err(|error| Failure::Refused(error.into()))?;
        self.seals
            .seal_names(stream, opening, &names, sealing, secured)
            .map_err(refused)?;
        Ok(sensitive)
    }

    /// AN OPENING'S SEALED VALUES ARE ALL SPLICED once it was emitted on `stream`: a filler the
    fn sealed_sent(&mut self, stream: u64) -> Result<(), Failure> {
        if !self.seals.pending_on(stream)
            || self.early.holds(stream)
            || self
                .framing
                .as_ref()
                .is_some_and(|framing| framing.holds(stream))
        {
            return Ok(());
        }
        self.seals.clear_on(stream);
        let f = refused(crate::seal::SEAL_BROKEN);
        self.fail(f.clone());
        Err(f)
    }

    /// THE TRANSPORT PIN, held on a dialled connection whose handshake just completed: the far end's
    fn hold_to_anchors(&mut self) -> Result<(), Failure> {
        let Some(rustls::Connection::Client(c)) = self.tls.as_ref() else {
            return Ok(());
        };
        self.established.peer_key_pin = c
            .peer_certificates()
            .and_then(|chain| chain.first())
            .and_then(|leaf| crate::tls::client::peer_key_pin(leaf.as_ref()));
        self.established.client_identity = self.presented.load(std::sync::atomic::Ordering::SeqCst);

        match self.pinned.as_ref().and_then(|a| a.key_pin.as_deref()) {
            Some(pin) if self.established.peer_key_pin.as_deref() != Some(pin) => {
                crate::egress_audit::tls_failed(&self.target, PIN_REFUSED);
                Err(Failure::Refused(PIN_REFUSED.into()))
            }
            _ => Ok(()),
        }
    }

    /// What the carrier read (`end` = its clean end; `end_of_frame` = the bytes complete a frame of
    fn feed(&mut self, bytes: &[u8], end: bool, end_of_frame: bool) -> Result<(), Failure> {
        let Some(tls) = self.tls.as_mut() else {
            return self.ingest(bytes, end, end_of_frame);
        };
        let mut rest = bytes;
        // The plaintext rustls holds after the last `process_new_packets` (T6: an exact read).
        let mut plaintext = 0_usize;
        while !rest.is_empty() {
            if tls.read_tls(&mut rest).map_err(failed)? == 0 {
                break;
            }
            match tls.process_new_packets() {
                Ok(state) => plaintext = state.plaintext_bytes_to_read(),
                Err(e) => {
                    // A dialled refusal is explained; an accepted one (an mTLS client under the
                    // listener's `client_ca`, no pin) keeps the stack's words exactly.
                    let (text, refusal) = crate::cold::framing::tls_failure(
                        &e,
                        matches!(tls, rustls::Connection::Client(_)),
                    );
                    if self.side == SIDE_DIAL && crate::egress_audit::is_verification(&e) {
                        crate::egress_audit::tls_failed(&self.target, &text);
                    }
                    self.security_error = Some(text);
                    // Flush the fatal alert that rustls queued (RFC 8446 §6.2) so the
                    // peer sees it before the TCP close.
                    let _ = self.tls_out();
                    return Err(refusal);
                }
            }
        }
        if end {
            tls.read_tls(&mut io::empty()).map_err(failed)?;
        }
        if matches!(self.phase, Phase::Handshaking) {
            if end {
                self.security_error = Some(HANDSHAKE_EOF.into());
                return Err(Failure::Refused(
                    "tls: the far end closed the handshake".into(),
                ));
            }
            if !self.tls.as_ref().is_some_and(|t| t.is_handshaking()) {
                let agreed = self
                    .tls
                    .as_ref()
                    .and_then(crate::off_path::compose::agreed_alpn);
                self.established.agreed_protocol = agreed;
                agreed_was_offered(
                    &self.alpn_offer,
                    self.established.agreed_protocol.as_deref(),
                )?;
                if let Some(rustls::Connection::Server(s)) = self.tls.as_ref() {
                    let asked = s.server_name().map(crate::off_path::compose::owned);
                    self.established.offered_name = asked;
                }
                self.hold_to_anchors()?;
                self.begin()?;
            }
        }
        // T6: the plaintext lands in this thread's TLS_PLAIN scratch (never the carrier's), read
        // exactly: no doubling `Vec`, no 16 KiB stack buffer, and the guard wipes it on every exit.
        let mut plain = Scratch::take(&TLS_PLAIN);
        let mut closed = false;
        #[cfg(test)]
        let plaintext = plaintext + tls_probe::inflation(plaintext);
        if let Some(tls) = self.tls.as_mut() {
            if plaintext > 0 {
                match plain
                    .read_into(plaintext, Tail::Trusted, |dst| tls.reader().read(dst))
                    .map_err(|_| Failure::Refused("tls read buffer".into()))?
                {
                    Ok(k) if k == plaintext => {}
                    _ => return Err(Failure::Refused("tls: plaintext count mismatch".into())),
                }
            }
            // One more read into a NON-EMPTY buffer once the plaintext is drained: rustls'
            // `Reader::read` answers without checking the close state while plaintext remains or
            // the buffer is empty; only this read reaches its close_notify / unclean-EOF check.
            let mut probe = [0_u8; 64];
            let r = loop {
                match tls.reader().read(&mut probe) {
                    // close_notify received.
                    Ok(0) => {
                        closed = true;
                        break Ok(());
                    }
                    Ok(k) => {
                        if plain.extend(&probe[..k]).is_err() {
                            break Err(Failure::Refused("tls read buffer".into()));
                        }
                    }
                    // A ticket-only record (no plaintext) lands here.
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break Ok(()),
                    // UnexpectedEof: the truncation guard.
                    Err(e) => break Err(failed(e)),
                }
            };
            probe.fill(0);
            r?;
        }
        self.tls_out()?;
        if matches!(self.phase, Phase::Open) && (!plain.is_empty() || closed) {
            self.ingest(plain.as_slice(), closed, true)?;
        }
        Ok(())
    }

    fn ingest(&mut self, bytes: &[u8], end: bool, end_of_frame: bool) -> Result<(), Failure> {
        #[cfg(test)]
        tls_probe::ingested(end);
        if self.begin_parked() {
            self.unfed.push_back((bytes.to_vec(), end, end_of_frame));
            return Ok(());
        }
        let Some(framing) = self.framing.as_mut() else {
            if self.door.is_some() || !matches!(self.phase, Phase::Open) {
                return if end { Err(Failure::Closed) } else { Ok(()) };
            }

            if !bytes.is_empty() || end_of_frame {
                self.inbox_bytes = self.inbox_bytes.saturating_add(bytes.len());
                self.inbox.push_back(Got {
                    stream: 0,
                    bytes: bytes.to_vec(),
                    end_of_frame,
                    status_code: None,
                    status_namespace: None,
                    handoff: false,
                    status_class: 0,
                    fault: FAULT_NONE,
                    retry_after_secs: None,
                    declared_len: None,
                    fields: false,
                    text: false,
                    reason: None,
                    failed: false,
                    end: false,
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
                self.framer_error = Some(e.error.clone());
                return Err(failed(e));
            }
        };
        self.absorb(y)
    }

    /// Take what the framer answered: its wire bytes to the socket (through TLS), its pieces to
    fn absorb(&mut self, mut y: Yielded) -> Result<(), Failure> {
        let mut wire = SecureVec::from(std::mem::take(&mut y.wire));
        if !wire.is_empty() {
            let spliced = self.tls.is_some() && self.seals.pending();
            if spliced {
                self.seals.splice(&mut wire).map_err(refused)?;
            }
            if self.tls.is_some() {
                let written = self.tls_write(&wire);
                wire.clear();
                written?;
            } else {
                self.queue(&wire, false)?;
            }
            wire.clear();
        }
        if y.agreed != 0 {
            busbar_contract::abi::transport::check::check_agreed_position(
                y.agreed,
                self.offer.len() as u64,
            )
            .map_err(|f| {
                crate::cold::framing::failed(format_args!(
                    "the framer's agreed protocol breaks {:?} at {}",
                    f.rule, f.field
                ))
            })?;
            self.agreed = y.agreed;
        }

        for flow in &y.flow {
            match flow {
                crate::framer::StreamFlow::Full(stream) => {
                    self.full.insert(*stream);
                }
                crate::framer::StreamFlow::Writable(stream) => {
                    self.full.remove(stream);
                }
            }
        }
        for g in y.pieces.iter().filter(|g| g.ends_stream() || g.failed) {
            self.full.remove(&g.stream);
            if g.failed {
                self.seals.clear_on(g.stream);
                self.early.drop_stream(g.stream);
            }
        }
        for g in std::mem::take(&mut y.pieces) {
            self.inbox_bytes = self.inbox_bytes.saturating_add(g.bytes.len());
            self.inbox.push_back(g);
        }
        self.framer_deadline = y.deadline_ns.map(framer::instant_of);
        if y.ended {
            self.phase = Phase::Ended;
        }
        Ok(())
    }

    /// Seal `bytes` whole into the socket's queue. The TLS output is funded (finite prepaid
    /// records and ciphertext, adopted TLS-OUTPUT-STORAGE-392-r2), so TLS takes a prefix and stops;
    /// each prefix's records move into `out` before the rest is offered. TLS taking nothing with
    /// nothing of its own left to move is a fault of the connection, never a spin.
    fn tls_write(&mut self, mut bytes: &[u8]) -> Result<(), Failure> {
        while !bytes.is_empty() {
            let Some(tls) = self.tls.as_mut() else {
                return Err(Failure::Closed);
            };
            let taken = tls.writer().write(bytes).map_err(failed)?;
            let owed = tls.wants_write();
            if taken == 0 && !owed {
                return Err(failed(io::Error::from(io::ErrorKind::WriteZero)));
            }
            self.tls_out()?;
            bytes = bytes.get(taken..).unwrap_or_default();
        }
        Ok(())
    }

    /// Move whatever TLS owes the far side into the socket's queue, straight into `out` (T6: no
    /// temporary `Vec`, one copy). It marks no frame end.
    fn tls_out(&mut self) -> Result<(), Failure> {
        if let Some(tls) = self.tls.as_mut() {
            let mut sink = OutSink {
                out: &mut self.out,
                queued: &mut self.queued,
            };
            while tls.wants_write() {
                match tls.write_tls(&mut sink) {
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::OutOfMemory => {
                        tracing::warn!(
                            dest = %self.target,
                            "connector write buffer allocation failed; connection closed"
                        );
                        return Err(Failure::Refused("write buffer".into()));
                    }
                    Err(e) => return Err(failed(e)),
                }
            }
        }
        Ok(())
    }

    /// Close: the framing finishes, TLS says goodbye, and what that owes is written as far as the
    pub fn close(mut self) {
        let framed = self.framing.is_some()
            || (self.door.is_none()
                && !matches!(self.phase, Phase::Connecting | Phase::Handshaking));
        if let Some(framing) = self.framing.take() {
            let y = framing.finish(CLOSE_NORMAL);
            let _ = self.absorb(y);
        }

        if let Some(tls) = self.tls.as_mut().filter(|_| framed) {
            tls.send_close_notify();
            let _ = self.tls_out();
        }
        let waker = std::task::Waker::noop();
        let _ = self.flush(&mut Context::from_waker(waker));

        self.carried.close();
    }
}

#[cfg(test)]
#[path = "tests/compose_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/compose_out_tests.rs"]
mod out_tests;

#[cfg(test)]
#[path = "tests/compose_read_tests.rs"]
mod read_tests;

#[cfg(test)]
#[path = "tests/compose_tls_tests.rs"]
mod tls_tests;

#[cfg(test)]
#[path = "tests/compose_tls_accept_tests.rs"]
mod tls_accept_tests;
