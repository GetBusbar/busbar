//! Frames, connections and the closed codes that describe what happened to them.
//!
//! Everything here belongs to the transport axis. A transport cannot name a plane and cannot name
//! a unit: it yields and writes frames, and it knows no protocol and no principal. Nothing in this
//! module carries meaning — meaning is the plane's answer, one module over.

use crate::bounded::{ArenaBytes, BoundedVec, SlabBytes, MAX_KEYS};
use crate::ids::StreamId;
use core::fmt;
use std::sync::Arc;

/// Which way bytes are moving.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub enum Direction {
    /// From the client toward the node.
    Inbound,
    /// From the node toward the client or an upstream.
    Outbound,
}

/// The transport's own reading of a frame's outcome class.
///
/// This is the kernel-derived leg of the fee decision. It is per-frame meta, never a session-level
/// fact, so a composed layer cannot overwrite a lower layer's reading.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub enum StatusClass {
    /// The upstream reported success.
    Success,
    /// The upstream blamed the request.
    ClientError,
    /// The upstream blamed itself.
    ServerError,
    /// The upstream reported something outside the three classes above.
    Other,
}

/// Which frame carries a transport's status class.
///
/// A transport that reports its status on the first response frame decides the fee at that frame.
/// A transport that reports it in a trailer decides at the terminal frame, and a stream that dies
/// before its trailer therefore posts the lower evidence. A transport with neither contributes no
/// status leg at all, and the plane's own finish class becomes the sole source.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub enum StatusAt {
    /// On the first response frame.
    FirstFrame,
    /// On the terminal frame.
    Terminal,
}

/// How a transport delimits what arrives.
///
/// Load-bearing, not descriptive. A stream that cannot decode a frame is out of step and every
/// later byte on it is suspect, so the session closes; a datagram that cannot be decoded is one
/// datagram, and the next one is unaffected — so it is discarded and the session stands. Reading a
/// decode failure without knowing which of the two it happened on turns a forged packet into a
/// dropped session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub enum Framing {
    /// Bytes in order, with no delimiters of their own: losing sync loses the connection.
    Stream,
    /// Self-delimiting messages, each independent of the last.
    Datagram,
}

/// A frame's transport-level meta.
///
/// Byte counts are always present. The transport-unit count is present only where the transport
/// declares that it decodes the payload, which is how a media transport reports units the byte
/// count cannot express.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct FrameMeta {
    /// How many bytes this frame carried on the wire.
    pub bytes: u64,
    /// The transport's own unit count, where it decodes the payload.
    pub transport_units: Option<u64>,
    /// The transport's status reading, where it carries one.
    pub status: Option<StatusClass>,
}

/// Transport bytes with a direction, a stream and meta. It has no meaning.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    /// Which way the bytes are moving.
    pub direction: Direction,
    /// Which stream of the connection they arrived on.
    pub stream: StreamId,
    /// The bytes, owned by the connection slab.
    pub bytes: SlabBytes,
    /// The transport's own reading of the frame.
    pub meta: FrameMeta,
}

/// A plane's bounded read cursor over the frames it has been handed.
///
/// A plane reads forward and never rewinds past what it has consumed. The cursor is what bounds a
/// plane's appetite: it never exposes more than the per-connection ceiling, so a plane cannot ask
/// the kernel to buffer an unbounded prefix on its behalf.
#[derive(Debug)]
pub struct FrameCursor<'u> {
    frames: &'u [Frame],
    position: usize,
    scanned: usize,
}

impl<'u> FrameCursor<'u> {
    /// A cursor over the frames a connection has produced so far.
    #[must_use]
    pub fn new(frames: &'u [Frame]) -> Self {
        Self {
            frames,
            position: 0,
            scanned: 0,
        }
    }

    /// The next unconsumed frame, without consuming it.
    #[must_use]
    pub fn peek(&self) -> Option<&'u Frame> {
        self.frames.get(self.position)
    }

    /// Consume and return the next frame.
    pub fn next_frame(&mut self) -> Option<&'u Frame> {
        let frame = self.frames.get(self.position)?;
        self.position += 1;
        self.scanned = self.scanned.saturating_add(frame.bytes.len());
        Some(frame)
    }

    /// How many frames remain unconsumed.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.frames.len().saturating_sub(self.position)
    }

    /// How many bytes the plane has consumed through this cursor.
    #[must_use]
    pub fn scanned_bytes(&self) -> usize {
        self.scanned
    }
}

/// Why a frame was dropped without changing any state.
///
/// A discard is not a refusal: it costs nothing, posts nothing, ends no unit and closes no session.
/// It is counted into the arrival aggregate so a flood is visible without being individually
/// journaled.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub enum DiscardCode {
    /// The bytes did not decode.
    Malformed,
    /// The frame correlated to nothing the node is holding.
    UnknownCorrelation,
    /// The source could not be the one it claims to be.
    ForgedSource,
    /// The frame repeats one already seen.
    Duplicate,
    /// The frame arrived outside the window it would have been valid in.
    OutOfWindow,
    /// The frame is of a shape this plane does not carry.
    Unsupported,
}

/// Why a connection is being closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub enum CloseReason {
    /// An orderly close.
    Normal,
    /// The far side closed first.
    PeerClosed,
    /// The node is draining.
    Drain,
    /// Codec state was poisoned by a panic.
    Poisoned,
    /// The principal's authority was withdrawn.
    Revoked,
    /// A deadline expired.
    Timeout,
    /// The transport itself failed.
    TransportFailed,
    /// A money reason closed the session.
    CapacityExhausted,
}

/// The closed set of transport failures.
///
/// Each maps one-to-one onto a unit end, so a transport never invents an outcome the ledger has no
/// row for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub enum TransportError {
    /// The far side refused the connection.
    Refused,
    /// A deadline expired.
    Timeout,
    /// The connection was reset mid-stream.
    Reset,
    /// The connection was closed.
    Closed,
    /// The secure handshake failed.
    HandshakeFailed,
    /// Key material could not be resolved.
    KeyUnavailable,
    /// The destination address was not admissible.
    AddressRefused,
    /// The far side stopped reading and the buffer is full.
    Backpressure,
    /// The bytes violated the transport's own framing.
    Framing,
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for TransportError {}

/// A plane could not read the bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub enum Decode {
    /// The bytes are not this dialect's shape.
    Malformed,
    /// The shape is understood but the operation is not one this plane declares.
    UnsupportedOperation,
    /// A declared fact key was absent where the dialect requires it.
    MissingDeclaredFact,
    /// The frame is larger than the plane's own framing allows.
    Oversize,
}

impl fmt::Display for Decode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Decode {}

/// A plane could not write the bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub enum Encode {
    /// The unit cannot be expressed in this dialect.
    Unrepresentable,
    /// The arena had no room.
    ArenaExhausted,
    /// A minted secret's placeholder did not appear exactly once at its declared location.
    SecretPlaceholder,
    /// Codec state for this connection is poisoned.
    Poisoned,
}

impl fmt::Display for Encode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Encode {}

/// What a presented client certificate says about its holder.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct CertFacts {
    /// The subject distinguished name.
    pub subject: String,
    /// The issuer distinguished name.
    pub issuer: String,
    /// The certificate's fingerprint.
    pub fingerprint: String,
}

/// What the bottom transport layer knows about an arrival, before any plane is chosen.
///
/// Locations resolve against this record, and they re-resolve after an upgrade, because an upgrade
/// replaces the layer the record describes.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct ArrivalRecord {
    /// The peer's source address as the bottom layer saw it.
    pub source: String,
    /// The local port the bytes arrived on.
    pub port: u16,
    /// The protocol named during the handshake, where one was.
    pub alpn: Option<String>,
    /// The name offered during the handshake, where one was.
    pub sni: Option<String>,
    /// The presented client certificate, where one was.
    pub peer_cert: Option<CertFacts>,
    /// The composed transport stack, bottom layer first.
    pub transport_chain: Vec<&'static str>,
}

/// One field of an outbound request's transport envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnvelopeField<'u> {
    /// The field's name.
    pub name: &'u str,
    /// The field's bytes.
    pub value: ArenaBytes<'u>,
}

/// The transport-level shape of an outbound request.
///
/// The envelope must still equal the verified destination after the egress-auth step has decorated
/// it; the lane cross-check re-runs on the decorated bytes for exactly that reason.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TransportEnvelope<'u> {
    /// The envelope's fields.
    pub fields: BoundedVec<EnvelopeField<'u>, MAX_KEYS>,
}

/// What opens a session's first unit on a session transport.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub enum Unit0Trigger {
    /// The first bytes on the connection.
    FirstBytes,
    /// The first delimited line.
    FirstLine,
    /// The first framed message.
    FirstMessage,
    /// The first datagram.
    FirstDatagram,
    /// The in-band upgrade itself.
    Upgrade,
    /// The transport's own handshake.
    Handshake,
}

/// What tells a transport that a frame belongs to a challenge-response exchange.
///
/// A transport without one leaves handshake units to the plane, which opens them itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub struct HandshakeTrigger {
    /// The transport's own name for the frame kind that opens the exchange.
    pub frame_kind: &'static str,
    /// The most rounds the exchange may take.
    pub max_rounds: u8,
}

/// A declared binding from a signalling exchange to the session it hands off to.
///
/// The handoff is what stops a media session being adopted by whoever dials it: the binding names
/// the transport fact both legs must agree on, and a mismatch is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub struct Handoff {
    /// The transport the signalling ran over.
    pub from: &'static str,
    /// The transport the session continues on.
    pub to: &'static str,
    /// The transport fact key both legs must agree on.
    pub binding_fact: &'static str,
}

/// A listening socket a transport opened.
///
/// The kernel holds it; a plane never sees one. The handle is opaque because what is behind it is
/// the transport's business and nothing else's.
#[derive(Clone)]
pub struct Listener(Arc<dyn ListenerHandle>);

impl Listener {
    /// Wrap a transport's own listener.
    #[must_use]
    pub fn new(handle: Arc<dyn ListenerHandle>) -> Self {
        Self(handle)
    }

    /// The local address the listener is bound to.
    #[must_use]
    pub fn local_addr(&self) -> String {
        self.0.local_addr()
    }
}

impl fmt::Debug for Listener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Listener")
            .field("local_addr", &self.0.local_addr())
            .finish()
    }
}

/// What a transport puts behind a [`Listener`].
pub trait ListenerHandle: Send + Sync {
    /// The local address the listener is bound to.
    fn local_addr(&self) -> String;
}

/// A connection a transport accepted or dialled.
///
/// The type index calls this a cloneable, reference-counted handle: the frame pump takes one
/// clone, and writing, closing and upgrading take another. Cloning the handle does not duplicate
/// the connection.
#[derive(Clone)]
pub struct Conn(Arc<dyn ConnHandle>);

impl Conn {
    /// Wrap a transport's own connection.
    #[must_use]
    pub fn new(handle: Arc<dyn ConnHandle>) -> Self {
        Self(handle)
    }

    /// The connection's node-local identity.
    #[must_use]
    pub fn id(&self) -> u64 {
        self.0.id()
    }

    /// The peer's source address.
    #[must_use]
    pub fn peer(&self) -> String {
        self.0.peer()
    }
}

impl fmt::Debug for Conn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Conn").field("id", &self.0.id()).finish()
    }
}

/// What a transport puts behind a [`Conn`].
pub trait ConnHandle: Send + Sync {
    /// The connection's node-local identity.
    fn id(&self) -> u64;

    /// The peer's source address.
    fn peer(&self) -> String;
}
