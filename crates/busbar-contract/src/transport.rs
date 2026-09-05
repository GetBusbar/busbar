//! The transport kind: how bytes move.
//!
//! A transport cannot name a plane and cannot name a unit. It yields and writes frames, inbound
//! and outbound, and it knows no protocol and no principal. Transports are in-tree only and never
//! dynamically loaded: they are inside the trusted computing base, and the controls on them are
//! review, the source denylist, and the frame-honesty tests that turn red for a transport whose
//! reported byte counts inflate or deflate against what actually moved.

use crate::bounded::ArenaBytes;
use crate::dest::{TransportKeyHandle, VerifiedDestination};
use crate::ids::StreamId;
use crate::plugin::Plugin;
use crate::unit::{ConfigView, Refusal};
use crate::wire::{
    ArrivalRecord, CloseReason, Conn, Frame, Handoff, HandshakeTrigger, Listener, StatusAt,
    TransportError,
};
use futures::Stream;
use std::future::Future;
use std::pin::Pin;

/// The one boxed future per call.
///
/// The allocation gate excludes exactly this: an asynchronous trait method has to box its future,
/// and one box per transport call is the price of having the transport axis be a trait at all.
pub type Fut<'a, T> = Pin<Box<dyn Future<Output = Result<T, TransportError>> + Send + 'a>>;

/// The frame pump's own type: a stream of framed bytes tagged with the stream they arrived on.
pub type FrameStream =
    Pin<Box<dyn Stream<Item = Result<(StreamId, Frame), TransportError>> + Send>>;

/// Everything a transport declares about itself.
pub trait TransportMeta {
    /// The transport's registry key.
    const KEY: &'static str;
    /// The selector forms this transport can evaluate on arriving bytes.
    const SELECTOR_FORMS: &'static [crate::grammar::SelectorForm];
    /// The selector forms this transport can evaluate when dialling out.
    const EGRESS_SELECTOR_FORMS: &'static [crate::grammar::SelectorForm];
    /// The transports this one can be layered over.
    const COMPOSES_OVER: &'static [&'static str];
    /// The signalling-to-session binding this transport declares, where it has one.
    const HANDOFF: Option<Handoff>;
    /// How this transport delimits what arrives.
    ///
    /// The kernel reads it to decide what a decode failure means: a stream that has lost sync
    /// closes, a datagram that could not be read is discarded and the session stands.
    const FRAMING: crate::wire::Framing;
    /// Whether this transport carries sessions.
    const SESSION: bool;
    /// Whether a session on this transport caches its principal.
    const SESSION_BOUND: bool;
    /// What opens a session's first unit.
    const UNIT0_TRIGGER: Option<crate::wire::Unit0Trigger>;
    /// The transports this one can upgrade in-band to.
    const UPGRADES_TO: &'static [&'static str];
    /// What tells this transport a frame opens a challenge-response exchange.
    const HANDSHAKE_TRIGGER: Option<HandshakeTrigger>;
    /// The transport fact keys this transport writes.
    const TRANSPORT_FACTS: &'static [&'static str];
    /// Whether this transport reads inside the payload and can report its own unit counts.
    const DECODES_PAYLOAD: bool;
    /// Which frame carries this transport's status class, where it carries one.
    ///
    /// A transport with none contributes no status leg to the fee decision, and the plane's own
    /// finish class becomes the sole source. A composed transport inherits the lower layer's leg.
    const STATUS_CLASS: Option<StatusAt>;
}

/// The transport's own configuration block, as a read-only view.
pub trait TransportConfigView: ConfigView {
    /// The address this transport should bind to.
    fn bind(&self) -> Option<&str>;
}

/// How bytes move.
///
/// Every call is asynchronous except closing, which must be able to run on a drop path.
pub trait Transport: Plugin + Send + Sync + 'static {
    /// What the bottom layer knows about a connection, before any plane is chosen.
    fn arrival(&self, conn: &Conn) -> ArrivalRecord;

    /// Open a listening socket.
    fn listen<'a>(
        &'a self,
        cfg: &'a dyn TransportConfigView,
        keys: &'a TransportKeyHandle,
    ) -> Fut<'a, Listener>;

    /// Take the next connection off a listener.
    fn accept<'a>(&'a self, l: &'a Listener) -> Fut<'a, Conn>;

    /// Dial a verified destination.
    fn dial<'a>(
        &'a self,
        dest: &'a VerifiedDestination,
        keys: &'a TransportKeyHandle,
    ) -> Fut<'a, Conn>;

    /// The frame pump for one connection.
    ///
    /// This takes one clone of the connection handle; writing, closing and upgrading take another.
    fn frames(&self, conn: Conn) -> FrameStream;

    /// Queue bytes for one stream, returning how many were queued.
    ///
    /// The bytes are copied into a per-connection slab, because the arena they came from is reset
    /// as soon as the frame is queued.
    fn write<'a>(
        &'a self,
        conn: &'a Conn,
        stream: StreamId,
        bytes: ArenaBytes<'a>,
    ) -> Fut<'a, usize>;

    /// Adopt a connection a lower layer is handing up, becoming the new top of the stack.
    ///
    /// The upgrade belongs to the TARGET, not the source. The connection that comes out belongs to
    /// this transport's registry, and only this transport can put it there — which is why the
    /// source could never express the upgrade as a method of its own: it would have had to return a
    /// handle it has no way to build. Here the target asks the source for its stream through
    /// [`Transport::detach`], and what it gets back is a stream the source has already given up.
    ///
    /// A source this transport does not compose over is refused with
    /// [`TransportError::HandoffMismatch`], and so is a stream that is not the shape this layer can
    /// adopt: an upgrade neither leg declared is not one the session may continue on.
    fn adopt<'a>(
        &'a self,
        from: &'a dyn Transport,
        conn: Conn,
        keys: &'a TransportKeyHandle,
    ) -> Fut<'a, Conn>;

    /// Give up the byte stream under a connection, for the layer adopting it.
    ///
    /// Removes the connection from this transport's own registry, so it is never read from or
    /// written to here again. `None` when the connection is unknown, when a reader still holds it
    /// (an upgrade never races an in-flight read, by the at-most-one-upgrade-in-flight rule; a
    /// caller that violates that ordering sees `None` rather than a torn stream), or when this
    /// transport has no raw stream to give — the default, because most layers are the bottom one or
    /// hand nothing up.
    fn detach(&self, conn: &Conn) -> Option<crate::wire::RawStream> {
        let _ = conn;
        None
    }

    /// Close a connection.
    fn close(&self, conn: Conn, reason: CloseReason);

    /// Write a refusal for bytes that never reached a plane.
    ///
    /// This is the pre-decode path: no plane is known yet, so the kernel renders the refusal
    /// through the transport's own generic envelope rather than through a dialect.
    ///
    /// `stream` names how much of the connection the refusal is about. On a transport whose first
    /// unit opens per stream, a refusal is one stream's — the other streams on that connection
    /// belong to other units, which have done nothing wrong and must go on to complete. `None` is
    /// the whole connection, which is the only honest reading on a transport that carries one.
    fn unit0_refusal<'a>(
        &'a self,
        conn: Conn,
        stream: Option<StreamId>,
        refusal: &'a Refusal,
        bytes: ArenaBytes<'a>,
    ) -> Fut<'a, ()>;
}
