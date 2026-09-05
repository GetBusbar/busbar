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
use core::fmt;
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

/// The transport kind's ABI generation.
///
/// Transports are in-tree and never dynamically loaded, so there is no loader window to police —
/// but the ABI-surface scan needs something to compare against, and a constant every transport
/// names is the difference between one generation and each crate having invented its own. It sits
/// beside the store's for the same reason: a kind's ABI is the kind's, not a plugin's.
pub const TRANSPORT_ABI: crate::plugin::AbiVersion = crate::plugin::AbiVersion(1);

/// The transport fact keys the kernel reserves, spelled once.
///
/// Transport facts are open vocabulary, which is right for a transport's own facts. These six are
/// not a transport's own: they are the structural values the arrival grammar already resolves
/// against, and a plane cannot see a connection, so the request target reaches it as one of these
/// or not at all. With nothing pinning the spelling, three planes each guessed `"path"` and said so
/// in a comment, and the boot check that would have caught a fourth guessing something else had
/// nothing to compare.
///
/// A transport that publishes one of these names the constant. A transport that publishes something
/// of its own names it whatever it likes, and none of this applies.
pub mod facts {
    /// The request target's path.
    pub const PATH: &str = "path";
    /// The request method, where the transport has one.
    pub const METHOD: &str = "method";
    /// The authority the request named.
    pub const AUTHORITY: &str = "authority";
    /// The protocol negotiated during the handshake.
    pub const ALPN: &str = "alpn";
    /// The server name offered during the handshake.
    pub const SNI: &str = "sni";
    /// The peer's source address as the bottom layer saw it.
    pub const PEER: &str = "peer";

    /// Every reserved key, for the registration check and the boot cell that walks them.
    pub const RESERVED: &[&str] = &[PATH, METHOD, AUTHORITY, ALPN, SNI, PEER];

    /// Whether a key is one the kernel reserves.
    #[must_use]
    pub fn is_reserved(key: &str) -> bool {
        RESERVED.contains(&key)
    }

    /// The first reserved key a transport publishes without having declared it.
    ///
    /// Run at registration, over the transport's own `TRANSPORT_FACTS` and the keys it actually
    /// writes. A reserved key published but not declared is a value a plane reads and no boot check
    /// knows about, which is the failure this module exists to make impossible.
    #[must_use]
    pub fn undeclared<'a>(declared: &[&'a str], published: &[&'a str]) -> Option<&'a str> {
        published
            .iter()
            .copied()
            .find(|key| is_reserved(key) && !declared.contains(key))
    }
}

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

/// One registered transport, as the registry holds it for the boot check.
///
/// The declarations are associated constants, which a trait object cannot read; this is them as
/// data, recorded at registration by the composition root that named the transport. Nothing here is
/// derived — every field is what the crate declared or what the root wired — because a check that
/// re-derived its own inputs would agree with itself for free.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Registered {
    /// The transport's registry key.
    pub key: &'static str,
    /// The layers it declares it can be built over.
    pub composes_over: &'static [&'static str],
    /// The layer it was ACTUALLY built over, where the root composed it over one.
    pub composed_over: Option<&'static str>,
}

/// A composition the registry will not boot on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompositionError {
    /// A transport declares it composes over a layer no registered transport provides.
    ///
    /// A declaration nothing checks is the frame-honesty problem one layer up: the stack a node
    /// reports is the stack its declarations describe, and a name that resolves to nothing means
    /// the description was never true.
    UnregisteredLayer {
        /// The transport that declared it.
        transport: &'static str,
        /// The layer it named.
        layer: &'static str,
    },
    /// A transport was composed over a layer it does not declare.
    ///
    /// The other direction of the same rule: a declared composition must be the one actually used,
    /// or the declaration describes a node nobody is running.
    UndeclaredComposition {
        /// The transport that was composed.
        transport: &'static str,
        /// What it was actually built over.
        used: &'static str,
    },
    /// Two transports registered under one key.
    DuplicateKey(&'static str),
}

impl fmt::Display for CompositionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnregisteredLayer { transport, layer } => write!(
                f,
                "transport `{transport}` composes over `{layer}`, which no registered transport \
                 provides"
            ),
            Self::UndeclaredComposition { transport, used } => write!(
                f,
                "transport `{transport}` was composed over `{used}`, which it does not declare"
            ),
            Self::DuplicateKey(key) => {
                write!(f, "two transports registered under the key `{key}`")
            }
        }
    }
}

impl std::error::Error for CompositionError {}

/// The boot check over a registry's transports: every declared layer exists, and every composition
/// that happened was declared.
///
/// Run once, at boot, after configuration is read. Both halves matter and neither implies the
/// other: a transport can declare a layer nobody registered, and a root can compose a transport
/// over a layer it never declared. Before this ran, `COMPOSES_OVER` was a comment with a type.
///
/// # Errors
///
/// Two transports share a key, a declared layer names no registered transport, or a transport was
/// built over a layer it does not declare.
pub fn check_composition(registered: &[Registered]) -> Result<(), CompositionError> {
    for (i, r) in registered.iter().enumerate() {
        if registered[..i].iter().any(|other| other.key == r.key) {
            return Err(CompositionError::DuplicateKey(r.key));
        }
    }
    for r in registered {
        for layer in r.composes_over {
            if !registered.iter().any(|other| other.key == *layer) {
                return Err(CompositionError::UnregisteredLayer {
                    transport: r.key,
                    layer,
                });
            }
        }
        if let Some(used) = r.composed_over {
            if !r.composes_over.contains(&used) {
                return Err(CompositionError::UndeclaredComposition {
                    transport: r.key,
                    used,
                });
            }
        }
    }
    Ok(())
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

    /// Render an outbound envelope and body as this transport's own wire bytes.
    ///
    /// The byte layout of an envelope belongs to the transport, and only to the transport: an
    /// `http` request line and folded headers, a gRPC length-prefixed message, a WebSocket payload
    /// are three different objects that no neutral layout describes. The egress unit used to write
    /// one anyway — `name: value`, a blank line, the body — because it must run the lane
    /// cross-check over the same bytes it hands to `write`, and had nothing else to run it over.
    /// That made the check honest about ONE buffer and wrong about which bytes were in it.
    ///
    /// The fields arrive POST-DECORATION: what the egress-auth unit added, and what it substituted
    /// a secret into, are already here. The bytes that come back are the bytes the cross-check
    /// reads and the bytes `write` is given, which is what the design means by the envelope still
    /// equalling the verified destination after decoration.
    ///
    /// Into the arena, because the hot path allocates nowhere else.
    ///
    /// # Errors
    ///
    /// The arena had no room, or the envelope names something this transport cannot express.
    fn encode_envelope<'a>(
        &self,
        fields: &[(&str, &[u8])],
        body: &[u8],
        arena: &'a dyn crate::bounded::Arena,
    ) -> Result<crate::bounded::ArenaBytes<'a>, crate::wire::Encode>;

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

    /// The layer this instance was actually built over, where it was built over one.
    ///
    /// What the registry's boot check compares against `COMPOSES_OVER`. A transport that opens its
    /// own socket answers `None` and is checked only on what it declares; a composed one names the
    /// layer under it, and a name that is not in its declaration refuses the boot.
    fn composed_over(&self) -> Option<&'static str> {
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
