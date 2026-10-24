//! The transport kind: how bytes move.
//!
//! A transport cannot name a plane and cannot name a unit. It yields and writes frames, inbound
//! and outbound, and it knows no protocol and no principal. A transport is a swappable kind (#3):
//! compiled in or dropped in, it is one memory-ABI framer door the connector serves over the host's
//! sockets, admitted by the same signed-load pipeline as every plugin. There is no transport trait:
//! the connector reaches a transport only through its door (step 36). The controls on one are that
//! admission, review, the source denylist, and the frame-honesty tests that turn red for a transport
//! whose reported byte counts inflate or deflate against what actually moved.

// The transport-facing vocabulary, folded in from the former `busbar-contract-transport` crate
// (DECISIONS #38): a KIND is a match-arm, not a crate, so the transport half lives here as one
// module tree rather than a sibling crate the contract depended on.
pub mod dest;
pub mod registry;
// THE TWO TRANSPORT ROLES (TRANSPORT-STACK): a transport plugin is a carrier or a framer. Which one
// is the export its door makes, never a derivation from what it composes over.
pub mod stack;
pub mod surface;
// The transport-axis enum (`Transport`) keeps its own file name from the folded
// crate; nested under the `transport` kind module this reads as inception, but renaming the axis
// module would change the public path dependents reach the enum through.
#[allow(clippy::module_inception)]
pub mod transport;
pub mod trust;
pub mod wire;

pub use stack::{
    BytesOut, Carrier, CarrierFacts, CarrierPoll, Chunk, Claim, ConnFacts, Dest, Framed, Framer,
    FramerOut, HostTime, Located, Side, TransportRow,
};

use crate::ids::StreamId;
// `Frame` is the plane-facing frame, which lives one level up in the contract's own `wire` module
// (it borrows the arena the contract owns). Every other wire name below arrives via the
// `pub use wire::{…}` re-export of this module's own transport `wire` submodule.
use crate::wire::Frame;
use futures::Stream;
use std::future::Future;
use std::pin::Pin;

/// A plugin kind's native interface generation.
///
/// Spelled here because the transport kind's own generation is spelled here, and a generation that
/// two crates each declared their own newtype for would compare equal to nothing. It carries no
/// meaning of its own: a kind pins a number, and the loader or the surface scan compares against it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub struct AbiVersion(pub u16);

/// The one boxed future per call.
///
/// The allocation gate excludes exactly this: an asynchronous trait method has to box its future,
/// and one box per transport call is the price of having the transport axis be a trait at all.
pub type Fut<'a, T> = Pin<Box<dyn Future<Output = Result<T, TransportError>> + Send + 'a>>;

/// The frame pump's own type: a stream of framed bytes tagged with the stream they arrived on.
pub type FrameStream =
    Pin<Box<dyn Stream<Item = Result<(StreamId, Frame), TransportError>> + Send>>;

/// The transport kind's ABI generation, the fact keys the kernel reserves, and the boot check over
/// a composed stack.
///
/// All three live in the `registry` submodule, where a transport author reads them and a plane
/// author does not; they are named here so that `busbar_contract::transport` still means what it
/// meant to the composition root that wires the registry.
pub use registry::{
    check_composition, facts, status_ns, CompositionError, Registered, TransportSettings,
    DEFAULT_REQUEST_BODY_MAX_BYTES, DEFAULT_REQUEST_TIMEOUT_SECS, TRANSPORT_ABI,
};

/// A plane's SERVED SURFACE as data — the operations, how each is addressed on each binding, how it
/// answers, and the media types on either side.
///
/// Re-exported here for the one reader who is not a transport author: a PLANE declares this, and a
/// plane's manifest may name `busbar-contract` and nothing else in the workspace. The declaration
/// itself is plane-agnostic and lives with the rest of the transport-facing vocabulary, because it
/// is read by every mount and by no plugin author who is not writing one.
pub use surface::{
    binding_at, check_surface, match_target, resolve_document, resolve_service, resolve_target,
    Answering, Bar, BindingDecl, Capture, Dispatch, Operation, SurfaceError, WireSurface,
    MAX_CAPTURES,
};

/// Where a dial lands, as the transport family that dials it spells it — named at the transport
/// module root because a plane builds one when it says where a unit wants to go.
pub use dest::UpstreamAddress;

/// The host-owned trust seam currency: the client identity and the egress trust a
/// composition root fills in and hands across to the transport that applies it.
pub use trust::{ClientIdentity, EgressTrust};

/// The transport wire vocabulary a plane still touches, re-exported at the transport module root so
/// `busbar_contract::transport::<name>` resolves exactly as `busbar_contract::transport::<name>` did.
pub use wire::{
    ArrivalRecord, CertFacts, CloseReason, Conn, ConnHandle, Decode, Direction, DiscardCode,
    Encode, FrameMeta, Framing, Handoff, HandshakeTrigger, RawIo, RawStream, StatusAt,
    TransportError, Unit0Trigger, WireFault, WireStatus, WireStatusClass,
};

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
    /// The numbering this transport spells its statuses in, where it puts a number on an answer.
    ///
    /// The other half of [`TransportMeta::STATUS_CLASS`]: that says WHICH FRAME carries the status,
    /// this says WHICH VOCABULARY wrote it. A number without its numbering is unreadable — `14` is
    /// `UNAVAILABLE` in a trailer numbering and is not a status at all in a status-line one — and
    /// every [`crate::wire::WireStatus`] a transport reports takes its namespace from here, so the
    /// declaration and the frames cannot disagree. `None` for a transport that reports no number,
    /// which is every transport whose `STATUS_CLASS` is `None`.
    const STATUS_NAMESPACE: Option<&'static str>;
    /// Whether this transport can apply a [`crate::transport::wire::ConnectionSecurity`] wrap to a
    /// freshly accepted/dialled raw stream (DECISIONS #40, the core-side transport-security seam).
    ///
    /// This is the static "wrappable byte stream" capability the composition root reconciles
    /// against the operator's binding config: `TLS`-configured binding + a transport that declares
    /// this `true` ⇒ it is handed a real rustls-backed wrap; `TLS`-configured binding + a transport
    /// that leaves this at the default `false` ⇒ the binding fails closed at boot rather than being
    /// silently served in plaintext. A transport with no byte stream to wrap at all (one that talks
    /// to a child process over its pipes) simply never overrides the default.
    const WRAPPABLE_BYTE_STREAM: bool = false;
    /// EVERY SCHEME THIS ENTRY ANSWERS FOR ([`Claim`]), in order; the first is the entry's own. A
    /// transport that answers for its own key alone makes the one claim its per-scheme constants
    /// above describe, which is this default.
    const CLAIMS: &'static [Claim] = &[Claim {
        key: Self::KEY,
        session: Self::SESSION,
        session_bound: Self::SESSION_BOUND,
        unit0_trigger: Self::UNIT0_TRIGGER,
        status_at: Self::STATUS_CLASS,
        status_namespace: Self::STATUS_NAMESPACE,
        transport_facts: Self::TRANSPORT_FACTS,
        selector_forms: Self::SELECTOR_FORMS,
    }];
}
