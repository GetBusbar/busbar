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
pub mod surface;
// The transport-axis enum (`Transport`) keeps its own file name from the folded
// crate; nested under the `transport` kind module this reads as inception, but renaming the axis
// module would change the public path dependents reach the enum through.
#[allow(clippy::module_inception)]
pub mod transport;
pub mod trust;
pub mod wire;

/// A plugin kind's native interface generation.
///
/// Spelled here because the transport kind's own generation is spelled here, and a generation that
/// two crates each declared their own newtype for would compare equal to nothing. It carries no
/// meaning of its own: a kind pins a number, and the loader or the surface scan compares against it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub struct AbiVersion(pub u16);

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
    ArrivalRecord, CertFacts, CloseReason, Conn, ConnFacts, ConnHandle, Decode, Direction,
    DiscardCode, Encode, FrameMeta, Framing, Handoff, HandshakeTrigger, RawIo, RawStream, Side,
    StatusAt, TransportError, Unit0Trigger, WireFault, WireStatus, WireStatusClass,
};
