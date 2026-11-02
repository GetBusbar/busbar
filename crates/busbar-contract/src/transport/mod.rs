//! The transport kind: how bytes move.

pub mod dest;
pub mod registry;
pub mod surface;

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
pub use registry::{
    check_composition, facts, status_ns, CompositionError, Registered, TransportSettings,
    DEFAULT_REQUEST_BODY_MAX_BYTES, DEFAULT_REQUEST_TIMEOUT_SECS, TRANSPORT_ABI,
};

/// A plane's SERVED SURFACE as data — the operations, how each is addressed on each binding, how it
pub use surface::{
    match_target, resolve_target, Answering, Bar, BindingDecl, Capture, Dispatch, Operation,
    WireSurface, MAX_CAPTURES,
};

/// Where a dial lands, as the transport family that dials it spells it — named at the transport
pub use dest::UpstreamAddress;

/// The host-owned trust seam currency: the client identity and the egress trust a
pub use trust::{ClientIdentity, EgressTrust};

/// The transport wire vocabulary a plane still touches, re-exported at the transport module root so
pub use wire::{
    ArrivalRecord, CertFacts, CloseReason, Conn, ConnFacts, ConnHandle, Decode, Direction,
    DiscardCode, Encode, FrameMeta, Framing, Handoff, HandshakeTrigger, RawIo, RawStream, Side,
    StatusAt, TransportError, Unit0Trigger, WireFault, WireStatus, WireStatusClass,
};
