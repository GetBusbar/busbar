//! The plugin-visible contract, and nothing else: the traits a plugin implements, the closed

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(missing_debug_implementations)]

#[allow(missing_docs)]
pub mod auth;
pub mod auth_calls;
pub mod authz;

#[allow(unsafe_code, missing_docs, missing_debug_implementations)]
pub mod abi;

#[cfg(test)]
#[path = "../../busbar-test-kit/src/alloc_counter.rs"]
pub mod alloc_counter;

mod sdk_hyper;

#[allow(missing_docs, missing_debug_implementations)]
pub mod billing;
pub mod bounded;
pub mod caps;
pub mod civil;
#[allow(missing_docs, missing_debug_implementations)]
pub mod codec;
pub mod config;
pub mod config_time;
pub mod conn;
pub mod count;
pub mod dest;

pub mod diagnostic;
pub mod duration;
pub mod export_calls;
pub mod framing_scope;
pub mod grammar;
pub mod header;
pub mod hook_calls;

#[allow(missing_docs, missing_debug_implementations)]
pub mod hook_wire;
#[allow(missing_docs)]
pub mod hooks;
pub mod ids;

pub mod io_host;
#[allow(missing_docs, missing_debug_implementations)]
pub mod ir;
pub(crate) mod json_grammar;
pub mod jsonrpc;
pub mod kinds;

#[allow(missing_docs, missing_debug_implementations)]
pub mod media;

pub mod net;
#[allow(missing_docs)]
pub mod operation;
pub mod plane;
pub mod plane_calls;
pub mod plugin;
pub mod plugin_rows;
#[allow(missing_docs, missing_debug_implementations)]
pub mod protocol;

pub mod provider_keys;
pub mod redacted;

#[allow(missing_docs)]
pub mod records;
pub mod scratch;
#[allow(missing_docs)]
pub mod secret;

pub mod secret_ref;
/// Settings sensitivity: every plugin setting is sensitive unless its schema declares it public.
pub mod settings_public;

pub mod secret_fields;
pub mod section;
pub mod services;
pub mod signal;

pub mod spans;
pub mod store_calls;
pub mod surface;
pub mod transport;
pub mod unit;
pub mod upstream;
pub mod vocab;
pub mod wire;

/// THE HEADER VOCABULARY the protocol-seam shapes name (`HeaderMap`, `HeaderName`, `HeaderValue`,
pub use http;

/// Milliseconds on the kernel's monotonic clock.

pub type Millis = u64;

pub use bounded::{
    BoundedVec, FactValue, Facts, FactsExhausted, Ir, Labels, Overflow, PlaneAlloc,
    PlaneAllocBudget, ScratchBytes, SlabBytes, Span, MAX_CURSOR_BYTES, MAX_KEYS, MAX_LEGS,
    MAX_LEG_REPLIES, MAX_NEEDMORE_FRAMES, MAX_RECORD_BYTES, MAX_RESPONSE_PTRS,
    MAX_SESSION_UPSTREAMS, MAX_USAGE_LINES, SCRATCH_BASE_BYTES,
};
pub use count::{
    read_count, read_count_bytes, Count, CountError, COUNT_SCALE, MAX_ACROSS_A_64_BIT_COLUMN,
    MIN_ACROSS_A_64_BIT_COLUMN, SCALE_MICRO_UNITS, SCALE_WHOLE_UNITS,
};
pub use dest::{
    ClientMode, DestinationFacts, DestinationId, EgressBody, Leg, RoutePlan, SecretOnce,
    SecretSlot, TransportKeyHandle, UpstreamAddress, VerifiedDestination,
};

pub use grammar::{
    ArrivalLocation, Claim, Idempotency, Location, MaskKind, PathSeg, ReplayMatch, Selector,
    SelectorFamily, SelectorForm, SignedOver,
};
pub use ids::{
    AdminVerbId, BucketRef, BucketScope, CapDimension, ClaimKey, ClassDirection, ClassEstimate,
    CorrelationRef, CorrelationValue, Estimate, LaneId, MeterClassDecl, MeterClassId, OpClassId,
    PrincipalId, RecordSchemaId, SchemeAlt, SchemeKey, SessionId, StreamId, TransportId, UnitKey,
    UpstreamIdx,
};
pub use kinds::{
    Challenge, ChallengeState, ContentFacts, CredentialLocator, Head, PlaneFacts, RecordBytes,
    SecretRef, StoreError,
};
pub use plane::{
    Ingress, Plane, PlaneMeta, PlaneSessionState, Progress, Response, SessionPlane, UnitDraft,
};

pub use plugin::{AbiVersion, Kind, KindMarker, Plugin};
pub use redacted::{constant_time_eq, sha256_hex, OwnerSeal, Secret};
pub use scratch::{Scratch, ScratchRefused};
pub use signal::{Signal, SignalBag, SignalValue};
pub use transport::{check_composition, CompositionError, Registered, TRANSPORT_ABI};
pub use unit::{
    AbortBy, AdmitFacts, AuditFacts, Clock, ConfigView, Ctx, FailureReason, FinishClass, LegResult,
    Origin, Refusal, RefusalReason, ResourceLocator, ScopeFacts, SessionView, Step, TransportView,
    Unit, UnitEnd, UsageLocator, UsageLocators,
};
pub use wire::{
    ArrivalRecord, CertFacts, CloseReason, Conn, ConnHandle, Decode, Direction, DiscardCode,
    Encode, EnvelopeField, Frame, FrameCursor, FrameMeta, Framing, Handoff, HandshakeTrigger,
    RawIo, RawStream, StatusAt, TransportEnvelope, TransportError, Unit0Trigger, WireFault,
    WireStatus, WireStatusClass,
};

/// The default admin-scope CEILING for an identity provider that names none (`read-only`). Relocated

pub const DEFAULT_MAX_ADMIN_SCOPE: &str = "read-only";

/// This crate's own test binary counts its allocations through [`alloc_counter::Counting`], the

#[cfg(test)]
extern crate self as busbar_contract;

#[cfg(test)]
#[global_allocator]
static ALLOC: alloc_counter::Counting = alloc_counter::Counting::new();
