//! The plugin-visible contract, and nothing else: the traits a plugin implements, the closed
//! grammars it declares against, and the bounded types it is handed. Core calls plugin, never the
//! reverse — no kernel, capability, unit, plane or transport type is named here.
//!
//! No default bodies, feature-invariant, and bounded (except the candidate set and its
//! permutation, which track unbounded configured pools). See `docs/design/contract-notes.md` for
//! the full rationale.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(missing_debug_implementations)]

pub mod bounded;
pub mod dest;
pub mod grammar;
pub mod ids;
pub mod kinds;
pub mod plane;
pub mod plugin;
pub mod transport;
pub mod unit;
pub mod wire;

pub use bounded::{
    Arena, ArenaBudget, ArenaBytes, BoundedVec, FactValue, Facts, Ir, IrPatch, Labels, SlabBytes,
    Span, ARENA_BYTES, MAX_CURSOR_BYTES, MAX_KEYS, MAX_LEGS, MAX_LEG_REPLIES, MAX_NEEDMORE_FRAMES,
    MAX_RECORD_BYTES, MAX_SESSION_UPSTREAMS, MAX_STEPS, MAX_USAGE_LINES,
};
pub use dest::{
    AuthDecoration, CandidateIdx, CandidateSet, ClientMode, DestinationFacts, DestinationId,
    EgressBody, Leg, OnEmpty, Permutation, RoutePlan, SecretOnce, SecretSlot, TransportKeyHandle,
    UpstreamAddress, VerifiedDestination, VetoCode,
};
pub use grammar::{
    ArrivalLocation, Claim, Idempotency, Location, MaskKind, PathSeg, ReplayMatch, Selector,
    SelectorFamily, SelectorForm, SignedOver,
};
pub use ids::{
    AdminVerbId, BucketChain, BucketRef, BucketScope, CapDimension, ClaimKey, ClassDirection,
    ClassEstimate, CorrelationRef, Estimate, LaneId, MeterClassDecl, MeterClassId, OpClassId,
    PrincipalId, RecordSchemaId, SchemeAlt, SchemeKey, SessionId, StreamId, TransportId, UnitKey,
    UpstreamIdx,
};
pub use kinds::{
    Ack, Anchor, AuthOutcome, AuthScheme, Challenge, ChallengeState, ContentFacts, Credential,
    CredentialFacts, CredentialLocator, EgressAuthScheme, Export, ExportItem, Head, Hook,
    HookFacts, HookKindDecl, HookView, KernelCounts, KeyMaterial, OnFailure, PlaneFacts,
    RecordBytes, Seat, Secret, SecretError, SecretRef, SecretValue, SliceGrant, Store, StoreError,
};
pub use plane::{
    Ingress, Plane, PlaneMeta, PlaneSessionState, Progress, Response, SessionPlane, UnitDraft,
};
pub use plugin::{AbiVersion, KernelSeal, Kind, KindMarker, Plugin, STORE_ABI};
pub use transport::{Fut, Transport, TransportConfigView, TransportMeta};
pub use unit::{
    AbortBy, AdmitFacts, AuditFacts, Clock, ConfigView, Ctx, FailureReason, FinishClass, LegResult,
    Origin, Refusal, RefusalReason, ResourceLocator, ScopeFacts, SessionView, Step, TransportView,
    Unit, UnitEnd, UsageLocator, UsageLocators,
};
pub use wire::{
    ArrivalRecord, CertFacts, CloseReason, Conn, ConnHandle, Decode, Direction, DiscardCode,
    Encode, EnvelopeField, Frame, FrameCursor, FrameMeta, Framing, Handoff, HandshakeTrigger,
    Listener, ListenerHandle, StatusAt, StatusClass, TransportEnvelope, TransportError,
    Unit0Trigger,
};
