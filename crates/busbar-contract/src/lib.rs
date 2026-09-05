//! The plugin-visible contract, and nothing else.
//!
//! busbar is a byte-governance router. Bytes come in over a transport; a plane says what they
//! mean; the kernel runs the same seven steps on every unit of work — authenticate, verify,
//! approve, admit, route, meter, audit — and bytes go out. The kernel does not know what any
//! protocol is.
//!
//! This crate is the seam that makes that true. It carries the traits a plugin implements, the
//! closed grammars a plugin declares against, and the bounded types a plugin is handed. It does
//! not carry the kernel, the capability types, any unit, any plane or any transport, and it never
//! will: a plugin's manifest may name this crate, and naming anything else in the workspace is a
//! failure in the gate. That direction is the whole architecture — core calls plugin, never the
//! reverse.
//!
//! ## What is deliberately not here
//!
//! The capability types — the per-step decision, the hold, the accrual, the posted settlement, the
//! durability loss marker, and the tokens that build them — live in the capability crate, which
//! the kernel and the units name and a plugin cannot. They are absent here on purpose: a plugin
//! that could name a hold could hold one, and a plugin that could build a decision would not need
//! the loop's permission for anything. Where this crate needs to describe a kernel-built value a
//! plugin merely reads, it uses the seal marker in the plugin module and says so at the point of
//! use.
//!
//! ## The three properties this crate is meant to have
//!
//! **No default bodies.** The honesty table of the design requires that every method of every kind
//! trait be implemented by the plugin. A default body is a plugin quietly declining to answer, and
//! the loop cannot tell that apart from an answer.
//!
//! **Feature-invariant.** This crate declares no cargo features. The surface a plugin compiles
//! against is the same surface everywhere, so a plugin built in one configuration cannot be
//! subtly different from the same plugin built in another.
//!
//! **Bounded.** Every collection on this surface has a ceiling that is part of its type, with the
//! two exceptions the design itself names: the candidate set and the permutation over it, which
//! are unbounded because configured pools are unbounded and bounding them would refuse a
//! configuration the previous release accepted.

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
    AuthDecoration, CandidateIdx, CandidateSet, ClientMode, DestinationFacts, EgressBody, Leg,
    OnEmpty, Permutation, RoutePlan, SecretOnce, SecretSlot, TransportKeyHandle,
    VerifiedDestination, VetoCode,
};
pub use grammar::{
    ArrivalLocation, Claim, Idempotency, Location, MaskKind, PathSeg, ReplayMatch, Selector,
    SelectorFamily, SelectorForm, SignedOver,
};
pub use ids::{
    AdminVerbId, BucketChain, BucketRef, BucketScope, CapDimension, ClassDirection, ClassEstimate,
    CorrelationRef, Estimate, LaneId, MeterClassDecl, MeterClassId, OpClassId, PrincipalId,
    RecordSchemaId, SchemeAlt, SchemeKey, SessionId, StreamId, TransportId, UpstreamIdx,
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
    Encode, EnvelopeField, Frame, FrameCursor, FrameMeta, Handoff, HandshakeTrigger, Listener,
    ListenerHandle, StatusAt, StatusClass, TransportEnvelope, TransportError, Unit0Trigger,
};
