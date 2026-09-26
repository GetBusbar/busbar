//! The plugin-visible contract, and nothing else: the traits a plugin implements, the closed
//! grammars it declares against, and the bounded types it is handed. Core calls plugin, never the
//! reverse — no kernel, capability, unit, plane or transport type is named here.
//!
//! No default bodies, feature-invariant, and bounded (except the candidate set and its
//! permutation, which track deployment-time configuration whose size is not fixed by this crate).
//! See `docs/design/contract-notes.md` for the full rationale.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(missing_debug_implementations)]

// THE PLUGIN-FACING HALF OF THE RETIRING API SHIM (DECISIONS #83: contract = shapes; #84: nothing
// on the plugin path may link a crate holding semantics; #35(a): one capability trait per kind lands
// here). `auth`, `hooks`, `secret` and `operation` are module-path-ONLY, byte-identical moves out of
// `busbar-api`, which re-exports every item under its original name until the fold retires it. Two
// names de-collided on the move (#35): `auth::AuthVerdict` (not `kinds::AuthOutcome`) and
// `secret::SecretModuleError` (not `kinds::SecretError`). Nothing here is re-exported at the crate
// root, so neither shadows the kind ABI's own spelling. `#[allow(missing_docs)]` travels with them
// for the reason it travels with `records`: documenting a self-evident field or variant would EDIT
// the moved surface.
#[allow(missing_docs)]
pub mod auth;
pub mod authz;
// THE SUBSTRATE-VALUES SHAPES (DECISIONS #83: contract = shapes; #83a, SD-1): `billing`, `codec`,
// `ir`, `protocol` (and `diagnostic`, below) are module-path-only moves out of `busbar-substrate-values`, which re-exports
// every item under its historical path until the split retires it (and the two upstream signal shapes
// joined `upstream`). `#[allow(missing_docs, missing_debug_implementations)]` travels with them for
// the reason it travels with `records`: documenting a self-evident field or deriving a `Debug` would
// EDIT the moved surface. Nothing here is re-exported at the crate root.
#[allow(missing_docs, missing_debug_implementations)]
pub mod billing;
pub mod bounded;
pub mod caps;
pub mod civil;
#[allow(missing_docs, missing_debug_implementations)]
pub mod codec;
pub mod config;
pub mod count;
pub mod dest;
// The diagnostic SHAPES and the three `#[macro_export]` emit macros (#83a O3, SD-1), moved out of
// `busbar-substrate-values::diagnostics` beside the rest; the catalog stays kernel-side.
pub mod diagnostic;
pub mod duration;
pub mod grammar;
#[allow(missing_docs)]
pub mod hooks;
pub mod ids;
#[allow(missing_docs, missing_debug_implementations)]
pub mod ir;
pub(crate) mod json_grammar;
pub mod kinds;
#[allow(missing_docs)]
pub mod operation;
pub mod plane;
pub mod plugin;
#[allow(missing_docs, missing_debug_implementations)]
pub mod protocol;
pub mod redacted;
// The money-path durable record SHAPES (DECISIONS #83: contract = shapes, ledger = semantics;
// DECISIONS #84: nothing on the plugin path may link a crate holding semantics). The module is a
// module-path-ONLY, byte-identical relocation of the store contract that used to sit in
// the retiring api shim and then in the money one-book; `#[allow(missing_docs)]` travels with
// it for the same reason it did there — documenting the handful of self-evident required trait
// methods (`get_key`/`list_keys`/…) would EDIT the moved surface, and the sacred constraint is that
// the move changes nothing. The oracle proves the wire bytes; the module's own record tests prove
// the serde round-trips.
#[allow(missing_docs)]
pub mod records;
// Which reply wakes which waiting unit: the AwaitReply leg's waiting table, a shape over the
// contract's own correlation and leg types (DECISIONS #83).
pub mod reply;
pub mod scratch;
#[allow(missing_docs)]
pub mod secret;
// The config secret-reference SHAPE (DECISIONS #83 MERGE, fold F1): the former `busbar-secret-ref`
// crate. Its `SecretRef` is also the kind ABI's (`kinds::SecretRef` re-exports it): one type.
pub mod secret_ref;
pub mod signal;
pub mod slice;
pub mod spans;
pub mod surface;
pub mod transport;
pub mod unit;
pub mod upstream;
pub mod verb_store;
pub mod vocab;
pub mod wire;

/// Milliseconds on the kernel's monotonic clock.
///
/// The kernel never reads a wall clock: every deadline, every tick interval and every lease
/// lifetime is a difference between two of these, handed in by the caller. It lives on the contract
/// (the ONE ABI crate, DECISIONS #38) because the slice/lease types it stamps — the store-facing
/// ABI a plugin's store implements and the kernel consumes — are the contract's own.
pub type Millis = u64;

pub use bounded::{
    BoundedVec, FactValue, Facts, FactsExhausted, Ir, IrEdit, IrPatch, Labels, Overflow,
    PlaneAlloc, PlaneAllocBudget, ScratchBytes, SlabBytes, Span, MAX_CURSOR_BYTES, MAX_KEYS,
    MAX_LEGS, MAX_LEG_REPLIES, MAX_NEEDMORE_FRAMES, MAX_RECORD_BYTES, MAX_RESPONSE_PTRS,
    MAX_SESSION_UPSTREAMS, MAX_USAGE_LINES, SCRATCH_BASE_BYTES,
};
pub use count::{
    read_count, read_count_bytes, stored_scale_default, Count, CountError, COUNT_SCALE,
    MAX_ACROSS_A_64_BIT_COLUMN, MIN_ACROSS_A_64_BIT_COLUMN, SCALE_MICRO_UNITS, SCALE_WHOLE_UNITS,
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
    ClassEstimate, CorrelationRef, CorrelationValue, Estimate, LaneId, MeterClassDecl,
    MeterClassId, OpClassId, PrincipalId, RecordSchemaId, Registration, SchemeAlt, SchemeKey,
    SessionId, StreamId, TransportId, UnitKey, UpstreamIdx, MAX_VOCABULARY,
};
pub use kinds::{
    Ack, Anchor, AuthOutcome, AuthScheme, Challenge, ChallengeState, ContentFacts, Credential,
    CredentialFacts, CredentialLocator, EnvelopeFields, Export, ExportItem, Head, Hook, HookFacts,
    HookKindDecl, HookView, KernelCounts, KeyMaterial, OnFailure, PlaneFacts, RecordBytes, Seat,
    Secret, SecretError, SecretRef, SecretValue, SignFailed, Signer, SliceGrant, Store, StoreError,
};
pub use plane::{
    Ingress, Plane, PlaneMeta, PlaneSessionState, Progress, Response, SessionPlane, UnitDraft,
};
// `KernelSeal` is deliberately absent: it is reachable as `plugin::KernelSeal` and nowhere else, so
// it is not among the names this crate offers as the plugin-visible ABI. It cannot be made private
// — the capability crate implements it on every token and sits above this one — so the scan named
// in its own documentation is what holds the in-tree side.
pub use plugin::{AbiVersion, Kind, KindMarker, Plugin, STORE_ABI};
pub use redacted::{constant_time_eq, sha256_hex, Redacted};
pub use scratch::{Scratch, ScratchRefused};
pub use signal::{Signal, SignalBag, SignalValue};
pub use transport::{
    check_composition, CompositionError, FrameStream, Fut, Registered, Transport,
    TransportConfigView, TransportMeta, TRANSPORT_ABI,
};
pub use unit::{
    AbortBy, AdmitFacts, AuditFacts, Clock, ConfigView, Ctx, FailureReason, FinishClass, LegResult,
    Origin, Refusal, RefusalReason, ResourceLocator, ScopeFacts, SessionView, Step, TransportView,
    Unit, UnitEnd, UsageLocator, UsageLocators,
};
pub use wire::{
    ArrivalRecord, CertFacts, CloseReason, Conn, ConnHandle, Decode, Direction, DiscardCode,
    Encode, EnvelopeField, Frame, FrameCursor, FrameMeta, Framing, Handoff, HandshakeTrigger,
    Listener, ListenerHandle, RawIo, RawStream, StatusAt, TransportEnvelope, TransportError,
    Unit0Trigger, WireStatus, WireStatusClass,
};

/// The default admin-scope CEILING for an identity provider that names none (`read-only`). Relocated
/// here (W4.b P2) from the deleted `busbar-substrate::config::auth` so the below-kernel `busbar-core-config`
/// spine can name it without a path back to the engine; `busbar_kernel::config::auth` re-exports it.
pub const DEFAULT_MAX_ADMIN_SCOPE: &str = "read-only";
