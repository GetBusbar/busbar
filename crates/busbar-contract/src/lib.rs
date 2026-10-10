//! The plugin-visible contract, and nothing else: the traits a plugin implements, the closed
//! grammars it declares against, and the bounded types it is handed. Core calls plugin, never the
//! reverse — no kernel, capability, unit, plane or transport type is named here.
//!
//! No default bodies, feature-invariant, and bounded (except the candidate set and its
//! permutation, which track deployment-time configuration whose size is not fixed by this crate).
//! See `docs/design/BUSBAR-1.6.0.md` #38 for the full rationale.

// UNSAFE POLICY (the DECISIONS #84 merge). Denied crate-wide, and allowed in exactly ONE module: `abi`,
// the plugin C ABI folded in from the former `busbar-plugin` and `busbar-plugin-sdk` crates. That module
// is the FFI boundary itself — the `#[repr(C)]` declarations a `'static` must be `Sync` to hold, the
// sized-struct reads over a peer's pointer, the export boundary, and the ONE set of frozen
// `#[no_mangle]` door symbols (defined once, here, so two plugins linked into one image never define
// them twice). Every other module stays unsafe-free: `tests/feature_invariance.rs` pins that the
// `allow` below is the only one, and that no `unsafe` token appears outside `src/abi/`.
#![deny(unsafe_code)]
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
pub mod auth_calls;
pub mod authz;
// THE PLUGIN ABI AND ITS AUTHOR-SIDE SDK (DECISIONS #84: the SDK and the contract share one definition,
// "the plugin contract", so they MERGE; #83: contract = shapes). `abi` is the former `busbar-plugin`
// (the shared airlock root, the COLD JSON lane `abi::cold`, the HOT `#[repr(C)]` lane `abi::hot`) and
// `abi::sdk` is the former `busbar-plugin-sdk` (the export macros, the one export boundary, the one
// dropped-in door). Module-path-only moves: every item keeps its name, and every `#[repr(C)]` layout is
// unchanged (`tests/layout_golden.rs`). `#[allow(missing_docs, missing_debug_implementations)]`
// travels with them for the reason it travels with `records`; `unsafe_code` is allowed here and
// nowhere else (the unsafe policy above).
#[allow(unsafe_code, missing_docs, missing_debug_implementations)]
pub mod abi;
// THE SANS-IO `hyper` DRIVE framers expand (`hyper_io!(<buffer>)`): a macro only, so the contract
// depends on neither `hyper` nor a buffer crate (ARCHITECT ruling 2026-09-30 (c)).
mod sdk_hyper;
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
pub mod conn;
pub mod count;
pub mod dest;
// The diagnostic SHAPES and the three `#[macro_export]` emit macros (#83a O3, SD-1), moved out of
// `busbar-substrate-values::diagnostics` beside the rest; the catalog stays kernel-side.
pub mod diagnostic;
pub mod duration;
pub mod export_calls;
pub mod grammar;
pub mod header;
pub mod hook_calls;
// The 1.5.5 wire, moved here verbatim from the kernel so it lives beside the ABI it serves: its
// field docs are the wire's own module text, and its structs deliberately derive no `Debug` (they
// borrow prompt text).
#[allow(missing_docs, missing_debug_implementations)]
pub mod hook_wire;
#[allow(missing_docs)]
pub mod hooks;
pub mod ids;
#[allow(missing_docs, missing_debug_implementations)]
pub mod ir;
pub(crate) mod json_grammar;
pub mod jsonrpc;
pub mod kinds;
// The media carriers (#83a SD-2b), re-expressed over `bounded::SlabBytes`.
#[allow(missing_docs, missing_debug_implementations)]
pub mod media;
// THE MIGRATION SEAMS: the legacy-row shapes and the three traits the store adapter implements and
// the ledger's migration consumes (the same division `slice` makes).
pub mod migration;
// The one URL and host reader (the destination-guard audit): pure, outside `abi/`.
pub mod net;
#[allow(missing_docs)]
pub mod operation;
pub mod plane;
pub mod plane_calls;
pub mod plugin;
pub mod plugin_rows;
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
pub mod section;
pub mod services;
pub mod signal;
// THE LOG'S SHIPPING SEAM: the trait the store adapter implements and the log ships through.
pub mod ship;
pub mod slice;
// THE STORE'S CALLS: the typed store v3 surface the loader implements and the kernel calls.
pub mod spans;
pub mod store_calls;
pub mod surface;
// THE TEST KIT IS NOT IN A RELEASE BUILD (Locked Decision #33, "there is NO testkit"). Its log
// double is compiled for this crate's own tests and, through the dev-only `test-seal` feature, for a
// plugin's dev-dependency edge; `tests/test_seal_is_dev_only.rs` refuses any non-dev edge that
// enables it, so no shipped artifact carries it.
#[cfg(any(test, feature = "test-seal"))]
pub mod testkit;
pub mod transport;
pub mod unit;
pub mod upstream;
pub mod verb_store;
pub mod vocab;
pub mod wire;

/// THE HEADER VOCABULARY the protocol-seam shapes name (`HeaderMap`, `HeaderName`, `HeaderValue`,
/// `StatusCode`), re-exported so a plane reaches the very types the contract's signatures use through
/// the contract alone (#83a O10: header vocabulary is spec-accepted here) rather than naming the crate
/// as a second dependency of its own.
pub use http;

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
    Ack, Challenge, ChallengeState, ContentFacts, CredentialLocator, EnvelopeFields, Head,
    PlaneFacts, RecordBytes, SecretRef, StoreError,
};
pub use plane::{
    Ingress, Plane, PlaneMeta, PlaneSessionState, Progress, Response, SessionPlane, UnitDraft,
};
// `KernelSeal` is deliberately absent: it is reachable as `plugin::KernelSeal` and nowhere else, so
// it is not among the names this crate offers as the plugin-visible ABI. It cannot be made private
// — the capability crate implements it on every token and sits above this one — so the scan named
// in its own documentation is what holds the in-tree side.
pub use plugin::{AbiVersion, Kind, KindMarker, Plugin};
pub use redacted::{constant_time_eq, sha256_hex, Redacted};
pub use scratch::{Scratch, ScratchRefused};
pub use signal::{Signal, SignalBag, SignalValue};
pub use transport::{
    check_composition, CompositionError, FrameStream, Fut, Registered, Transport,
    TransportConfigView, TransportMeta, TRANSPORT_ABI,
};
pub use transport::{Carrier, Framer};
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
