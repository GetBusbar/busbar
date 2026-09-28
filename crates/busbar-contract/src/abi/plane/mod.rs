// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE KIND'S ABI (the design's plugin-ABI section; the signed per-kind design B.6): its
//! version, its table, the `in`/`out` of every op, its Statement tail, its generation snapshot and
//! its cancel vocabulary.
//!
//! A PLANE serves units: [`slot::ARRIVE`] classifies an arrival, [`slot::ON_PIECE`] is pushed every
//! piece of the unit's bytes and writes its answer into HOST buffers, reporting its CUMULATIVE units
//! with every piece, so a plane makes zero host calls per chunk. Backpressure is `emitted`/`more`:
//! a plane with more output than `reply_cap` answers `more = 1`, the kernel flushes, waits for the
//! socket to be writable and calls again. Money-blind: a plane reports what happened, in its own
//! billable classes by index; it never prices it.
//!
//! REQUEST-PATH RESULTS GO INTO HOST BUFFERS (memory class (i)). Every result an op produces —
//! reply bytes, reply head fields, unit counts, record writes — is written into a buffer the `in`
//! names as pointer + capacity; the bytes of fields and record writes go into the call's `arena`,
//! and the structs name them by [`Span`]. Nothing the host needs after the call lives in plugin
//! memory. Each `out` states what it wrote as a `*_len`; a `*_len` larger than its capacity means the
//! buffer was too small: the plugin wrote nothing into it, the `*_len` is what it needs, and the host
//! grows the buffer and calls the op once more. The one exception is `on_piece`'s reply bytes, which
//! stream: a full `reply_buf` is backpressure (`more`), never a re-call.
//!
//! WHAT CROSSES AND WHEN:
//!
//! * STATIC FACTS — the Statement's kind tail, [`PlaneTail`]: `'static`, signed in the manifest.
//! * CONFIG-DEPENDENT FACTS — the GENERATION SNAPSHOT, [`PlaneSnapshot`], answered on `open`
//!   ([`PlaneOpenOut`]) and `refresh` ([`PlaneRefreshOut`]): valid until `retire` of that generation
//!   (memory class (ii)).
//! * SETTINGS — the `settings` blob `validate`, `open` and `refresh` receive has its `rate_card` and
//!   `fees` keys stripped by the kernel before it crosses (B.6; RED-tested at the kernel).
//! * NEEDS — a plane states its connection needs as `(transport, auth)` per direction in its tail
//!   ([`PlaneTail::needs`], each a [`Need`]); the kernel instantiates them through the connector.
//!
//! CANCEL BILLING — the four 1.5.5 rules, pinned (the review's parity M3). The lifecycle `cancel`
//! answers a disposition ([`CANCEL_OK_PARTIAL`], [`CANCEL_FAILED`], [`CANCEL_ABORTED`]) and the
//! kernel bills from it by [`cancel_bills_reported_units`]:
//!
//! 1. A TRANSLATE-ABORT IS NEVER BILLED: a unit the plane aborted before the far end answered is
//!    [`CANCEL_ABORTED`], and bills nothing.
//! 2. ONLY FAR-END-REPORTED USAGE IS BILLED: of the cumulative units the last piece reported, only
//!    those with [`UNITS_REPORTED`] count; [`UNITS_ESTIMATED`] never bills.
//! 3. A NON-STREAMED PARTIAL BILLS ZERO: [`CANCEL_OK_PARTIAL`] bills the reported units only when
//!    the reply was streamed to the caller; a cut whole-body reply bills `0`.
//! 4. THE BUDGET REFUND IS A SEPARATE ACT: whatever the disposition, the kernel releases the unit's
//!    budget hold on its own path; cancel billing never folds the refund in and never returns it.
//!
//! [`CANCEL_FAILED`] bills nothing.
//!
//! EVERY `PlaneDecl` FIELD, AND WHERE IT WENT (nothing dropped silently):
//!
//! | hot-lane `PlaneDecl` / `BuildCtx` | here |
//! |---|---|
//! | `abi` (preamble), `size`, `version` | the door: magic, mechanism version, `kind_abi`; [`crate::abi::mechanism::door::KindTailHead::size`] |
//! | `name` | [`crate::abi::mechanism::door::Statement::name`] |
//! | `section_key` | tail: the [`PlaneTail::sections`] entry flagged [`SECTION_DECLARING`] |
//! | `scope` | tail [`PlaneTail::scope`] |
//! | `label` | tail [`PlaneTail::label`] |
//! | `provided_carriers` | tail [`PlaneTail::ingress`] (`INGRESS_*` bits, same numbering) |
//! | `config_validate` | lifecycle `validate` |
//! | `build` | lifecycle `open` ([`PlaneOpenIn`], [`PlaneOpenOut`]) |
//! | `hydrate` | kind op [`slot::HYDRATE`] |
//! | `start` | kind op [`slot::START`] |
//! | `admin_routes` | snapshot [`PlaneSnapshot::admin_routes`]; served through [`slot::SERVE`] |
//! | `openapi` | snapshot [`PlaneSnapshot::openapi`] |
//! | `dispatch` | kind ops [`slot::ARRIVE`] + [`slot::ON_PIECE`] (+ [`slot::REFUSAL`]) |
//! | `fallback` | tail [`TAIL_FALLBACK`] in [`PlaneTail::flags`] |
//! | `subject_noun`, `admin_noun`, `audit_kind` | tail, same names |
//! | `signing_domain`, `signing_kid_prefix` | tail, same names |
//! | `scope_kinds` | tail [`PlaneTail::scope_kinds`] |
//! | `owned_sections` | tail [`PlaneTail::sections`] |
//! | `billable_classes` | tail [`PlaneTail::billable_classes`]; per-call units name them by index |
//! | `fee_units` | tail [`PlaneTail::fee_units`] |
//! | `claims` | snapshot [`PlaneSnapshot::claims`] |
//! | `admission` | snapshot [`PlaneSnapshot::audience`] + [`PlaneSnapshot::resource_metadata`] |
//! | `metric_families` | [`crate::abi::mechanism::door::Statement::families`] (per-call metrics by index) |
//! | `served_op_classes` | tail [`PlaneTail::op_classes`]; [`ArriveOut::op_class`] indexes it |
//! | `record_kinds` | tail [`PlaneTail::record_kinds`]; [`RecordWrite::kind`] indexes it |
//! | `dispatch_flags` / `DISPATCH_BLOCKS` | DROPPED — B.6: "`DISPATCH_BLOCKS` is deleted"; a plane never blocks (the design's plugin-ABI section: no blocking on the hot path). Replaced by [`PlaneTail::dispatch_shape`] |
//! | `required_sections` | tail: [`SECTION_REQUIRED`] on a [`PlaneTail::sections`] entry |
//! | `BuildCtx.host`, `host_ctx` | [`crate::abi::mechanism::lifecycle::OpenIn::host`] |
//! | `BuildCtx.config_*` | `OpenIn::settings` (`rate_card`/`fees` stripped) |
//! | `BuildCtx.resolved_refs_*` | `OpenIn::secrets` |
//! | `BuildCtx.public_url_*` | [`PlaneOpenIn::public_url`] |
//! | (new, B.6) dialects, `dialect_auth`, `route_cost`, `cli_help` | tail |
//! | (new) needs, consumed sections, egress targets | tail [`PlaneTail::needs`], [`SECTION_CONSUMED`], [`PlaneTail::egress_targets`] |
//!
//! ```
//! use std::mem::{offset_of, size_of};
//! use busbar_contract::abi::mechanism::lifecycle::{OpsHead, LIFECYCLE_SLOTS};
//! use busbar_contract::abi::plane::{slot, Ops, KIND_SLOTS, SLOTS};
//! // Kind op `k` is at slot index LIFECYCLE_SLOTS + k, contiguous after the lifecycle head.
//! let order = [
//!     (slot::ARRIVE, offset_of!(Ops, arrive)),
//!     (slot::ON_PIECE, offset_of!(Ops, on_piece)),
//!     (slot::REFUSAL, offset_of!(Ops, refusal)),
//!     (slot::SERVE, offset_of!(Ops, serve)),
//!     (slot::HYDRATE, offset_of!(Ops, hydrate)),
//!     (slot::START, offset_of!(Ops, start)),
//! ];
//! assert_eq!(order.len() as u32, KIND_SLOTS);
//! for (k, (index, offset)) in order.into_iter().enumerate() {
//!     assert_eq!(index, LIFECYCLE_SLOTS + k as u32);
//!     assert_eq!(offset, size_of::<OpsHead>() + 8 * k);
//! }
//! assert_eq!(SLOTS, LIFECYCLE_SLOTS + KIND_SLOTS);
//! assert_eq!(size_of::<Ops>(), size_of::<OpsHead>() + 8 * KIND_SLOTS as usize);
//! ```

pub mod check;

use std::mem::size_of;

use super::host::conn::connector::Need;
use super::mechanism::call::{AbiStr, Blob, DeadlineClass, InHead, Op, OutHead};
use super::mechanism::door::KindTailHead;
use super::mechanism::lifecycle::{GenIn, OpenIn, OpenOut, OpsHead, LIFECYCLE_SLOTS};

/// The plane kind's ABI version: new in 1.6.0 (v1.5.5 had no plane ABI), so it ships `1`.
pub const ABI_VERSION: u32 = 1;

/// [`crate::abi::mechanism::call::InHead::op`] of each plane op, in table order: kind op `k` is
/// [`LIFECYCLE_SLOTS`]` + k`. `tick` and `cancel` are the lifecycle's.
pub mod slot {
    use super::LIFECYCLE_SLOTS;

    /// Classify an arrival.
    pub const ARRIVE: u32 = LIFECYCLE_SLOTS;
    /// One piece of a unit's bytes.
    pub const ON_PIECE: u32 = LIFECYCLE_SLOTS + 1;
    /// Render a refusal in the unit's dialect.
    pub const REFUSAL: u32 = LIFECYCLE_SLOTS + 2;
    /// Serve one of the snapshot's admin routes.
    pub const SERVE: u32 = LIFECYCLE_SLOTS + 3;
    /// Restore durable state before the listener opens.
    pub const HYDRATE: u32 = LIFECYCLE_SLOTS + 4;
    /// Begin background work after the listener is bound.
    pub const START: u32 = LIFECYCLE_SLOTS + 5;
}

/// How many kind ops the table holds after the lifecycle.
pub const KIND_SLOTS: u32 = 6;
/// How many slots the whole table holds ([`OpsHead::slots`]).
pub const SLOTS: u32 = LIFECYCLE_SLOTS + KIND_SLOTS;

/// The plane kind's ops table: the lifecycle, then the plane's six ops.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Ops {
    /// The lifecycle. `open` is in [`PlaneOpenIn`], out [`PlaneOpenOut`]; `refresh` out is
    /// [`PlaneRefreshOut`]; `cancel` answers a `CANCEL_*` disposition.
    pub head: OpsHead,
    /// [`slot::ARRIVE`]: in [`ArriveIn`], out [`ArriveOut`].
    pub arrive: Option<Op>,
    /// [`slot::ON_PIECE`]: in [`OnPieceIn`], out [`OnPieceOut`].
    pub on_piece: Option<Op>,
    /// [`slot::REFUSAL`]: in [`RefusalIn`], out [`RefusalOut`].
    pub refusal: Option<Op>,
    /// [`slot::SERVE`]: in [`ServeIn`], out [`ServeOut`].
    pub serve: Option<Op>,
    /// [`slot::HYDRATE`]: in [`GenIn`], out [`OutHead`].
    pub hydrate: Option<Op>,
    /// [`slot::START`]: in [`GenIn`], out [`OutHead`].
    pub start: Option<Op>,
}

// ── the op contracts ─────────────────────────────────────────────────────────────────────────────

/// One op's contract: where it runs, whether it may pend, its largest `in`/`out`, its deadline
/// class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpContract {
    /// The slot index.
    pub slot: u32,
    /// `true` = on the request path; `false` = off-path.
    pub request_path: bool,
    /// `true` = the op may answer PENDING (on a real ticket).
    pub may_pend: bool,
    /// The largest `in` the host writes, in bytes.
    pub max_in: usize,
    /// The largest `out` the plugin writes, in bytes.
    pub max_out: usize,
    /// The deadline class the host stamps in `InHead::deadline_class`.
    pub deadline: DeadlineClass,
}

/// `contract!(slot, request_path, may_pend, In, Out, class)`: one [`OpContract`], sized from its
/// own `in`/`out` types.
macro_rules! contract {
    ($slot:ident, $rp:expr, $pend:expr, $in:ty, $out:ty, $class:ident) => {
        OpContract {
            slot: slot::$slot,
            request_path: $rp,
            may_pend: $pend,
            max_in: size_of::<$in>(),
            max_out: size_of::<$out>(),
            deadline: DeadlineClass::$class,
        }
    };
}

/// Every kind op's contract, in slot order. `arrive` and `refusal` are pure: they never pend.
/// `on_piece` pends (a plane waiting on its own upstream) under the stream's deadline. `hydrate`
/// and `start` are boot-time and off-path.
#[rustfmt::skip]
pub const CONTRACTS: [OpContract; KIND_SLOTS as usize] = [
    contract!(ARRIVE, true, false, ArriveIn, ArriveOut, Call),
    contract!(ON_PIECE, true, true, OnPieceIn, OnPieceOut, Stream),
    contract!(REFUSAL, true, false, RefusalIn, RefusalOut, Call),
    contract!(SERVE, true, true, ServeIn, ServeOut, Call),
    contract!(HYDRATE, false, true, GenIn, OutHead, Call),
    contract!(START, false, true, GenIn, OutHead, Call),
];

// ── the cancel vocabulary and its billing rule ───────────────────────────────────────────────────

/// [`crate::abi::mechanism::lifecycle::CancelOut::disposition`]: the unit was cut after the far end
/// answered; the last piece's far-end-reported units stand.
pub const CANCEL_OK_PARTIAL: u32 = 1;
/// The unit failed; nothing is billed.
pub const CANCEL_FAILED: u32 = 2;
/// The plane aborted the unit before the far end answered (a translate-abort); nothing is billed.
pub const CANCEL_ABORTED: u32 = 3;

/// THE CANCEL BILLING RULE (the four 1.5.5 rules, this module's doc): whether the kernel bills the
/// far-end-reported ([`UNITS_REPORTED`]) cumulative units of a cancelled unit. `streamed` = the
/// reply reached the caller as a stream. An unknown disposition bills nothing. The budget refund is
/// NOT decided here: it is always the kernel's separate act.
#[must_use]
pub const fn cancel_bills_reported_units(disposition: u32, streamed: bool) -> bool {
    disposition == CANCEL_OK_PARTIAL && streamed
}

// ── the vocabulary codes ─────────────────────────────────────────────────────────────────────────

/// [`PlaneTail::flags`]: the one plane that is the fallback catch-all.
pub const TAIL_FALLBACK: u32 = 1;

/// [`PlaneTail::ingress`]: a request expecting one reply.
pub const INGRESS_REQUEST_RESPONSE: u32 = 1;
/// [`PlaneTail::ingress`]: a request expecting a streamed reply.
pub const INGRESS_RESPONSE_STREAM: u32 = 1 << 1;
/// [`PlaneTail::ingress`]: an in/out session either side may originate.
pub const INGRESS_DUPLEX_SESSION: u32 = 1 << 2;
/// [`PlaneTail::ingress`]: a host-initiated, reply-less pull.
pub const INGRESS_SUBSCRIPTION: u32 = 1 << 3;
/// [`PlaneTail::ingress`]: many concurrent stateful connections.
pub const INGRESS_ACCEPT_LOOP: u32 = 1 << 4;

/// [`PlaneTail::dispatch_shape`]: the kernel gathers the caller's whole body and pushes it as one
/// piece.
pub const SHAPE_WHOLE: u32 = 0;
/// [`PlaneTail::dispatch_shape`]: the kernel pushes the caller's bytes piece by piece as they
/// arrive.
pub const SHAPE_PIECEWISE: u32 = 1;

/// [`Section::flags`]: the plane's declaring section.
pub const SECTION_DECLARING: u32 = 1;
/// [`Section::flags`]: a document must carry the section when the plane is linked.
pub const SECTION_REQUIRED: u32 = 1 << 1;
/// [`Section::flags`]: the plane reads the section but does not own its grammar.
pub const SECTION_CONSUMED: u32 = 1 << 2;

/// [`UnitCount::source`]: the plane's own estimate; never billed.
pub const UNITS_ESTIMATED: u32 = 0;
/// [`UnitCount::source`]: the far end reported it; the only billable source.
pub const UNITS_REPORTED: u32 = 1;

/// [`ArriveOut::principal_need`]: no principal.
pub const PRINCIPAL_NONE: u32 = 0;
/// [`ArriveOut::principal_need`]: the kernel must verify a principal before the first piece.
pub const PRINCIPAL_REQUIRED: u32 = 1;
/// [`ArriveOut::principal_need`]: verify one if the caller presents it.
pub const PRINCIPAL_OPTIONAL: u32 = 2;

/// [`OnPieceIn::from`]: the piece is the caller's.
pub const FROM_CALLER: u32 = 0;
/// [`OnPieceIn::from`]: the piece is the far end's.
pub const FROM_FAR_END: u32 = 1;

/// [`OnPieceIn::flags`]: the piece completes its frame.
pub const PIECE_END_OF_FRAME: u32 = 1;
/// [`OnPieceIn::flags`]: no piece follows from this side.
pub const PIECE_LAST: u32 = 1 << 1;
/// [`OnPieceIn::flags`]: `status_code`/`status_class` are set.
pub const PIECE_HAS_STATUS: u32 = 1 << 2;

/// [`OnPieceOut::flags`]: the emitted bytes go to the far end (else to the caller).
pub const EMIT_TO_FAR_END: u32 = 1;
/// [`OnPieceOut::flags`]: the unit's reply is complete.
pub const EMIT_DONE: u32 = 1 << 1;

/// [`RefusalIn::cause`]: the kernel refused.
pub const REFUSAL_KERNEL: u32 = 0;
/// [`RefusalIn::cause`]: a gate refused.
pub const REFUSAL_GATE: u32 = 1;
/// [`RefusalOut::marker`]: the rendered refusal is a gate rejection (the `GateRejected` marker the
/// kernel keeps).
pub const MARK_GATE_REJECTED: u32 = 1;

/// [`RecordWrite::op`]: put.
pub const RECORD_PUT: u32 = 1;
/// [`RecordWrite::op`]: delete.
pub const RECORD_DELETE: u32 = 2;

// ── the Statement tail ───────────────────────────────────────────────────────────────────────────

/// One top-level config section the plane owns or reads.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Section {
    /// The section's key.
    pub name: AbiStr,
    /// `SECTION_*` bits.
    pub flags: u32,
    /// Alignment padding.
    pub _reserved: u32,
}

/// A dialect's default auth style (the 1.5.5 dialect defaults), as data.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DialectAuth {
    /// Index into [`PlaneTail::dialects`].
    pub dialect: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// The style, an open string.
    pub style: AbiStr,
}

/// One operation class the plane serves one level down, and the display name a refusal naming the
/// plane reads.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OpClass {
    /// The operation class.
    pub op: AbiStr,
    /// The plane's display name.
    pub name: AbiStr,
}

/// One billable class and the unit family it counts in. Classes are disjoint (#71).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BillableClass {
    /// The class.
    pub class: AbiStr,
    /// Its unit family.
    pub family: AbiStr,
}

/// One term of the plane's route cost: `cheapest` = Σ price(class) × weight.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RouteCost {
    /// Index into [`PlaneTail::billable_classes`].
    pub class: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// The weight.
    pub weight: f64,
}

/// THE PLANE'S STATEMENT TAIL: static facts, `'static` data.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PlaneTail {
    /// The tail head.
    pub head: KindTailHead,
    /// [`TAIL_FALLBACK`]; any other bit refuses the load.
    pub flags: u32,
    /// `INGRESS_*` bits.
    pub ingress: u32,
    /// `SHAPE_*`.
    pub dispatch_shape: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// The scope label.
    pub scope: AbiStr,
    /// The human label.
    pub label: AbiStr,
    /// What one registration on this plane is called.
    pub subject_noun: AbiStr,
    /// The singular noun for one registration in its named-definition section.
    pub admin_noun: AbiStr,
    /// The record resource kind for a registration.
    pub audit_kind: AbiStr,
    /// The versioned signing domain; absent = the plane signs nothing.
    pub signing_domain: AbiStr,
    /// The signature `kid` prefix; absent = the plane signs nothing.
    pub signing_kid_prefix: AbiStr,
    /// The plane's command-line help text.
    pub cli_help: AbiStr,
    /// The sections it owns or reads.
    pub sections: *const Section,
    /// How many.
    pub sections_len: usize,
    /// Its dialects; per-call `dialect` indexes them.
    pub dialects: *const AbiStr,
    /// How many.
    pub dialects_len: usize,
    /// The dialects' default auth styles.
    pub dialect_auth: *const DialectAuth,
    /// How many.
    pub dialect_auth_len: usize,
    /// The grant kinds that admit traffic, `scope`'s first.
    pub scope_kinds: *const AbiStr,
    /// How many.
    pub scope_kinds_len: usize,
    /// The operation classes it serves.
    pub op_classes: *const OpClass,
    /// How many.
    pub op_classes_len: usize,
    /// Its billable classes; [`UnitCount::class`] indexes them.
    pub billable_classes: *const BillableClass,
    /// How many.
    pub billable_classes_len: usize,
    /// Its route cost.
    pub route_cost: *const RouteCost,
    /// How many.
    pub route_cost_len: usize,
    /// The fee units it counts.
    pub fee_units: *const AbiStr,
    /// How many.
    pub fee_units_len: usize,
    /// The record kinds it keeps; [`RecordWrite::kind`] indexes them.
    pub record_kinds: *const AbiStr,
    /// How many.
    pub record_kinds_len: usize,
    /// Its connection needs, `(transport, auth)` per direction.
    pub needs: *const Need,
    /// How many.
    pub needs_len: usize,
    /// The config paths, inside its sections, that name its egress targets.
    pub egress_targets: *const AbiStr,
    /// How many.
    pub egress_targets_len: usize,
}

// ── the generation snapshot ──────────────────────────────────────────────────────────────────────

/// One path the built plane answers on.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Claim {
    /// The verb.
    pub verb: AbiStr,
    /// The target path.
    pub target: AbiStr,
    /// The transport claim it arrives over.
    pub carrier: AbiStr,
}

/// One admin route the built plane serves through [`slot::SERVE`].
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AdminRoute {
    /// The verb.
    pub verb: AbiStr,
    /// The target path.
    pub target: AbiStr,
}

/// THE GENERATION SNAPSHOT: what the plane answers for THIS generation's settings. Valid until
/// `retire` of `generation`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PlaneSnapshot {
    /// `size_of::<PlaneSnapshot>()`.
    pub size: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// The generation it belongs to.
    pub generation: u64,
    /// The paths it answers on; empty = it mounts nothing this generation.
    pub claims: *const Claim,
    /// How many.
    pub claims_len: usize,
    /// Its admin routes.
    pub admin_routes: *const AdminRoute,
    /// How many.
    pub admin_routes_len: usize,
    /// Its OpenAPI contribution (a JSON blob; absent = none).
    pub openapi: Blob,
    /// The audience it binds; absent = no receiving side.
    pub audience: AbiStr,
    /// Its resource metadata.
    pub resource_metadata: AbiStr,
}

/// The plane's `open` `in`: the lifecycle's, plus the deployment's public base URL.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PlaneOpenIn {
    /// The lifecycle `in`.
    pub open: OpenIn,
    /// The deployment's public base URL; absent = none stated.
    pub public_url: AbiStr,
}

/// The plane's `open` `out`: the lifecycle's, plus the first generation's snapshot.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PlaneOpenOut {
    /// The lifecycle `out`.
    pub open: OpenOut,
    /// The snapshot.
    pub snapshot: *const PlaneSnapshot,
}

/// The plane's `refresh` `out`: the new generation's snapshot.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PlaneRefreshOut {
    /// The head.
    pub head: OutHead,
    /// The snapshot.
    pub snapshot: *const PlaneSnapshot,
}

// ── per-call shapes ──────────────────────────────────────────────────────────────────────────────

/// One head field the HOST hands in, borrowed for the call.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Field {
    /// The name.
    pub name: AbiStr,
    /// The value.
    pub value: AbiStr,
}

/// [`Span::offset`]: no bytes (the span's `len` is then `0`).
pub const SPAN_ABSENT: u32 = u32::MAX;

/// A byte range of the call's HOST `arena`; [`SPAN_ABSENT`] = none.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Span {
    /// Offset into the arena.
    pub offset: u32,
    /// Length.
    pub len: u32,
}

/// One head field the plugin writes, its bytes in the call's `arena`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OutField {
    /// The name.
    pub name: Span,
    /// The value.
    pub value: Span,
}

/// One cumulative unit count, in a HOST buffer.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct UnitCount {
    /// Index into [`PlaneTail::billable_classes`].
    pub class: u32,
    /// [`UNITS_ESTIMATED`] | [`UNITS_REPORTED`].
    pub source: u32,
    /// The cumulative count.
    pub amount: u64,
}

/// One record write, a destination fact the kernel applies on the record seam; its key and value
/// bytes are in the call's `arena`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RecordWrite {
    /// Index into [`PlaneTail::record_kinds`].
    pub kind: u32,
    /// [`RECORD_PUT`] | [`RECORD_DELETE`].
    pub op: u32,
    /// The key.
    pub key: Span,
    /// The value (empty for a delete).
    pub value: Span,
}

/// `arrive`'s `in`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ArriveIn {
    /// The head.
    pub head: InHead,
    /// Index into the snapshot's claims the arrival matched.
    pub claim: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// The request target.
    pub target: AbiStr,
    /// The head fields.
    pub fields: *const Field,
    /// How many.
    pub fields_len: usize,
    /// The body so far, zero-copy.
    pub body: Blob,
    /// HOST buffer for the expected units.
    pub units_buf: *mut UnitCount,
    /// Its capacity.
    pub units_cap: usize,
}

/// `arrive`'s `out`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ArriveOut {
    /// The head.
    pub head: OutHead,
    /// Index into [`PlaneTail::op_classes`].
    pub op_class: u32,
    /// `PRINCIPAL_*`.
    pub principal_need: u32,
    /// Index into [`PlaneTail::dialects`].
    pub dialect: u32,
    /// Expected units written to `units_buf` (the admission estimate).
    pub units_len: u32,
}

/// `on_piece`'s `in`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OnPieceIn {
    /// The head.
    pub head: InHead,
    /// [`FROM_CALLER`] | [`FROM_FAR_END`].
    pub from: u32,
    /// `PIECE_*` bits.
    pub flags: u32,
    /// The stream.
    pub stream: u64,
    /// The piece's bytes, zero-copy.
    pub bytes: Blob,
    /// With [`PIECE_HAS_STATUS`]: the exact status number.
    pub status_code: u32,
    /// With [`PIECE_HAS_STATUS`]: the status class.
    pub status_class: u32,
    /// HOST buffer for the bytes the plane emits.
    pub reply_buf: *mut u8,
    /// Its capacity.
    pub reply_cap: usize,
    /// HOST buffer for the cumulative units.
    pub units_buf: *mut UnitCount,
    /// Its capacity.
    pub units_cap: usize,
    /// HOST buffer for record writes.
    pub records_buf: *mut RecordWrite,
    /// Its capacity.
    pub records_cap: usize,
    /// HOST buffer for the reply's head fields.
    pub fields_buf: *mut OutField,
    /// Its capacity.
    pub fields_cap: usize,
    /// HOST arena for the bytes of fields and record writes.
    pub arena_buf: *mut u8,
    /// Its capacity.
    pub arena_cap: usize,
}

/// `on_piece`'s `out`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OnPieceOut {
    /// The head.
    pub head: OutHead,
    /// Bytes written to `reply_buf`.
    pub emitted: u64,
    /// `1` = more output is waiting; flush and call again once writable.
    pub more: u32,
    /// `EMIT_*` bits.
    pub flags: u32,
    /// The reply status number, when this piece starts the caller's reply; `0` otherwise.
    pub reply_status: u32,
    /// Fields written to `fields_buf`.
    pub fields_len: u32,
    /// Cumulative units written to `units_buf`.
    pub units_len: u32,
    /// Record writes written to `records_buf`.
    pub records_len: u32,
    /// Bytes written to `arena_buf`.
    pub arena_len: u64,
}

/// `refusal`'s `in`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RefusalIn {
    /// The head.
    pub head: InHead,
    /// `REFUSAL_KERNEL` | `REFUSAL_GATE`.
    pub cause: u32,
    /// The status number the kernel chose.
    pub status: u32,
    /// Index into [`PlaneTail::dialects`].
    pub dialect: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// The refusal text; never secret material.
    pub text: AbiStr,
    /// HOST buffer for the rendered body.
    pub reply_buf: *mut u8,
    /// Its capacity.
    pub reply_cap: usize,
    /// HOST buffer for the reply's head fields.
    pub fields_buf: *mut OutField,
    /// Its capacity.
    pub fields_cap: usize,
    /// HOST arena for the bytes of fields and record writes.
    pub arena_buf: *mut u8,
    /// Its capacity.
    pub arena_cap: usize,
}

/// `refusal`'s `out`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RefusalOut {
    /// The head.
    pub head: OutHead,
    /// Bytes written to `reply_buf`.
    pub emitted: u64,
    /// [`MARK_GATE_REJECTED`] or `0`.
    pub marker: u32,
    /// Fields written to `fields_buf`.
    pub fields_len: u32,
    /// Bytes written to `arena_buf`.
    pub arena_len: u64,
}

/// `serve`'s `in`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ServeIn {
    /// The head.
    pub head: InHead,
    /// Index into the snapshot's admin routes.
    pub route: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// The request target.
    pub target: AbiStr,
    /// The head fields.
    pub fields: *const Field,
    /// How many.
    pub fields_len: usize,
    /// The body, zero-copy.
    pub body: Blob,
    /// HOST buffer for the reply body.
    pub reply_buf: *mut u8,
    /// Its capacity.
    pub reply_cap: usize,
    /// HOST buffer for the reply's head fields.
    pub fields_buf: *mut OutField,
    /// Its capacity.
    pub fields_cap: usize,
    /// HOST arena for the bytes of fields and record writes.
    pub arena_buf: *mut u8,
    /// Its capacity.
    pub arena_cap: usize,
}

/// `serve`'s `out`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ServeOut {
    /// The head.
    pub head: OutHead,
    /// The reply status number.
    pub status: u32,
    /// Fields written to `fields_buf`.
    pub fields_len: u32,
    /// Bytes written to `reply_buf`.
    pub emitted: u64,
    /// Bytes written to `arena_buf`.
    pub arena_len: u64,
}

#[cfg(test)]
#[path = "../tests/plane_kind_tests.rs"]
mod tests;
