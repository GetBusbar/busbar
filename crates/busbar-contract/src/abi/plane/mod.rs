// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE KIND'S ABI (`BUSBAR-1.6.0.md` THE DESIGN, the plugin ABI section): its
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
//! memory. Each `out` states `*_written` and `*_needed` per buffer; the short-buffer rule,
//! with its multi-buffer form, is stated once, on [`OutHead`](crate::abi::mechanism::call::OutHead).
//!
//! BACKPRESSURE IS NOT A SHORT BUFFER: `on_piece`'s reply bytes stream. A full `reply_buf` is READY
//! with `more = 1` (and at least one byte `emitted`); the kernel flushes, waits for the socket to be
//! writable and calls again. `emitted` is therefore never above `reply_cap` and has no `needed`.
//! THAT RE-CALL CARRIES NO NEW BYTES: it is an `on_piece` of the same unit with the SAME `from` as
//! the piece that answered `more = 1`, zero bytes, no `PIECE_*` flags and no status; the piece's
//! bytes were taken whole, and the re-call answers only what the first could not hold (the
//! transport's `YIELD_MORE` re-call, in the plane's terms).
//!
//! ONE UNIT, ONE KEY. The kernel mints the unit's key and hands it to every op of the unit:
//! [`ArriveIn::unit`] and [`OnPieceIn::unit`]. The caller's head (target and fields) crosses ONCE,
//! at `arrive`; a plane keeps what it needs of it keyed by `unit`, and no piece re-sends it.
//!
//! THE KERNEL DRIVES THE ROUTE (`BUSBAR-1.6.0.md` Part 3, the plane driver). The kernel keeps the caller's body
//! and runs its own egress walk. Each attempt starts with an ATTEMPT piece ([`FROM_KERNEL`],
//! [`OnPieceIn::member`], [`OnPieceIn::attempt_no`]); the plane answers with the request bound for
//! the far end, its verb and target as explicit fields ([`OnPieceOut::verb`],
//! [`OnPieceOut::target`]), then its dialect fields and body. Far-end pieces come back
//! [`FROM_FAR_END`], and the plane's answer may carry a `VERDICT_*` beside the walk's status table.
//! When a hook is bound, [`slot::PROJECT`] (pure, once per unit) writes the hook kind's own request
//! view. A duplex session's unsolicited output reaches the kernel through the instance's one driver
//! ticket: `drive` ([`PlaneDriveIn`], [`PlaneDriveOut`]) names the ready sessions.
//!
//! WHAT CROSSES AND WHEN:
//!
//! * STATIC FACTS — the Statement's kind tail, [`PlaneTail`]: `'static`, signed in the manifest.
//! * CONFIG-DEPENDENT FACTS — the GENERATION SNAPSHOT, [`PlaneSnapshot`], answered on `open`
//!   ([`PlaneOpenOut`]) and `refresh` ([`PlaneRefreshOut`]): valid until `retire` of that generation
//!   (memory class (ii)).
//! * SETTINGS — the `settings` blob `validate`, `open` and `refresh` receive has its `rate_card` and
//!   `fees` keys stripped by the kernel before it crosses (RED-tested at the kernel).
//! * NEEDS — a plane states its connection needs as `(transport, auth)` per direction in its tail
//!   ([`PlaneTail::needs`], each a [`Need`]); the kernel instantiates them through the connector.
//!
//! CANCEL BILLING — the four 1.5.5 rules, pinned . The lifecycle `cancel`
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
//! | (new) chained record framing | tail [`PlaneTail::record_chains`] |
//! | `dispatch_flags` / `DISPATCH_BLOCKS` | DROPPED — a plane never blocks (the design's plugin-ABI section: no blocking on the hot path). Replaced by [`PlaneTail::dispatch_shape`] |
//! | `required_sections` | tail: [`SECTION_REQUIRED`] on a [`PlaneTail::sections`] entry |
//! | `BuildCtx.host`, `host_ctx` | [`crate::abi::mechanism::lifecycle::OpenIn::host`] |
//! | `BuildCtx.config_*` | `OpenIn::settings` (`rate_card`/`fees` stripped) |
//! | `BuildCtx.resolved_refs_*` | `OpenIn::secrets` |
//! | `BuildCtx.public_url_*` | [`PlaneOpenIn::public_url`] |
//! | (new) dialects, `dialect_auth`, `route_cost`, `cli_help` | tail |
//! | (new) needs, consumed sections, egress targets | tail [`PlaneTail::needs`], [`SECTION_CONSUMED`], [`PlaneTail::egress_targets`] |
//! | (new) kernel-owned trust keys | tail [`PlaneTail::trust_keys`] |
//!
//! KERNEL-OWNED TRUST KEYS. The trust lifecycle (pin, re-verification cadence, demotion) is the
//! kernel's. A plane whose registrations carry those keys DECLARES them in its tail
//! ([`PlaneTail::trust_keys`], each a [`TrustKey`]): which per-registration key of its declaring
//! section holds the pin ([`TRUST_PIN`]), the re-verification bound ([`TRUST_REVERIFY_TTL`]) and the
//! recovery backoff ([`TRUST_RECOVERY_BACKOFF`]). The kernel parses and validates those keys; the
//! plane's own validator does not.
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
//!     (slot::PROJECT, offset_of!(Ops, project)),
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

use super::hook::{RequestView, SignalEntry};
use super::host::conn::connector::Need;
use super::mechanism::call::{AbiStr, Blob, InHead, Op, OutHead};
pub use super::mechanism::check::SPAN_ABSENT;
use super::mechanism::check::{contract, OpContract};
use super::mechanism::door::KindTailHead;
use super::mechanism::lifecycle::{
    slot as life, CancelIn, CancelOut, DriveIn, GenIn, OpenIn, OpenOut, OpsHead, RefreshIn,
    ReleaseIn, TickIn, TickOut, ValidateIn, LIFECYCLE_SLOTS,
};

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
    /// Project a unit's request into the hook kind's request view.
    pub const PROJECT: u32 = LIFECYCLE_SLOTS + 6;
}

/// How many kind ops the table holds after the lifecycle.
pub const KIND_SLOTS: u32 = 7;
/// How many slots the whole table holds ([`OpsHead::slots`]).
pub const SLOTS: u32 = LIFECYCLE_SLOTS + KIND_SLOTS;

/// The plane kind's ops table: the lifecycle, then the plane's seven ops.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Ops {
    /// The lifecycle. `open` is in [`PlaneOpenIn`], out [`PlaneOpenOut`]; `refresh` out is
    /// [`PlaneRefreshOut`]; `drive` is in [`PlaneDriveIn`], out [`PlaneDriveOut`]; `cancel`
    /// answers a `CANCEL_*` disposition.
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
    /// [`slot::PROJECT`]: in [`ProjectIn`], out [`ProjectOut`].
    pub project: Option<Op>,
}

// ── the op contracts ─────────────────────────────────────────────────────────────────────────────

/// Every kind op's contract, in slot order. `arrive`, `refusal` and `project` are pure: they never
/// pend.
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
    contract!(PROJECT, true, false, ProjectIn, ProjectOut, Call),
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
/// [`PlaneTail::flags`]: the plane answers health probes. A probe is a kernel-originated unit
/// pinned to one member: its `arrive` names [`CLAIM_PROBE`], its ATTEMPT piece asks for the probe
/// request, and it is zero-billed and draws no lease.
pub const TAIL_PROBES: u32 = 1 << 1;

/// [`Claim::flags`]: the route takes no inbound credential; the kernel admits an arrival on it
/// without verifying a caller. Without it, the route takes one.
pub const CLAIM_OPEN: u32 = 1;
/// [`Claim::flags`]: the target matches exactly. Without it, the target is a prefix.
pub const CLAIM_EXACT: u32 = 1 << 1;

/// [`ArriveIn::claim`]: the arrival is a health probe, not a snapshot claim. Only a plane whose
/// tail states [`TAIL_PROBES`] is sent one.
pub const CLAIM_PROBE: u32 = u32::MAX;

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
/// [`OnPieceIn::from`]: the piece is the kernel's. With [`OnPieceIn::attempt_no`] above `0` it
/// is an ATTEMPT piece: the kernel has picked [`OnPieceIn::member`] and asks for the request bound
/// for it (the caller's body is re-pushed on every attempt). With `attempt_no == 0` and no bytes
/// it collects a session's unsolicited output, after `drive` named the session ready.
pub const FROM_KERNEL: u32 = 2;

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

/// [`OnPieceOut::verdict`]: no verdict; the walk's status table alone decides.
pub const VERDICT_NONE: u32 = 0;
/// [`OnPieceOut::verdict`]: the far end's answer is a success.
pub const VERDICT_OK: u32 = 1;
/// [`OnPieceOut::verdict`]: the far end's answer is a failure another member may not share. The
/// walk fails over only before the first byte reaches the caller; after it, a retry is hard.
pub const VERDICT_RETRY: u32 = 2;
/// [`OnPieceOut::verdict`]: the far end's answer is a failure no other member would change.
pub const VERDICT_HARD: u32 = 3;

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

/// [`AdminRoute::flags`]: a public route. [`slot::SERVE`] serves it to an unauthenticated caller;
/// the arrival gate and the audit still run, it meters nothing, and a signature it carries is
/// verified by an auth plugin under the style the plane's inbound need declares.
pub const ROUTE_PUBLIC: u32 = 1;

/// [`RecordChain::framing`]: each field of the record's digest is length-prefixed.
pub const CHAIN_LENGTH_PREFIXED: u32 = 1;
/// [`RecordChain::framing`]: the fields of the record's digest are joined by `|`.
pub const CHAIN_PIPE_SEPARATED: u32 = 2;
/// [`RecordChain::flags`]: the record's scope enters its digest.
pub const CHAIN_DIGESTS_SCOPE: u32 = 1;

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

/// One billable class and the unit family it counts in. Classes are disjoint.
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

/// One chained record kind and the framing its chain keeps. The host frames each record's prelude
/// (previous digest, scope, sequence) in this framing, joins the plane's own field bytes and
/// verifies the chain, so a chain written before this ABI still verifies. A record kind no entry
/// names is not chained. This framing is the plane's record chains' only: the kernel's own audit
/// chain is the one fixed record.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RecordChain {
    /// Index into [`PlaneTail::record_kinds`].
    pub kind: u32,
    /// [`CHAIN_LENGTH_PREFIXED`] | [`CHAIN_PIPE_SEPARATED`].
    pub framing: u32,
    /// [`CHAIN_DIGESTS_SCOPE`] or `0`.
    pub flags: u32,
    /// Alignment padding.
    pub _reserved: u32,
}

/// [`TrustKey::role`]: the key holds the registration's pin object, `{mechanism, key?,
/// fingerprint?}`: which authenticity root it has and the operator's out-of-band material.
pub const TRUST_PIN: u32 = 1;
/// [`TrustKey::role`]: the key holds the longest a verification may be reused before the
/// counterparty is re-verified, a `<n><s|m|h|d>` duration.
pub const TRUST_REVERIFY_TTL: u32 = 2;
/// [`TrustKey::role`]: the key holds how long after a drift a clean answer is disbelieved, a
/// `<n><s|m|h|d>` duration.
pub const TRUST_RECOVERY_BACKOFF: u32 = 3;
/// [`TrustKey::flags`], on a [`TRUST_PIN`] key only: the pin object may also carry `fingerprint`.
pub const PIN_FINGERPRINT: u32 = 1;
/// [`PinMechanism::flags`]: the mechanism is an authenticity root, so a pin naming it needs key
/// material. A mechanism without it is the no-root spelling, which must carry none.
pub const MECHANISM_ROOT: u32 = 1;

/// One pin mechanism a [`TRUST_PIN`] key accepts, as the operator spells it.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PinMechanism {
    /// The config token.
    pub token: AbiStr,
    /// [`MECHANISM_ROOT`] or `0`.
    pub flags: u32,
    /// Alignment padding.
    pub _reserved: u32,
}

/// One per-registration key of the plane's declaring section that the KERNEL parses for the trust
/// lifecycle. At most one key per role.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TrustKey {
    /// The key, as written inside one registration.
    pub key: AbiStr,
    /// [`TRUST_PIN`] | [`TRUST_REVERIFY_TTL`] | [`TRUST_RECOVERY_BACKOFF`].
    pub role: u32,
    /// [`PIN_FINGERPRINT`] on a pin; `0` otherwise.
    pub flags: u32,
    /// A duration key's value when a registration writes none; absent = zero. A pin has none.
    pub default: AbiStr,
    /// A pin's mechanisms; empty for a duration key.
    pub mechanisms: *const PinMechanism,
    /// How many.
    pub mechanisms_len: usize,
}

/// THE PLANE'S STATEMENT TAIL: static facts, `'static` data.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PlaneTail {
    /// The tail head.
    pub head: KindTailHead,
    /// [`TAIL_FALLBACK`] | [`TAIL_PROBES`]; any other bit refuses the load.
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
    /// Its chained record kinds, each with its framing; at most one entry per kind.
    pub record_chains: *const RecordChain,
    /// How many.
    pub record_chains_len: usize,
    /// The per-registration keys the kernel parses for the trust lifecycle.
    pub trust_keys: *const TrustKey,
    /// How many.
    pub trust_keys_len: usize,
}

// ── the generation snapshot ──────────────────────────────────────────────────────────────────────

/// One path the built plane answers on. One route — a verb, a target and whether the target is
/// matched exactly or as a prefix — is claimed at most once in a snapshot.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Claim {
    /// The verb.
    pub verb: AbiStr,
    /// The target path.
    pub target: AbiStr,
    /// The transport claim it arrives over.
    pub carrier: AbiStr,
    /// [`CLAIM_OPEN`] | [`CLAIM_EXACT`]; any other bit refuses the snapshot.
    pub flags: u32,
    /// Alignment padding.
    pub _reserved: u32,
}

/// One admin route the built plane serves through [`slot::SERVE`].
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AdminRoute {
    /// The verb.
    pub verb: AbiStr,
    /// The target path.
    pub target: AbiStr,
    /// [`ROUTE_PUBLIC`] or `0`.
    pub flags: u32,
    /// Alignment padding.
    pub _reserved: u32,
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
    /// The unit, as the kernel minted it: every [`OnPieceIn`] of this unit carries the same key.
    /// The caller's head (`target`, `fields`) crosses here ONCE; a plane keeps what it needs of it
    /// keyed by `unit`, and no piece re-sends it.
    pub unit: u64,
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
    pub units_written: u32,
    /// Short answer: the units `units_buf` needs.
    pub units_needed: u32,
    /// Alignment padding.
    pub _reserved: u32,
}

/// `on_piece`'s `in`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OnPieceIn {
    /// The head.
    pub head: InHead,
    /// The unit, as the kernel minted it: the key its [`ArriveIn::unit`] carried.
    pub unit: u64,
    /// [`FROM_CALLER`] | [`FROM_FAR_END`] | [`FROM_KERNEL`].
    pub from: u32,
    /// `PIECE_*` bits.
    pub flags: u32,
    /// A duplex session's stream, as `drive` names it; `0` for a request unit.
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
    /// On an ATTEMPT piece: the operator's name for the member the kernel picked; absent
    /// otherwise.
    pub member: AbiStr,
    /// On an ATTEMPT piece: the attempt's number, from `1`; `0` on every other piece.
    pub attempt_no: u32,
    /// Alignment padding.
    pub _reserved: u32,
}

/// `on_piece`'s `out`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OnPieceOut {
    /// The head.
    pub head: OutHead,
    /// Bytes written to `reply_buf`.
    pub emitted: u64,
    /// `1` = more output is waiting; flush and call again once writable, with the same `from`,
    /// no bytes and no `PIECE_*` flags.
    pub more: u32,
    /// `EMIT_*` bits.
    pub flags: u32,
    /// The reply status number, when this piece starts the caller's reply; `0` otherwise.
    pub reply_status: u32,
    /// Fields written to `fields_buf`.
    pub fields_written: u32,
    /// Short answer: the fields `fields_buf` needs.
    pub fields_needed: u32,
    /// Cumulative units written to `units_buf`.
    pub units_written: u32,
    /// Short answer: the units `units_buf` needs.
    pub units_needed: u32,
    /// Record writes written to `records_buf`.
    pub records_written: u32,
    /// Short answer: the record writes `records_buf` needs.
    pub records_needed: u32,
    /// `VERDICT_*`: the plane's reading of a far-end answer, beside the walk's status table.
    pub verdict: u32,
    /// Bytes written to `arena_buf`.
    pub arena_written: u64,
    /// Short answer: the bytes `arena_buf` needs.
    pub arena_needed: u64,
    /// The answer to an ATTEMPT piece, with [`EMIT_TO_FAR_END`]: the request's verb, in the
    /// arena; a zero length = none. The kernel adds the auth fields and sends it through the
    /// connector.
    pub verb: Span,
    /// With `verb`: the request's target, in the arena; a zero length = none.
    pub target: Span,
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
    pub reply_written: u64,
    /// Short answer: the bytes `reply_buf` needs.
    pub reply_needed: u64,
    /// Bytes written to `arena_buf`.
    pub arena_written: u64,
    /// Short answer: the bytes `arena_buf` needs.
    pub arena_needed: u64,
    /// [`MARK_GATE_REJECTED`] or `0`.
    pub marker: u32,
    /// Fields written to `fields_buf`.
    pub fields_written: u32,
    /// Short answer: the fields `fields_buf` needs.
    pub fields_needed: u32,
    /// Alignment padding.
    pub _reserved: u32,
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
    /// Bytes written to `reply_buf`.
    pub reply_written: u64,
    /// Short answer: the bytes `reply_buf` needs.
    pub reply_needed: u64,
    /// Bytes written to `arena_buf`.
    pub arena_written: u64,
    /// Short answer: the bytes `arena_buf` needs.
    pub arena_needed: u64,
    /// The reply status number.
    pub status: u32,
    /// Fields written to `fields_buf`.
    pub fields_written: u32,
    /// Short answer: the fields `fields_buf` needs.
    pub fields_needed: u32,
    /// Alignment padding.
    pub _reserved: u32,
}

/// The plane's `drive` `in`: the lifecycle's, plus a HOST buffer for the sessions with output
/// ready. A plane instance holds ONE driver ticket; when a session has unsolicited output the
/// plane wakes it, and `drive` names the ready sessions by their stream. The kernel then calls
/// `on_piece` ([`FROM_KERNEL`], no bytes) once for each.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PlaneDriveIn {
    /// The lifecycle `in`.
    pub drive: DriveIn,
    /// HOST buffer for the streams of the ready sessions.
    pub sessions_buf: *mut u64,
    /// Its capacity.
    pub sessions_cap: usize,
}

/// The plane's `drive` `out`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PlaneDriveOut {
    /// The head.
    pub head: OutHead,
    /// Streams written to `sessions_buf`.
    pub sessions_written: u32,
    /// Short answer: the streams `sessions_buf` needs.
    pub sessions_needed: u32,
}

/// `project`'s `in`: the arrival `arrive` classified, and HOST buffers for the view.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProjectIn {
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
    /// The body, zero-copy.
    pub body: Blob,
    /// HOST buffer for the view's signals.
    pub signals_buf: *mut SignalEntry,
    /// Its capacity.
    pub signals_cap: usize,
    /// HOST arena for the view's strings and the projected body.
    pub arena_buf: *mut u8,
    /// Its capacity.
    pub arena_cap: usize,
}

/// `project`'s `out`: the hook kind's own [`RequestView`], its plane-derived fields written by the
/// plane (its strings in the arena, its signals in `signals_buf`), and the projected body where
/// the plane has one. The kernel fills the request id and every stage field from the route walk.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProjectOut {
    /// The head.
    pub head: OutHead,
    /// The view. `signals` is `signals_buf` and `signals_len` the signals written; `pool` and
    /// `ingress_dialect` lie in the arena.
    pub view: RequestView,
    /// The projected body, in the arena; [`SPAN_ABSENT`] = the plane projects none.
    pub body: Span,
    /// Short answer: the signals `signals_buf` needs.
    pub signals_needed: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// Bytes written to `arena_buf`.
    pub arena_written: u64,
    /// Short answer: the bytes `arena_buf` needs.
    pub arena_needed: u64,
}

// THE SDK's VIEW OF THE PLANE TABLE (`abi::sdk::door`): each kind op's `in`/`out`, stated next to
// the table, so `plugin_door!` refuses a plane plugin that wires a kind op to another op's
// structs. Every struct named here is plain data (integers, raw pointers, `AbiStr`/`Blob`, nested
// plain structs): every bit pattern is a valid value, which is what `AbiIn`/`AbiOut` promise.
//
// SAFETY (all below): `#[repr(C)]`, leading with `InHead`/`OutHead`, plain data only.
unsafe impl super::sdk::door::AbiIn for PlaneOpenIn {}
unsafe impl super::sdk::door::AbiIn for PlaneDriveIn {}
unsafe impl super::sdk::door::AbiIn for ArriveIn {}
unsafe impl super::sdk::door::AbiIn for OnPieceIn {}
unsafe impl super::sdk::door::AbiIn for RefusalIn {}
unsafe impl super::sdk::door::AbiIn for ServeIn {}
unsafe impl super::sdk::door::AbiIn for ProjectIn {}
unsafe impl super::sdk::door::AbiOut for PlaneOpenOut {}
unsafe impl super::sdk::door::AbiOut for PlaneRefreshOut {}
unsafe impl super::sdk::door::AbiOut for PlaneDriveOut {}
unsafe impl super::sdk::door::AbiOut for ArriveOut {}
unsafe impl super::sdk::door::AbiOut for OnPieceOut {}
unsafe impl super::sdk::door::AbiOut for RefusalOut {}
unsafe impl super::sdk::door::AbiOut for ServeOut {}
unsafe impl super::sdk::door::AbiOut for ProjectOut {}

// Each plane kind op's `in`/`out`, per [`Ops`]' docs.
super::sdk::door::slot_structs!(Ops {
    slot::ARRIVE => ArriveIn, ArriveOut;
    slot::ON_PIECE => OnPieceIn, OnPieceOut;
    slot::REFUSAL => RefusalIn, RefusalOut;
    slot::SERVE => ServeIn, ServeOut;
    slot::HYDRATE => GenIn, OutHead;
    slot::START => GenIn, OutHead;
    slot::PROJECT => ProjectIn, ProjectOut;
});

/// The plane's LIFECYCLE `in`/`out` ([`KindOps::Lifecycle`](super::sdk::door::KindOps::Lifecycle)):
/// the lifecycle's own, except `open` ([`PlaneOpenIn`], [`PlaneOpenOut`]) and `refresh`
/// ([`PlaneRefreshOut`]), which carry the generation snapshot, and `drive` ([`PlaneDriveIn`],
/// [`PlaneDriveOut`]), which names the ready sessions.
///
/// A plane plugin wiring a slot to another op's structs does not compile, a kind op:
///
/// ```compile_fail,E0271
/// use busbar_contract::abi::plane::*;
/// use busbar_contract::abi::mechanism::call::{InHead, OutHead, Outcome};
/// use busbar_contract::abi::mechanism::lifecycle::*;
/// use busbar_contract::abi::sdk::door::Slot;
/// # use std::ffi::c_void;
/// # macro_rules! ready { ($n:ident, $i:ty, $o:ty) => {
/// #     struct $n;
/// #     impl Slot for $n { type In = $i; type Out = $o;
/// #         fn call(_: *mut c_void, _: &$i, _: &mut $o) -> Outcome { Outcome::Ready } }
/// # } }
/// # ready!(V, ValidateIn, OutHead); ready!(Op_, PlaneOpenIn, PlaneOpenOut);
/// # ready!(Rf, RefreshIn, PlaneRefreshOut);
/// # ready!(Rt, GenIn, OutHead); ready!(Tk, TickIn, TickOut);
/// # ready!(Dr, PlaneDriveIn, PlaneDriveOut);
/// # ready!(Cn, CancelIn, CancelOut); ready!(Rl, ReleaseIn, OutHead); ready!(Cl, InHead, OutHead);
/// # ready!(Arrive, ArriveIn, ArriveOut); ready!(Refusal, RefusalIn, RefusalOut);
/// # ready!(Serve, ServeIn, ServeOut); ready!(Hydrate, GenIn, OutHead);
/// # ready!(Start, GenIn, OutHead); ready!(Project, ProjectIn, ProjectOut);
/// ready!(OnPiece, RefusalIn, RefusalOut); // `refusal`'s structs on `on_piece`: refused
/// busbar_contract::plugin_door! {
///     ops: busbar_contract::abi::plane::Ops,
///     statement: busbar_contract::abi::sdk::door::statement("wrong", "0", 1),
///     lifecycle: { validate: V, open: Op_, refresh: Rf, retire: Rt, tick: Tk, drive: Dr,
///                  cancel: Cn, release: Rl, close: Cl },
///     kind_ops: { arrive: Arrive, on_piece: OnPiece, refusal: Refusal, serve: Serve,
///                 hydrate: Hydrate, start: Start, project: Project },
/// }
/// # fn main() { let _ = door(); }
/// ```
///
/// or a lifecycle slot (an `open` writing the lifecycle's `OpenOut`, with no snapshot):
///
/// ```compile_fail,E0271
/// use busbar_contract::abi::plane::*;
/// use busbar_contract::abi::mechanism::call::{InHead, OutHead, Outcome};
/// use busbar_contract::abi::mechanism::lifecycle::*;
/// use busbar_contract::abi::sdk::door::Slot;
/// # use std::ffi::c_void;
/// # macro_rules! ready { ($n:ident, $i:ty, $o:ty) => {
/// #     struct $n;
/// #     impl Slot for $n { type In = $i; type Out = $o;
/// #         fn call(_: *mut c_void, _: &$i, _: &mut $o) -> Outcome { Outcome::Ready } }
/// # } }
/// # ready!(V, ValidateIn, OutHead); ready!(Rf, RefreshIn, PlaneRefreshOut);
/// ready!(Op_, OpenIn, OpenOut); // the lifecycle's `open`, no snapshot: refused
/// # ready!(Rt, GenIn, OutHead); ready!(Tk, TickIn, TickOut);
/// # ready!(Dr, PlaneDriveIn, PlaneDriveOut);
/// # ready!(Cn, CancelIn, CancelOut); ready!(Rl, ReleaseIn, OutHead); ready!(Cl, InHead, OutHead);
/// # ready!(Arrive, ArriveIn, ArriveOut); ready!(Refusal, RefusalIn, RefusalOut);
/// # ready!(Serve, ServeIn, ServeOut); ready!(Hydrate, GenIn, OutHead);
/// # ready!(Start, GenIn, OutHead); ready!(Project, ProjectIn, ProjectOut);
/// # ready!(OnPiece, OnPieceIn, OnPieceOut);
/// busbar_contract::plugin_door! {
///     ops: busbar_contract::abi::plane::Ops,
///     statement: busbar_contract::abi::sdk::door::statement("wrong", "0", 1),
///     lifecycle: { validate: V, open: Op_, refresh: Rf, retire: Rt, tick: Tk, drive: Dr,
///                  cancel: Cn, release: Rl, close: Cl },
///     kind_ops: { arrive: Arrive, on_piece: OnPiece, refusal: Refusal, serve: Serve,
///                 hydrate: Hydrate, start: Start, project: Project },
/// }
/// # fn main() { let _ = door(); }
/// ```
///
/// With `OnPiece` reading [`OnPieceIn`] and writing [`OnPieceOut`] the same plugin compiles
/// (`abi/sdk/tests/door_tests.rs`, `a_plane_plugin_wires_every_kind_op`).
#[derive(Debug, Clone, Copy)]
pub struct PlaneLifecycle;

super::sdk::door::slot_structs!(PlaneLifecycle {
    life::VALIDATE => ValidateIn, OutHead;
    life::OPEN => PlaneOpenIn, PlaneOpenOut;
    life::REFRESH => RefreshIn, PlaneRefreshOut;
    life::RETIRE => GenIn, OutHead;
    life::TICK => TickIn, TickOut;
    life::DRIVE => PlaneDriveIn, PlaneDriveOut;
    life::CANCEL => CancelIn, CancelOut;
    life::RELEASE => ReleaseIn, OutHead;
    life::CLOSE => InHead, OutHead;
});

#[cfg(test)]
#[path = "../tests/plane_kind_tests.rs"]
mod tests;
