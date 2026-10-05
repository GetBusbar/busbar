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
//! view, its prompt view and the body's end user; a request-stage hook's rewrite comes back to it
//! as [`ProjectIn::rewrite`], which the plane applies to the body ([`ProjectOut::rewritten`]) and
//! re-projects. A duplex session's unsolicited output reaches the kernel through the instance's one driver
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
//! * NEEDS — a plane states its connection needs as `(transport, auth)` per direction in its
//!   Statement, as every kind does ([`Statement::needs`](crate::abi::mechanism::door::Statement),
//!   each a `Need`); the kernel instantiates them through the connector.
//!
//! CANCEL BILLING — the four 1.5.5 rules, pinned . The lifecycle `cancel`
//! answers a disposition ([`CANCEL_OK_PARTIAL`], [`CANCEL_FAILED`], [`CANCEL_ABORTED`]) and the
//! kernel bills from it by [`cancel_bills_reported_units`]:
//!
//! 1. A TRANSLATE-ABORT IS NEVER BILLED: a unit the plane aborted before the far end answered is
//!    [`CANCEL_ABORTED`], and bills nothing.
//! 2. ONLY FAR-END-REPORTED USAGE IS BILLED: of the cumulative units the last piece reported, only
//!    those whose source bills ([`units_bill`]: [`UNITS_REPORTED`], and [`UNITS_FLOOR`] for a
//!    delivered reply whose usage could not be read) count; [`UNITS_ESTIMATED`] never bills.
//! 3. A NON-STREAMED PARTIAL BILLS ZERO: [`CANCEL_OK_PARTIAL`] bills the reported units only when
//!    the reply was streamed to the caller; a cut whole-body reply bills `0`.
//! 4. THE BUDGET REFUND IS A SEPARATE ACT: whatever the disposition, the kernel releases the unit's
//!    budget hold on its own path; cancel billing never folds the refund in and never returns it.
//!
//! [`CANCEL_FAILED`] bills nothing.
//!
//! # The cancel rule
//!
//! A caller can cancel one of its own in-flight units by name. `arrive` names every unit it
//! classifies with an optional [`ArriveOut::correlation`]. The CANCEL KEY is (connection, the
//! arrival's authenticated principal, correlation): the principal is the one the kernel verified
//! for the arrival, never a value a plane reports, so a correlation is never connection-wide. A
//! subsequent arrival whose [`ArriveOut::cancels`] equals a live unit's correlation under the same
//! connection and principal is a cancel:
//!
//! 1. The cancel acts only AFTER its own arrival has passed the same authentication as any arrival.
//!    An arrival that is unauthenticated, or refused, cancels nothing.
//! 2. The kernel ends the named unit, whatever its shape (a one-shot unit included), through the
//!    lifecycle `cancel`, and bills it by [`cancel_bills_reported_units`] like any other cut. A
//!    cancel racing the unit's own end settles the unit's hold exactly once.
//! 3. The named unit is SILENCED: nothing of its reply that has not already reached the caller is
//!    written after the cancel.
//! 4. The cancel itself is a notice: it opens no hold, bills nothing and writes no reply.
//! 5. A `cancels` value naming no live unit, a finished unit, another connection's unit or ANOTHER
//!    PRINCIPAL's unit matches nothing and is ignored silently. It is never an error and never
//!    reveals that another principal's unit exists.
//! 6. A DUPLICATE correlation (an arrival whose key is already held by a live unit) is served, but
//!    it gets no cancel key: the key stays with the unit that claimed it first, the duplicate can
//!    never be cancelled by name, and a cancel naming the key ends only the first. That is the
//!    served baseline's behaviour, and the claim is never displaced.
//!
//! The kernel's key table is bounded by the connection's in-flight units: an entry leaves at its
//! unit's end, and the whole table at the connection's close. When to emit a cancel is the plane's
//! call; a plane whose dialect defines cancel only on some carriers leaves `cancels` at `0`
//! everywhere else.
//!
//! # The catalogue-moved tick
//!
//! A session that asked to be told when the catalogue moves ([`EMIT_WATCH_CATALOGUE`] on any of
//! its pieces) is given a [`PIECE_CATALOGUE_MOVED`] piece ([`FROM_KERNEL`], no bytes) on its stream
//! when the catalogue generation moves. The watch is keyed by (session stream, the session's
//! authenticated principal, the one the kernel verified); a repeated WATCH is idempotent, and
//! [`EMIT_UNWATCH_CATALOGUE`] drops it, as does the session ending or being evicted, so the watch
//! set is bounded by live sessions. The kernel holds AT MOST ONE pending tick per watch: moves that
//! land while one is pending coalesce into it, so a slow plane never queues ticks. The plane keeps
//! what the session watches (its own bounded state) and answers the tick with whatever it tells the
//! session, or with nothing; a watch never widens what the session's principal may see.
//!
//! # A refused arrival
//!
//! An `arrive` that answers REFUSED states why in its `head.error`: the plane's own words, at most
//! [`MAX_REFUSAL_TEXT`] bytes. The kernel carries them to the plane's `refusal` as
//! [`RefusalIn::text`] with [`REFUSAL_ARRIVE`] and the arrival's claimant dialect, so the caller
//! is answered in the plane's dialect and words:
//!
//! 1. The bytes are opaque: the kernel never parses or changes them.
//! 2. More than [`MAX_REFUSAL_TEXT`] is a FAULT of that `arrive`; the kernel refuses the arrival in
//!    its own words ([`REFUSAL_KERNEL`]) and never cuts the text.
//! 3. The text reaches the caller only through the plane's `refusal` rendering.
//! 4. The kernel never logs or audits the text, since it may echo what the caller sent.
//! 5. [`MAX_REFUSAL_TEXT`] is at or above the largest field line a transport admits, so words that
//!    echo a field line the caller sent never overflow it.
//! 6. A REFUSAL ABOUT AN ENTRY (ARCHITECT Q-DEL-A2A-GATE: "refused → audits the refusal; nothing
//!    was charged", and the caller's grant is judged before the entry's standing): a REFUSED
//!    `arrive` that names the entry its refusal concerns ([`ArriveOut::pool`] with a
//!    [`ROUTE_POOL`] or [`ROUTE_DIRECT`] [`ArriveOut::route`], and its operation class and
//!    dialect) is held: the kernel judges the caller's identity and its grant over that entry
//!    first (a refusal there wins), then renders this refusal before admission, so nothing is
//!    charged. Its status may be 400 to 599 (the entry, not the caller, may be at fault).
//!
//! [`RefusalOut::status`] lets the rendering name the status its dialect answers with; `0` keeps
//! the one the kernel chose. The gate-rejected audit marker is the kernel's: it sets it from
//! [`REFUSAL_GATE`], and a plane never sets [`RefusalOut::marker`].
//!
//! EVERY `PlaneDecl` FIELD, AND WHERE IT WENT (nothing dropped silently):
//!
//! | hot-lane `PlaneDecl` / `BuildCtx` | here |
//! |---|---|
//! | `abi` (preamble), `size`, `version` | the door: magic, mechanism version, `kind_abi`; [`crate::abi::mechanism::door::KindTailHead::size`] |
//! | `name` | [`crate::abi::mechanism::door::Statement::name`] |
//! | `section_key` | Statement: the `sections` entry flagged [`SECTION_DECLARING`](crate::abi::mechanism::door::SECTION_DECLARING) |
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
//! | (new) refusal statuses per dialect and reason | tail [`PlaneTail::refusal_statuses`]; [`RefusalIn::reason`] |
//! | `dispatch_flags` / `DISPATCH_BLOCKS` | DROPPED — a plane never blocks (the design's plugin-ABI section: no blocking on the hot path). Replaced by [`PlaneTail::dispatch_shape`] |
//! | `required_sections` | Statement: [`SECTION_REQUIRED`](crate::abi::mechanism::door::SECTION_REQUIRED) on a `sections` entry |
//! | `BuildCtx.host`, `host_ctx` | [`crate::abi::mechanism::lifecycle::OpenIn::host`] |
//! | `BuildCtx.config_*` | `OpenIn::settings` (`rate_card`/`fees` stripped) |
//! | `BuildCtx.resolved_refs_*` | `OpenIn::secrets` |
//! | `BuildCtx.public_url_*` | [`PlaneOpenIn::public_url`] |
//! | (new) dialects, `dialect_auth`, `route_cost`, `cli_help` | tail |
//! | (new) needs, consumed sections, egress targets | Statement `needs`, [`SECTION_CONSUMED`](crate::abi::mechanism::door::SECTION_CONSUMED); tail [`PlaneTail::egress_targets`] |
//! | (new) kernel-owned trust keys | tail [`PlaneTail::trust_keys`] |
//! | (new) the section-level caller-credential refusal | tail [`PlaneTail::caller_credential_refusal`] |
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

use super::hook::{MessageView, PromptView, RequestView, SignalEntry};
use super::mechanism::call::{AbiStr, Blob, Field, InHead, Op, OutHead, Span};
pub use super::mechanism::check::SPAN_ABSENT;
use super::mechanism::check::{contract, OpContract};
use super::mechanism::door::KindTailHead;
use super::mechanism::lifecycle::{
    slot as life, CancelIn, CancelOut, DriveIn, GenIn, OpenIn, OpenOut, OpsHead, RefreshIn,
    ReleaseIn, TickIn, TickOut, ValidateIn, LIFECYCLE_SLOTS,
};
use crate::caps::ReasonCode;

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
/// [`PlaneTail::flags`]: the plane's request-stage hooks run GATE-FIRST (spec Part 3 section 12
/// "Hooks": in the hook order the previous release used for that plane; ARCHITECT ruling
/// Q-FOLD-A2A-2). The decision gates attached to the entry the plane's `project` names
/// ([`crate::abi::hook::RequestView::pool`]) screen its projected body first — keyed on the view's
/// session for the incremental scan, fail-closed, a refusal at the hook's own clamped status — and
/// then the entry's rewrite chain runs; no stage tap and no route policy fires. Without it the
/// hooks run in the routed order: the rewrite chain, the request taps, then the route decision.
pub const TAIL_HOOKS_GATED: u32 = 1 << 2;

/// [`Claim::flags`]: the route takes no inbound credential; the kernel admits an arrival on it
/// without verifying a caller. Without it, the route takes one.
pub const CLAIM_OPEN: u32 = 1;
/// [`Claim::flags`]: the target matches exactly. Without it (and without [`CLAIM_PATTERN`]), the
/// target is a one-level prefix.
pub const CLAIM_EXACT: u32 = 1 << 1;
/// [`Claim::flags`]: the target is a path pattern. Each `/`-separated segment is a literal, or a
/// placeholder spelled `{name}` that matches exactly one non-empty segment with no `/`. The host
/// reads it as the claim grammar's segment pattern ([`check::claim_selector`]), so the registry's
/// sealed precedence is unchanged: exact beats pattern beats prefix. Never with [`CLAIM_EXACT`].
pub const CLAIM_PATTERN: u32 = 1 << 2;

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

/// [`UnitCount::source`]: the plane's own estimate; never billed.
pub const UNITS_ESTIMATED: u32 = 0;
/// [`UnitCount::source`]: the far end reported it; it bills.
pub const UNITS_REPORTED: u32 = 1;
/// [`UnitCount::source`]: the plane's floor for a delivered reply whose far-end usage could not be
/// read (the usage floor, Q24/Q28: 1.5.5's truncated-tail estimate bills, never 0). It bills like
/// [`UNITS_REPORTED`]; the plane decides when it applies, the kernel adds no floor of its own.
pub const UNITS_FLOOR: u32 = 2;

/// THE ONE BILLING RULE ON A COUNT'S SOURCE: [`UNITS_REPORTED`] and [`UNITS_FLOOR`] bill;
/// [`UNITS_ESTIMATED`] (and any other value) never does. Every kernel site that ledgers, meters or
/// reads a fee unit from a plane's counts asks this, never a source compare of its own.
pub const fn units_bill(source: u32) -> bool {
    matches!(source, UNITS_REPORTED | UNITS_FLOOR)
}

/// [`ArriveOut::principal_need`]: no principal.
pub const PRINCIPAL_NONE: u32 = 0;
/// [`ArriveOut::principal_need`]: the kernel must verify a principal before the first piece.
pub const PRINCIPAL_REQUIRED: u32 = 1;
/// [`ArriveOut::principal_need`]: verify one if the caller presents it.
pub const PRINCIPAL_OPTIONAL: u32 = 2;

/// [`ArriveOut::route`]: the entry names a POOL of the plane's section; the walk keys its state by
/// (plane key, pool) and its rows carry the pool's label. The all-zero default.
pub const ROUTE_POOL: u8 = 0;
/// [`ArriveOut::route`]: the entry names one MODEL entry, routed directly; the walk keys its state by
/// (plane key, model entry) and its meter and ledger rows carry 1.5.5's empty pool label.
pub const ROUTE_DIRECT: u8 = 1;
/// [`ArriveOut::route`]: the plane ANSWERS THIS UNIT ITSELF and names no entry
/// ([`ArriveOut::pool`] absent): the kernel admits it with no route walk, and with only far-end
/// reported units billing, it bills nothing; it is audited as every unit is (ARCHITECT Q-L3B-LOCAL,
/// refining Q-SW6's "none named is refused").
pub const ROUTE_LOCAL: u8 = 2;
/// [`ArriveOut::route`]: the unit names no entry and is ROUTED BY THE PRINCIPAL'S SCOPE
/// ([`ArriveOut::pool`] absent): the kernel resolves it to the ONE entry of the plane's section the
/// principal's grant of the plane's scope kind reaches, and routes it directly to that entry (the
/// attempt's member names it). [`ArriveOut::pool`] may name the CANDIDATE entries — the ones the
/// plane would serve this unit at (those serving, whose capabilities fit it) — joined by
/// [`ROUTE_SCOPE_SEPARATOR`]; the kernel then resolves over the grant's reach intersected with
/// them (ARCHITECT Q-DEL-A2A-SCOPE-TRUST); absent, every entry is a candidate. Zero or several reachable entries refuse it `no_destination`, before
/// anything is charged, which the plane renders in its own words through `refusal`: its
/// [`RefusalIn::text`] names the reachable candidate entries, joined by [`ROUTE_SCOPE_SEPARATOR`]
/// (empty when none reach) (ARCHITECT Q-DEL-A2A-SELECT: scope seals the destinations).
pub const ROUTE_SCOPE: u8 = 3;
/// What joins the reachable entries a [`ROUTE_SCOPE`] refusal's [`RefusalIn::text`] names.
pub const ROUTE_SCOPE_SEPARATOR: &str = ", ";

/// [`ArriveOut::route_flags`]: the unit's operation is performed AT MOST ONCE (ARCHITECT round 4
/// Q-L3B-SURFACES (h): the walk does repeatable). A walk over a pool still moves to another member
/// before anything was answered (a refused connection, an open breaker), but a member that ANSWERED
/// with a failure is not retried on another: its answer is the unit's. Unset, an answered failure
/// fails over as the walk's status table says.
pub const ROUTE_ONCE: u8 = 1;

/// [`ArriveOut::route_flags`]: the unit is served as a DUPLEX SESSION (K6; ARCHITECT round 5
/// Q-L3B-K6-HTTP (a)): its route leg is the driver's session, whose caller leg is the unit's own
/// caller side (its read yields the arrival's body once, then nothing until the caller goes). Its
/// pieces name the unit's stream ([`OnPieceIn::stream`]), its unsolicited output is named on the
/// instance's driver ticket (`drive`) and collected on the session's caller-side ticket, and it is
/// one unit with one line. Unset, the unit's route is one request's.
pub const ROUTE_SESSION: u8 = 2;

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
/// [`OnPieceIn::flags`], [`FROM_FAR_END`]: the bytes are a head of the far end's fields that
/// follows its body (trailers), as the transport rendered them. The plane decides: one whose far
/// end reports its outcome there (a trailer status) reads it, any other ignores the piece. The
/// kernel never drops or reads it.
pub const PIECE_FIELDS: u32 = 1 << 3;
/// [`OnPieceIn::flags`]: the CATALOGUE-MOVED TICK. With [`FROM_KERNEL`], `attempt_no == 0` and no
/// bytes, on a session's [`OnPieceIn::stream`], it says the catalogue generation that session
/// watches ([`EMIT_WATCH_CATALOGUE`]) moved since the last tick it was given. The plane answers
/// with whatever it tells the session about the move, or with nothing. See
/// the catalogue-moved tick in this module's documentation.
pub const PIECE_CATALOGUE_MOVED: u32 = 1 << 4;

/// [`OnPieceOut::flags`]: the emitted bytes go to the far end (else to the caller).
pub const EMIT_TO_FAR_END: u32 = 1;
/// [`OnPieceOut::flags`]: the unit's reply is complete.
pub const EMIT_DONE: u32 = 1 << 1;
/// [`OnPieceOut::flags`]: the bytes this answer emits are ONE text message (a carrier with text and
/// binary messages sends them as text). Only on an answer that emits at least one byte and
/// completes its message (`more == 0`).
pub const PIECE_OUT_TEXT: u32 = 1 << 2;
/// [`OnPieceOut::flags`]: WATCH. From now on, this piece's session is given a
/// [`PIECE_CATALOGUE_MOVED`] tick whenever the catalogue generation moves. The watch is keyed by
/// (session stream, the session's authenticated principal) and is the kernel's to hold; a repeated
/// WATCH is idempotent.
pub const EMIT_WATCH_CATALOGUE: u32 = 1 << 3;
/// [`OnPieceOut::flags`]: DROP the watch [`EMIT_WATCH_CATALOGUE`] set for this piece's session. The
/// kernel also drops it on its own when the session ends or is evicted. Never set together with
/// [`EMIT_WATCH_CATALOGUE`].
pub const EMIT_UNWATCH_CATALOGUE: u32 = 1 << 4;

/// Whether every flag in `flags` is one bit and no two share it. Each flag set below is asserted
/// with it, so two lanes that pick the same bit for different flags fail to compile.
const fn one_bit_each(flags: &[u32]) -> bool {
    let mut seen = 0u32;
    let mut i = 0;
    while i < flags.len() {
        let f = flags[i];
        if f.count_ones() != 1 || seen & f != 0 {
            return false;
        }
        seen |= f;
        i += 1;
    }
    true
}
const _: () = assert!(one_bit_each(&[
    PIECE_END_OF_FRAME,
    PIECE_LAST,
    PIECE_HAS_STATUS,
    PIECE_FIELDS,
    PIECE_CATALOGUE_MOVED,
]));
const _: () = assert!(one_bit_each(&[
    EMIT_TO_FAR_END,
    EMIT_DONE,
    PIECE_OUT_TEXT,
    EMIT_WATCH_CATALOGUE,
    EMIT_UNWATCH_CATALOGUE,
]));

/// [`OnPieceOut::verdict`]: no verdict; the walk's status table alone decides.
pub const VERDICT_NONE: u32 = 0;
/// [`OnPieceOut::verdict`]: the far end's answer is a success.
pub const VERDICT_OK: u32 = 1;
/// [`OnPieceOut::verdict`]: the far end's answer is a failure another member may not share. The
/// walk fails over only before the first byte reaches the caller; after it, a retry is hard. On
/// the caller's body bound for the far end, answered with nothing at all, it DECLINES the attempt's
/// member (one this unit may not reach): nothing is sent and the walk moves to its next member.
pub const VERDICT_RETRY: u32 = 2;
/// [`OnPieceOut::verdict`]: the far end's answer is a failure no other member would change.
pub const VERDICT_HARD: u32 = 3;

/// [`RefusalIn::cause`]: the kernel refused.
pub const REFUSAL_KERNEL: u32 = 0;
/// [`RefusalIn::cause`]: a gate refused.
pub const REFUSAL_GATE: u32 = 1;
/// [`RefusalIn::cause`]: the plane refused its own arrival; [`RefusalIn::text`] is that arrival's
/// words (see "A refused arrival" in this module's documentation).
pub const REFUSAL_ARRIVE: u32 = 2;
/// The most bytes of text a REFUSED `arrive` may carry in its `head.error`. More is a FAULT of
/// that `arrive`: the words are refused whole, never cut. It is at or above the largest field
/// line a transport admits ([`LARGEST_ADMITTED_FIELD_LINE`]), so an echoed field never overflows.
pub const MAX_REFUSAL_TEXT: u64 = 512 * 1024;
/// The largest field line a transport admits: a textual head is read into at most 8 KiB plus
/// 100 x 4 KiB (its library's default read buffer), and one field line may fill it; a binary
/// field list is admitted up to 16 KiB.
pub const LARGEST_ADMITTED_FIELD_LINE: u64 = 8192 + 4096 * 100;
const _: () = assert!(MAX_REFUSAL_TEXT >= LARGEST_ADMITTED_FIELD_LINE);
/// The gate-rejected audit marker (the `GateRejected` marker the kernel keeps). The kernel sets it
/// from [`REFUSAL_GATE`]; [`RefusalOut::marker`] from a plane is always `0`.
pub const MARK_GATE_REJECTED: u32 = 1;

/// [`RecordWrite::op`]: put, the one write to a record kind of the plane's own. A put of an EMPTY
/// value is a tombstone: the record reads as absent. A code that is neither it nor
/// [`RECORD_AUDIT`] is FAULT, never a write the kernel drops.
pub const RECORD_PUT: u32 = 1;
/// [`RecordWrite::op`]: THE UNIT'S AUDIT RECORD, a row on the kernel's own audit chain (the one
/// fixed record), not a record of the plane's: its `key` is the row's action, its `value` the
/// resource it names, and its `kind` the row's outcome, [`AUDIT_APPLIED`] or [`AUDIT_REJECTED`]
/// (not a record kind). The kernel writes the row under the unit's principal, which the plane never
/// sees. The action and the resource are UTF-8, the action never empty. (`2` is the retired
/// delete and never reused.)
pub const RECORD_AUDIT: u32 = 3;

/// [`AdminRoute::flags`]: a public route. [`slot::SERVE`] serves it to an unauthenticated caller;
/// the arrival gate and the audit still run, it meters nothing, and a signature it carries is
/// verified by an auth plugin under the style the plane's inbound need declares.
pub const ROUTE_PUBLIC: u32 = 1;

/// [`ServeOut::audit`]: no audit row.
pub const AUDIT_NONE: u32 = 0;
/// [`ServeOut::audit`]: the request applied; the row's outcome is `applied`.
pub const AUDIT_APPLIED: u32 = 1;
/// [`ServeOut::audit`]: the request was rejected after it was judged; the row's outcome is
/// `rejected`.
pub const AUDIT_REJECTED: u32 = 2;

/// [`RecordChain::framing`]: each field of the record's digest is length-prefixed.
pub const CHAIN_LENGTH_PREFIXED: u32 = 1;
/// [`RecordChain::framing`]: the fields of the record's digest are joined by `|`.
pub const CHAIN_PIPE_SEPARATED: u32 = 2;
/// [`RecordChain::flags`]: the record's scope enters its digest.
pub const CHAIN_DIGESTS_SCOPE: u32 = 1;

/// [`RefusalStatus::dialect`]: the row holds for every dialect the plane has no row of its own for.
pub const REFUSAL_ANY_DIALECT: u32 = u32::MAX;

/// THE WIRE REFUSAL CODES: a refusal reason as it crosses the plane ABI ([`RefusalStatus::reason`],
/// [`RefusalIn::reason`]). Every number is written out and the table is APPEND-ONLY: a code never
/// changes meaning, and a reason the kernel's vocabulary gains takes the next number here. The
/// kernel's vocabulary maps to and from it ([`reason_code`], [`reason_of`]; both matches are
/// exhaustive, so a new reason cannot be left off). This crate's tests pin every code to its word.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RefusalCode {
    /// `InFlightCap`.
    InFlightCap = 0,
    /// `CursorBudget`.
    CursorBudget = 1,
    /// `CredentialBudget`.
    CredentialBudget = 2,
    /// `SessionBudget`.
    SessionBudget = 3,
    /// `SpillBudget`.
    SpillBudget = 4,
    /// `ScratchExhausted`.
    ScratchExhausted = 5,
    /// `RateLimited`.
    RateLimited = 6,
    /// `BodyTooLarge`.
    BodyTooLarge = 7,
    /// `OpenSlotBusy`.
    OpenSlotBusy = 8,
    /// `DecodeFailed`.
    DecodeFailed = 9,
    /// `SchemeNotDeclared`.
    SchemeNotDeclared = 10,
    /// `SessionUnbound`.
    SessionUnbound = 11,
    /// `Unauthenticated`.
    Unauthenticated = 12,
    /// `ChallengeExhausted`.
    ChallengeExhausted = 13,
    /// `Revoked`.
    Revoked = 14,
    /// `ScopeDenied`.
    ScopeDenied = 15,
    /// `PoolNotPermitted`.
    PoolNotPermitted = 16,
    /// `NoRate`.
    NoRate = 17,
    /// `HookVeto`.
    HookVeto = 18,
    /// `NoDestination`.
    NoDestination = 19,
    /// `OverBudget`.
    OverBudget = 20,
    /// `GroupFrozen`.
    GroupFrozen = 21,
    /// `Unpriced`.
    Unpriced = 22,
    /// `OverdraftCeiling`.
    OverdraftCeiling = 23,
    /// `StaleSlice`.
    StaleSlice = 24,
    /// `DurabilityUnavailable`.
    DurabilityUnavailable = 25,
    /// `TierMismatch`.
    TierMismatch = 26,
    /// `Replayed`.
    Replayed = 27,
    /// `InFlight`.
    InFlight = 28,
    /// `DestinationBudgetExhausted`.
    DestinationBudgetExhausted = 29,
    /// `BreakerOpen`.
    BreakerOpen = 30,
    /// `DestinationUnreachable`.
    DestinationUnreachable = 31,
    /// `MeterDisputed`.
    MeterDisputed = 32,
    /// `HandoffMismatch`.
    HandoffMismatch = 33,
    /// `PlanePanic`.
    PlanePanic = 34,
    /// `TaskLost`.
    TaskLost = 35,
    /// `Stalled`.
    Stalled = 36,
    /// `SecretPlaceholder`.
    SecretPlaceholder = 37,
    /// `Drain`.
    Drain = 38,
    /// `Superseded`.
    Superseded = 39,
    /// `ClientGone`.
    ClientGone = 40,
    /// `DeadlineExceeded`.
    DeadlineExceeded = 41,
}

impl RefusalCode {
    /// Every code, in number order.
    pub const ALL: &'static [RefusalCode] = &[
        RefusalCode::InFlightCap,
        RefusalCode::CursorBudget,
        RefusalCode::CredentialBudget,
        RefusalCode::SessionBudget,
        RefusalCode::SpillBudget,
        RefusalCode::ScratchExhausted,
        RefusalCode::RateLimited,
        RefusalCode::BodyTooLarge,
        RefusalCode::OpenSlotBusy,
        RefusalCode::DecodeFailed,
        RefusalCode::SchemeNotDeclared,
        RefusalCode::SessionUnbound,
        RefusalCode::Unauthenticated,
        RefusalCode::ChallengeExhausted,
        RefusalCode::Revoked,
        RefusalCode::ScopeDenied,
        RefusalCode::PoolNotPermitted,
        RefusalCode::NoRate,
        RefusalCode::HookVeto,
        RefusalCode::NoDestination,
        RefusalCode::OverBudget,
        RefusalCode::GroupFrozen,
        RefusalCode::Unpriced,
        RefusalCode::OverdraftCeiling,
        RefusalCode::StaleSlice,
        RefusalCode::DurabilityUnavailable,
        RefusalCode::TierMismatch,
        RefusalCode::Replayed,
        RefusalCode::InFlight,
        RefusalCode::DestinationBudgetExhausted,
        RefusalCode::BreakerOpen,
        RefusalCode::DestinationUnreachable,
        RefusalCode::MeterDisputed,
        RefusalCode::HandoffMismatch,
        RefusalCode::PlanePanic,
        RefusalCode::TaskLost,
        RefusalCode::Stalled,
        RefusalCode::SecretPlaceholder,
        RefusalCode::Drain,
        RefusalCode::Superseded,
        RefusalCode::ClientGone,
        RefusalCode::DeadlineExceeded,
    ];

    /// The number on the wire.
    #[must_use]
    pub const fn code(self) -> u32 {
        self as u32
    }

    /// The code `code` names; `None` for a number the table does not hold.
    #[must_use]
    pub const fn of(code: u32) -> Option<RefusalCode> {
        let all = Self::ALL;
        let mut i = 0;
        while i < all.len() {
            if all[i] as u32 == code {
                return Some(all[i]);
            }
            i += 1;
        }
        None
    }
}

/// A kernel refusal reason's wire code.
#[must_use]
pub const fn reason_code(reason: ReasonCode) -> u32 {
    wire_code(reason).code()
}

/// A kernel refusal reason's wire code, as the code.
#[must_use]
pub const fn wire_code(reason: ReasonCode) -> RefusalCode {
    match reason {
        ReasonCode::InFlightCap => RefusalCode::InFlightCap,
        ReasonCode::CursorBudget => RefusalCode::CursorBudget,
        ReasonCode::CredentialBudget => RefusalCode::CredentialBudget,
        ReasonCode::SessionBudget => RefusalCode::SessionBudget,
        ReasonCode::SpillBudget => RefusalCode::SpillBudget,
        ReasonCode::ScratchExhausted => RefusalCode::ScratchExhausted,
        ReasonCode::RateLimited => RefusalCode::RateLimited,
        ReasonCode::BodyTooLarge => RefusalCode::BodyTooLarge,
        ReasonCode::OpenSlotBusy => RefusalCode::OpenSlotBusy,
        ReasonCode::DecodeFailed => RefusalCode::DecodeFailed,
        ReasonCode::SchemeNotDeclared => RefusalCode::SchemeNotDeclared,
        ReasonCode::SessionUnbound => RefusalCode::SessionUnbound,
        ReasonCode::Unauthenticated => RefusalCode::Unauthenticated,
        ReasonCode::ChallengeExhausted => RefusalCode::ChallengeExhausted,
        ReasonCode::Revoked => RefusalCode::Revoked,
        ReasonCode::ScopeDenied => RefusalCode::ScopeDenied,
        ReasonCode::PoolNotPermitted => RefusalCode::PoolNotPermitted,
        ReasonCode::NoRate => RefusalCode::NoRate,
        ReasonCode::HookVeto => RefusalCode::HookVeto,
        ReasonCode::NoDestination => RefusalCode::NoDestination,
        ReasonCode::OverBudget => RefusalCode::OverBudget,
        ReasonCode::GroupFrozen => RefusalCode::GroupFrozen,
        ReasonCode::Unpriced => RefusalCode::Unpriced,
        ReasonCode::OverdraftCeiling => RefusalCode::OverdraftCeiling,
        ReasonCode::StaleSlice => RefusalCode::StaleSlice,
        ReasonCode::DurabilityUnavailable => RefusalCode::DurabilityUnavailable,
        ReasonCode::TierMismatch => RefusalCode::TierMismatch,
        ReasonCode::Replayed => RefusalCode::Replayed,
        ReasonCode::InFlight => RefusalCode::InFlight,
        ReasonCode::DestinationBudgetExhausted => RefusalCode::DestinationBudgetExhausted,
        ReasonCode::BreakerOpen => RefusalCode::BreakerOpen,
        ReasonCode::DestinationUnreachable => RefusalCode::DestinationUnreachable,
        ReasonCode::MeterDisputed => RefusalCode::MeterDisputed,
        ReasonCode::HandoffMismatch => RefusalCode::HandoffMismatch,
        ReasonCode::PlanePanic => RefusalCode::PlanePanic,
        ReasonCode::TaskLost => RefusalCode::TaskLost,
        ReasonCode::Stalled => RefusalCode::Stalled,
        ReasonCode::SecretPlaceholder => RefusalCode::SecretPlaceholder,
        ReasonCode::Drain => RefusalCode::Drain,
        ReasonCode::Superseded => RefusalCode::Superseded,
        ReasonCode::ClientGone => RefusalCode::ClientGone,
        ReasonCode::DeadlineExceeded => RefusalCode::DeadlineExceeded,
    }
}

/// The kernel refusal reason a wire code names; `None` for a number the table does not hold.
#[must_use]
pub const fn reason_of(code: u32) -> Option<ReasonCode> {
    let Some(c) = RefusalCode::of(code) else {
        return None;
    };
    Some(match c {
        RefusalCode::InFlightCap => ReasonCode::InFlightCap,
        RefusalCode::CursorBudget => ReasonCode::CursorBudget,
        RefusalCode::CredentialBudget => ReasonCode::CredentialBudget,
        RefusalCode::SessionBudget => ReasonCode::SessionBudget,
        RefusalCode::SpillBudget => ReasonCode::SpillBudget,
        RefusalCode::ScratchExhausted => ReasonCode::ScratchExhausted,
        RefusalCode::RateLimited => ReasonCode::RateLimited,
        RefusalCode::BodyTooLarge => ReasonCode::BodyTooLarge,
        RefusalCode::OpenSlotBusy => ReasonCode::OpenSlotBusy,
        RefusalCode::DecodeFailed => ReasonCode::DecodeFailed,
        RefusalCode::SchemeNotDeclared => ReasonCode::SchemeNotDeclared,
        RefusalCode::SessionUnbound => ReasonCode::SessionUnbound,
        RefusalCode::Unauthenticated => ReasonCode::Unauthenticated,
        RefusalCode::ChallengeExhausted => ReasonCode::ChallengeExhausted,
        RefusalCode::Revoked => ReasonCode::Revoked,
        RefusalCode::ScopeDenied => ReasonCode::ScopeDenied,
        RefusalCode::PoolNotPermitted => ReasonCode::PoolNotPermitted,
        RefusalCode::NoRate => ReasonCode::NoRate,
        RefusalCode::HookVeto => ReasonCode::HookVeto,
        RefusalCode::NoDestination => ReasonCode::NoDestination,
        RefusalCode::OverBudget => ReasonCode::OverBudget,
        RefusalCode::GroupFrozen => ReasonCode::GroupFrozen,
        RefusalCode::Unpriced => ReasonCode::Unpriced,
        // KERNEL-ONLY MONEY VERDICTS (ARCHITECT ruling 2026-10-01): a plane never carries the
        // overdraft ceiling or a stale slice, so their codes decode to nothing, which every caller
        // judges a malformed plane answer. The kernel's own encode ([`reason_code`]) keeps them.
        RefusalCode::OverdraftCeiling | RefusalCode::StaleSlice => return None,
        RefusalCode::DurabilityUnavailable => ReasonCode::DurabilityUnavailable,
        RefusalCode::TierMismatch => ReasonCode::TierMismatch,
        RefusalCode::Replayed => ReasonCode::Replayed,
        RefusalCode::InFlight => ReasonCode::InFlight,
        RefusalCode::DestinationBudgetExhausted => ReasonCode::DestinationBudgetExhausted,
        RefusalCode::BreakerOpen => ReasonCode::BreakerOpen,
        RefusalCode::DestinationUnreachable => ReasonCode::DestinationUnreachable,
        RefusalCode::MeterDisputed => ReasonCode::MeterDisputed,
        RefusalCode::HandoffMismatch => ReasonCode::HandoffMismatch,
        RefusalCode::PlanePanic => ReasonCode::PlanePanic,
        RefusalCode::TaskLost => ReasonCode::TaskLost,
        RefusalCode::Stalled => ReasonCode::Stalled,
        RefusalCode::SecretPlaceholder => ReasonCode::SecretPlaceholder,
        RefusalCode::Drain => ReasonCode::Drain,
        RefusalCode::Superseded => ReasonCode::Superseded,
        RefusalCode::ClientGone => ReasonCode::ClientGone,
        RefusalCode::DeadlineExceeded => ReasonCode::DeadlineExceeded,
    })
}

// ── the Statement tail ───────────────────────────────────────────────────────────────────────────

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
    /// The style's parameters for this dialect, a [`super::mechanism::call::BLOB_JSON`] object the
    /// host hands the auth plugin's `open_outbound` as its settings at seal, under the provider's
    /// own (ARCHITECT RULING 2026-10-03, Q-L6-AUTHPARAMS; ruling 2026-09-28 "the kernel resolves the
    /// dialect's declared parameters at seal into OpenOutboundIn::settings"). [`Blob::ABSENT`]: the
    /// style takes none. A value `{"host_label_after": [labels], "default": word, "unread": text}`
    /// is resolved at seal from the provider's base URL host: the dotted label after one of
    /// `labels` when it reads as a dashed name ending in a number (`<word>-...-<digits>`, three
    /// parts or more), else `default`, with `unread` logged as the operator's warning.
    pub params: Blob,
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
/// [`TrustKey::role`]: the key holds a boolean, the registration's PRIVATE REACH: `true` admits a
/// private address (RFC 1918, loopback, link-local and the rest of `net::ip_is_internal`) at the
/// registration's own target, for its member's need only, as an allowlist entry naming that host
/// would (`advanced.allow_destinations`); the need keeps its egress class, and a cloud-metadata
/// address stays refused. Absent or `false`: the class judges alone. The host seals it into the
/// registration's trust anchors beside its pin, and the connector's one guard honours it on every
/// connection the need opens to that destination. It carries no default and no mechanisms.
pub const TRUST_PRIVATE_REACH: u32 = 4;
/// [`TrustKey::flags`], on a [`TRUST_PIN`] key only: the pin object may also carry `fingerprint`.
pub const PIN_FINGERPRINT: u32 = 1;
/// [`PinMechanism::flags`]: the mechanism is an authenticity root, so a pin naming it needs key
/// material. A mechanism without it is the no-root spelling, which must carry none.
pub const MECHANISM_ROOT: u32 = 1;
/// [`PinMechanism::flags`], on a root only: the mechanism's key material is the FAR END'S KEY, a pin
/// of its certificate's SubjectPublicKeyInfo (`transport::trust::key_pin`'s spelling). The host
/// seals it into the trust anchors of the registration's member route, and the connector enforces
/// it on every connection to the registration and reports the key it observed (the transport pin, ARCHITECT 2026-10-03, the
/// transport pin). A mechanism without it keeps its material for the plane and the kernel's
/// signature check alone.
pub const MECHANISM_PEER_KEY: u32 = 2;

/// One pin mechanism a [`TRUST_PIN`] key accepts, as the operator spells it.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PinMechanism {
    /// The config token.
    pub token: AbiStr,
    /// [`MECHANISM_ROOT`] (with [`MECHANISM_PEER_KEY`] where its material is the far end's key) or
    /// `0`.
    pub flags: u32,
    /// Alignment padding.
    pub _reserved: u32,
}

/// The status one refusal reason wears in one dialect (or in every dialect, with
/// [`REFUSAL_ANY_DIALECT`]). The kernel chooses a refusal's status from the plane's rows: the row
/// for the unit's dialect, else the [`REFUSAL_ANY_DIALECT`] row, else its own default. A protocol
/// whose dialects answer the same condition with different statuses states each here, so the
/// status a client reads is the dialect's own.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefusalStatus {
    /// Index into [`PlaneTail::dialects`], or [`REFUSAL_ANY_DIALECT`].
    pub dialect: u32,
    /// The reason's code ([`reason_code`]).
    pub reason: u32,
    /// The status number, 400 to 599.
    pub status: u32,
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
    /// [`TRUST_PIN`] | [`TRUST_REVERIFY_TTL`] | [`TRUST_RECOVERY_BACKOFF`] |
    /// [`TRUST_PRIVATE_REACH`].
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
    /// The statuses its refusals wear where they are not the kernel's defaults; at most one entry
    /// per `(dialect, reason)`.
    pub refusal_statuses: *const RefusalStatus,
    /// How many.
    pub refusal_statuses_len: usize,
    /// The plane's own sentence refusing the reserved `upstream_credentials: passthrough` section
    /// default, emitted by the kernel verbatim; NULL when forwarding the caller's credential is
    /// legitimate on this plane.
    pub caller_credential_refusal: AbiStr,
    /// THE ADMIN ROUTES THE PLANE SERVES, stated once (ARCHITECT Q-L3B-VERBS: the kernel's registry
    /// row reads a door plane's admin verbs from its Statement): each verb, target relative to the
    /// admin mount, flags and audit word, as its snapshots publish them. NULL/0 = none. A tail
    /// addition.
    pub admin_routes: *const AdminRoute,
    /// How many.
    pub admin_routes_len: usize,
    /// THE OPENAPI PATH FRAGMENT of those admin routes: a JSON object keyed by each target relative
    /// to the admin mount (the kernel keys it under the mount when it merges the admin document);
    /// absent = none. A tail addition.
    pub admin_openapi: Blob,
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
    /// [`CLAIM_OPEN`] | [`CLAIM_EXACT`] | [`CLAIM_PATTERN`]; any other bit refuses the snapshot.
    pub flags: u32,
    /// The dialect a refusal on this route wears before `arrive` has read the arrival: an index
    /// into [`PlaneTail::dialects`], opaque to the kernel, which carries it from the matched route
    /// into [`RefusalIn::dialect`] (the kernel authenticates and sizes a request before the plane
    /// reads it, and picks no dialect of its own). `0` for a plane with no dialects.
    pub refusal_dialect: u16,
    /// Alignment padding.
    pub _pad: u16,
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
    /// The word the kernel's audit row names a served request by; empty = never audited.
    pub audit_verb: AbiStr,
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
    /// THE PROTECTED-RESOURCE FACTS beside its audience (ARCHITECT Q-L3B-RFC9728): a JSON object
    /// `{"authorization_servers": [..], "scopes_supported": [..]}`, from which the kernel renders the
    /// RFC 9728 document at [`PlaneSnapshot::resource_metadata`] (no unit, no audit row); absent =
    /// none stated. A tail addition.
    pub resource_facts: Blob,
}

/// The plane's `open` `in`: the lifecycle's, plus the deployment's public base URL.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PlaneOpenIn {
    /// The lifecycle `in`.
    pub open: OpenIn,
    /// The deployment's public base URL; absent = none stated.
    pub public_url: AbiStr,
    /// THE PLANE'S OTHER OWNED SECTIONS this document writes (the Statement's sections that are
    /// neither its declaring section nor consumed), as one JSON object keyed by section name, each
    /// as written; [`crate::abi::mechanism::call::BLOB_ABSENT`] when it writes none (ARCHITECT
    /// Q-L3B-AUD: a plane reads its own sections and states its claims from them). A tail addition.
    pub owned: Blob,
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

/// A HOST-OWNED LIST OF [`Field`]s a host lends a plane (`OnPieceIn::head_fields`): the names and
/// values it owns and the field array pointing into them, built once and moved as one value. The
/// pointers point only into this list's own heap bytes, which never move while it lives, so it
/// may cross threads with the op that lends it.
#[derive(Debug, Default)]
pub struct FieldList {
    /// The names and values, kept only to own the bytes `fields` points into.
    _owned: Vec<(Vec<u8>, Vec<u8>)>,
    fields: Vec<Field>,
}

// SAFETY: every pointer in `fields` points into `_owned`'s own heap allocations, owned here and
// never mutated or moved (a Vec's heap does not move when the Vec does) while the list lives.
unsafe impl Send for FieldList {}
// SAFETY: as above; the list is read-only once built.
unsafe impl Sync for FieldList {}

impl FieldList {
    /// The list of `pairs` (name, value), in order.
    #[must_use]
    pub fn new(pairs: Vec<(Vec<u8>, Vec<u8>)>) -> Self {
        let fields = pairs
            .iter()
            .map(|(n, v)| Field {
                name: AbiStr {
                    ptr: n.as_ptr(),
                    len: n.len(),
                },
                value: AbiStr {
                    ptr: v.as_ptr(),
                    len: v.len(),
                },
            })
            .collect();
        FieldList {
            _owned: pairs,
            fields,
        }
    }

    /// The field array, NULL when empty.
    #[must_use]
    pub fn as_ptr(&self) -> *const Field {
        if self.fields.is_empty() {
            core::ptr::null()
        } else {
            self.fields.as_ptr()
        }
    }

    /// How many fields.
    #[must_use]
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    /// Whether there are none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }
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
    /// [`UNITS_ESTIMATED`] | [`UNITS_REPORTED`] | [`UNITS_FLOOR`].
    pub source: u32,
    /// The cumulative count.
    pub amount: u64,
}

/// One record write, a destination fact the kernel applies on the record seam; its key and value
/// bytes are in the call's `arena`.
///
/// The kernel batches record writes to the store, and a write is DURABLE before the op that carried
/// it completes: the instance reads its own write at once, and a write the store refuses fails the
/// op. What must be decided once and for all (a replay refusal, an idempotency key, an approval
/// redemption) is a `records.claim`, a one-time put the store answers itself.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RecordWrite {
    /// Index into [`PlaneTail::record_kinds`]; with [`RECORD_AUDIT`], the audit row's outcome.
    pub kind: u32,
    /// [`RECORD_PUT`] | [`RECORD_AUDIT`].
    pub op: u32,
    /// The key.
    pub key: Span,
    /// The value.
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
    /// The request method, as the caller sent it. The plane decides which methods its paths
    /// accept; one it does not is a refused arrive, with the plane's own status and bytes.
    pub method: AbiStr,
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
    /// On REFUSED: the plane's own code for why, opaque to the kernel and echoed to `refusal` as
    /// [`RefusalIn::plane_code`], so the plane renders what its `arrive` decided. Nonzero on
    /// REFUSED, `0` on every other outcome.
    pub refusal: u32,
    /// On REFUSED: the status the refusal wears, 400 to 499: an arrive refusal is the caller's
    /// fault by definition; 400 to 599 for a refusal about an entry (see "A refused arrival",
    /// rule 6). `0` on every other outcome.
    pub refusal_status: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// This unit's CORRELATION KEY: a non-zero value the plane derives from the arrival (for
    /// example from its request identifier), naming the unit for a subsequent
    /// [`ArriveOut::cancels`]; `0` = the unit cannot be cancelled by name. A tail addition. It is
    /// scoped to (connection, the arrival's authenticated principal), never connection-wide: see
    /// the cancel rule in this module's documentation.
    pub correlation: u64,
    /// A non-zero value makes this arrival a CANCEL: it names the [`ArriveOut::correlation`] of an
    /// in-flight unit of the same connection and principal (the cancel rule, in this module's
    /// documentation).
    /// `0` = not a cancel. Never set together with a non-zero [`ArriveOut::correlation`].
    pub cancels: u64,
    /// On READY: the ENTRY the unit routes over, its name inside the plane's own config section
    /// (ARCHITECT Q-SW6, 2026-10-02): a pool or a model entry, as [`ArriveOut::route`] says. The kernel
    /// resolves (plane key, entry) and never parses the name; none named is refused. Plane memory,
    /// valid until the instance's next call. A tail addition; absent on every other outcome.
    pub pool: AbiStr,
    /// On READY: [`ROUTE_POOL`] or [`ROUTE_DIRECT`], what [`ArriveOut::pool`] names (ARCHITECT Q-FL3,
    /// 2026-10-02), or [`ROUTE_LOCAL`] or [`ROUTE_SCOPE`] with no pool named. A tail addition;
    /// [`ROUTE_POOL`] on every
    /// other outcome.
    pub route: u8,
    /// On READY: `ROUTE_*` flag bits ([`ROUTE_ONCE`], [`ROUTE_SESSION`]); `0` on every other
    /// outcome. A tail addition, in what was padding.
    pub route_flags: u8,
    /// Alignment padding.
    pub _route_reserved: [u8; 6],
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
    /// On an ATTEMPT piece: the operator's name for the pool the kernel picked `member` from (a
    /// member may shape its request differently in each pool it serves); absent otherwise.
    pub pool: AbiStr,
    /// On every piece of a unit: the caller's opaque, stable, non-reversible per-principal
    /// reference (lower-case hex), never the principal itself; absent when the node keeps no
    /// signing material to derive it from.
    pub caller_ref: AbiStr,
    /// On every piece of a unit: the snapshot claim the unit arrived on (`ArriveIn::claim`).
    pub claim: u32,
    /// On every piece of a unit: the dialect `arrive` answered (`ArriveOut::dialect`).
    pub dialect: u32,
    /// With [`FROM_FAR_END`] on the answer's first piece: the far end's response head fields the
    /// plane's need keeps (`Need::keep_response_headers`), in the far end's order, names lower-case;
    /// no other response field ever crosses. NULL with `0` otherwise.
    pub head_fields: *const Field,
    /// How many.
    pub head_fields_len: usize,
    /// From the unit's first attempt on, on every piece: `1` when the attempt's member relays the
    /// caller's own credential to the far end (the operator configured its upstream credentials as
    /// passthrough), `0` otherwise and before any attempt.
    pub passthrough: u32,
    /// Alignment padding.
    pub _reserved_tail: u32,
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
    /// With [`EMIT_TO_FAR_END`]: the need the far request rides (ARCHITECT Q-L5B-NEEDS 2026-10-03,
    /// spec #3: a plane's needs are a list of (transport, auth) per direction, and the kernel binds
    /// every declared outbound need of a member), as its index in the Statement's needs PLUS ONE;
    /// `0` = the member's first bound need (a plane with one outbound need never names one). A tail
    /// addition.
    pub need: u32,
    /// Alignment padding.
    pub _need_reserved: u32,
    /// THE UNIT'S LEDGER LANE, in the arena; a zero length = none named. The billing identity the
    /// unit's units are priced, ledgered and metered under, which is not the route entry the walk
    /// picked (a call of one tool on a pooled server is the tool's lane, not the server's). The
    /// kernel qualifies it with the plane's own key, so a plane names lanes of its own card alone;
    /// the last one an answer of the unit named holds, and a unit whose answers name none is laned
    /// by the entry its route picked. UTF-8, without control characters. A tail addition.
    pub lane: Span,
}

/// `refusal`'s `in`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RefusalIn {
    /// The head.
    pub head: InHead,
    /// [`REFUSAL_KERNEL`] | [`REFUSAL_GATE`] | [`REFUSAL_ARRIVE`].
    pub cause: u32,
    /// The status number the kernel chose.
    pub status: u32,
    /// Index into [`PlaneTail::dialects`].
    pub dialect: u32,
    /// The refusal reason's code ([`reason_code`]): with the status and the dialect, what the
    /// plane renders. Two reasons may share a status and still read differently to a client.
    pub reason: u32,
    /// The refusal text: the kernel's own message for the refusal (for a limit, it names the
    /// bucket that blocked); never secret material. With [`REFUSAL_ARRIVE`]: the refused arrival's
    /// `head.error`, byte for byte. With [`REFUSAL_GATE`]: the vetoing hook's own message, as the
    /// kernel's hook engine sanitised it.
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
    /// The unit the refusal ends, as the kernel minted it; `0` when no unit had arrived.
    pub unit: u64,
    /// The plane's own code from a REFUSED `arrive` ([`ArriveOut::refusal`]); `0` otherwise.
    pub plane_code: u32,
    /// The seconds the caller is told to wait before retrying; `0` = no such advice.
    pub retry_after_s: u32,
    /// The request target, as the caller sent it. A refusal can precede `arrive` (the kernel
    /// authenticates first): the plane then chooses its envelope from the target by its own rule;
    /// the kernel never picks a dialect.
    pub target: AbiStr,
    /// HOST buffer for record writes: the refusal's record writes, as an `on_piece` answer's
    /// ([`RecordWrite`], their bytes in the arena), so a plane writes its declared audit row
    /// ([`RECORD_AUDIT`]) for a unit the kernel refused. A tail addition.
    pub records_buf: *mut RecordWrite,
    /// Its capacity.
    pub records_cap: usize,
    /// With [`REFUSAL_GATE`]: the name of the hook that vetoed the unit, opaque bytes; absent on
    /// every other refusal. A tail addition.
    pub hook: AbiStr,
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
    /// Always `0`: the kernel sets [`MARK_GATE_REJECTED`] itself; a plane that sets it is FAULT.
    pub marker: u32,
    /// Fields written to `fields_buf`.
    pub fields_written: u32,
    /// Short answer: the fields `fields_buf` needs.
    pub fields_needed: u32,
    /// The status number the rendered reply carries, in [`RefusalIn::status`]'s space; the
    /// transport maps it to its wire. `0` = keep [`RefusalIn::status`].
    pub status: u32,
    /// Record writes written to `records_buf`. A tail addition.
    pub records_written: u32,
    /// Short answer: the record writes `records_buf` needs.
    pub records_needed: u32,
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
    /// `AUDIT_*`: the row the kernel audits the request with, under the route's `audit_verb`.
    pub audit: u32,
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
    /// A request-stage hook's rewrite (the hook's own rewrite bytes, which the kernel never
    /// parses): the plane applies it to `body` in its own dialect, answers the rewritten body in
    /// [`ProjectOut::rewritten`] and projects THAT body. [`Blob::ABSENT`] on the unit's first
    /// `project`.
    pub rewrite: Blob,
    /// HOST buffer for the prompt view's turns ([`PromptView::messages`]).
    pub messages_buf: *mut MessageView,
    /// Its capacity.
    pub messages_cap: usize,
    /// The unit, as the kernel minted it ([`ArriveIn::unit`]): a plane that applies a rewrite
    /// keeps the rewritten body as its unit's request, so every attempt it writes from then on is
    /// written from it.
    pub unit: u64,
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
    /// The prompt view: `system` and every turn's strings in the arena, the turns at
    /// `messages_buf` (`message_count` of them). `body` stays [`Blob::ABSENT`]: the body a hook
    /// sees is the one the kernel keeps, which it lends itself.
    pub prompt: PromptView,
    /// The body's end user (OLD `CallerIdentity::user`), in whichever field the plane's dialect
    /// spells it, in the arena; NULL = none. The kernel shows it only to a hook granted `user`.
    pub end_user: AbiStr,
    /// The rewritten body, in the arena, when [`ProjectIn::rewrite`] was given and the plane
    /// applied it: the body the kernel keeps and re-pushes on every attempt from now on. Empty
    /// (or [`SPAN_ABSENT`]) = not applied, and the unit proceeds with the body it had (1.5.5:
    /// a rewrite that cannot be applied leaves the request unmodified).
    pub rewritten: Span,
    /// Short answer: the turns `messages_buf` needs.
    pub messages_needed: u32,
    /// Alignment padding.
    pub _reserved2: u32,
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
