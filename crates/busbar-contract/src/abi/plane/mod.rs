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
//!     (slot::CATALOG, offset_of!(Ops, catalog)),
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
    /// Render a catalog route's listing of the names the kernel hands it.
    pub const CATALOG: u32 = LIFECYCLE_SLOTS + 7;
}

/// How many kind ops the table holds after the lifecycle.
pub const KIND_SLOTS: u32 = 8;
/// How many slots the whole table holds ([`OpsHead::slots`]).
pub const SLOTS: u32 = LIFECYCLE_SLOTS + KIND_SLOTS;

/// The plane kind's ops table: the lifecycle, then the plane's eight ops.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Ops {
    /// The lifecycle. `open` is in [`PlaneOpenIn`], out [`PlaneOpenOut`]; `refresh` out is
    /// [`PlaneRefreshOut`]; `drive` is in [`PlaneDriveIn`], out [`PlaneDriveOut`]; `cancel` is in
    /// [`PlaneCancelIn`], out [`PlaneCancelOut`], and answers a `CANCEL_*` disposition.
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
    /// [`slot::CATALOG`]: in [`CatalogIn`], out [`CatalogOut`]. A tail addition: a plane that
    /// claims no [`CLAIM_CATALOG`] route leaves it `None`.
    pub catalog: Option<Op>,
}

// ── the op contracts ─────────────────────────────────────────────────────────────────────────────

/// Every kind op's contract, in slot order. `arrive`, `refusal`, `project` and `catalog` are pure:
/// they never pend.
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
    contract!(CATALOG, true, false, CatalogIn, CatalogOut, Call),
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
/// [`PlaneTail::flags`]: the plane takes a unit's refusal as a piece first where the unit's hop
/// may hold state the plane must end: when the walk refuses the unit
/// [`crate::caps::ReasonCode::CredentialUnavailable`] (the member's credential, re-resolved for the
/// attempt, no longer resolves, and nothing was dialled), or ends it with no member left, whether or
/// not an attempt's request went out (the walk's exhaustion terminal, refused
/// [`crate::caps::ReasonCode::BreakerOpen`]; when no attempt of the walk sent its request, the piece
/// names why the last did not in its place, an `Unsent*` [`RefusalCode`], and [`nothing_sent`]
/// reads that and the credential's refusal alike as a hop that never left), the kernel hands `on_piece` a [`FROM_KERNEL`] piece
/// flagged [`PIECE_REFUSED`] and [`PIECE_LAST`], carrying that reason in [`OnPieceIn::reason`], on
/// the unit's own ticket: the plane's record writes on that answer are written, as any piece's are,
/// and nothing it emits reaches the caller. Then the unit is refused as it is without the bit:
/// `refusal` renders it. Without the bit no such piece is sent.
pub const TAIL_REFUSED_PIECE: u32 = 1 << 3;

/// [`DialectAuth::flags`]: a provider's `protocol` may name this dialect.
///
/// The kernel reads it as declared data (ARCHITECT ruling 2026-10-16, item 3): a provider whose
/// `protocol` is a dialect no linked plane flags is refused at boot, and the refusal lists the
/// flagged dialects, in the planes' registration order and each plane's dialect order.
pub const DIALECT_PROVIDER: u32 = 1;

/// [`Claim::flags`]: the route takes no inbound credential; the kernel admits an arrival on it
/// without verifying a caller. Without it, the route takes one.
pub const CLAIM_OPEN: u32 = 1;
/// [`Claim::flags`]: the target matches exactly. Without it (and without [`CLAIM_PATTERN`]), the
/// target is a one-level prefix.
pub const CLAIM_EXACT: u32 = 1 << 1;
/// [`Claim::flags`]: the target is a path pattern. Each `/`-separated segment is a literal, or a
/// placeholder spelled `{name}` that matches exactly one non-empty segment with no `/`, or a
/// placeholder spelled `{name+}` that matches ONE OR MORE segments (the arriving path's own `/`
/// between them, raw; an encoded `%2F` is inside one segment either way), at most one per pattern,
/// a second refused at registration (ARCHITECT ruling 2026-10-16, 3b A). The host reads it as the
/// claim grammar's segment pattern ([`check::claim_selector`]), so the registry's sealed precedence
/// is unchanged: exact beats pattern beats prefix. Never with [`CLAIM_EXACT`].
pub const CLAIM_PATTERN: u32 = 1 << 2;
/// [`Claim::flags`]: the route is a CATALOG listing, answered with no unit.
///
/// The kernel mints no unit for an arrival on it, writes no audit record and meters nothing; it
/// computes the names its caller may see (its own visibility rule, and every plane generation's
/// listed names after it) and hands them, with the request head, to the plane's pure `catalog` op
/// ([`CatalogIn`]), serving the bytes the plane renders (ARCHITECT ruling 2026-10-16, 3b C).
pub const CLAIM_CATALOG: u32 = 1 << 3;
/// [`Claim::flags`]: callers sign a request to this route's path (its inbound auth point).
///
/// The kernel looks it up BY PATH, across every claim of the path whatever its verb: a request to a
/// path some claim flags is put through the signed-request pre-step (the auth chain's verifier of
/// one) before anything else is decided, so a signed request with a verb no claim takes verifies
/// first and is then answered the method refusal, as the previous release answered it (ARCHITECT
/// ruling 2026-10-16, 3b A). Only on a [`CLAIM_RAW_AFFIX`] claim, matched against the raw path as
/// the previous release matched it, odd paths included (ARCHITECT ruling 2026-10-17).
pub const CLAIM_SIGNED_INGRESS: u32 = 1 << 4;
/// [`Claim::flags`]: the target is a RAW AFFIX, spelled `<prefix>*<suffix>`. It matches a request
/// whose raw, undecoded path starts with the prefix and ends with the suffix, compared as bytes:
/// empty segments, a trailing `/` and a leading `//` count as the bytes they are, and the two
/// affixes may share bytes ([`check::raw_affix_matches`]). One spelling per suffix, so a path with
/// N suffixes is N claims. A raw-affix claim states a fact about paths, read by path: it mounts no
/// route and takes no arrival (ARCHITECT ruling 2026-10-17). Never with [`CLAIM_OPEN`],
/// [`CLAIM_EXACT`] or [`CLAIM_PATTERN`]. Bits 3 and 4 are taken by flags in flight.
pub const CLAIM_RAW_AFFIX: u32 = 1 << 5;
/// [`Claim::flags`]: the target is an ENTRY FACT, the request shape whose arrival opens the entry
/// span the claim states ([`PlaneSnapshot::arrival_spans`]; an empty name ends the reading there,
/// and the arrival opens none). The host reads a plane's entry facts in its snapshot's order, ahead
/// of the span the arrival's own claim states, and the first one the request meets decides. The
/// target is one or more space-separated predicates, every one of which the request must meet:
/// `field:<name>` (a head field `<name>`, lower-case, is present), `field:<name>=<prefix>` (its value
/// starts with `<prefix>`; a field the host's auth consumed is read by its scheme word alone), and
/// at most one `path:<pattern>` over the raw, undecoded path, in which `*` matches any run of bytes
/// and a whole segment `{}` or `{<field>}` matches one non-empty segment, `{<field>}` recording it,
/// percent-decoded, as the span's field `<field>` ([`check::entry_fact`]). An entry fact mounts no
/// route and takes no arrival. Never with another flag.
pub const CLAIM_ENTRY: u32 = 1 << 6;

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

/// The layout of this kind's answers, as one number: the revision of every plane `out` struct the
/// host reads back ([`ArriveOut`], [`OnPieceOut`], [`RefusalOut`], [`ServeOut`], [`ProjectOut`],
/// [`PlaneOpenOut`], [`PlaneRefreshOut`], [`PlaneDriveOut`], [`PlaneCancelOut`]).
/// [`PlaneTail::answer_layout`] states it, so a plane built against another answer layout is
/// refused at load, never read wrong. `1`: [`OnPieceOut`] is 248 bytes, ending in
/// [`OnPieceOut::fault_reason`], and [`ArriveOut::refusal_flags`] holds what was padding. Any move
/// of a field of one of those structs (a size, an offset, a padding word given a meaning) moves it.
pub const ANSWER_LAYOUT: u32 = 1;

// The answers [`ANSWER_LAYOUT`] `1` names, pinned: a struct that moves fails this build until the
// layout moves with it (and these with it), so a plane built against another contract states
// another `answer_layout` and is refused at load, never read wrong. The figures are a 64-bit
// target's; the guard is a const `if`, not a `cfg`, so the item is on every build's surface (the
// contract is feature-invariant: `tests/feature_invariance.rs`).
const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(ANSWER_LAYOUT == 1);
    if usize::BITS == 64 {
        assert!(size_of::<ArriveOut>() == 232);
        assert!(offset_of!(ArriveOut, refusal_flags) == 124);
        assert!(size_of::<OnPieceOut>() == 248);
        assert!(offset_of!(OnPieceOut, fault_reason) == 240);
        assert!(size_of::<RefusalOut>() == 152);
        assert!(size_of::<ServeOut>() == 152);
        assert!(size_of::<ProjectOut>() == 328);
        assert!(size_of::<PlaneOpenOut>() == 120);
        assert!(size_of::<PlaneRefreshOut>() == 104);
        assert!(size_of::<PlaneDriveOut>() == 104);
        assert!(size_of::<PlaneCancelOut>() == 120);
    }
};

/// [`UnitCount::source`]: the plane's own estimate; never billed.
pub const UNITS_ESTIMATED: u32 = 0;
/// [`UnitCount::source`]: the far end reported it; it bills.
pub const UNITS_REPORTED: u32 = 1;
/// [`UnitCount::source`]: the plane's floor for a delivered reply whose far-end usage could not be
/// read (the usage floor, Q24/Q28: 1.5.5's truncated-tail estimate bills, never 0). It bills like
/// [`UNITS_REPORTED`]; the plane decides when it applies, the kernel adds no floor of its own.
pub const UNITS_FLOOR: u32 = 2;

/// [`OnPieceOut::tap_fault`]: no usage-tap fault.
pub const TAP_FAULT_NONE: u8 = 0;
/// [`OnPieceOut::tap_fault`]: the cell's own reader refused the body (`reason="decode"`).
pub const TAP_FAULT_DECODE: u8 = 1;
/// [`OnPieceOut::tap_fault`]: the body is not JSON (`reason="bad_json"`).
pub const TAP_FAULT_BAD_JSON: u8 = 2;
/// [`OnPieceOut::tap_fault`]: the caller's dialect is not one the tap reads
/// (`reason="unknown_protocol"`).
pub const TAP_FAULT_UNKNOWN_PROTOCOL: u8 = 3;

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
/// [`ArriveOut::route`]: the plane ANSWERS THIS UNIT ITSELF at the ONE entry the principal's grant
/// reaches. The kernel resolves the entry exactly as ROUTE_SCOPE does ([`ArriveOut::pool`] may
/// name the candidates; zero or several reachable entries refuse `no_destination`, rendered through
/// `refusal` as ROUTE_SCOPE's), then admits it with NO route walk: no pool, no breaker, no egress.
/// It bills nothing when only far-end-reported units bill, as ROUTE_LOCAL does, and it is audited
/// under the resolved entry.
pub const ROUTE_SCOPE_LOCAL: u8 = 4;

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

/// [`ArriveOut::route_flags`]: the caller asked for its answer STREAMED (ARCHITECT Q1 ArriveOut,
/// 2026-10-05). The plane states it, because only the plane reads its dialect's body; the kernel
/// applies what a stream means to the walk from it: the stream ceiling bounds the whole send rather
/// than the pool's request timeout, and once a byte of the answer has reached the caller a cut is
/// not a refund (Part 2 #62). Unset, the answer is the caller's whole or not at all.
pub const ROUTE_STREAM: u8 = 4;

/// [`ArriveOut::route_flags`], on a unit the plane answers itself ([`ROUTE_LOCAL`] or
/// [`ROUTE_SCOPE_LOCAL`]) alone: the plane answers it AS AN ADMITTED CALL. The kernel admits a keyed
/// unit through its one check-then-charge on the plane's own pool, so the call counts its request
/// against the caller's caps and is refused when they are spent (1.5.5's rule, R2: a verb answered
/// out of busbar's own state is still admitted, metered and audited); it bills only what the plane
/// reports, a fee unit it does not report given back. Unset, a local unit stating no expected units
/// is admitted with nothing charged or counted (a notification, a public document). Set on a unit
/// routed to any member, it contradicts its route.
pub const ROUTE_COUNTED: u8 = 8;

/// [`ArriveOut::refusal_flags`]: the arrival names an ACTION THE PLANE'S PROTOCOL HAS BUT THE PLANE
/// DOES NOT SERVE. The refusal is the caller's request as the plane read it (counted under the
/// claimant dialect like any other refusal of a read request), not a path or a verb no protocol of
/// the plane claims. The plane states it, because only the plane reads its own resource grammar;
/// the kernel and the root count the outcome and never read the plane's code or status to tell one
/// refusal from another.
pub const REFUSED_UNSUPPORTED_ACTION: u32 = 1;

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
/// kernel never drops or reads it. With [`PIECE_HAS_STATUS`]: `status_code`/`status_class` are the
/// status the transport read off the trailers (a transport that states its answer's status at the
/// end); a non-success one ends the answer, and this is its [`PIECE_LAST`] piece.
pub const PIECE_FIELDS: u32 = 1 << 3;
/// [`OnPieceIn::flags`]: the CATALOGUE-MOVED TICK. With [`FROM_KERNEL`], `attempt_no == 0` and no
/// bytes, on a session's [`OnPieceIn::stream`], it says the catalogue generation that session
/// watches ([`EMIT_WATCH_CATALOGUE`]) moved since the last tick it was given. The plane answers
/// with whatever it tells the session about the move, or with nothing. See
/// the catalogue-moved tick in this module's documentation.
pub const PIECE_CATALOGUE_MOVED: u32 = 1 << 4;
/// [`OnPieceIn::flags`]: the REFUSED PIECE. With [`FROM_KERNEL`], [`PIECE_LAST`],
/// `attempt_no == 0` and no bytes, the unit is about to be refused for [`OnPieceIn::reason`]. Sent
/// only to a plane whose tail states [`TAIL_REFUSED_PIECE`]; see it for when.
pub const PIECE_REFUSED: u32 = 1 << 5;
/// [`OnPieceIn::flags`], [`FROM_FAR_END`] with [`PIECE_LAST`]: the far end's answer ended without
/// completing (its connection failed, or the send's deadline passed, after its head). Without it,
/// the far end's [`PIECE_LAST`] is a complete answer. The kernel sets it on no other piece; a plane
/// that receives it on any other piece faults the piece ([`check::check_piece_in`]). A plane that
/// reads no cut ignores the bit and ends the answer as it would any other.
pub const PIECE_CUT: u32 = 1 << 6;
/// [`OnPieceIn::flags`], [`FROM_FAR_END`] with [`PIECE_HAS_STATUS`] (the answer's first piece): the
/// kernel will not fail this answer over, whatever verdict the plane answers it with, so an answer
/// whose verdict is [`VERDICT_RETRY`] is the unit's last. The kernel sets it on no other piece; a
/// plane that receives it on any other piece faults the piece ([`check::check_piece_in`]).
pub const PIECE_FINAL: u32 = 1 << 7;

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

/// [`OnPieceOut::flags`]: MESSAGE BOUNDARY. The bytes this answer emits toward the caller END one
/// message: a carrier that frames messages (a length-prefixed message stream) frames ONE message on
/// this boundary, however many answers its bytes spanned (a message past one reply buffer is still
/// one message); a carrier with no message framing ignores it. An answer may carry it with no bytes
/// of its own (the boundary after bytes already emitted). Not on a request bound for the far end.
pub const EMIT_MESSAGE_END: u32 = 1 << 5;
/// [`OnPieceOut::flags`]: FINAL STATUS. On the closing answer ([`EMIT_DONE`]): the reply ends with
/// the status [`OnPieceOut::final_status`] states, its message and details in the arena, in the
/// numbering the claim's transport declares for its own statuses. A carrier that reports a reply's
/// status AFTER its bytes (trailing fields) reports this one there, so a reply that fails after its
/// first message still ends with its own status; any other carrier ignores it.
pub const EMIT_FINAL_STATUS: u32 = 1 << 6;

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
    EMIT_MESSAGE_END,
    EMIT_FINAL_STATUS,
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
/// [`AdminRoute::flags`], on a [`ROUTE_PUBLIC`] route only: the route is addressed by the plane's
/// OWN correlation token, carried in the request's `authorization` field, so that one field crosses
/// to [`slot::SERVE`] (every other credential field stays struck). The token is busbar's own value,
/// minted and re-verified only through the host's signing service: it is not a caller principal
/// and the plane holds no key (`BUSBAR-1.6.0.md` l.4882: a callback route "is auth `none`; the
/// plane checks its own callback correlation token (never logged/audited)"). Without
/// [`ROUTE_PUBLIC`] the snapshot is refused.
pub const ROUTE_CARRIES_OWN_TOKEN: u32 = 1 << 1;

/// [`ServeOut::audit`]: no audit row.
pub const AUDIT_NONE: u32 = 0;
/// [`ServeOut::audit`]: the request applied; the row's outcome is `applied`.
pub const AUDIT_APPLIED: u32 = 1;
/// [`ServeOut::audit`]: the request was rejected after it was judged; the row's outcome is
/// `rejected`.
pub const AUDIT_REJECTED: u32 = 2;
/// A [`RECORD_AUDIT`] write's outcome only (never [`ServeOut::audit`]): the unit was served with
/// something the caller asked for left out (a control the far end's form cannot carry); the row's
/// outcome is `degraded`, the 1.5.5 row's.
pub const AUDIT_DEGRADED: u32 = 3;

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
    /// `Untrusted`.
    Untrusted = 42,
    /// `CredentialUnavailable`.
    CredentialUnavailable = 43,
    /// `MethodNotAllowed`.
    MethodNotAllowed = 44,
    /// `Internal`.
    Internal = 45,
    /// THE WALK'S EXHAUSTION, NOTHING SENT: the attempt had no member in hand when its request
    /// was to go out. This and every `Unsent*` code below is a kernel-to-plane reason alone: it
    /// rides the walk's exhausted refused piece ([`TAIL_REFUSED_PIECE`]) in place of
    /// [`RefusalCode::BreakerOpen`] when no attempt of the walk sent a request, naming why the
    /// last one did not, so a plane can tell a hop that never left from one that left and failed
    /// over. It is no reason the kernel's vocabulary holds: [`reason_of`] decodes it to nothing,
    /// and a plane never states it.
    UnsentNoAttempt = 46,
    /// Nothing sent: the member has no route on this node.
    UnsentNoRoute = 47,
    /// Nothing sent: the far request named a need its member has no binding for.
    UnsentNeedUnbound = 48,
    /// Nothing sent: the far request's target is not a path.
    UnsentTargetNotPath = 49,
    /// Nothing sent: a field of the far request is named by no RFC 9110 token.
    UnsentFieldName = 50,
    /// Nothing sent: the dispatch could not be recorded before the dial.
    UnsentUnrecorded = 51,
    /// Nothing sent: the member's auth call answered no fields.
    UnsentAuthFailed = 52,
    /// Nothing sent: the connection table refused to open the attempt.
    UnsentOpenRefused = 53,
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
        RefusalCode::Untrusted,
        RefusalCode::CredentialUnavailable,
        RefusalCode::MethodNotAllowed,
        RefusalCode::Internal,
        RefusalCode::UnsentNoAttempt,
        RefusalCode::UnsentNoRoute,
        RefusalCode::UnsentNeedUnbound,
        RefusalCode::UnsentTargetNotPath,
        RefusalCode::UnsentFieldName,
        RefusalCode::UnsentUnrecorded,
        RefusalCode::UnsentAuthFailed,
        RefusalCode::UnsentOpenRefused,
    ];

    /// Whether the code is one of the `Unsent*` codes: the walk's exhaustion with no attempt's
    /// request sent ([`RefusalCode::UnsentNoAttempt`]).
    #[must_use]
    pub const fn unsent(self) -> bool {
        matches!(
            self,
            RefusalCode::UnsentNoAttempt
                | RefusalCode::UnsentNoRoute
                | RefusalCode::UnsentNeedUnbound
                | RefusalCode::UnsentTargetNotPath
                | RefusalCode::UnsentFieldName
                | RefusalCode::UnsentUnrecorded
                | RefusalCode::UnsentAuthFailed
                | RefusalCode::UnsentOpenRefused
        )
    }

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
        ReasonCode::Untrusted => RefusalCode::Untrusted,
        ReasonCode::CredentialUnavailable => RefusalCode::CredentialUnavailable,
        ReasonCode::MethodNotAllowed => RefusalCode::MethodNotAllowed,
        ReasonCode::Internal => RefusalCode::Internal,
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
        RefusalCode::Untrusted => ReasonCode::Untrusted,
        RefusalCode::CredentialUnavailable => ReasonCode::CredentialUnavailable,
        RefusalCode::MethodNotAllowed => ReasonCode::MethodNotAllowed,
        RefusalCode::Internal => ReasonCode::Internal,
        // THE WALK'S EXHAUSTION WITH NOTHING SENT: a kernel-to-plane piece reason, never a
        // reason a plane states, so it decodes to nothing (a malformed plane answer).
        RefusalCode::UnsentNoAttempt
        | RefusalCode::UnsentNoRoute
        | RefusalCode::UnsentNeedUnbound
        | RefusalCode::UnsentTargetNotPath
        | RefusalCode::UnsentFieldName
        | RefusalCode::UnsentUnrecorded
        | RefusalCode::UnsentAuthFailed
        | RefusalCode::UnsentOpenRefused => return None,
    })
}

/// WHETHER THE REFUSED PIECE'S REASON (`OnPieceIn::reason`) SAYS NOTHING LEFT for the unit: the
/// member's credential was unavailable before the dial ([`RefusalCode::CredentialUnavailable`]),
/// or the walk exhausted with no attempt's request sent (an `Unsent*` code). `false` for every
/// other reason, [`RefusalCode::BreakerOpen`] included: that exhaustion sent a request.
#[must_use]
pub const fn nothing_sent(reason: u32) -> bool {
    match RefusalCode::of(reason) {
        Some(RefusalCode::CredentialUnavailable) => true,
        Some(code) => code.unsent(),
        None => false,
    }
}

// ── the one refusal classification ───────────────────────────────────────────────────────────────

/// THE ONE REFUSAL CLASSIFICATION: which family of answer a refusal reason gets, whatever the
/// plane. This is the P-item "refusal-reason collapse" (spec DONE item 2).
///
/// A refusal reason is the kernel's own word, and a client never sees it. A client sees the plane's
/// rendering of it. Before this table there were eight hand-copied reason matches, and they
/// disagreed: the kernel's default status, three renderers in one plane, one in each of four
/// others, and the admin surface's. One of them still ended in a catch-all that answered a rate
/// limit, a spent budget or a frozen group as "internal", which tells a caller the node broke when
/// it was a policy refusal, so the caller retries the wrong thing. 1.5.5 never did that: on its one
/// plane each limit reason has its own status and kind (v1.5.5 `crates/busbar/src/ingress/mod.rs:
/// 237-305`: rate 429 `rate_limit_error`, budget 429 `insufficient_quota`, frozen group 403
/// `permission_error`), and none becomes a 500.
///
/// So the reason-to-class grouping lives ONCE, here, and a plane holds only a class-to-wire table:
/// its own codes and words. The grouping follows the one plane 1.5.5 shipped (owner correction
/// 2026-09-28): each class has one kernel default status, and that default plus that plane's stated
/// per-reason rows reproduce every status it answered, byte for byte, against the 1.5.5 golden
/// cells.
///
/// The match in [`RefusalCode::class`] has no `_` arm, so a code added without a class does not
/// compile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RefusalClass {
    /// The plane could not read the request.
    Unreadable,
    /// The request was readable, and this node will not take it as asked: an unbillable name, a
    /// replayed or superseded idempotency key.
    Rejected,
    /// No usable authority: no credential, a revoked one, or an exchange that never produced one.
    Unauthenticated,
    /// The caller is known and may not do this.
    Forbidden,
    /// The request, or what it needs held, is larger than the node allows.
    TooLarge,
    /// The caller is over its arrival rate.
    Throttled,
    /// The node's in-flight table, or the idempotency key's unit, is busy.
    Busy,
    /// A money cap in the caller's chain has no headroom.
    QuotaExhausted,
    /// There is nowhere for the request to go.
    NotFound,
    /// A destination exists, and the way to it is shut: unreachable, breaker open, or its budget
    /// spent.
    Unreachable,
    /// The node cannot take the unit now: capacity, drain, journal, or the client left.
    Unavailable,
    /// The unit ran out of time.
    Timeout,
    /// A plane call panicked.
    PlaneFault,
    /// The node got something wrong and says so without saying what.
    NodeFault,
}

impl RefusalClass {
    /// Every class.
    pub const ALL: &'static [RefusalClass] = &[
        RefusalClass::Unreadable,
        RefusalClass::Rejected,
        RefusalClass::Unauthenticated,
        RefusalClass::Forbidden,
        RefusalClass::TooLarge,
        RefusalClass::Throttled,
        RefusalClass::Busy,
        RefusalClass::QuotaExhausted,
        RefusalClass::NotFound,
        RefusalClass::Unreachable,
        RefusalClass::Unavailable,
        RefusalClass::Timeout,
        RefusalClass::PlaneFault,
        RefusalClass::NodeFault,
    ];

    /// Whether the class is a fault of this node, the one family a plane may render as its
    /// internal error. Every other class is a refusal the caller is owed by name.
    #[must_use]
    pub const fn is_node_fault(self) -> bool {
        matches!(self, RefusalClass::PlaneFault | RefusalClass::NodeFault)
    }
}

impl RefusalCode {
    /// THE class of this code: the one reason-to-class match in the tree.
    #[must_use]
    pub const fn class(self) -> RefusalClass {
        use RefusalClass as C;
        match self {
            RefusalCode::DecodeFailed => C::Unreadable,
            RefusalCode::NoRate
            | RefusalCode::Unpriced
            | RefusalCode::Replayed
            | RefusalCode::Superseded
            | RefusalCode::MethodNotAllowed => C::Rejected,
            RefusalCode::Unauthenticated
            | RefusalCode::Revoked
            | RefusalCode::SessionUnbound
            | RefusalCode::SchemeNotDeclared
            | RefusalCode::ChallengeExhausted => C::Unauthenticated,
            RefusalCode::ScopeDenied
            | RefusalCode::PoolNotPermitted
            | RefusalCode::HookVeto
            | RefusalCode::GroupFrozen
            | RefusalCode::Untrusted => C::Forbidden,
            RefusalCode::BodyTooLarge
            | RefusalCode::CursorBudget
            | RefusalCode::CredentialBudget => C::TooLarge,
            RefusalCode::RateLimited => C::Throttled,
            RefusalCode::InFlightCap | RefusalCode::InFlight => C::Busy,
            RefusalCode::OverBudget => C::QuotaExhausted,
            RefusalCode::NoDestination => C::NotFound,
            RefusalCode::DestinationUnreachable
            | RefusalCode::BreakerOpen
            | RefusalCode::DestinationBudgetExhausted
            | RefusalCode::CredentialUnavailable
            | RefusalCode::UnsentNoAttempt
            | RefusalCode::UnsentNoRoute
            | RefusalCode::UnsentNeedUnbound
            | RefusalCode::UnsentTargetNotPath
            | RefusalCode::UnsentFieldName
            | RefusalCode::UnsentUnrecorded
            | RefusalCode::UnsentAuthFailed
            | RefusalCode::UnsentOpenRefused => C::Unreachable,
            RefusalCode::SessionBudget
            | RefusalCode::SpillBudget
            | RefusalCode::ScratchExhausted
            | RefusalCode::OpenSlotBusy
            | RefusalCode::OverdraftCeiling
            | RefusalCode::StaleSlice
            | RefusalCode::DurabilityUnavailable
            | RefusalCode::TierMismatch
            | RefusalCode::Drain
            | RefusalCode::ClientGone => C::Unavailable,
            RefusalCode::Stalled | RefusalCode::DeadlineExceeded => C::Timeout,
            RefusalCode::PlanePanic => C::PlaneFault,
            RefusalCode::MeterDisputed
            | RefusalCode::HandoffMismatch
            | RefusalCode::TaskLost
            | RefusalCode::SecretPlaceholder
            | RefusalCode::Internal => C::NodeFault,
        }
    }
}

/// The class of a kernel refusal reason ([`RefusalCode::class`] of its wire code).
#[must_use]
pub const fn class_of(reason: ReasonCode) -> RefusalClass {
    wire_code(reason).class()
}

/// The class of a refusal as a plane is handed it ([`RefusalCode::class`] of its wire code).
#[must_use]
pub fn class_of_refusal(reason: crate::unit::RefusalReason) -> RefusalClass {
    class_of(ReasonCode::from(reason))
}

/// The class of a reason by its spelling on the journal and the wire (`ReasonCode::as_str`), for
/// every reason a plane can be handed ([`reason_of`]); `None` for any other word, the kernel's own
/// two money verdicts included.
#[must_use]
pub fn class_of_word(word: &str) -> Option<RefusalClass> {
    RefusalCode::ALL
        .iter()
        .find(|c| reason_of(c.code()).is_some_and(|r| r.as_str() == word))
        .map(|c| c.class())
}

// ── the Statement tail ───────────────────────────────────────────────────────────────────────────

/// A dialect's default auth style (the 1.5.5 dialect defaults), as data.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DialectAuth {
    /// Index into [`PlaneTail::dialects`].
    pub dialect: u32,
    /// [`DIALECT_PROVIDER`]; any other bit refuses the load. The word was the line's alignment
    /// padding, so a line that predates it states `0`: a dialect no provider may name (ARCHITECT
    /// ruling 2026-10-16, an append in place).
    pub flags: u32,
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

impl DialectAuth {
    /// THE EMPTY DECLARATION: every field zero (NULL lists, empty strings, no flags). A plugin
    /// builds its value as `DialectAuth { …, ..DialectAuth::ZERO }` so a field appended later reads
    /// as not declared.
    pub const ZERO: Self = Self {
        dialect: 0,
        flags: 0,
        style: AbiStr::ZERO,
        params: Blob::ZERO,
    };
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

impl OpClass {
    /// THE EMPTY DECLARATION: every field zero (NULL lists, empty strings, no flags). A plugin
    /// builds its value as `OpClass { …, ..OpClass::ZERO }` so a field appended later reads as not
    /// declared.
    pub const ZERO: Self = Self {
        op: AbiStr::ZERO,
        name: AbiStr::ZERO,
    };
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

impl BillableClass {
    /// THE EMPTY DECLARATION: every field zero (NULL lists, empty strings, no flags). A plugin
    /// builds its value as `BillableClass { …, ..BillableClass::ZERO }` so a field appended later
    /// reads as not declared.
    pub const ZERO: Self = Self {
        class: AbiStr::ZERO,
        family: AbiStr::ZERO,
    };
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
///
/// ON A CHAINED KIND:
/// * A [`RECORD_PUT`] APPENDS: its `key` is the chain's SCOPE (UTF-8, never empty, never ending in
///   what a listed key ends in) and its `value` the record's own fields, already in the framing
///   (pipe-separated: each field after a `|`, the first included). The host is the chain's
///   authority: it takes the scope's next sequence and its tail's digest, frames the prelude, seals
///   the record and keeps it once the store took it. A put of an EMPTY value drops the whole chain
///   (the tombstone of each record), and its next append starts again at sequence `1`.
/// * `records.list` answers each record as `(chain_key(scope, seq), the plane's own bytes)`
///   (`crate::services::chain_key`), every chain VERIFIED first: a chain that does not verify is
///   announced by one more span, keyed by the bare scope (it sorts ahead of the chain's records),
///   whose value is the break in words; its records are still answered (a detection never
///   deletes). An append is read back once the store took it, never from the write queue.
/// * `records.get` is refused: a chain is read whole, through `records.list`.
/// * `records.claim` is the kind's as any other's: its claims never touch the chain.
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

impl RecordChain {
    /// THE EMPTY DECLARATION: every field zero (NULL lists, empty strings, no flags). A plugin
    /// builds its value as `RecordChain { …, ..RecordChain::ZERO }` so a field appended later reads
    /// as not declared.
    pub const ZERO: Self = Self {
        kind: 0,
        framing: 0,
        flags: 0,
        _reserved: 0,
    };
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
/// [`TrustKey::role`]: the key holds the registration's CONFIGURED ITEM APPROVALS, a map of item to
/// an object whose field [`TrustKey::default`] names holds the digest the operator approved the
/// item at (`{<item>: {<field>: "<digest>"}}`). The kernel seeds the counterparty's approved items
/// from it at every admit (an edit is the operator's re-approval); an item written with a blank or
/// absent digest is allowed but approved at none, and is served at none. The core-admin trust verbs
/// approve and revoke on top of it. It carries no mechanisms and no flags; its `default` is
/// required.
pub const TRUST_ITEM_APPROVALS: u32 = 5;
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

impl PinMechanism {
    /// THE EMPTY DECLARATION: every field zero (NULL lists, empty strings, no flags). A plugin
    /// builds its value as `PinMechanism { …, ..PinMechanism::ZERO }` so a field appended later
    /// reads as not declared.
    pub const ZERO: Self = Self {
        token: AbiStr::ZERO,
        flags: 0,
        _reserved: 0,
    };
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
    /// [`TRUST_PRIVATE_REACH`] | [`TRUST_ITEM_APPROVALS`].
    pub role: u32,
    /// [`PIN_FINGERPRINT`] on a pin; `0` otherwise.
    pub flags: u32,
    /// A duration key's value when a registration writes none; absent = zero. A pin has none. On a
    /// [`TRUST_ITEM_APPROVALS`] key: the field of each item's object holding its approved digest.
    pub default: AbiStr,
    /// A pin's mechanisms; empty for a duration key.
    pub mechanisms: *const PinMechanism,
    /// How many.
    pub mechanisms_len: usize,
}

impl TrustKey {
    /// THE EMPTY DECLARATION: every field zero (NULL lists, empty strings, no flags). A plugin
    /// builds its value as `TrustKey { …, ..TrustKey::ZERO }` so a field appended later reads as
    /// not declared.
    pub const ZERO: Self = Self {
        key: AbiStr::ZERO,
        role: 0,
        flags: 0,
        default: AbiStr::ZERO,
        mechanisms: std::ptr::null(),
        mechanisms_len: 0,
    };
}

/// HOW THE TRUST KEY ROW IS MADE (status row 194): from [`TrustKey::EMPTY`], its plain fields set
/// directly and each list by its setter, to items that live for the program.
impl TrustKey {
    /// Nothing stated: every string absent, every list empty, every number zero.
    pub const EMPTY: TrustKey = TrustKey {
        key: AbiStr::ABSENT,
        role: 0,
        flags: 0,
        default: AbiStr::ABSENT,
        mechanisms: std::ptr::null(),
        mechanisms_len: 0,
    };

    abi_lists! {
        mechanisms, mechanisms_len: PinMechanism
            => mechanisms_ptr, with_mechanisms, with_raw_mechanisms;
    }
}

/// THE GRAMMAR OF [`PlaneTail::cli_help`]: the plane's rows of the host's command-line help, each
/// filling one slot of it. A row opens with [`MARK`], the slot's name and [`NAME_END`], and runs to
/// the next [`MARK`]; text before the first mark is one [`FLAG`] row (a plane that states only its
/// `Flags:` block writes it bare). The host places each slot's rows in the plane order it reads
/// them; a slot it does not know is not printed.
pub mod cli_help {
    /// Opens a row (ASCII record separator).
    pub const MARK: &str = "\u{1e}";
    /// Ends a row's slot name (ASCII unit separator).
    pub const NAME_END: &str = "\u{1f}";
    /// The one-line description the help opens with (the first one stated is printed).
    pub const TAGLINE: &str = "tagline";
    /// A block of the help's `Flags:` rows; its first word is the flag the host accepts.
    pub const FLAG: &str = "flag";
    /// A block of the help's `ENDPOINTS` rows.
    pub const ENDPOINT: &str = "endpoint";

    /// Every `(slot, text)` row `help` states, in order; a row with no [`NAME_END`] names no slot.
    pub fn rows(help: &str) -> impl Iterator<Item = (&str, &str)> {
        let (bare, marked) = help.split_once(MARK).unwrap_or((help, ""));
        let bare = (!bare.is_empty()).then_some((FLAG, bare));
        let marked = (help.contains(MARK).then_some(marked))
            .into_iter()
            .flat_map(|rest| rest.split(MARK))
            .map(|row| row.split_once(NAME_END).unwrap_or(("", row)));
        bare.into_iter().chain(marked)
    }
}

/// THE PLANE'S STATEMENT TAIL: static facts, `'static` data.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PlaneTail {
    /// The tail head.
    pub head: KindTailHead,
    /// [`TAIL_FALLBACK`] | [`TAIL_PROBES`] | [`TAIL_HOOKS_GATED`] | [`TAIL_REFUSED_PIECE`]; any
    /// other bit refuses the load.
    pub flags: u32,
    /// `INGRESS_*` bits.
    pub ingress: u32,
    /// `SHAPE_*`.
    pub dispatch_shape: u32,
    /// [`ANSWER_LAYOUT`] as the plugin was built: the layout it writes its answers in. The loader
    /// refuses a plane whose number is not the host's (a tail that predates the word states `0`,
    /// the padding it was), naming the rebuild.
    pub answer_layout: u32,
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
    /// The plane's command-line help text, in the [`cli_help`] grammar.
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
    /// THE PLANE'S STREAM CEILING, seconds (ARCHITECT ruling 2026-10-07, STREAM-CEILING): how long a
    /// unit whose `arrive` stated [`ROUTE_STREAM`] may run, measured from the moment its route is
    /// known. The kernel stamps it as the unit's deadline, so it bounds the whole streamed answer
    /// and a caller that stops reading it alike: when it passes, the unit is cut
    /// (`DeadlineExceeded`) and bills what it delivered (Part 2 #62). `0` = NO ceiling: the
    /// streamed answer runs to its own end and a stalled caller holds it until the caller goes, as
    /// the previous release served it. A tail addition: a tail whose `size` ends before it
    /// states `0`.
    pub stream_ceiling_secs: u64,
    /// THE LANE WORDS THE PLANE MAY STATE ON ITS ATTEMPTS' COUNTERS, declared once (beside the
    /// operator's entry names, the only other words [`OnPieceOut::metric_lane`] may carry): a
    /// closed vocabulary of its own, so a plane can never mint a time series per distinct string.
    /// At most [`MAX_METRIC_LANES`] words, each named, none twice. NULL/0 = none. A tail addition.
    pub metric_lanes: *const AbiStr,
    /// How many.
    pub metric_lanes_len: usize,
}

impl PlaneTail {
    /// THE EMPTY DECLARATION: every field zero (NULL lists, empty strings, no flags). A plugin
    /// builds its value as `PlaneTail { …, ..PlaneTail::ZERO }` so a field appended later reads as
    /// not declared.
    pub const ZERO: Self = Self {
        head: KindTailHead::ZERO,
        flags: 0,
        ingress: 0,
        dispatch_shape: 0,
        answer_layout: 0,
        scope: AbiStr::ZERO,
        label: AbiStr::ZERO,
        subject_noun: AbiStr::ZERO,
        admin_noun: AbiStr::ZERO,
        audit_kind: AbiStr::ZERO,
        signing_domain: AbiStr::ZERO,
        signing_kid_prefix: AbiStr::ZERO,
        cli_help: AbiStr::ZERO,
        dialects: std::ptr::null(),
        dialects_len: 0,
        dialect_auth: std::ptr::null(),
        dialect_auth_len: 0,
        scope_kinds: std::ptr::null(),
        scope_kinds_len: 0,
        op_classes: std::ptr::null(),
        op_classes_len: 0,
        billable_classes: std::ptr::null(),
        billable_classes_len: 0,
        route_cost: std::ptr::null(),
        route_cost_len: 0,
        fee_units: std::ptr::null(),
        fee_units_len: 0,
        record_kinds: std::ptr::null(),
        record_kinds_len: 0,
        egress_targets: std::ptr::null(),
        egress_targets_len: 0,
        record_chains: std::ptr::null(),
        record_chains_len: 0,
        trust_keys: std::ptr::null(),
        trust_keys_len: 0,
        refusal_statuses: std::ptr::null(),
        refusal_statuses_len: 0,
        caller_credential_refusal: AbiStr::ZERO,
        admin_routes: std::ptr::null(),
        admin_routes_len: 0,
        admin_openapi: Blob::ZERO,
        stream_ceiling_secs: 0,
        metric_lanes: std::ptr::null(),
        metric_lanes_len: 0,
    };
}

/// HOW THE PLANE KIND TAIL IS MADE (status row 194): from [`PlaneTail::EMPTY`], its plain fields
/// set directly and each list by its setter, to items that live for the program.
impl PlaneTail {
    /// Nothing stated: every string absent, every list empty, every number zero; the head
    /// sized to the whole tail.
    pub const EMPTY: PlaneTail = PlaneTail {
        head: KindTailHead {
            size: core::mem::size_of::<PlaneTail>() as u32,
            _reserved: 0,
        },
        flags: 0,
        ingress: 0,
        dispatch_shape: 0,
        answer_layout: 0,
        scope: AbiStr::ABSENT,
        label: AbiStr::ABSENT,
        subject_noun: AbiStr::ABSENT,
        admin_noun: AbiStr::ABSENT,
        audit_kind: AbiStr::ABSENT,
        signing_domain: AbiStr::ABSENT,
        signing_kid_prefix: AbiStr::ABSENT,
        cli_help: AbiStr::ABSENT,
        dialects: std::ptr::null(),
        dialects_len: 0,
        dialect_auth: std::ptr::null(),
        dialect_auth_len: 0,
        scope_kinds: std::ptr::null(),
        scope_kinds_len: 0,
        op_classes: std::ptr::null(),
        op_classes_len: 0,
        billable_classes: std::ptr::null(),
        billable_classes_len: 0,
        route_cost: std::ptr::null(),
        route_cost_len: 0,
        fee_units: std::ptr::null(),
        fee_units_len: 0,
        record_kinds: std::ptr::null(),
        record_kinds_len: 0,
        egress_targets: std::ptr::null(),
        egress_targets_len: 0,
        record_chains: std::ptr::null(),
        record_chains_len: 0,
        trust_keys: std::ptr::null(),
        trust_keys_len: 0,
        refusal_statuses: std::ptr::null(),
        refusal_statuses_len: 0,
        caller_credential_refusal: AbiStr::ABSENT,
        admin_routes: std::ptr::null(),
        admin_routes_len: 0,
        admin_openapi: Blob::ABSENT,
        stream_ceiling_secs: 0,
        metric_lanes: std::ptr::null(),
        metric_lanes_len: 0,
    };

    abi_lists! {
        dialects, dialects_len: AbiStr => dialects_ptr, with_dialects, with_raw_dialects;
        dialect_auth, dialect_auth_len: DialectAuth
            => dialect_auth_ptr, with_dialect_auth, with_raw_dialect_auth;
        scope_kinds, scope_kinds_len: AbiStr
            => scope_kinds_ptr, with_scope_kinds, with_raw_scope_kinds;
        op_classes, op_classes_len: OpClass => op_classes_ptr, with_op_classes, with_raw_op_classes;
        billable_classes, billable_classes_len: BillableClass
            => billable_classes_ptr, with_billable_classes, with_raw_billable_classes;
        route_cost, route_cost_len: RouteCost
            => route_cost_ptr, with_route_cost, with_raw_route_cost;
        fee_units, fee_units_len: AbiStr => fee_units_ptr, with_fee_units, with_raw_fee_units;
        record_kinds, record_kinds_len: AbiStr
            => record_kinds_ptr, with_record_kinds, with_raw_record_kinds;
        egress_targets, egress_targets_len: AbiStr
            => egress_targets_ptr, with_egress_targets, with_raw_egress_targets;
        record_chains, record_chains_len: RecordChain
            => record_chains_ptr, with_record_chains, with_raw_record_chains;
        trust_keys, trust_keys_len: TrustKey
            => trust_keys_ptr, with_trust_keys, with_raw_trust_keys;
        refusal_statuses, refusal_statuses_len: RefusalStatus
            => refusal_statuses_ptr, with_refusal_statuses, with_raw_refusal_statuses;
        admin_routes, admin_routes_len: AdminRoute
            => admin_routes_ptr, with_admin_routes, with_raw_admin_routes;
        metric_lanes, metric_lanes_len: AbiStr
            => metric_lanes_ptr, with_metric_lanes, with_raw_metric_lanes;
    }
}

/// The most lane words a plane's tail may declare ([`PlaneTail::metric_lanes`]).
pub const MAX_METRIC_LANES: usize = 16;

/// A plane `refresh`'s EXTENSIONS KEY ([`crate::abi::mechanism::extensions`], carried in
/// `RefreshIn::head.extensions`): the plane's other owned sections the applied document writes,
/// the same JSON object [`PlaneOpenIn::owned`] carries at `open` (keyed by section name, each as
/// written). Absent = the document writes none. A plane that reads no owned section at `refresh`
/// never reads it; the host resolves a need's `owned.` trust path against it (ABI rule: a new field
/// lives in the extensions blob first).
pub const EXT_OWNED: &str = "owned";

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

impl Claim {
    /// THE EMPTY DECLARATION: every field zero (NULL lists, empty strings, no flags). A plugin
    /// builds its value as `Claim { …, ..Claim::ZERO }` so a field appended later reads as not
    /// declared.
    pub const ZERO: Self = Self {
        verb: AbiStr::ZERO,
        target: AbiStr::ZERO,
        carrier: AbiStr::ZERO,
        flags: 0,
        refusal_dialect: 0,
        _pad: 0,
    };
}

/// One admin route the built plane serves through [`slot::SERVE`].
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AdminRoute {
    /// The verb.
    pub verb: AbiStr,
    /// The target path.
    pub target: AbiStr,
    /// [`ROUTE_PUBLIC`], with [`ROUTE_CARRIES_OWN_TOKEN`] beside it where it is set, or `0`.
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
    /// THE NAMES IT LISTS for this generation (THE DESIGN section 2: `/v1/models` appends each
    /// plane generation's listed names, filtered by the caller's grant of the plane's scope kind),
    /// each non-empty UTF-8; NULL/0 = none. A tail addition: a snapshot whose `size` ends before it
    /// lists none, and the host reads nothing past that `size`.
    pub listed: *const AbiStr,
    /// How many.
    pub listed_len: usize,
    /// THE ARRIVAL SPANS of its claims (status row 173: the request span a route's arrival opens,
    /// as the previous release's ingress entry spans did), PARALLEL to [`PlaneSnapshot::claims`]:
    /// entry `i` names the span an arrival on `claims[i]` opens, empty = that claim opens none. Each
    /// name is DATA the kernel builds one tracing callsite for when it binds the snapshot, never per
    /// request; a non-empty name is `[a-z0-9_]`, at most [`MAX_ARRIVAL_SPAN`] bytes. NULL/0 = no
    /// claim opens one; any other length than `claims_len` refuses the snapshot. A tail addition: a
    /// snapshot whose `size` ends before it opens none, and the host reads nothing past that `size`.
    pub arrival_spans: *const AbiStr,
    /// How many: `0` or `claims_len`.
    pub arrival_spans_len: usize,
}

/// The longest arrival span name a snapshot may state ([`PlaneSnapshot::arrival_spans`]).
pub const MAX_ARRIVAL_SPAN: usize = 64;

/// ONE PROVIDER'S DIALECT FACTS, as a plane receives them at `open` (THE DESIGN section 4: a
/// plane receives, at open, the dialect fields of the providers it references and resolves model
/// to dialect itself; the kernel checks no dialect).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProviderFacts {
    /// The provider's name: its key in the root `providers:` map.
    pub name: AbiStr,
    /// Its `protocol`, as the configuration resolved it (after the catalog merge).
    pub protocol: AbiStr,
    /// Its `error_map`, as one JSON object; [`crate::abi::mechanism::call::BLOB_ABSENT`] when it
    /// states none.
    pub error_map: Blob,
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
    /// THE DIALECT FACTS OF THE PROVIDERS ITS SECTION REFERENCES (each `models.<m>.provider`), one
    /// per provider, in the order first referenced; NULL/0 = none. Read at `open` only: the root
    /// `providers:` a door plane is served over are the deployment's at boot. A tail addition: a
    /// host whose `in` ends before it hands none (the `in` is read up to its `size`).
    pub providers: *const ProviderFacts,
    /// How many.
    pub providers_len: usize,
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

impl OutField {
    /// THE EMPTY DECLARATION: every field zero (NULL lists, empty strings, no flags). A plugin
    /// builds its value as `OutField { …, ..OutField::ZERO }` so a field appended later reads as
    /// not declared.
    pub const ZERO: Self = Self {
        name: Span::ZERO,
        value: Span::ZERO,
    };
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

impl UnitCount {
    /// THE EMPTY DECLARATION: every field zero (NULL lists, empty strings, no flags). A plugin
    /// builds its value as `UnitCount { …, ..UnitCount::ZERO }` so a field appended later reads as
    /// not declared.
    pub const ZERO: Self = Self {
        class: 0,
        source: 0,
        amount: 0,
    };
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

impl RecordWrite {
    /// THE EMPTY DECLARATION: every field zero (NULL lists, empty strings, no flags). A plugin
    /// builds its value as `RecordWrite { …, ..RecordWrite::ZERO }` so a field appended later reads
    /// as not declared.
    pub const ZERO: Self = Self {
        kind: 0,
        op: 0,
        key: Span::ZERO,
        value: Span::ZERO,
    };
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
    /// On REFUSED: `REFUSED_*` bits, the refusal's neutral outcome ([`REFUSED_UNSUPPORTED_ACTION`]);
    /// `0` on every other outcome. In what was padding.
    pub refusal_flags: u32,
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
    /// 2026-10-02), or [`ROUTE_LOCAL`], [`ROUTE_SCOPE`] or [`ROUTE_SCOPE_LOCAL`] with no pool named
    /// (the scope's two naming their candidates there). A tail addition;
    /// [`ROUTE_POOL`] on every
    /// other outcome.
    pub route: u8,
    /// On READY: `ROUTE_*` flag bits ([`ROUTE_ONCE`], [`ROUTE_SESSION`], [`ROUTE_STREAM`],
    /// [`ROUTE_COUNTED`]); `0`
    /// on every other outcome. A tail addition, in what was padding.
    pub route_flags: u8,
    /// Alignment padding.
    pub _route_reserved: [u8; 6],
    /// On READY: the unit's STICKY-ROUTING KEY, opaque to the kernel (ARCHITECT Q1 ArriveOut,
    /// 2026-10-05): the plane computes it from what only it reads (its dialect's body, its own
    /// section's settings), and the walk prefers one stable member for every unit stating the same
    /// key, with no plane or protocol knowledge. Absent (NULL, `0`) = no affinity, and absent on
    /// every other outcome. Plane memory, valid until the instance's next call. A tail addition.
    pub affinity: AbiStr,
    /// On READY: THE TRUST FACTS the unit rests on (ARCHITECT 2026-10-06: trust is the kernel's
    /// Approve step, and a plane states facts and judges none): the COUNTERPARTY, a name among the
    /// trust entries the plane's section declares (its trust keys). The kernel's Approve judges it
    /// against its trust book (declared, sighted, not quarantined) and refuses the unit
    /// [`RefusalCode::Untrusted`] otherwise. Absent = the unit rests on no counterparty, and nothing
    /// is judged; absent on every other outcome. Plane memory, valid until the instance's next
    /// call. A tail addition.
    pub trust_counterparty: AbiStr,
    /// With `trust_counterparty`: the ITEM the unit uses there (a tool, a skill: the plane's own
    /// per-item trust key), opaque to the kernel; the kernel requires it sighted and approved at
    /// `trust_digest`. Absent = the counterparty as a whole.
    pub trust_item: AbiStr,
    /// With `trust_item`: the DIGEST the item is offered at now, as the plane observed it,
    /// opaque to the kernel. Absent = the item's last sighting (`trust.sight_item`) stands.
    pub trust_digest: AbiStr,
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
    /// On an ATTEMPT piece: the operator's name for the member the kernel picked. On every piece
    /// with `attempt_no` `0` of a [`ROUTE_SCOPE_LOCAL`] unit: the entry its scope resolved to (it
    /// is walked to no member). Absent otherwise.
    pub member: AbiStr,
    /// On an ATTEMPT piece: the attempt's number, from `1`; `0` on every other piece.
    pub attempt_no: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// On an ATTEMPT piece: the operator's name for the pool the kernel picked `member` from (a
    /// member may shape its request differently in each pool it serves); absent otherwise.
    pub pool: AbiStr,
    /// On every piece of a unit: the caller's opaque, stable, non-reversible per-principal
    /// reference (lower-case hex), never the principal itself; absent only when the host
    /// lends no caller-reference key at all (the kernel's driver config `caller_refs: None`).
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
    /// With [`PIECE_REFUSED`]: the code of the reason the unit was refused for ([`reason_code`]);
    /// `0` on every other piece. Laid in what was the struct's tail padding.
    pub reason: u32,
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
    /// THE PLANE'S BREAKER FAULT READING of a far-end answer (ARCHITECT 2026-10-05): the
    /// destination's health as the plane reads the answer, in the transport kind's ONE fault
    /// vocabulary (`abi::transport::FAULT_*`: none, caller, transient, hard, healthy), which the
    /// breaker records against the destination (healthy: a success, whatever the status). Separate from [`OnPieceOut::verdict`] (the walk's routing
    /// reading): an answer the walk retries elsewhere may be the caller's fault, and one it keeps
    /// may still be the destination's. `FAULT_NONE` = no reading: the kernel keeps waiting for the
    /// plane's reading of that answer until its last piece, then the transport's stands. Laid in
    /// the padding after
    /// `need` (pre-tag v1).
    pub fault: u8,
    /// THE UNIT'S USAGE-TAP FAULT (`TAP_FAULT_*`), beside the units this answer reports: why the
    /// plane's usage tap could not read a same-protocol 2xx body, so the request billed 0 tokens
    /// ([`crate::codec::UsageTapFault`]). The kernel counts it, once per answer that carries it, on
    /// `busbar_billing_tap_decode_fail_total{protocol,reason}` under the unit's dialect, and warns
    /// once per `(protocol, reason)`: the fault crosses as data, never as a host call. A CLOSED
    /// enum: [`TAP_FAULT_NONE`] = none, then the named reasons; any other value is counted under
    /// `reason="unknown"` (and warned once), never ignored and never read as none. Laid in the
    /// padding after `fault` (pre-release, at the unchanged plane ABI version).
    pub tap_fault: u8,
    /// Alignment padding.
    pub _fault_reserved: [u8; 2],
    /// THE UNIT'S LEDGER LANE, in the arena; a zero length = none named. The billing identity the
    /// unit's units are priced, ledgered and metered under, which is not the route entry the walk
    /// picked (a call of one tool on a pooled server is the tool's lane, not the server's). The
    /// kernel qualifies it with the plane's own key, so a plane names lanes of its own card alone;
    /// the last one an answer of the unit named holds, and a unit whose answers name none is laned
    /// by the entry its route picked. UTF-8, without control characters. A tail addition.
    pub lane: Span,
    /// With [`EMIT_FINAL_STATUS`]: the reply's final status number, in the numbering the claim's
    /// transport declares for its own statuses. A tail addition.
    pub final_status: u32,
    /// Alignment padding.
    pub _final_reserved: u32,
    /// With [`EMIT_FINAL_STATUS`]: the final status's message, in the arena; a zero length = none.
    pub final_message: Span,
    /// With [`EMIT_FINAL_STATUS`]: the final status's details, opaque bytes the carrier hands on
    /// verbatim, in the arena; a zero length = none.
    pub final_details: Span,
    /// THE ATTEMPT'S COUNTER LABELS, stated on the answer to an ATTEMPT piece: the `pool` label
    /// the kernel's upstream-attempt and upstream-failure counters carry for it, in the arena; a
    /// zero length = none, and the kernel keeps its own (the walk's pool). The kernel takes it only
    /// from a bounded set — a pool label or an entry name the unit's route can reach — and a word
    /// outside it falls back to its own and is counted refused. UTF-8. A tail addition.
    pub metric_pool: Span,
    /// The same for the `lane` label: an entry name the unit's route can reach, or a word of the
    /// plane's declared [`PlaneTail::metric_lanes`]; anything else falls back to the kernel's own
    /// (the member's qualified entry) and is counted refused. A tail addition.
    pub metric_lane: Span,
    /// THE MEMBER WHOSE WAIT THE REFUSAL ANSWERS, stated on the answer to the [`PIECE_REFUSED`]
    /// piece the walk's exhaustion hands ([`TAIL_REFUSED_PIECE`], reason `BreakerOpen`): the ONE
    /// member of the unit's pool the plane may send this unit to (an entry name, as
    /// [`OnPieceIn::member`] lends it), in the arena; the refusal's `Retry-After` is then that
    /// member's own cooldown in the pool, never the soonest across the pool's members (the walk's
    /// figure, which a zero length keeps). Stated on any other answer, or naming no member of the
    /// unit's pool, it is refused: the unit ends as the plane's fault. UTF-8. A tail addition: a
    /// plane whose answer stops short of it states none (the host reads an absent tail field as
    /// zero, `abi::mechanism::call` SIZES).
    pub wait_member: Span,
    /// THE REASON THE FAULT READING STATES (ARCHITECT, the far-end fault reading): beside a
    /// [`OnPieceOut::fault`] reading, the plane's own neutral words for why it reads the answer so
    /// (an exhausted account, a refused credential), in the arena; a zero length = none stated. The plane classifies the far end's code; the kernel carries these words
    /// VERBATIM to the breaker's record of the reading (the member's down reason and its operator
    /// diagnostic) and never reads a code to make its own. Stated with no reading, it contradicts
    /// the answer. UTF-8. A tail addition.
    pub fault_reason: Span,
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
    /// With [`RefusalCode::Untrusted`]: why the kernel's Approve did not trust the unit's stated
    /// facts (`abi::host::service::DISTRUST_*`, the one trust vocabulary, `trust.serves`'s too),
    /// so the plane renders the words its dialect has for each (an unknown item as not found, a
    /// known one ungranted as refused); `0` on every other refusal. A tail addition.
    pub trust: u32,
    /// Alignment padding.
    pub _trust_reserved: u32,
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
    /// HOST buffer for record writes: the served request's record writes, as an `on_piece`
    /// answer's ([`RecordWrite`], their bytes in the arena), so a route (a public callback among
    /// them) writes the state transition it recorded to the plane's record chain itself. A tail
    /// addition.
    pub records_buf: *mut RecordWrite,
    /// Its capacity.
    pub records_cap: usize,
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
    /// Record writes written to `records_buf`. A tail addition.
    pub records_written: u32,
    /// Short answer: the record writes `records_buf` needs.
    pub records_needed: u32,
}

/// `catalog`'s `in`: a [`CLAIM_CATALOG`] route's request head and the names the kernel lists for
/// its caller, in the kernel's order. The plane renders the listing in the dialect the request
/// names (its own detection) into the host buffers. Pure: it never pends, and no unit exists.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CatalogIn {
    /// The head.
    pub head: InHead,
    /// The request method.
    pub method: AbiStr,
    /// The request target (path and query).
    pub target: AbiStr,
    /// The request's head fields.
    pub fields: *const Field,
    /// How many.
    pub fields_len: usize,
    /// The names, each non-empty UTF-8.
    pub names: *const AbiStr,
    /// How many.
    pub names_len: usize,
    /// HOST buffer for the reply body.
    pub reply_buf: *mut u8,
    /// Its capacity.
    pub reply_cap: usize,
    /// HOST buffer for the reply's head fields.
    pub fields_buf: *mut OutField,
    /// Its capacity.
    pub fields_cap: usize,
    /// HOST arena for the bytes of the fields.
    pub arena_buf: *mut u8,
    /// Its capacity.
    pub arena_cap: usize,
}

/// `catalog`'s `out`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CatalogOut {
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

/// The plane's `cancel` `in` (SEAM-L(r)): the lifecycle's, embedded FIRST so the dispatcher fills
/// its head as every kind's, plus HOST buffers for the cancelled unit's record writes, as an
/// `on_piece` answer's ([`RecordWrite`], their bytes in the arena): `cancel` is a unit's last
/// terminal crossing, so a unit cut by a deadline, a reload or a shutdown still writes its row.
/// `cancel` may not pend and is never re-called: what does not fit the host's buffers is FAULT.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PlaneCancelIn {
    /// The lifecycle `in`.
    pub cancel: CancelIn,
    /// HOST buffer for record writes.
    pub records_buf: *mut RecordWrite,
    /// Its capacity.
    pub records_cap: usize,
    /// HOST arena for the record writes' bytes.
    pub arena_buf: *mut u8,
    /// Its capacity.
    pub arena_cap: usize,
    /// THE CANCELLED UNIT, as the kernel minted it (the key its [`ArriveIn::unit`] carried), so a
    /// plane that keys its units from `arrive` frees it by that key: on the host's own cancel of a
    /// unit, one whose ticket no piece ever carried included (audit P-M7), and on the cancel of an
    /// op in flight, the unit that op's own `in` names. `0` for the instance's driver ticket.
    pub unit: u64,
}

/// The plane's `cancel` `out`: the lifecycle's, embedded first, and what the plane wrote.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PlaneCancelOut {
    /// The lifecycle `out` (its disposition).
    pub cancel: CancelOut,
    /// Record writes written to `records_buf`.
    pub records_written: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// Bytes written to `arena_buf`.
    pub arena_written: u64,
}

/// The status a FAULT `project` answers the caller with (1.5.5 `proxy/engine/mod.rs`: the rewrite
/// gate's `reject(500, ..)` when the validated body could not be materialized for the rewrite pass).
pub const PROJECT_FAULT_STATUS: u16 = 500;

/// The words a FAULT `project` answers the caller with, byte for byte 1.5.5's.
pub const PROJECT_FAULT_MESSAGE: &str = "request rewrite could not be applied";

/// `project`'s outcomes, and what the kernel makes of each where a rewrite hook is configured for
/// the unit (v1.5.5 `proxy/engine/mod.rs:728`: the document is materialized, `:749`, before any
/// hook runs, so the unit's first `project` is made before any rewrite hook is invoked) or the call
/// carried a rewrite ([`ProjectIn::rewrite`] present):
///
/// * READY: the view (and the rewritten body, when the plane applied the rewrite).
/// * REFUSED (or FAILED with nothing needed): the plane declines to apply the rewrite. That is the
///   rewriting hook's own failure, answered by its `on_error` (a load-bearing hook refuses the
///   unit; any other proceeds with the request as it stood).
/// * FAULT: the plane could not apply a rewrite it must not leave unapplied (a redaction whose
///   document the body does not parse into). The kernel ALWAYS answers
///   [`PROJECT_FAULT_STATUS`] with [`PROJECT_FAULT_MESSAGE`], whatever the hook's `on_error` says,
///   and the body is never forwarded: the request fails closed, as 1.5.5's did.
///
/// A FAULT the plane marked unparseable ([`project_fault_unparseable`]) on a `project` where no
/// rewrite hook is configured and no rewrite was carried (`faultable` false) is no 500: the kernel's
/// hooks judge the request as 1.5.5's judged a body it could not parse, a Null body, and the request
/// proceeds (v1.5.5 `proxy/engine/mod.rs:957-961`). Every other FAULT there (a slot panic, a frame
/// refused before the crossing, a quarantined instance, an answer that broke its kind's rule, or a
/// FAULT without the mark) is a broken plane: the unit fails closed, unreadable.
///
/// This is the one home of the mapping; the kernel holds no status or words of its own for it.
#[must_use]
pub const fn project_faults(outcome: super::mechanism::call::Outcome, faultable: bool) -> bool {
    faultable && matches!(outcome, super::mechanism::call::Outcome::Fault)
}

/// THE UNPARSEABLE-BODY MARK, in `ProjectOut::view.flags` of a FAULT `project`: the plane parsed
/// the body itself and the body's document is unparseable. It means nothing on any other outcome.
/// The mark is the plane's own word that it ran to its answer: a FAULT the host minted (a slot
/// panic, whose door writes nothing but the outcome; a frame refused before the crossing; a
/// quarantined instance; an answer that broke its kind's rule) leaves `view.flags` as the host
/// zeroed it or as the plane wrote it for another outcome, never this mark.
pub const PROJECT_FAULT_UNPARSEABLE: u32 = 1 << 31;

/// WHETHER A `project` IS THE PLANE'S OWN FAULT OVER AN UNPARSEABLE BODY: [`Outcome::Fault`], the
/// `out` head stating FAULT too (a door mirrors the outcome it answered; a READY answer the host's
/// kind check refused states READY there), and [`PROJECT_FAULT_UNPARSEABLE`] in `view.flags`.
/// Where [`project_faults`] does not make it the
/// shared 500 (no rewrite configured or carried), the kernel's hooks judge the request as 1.5.5's
/// judged a body it could not parse, a Null body. Every other FAULT fails closed.
///
/// [`Outcome::Fault`]: super::mechanism::call::Outcome::Fault
#[must_use]
pub const fn project_fault_unparseable(
    outcome: super::mechanism::call::Outcome,
    out: &ProjectOut,
) -> bool {
    use super::mechanism::call::{Outcome, RawOutcome};
    matches!(outcome, Outcome::Fault)
        && out.head.outcome.0 == RawOutcome::of(Outcome::Fault).0
        && out.view.flags == PROJECT_FAULT_UNPARSEABLE
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
unsafe impl super::sdk::door::AbiIn for PlaneCancelIn {}
unsafe impl super::sdk::door::AbiIn for ArriveIn {}
unsafe impl super::sdk::door::AbiIn for OnPieceIn {}
unsafe impl super::sdk::door::AbiIn for RefusalIn {}
unsafe impl super::sdk::door::AbiIn for ServeIn {}
unsafe impl super::sdk::door::AbiIn for ProjectIn {}
unsafe impl super::sdk::door::AbiIn for CatalogIn {}
unsafe impl super::sdk::door::AbiOut for PlaneOpenOut {}
unsafe impl super::sdk::door::AbiOut for PlaneRefreshOut {}
unsafe impl super::sdk::door::AbiOut for PlaneDriveOut {}
unsafe impl super::sdk::door::AbiOut for PlaneCancelOut {}
unsafe impl super::sdk::door::AbiOut for ArriveOut {}
unsafe impl super::sdk::door::AbiOut for OnPieceOut {}
unsafe impl super::sdk::door::AbiOut for RefusalOut {}
unsafe impl super::sdk::door::AbiOut for ServeOut {}
unsafe impl super::sdk::door::AbiOut for ProjectOut {}
unsafe impl super::sdk::door::AbiOut for CatalogOut {}

// Each plane kind op's `in`/`out`, per [`Ops`]' docs.
super::sdk::door::slot_structs!(Ops {
    slot::ARRIVE => ArriveIn, ArriveOut;
    slot::ON_PIECE => OnPieceIn, OnPieceOut;
    slot::REFUSAL => RefusalIn, RefusalOut;
    slot::SERVE => ServeIn, ServeOut;
    slot::HYDRATE => GenIn, OutHead;
    slot::START => GenIn, OutHead;
    slot::PROJECT => ProjectIn, ProjectOut;
    slot::CATALOG => CatalogIn, CatalogOut;
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
/// # ready!(Cn, PlaneCancelIn, PlaneCancelOut); ready!(Rl, ReleaseIn, OutHead); ready!(Cl, InHead, OutHead);
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
/// # ready!(Cn, PlaneCancelIn, PlaneCancelOut); ready!(Rl, ReleaseIn, OutHead); ready!(Cl, InHead, OutHead);
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
    life::CANCEL => PlaneCancelIn, PlaneCancelOut;
    life::RELEASE => ReleaseIn, OutHead;
    life::CLOSE => InHead, OutHead;
});

#[cfg(test)]
#[path = "../tests/plane_kind_tests.rs"]
mod tests;
