// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOOK KIND'S ABI: its version and its table (the design's locked plugin ABI: one
//! mechanism, every shape in `abi/`). M0 landed the skeleton; this is M3-SHAPES
//! (`abi-v2-perkind.md` B.4): `decide`, `transform`, `notify`, `configure`, `status`, `describe`
//! and `serve`, the fixed views, the Statement tail and the `CancelOut` disposition vocabulary.
//! NOTHING dispatches through this yet (M3-wire, after M1) — this crate defines the shapes and
//! their compile-time layout only. 1.5.5 behaviour stays byte-identical (a 1.6.0 FUNCTIONAL FIXED
//! POINT); this transcribes the OLD `busbar-contract::hooks`/`busbar-kernel::hooks::wire` shapes
//! (`RoutingRequest`, `Candidate`, `PromptProjection`, `CallerIdentity`, `SignalBag`,
//! `RoutingDecision`, `TransformOutcome`) into fixed C layout, unchanged in meaning.
//!
//! **OFF-WORKER (OWNER RULING, decided 2026-09-27, abi-brief.md section 4 item 1):** every hook call
//! (`decide`/`transform`/`notify`/`configure`/`status`/`describe`/`serve`) runs OFF the request's
//! own worker thread, never inline on it — the 1.5.5 `spawn_blocking` + hard-timeout parity this
//! ruling keeps (`dlopen_decide_deadline_cuts_off_a_slow_gate`,
//! `dlopen_slow_gate_hits_the_deadline`): a hook that sleeps or spins loses only its own call, not
//! its worker's other in-flight requests. Each op's contract doc below repeats this so a plugin
//! author reads it at the op, not only here; it constrains M1's dispatch (M3-wire), not a shape in
//! this file.
//!
//! B.4, transcribed:
//! - **Views** (fixed, no JSON; a `flags`/`present` bitmask marks optional fields): [`RequestView`]
//!   (the OLD `RoutingRequest`/`HookReqProjection`); the static half of `candidates[]`
//!   ([`CandidateStatic`], OLD `Candidate`'s config fields), built at generation, with the dynamic
//!   fields ([`CandidateDynamic`]) filled per request; the prompt view and body blob
//!   ([`PromptView`], OLD `PromptProjection`), both present iff `prompt` ∈ {ro, rw}, IDENTICAL for
//!   both (rw differs only at the reply, in `transform`'s rewrite grant); the user view
//!   ([`UserView`], OLD `CallerIdentity`) iff granted; the requested signals ([`SignalEntry`], OLD
//!   `SignalBag`, in push/insertion order).
//! - **Slots:** [`slot::DECIDE`] (P, may_pend): out verb bits, `reject_status` + presence,
//!   `reject_message`, `restrict_tags`, `order` into the host `order_buf`. [`slot::TRANSFORM`] (P):
//!   out verb bits plus rewrite blobs — the kernel reads only the bits; the PLANE parses and
//!   validates the blobs, and proceeds unmodified on failure; a `ro` rewrite is dropped by the
//!   kernel from the grant. [`slot::NOTIFY`] (P, taps): `in` is copied into the host-owned tap pool
//!   (global cap 1024, drop metric, [`StageView`] with no prompt or signals, `groups:` filter); it
//!   never holds the request. [`slot::CONFIGURE`], [`slot::STATUS`], [`slot::DESCRIBE`] (O): run on
//!   a FRESH MANAGEMENT INSTANCE through the same door; status and describe return the 1.5.5 blobs
//!   (as [`Blob`] payloads — off-path JSON is allowed here); configure acks the pushed version, 5s
//!   deadline, a nack does not commit. [`slot::SERVE`] (O): routes are instance facts
//!   ([`Tail::routes`]), confined to `/hooks/<name>/*`; none/key/admin auth is enforced before
//!   `serve`; admin routes are admin-listener only (kernel routing, not a new shape here).
//! - **Kernel normalizers** (HOST-SIDE, enforced on the fixed struct, unchanged from 1.5.5; not new
//!   shapes): reject > restrict (fail-closed, `on_empty`) > abstain > order, through
//!   `from_ranked`; `reject_status` clamped to 400-499, else 403; the full 1.5.5 sanitiser on
//!   `reject_message` (control characters, U+2028/2029, U+200B-200F, U+202A-202E, U+2066-2069,
//!   U+FEFF; whitespace-only falls back to the default), capped at 300 characters on a character
//!   boundary; `restrict_tags` trimmed, empties dropped.
//! - **`on_error`:** FAILED, FAULT, timeout and REFUSED feed the chain (the mechanism's own
//!   [`Outcome`](super::mechanism::call::Outcome) values plus a deadline expiry); `timeout_ms == 0`
//!   means the default. Kernel policy (`on_error` chain walk), not a new ABI shape.
//! - **`infallible` hooks:** chain terminal `Weighted`, grants forced off, `on_empty` Reject,
//!   default timeout ([`Tail::infallible`]). Plain `weighted` stays zero-cost with no policy
//!   object.
//! - **Boot:** `preopen_gate_hooks` aborts on a broken GATE and never on a broken TAP (kernel boot
//!   behaviour; [`Tail::kind_class`] is what it reads). Hook secrets are pre-resolved and fail
//!   closed (the shared `open`'s `secrets`/`secrets_len`, mechanism-level, not new here).
//! - **SDK helpers `lower_1_5_5_reply` / `projection_json`:** named in the brief for the NEW SDK
//!   (M3-wire); the current tree's equivalents are `busbar_kernel::hooks::wire::{normalize,
//!   transform_outcome}` (reply lowering) and the `SignalBag` `Serialize` impl walking `iter()` in
//!   push order (the projection). Their byte-for-byte behaviour (a typed-field mismatch answers
//!   FAILED; an out-of-range `order` index is dropped; no `requested_model`/`tool_count`/
//!   `system_chars`; `SignalBag` flattened in insertion order) is an M3-wire acceptance test, not a
//!   shape.
//! - **Acceptance:** 178 v1.5.5 hook tests ported verbatim, plus memory-form RED tests for each
//!   malformed class (M4 HOOK-PARITY, after this shape lands).
//!
//! ASSUMPTIONS (M3-SHAPES, noted for the SLOT-LOG; none are money- or customer-visible — 1.5.5
//! reply BEHAVIOUR is unchanged, only its wire shape moves from JSON to fixed C layout, which is
//! the whole point of this milestone — so none is an owner question):
//! - "hook words" (B.4's tail bullet) are the OLD `RESERVED_HOOK_NAMES` /
//!   `FROZEN_HOOK_NAME_WORD_SPACE` kernel-side reserved-name check against a plugin's own
//!   [`super::mechanism::door::Statement::name`]; they name no new Statement field.
//! - `routes` (B.4's "routes, serve" row) is [`Tail::routes`], a Statement fact the plugin states
//!   once (an OLD `HttpEndpointRequest`/`Route`-style declaration folded into the fixed tail);
//!   `serve` is the op the kernel calls per matched request.
//! - Signal ids ([`signal`]) are numbered in the OLD `Signal` enum's declared order
//!   (`busbar-contract/src/signal.rs`): `RequestedModel, RequestTotalChars, RequestMessageCount,
//!   RequestToolCount, RequestSystemChars, CandidateBreakerState, CandidateErrorRate,
//!   CandidateLatencyP95Ms, RoutingPolicy, ResponseTokensOut`.
//! - `configure`/`status`/`describe`'s `in` beyond the shared [`InHead`] is only what B.4 states
//!   (configure: a version + settings; status/describe: nothing extra) — no other 1.5.5 status
//!   JSON field is renamed or reshaped here; it crosses unchanged as a [`Blob`] payload.
//! - The `CancelOut` disposition vocabulary ([`cancel`]) is not stated in B.4; `decide`/`transform`/
//!   `serve` are this kind's `may_pend` ops, and the two dispositions below cover a cancelled
//!   verdict/response uniformly (nothing partial is ever committed for a hook reply).

use super::mechanism::call::{AbiStr, Blob, InHead, Op, OutHead};
use super::mechanism::door::KindTailHead;
use super::mechanism::lifecycle::{OpsHead, LIFECYCLE_SLOTS};

/// The hook kind's ABI version: v1.5.5 shipped `1` (`HOOK_ABI_VERSION`), so 1.6.0 ships `2`.
pub const ABI_VERSION: u32 = 2;

/// [`InHead::op`] values the hook kind adds after the shared lifecycle, in table order.
///
/// # Examples
/// ```
/// use busbar_contract::abi::hook::{slot, SLOTS};
/// use busbar_contract::abi::mechanism::lifecycle::LIFECYCLE_SLOTS;
/// assert_eq!(slot::DECIDE, LIFECYCLE_SLOTS + 0);
/// assert_eq!(slot::TRANSFORM, LIFECYCLE_SLOTS + 1);
/// assert_eq!(slot::NOTIFY, LIFECYCLE_SLOTS + 2);
/// assert_eq!(slot::CONFIGURE, LIFECYCLE_SLOTS + 3);
/// assert_eq!(slot::STATUS, LIFECYCLE_SLOTS + 4);
/// assert_eq!(slot::DESCRIBE, LIFECYCLE_SLOTS + 5);
/// assert_eq!(slot::SERVE, LIFECYCLE_SLOTS + 6);
/// assert_eq!(SLOTS, LIFECYCLE_SLOTS + 7);
/// ```
pub mod slot {
    use super::LIFECYCLE_SLOTS;

    /// `decide`.
    pub const DECIDE: u32 = LIFECYCLE_SLOTS;
    /// `transform`.
    pub const TRANSFORM: u32 = LIFECYCLE_SLOTS + 1;
    /// `notify`.
    pub const NOTIFY: u32 = LIFECYCLE_SLOTS + 2;
    /// `configure`.
    pub const CONFIGURE: u32 = LIFECYCLE_SLOTS + 3;
    /// `status`.
    pub const STATUS: u32 = LIFECYCLE_SLOTS + 4;
    /// `describe`.
    pub const DESCRIBE: u32 = LIFECYCLE_SLOTS + 5;
    /// `serve`.
    pub const SERVE: u32 = LIFECYCLE_SLOTS + 6;
}

/// How many slots the hook kind's whole table holds (the lifecycle plus its seven own ops).
pub const SLOTS: u32 = LIFECYCLE_SLOTS + 7;

/// The hook kind's ops table. Leads with the shared [`OpsHead`]; kind op `k` is at slot index
/// [`LIFECYCLE_SLOTS`]` + k` ([`slot`]). EVERY slot below is called OFF-WORKER (module doc).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Ops {
    /// The lifecycle.
    pub head: OpsHead,
    /// Rank/gate a request. REQUEST-PATH, `may_pend`,
    /// [`DeadlineClass::Call`](super::mechanism::call::DeadlineClass::Call), off-worker. In
    /// [`DecideIn`], out [`DecideOut`].
    pub decide: Option<Op>,
    /// Rewrite a request the plugin has `ro`/`rw` prompt access to. REQUEST-PATH, `may_pend`,
    /// [`DeadlineClass::Call`](super::mechanism::call::DeadlineClass::Call), off-worker. In
    /// [`DecideIn`] (the same views `decide` sees), out [`TransformOut`].
    pub transform: Option<Op>,
    /// Watch a request; fire-and-forget. REQUEST-PATH, `may_pend`,
    /// [`DeadlineClass::Call`](super::mechanism::call::DeadlineClass::Call), off-worker,
    /// off-request (it never holds the request open). In [`NotifyIn`], out [`OutHead`].
    pub notify: Option<Op>,
    /// Push settings to a fresh management instance. OFF-PATH, `may_pend`, 5s deadline
    /// ([`DeadlineClass::Call`](super::mechanism::call::DeadlineClass::Call)), off-worker. In
    /// [`ConfigureIn`], out [`ConfigureOut`].
    pub configure: Option<Op>,
    /// The 1.5.5 status blob, unchanged. OFF-PATH, not `may_pend`, off-worker. In [`InHead`], out
    /// [`StatusOut`].
    pub status: Option<Op>,
    /// The 1.5.5 describe blob, unchanged. OFF-PATH, not `may_pend`, off-worker. In [`InHead`],
    /// out [`DescribeOut`].
    pub describe: Option<Op>,
    /// The plugin's own HTTP surface (`/hooks/<name>/*`, [`Tail::routes`]). OFF-PATH, `may_pend`,
    /// [`DeadlineClass::Call`](super::mechanism::call::DeadlineClass::Call), off-worker. In
    /// [`ServeIn`], out [`ServeOut`].
    pub serve: Option<Op>,
}

// ── Signals (OLD `Signal`/`SignalBag`, `busbar-contract/src/signal.rs`) ─────────────────────────

/// One requested/reported signal, in push (insertion) order — the fixed-layout form of the OLD
/// `SignalBag`, whose `Serialize` impl walks `iter()` in that same order.
pub mod signal {
    /// OLD `Signal::RequestedModel`.
    pub const REQUESTED_MODEL: u32 = 0;
    /// OLD `Signal::RequestTotalChars`.
    pub const REQUEST_TOTAL_CHARS: u32 = 1;
    /// OLD `Signal::RequestMessageCount`.
    pub const REQUEST_MESSAGE_COUNT: u32 = 2;
    /// OLD `Signal::RequestToolCount`.
    pub const REQUEST_TOOL_COUNT: u32 = 3;
    /// OLD `Signal::RequestSystemChars`.
    pub const REQUEST_SYSTEM_CHARS: u32 = 4;
    /// OLD `Signal::CandidateBreakerState`.
    pub const CANDIDATE_BREAKER_STATE: u32 = 5;
    /// OLD `Signal::CandidateErrorRate`.
    pub const CANDIDATE_ERROR_RATE: u32 = 6;
    /// OLD `Signal::CandidateLatencyP95Ms`.
    pub const CANDIDATE_LATENCY_P95_MS: u32 = 7;
    /// OLD `Signal::RoutingPolicy`.
    pub const ROUTING_POLICY: u32 = 8;
    /// OLD `Signal::ResponseTokensOut`.
    pub const RESPONSE_TOKENS_OUT: u32 = 9;
}

/// One signal value, keyed by a [`signal`] id, in push order.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SignalEntry {
    /// A [`signal`] constant.
    pub id: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// The value.
    pub value: f64,
}

// ── Views ────────────────────────────────────────────────────────────────────────────────────

/// [`RequestView::flags`]: `max_tokens` is present.
pub const REQUEST_HAS_MAX_TOKENS: u32 = 1 << 0;
/// [`RequestView::flags`]: the request declares tool definitions.
pub const REQUEST_HAS_TOOLS: u32 = 1 << 1;
/// [`RequestView::flags`]: the request is streamed.
pub const REQUEST_STREAM: u32 = 1 << 2;

/// The request view (OLD `RoutingRequest`/`HookReqProjection`): what `decide`/`transform` see
/// about the request itself, minus the prompt and identity (their own views, granted separately).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RequestView {
    /// The OLD `request_id`.
    pub request_id: u64,
    /// The OLD `pool`.
    pub pool: AbiStr,
    /// The OLD `ingress_protocol`.
    pub ingress_protocol: AbiStr,
    /// The OLD `message_count`.
    pub message_count: u64,
    /// The OLD `total_chars`.
    pub total_chars: u64,
    /// The OLD `max_tokens`, meaningful only when [`REQUEST_HAS_MAX_TOKENS`] is set.
    pub max_tokens: u32,
    /// [`REQUEST_HAS_MAX_TOKENS`] | [`REQUEST_HAS_TOOLS`] | [`REQUEST_STREAM`].
    pub flags: u32,
    /// The requested/reported signals ([`SignalEntry`]), in push order.
    pub signals: *const SignalEntry,
    /// How many.
    pub signals_len: usize,
}

/// [`CandidateStatic::present`]: `context_max` is present.
pub const CANDIDATE_HAS_CONTEXT_MAX: u32 = 1 << 0;
/// [`CandidateStatic::present`]: `tier` is present.
pub const CANDIDATE_HAS_TIER: u32 = 1 << 1;
/// [`CandidateStatic::present`]: `cost_per_mtok` is present.
pub const CANDIDATE_HAS_COST_PER_MTOK: u32 = 1 << 2;

/// The STATIC half of one candidate (OLD `Candidate`'s pool-config fields): built once at
/// generation and unchanged across requests (memory class ii, valid to the next `refresh`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CandidateStatic {
    /// The OLD `idx`: this candidate's position, stable across a generation.
    pub idx: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// The OLD `model`.
    pub model: AbiStr,
    /// The OLD `provider`.
    pub provider: AbiStr,
    /// The OLD `weight`.
    pub weight: u32,
    /// The OLD `context_max`, meaningful only when [`CANDIDATE_HAS_CONTEXT_MAX`] is set.
    pub context_max: u32,
    /// The OLD `tier`, meaningful only when [`CANDIDATE_HAS_TIER`] is set.
    pub tier: AbiStr,
    /// The OLD `cost_per_mtok`, meaningful only when [`CANDIDATE_HAS_COST_PER_MTOK`] is set.
    pub cost_per_mtok: f64,
    /// The OLD `tags`.
    pub tags: *const AbiStr,
    /// How many.
    pub tags_len: usize,
    /// [`CANDIDATE_HAS_CONTEXT_MAX`] | [`CANDIDATE_HAS_TIER`] | [`CANDIDATE_HAS_COST_PER_MTOK`].
    pub present: u32,
    /// Alignment padding.
    pub _reserved2: u32,
}

/// [`CandidateDynamic::present`]: `latency_ms` is present.
pub const CANDIDATE_HAS_LATENCY_MS: u32 = 1 << 0;
/// [`CandidateDynamic::present`]: `budget_remaining` is present.
pub const CANDIDATE_HAS_BUDGET_REMAINING: u32 = 1 << 1;
/// [`CandidateDynamic::present`]: `rate_headroom` is present.
pub const CANDIDATE_HAS_RATE_HEADROOM: u32 = 1 << 2;

/// The DYNAMIC half of one candidate (OLD `Candidate`'s live fields): filled per request, parallel
/// to a [`CandidateStatic`] array of the same length and order.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CandidateDynamic {
    /// The OLD `latency_ms`, meaningful only when [`CANDIDATE_HAS_LATENCY_MS`] is set.
    pub latency_ms: f64,
    /// The OLD `available_concurrency`.
    pub available_concurrency: u64,
    /// The OLD `budget_remaining`, meaningful only when [`CANDIDATE_HAS_BUDGET_REMAINING`] is set
    /// — DYNAMIC, a per-request store read (the hook view's "cost" field the brief asks be listed).
    pub budget_remaining: i64,
    /// The OLD `rate_headroom`, meaningful only when [`CANDIDATE_HAS_RATE_HEADROOM`] is set —
    /// DYNAMIC, a per-request governance read (the hook view's "budget" field the brief asks be
    /// listed).
    pub rate_headroom: f64,
    /// This candidate's own signals ([`SignalEntry`]), in push order.
    pub signals: *const SignalEntry,
    /// How many.
    pub signals_len: usize,
    /// [`CANDIDATE_HAS_LATENCY_MS`] | [`CANDIDATE_HAS_BUDGET_REMAINING`] |
    /// [`CANDIDATE_HAS_RATE_HEADROOM`].
    pub present: u32,
    /// Alignment padding.
    pub _reserved: u32,
}

/// The prompt view and body blob (OLD `PromptProjection`): present, and IDENTICAL, whenever
/// `prompt` is granted `ro` or `rw` ([`PROMPT_RO`]/[`PROMPT_RW`]); absent (`system` NULL, `body`
/// absent, `message_count == 0`) otherwise.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PromptView {
    /// The OLD `PromptProjection::system`; NULL = none.
    pub system: AbiStr,
    /// The OLD `PromptProjection::messages`'s length.
    pub message_count: u64,
    /// The body blob: the flattened `(role, text)` messages, as a
    /// [`super::mechanism::call::BLOB_JSON`] payload — tool-call args/results and reasoning text
    /// already flattened into message text, unreadable content already replaced by the 1.5.5
    /// marker, byte-identical to the OLD wire's `HookMessage[]`.
    pub body: Blob,
}

/// The user view (OLD `CallerIdentity`): present iff `user` access is granted
/// ([`USER_RO`]); every field NULL when not granted.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct UserView {
    /// The OLD `key_id`; NULL = none.
    pub key_id: AbiStr,
    /// The OLD `key_name`; NULL = none.
    pub key_name: AbiStr,
    /// The OLD `user`; NULL = none.
    pub user: AbiStr,
}

/// [`DecideIn`]/`TransformIn`'s `present`: the prompt view/body are populated.
pub const VIEW_HAS_PROMPT: u32 = 1 << 0;
/// [`DecideIn`]/`TransformIn`'s `present`: the user view is populated.
pub const VIEW_HAS_USER: u32 = 1 << 1;

/// `decide`'s and `transform`'s shared `in` (both ops see identical views; only their `out` and
/// grant differ — B.4: "identical for both").
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DecideIn {
    /// The head.
    pub head: InHead,
    /// The request view.
    pub request: RequestView,
    /// The static half of each candidate, [`candidates_len`](Self::candidates_len) long.
    pub candidates: *const CandidateStatic,
    /// The dynamic half of each candidate, the SAME length, in the SAME order.
    pub candidate_dynamics: *const CandidateDynamic,
    /// How many candidates.
    pub candidates_len: usize,
    /// The prompt view; meaningful only when [`VIEW_HAS_PROMPT`] is set.
    pub prompt: PromptView,
    /// The user view; meaningful only when [`VIEW_HAS_USER`] is set.
    pub user: UserView,
    /// [`VIEW_HAS_PROMPT`] | [`VIEW_HAS_USER`].
    pub present: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// The host-owned buffer `decide` writes a candidate order into (request-path result buffers
    /// are host-owned); unused by `transform`.
    pub order_buf: *mut u32,
    /// `order_buf`'s capacity.
    pub order_cap: usize,
}

/// [`DecideOut::verbs`]: prefer an order (`order_buf`/`order_written` hold it) — OLD
/// `RoutingDecision::Prefer`.
pub const VERB_PREFER: u32 = 1 << 0;
/// [`DecideOut::verbs`]: no opinion — OLD `RoutingDecision::Abstain`.
pub const VERB_ABSTAIN: u32 = 1 << 1;
/// [`DecideOut::verbs`]: refuse the request — OLD `RoutingDecision::Reject`.
pub const VERB_REJECT: u32 = 1 << 2;
/// [`DecideOut::verbs`]: narrow to `restrict_tags` — OLD `RoutingDecision::Restrict`.
pub const VERB_RESTRICT: u32 = 1 << 3;

/// `decide`'s `out`. Precedence when more than one verb bit is set is a KERNEL normalizer (module
/// doc): reject > restrict > order/abstain.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DecideOut {
    /// The head.
    pub head: OutHead,
    /// [`VERB_PREFER`] | [`VERB_ABSTAIN`] | [`VERB_REJECT`] | [`VERB_RESTRICT`].
    pub verbs: u32,
    /// The OLD `Reject::status`; the kernel clamps it to 400-499, else 403.
    pub reject_status: u16,
    /// Alignment padding.
    pub _reserved: u16,
    /// The OLD `Reject::message`; the kernel runs the full 1.5.5 sanitiser and 300-char cap on it.
    pub reject_message: AbiStr,
    /// The OLD `Restrict::tags_any`.
    pub restrict_tags: *const AbiStr,
    /// How many.
    pub restrict_tags_len: usize,
    /// How many `u32` candidate indices the plugin wrote into `order_buf` (an out-of-range index
    /// is dropped by the kernel, per `lower_1_5_5_reply`'s stated behaviour).
    pub order_written: usize,
}

/// [`TransformOut::verbs`]: apply `rewrite` — OLD `TransformOutcome::Rewrite`.
pub const VERB_REWRITE: u32 = 1 << 0;
// VERB_ABSTAIN and VERB_REJECT (above) are reused for transform's OLD `Abstain`/`Reject`; OLD
// `Failed` maps to the mechanism's own `Outcome::Failed` rather than a verb bit.

/// `transform`'s `out`. The kernel reads ONLY `verbs`; the PLANE parses and validates `rewrite`,
/// proceeding unmodified on failure. A `ro`-granted rewrite is dropped by the kernel from the
/// grant (never reaches the plane).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TransformOut {
    /// The head.
    pub head: OutHead,
    /// [`VERB_REWRITE`] | [`VERB_ABSTAIN`] | [`VERB_REJECT`].
    pub verbs: u32,
    /// The OLD `Reject::status`; the kernel clamps it to 400-499, else 403.
    pub reject_status: u16,
    /// Alignment padding.
    pub _reserved: u16,
    /// The OLD `Reject::message`; sanitised the same way as `decide`'s.
    pub reject_message: AbiStr,
    /// Opaque to the kernel: the OLD `RewriteReply` (`messages[]`, `tools[]`), as a
    /// [`super::mechanism::call::BLOB_JSON`] payload the PLANE parses.
    pub rewrite: Blob,
}

/// The stage view a tap receives (OLD "stage projection"): [`RequestView`] with NO prompt and NO
/// signals — B.4's explicit exclusion.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct StageView {
    /// The OLD `request_id`.
    pub request_id: u64,
    /// The OLD `pool`.
    pub pool: AbiStr,
    /// The OLD `ingress_protocol`.
    pub ingress_protocol: AbiStr,
    /// The OLD `message_count`.
    pub message_count: u64,
    /// The OLD `total_chars`.
    pub total_chars: u64,
    /// The OLD `max_tokens`, meaningful only when [`REQUEST_HAS_MAX_TOKENS`] is set.
    pub max_tokens: u32,
    /// [`REQUEST_HAS_MAX_TOKENS`] | [`REQUEST_HAS_TOOLS`] | [`REQUEST_STREAM`].
    pub flags: u32,
}

/// `notify`'s `in`: a value COPY into the host-owned tap pool (global cap 1024, a drop metric past
/// it, `groups:` filtered before this call is ever made) — it never holds the request open.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NotifyIn {
    /// The head.
    pub head: InHead,
    /// The stage view.
    pub stage: StageView,
}

/// `configure`'s `in`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ConfigureIn {
    /// The head.
    pub head: InHead,
    /// The pushed configuration version.
    pub version: u64,
    /// The settings blob.
    pub settings: Blob,
}

/// `configure`'s `out`. `acked_version == version` on success; a nack (any other outcome, or a
/// differing `acked_version`) does not commit.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ConfigureOut {
    /// The head.
    pub head: OutHead,
    /// The version this fresh management instance acknowledges.
    pub acked_version: u64,
}

/// `status`'s `out`: the 1.5.5 status blob, unchanged.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct StatusOut {
    /// The head.
    pub head: OutHead,
    /// The 1.5.5 status JSON, as a [`super::mechanism::call::BLOB_JSON`] blob.
    pub status: Blob,
}

/// `describe`'s `out`: the 1.5.5 describe blob, unchanged.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DescribeOut {
    /// The head.
    pub head: OutHead,
    /// The 1.5.5 describe JSON, as a [`super::mechanism::call::BLOB_JSON`] blob.
    pub describe: Blob,
}

/// `serve`'s `in`: one HTTP request dispatched to this hook's own routes
/// (`/hooks/<name>/*`, [`Tail::routes`]). None/key/admin auth is enforced by the kernel BEFORE
/// this call; admin routes are reachable only on the admin listener.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ServeIn {
    /// The head.
    pub head: InHead,
    /// The HTTP method.
    pub method: AbiStr,
    /// The path, confined to `/hooks/<name>/*`.
    pub path: AbiStr,
    /// The raw query string; absent = none.
    pub query: AbiStr,
    /// Header name/value pairs, interleaved (`name`, `value`, …).
    pub headers: *const AbiStr,
    /// How many `AbiStr` entries `headers` holds (twice the header count).
    pub headers_len: usize,
    /// The request body; absent = none.
    pub body: Blob,
}

/// `serve`'s `out`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ServeOut {
    /// The head.
    pub head: OutHead,
    /// The HTTP status code.
    pub status_code: u16,
    /// Alignment padding.
    pub _reserved: [u8; 6],
    /// Response header name/value pairs, interleaved, under `head.lease` until `release(lease)`.
    pub headers_out: *const AbiStr,
    /// How many `AbiStr` entries `headers_out` holds.
    pub headers_out_len: usize,
    /// The response body.
    pub body: Blob,
}

// ── Statement tail ───────────────────────────────────────────────────────────────────────────

/// [`Tail::kind_class`]: a GATE (fire-and-wait; `decide`/`transform` may block the chain) — OLD
/// `HookKind::Gate`.
pub const CLASS_GATE: u32 = 0;
/// [`Tail::kind_class`]: a TAP (fire-and-forget; `notify` only) — OLD `HookKind::Tap`.
pub const CLASS_TAP: u32 = 1;

/// [`Tail::prompt_access`]: no prompt view/body — OLD `PromptAccess::No` (the default).
pub const PROMPT_NO: u32 = 0;
/// [`Tail::prompt_access`]: read-only prompt view/body — OLD `PromptAccess::Ro`.
pub const PROMPT_RO: u32 = 1;
/// [`Tail::prompt_access`]: read-write — the same view/body as `ro`, PLUS the `transform` rewrite
/// grant — OLD `PromptAccess::Rw`.
pub const PROMPT_RW: u32 = 2;

/// [`Tail::user_access`]: no user view — OLD `UserAccess::No` (the default).
pub const USER_NO: u32 = 0;
/// [`Tail::user_access`]: read-only user view — OLD `UserAccess::Ro`.
pub const USER_RO: u32 = 1;

/// The hook kind's Statement tail (B.4's "Tail"): the OLD `HookKind`, `PromptAccess`,
/// `UserAccess`, `infallible` fact, the signals this instance wants and the routes it serves.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Tail {
    /// The head.
    pub head: KindTailHead,
    /// [`CLASS_GATE`] | [`CLASS_TAP`].
    pub kind_class: u32,
    /// [`PROMPT_NO`] | [`PROMPT_RO`] | [`PROMPT_RW`].
    pub prompt_access: u32,
    /// [`USER_NO`] | [`USER_RO`].
    pub user_access: u32,
    /// Non-zero: an INFALLIBLE hook — the chain terminal is forced `Weighted`, grants are forced
    /// off, `on_empty` is forced `Reject`, and the timeout is forced to the default.
    pub infallible: u8,
    /// Alignment padding.
    pub _reserved: [u8; 3],
    /// The [`signal`] ids this instance wants reported on [`RequestView::signals`] /
    /// [`CandidateDynamic::signals`].
    pub requested_signals: *const u32,
    /// How many.
    pub requested_signals_len: usize,
    /// The HTTP route path patterns this instance serves via `serve`, confined to
    /// `/hooks/<name>/*`.
    pub routes: *const AbiStr,
    /// How many.
    pub routes_len: usize,
}

/// The hook kind's [`super::mechanism::lifecycle::CancelOut::disposition`] vocabulary.
///
/// ASSUMPTION (M3-SHAPES): B.4 does not enumerate a cancel disposition vocabulary; a hook reply is
/// never partially committed (the kernel normalizer runs on a complete `out` or not at all), so
/// the two dispositions below cover every `may_pend` op (`decide`/`transform`/`serve`) uniformly.
pub mod cancel {
    /// The pending op was aborted before it produced a verdict/response; `on_error` runs as
    /// though this call had answered [`super::super::mechanism::call::Outcome::Failed`].
    pub const ABORTED: u32 = 0;
    /// The op had already completed when the cancel arrived (a race with the deadline); its
    /// result stands.
    pub const RACED_TO_COMPLETION: u32 = 1;
}
