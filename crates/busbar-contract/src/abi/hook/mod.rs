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
//! `RoutingDecision`, `TransformOutcome`, `HookStageProjection`, `HookContext`,
//! `BudgetBucketState`) into fixed C layout, unchanged in meaning.
//!
//! **ARCHITECT REVIEW RULING (fresh-Opus M3-SHAPES review, 2026-09-28), folded in on top of the
//! first landing:**
//! 1. **No plugin-pointer results on the request path.** `decide`/`transform` are REQUEST-PATH, so
//!    every result they write goes into a HOST-owned buffer named in [`DecideIn`]
//!    (`reject_message_buf`/`_cap`, `restrict_tags_buf`/`_cap`, `rewrite_buf`/`_cap`, alongside the
//!    existing `order_buf`/`_cap`), never a plugin-owned pointer in the `out`. Each has a
//!    `*_written`/`*_needed` pair in [`DecideOut`]/[`TransformOut`]: too small a cap means the
//!    plugin writes nothing, sets `*_needed`, and the host re-invokes ONCE with a bigger buffer.
//! 2. Off-path lists/text the plugin DOES own ([`ScrapeIn`]'s snapshot aside — see export) stay
//!    [`Blob`]/pointer results ONLY on off-path ops, under memory class (iv): held live under
//!    `head.lease` until `release(lease)`. [`StatusOut`], [`DescribeOut`] and off-path route
//!    responses are that class; noted on each.
//! 3. [`SignalEntry`] carries a TAGGED value (`tag` + a 16-byte payload), not a bare `f64`, so an
//!    integer signal renders as an integer and a string signal as a string once wired (1.5.5's
//!    `SignalBag` JSON is not all-numeric).
//! 4. [`StageView`] gains the OLD `HookStageProjection` fields (`at`, `model`, `attempt_number`,
//!    `remaining_candidates`, `previous_failure`, `outcome`, `status`), presence-bitmasked, so a
//!    stage tap (candidate/routing/response) carries what 1.5.5 carried; a REQUEST-stage tap sets
//!    no stage-projection presence bit (1.5.5's `stage: None`).
//! 5. [`DecideIn`] gains the OLD `HookContext` (`budget_remaining` + presence,
//!    `budget: *const `[`BudgetBucketState`]).
//! 6. **Zero-copy body, no kernel-built JSON (owner rule, ruling 3 of the shared mechanism).**
//!    [`PromptView::body`] is the RAW origin-dialect request bytes
//!    ([`super::mechanism::call::BLOB_OCTETS`]), not kernel-flattened JSON; the SDK/plugin parses
//!    its own dialect. [`TransformOut`]'s rewrite bytes are likewise plugin-produced dialect bytes
//!    written into the host's `rewrite_buf`, opaque octets, never kernel-built JSON.
//! 7. [`DecideOut`] gains `VERB_HAS_REJECT_STATUS`; without it the mechanism's 403 default applies
//!    (a plugin that rejects without an opinion on the status need not compute one).
//! 8. `ingress_protocol` renamed `ingress_dialect` throughout (the SDK maps it to the frozen 1.5.5
//!    wire key, whatever that key's own spelling is — a wire-key rename is not implied).
//!    [`CandidateStatic::context_max`] widened `u32` -> `u64` (a context window is a token count,
//!    not bounded to 32 bits).
//!
//! **SECOND REVIEW PASS (ARCHITECT ruling, 2026-09-28), folded in on the same landing — the
//! reviewer's own "extra parity findings" beyond the fresh-Opus review's ten items:**
//! 9. [`Tail::routes`] carries [`Route`] entries (`path`, `method`, `auth`), not bare path
//!    strings: none/key/admin auth cannot be read off a path, and `{path, method}` is the
//!    collision key the kernel checks at load (the same shape B.5 gives export's routes).
//! 10. [`ConfigureIn`] gains `name`, echoing the OLD `ConfigureBody`'s instance name.
//! 11. Hook words are [`Tail::declared_words`]: STATIC, a Statement fact (see the ASSUMPTIONS
//!    section below, now a ruling rather than an assumption).
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
//! - **Views** (fixed, no JSON on the request path — [`PromptView::body`] crosses as raw octets,
//!   never a kernel-built document; a `flags`/`present` bitmask marks optional fields):
//!   [`RequestView`] (the OLD `RoutingRequest`/`HookReqProjection`); the static half of
//!   `candidates[]` ([`CandidateStatic`], OLD `Candidate`'s config fields), built at generation,
//!   with the dynamic fields ([`CandidateDynamic`]) filled per request; the prompt view and body
//!   blob ([`PromptView`], OLD `PromptProjection`), both present iff `prompt` ∈ {ro, rw}, IDENTICAL
//!   for both (rw differs only at the reply, in `transform`'s rewrite grant); the user view
//!   ([`UserView`], OLD `CallerIdentity`) iff granted; the requested signals ([`SignalEntry`], OLD
//!   `SignalBag`, in push/insertion order); the OLD `HookContext` budget fields on [`DecideIn`].
//! - **Slots:** [`slot::DECIDE`] (P, may_pend): out verb bits, `reject_status` + presence,
//!   a reject-message write into the host buffer, a restrict-tags write into the host buffer,
//!   `order` into the host `order_buf`. [`slot::TRANSFORM`] (P): out verb bits plus a rewrite-bytes
//!   write into the host buffer — the kernel reads only the bits; the CALLER (whichever
//!   request-serving code invoked this chain) parses and validates the bytes, and proceeds
//!   unmodified on failure; a `ro` rewrite is dropped by the kernel from the grant.
//!   [`slot::NOTIFY`] (P, taps): `in` is copied into the host-owned tap pool (global cap 1024, drop
//!   metric, [`StageView`] with no prompt or signals, `groups:` filter); it never holds the
//!   request. [`slot::CONFIGURE`], [`slot::STATUS`], [`slot::DESCRIBE`] (O): run on a FRESH
//!   MANAGEMENT INSTANCE through the same door; status and describe return the 1.5.5 blobs (as
//!   [`Blob`] payloads — off-path JSON is allowed here); configure acks the pushed version, 5s
//!   deadline, a nack does not commit. [`slot::SERVE`] (O): routes are instance facts
//!   ([`Tail::routes`]), confined to `/hooks/<name>/*`; none/key/admin auth is enforced before
//!   `serve`; admin routes are admin-listener only (kernel routing, not a new shape here).
//! - **Kernel normalizers** (HOST-SIDE, enforced on the fixed struct, unchanged from 1.5.5; not new
//!   shapes): `reject_status` clamped to 400-499, else 403 when [`VERB_HAS_REJECT_STATUS`] is
//!   unset; the full 1.5.5 sanitiser on the reject-message bytes (control characters, U+2028/2029,
//!   U+200B-200F, U+202A-202E, U+2066-2069, U+FEFF; whitespace-only falls back to the default),
//!   capped at 300 characters on a character boundary; restrict-tags trimmed, empties dropped.
//!   (H1: exactly one `verbs` bit on READY makes the old cross-verb precedence chain moot — a
//!   plugin cannot answer with two verbs for the kernel to rank.)
//! - **`on_error`:** FAILED, FAULT, timeout and REFUSED feed the chain (the mechanism's own
//!   [`Outcome`](super::mechanism::call::Outcome) values plus a deadline expiry); `timeout_ms == 0`
//!   means the default. Kernel policy (`on_error` chain walk), not a new ABI shape.
//! - **`infallible` hooks:** chain terminal `Weighted`, grants forced off, `on_empty` Reject,
//!   default timeout ([`Tail::infallible`]). Plain `weighted` stays zero-cost with no policy
//!   object.
//! - **Boot:** `preopen_gate_hooks` aborts on a broken GATE and never on a broken TAP (kernel boot
//!   behaviour; [`Tail::kind_class`] is what it reads). Hook secrets are pre-resolved and fail
//!   closed (the shared `open`'s `secrets`/`secrets_len`, mechanism-level, not new here).
//! - **SDK helpers `lower_1_5_5_reply` / `projection_json`:** the NEW SDK's (M3-wire) equivalents
//!   of the current tree's `busbar_kernel::hooks::wire::{normalize,
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
//! - "hook words" (B.4's tail bullet) are [`Tail::declared_words`] (ARCHITECT ruling, folded in on
//!   top of the first landing): STATIC, a Statement fact, not a per-call answer — a native
//!   ranking strategy (the OLD `RESERVED_HOOK_NAMES`: `cheapest`/`fastest`/`least_busy`/`usage`)
//!   becomes a hook plugin by declaring the word it claims here.
//! - `routes` (B.4's "routes, serve" row) is [`Tail::routes`], now [`Route`] entries (path +
//!   method + auth, ARCHITECT ruling: a bare path string cannot state none/key/admin auth), a
//!   Statement fact the plugin states once; `serve` is the op the kernel calls per matched
//!   request.
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

pub mod validate;
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
    /// [`StatusOut`] (memory class iv: the blob lives under `head.lease` until `release`).
    pub status: Option<Op>,
    /// The 1.5.5 describe blob, unchanged. OFF-PATH, not `may_pend`, off-worker. In [`InHead`],
    /// out [`DescribeOut`] (memory class iv: the blob lives under `head.lease` until `release`).
    pub describe: Option<Op>,
    /// The plugin's own HTTP surface (`/hooks/<name>/*`, [`Tail::routes`]). OFF-PATH, `may_pend`,
    /// [`DeadlineClass::Call`](super::mechanism::call::DeadlineClass::Call), off-worker. In
    /// [`ServeIn`], out [`ServeOut`] (memory class iv: the response headers/body live under
    /// `head.lease` until `release`).
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

/// [`SignalEntry::tag`]: the payload is [`SignalValue::u64_`].
pub const SIGNAL_TAG_U64: u32 = 0;
/// [`SignalEntry::tag`]: the payload is [`SignalValue::i64_`].
pub const SIGNAL_TAG_I64: u32 = 1;
/// [`SignalEntry::tag`]: the payload is [`SignalValue::f64_`].
pub const SIGNAL_TAG_F64: u32 = 2;
/// [`SignalEntry::tag`]: the payload is [`SignalValue::str_`].
pub const SIGNAL_TAG_STR: u32 = 3;
/// [`SignalEntry::tag`]: the payload is [`SignalValue::boolean`] (`0`/`1`).
pub const SIGNAL_TAG_BOOL: u32 = 4;

/// One signal's value, tagged by [`SignalEntry::tag`] (ARCHITECT review ruling 3: 1.5.5's
/// `SignalBag` JSON is not all-numeric — `RoutingPolicy` is a string, `RequestedModel` a string —
/// so the ABI carries a real tag rather than coercing every signal to `f64`). 16 bytes, the same
/// width as an [`AbiStr`], so every variant fits without indirection.
#[repr(C)]
#[derive(Clone, Copy)]
pub union SignalValue {
    /// Live iff `tag == `[`SIGNAL_TAG_U64`].
    pub u64_: u64,
    /// Live iff `tag == `[`SIGNAL_TAG_I64`].
    pub i64_: i64,
    /// Live iff `tag == `[`SIGNAL_TAG_F64`].
    pub f64_: f64,
    /// Live iff `tag == `[`SIGNAL_TAG_BOOL`]; `0` false, `1` true (widened for a stable layout).
    pub boolean: u8,
    /// Live iff `tag == `[`SIGNAL_TAG_STR`].
    pub str_: AbiStr,
}

impl std::fmt::Debug for SignalValue {
    /// A union carries no tag of its own — printing a specific field without first consulting
    /// [`SignalEntry::tag`] would read whichever bytes happen to be there under the wrong type, so
    /// this never does.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignalValue").finish_non_exhaustive()
    }
}

/// One signal, keyed by a [`signal`] id, in push order.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SignalEntry {
    /// A [`signal`] constant.
    pub id: u32,
    /// [`SIGNAL_TAG_U64`] | [`SIGNAL_TAG_I64`] | [`SIGNAL_TAG_F64`] | [`SIGNAL_TAG_STR`] |
    /// [`SIGNAL_TAG_BOOL`].
    pub tag: u32,
    /// The value; read the field `tag` names.
    pub value: SignalValue,
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
    /// The OLD `ingress_protocol` (ARCHITECT review ruling 8: renamed `ingress_dialect` — the SDK
    /// maps it to the frozen 1.5.5 wire key; the wire key's own spelling is unchanged).
    pub ingress_dialect: AbiStr,
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
    /// Alignment padding (widened `context_max` below needs 8-byte alignment).
    pub _reserved3: u32,
    /// The OLD `context_max`, meaningful only when [`CANDIDATE_HAS_CONTEXT_MAX`] is set.
    /// ARCHITECT review ruling 8: widened `u32` -> `u64` (a context window is a token count).
    pub context_max: u64,
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
    /// The body blob, ARCHITECT review ruling 6: the RAW origin-dialect request bytes, as
    /// [`super::mechanism::call::BLOB_OCTETS`] — zero-copy, never a kernel-built JSON document
    /// (the shared mechanism's own rule: JSON crosses only as an already-opaque payload the
    /// KERNEL never constructs). The SDK/plugin parses its own dialect (llm/mcp/a2a) to recover
    /// the flattened `(role, text)` view 1.5.5's `PromptProjection` computed kernel-side.
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

/// [`BudgetBucketState::present`]: `remaining_micros` is present.
pub const BUDGET_HAS_REMAINING_MICROS: u32 = 1 << 0;

/// One bucket of the OLD `HookContext::budget`'s budget-chain (the caller key's own bucket, or an
/// ancestor budget group's), innermost first, derived at the current rate card.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BudgetBucketState {
    /// The OLD `bucket_id`.
    pub bucket_id: AbiStr,
    /// The OLD `budget_group`; NULL = the key's own bucket (not a group).
    pub budget_group: AbiStr,
    /// The OLD `pool`; NULL = a group-wide bucket (not pool-qualified).
    pub pool: AbiStr,
    /// The OLD `spend_micros_at_current_rate`.
    pub spend_micros_at_current_rate: i64,
    /// The OLD `remaining_micros`, meaningful only when [`BUDGET_HAS_REMAINING_MICROS`] is set
    /// (unset = an uncapped bucket).
    pub remaining_micros: i64,
    /// The OLD `window_start`.
    pub window_start: u64,
    /// The OLD `budget_period` (`minute` | `hour` | `day` | `month` | `total`).
    pub budget_period: AbiStr,
    /// [`BUDGET_HAS_REMAINING_MICROS`].
    pub present: u32,
    /// Alignment padding.
    pub _reserved: u32,
}

/// [`DecideIn`]'s `present`: the prompt view/body are populated.
pub const VIEW_HAS_PROMPT: u32 = 1 << 0;
/// [`DecideIn`]'s `present`: the user view is populated.
pub const VIEW_HAS_USER: u32 = 1 << 1;
/// [`DecideIn`]'s `present`: `budget_remaining` (the OLD `HookContext::budget_remaining`) is
/// populated.
pub const VIEW_HAS_BUDGET_REMAINING: u32 = 1 << 2;

/// `decide`'s and `transform`'s shared `in` (both ops see identical views; only their `out` and
/// grant differ — B.4: "identical for both"). Carries every HOST-owned result buffer the two ops
/// write into (ARCHITECT review ruling 1: no plugin-pointer results on the request path).
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
    /// The OLD `HookContext::budget_remaining`; meaningful only when
    /// [`VIEW_HAS_BUDGET_REMAINING`] is set.
    pub budget_remaining: i64,
    /// The OLD `HookContext::budget`.
    pub budget: *const BudgetBucketState,
    /// How many.
    pub budget_len: usize,
    /// [`VIEW_HAS_PROMPT`] | [`VIEW_HAS_USER`] | [`VIEW_HAS_BUDGET_REMAINING`].
    pub present: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// The host-owned buffer `decide` writes a candidate order into; unused by `transform`.
    pub order_buf: *mut u32,
    /// `order_buf`'s capacity (count of `u32` slots).
    pub order_cap: usize,
    /// The host-owned buffer `decide`/`transform` write a `reject_message` into (UTF-8 bytes, not
    /// NUL-terminated).
    pub reject_message_buf: *mut u8,
    /// `reject_message_buf`'s capacity, in bytes.
    pub reject_message_cap: usize,
    /// The host-owned buffer `decide` writes `restrict_tags` into: each tag's UTF-8 bytes,
    /// NUL-separated (a tag itself never contains a NUL).
    pub restrict_tags_buf: *mut u8,
    /// `restrict_tags_buf`'s capacity, in bytes.
    pub restrict_tags_cap: usize,
    /// The host-owned buffer `transform` writes its rewrite bytes into (opaque octets, the
    /// caller's own dialect — never kernel-built JSON, ARCHITECT review ruling 6); unused by
    /// `decide`.
    pub rewrite_buf: *mut u8,
    /// `rewrite_buf`'s capacity, in bytes.
    pub rewrite_cap: usize,
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
/// [`DecideOut::verbs`]/[`TransformOut::verbs`]: `reject_status` is populated; unset means the
/// mechanism's 403 default applies regardless of `reject_status`'s bytes (ARCHITECT review
/// ruling 7).
pub const VERB_HAS_REJECT_STATUS: u32 = 1 << 4;

/// `decide`'s `out`. Exactly one of [`VERB_PREFER`], [`VERB_ABSTAIN`], [`VERB_REJECT`],
/// [`VERB_RESTRICT`] must be set (H1: SEH fix-forward ruling, 2026-09-27); the validator FAULTs on
/// 0 or 2+ bits.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DecideOut {
    /// The head.
    pub head: OutHead,
    /// [`VERB_PREFER`] | [`VERB_ABSTAIN`] | [`VERB_REJECT`] | [`VERB_RESTRICT`] |
    /// [`VERB_HAS_REJECT_STATUS`].
    pub verbs: u32,
    /// The OLD `Reject::status`, meaningful only when [`VERB_HAS_REJECT_STATUS`] is set; the
    /// kernel clamps it to 400-499, else 403.
    pub reject_status: u16,
    /// Alignment padding.
    pub _reserved: u16,
    /// How many bytes the plugin wrote into [`DecideIn::reject_message_buf`] (the kernel runs the
    /// full 1.5.5 sanitiser and 300-char cap on them).
    pub reject_message_written: usize,
    /// `0` unless `reject_message_written == 0` because the buffer was too small: the byte length
    /// the plugin needed. The host re-invokes ONCE with a buffer at least this large.
    pub reject_message_needed: usize,
    /// How many bytes the plugin wrote into [`DecideIn::restrict_tags_buf`] (NUL-separated tags;
    /// the kernel trims each and drops empties).
    pub restrict_tags_written: usize,
    /// `0` unless `restrict_tags_written == 0` because the buffer was too small.
    pub restrict_tags_needed: usize,
    /// How many `u32` candidate indices the plugin wrote into [`DecideIn::order_buf`] (an
    /// out-of-range index is dropped by the kernel, per `lower_1_5_5_reply`'s stated behaviour).
    pub order_written: usize,
    /// `0` unless `order_written == 0` because `order_buf` was too small: the slot count needed.
    pub order_needed: usize,
}

/// [`TransformOut::verbs`]: apply the rewrite bytes — OLD `TransformOutcome::Rewrite`.
pub const VERB_REWRITE: u32 = 1 << 0;
// VERB_ABSTAIN and VERB_REJECT (above) are reused for transform's OLD `Abstain`/`Reject`;
// VERB_HAS_REJECT_STATUS is shared with decide's. OLD `Failed` maps to the mechanism's own
// `Outcome::Failed` rather than a verb bit.

/// `transform`'s `out`. The kernel reads ONLY `verbs`; the CALLER (whichever request-serving
/// code invoked this chain) parses and validates the rewrite bytes, proceeding unmodified on
/// failure. A `ro`-granted rewrite is dropped by the kernel from the grant (never reaches the
/// caller).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TransformOut {
    /// The head.
    pub head: OutHead,
    /// [`VERB_REWRITE`] | [`VERB_ABSTAIN`] | [`VERB_REJECT`] | [`VERB_HAS_REJECT_STATUS`].
    pub verbs: u32,
    /// The OLD `Reject::status`, meaningful only when [`VERB_HAS_REJECT_STATUS`] is set; the
    /// kernel clamps it to 400-499, else 403.
    pub reject_status: u16,
    /// Alignment padding.
    pub _reserved: u16,
    /// How many bytes the plugin wrote into [`DecideIn::reject_message_buf`]; sanitised the same
    /// way as `decide`'s.
    pub reject_message_written: usize,
    /// `0` unless `reject_message_written == 0` because the buffer was too small.
    pub reject_message_needed: usize,
    /// How many bytes the plugin wrote into [`DecideIn::rewrite_buf`]: opaque octets in the
    /// caller's own dialect (ARCHITECT review ruling 6), never kernel-parsed.
    pub rewrite_written: usize,
    /// `0` unless `rewrite_written == 0` because `rewrite_buf` was too small.
    pub rewrite_needed: usize,
}

/// [`StageView::stage_present`]: the OLD `HookStageProjection` block is present at all (a
/// REQUEST-stage tap sets none of the bits below — 1.5.5's `stage: None`).
pub const STAGE_HAS_PROJECTION: u32 = 1 << 0;
/// [`StageView::stage_present`]: `model` is present.
pub const STAGE_HAS_MODEL: u32 = 1 << 1;
/// [`StageView::stage_present`]: `attempt_number` is present.
pub const STAGE_HAS_ATTEMPT_NUMBER: u32 = 1 << 2;
/// [`StageView::stage_present`]: `remaining_candidates` is present.
pub const STAGE_HAS_REMAINING_CANDIDATES: u32 = 1 << 3;
/// [`StageView::stage_present`]: `previous_failure` is present.
pub const STAGE_HAS_PREVIOUS_FAILURE: u32 = 1 << 4;
/// [`StageView::stage_present`]: `outcome` is present.
pub const STAGE_HAS_OUTCOME: u32 = 1 << 5;
/// [`StageView::stage_present`]: `status` is present.
pub const STAGE_HAS_STATUS: u32 = 1 << 6;

/// [`StageView::at`]: the OLD `HookStageProjection::at == "candidate"`.
pub const STAGE_AT_CANDIDATE: u32 = 0;
/// [`StageView::at`]: the OLD `HookStageProjection::at == "routing"`.
pub const STAGE_AT_ROUTING: u32 = 1;
/// [`StageView::at`]: the OLD `HookStageProjection::at == "response"`.
pub const STAGE_AT_RESPONSE: u32 = 2;

/// The stage view a tap receives (OLD "stage projection"): [`RequestView`] with NO prompt and NO
/// signals (B.4's explicit exclusion), plus the OLD `HookStageProjection` fields (`at`, `model`,
/// `attempt_number`, `remaining_candidates`, `previous_failure`, `outcome`, `status`),
/// presence-bitmasked (ARCHITECT review ruling 4) since they ride only stage taps
/// (candidate/routing/response), never a request-stage tap.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct StageView {
    /// The OLD `request_id`.
    pub request_id: u64,
    /// The OLD `pool`.
    pub pool: AbiStr,
    /// The OLD `ingress_protocol` (ARCHITECT review ruling 8: renamed `ingress_dialect`).
    pub ingress_dialect: AbiStr,
    /// The OLD `message_count`.
    pub message_count: u64,
    /// The OLD `total_chars`.
    pub total_chars: u64,
    /// The OLD `HookStageProjection::remaining_candidates`, meaningful only when
    /// [`STAGE_HAS_REMAINING_CANDIDATES`] is set.
    pub remaining_candidates: u64,
    /// The OLD `HookStageProjection::model`, meaningful only when [`STAGE_HAS_MODEL`] is set.
    pub model: AbiStr,
    /// The OLD `HookStageProjection::previous_failure`, meaningful only when
    /// [`STAGE_HAS_PREVIOUS_FAILURE`] is set.
    pub previous_failure: AbiStr,
    /// The OLD `HookStageProjection::outcome` (`ok` | `failed` | `rejected_by_gate`), meaningful
    /// only when [`STAGE_HAS_OUTCOME`] is set.
    pub outcome: AbiStr,
    /// The OLD `max_tokens`, meaningful only when [`REQUEST_HAS_MAX_TOKENS`] is set.
    pub max_tokens: u32,
    /// [`REQUEST_HAS_MAX_TOKENS`] | [`REQUEST_HAS_TOOLS`] | [`REQUEST_STREAM`].
    pub flags: u32,
    /// [`STAGE_AT_CANDIDATE`] | [`STAGE_AT_ROUTING`] | [`STAGE_AT_RESPONSE`], meaningful only
    /// when [`STAGE_HAS_PROJECTION`] is set.
    pub at: u32,
    /// The OLD `HookStageProjection::attempt_number`, meaningful only when
    /// [`STAGE_HAS_ATTEMPT_NUMBER`] is set.
    pub attempt_number: u32,
    /// The OLD `HookStageProjection::status`, meaningful only when [`STAGE_HAS_STATUS`] is set.
    pub status: u16,
    /// Alignment padding.
    pub _reserved: [u8; 2],
    /// [`STAGE_HAS_PROJECTION`] | [`STAGE_HAS_MODEL`] | [`STAGE_HAS_ATTEMPT_NUMBER`] |
    /// [`STAGE_HAS_REMAINING_CANDIDATES`] | [`STAGE_HAS_PREVIOUS_FAILURE`] |
    /// [`STAGE_HAS_OUTCOME`] | [`STAGE_HAS_STATUS`].
    pub stage_present: u32,
    /// Alignment padding.
    pub _reserved2: u32,
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

/// `configure`'s `in`. ARCHITECT review ruling (fresh-Opus M3-SHAPES review, parity item):
/// echoes the OLD `ConfigureBody`'s instance name, so the fresh management instance knows which
/// instance it is configuring.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ConfigureIn {
    /// The head.
    pub head: InHead,
    /// The pushed configuration version.
    pub version: u64,
    /// The settings blob.
    pub settings: Blob,
    /// The instance name (OLD `ConfigureBody::hook`).
    pub name: AbiStr,
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

/// `status`'s `out`: the 1.5.5 status blob, unchanged. OFF-PATH: `status` is a plugin-owned
/// result, memory class (iv) — live under `head.lease` until `release(lease)`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct StatusOut {
    /// The head.
    pub head: OutHead,
    /// The 1.5.5 status JSON, as a [`super::mechanism::call::BLOB_JSON`] blob, under `head.lease`.
    pub status: Blob,
}

/// `describe`'s `out`: the 1.5.5 describe blob, unchanged. OFF-PATH: `describe` is a plugin-owned
/// result, memory class (iv) — live under `head.lease` until `release(lease)`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DescribeOut {
    /// The head.
    pub head: OutHead,
    /// The 1.5.5 describe JSON, as a [`super::mechanism::call::BLOB_JSON`] blob, under
    /// `head.lease`.
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

/// `serve`'s `out`. OFF-PATH: the response is a plugin-owned result, memory class (iv) — the
/// headers and body live under `head.lease` until `release(lease)`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ServeOut {
    /// The head.
    pub head: OutHead,
    /// The HTTP status code.
    pub status_code: u16,
    /// Alignment padding.
    pub _reserved: [u8; 6],
    /// Response header name/value pairs, interleaved, under `head.lease` until `release(lease)`
    /// (memory class iv: an off-path list).
    pub headers_out: *const AbiStr,
    /// How many `AbiStr` entries `headers_out` holds.
    pub headers_out_len: usize,
    /// The response body, under `head.lease` until `release(lease)` (memory class iv).
    pub body: Blob,
}

// ── Statement tail ───────────────────────────────────────────────────────────────────────────

/// [`Route::auth`]: no auth required before `serve` — OLD `RouteAuth::None`.
pub const ROUTE_AUTH_NONE: u32 = 0;
/// [`Route::auth`]: a data-plane key required before `serve` — OLD `RouteAuth::Key`.
pub const ROUTE_AUTH_KEY: u32 = 1;
/// [`Route::auth`]: admin auth required, reachable only on the admin listener — OLD
/// `RouteAuth::Admin`.
pub const ROUTE_AUTH_ADMIN: u32 = 2;

/// One HTTP route this instance serves via `serve` (ARCHITECT review ruling, fresh-Opus M3-SHAPES
/// review, parity item): `{path, method}` is the collision key the kernel checks at load;
/// `auth` is enforced by the kernel BEFORE `serve` is ever called — none/key/admin auth cannot be
/// read off a bare path string, which is why a route is this struct, not an [`AbiStr`].
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Route {
    /// The path, confined to `/hooks/<name>/*`.
    pub path: AbiStr,
    /// The HTTP method.
    pub method: AbiStr,
    /// [`ROUTE_AUTH_NONE`] | [`ROUTE_AUTH_KEY`] | [`ROUTE_AUTH_ADMIN`].
    pub auth: u32,
    /// Alignment padding.
    pub _reserved: u32,
}

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
/// `UserAccess`, `infallible` fact, the signals this instance wants, the routes it serves and the
/// hook words it declares.
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
    /// The HTTP routes this instance serves via `serve`, confined to `/hooks/<name>/*`.
    pub routes: *const Route,
    /// How many.
    pub routes_len: usize,
    /// ARCHITECT RULING: the hook words this instance declares — STATIC, a Statement fact, not a
    /// per-call answer. A native ranking strategy (the OLD `cheapest`/`fastest`/`least_busy`/
    /// `usage` reserved words) becomes a hook plugin by declaring the word it claims here; the
    /// kernel's reserved-word check reads this list, not a per-call reply.
    pub declared_words: *const AbiStr,
    /// How many.
    pub declared_words_len: usize,
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

// THE SDK's VIEW OF THE HOOK TABLE (`abi::sdk::door`): each kind op's `in`/`out`, stated next to
// the table, so `plugin_door!` refuses a hook plugin that wires a kind op to another op's
// structs. Every struct named here is plain data (integers, raw pointers, `AbiStr`/`Blob`, nested
// plain structs): every bit pattern is a valid value, which is what `AbiIn`/`AbiOut` promise.
//
// SAFETY (all below): `#[repr(C)]`, leading with `InHead`/`OutHead`, plain data only.
unsafe impl super::sdk::door::AbiIn for DecideIn {}
unsafe impl super::sdk::door::AbiIn for NotifyIn {}
unsafe impl super::sdk::door::AbiIn for ConfigureIn {}
unsafe impl super::sdk::door::AbiIn for ServeIn {}
unsafe impl super::sdk::door::AbiOut for DecideOut {}
unsafe impl super::sdk::door::AbiOut for TransformOut {}
unsafe impl super::sdk::door::AbiOut for ConfigureOut {}
unsafe impl super::sdk::door::AbiOut for StatusOut {}
unsafe impl super::sdk::door::AbiOut for DescribeOut {}
unsafe impl super::sdk::door::AbiOut for ServeOut {}

/// Each hook kind op's `in`/`out` for [`plugin_door!`](crate::plugin_door), per [`Ops`]' docs. A
/// plugin wiring a slot to another op's structs does not compile:
///
/// ```compile_fail,E0271
/// use busbar_contract::abi::hook::{ConfigureIn, ConfigureOut, DecideIn, DecideOut};
/// use busbar_contract::abi::hook::{DescribeOut, NotifyIn, ServeIn, ServeOut, StatusOut, TransformOut};
/// use busbar_contract::abi::mechanism::call::{InHead, OutHead, Outcome};
/// use busbar_contract::abi::mechanism::lifecycle::*;
/// use busbar_contract::abi::sdk::door::Slot;
/// # use std::ffi::c_void;
/// # macro_rules! ready { ($n:ident, $i:ty, $o:ty) => {
/// #     struct $n;
/// #     impl Slot for $n { type In = $i; type Out = $o;
/// #         fn call(_: *mut c_void, _: &$i, _: &mut $o) -> Outcome { Outcome::Ready } }
/// # } }
/// # ready!(V, ValidateIn, OutHead); ready!(Op_, OpenIn, OpenOut); ready!(Rf, RefreshIn, OutHead);
/// # ready!(Rt, GenIn, OutHead); ready!(Tk, TickIn, TickOut); ready!(Dr, DriveIn, OutHead);
/// # ready!(Cn, CancelIn, CancelOut); ready!(Rl, ReleaseIn, OutHead); ready!(Cl, InHead, OutHead);
/// # ready!(Decide, DecideIn, DecideOut); ready!(Transform, DecideIn, TransformOut);
/// # ready!(Configure, ConfigureIn, ConfigureOut); ready!(Status, InHead, StatusOut);
/// # ready!(Describe, InHead, DescribeOut); ready!(Serve, ServeIn, ServeOut);
/// ready!(Notify, ConfigureIn, ConfigureOut); // `configure`'s structs on `notify`: refused
/// busbar_contract::plugin_door! {
///     ops: busbar_contract::abi::hook::Ops,
///     statement: busbar_contract::abi::sdk::door::statement("wrong", "0", 1),
///     lifecycle: { validate: V, open: Op_, refresh: Rf, retire: Rt, tick: Tk, drive: Dr,
///                  cancel: Cn, release: Rl, close: Cl },
///     kind_ops: { decide: Decide, transform: Transform, notify: Notify, configure: Configure,
///                 status: Status, describe: Describe, serve: Serve },
/// }
/// # fn main() { let _ = door(); }
/// ```
///
/// With `Notify` reading [`NotifyIn`] and writing [`OutHead`] the same plugin compiles
/// (`abi/sdk/tests/door_tests.rs`, `a_hook_plugin_wires_every_kind_op`).
macro_rules! kind_slots {
    ($($slot:ident => $in:ty, $out:ty;)*) => {$(
        // SAFETY: the structs `Ops`' doc states for this slot.
        unsafe impl super::sdk::door::KindSlot<{ slot::$slot }> for Ops {
            type In = $in;
            type Out = $out;
        }
    )*};
}

kind_slots! {
    DECIDE => DecideIn, DecideOut;
    TRANSFORM => DecideIn, TransformOut;
    NOTIFY => NotifyIn, OutHead;
    CONFIGURE => ConfigureIn, ConfigureOut;
    STATUS => InHead, StatusOut;
    DESCRIBE => InHead, DescribeOut;
    SERVE => ServeIn, ServeOut;
}
