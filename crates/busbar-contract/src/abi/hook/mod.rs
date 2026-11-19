// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The hook ABI defines its version, table, `decide`, `transform`, `notify`, `configure`, `status`, `describe`, `serve`, fixed views, Statement tail, and `CancelOut` disposition vocabulary. The dispatcher calls it through `busbar-plugin-loader::dispatch::kinds::hook`, and the layout golden pins its layout. The fixed C views preserve the meaning of `RoutingRequest`, `Candidate`, `PromptProjection`, `CallerIdentity`, `SignalBag`, `RoutingDecision`, `TransformOutcome`, `HookStageProjection`, `HookContext`, and `BudgetBucketState`, with byte-identical 1.5.5 behavior.
//!
//!
//!
//!
//!
//!
//!
//!
//!
//!
//! # Host-owned request results
//!
//! 1. **No plugin-pointer results on the request path.** `decide`/`transform` are REQUEST-PATH, so
//!    every result they write goes into a HOST-owned buffer named in `DecideIn`
//!    (`reject_message_buf`/`_cap`, `restrict_tags_buf`/`_cap`, `rewrite_buf`/`_cap`, alongside the
//!    existing `order_buf`/`_cap`), never a plugin-owned pointer in the `out`. Each has a
//!    `*_written`/`*_needed` pair in `DecideOut`/`TransformOut`: too small a cap means the
//!    plugin writes nothing, sets `*_needed`, and the host re-invokes ONCE with a bigger buffer.
//! 2. Off-path lists/text the plugin DOES own (`ScrapeIn`'s snapshot aside — see export) stay
//!    [`Blob`]/pointer results ONLY on off-path ops, under memory class (iv): held live under
//!    `head.lease` until `release(lease)`. `StatusOut`, `DescribeOut` and off-path route
//!    responses are that class; noted on each.
//! 3. [`SignalEntry`] carries a TAGGED value (`tag` + a 16-byte payload), not a bare `f64`, so an
//!    integer signal renders as an integer and a string signal as a string once wired (1.5.5's
//!    `SignalBag` JSON is not all-numeric).
//! 4. `StageView` gains the OLD `HookStageProjection` fields (`at`, `model`, `attempt_number`,
//!    `remaining_candidates`, `previous_failure`, `outcome`, `status`), presence-bitmasked, so a
//!    stage tap (candidate/routing/response) carries what 1.5.5 carried; a REQUEST-stage tap sets
//!    no stage-projection presence bit (1.5.5's `stage: None`).
//! 5. `DecideIn` gains the OLD `HookContext` (`budget_remaining` + presence,
//!    `budget: *const `[`BudgetBucketState`]).
//! 6. **Zero-copy body, no kernel-built JSON.**
//!    [`PromptView::body`] is the RAW origin-dialect request bytes
//!    ([`super::mechanism::call::BLOB_OCTETS`]), not kernel-flattened JSON; the SDK/plugin parses
//!    its own dialect. `TransformOut`'s rewrite bytes are likewise plugin-produced dialect bytes
//!    written into the host's `rewrite_buf`, opaque octets, never kernel-built JSON.
//! 7. `DecideOut` gains `VERB_HAS_REJECT_STATUS`; without it the mechanism's 403 default applies
//!    (a plugin that rejects without an opinion on the status need not compute one).
//! 8. `ingress_protocol` renamed `ingress_dialect` throughout (the SDK maps it to the frozen 1.5.5
//!    wire key, whatever that key's own spelling is — a wire-key rename is not implied).
//!    [`CandidateStatic::context_max`] widened `u32` -> `u64` (a context window is a token count,
//!    not bounded to 32 bits).
//!
//! # Route and result shapes
//!
//! 9. [`Tail::routes`] carries [`Route`] entries (`path`, `method`, `auth`), not bare path
//!    strings: none/key/admin auth cannot be read off a path, and `{path, method}` is the
//!    collision key the kernel checks at load (the same shape B.5 gives export's routes).
//! 10. `ConfigureIn` gains `name`, echoing the OLD `ConfigureBody`'s instance name.
//! 11. Hook words are Statement word marks
//!     ([`MARK_WORD_HOOK`](crate::abi::mechanism::door::MARK_WORD_HOOK)): STATIC, a Statement fact.
//!
//!
//! **OFF-WORKER:** every hook call
//! (`decide`/`transform`/`notify`/`configure`/`status`/`describe`/`serve`) runs OFF the request's
//! own worker thread, never inline on it — the 1.5.5 `spawn_blocking` + hard-timeout parity this
//! behavior preserves (`dlopen_decide_deadline_cuts_off_a_slow_gate`,
//! `dlopen_slow_gate_hits_the_deadline`): a hook that sleeps or spins loses only its own call, not
//! its worker's other in-flight requests. Each op's contract doc below repeats this so a plugin
//! author reads it at the op, not only here; it constrains M1's dispatch (M3-wire), not a shape in
//! this file.
//!
//! B.4, transcribed:
//! - **Views** (fixed, no JSON on the request path — [`PromptView::body`] crosses as raw octets,
//!   never a kernel-built document; a `flags`/`present` bitmask marks optional fields):
//!   [`RequestView`] (the OLD `RoutingRequest`/`HookReqProjection`); the static half of
//!   `candidates[]` (`CandidateStatic`, OLD `Candidate`'s config fields), built at generation,
//!   with the dynamic fields (`CandidateDynamic`) filled per request; the prompt view and body
//!   blob ([`PromptView`], OLD `PromptProjection`), both present iff `prompt` ∈ {ro, rw}, IDENTICAL
//!   for both (rw differs only at the reply, in `transform`'s rewrite grant); the user view
//!   (`UserView`, OLD `CallerIdentity`) iff granted; the requested signals ([`SignalEntry`], OLD
//!   `SignalBag`, in push/insertion order); the OLD `HookContext` budget fields on `DecideIn`.
//! - **Slots:** [`slot::DECIDE`] (P, may_pend): out verb bits, `reject_status` + presence,
//!   a reject-message write into the host buffer, a restrict-tags write into the host buffer,
//!   `order` into the host `order_buf`. [`slot::TRANSFORM`] (P): out verb bits plus a rewrite-bytes
//!   write into the host buffer — the kernel reads only the bits; the CALLER (whichever
//!   request-serving code invoked this chain) parses and validates the bytes, and proceeds
//!   unmodified on failure; a `ro` rewrite is dropped by the kernel from the grant.
//!   [`slot::NOTIFY`] (P, taps): `in` is copied into the host-owned tap pool (global cap 1024, drop
//!   metric, `StageView` plus the request's declared signals and — under a `prompt: ro` grant
//!   only — the prompt view (WIRE-HOOK Q5), `groups:` filter); it never holds the request. [`slot::CONFIGURE`], [`slot::STATUS`], [`slot::DESCRIBE`] (O): run on a FRESH
//!   MANAGEMENT INSTANCE through the same door; status and describe return the 1.5.5 blobs (as
//!   [`Blob`] payloads — off-path JSON is allowed here); configure acks the pushed version, 5s
//!   deadline, a nack does not commit. [`slot::SERVE`] (O): serves [`Tail::routes`] on the
//!   dispatcher after host confinement and auth checks; leased response bytes are copied before
//!   release. A hook declaring no routes may retain the SDK's ordinary stub.
//! - **Kernel normalizers** (HOST-SIDE, enforced on the fixed struct, unchanged from 1.5.5; not new
//!   shapes): `reject_status` clamped to 400-499, else 403 when `VERB_HAS_REJECT_STATUS` is
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
//! - **Acceptance:** 181 v1.5.5 hook tests ported verbatim, plus memory-form RED tests for each
//!   malformed class (M4 HOOK-PARITY, after this shape lands).
//!
//! Hook words, routes, signals, and cancellation use these fixed-layout rules:
//! - "hook words" (B.4's tail bullet) are Statement word marks,
//!   [`MARK_WORD_HOOK`](crate::abi::mechanism::door::MARK_WORD_HOOK): static Statement data, not
//!   a per-call answer. A native
//!   ranking strategy (the OLD `RESERVED_HOOK_NAMES`: `cheapest`/`fastest`/`least_busy`/`usage`)
//!   becomes a hook plugin by declaring the word it claims here.
//! - `routes` (B.4's "routes, serve" row) is [`Tail::routes`], now [`Route`] entries (path +
//!   method + auth: a bare path string cannot state none/key/admin auth), a
//!   Statement fact the plugin states once; `serve` is the op the kernel calls per matched
//!   request.
//! - Signal ids ([`signal`]) are numbered in the OLD `Signal` enum's declared order
//!   (`busbar-contract/src/signal.rs`): `RequestedModel, RequestTotalChars, RequestMessageCount,
//!   RequestToolCount, RequestSystemChars, CandidateBreakerState, CandidateErrorRate,
//!   CandidateLatencyP95Ms, RoutingPolicy, ResponseTokensOut`. `CandidateErrorRate` and
//!   `ResponseTokensOut` are RETIRED: their ids stay (the catalog is append-only, an old config
//!   parses) and the kernel drops them at config load with a warning (`signal::configured`).
//! - `configure`/`status`/`describe`'s `in` beyond the shared [`InHead`] is only what B.4 states
//!   (configure: a version + settings; status/describe: nothing extra) — no other 1.5.5 status
//!   JSON field is renamed or reshaped here; it crosses unchanged as a [`Blob`] payload.
//! - The `CancelOut` disposition vocabulary ([`cancel`]) is not stated in B.4; `decide`/`transform`/
//!   `serve` are this kind's `may_pend` ops, and the two dispositions below cover a cancelled
//!   verdict/response uniformly (nothing partial is ever committed for a hook reply).
//!
//!

use super::mechanism::call::{AbiStr, Blob, InHead, Op, OutHead};

use super::mechanism::door::KindTailHead;
use super::mechanism::lifecycle::{OpsHead, LIFECYCLE_SLOTS};

/// The hook kind's ABI version: v1.5.5 shipped `1`, so 1.6.0 ships `2`.
pub const ABI_VERSION: u32 = super::versions::HOOK.raw();

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
    /// `DecideIn`, out `DecideOut`.
    pub decide: Option<Op>,
    /// Rewrite a request the plugin has `ro`/`rw` prompt access to. REQUEST-PATH, `may_pend`,
    /// [`DeadlineClass::Call`](super::mechanism::call::DeadlineClass::Call), off-worker. In
    /// `DecideIn` (the same views `decide` sees), out `TransformOut`.
    pub transform: Option<Op>,
    /// Watch a request; fire-and-forget. REQUEST-PATH, `may_pend`,
    /// [`DeadlineClass::Call`](super::mechanism::call::DeadlineClass::Call), off-worker,
    /// off-request (it never holds the request open). In `NotifyIn`, out [`OutHead`].
    pub notify: Option<Op>,
    /// Push settings to a fresh management instance. OFF-PATH, `may_pend`, 5s deadline
    /// ([`DeadlineClass::Call`](super::mechanism::call::DeadlineClass::Call)), off-worker. In
    /// `ConfigureIn`, out `ConfigureOut`.
    pub configure: Option<Op>,
    /// The hook's status blob (JSON). OFF-PATH, not `may_pend`, off-worker. In [`InHead`], out
    /// `StatusOut` (memory class iv: the blob lives under `head.lease` until `release`).
    pub status: Option<Op>,
    /// The hook's self-description blob (JSON). OFF-PATH, not `may_pend`, off-worker. In [`InHead`],
    /// out `DescribeOut` (memory class iv: the blob lives under `head.lease` until `release`).
    pub describe: Option<Op>,
    /// The plugin's own HTTP surface (`/hooks/<name>/*`, [`Tail::routes`]). OFF-PATH, `may_pend`,
    /// [`DeadlineClass::Call`](super::mechanism::call::DeadlineClass::Call), off-worker. In
    /// [`ServeIn`], out [`ServeOut`] (memory class iv: the response headers/body live under
    /// `head.lease` until `release`).
    pub serve: Option<Op>,
}

/// One requested/reported signal, in push (insertion) order: a signal bag in fixed layout.
pub mod signal {
    /// The response's output tokens.
    pub const RESPONSE_TOKENS_OUT: u32 = 9;
}

/// One signal's value, tagged by [`SignalEntry::tag`] (not every signal is a number: the routing
/// policy and the requested model are strings, so the ABI carries a real tag rather than coercing
/// every signal to `f64`). 16 bytes, the same
/// width as an [`AbiStr`], so every variant fits without indirection.
#[repr(C)]
#[derive(Clone, Copy)]
pub union SignalValue {
    /// Live iff `tag == ``SIGNAL_TAG_U64`.
    pub u64_: u64,
    /// Live iff `tag == ``SIGNAL_TAG_I64`.
    pub i64_: i64,
    /// Live iff `tag == ``SIGNAL_TAG_F64`.
    pub f64_: f64,
    /// Live iff `tag == ``SIGNAL_TAG_BOOL`; `0` false, `1` true (widened for a stable layout).
    pub boolean: u8,
    /// Live iff `tag == ``SIGNAL_TAG_STR`.
    pub str_: AbiStr,
}

impl std::fmt::Debug for SignalValue {
    /// A union carries no tag of its own — printing a specific field without first consulting
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
    /// `SIGNAL_TAG_U64` | `SIGNAL_TAG_I64` | `SIGNAL_TAG_F64` | `SIGNAL_TAG_STR` |
    /// `SIGNAL_TAG_BOOL`.
    pub tag: u32,
    /// The value; read the field `tag` names.
    pub value: SignalValue,
}

/// [`RequestView::flags`]: `max_tokens` is present.
pub const REQUEST_HAS_MAX_TOKENS: u32 = 1 << 0;
/// [`RequestView::flags`]: the request declares tool definitions.
pub const REQUEST_HAS_TOOLS: u32 = 1 << 1;
/// [`RequestView::flags`]: the request is streamed.
pub const REQUEST_STREAM: u32 = 1 << 2;
/// The projecting plane attests that its text projection represents the whole prompt.
/// Omit for unknown, omitted, non-text or tool content. The host clears this assurance
/// when it withholds or truncates the projection before lending it to a hook.
pub const REQUEST_TEXT_COMPLETE: u32 = 1 << 3;

/// The request view: what `decide`/`transform` see
/// about the request itself, minus the prompt and identity (their own views, granted separately).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RequestView {
    /// The `request_id`.
    pub request_id: u64,
    /// The `pool`.
    pub pool: AbiStr,
    /// The dialect the request arrived in.
    pub ingress_dialect: AbiStr,
    /// The `message_count`.
    pub message_count: u64,
    /// The `total_chars`.
    pub total_chars: u64,
    /// The `max_tokens`, meaningful only when [`REQUEST_HAS_MAX_TOKENS`] is set.
    pub max_tokens: u32,
    /// [`REQUEST_HAS_MAX_TOKENS`] | [`REQUEST_HAS_TOOLS`] | [`REQUEST_STREAM`].
    pub flags: u32,
    /// The requested/reported signals ([`SignalEntry`]), in push order.
    pub signals: *const SignalEntry,
    /// How many.
    pub signals_len: usize,
    /// The request's session: opaque octets ([`BLOB_OCTETS`](super::mechanism::call::BLOB_OCTETS))
    /// that group the requests of one conversation, filled by the plane's `project` (each plane
    /// names its own key; a plane with none leaves it absent). Neither the kernel nor a hook reads
    /// meaning into the bytes: the kernel keys its incremental scan on them, bound to the caller and
    /// the hook generation. [`BLOB_ABSENT`](super::mechanism::call::BLOB_ABSENT) = no session, and
    /// every request is
    /// screened whole.
    pub session: Blob,
}

/// The prompt view and body blob: present, and IDENTICAL, whenever
/// `prompt` is granted `ro` or `rw` (`PROMPT_RO`/`PROMPT_RW`); absent (`system` NULL, `body`
/// absent, `message_count == 0`) otherwise.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PromptView {
    /// The system text; NULL = none.
    pub system: AbiStr,
    /// How many messages the prompt holds.
    pub message_count: u64,
    /// The body blob contains the raw origin-dialect request bytes, as
    /// [`super::mechanism::call::BLOB_OCTETS`] — zero-copy, never a kernel-built JSON document
    /// (the shared mechanism's own rule: JSON crosses only as an already-opaque payload the
    /// KERNEL never constructs). The SDK/plugin parses its own dialect (llm/mcp/a2a) to recover
    /// the flattened `(role, text)` view.
    /// [`BLOB_ABSENT`](super::mechanism::call::BLOB_ABSENT) until the request-serving code hands
    /// the host the raw bytes; [`messages`](Self::messages) carries the flattened view regardless.
    pub body: Blob,
    /// The prompt's messages, flattened: one [`MessageView`] per message, in request order, so a
    /// hook reads them without parsing a dialect. A
    /// pre-tag v1 layout edit: the layout golden is regenerated, no version bump.
    pub messages: *const MessageView,
    /// How many; equals [`message_count`](Self::message_count)
    /// ([`validate::check_prompt_view`]).
    pub messages_len: usize,
}

/// One message of the prompt view: its role and its flattened text.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MessageView {
    /// The `role`.
    pub role: AbiStr,
    /// The message's text content, flattened.
    pub text: AbiStr,
}

/// One bucket of the request's budget chain (the caller key's own bucket, or an
/// ancestor budget group's), innermost first, derived at the current rate card.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BudgetBucketState {
    /// The `bucket_id`.
    pub bucket_id: AbiStr,
    /// The `budget_group`; NULL = the key's own bucket (not a group).
    pub budget_group: AbiStr,
    /// The `pool`; NULL = a group-wide bucket (not pool-qualified).
    pub pool: AbiStr,
    /// The `spend_micros_at_current_rate`.
    pub spend_micros_at_current_rate: i64,
    /// The `remaining_micros`, meaningful only when `BUDGET_HAS_REMAINING_MICROS` is set
    /// (unset = an uncapped bucket).
    pub remaining_micros: i64,
    /// The `window_start`.
    pub window_start: u64,
    /// The `budget_period` (`minute` | `hour` | `day` | `month` | `total`).
    pub budget_period: AbiStr,
    /// `BUDGET_HAS_REMAINING_MICROS`.
    pub present: u32,
    /// Alignment padding.
    pub _reserved: u32,
}

/// [`DecideOut::verbs`]: prefer an order (`order_buf`/`order_written` hold it).
pub const VERB_PREFER: u32 = 1 << 0;
/// [`DecideOut::verbs`]: no opinion.
pub const VERB_ABSTAIN: u32 = 1 << 1;
/// [`DecideOut::verbs`]: refuse the request.
pub const VERB_REJECT: u32 = 1 << 2;
/// [`DecideOut::verbs`]: narrow to `restrict_tags`.
pub const VERB_RESTRICT: u32 = 1 << 3;
/// [`DecideOut::verbs`]: prioritize an unordered set in `order_buf`, retaining ordinary ranking
/// or weighted selection within that set and the remaining eligible fallback candidates.
pub const VERB_PRIORITIZE: u32 = 1 << 5;

/// [`TransformOut::verbs`]: apply the rewrite bytes.
pub const VERB_REWRITE: u32 = 1 << 0;

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

/// One HTTP route this instance serves via `serve`. The pair `{path, method}`
/// is the collision key the kernel checks at load;
/// `auth` is enforced by the kernel BEFORE `serve` is ever called — none/key/admin auth cannot be
/// read off a bare path string, which is why a route is this struct, not an [`AbiStr`].
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Route {
    /// The path, confined to `/hooks/<name>/*`.
    pub path: AbiStr,
    /// The HTTP method.
    pub method: AbiStr,
    /// `ROUTE_AUTH_NONE` | `ROUTE_AUTH_KEY` | `ROUTE_AUTH_ADMIN`.
    pub auth: u32,
    /// Alignment padding.
    pub _reserved: u32,
}

/// The hook kind's Statement tail (B.4's "Tail"): the hook's class, its prompt and user grants,
/// its `infallible` fact, the signals this instance wants, the routes it serves and the
/// hook words it declares.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Tail {
    /// The head.
    pub head: KindTailHead,
    /// `CLASS_GATE` | `CLASS_TAP`.
    pub kind_class: u32,
    /// `PROMPT_NO` | `PROMPT_RO` | `PROMPT_RW`.
    pub prompt_access: u32,
    /// `USER_NO` | `USER_RO`.
    pub user_access: u32,
    /// Non-zero: an INFALLIBLE hook — the chain terminal is forced `Weighted`, grants are forced
    /// off, `on_empty` is forced `Reject`, and the timeout is forced to the default.
    pub infallible: u8,
    /// Alignment padding.
    pub _reserved: [u8; 3],
    /// The [`signal`] ids this instance wants reported on [`RequestView::signals`] /
    /// [`CandidateDynamic::signals`].
    ///
    /// RETIRED (H7): stated empty. The signals a hook is lent are the operator's `hooks:`
    /// configuration, never this list: the host never reads it, and refuses at bind a tail that
    /// states any.
    pub requested_signals: *const u32,
    /// How many.
    pub requested_signals_len: usize,
    /// The HTTP routes this instance serves via `serve`, confined to `/hooks/<name>/*`.
    pub routes: *const Route,
    /// How many.
    pub routes_len: usize,
}

/// HOW THE HOOK KIND TAIL IS MADE: from [`Tail::EMPTY`], its plain fields set
impl Tail {
    /// Nothing stated: every string absent, every list empty, every number zero; the head
    pub const EMPTY: Tail = Tail {
        head: KindTailHead {
            size: core::mem::size_of::<Tail>() as u32,
            _reserved: 0,
        },
        kind_class: 0,
        prompt_access: 0,
        user_access: 0,
        infallible: 0,
        _reserved: [0; 3],
        requested_signals: std::ptr::null(),
        requested_signals_len: 0,
        routes: std::ptr::null(),
        routes_len: 0,
    };

    abi_lists! {
        requested_signals, requested_signals_len: u32
            => requested_signals_ptr, with_requested_signals, with_raw_requested_signals;
        routes, routes_len: Route => routes_ptr, with_routes, with_raw_routes;
    }
}

/// The hook kind's [`super::mechanism::lifecycle::CancelOut::disposition`] vocabulary.
pub mod cancel {
    /// The pending op was aborted before it produced a verdict/response; `on_error` runs as
    pub const ABORTED: u32 = 0;
}
