//! The hook / routing contract surface (`1.6.0-hook-plugin.md` Appendix A).
//!
//! The plane-neutral ABI TYPES both the host and every hook-plugin author name: the [`RoutingPolicy`]
//! trait, its read-only projections ([`RoutingRequest`]/[`Candidate`]/[`RoutingContext`]), the
//! decision/transform verbs, the plane-neutral grant axes ([`Access`]/[`Need`]/[`HookSubject`]), and
//! the cold [`wire`] envelope. These are NEW 1.6.0 contract surface (no 1.5.5 golden constrains them);
//! they replace the retiring `busbar-api` hook types.
//!
//! Rulings honoured: async methods box their futures as [`HookFut`] = `Pin<Box<dyn Future + Send>>`
//! (the transport `Fut` pattern), NEVER `async-trait`; the plugin **computes no money** —
//! [`Candidate::estimated_cost`] is a host-computed opaque scalar and the rate/price types live in
//! `busbar-kernel-ledger`, never here; no plugin self-KEY appears on any type.

pub mod wire;

use crate::signal::SignalBag;
use std::borrow::Cow;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

/// One boxed future per awaiting hook call — the SAME pattern as transport's `Fut`, NOT `async-trait`
/// (a forbidden dependency). Output is the call's own type (already a `Result` where the op can fail),
/// so this alias does not impose transport's `TransportError`.
pub type HookFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A boxed, thread-safe policy error. Dependency-free (no `anyhow`/`thiserror`).
pub type PolicyError = Box<dyn std::error::Error + Send + Sync>;

/// The result of a `decide` call. `Ok(Abstain)` is "no opinion"; `Err` is coerced to the pool's
/// `on_error` by the host, never surfaced to the client.
pub type PolicyResult = Result<RoutingDecision, PolicyError>;

/// THE transport-agnostic hook contract.
///
/// A compiled-in native hook impls it directly; a dropped-in cdylib is wrapped by the loader's
/// `DlopenPolicy` which also impls it. `decide`/`transform` and the management ops box a future
/// because a dlopen impl awaits an offloaded FFI call; a native impl returns an already-ready future
/// (`Box::pin(async move { … })`) with no real await. `name` is sync.
pub trait RoutingPolicy: Send + Sync + 'static {
    /// Rank candidates. MUST be cancel-safe and SHOULD respect `budget` (the host also
    /// hard-`timeout`s the call). `Err`/deadline → handled by the host per `on_error`.
    fn decide<'a>(
        &'a self,
        req: &'a RoutingRequest<'a>,
        candidates: &'a [Candidate<'a>],
        ctx: &'a RoutingContext<'a>,
        budget: Duration,
    ) -> HookFut<'a, PolicyResult>;

    /// Stable policy/transport name for metrics + the `x-busbar-route` header. SYNC (a `&'static str`
    /// is always in hand) — pinned sync per the ruling, no future.
    fn name(&self) -> &'static str;

    /// REWRITE phase (`argument: rw` gate). DEFAULT: abstain (native ranking hooks never rewrite).
    fn transform<'a>(
        &'a self,
        _req: &'a RoutingRequest<'a>,
        _budget: Duration,
    ) -> HookFut<'a, TransformOutcome> {
        Box::pin(async { TransformOutcome::Abstain })
    }

    /// PUSH a settings map (`configure`). DEFAULT: not configurable.
    fn configure<'a>(
        &'a self,
        _hook_name: &'a str,
        _settings: &'a serde_json::Map<String, serde_json::Value>,
        _settings_version: u64,
        _budget: Duration,
    ) -> HookFut<'a, Result<(), PolicyError>> {
        Box::pin(async { Err("this hook transport does not support configure".into()) })
    }

    /// DESCRIBE settings schema. DEFAULT: none.
    fn describe<'a>(&'a self, _budget: Duration) -> HookFut<'a, Option<serde_json::Value>> {
        Box::pin(async { None })
    }

    /// STATUS (observed settings + self-reported metrics). DEFAULT: none.
    fn status<'a>(&'a self, _budget: Duration) -> HookFut<'a, Option<HookStatus>> {
        Box::pin(async { None })
    }

    /// TAP (fire-and-forget): write the pre-serialized projection bytes; no reply read. DEFAULT no-op.
    fn notify<'a>(&'a self, _projection: &'a [u8], _budget: Duration) -> HookFut<'a, ()> {
        Box::pin(async {})
    }
}

/// Read-only, cheaply-built projection of the request.
///
/// Built ONCE per request from the normalized IR, only for non-default pools. Borrows where possible.
#[derive(Debug, Clone)]
pub struct RoutingRequest<'a> {
    /// Per-process-lifetime correlation id (Copy-cheap).
    pub request_id: u64,
    /// The pool this request is routing within.
    pub pool: &'a str,
    /// The ingress protocol the request arrived on.
    pub ingress_protocol: &'a str,
    /// The model the request asked for, if any.
    pub requested_model: Option<&'a str>,
    /// The number of messages in the request.
    pub message_count: usize,
    /// The number of tools declared on the request.
    pub tool_count: usize,
    /// Whether the request declares any tools.
    pub has_tools: bool,
    /// Σ text-block chars (system + messages); a SIZE, not tokens.
    pub total_chars: usize,
    /// The system-preamble char count.
    pub system_chars: usize,
    /// The request's response-token ceiling, if declared.
    pub max_tokens: Option<u32>,
    /// Whether the caller asked to stream.
    pub stream: bool,
    /// The ARGUMENT-axis content — `Some` ONLY behind an `argument: ro|rw` grant. The plane-neutral
    /// generalization of the old `prompt` field (an llm prompt is the canonical instance).
    pub argument: Option<ArgumentProjection<'a>>,
    /// Caller identity — `Some` ONLY behind an `identity: ro` grant. Never a secret/token.
    pub identity: Option<CallerIdentity>,
    /// Declared request-phase signals; EMPTY (unallocated) on the default path.
    pub signals: SignalBag,
}

/// The argument-axis content projection (grant `argument: ro|rw`), read from the normalized IR.
///
/// Text only; provider-unreadable content is a fixed marker, never dropped. `Debug` REDACTS content.
#[derive(Clone)]
pub struct ArgumentProjection<'a> {
    /// The llm system / subject preamble.
    pub system: Option<Cow<'a, str>>,
    /// `(role, flattened text)` pairs in request order.
    pub messages: Vec<(Cow<'a, str>, Cow<'a, str>)>,
}

impl std::fmt::Debug for ArgumentProjection<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArgumentProjection")
            .field("system", &self.system.as_ref().map(|_| "<redacted>"))
            .field(
                "messages",
                &format_args!("<{} redacted>", self.messages.len()),
            )
            .finish()
    }
}

/// The caller-identity projection (grant `identity: ro`).
///
/// By construction carries no secret. `Debug` shows the key labels but REDACTS `user`.
#[derive(Clone)]
pub struct CallerIdentity {
    /// The caller key's id.
    pub key_id: Option<String>,
    /// The caller key's human name.
    pub key_name: Option<String>,
    /// The end-user identity, if any (redacted in `Debug`).
    pub user: Option<String>,
}

impl std::fmt::Debug for CallerIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallerIdentity")
            .field("key_id", &self.key_id)
            .field("key_name", &self.key_name)
            .field("user", &self.user.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// One routable member.
///
/// Projected from the lane table + member config + store. `idx` is the failover loop's stable handle.
#[derive(Debug, Clone)]
pub struct Candidate<'a> {
    /// The failover loop's stable handle.
    pub idx: usize,
    /// The candidate's model.
    pub model: &'a str,
    /// The candidate's provider.
    pub provider: &'a str,
    /// The candidate's SWRR weight.
    pub weight: u32,
    /// The candidate's context-window ceiling, if known.
    pub context_max: Option<usize>,
    /// The candidate's tier, if any.
    pub tier: Option<&'a str>,
    /// HOST-COMPUTED comparable routing cost in micro-units. Opaque to the plugin: the host derives
    /// it via `busbar-kernel-ledger` (Σ rate×estimated-units); the plugin only compares it. `None` =
    /// the card does not price this lane/class ⇒ sorted LAST, never `0`. This REPLACES the old
    /// `cost_per_mtok`, which is deleted. The plugin holds no price (#41(4)).
    pub estimated_cost: Option<i64>,
    /// The candidate's tags.
    pub tags: &'a [String],
    /// EWMA end-to-end latency; `None` until first served.
    pub latency_ms: Option<f64>,
    /// The candidate's currently-available concurrency.
    pub available_concurrency: usize,
    /// The candidate's remaining budget in micro-units, when plumbed.
    pub budget_remaining: Option<i64>,
    /// Rate-limit headroom in `[0.0, 1.0]`; `None` when no rate limit applies.
    pub rate_headroom: Option<f64>,
    /// Declared candidate-phase signals.
    pub signals: SignalBag,
}

/// Read-only context beyond request + candidates.
#[derive(Debug, Clone)]
pub struct RoutingContext<'a> {
    /// The pool this request is routing within.
    pub pool: &'a str,
    /// Per-key governance budget, when plumbed.
    pub budget_remaining: Option<i64>,
    /// The budget-chain, innermost first.
    pub budget: &'a [BudgetBucketState],
}

/// One bucket of the request's BUDGET-CHAIN state, exposed read-only into the pre-forward routing seam
/// so a policy can be budget-aware (e.g. downshift to a cheaper model/tier as a bucket nears its cap).
///
/// Busbar builds only this READ surface — routing POLICY lives in the hook, never in core. All figures
/// are ABSTRACT cost units in MICRO-units (1e-6), derived at the moment of the projection from the
/// token ledger × the operator's current rate card (never stored, no currency).
///
/// (Relocated verbatim from the retiring `busbar-api::hooks::BudgetBucketState`, which the hook design
/// homes in `busbar-contract`; see the branch notes on the `budget` field of [`RoutingContext`].)
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BudgetBucketState {
    /// The bucket id: the key's own id (innermost bucket) or `group:<name>@<window>[#<pool>]` for an
    /// ancestor group's budget-window bucket.
    pub bucket_id: String,
    /// The budget-group name for a group bucket; `None` for the key's own bucket.
    pub budget_group: Option<String>,
    /// The bucket's pool scope: `Some(pool)` for a pool-qualified limit's bucket (it accounts only
    /// that pool's traffic); `None` for a group-wide bucket. Additive — absent on the wire from older
    /// busbars reads as `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool: Option<String>,
    /// The bucket's spend so far this window, derived at the CURRENT rate card.
    pub spend_micros_at_current_rate: i64,
    /// Micro-units remaining under the bucket's cap (`None` = uncapped bucket).
    pub remaining_micros: Option<i64>,
    /// Epoch start of the bucket's current budget window.
    pub window_start: u64,
    /// This bucket's own window kind: `minute` | `hour` | `day` | `month` | `total` (nouns).
    pub budget_period: String,
}

/// The `decide` verb.
///
/// Duplicates/unknown idxs ignored; omitted candidates are lowest-priority, not excluded (failover can
/// still reach them).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutingDecision {
    /// Ranked candidate idxs, most-preferred first.
    Prefer(Vec<usize>),
    /// No opinion → pool default (weighted/SWRR).
    Abstain,
    /// Host RE-CLAMPS status to 4xx + sanitizes message.
    Reject {
        /// The refusal status (re-clamped to 4xx by the host).
        status: u16,
        /// The refusal message (sanitized by the host).
        message: String,
    },
    /// Keep only members with ANY tag; empty → `on_empty`.
    Restrict {
        /// Keep candidates carrying ANY of these tags.
        tags_any: Vec<String>,
    },
}

/// The `transform` (rewrite-phase) verb. Precedence: Reject > Rewrite > Abstain.
#[derive(Debug, Clone, PartialEq)]
pub enum TransformOutcome {
    /// Replace the body (fail-closed parsed).
    Rewrite(RewriteReply),
    /// Reject the request.
    Reject {
        /// The refusal status.
        status: u16,
        /// The refusal message.
        message: String,
    },
    /// Proceed with the ORIGINAL body.
    Abstain,
    /// Could-not-answer; the host applies `on_error` (operator log only).
    Failed {
        /// The could-not-answer detail (operator log only).
        message: String,
    },
}

/// A parsed, validated rewrite reply. Opaque dialect-agnostic JSON arrays busbar re-renders per plane.
#[derive(Debug, Clone, PartialEq)]
pub struct RewriteReply {
    /// The rewritten messages, as opaque per-plane JSON.
    pub messages: Vec<serde_json::Value>,
    /// The rewritten tools, as opaque per-plane JSON.
    pub tools: Vec<serde_json::Value>,
}

/// A hook's self-reported observed state (the `status` control-plane reply). Every field optional.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct HookStatus {
    /// The hook's observed settings version.
    pub settings_version: Option<u64>,
    /// The hook's observed settings (key NAMES only compared downstream).
    pub settings: Option<serde_json::Map<String, serde_json::Value>>,
    /// The hook's self-reported metrics (validated/bounded by the host).
    pub metrics: Option<Vec<serde_json::Value>>,
}

/// One ordered access rung, `No ⊂ Ro ⊂ Rw`.
///
/// `Ord` derives from declaration order (the variant sequence IS the ladder) — pinned by a same-crate
/// test.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Need {
    /// No access.
    No,
    /// Read-only access.
    Ro,
    /// Read-write access.
    Rw,
}

/// The two axes the engine owns.
///
/// The manifest DECLARES one, operator config GRANTS one, the host MEETS them per axis
/// ([`Access::meet`] = the lower rung on each). The human spellings (`prompt:`/`user:` in config,
/// `needs.prompt`/`needs.user` in a manifest) project onto these at their own edges only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Access {
    /// The argument-axis rung.
    pub argument: Need,
    /// The identity-axis rung.
    pub identity: Need,
}

impl Access {
    /// Meet two grants: the lower rung on each axis.
    #[must_use]
    pub fn meet(self, other: Access) -> Access {
        Access {
            argument: self.argument.min(other.argument),
            identity: self.identity.min(other.identity),
        }
    }
}

/// The plane-neutral subject seam (host/plane-facing; answered by `Plane::hook_subject`, NOT crossed
/// to the plugin).
///
/// LOCATORS, not values: a locator resolved against the body a plane already decoded is byte-identical
/// to what the plane would serialize. A plane with no caller-written subject (control/admin) returns
/// `Option::None` — distinct from a `Some` subject with an empty argument.
#[derive(Debug, Clone)]
pub struct HookSubject<'a> {
    /// Where the subject's own name is.
    pub subject: Locator<'a>,
    /// Where its argument payload is; `None` = no argument.
    pub argument: Option<Locator<'a>>,
}

/// How a plane points at its subject/argument.
#[derive(Debug, Clone)]
pub enum Locator<'a> {
    /// The entire decoded document (llm).
    Whole,
    /// An RFC-6901 JSON pointer into it (mcp callable/args, a2a method/params).
    Pointer(Cow<'a, str>),
    /// A host-built payload with no request locator (duplex session config, section 3c).
    Synthesized(Cow<'a, str>),
}
