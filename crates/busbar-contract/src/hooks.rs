// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The HOOK contract: the transport-agnostic [`RoutingPolicy`] trait and the read-only projections
//! it is invoked with. The engine builds the projections once per request (and only for pools with
//! a policy — the default weighted path never constructs them); a policy implementation ranks,
//! decides, or transforms on them and can never touch the mutable IR or engine state.

/// A read-only, cheaply-constructed projection of the request for routing decisions. Built ONCE per
/// request from the NORMALIZED IR — the same representation the request that goes upstream is built
/// from — BEFORE the failover loop, and ONLY for non-default pools. Borrows where possible; owns
/// only small derived scalars. A policy never touches the mutable IR or engine state.
#[derive(Debug, Clone)]
pub struct RoutingRequest<'a> {
    /// This request's correlation id — a single `u64` stamped once at ingress (the engine's
    /// `RequestCtx::request_id`), unique-per-process-lifetime and Copy-cheap (no UUID/String). Lets
    /// a hook (or a log line reading the same id off busbar's tracing span) join THIS routing
    /// decision to the request's eventual OUTCOME on the completion-tap notification, which carries
    /// the identical value for the same request.
    pub request_id: u64,
    /// The pool the request resolved to.
    pub pool: &'a str,
    /// The ingress dialect's wire name, as the plane that admitted the request reports it.
    pub ingress_protocol: &'a str,
    /// Number of messages on the request.
    pub message_count: usize,
    /// Whether the request carries any tool definition.
    pub has_tools: bool,
    /// Sum of all text-block chars across system + messages. A v1 SIZE signal (NOT a token count).
    pub total_chars: usize,
    /// The caller's output-token cap, if any.
    pub max_tokens: Option<u32>,
    /// Whether the caller asked for a streamed reply.
    pub stream: bool,
    /// THE SUBJECT'S ARGUMENT PAYLOAD — the span [`HookSubject::argument_span`] names, projected.
    /// `Some` ONLY when the engine's effective ARGUMENT access is `ro` or `rw` (default `no`). The
    /// default projection is shape-only; this is the operator-granted exception that lets a trusted
    /// hook screen content (PII, guardrails, audit) or rewrite it (`rw`). Borrows from the parsed
    /// body where it can; only block-array flattening allocates, and that cost is paid only behind
    /// the grant.
    ///
    /// One plane projects that payload as a conversation, another as a call's arguments, a third as
    /// a session configuration. They are the same thing to a gate, which is why the axis is the
    /// subject's and not one plane's.
    pub argument: Option<ArgumentProjection<'a>>,
    /// Caller identity — `Some` ONLY when the effective IDENTITY access is `ro` (default `no`). Carries the
    /// governance virtual-key `id`/`name` and the body's end-user field. NEVER the caller's
    /// secret/token, regardless of configuration.
    pub identity: Option<CallerIdentity>,
    /// The declared-signal bag: request-phase [`crate::Signal`] entries a
    /// consumer explicitly declared (see `busbar::hooks::RequestedSignals`), computed ONLY when
    /// declared — EMPTY (nothing allocated) on the default path,
    /// where the wire's `#[serde(flatten)]` renders it as zero additional keys. ADDITIVE: every
    /// existing typed field above is unchanged; a consumer that reads only them sees the identical
    /// projection it always has.
    pub signals: crate::SignalBag,
}

/// THE ARGUMENT-PAYLOAD projection (the engine's `argument: ro|rw` access), read from the
/// normalized IR — the reading of [`HookSubject::argument_span`].
///
/// Text only: every content block that carries screenable text is flattened, including reasoning
/// text, tool-call arguments and tool-result content. Content busbar cannot read (provider-encrypted
/// reasoning, in any of the wire shapes that carry it) is replaced by a fixed non-content marker
/// rather than shown or silently dropped — the correct read of that marker is *"there is content
/// here I cannot screen"*, never *"this turn is empty"* and never *"this is genuine ciphertext"*.
/// Structurally text-less blocks (images) contribute no text, but their message entries remain —
/// with empty text — so a screening hook never sees fewer turns than the provider does.
///
/// # ALIGNMENT: entries index against the NORMALIZED turns, not against the wire array
///
/// This projection is built from the same normalized request the provider's bytes are built from,
/// and normalization moves the system prompt to one place on every protocol. A body that sends its
/// system prompt as an in-band turn therefore contributes to `system` here and NOT to a turn — and
/// `message_count` is one lower than the wire array's length for such a body.
///
/// That is deliberate and is the reason this projection exists in this form: it is what makes a hook
/// behave the same way whichever dialect the client happens to speak. A hook that looked for the
/// system prompt in `messages[0]` finds it in `system`, on every protocol.
///
/// `Cow`: a single-block turn borrows straight from the normalized request (the common case, zero
/// copies); only a multi-block turn allocates a joined string.
#[derive(Clone)]
pub struct ArgumentProjection<'a> {
    /// The system prompt's text, flattened (bare string, or text blocks concatenated).
    pub system: Option<std::borrow::Cow<'a, str>>,
    /// Every message as `(role, flattened text)`, in request order.
    pub messages: Vec<(std::borrow::Cow<'a, str>, std::borrow::Cow<'a, str>)>,
}

/// Debug REDACTS the content: this struct exists precisely because the operator opted the subject's
/// argument payload into the hook payload, and a stray `{:?}` on the routing path (a debug log while
/// chasing a hook issue) must not fan that text out into log aggregators. Shapes only.
impl std::fmt::Debug for ArgumentProjection<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArgumentProjection")
            .field(
                "system_chars",
                &self.system.as_deref().map(|s| s.chars().count()),
            )
            .field("message_count", &self.messages.len())
            .finish_non_exhaustive()
    }
}

/// The caller identity projection (the hook's `user: ro` grant). By construction this can never
/// carry a secret: the governance lookup resolves the token to its key record and only the record's
/// `id`/`name` are projected.
#[derive(Clone)]
pub struct CallerIdentity {
    /// Governance virtual-key id (stable handle), if the caller authenticated with a virtual key.
    pub key_id: Option<String>,
    /// Governance virtual-key display name.
    pub key_name: Option<String>,
    /// The request body's end-user identifier (`user` in OpenAI dialect, `metadata.user_id` in
    /// Anthropic dialect), if the caller supplied one.
    pub user: Option<String>,
}

/// Debug shows the operator-facing key labels but REDACTS the end-user identifier — it is caller
/// PII that the operator opted into the hook payload, not into every debug log on the routing path.
impl std::fmt::Debug for CallerIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallerIdentity")
            .field("key_id", &self.key_id)
            .field("key_name", &self.key_name)
            .field("user", &self.user.as_deref().map(|_| "<redacted>"))
            .finish()
    }
}

/// WHAT A HOOK IS ASKED TO JUDGE, said in locators — the plane's answer to "what is being asked
/// for here", for a hook that is about to decide whether it may proceed.
///
/// # Why this is not a payload
///
/// Every other plane step answers with a locator: `authenticate` says WHERE the credential is,
/// [`crate::unit::AdmitFacts::lane_locator`] says WHERE the lane name is, `input_span` says WHICH
/// span is the priced input. The plane never holds the value and the kernel resolves the locator
/// against the same bytes. A hook subject is the same question one step earlier, so it takes the
/// same form — and the form is what makes it byte-identical: a locator resolved against the body a
/// plane already decoded cannot differ from the payload that plane would have serialized.
///
/// # Why it exists
///
/// The neutral seam that fires an operator's gates could not name its own subject. So each plane
/// lent it one, and the borrowed nouns ended up in kind-neutral crates: one plane's word for a
/// callable and one for its arguments on the request-admission host ABI — into which a second plane
/// spells a task operation and a third a literal method name, neither of which has callables at all
/// — and a fourth plane's word for a target and one for its content on the routing projection. Three
/// planes' vocabulary for one question none of them was allowed to ask abstractly. This is that
/// question, asked once, in nouns no plane owns.
///
/// # The CONTAINER is deliberately absent
///
/// Which pool, which server, which agent a request is addressed to is resolved from operator
/// configuration and is not in the request at all, so no locator could point at it. The firing site
/// resolved it and supplies it, exactly as it does today.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HookSubject {
    /// Where the SUBJECT'S OWN NAME is in the request — the thing the caller asked for, under
    /// whatever noun this plane's dialect gives it: a tool, a skill, a model, a session mode.
    ///
    /// `None` when the request does not carry one because the plane's configuration does. That is a
    /// fact about the dialect, not a gap: a hook told `None` has been told the request names no
    /// target, which is true, rather than shown a name borrowed from somewhere else.
    pub subject_locator: Option<crate::grammar::Location>,
    /// Where the subject's ARGUMENT PAYLOAD is: the span of the request body a content-granted hook
    /// is shown, and that an `rw` grant may rewrite.
    ///
    /// `None` when the operation carries no arguments to screen. The grant ladder is unchanged and
    /// is applied by the engine, never here — a projection that decided for itself whether it may be
    /// seen would be a projection with a policy in it.
    pub argument_span: Option<crate::bounded::Span>,
}

/// [`HookSubject`] READ — the plane's two locators already resolved, which is the form the neutral
/// firing seam carries.
///
/// A locator is the honest way for a plane to ANSWER, because a locator cannot disagree with the
/// bytes it points into. It is not the way a seam can be CALLED: a firing site holds no unit to
/// resolve one against, and on two of the four planes that fire this seam the subject is not in the
/// arriving bytes at all — a tool call's name is resolved against the operator's server table
/// before the gate sees it, and a duplex open's mode is operator configuration that was settled
/// before a frame arrived. So the plane reads its own answer, in its own bytes, and hands the seam
/// the two values, which is the same relationship [`crate::unit::AdmitFacts::lane_locator`] has to
/// the lane name the door ends up charging.
///
/// Gathered into one type rather than passed as a pair, for the reason every other bundle on this
/// path is gathered: two adjacent parameters of a request that a caller can silently transpose is
/// a gate that screens the arguments and admits on the name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SubjectFacts<'a> {
    /// The subject's own NAME — [`HookSubject::subject_locator`] read. `None` says this operation
    /// names no target, which is a fact a gate may act on; it is never a stand-in for one.
    pub subject: Option<&'a str>,
    /// The subject's ARGUMENT PAYLOAD — [`HookSubject::argument_span`] read. `None` says the
    /// operation carries nothing to screen, which a gate must not read as screened-clean-empty.
    pub arguments: Option<&'a [u8]>,
}

/// One routable member, with the metadata + live signals a policy ranks on. Projected from the
/// engine's lane table + the pool member config + the store. `idx` is the stable handle the
/// failover loop already speaks.
#[derive(Debug, Clone)]
pub struct Candidate<'a> {
    /// Index into the engine's lane table — the failover loop's lingua franca.
    pub idx: usize,
    /// The member model this lane dispatches to.
    pub model: &'a str,
    /// Upstream provider name. Projected to the hook wire so a hook can implement a
    /// provider-preference strategy.
    pub provider: &'a str,
    /// The configured SWRR weight. Projected to the hook wire so an external hook can implement a
    /// weighted-variant strategy (the signal the built-in `weighted` floor uses).
    pub weight: u32,
    /// Member context-window ceiling. Projected to the hook wire so a hook can route by context-fit.
    pub context_max: Option<usize>,
    // ── operator-declared member metadata (config) ───────────────────────────────────────────────
    /// Operator-declared tier label, when configured.
    pub tier: Option<&'a str>,
    /// Operator-declared cost per million tokens, when configured.
    pub cost_per_mtok: Option<f64>,
    /// Free-form operator tags. Projected to the hook wire (omitted when empty).
    pub tags: &'a [String],
    // ── live signals (read per-request from the store at the seam) ───────────────────────────────
    /// Rolling EWMA of recent end-to-end latency for this lane, in milliseconds. `None` until the
    /// lane has served at least one request.
    pub latency_ms: Option<f64>,
    /// Currently-available concurrency permits on this lane's semaphore (free slots). A `least_busy`
    /// policy prefers the lane with the most headroom.
    pub available_concurrency: usize,
    /// Per-lane lifetime request budget remaining (`None` = unlimited). The `usage` policy prefers
    /// the lane with the most budget left; cheap (read from the store).
    pub budget_remaining: Option<i64>,
    /// Rate-limit HEADROOM as a fraction in `[0.0, 1.0]`: how much of the request's governance
    /// rate budget (the tighter of the caller key's RPM / TPM limit) is still available this window —
    /// `1.0` is fully-unused, `0.0` is at the cap. `None` when no rate limit applies (governance
    /// disabled, or the key has neither RPM nor TPM set). The `usage` policy prefers the candidate
    /// with the MOST headroom (furthest from a provider 429). Rate limits are per-KEY in busbar
    /// today, so this value is currently the same across a request's candidates — `usage` then ranks
    /// deterministically by `idx` — but the field is per-candidate so a future per-lane rate signal
    /// drops in without a contract change.
    pub rate_headroom: Option<f64>,
    /// The declared-signal bag: candidate-phase [`crate::Signal`] entries a
    /// consumer explicitly declared (e.g. `CandidateBreakerState`/`CandidateErrorRate`), computed
    /// ONLY when declared. See [`RoutingRequest::signals`] for the full contract; identical here.
    pub signals: crate::SignalBag,
}

/// One bucket of the request's BUDGET-CHAIN state, exposed read-only into the pre-forward routing
/// seam so a policy can be budget-aware (e.g. downshift to a cheaper model/tier as a bucket nears
/// its cap). Busbar builds only this READ surface - routing POLICY lives in the hook, never in
/// core. All figures are ABSTRACT cost units in MICRO-units (1e-6), derived at the moment of the
/// projection from the token ledger x the operator's current rate card (never stored, no currency).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BudgetBucketState {
    /// The bucket id: the key's own id (innermost bucket) or `group:<name>@<window>[#<pool>]`
    /// for an ancestor group's budget-window bucket.
    pub bucket_id: String,
    /// The budget-group name for a group bucket; `None` for the key's own bucket.
    pub budget_group: Option<String>,
    /// The bucket's pool scope: `Some(pool)` for a pool-qualified limit's bucket (it accounts
    /// only that pool's traffic); `None` for a group-wide bucket. Additive - absent on the wire
    /// from older busbars reads as `None`.
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

/// Read-only context a policy may consult beyond the request + candidates themselves.
#[derive(Debug, Clone)]
pub struct RoutingContext<'a> {
    /// The pool the decision is for.
    pub pool: &'a str,
    /// Per-KEY governance budget remaining for this request, when known/plumbed. `None` when
    /// governance is disabled or per-key budget is not visible at the seam (v1 default).
    pub budget_remaining: Option<i64>,
    /// The request's BUDGET-CHAIN state: the caller key's bucket plus every ancestor budget group,
    /// innermost first (see [`BudgetBucketState`]). Empty when governance is disabled or no key
    /// resolved. The budget-aware-routing read seam: a policy may downshift on it; busbar itself
    /// never routes on budget.
    pub budget: &'a [BudgetBucketState],
}

/// A boxed, thread-safe policy error. Kept dependency-free (no `anyhow`/`thiserror`) so the routing
/// contract adds no new crate. A transport surfaces transient failures (a webhook 500, a socket
/// disconnect, a marshaling error) as this; the caller coerces any `Err` to the pool's `on_error`
/// fallback, so an error NEVER propagates to the client — it degrades to weighted/reject/first.
pub type PolicyError = Box<dyn std::error::Error + Send + Sync>;

/// The result of a policy decision. `Ok(Abstain)` is the clean "no opinion" path; `Err` is coerced
/// to `on_error` by the caller (never surfaced to the client).
pub type PolicyResult = Result<RoutingDecision, PolicyError>;

/// The decision: an ordered preference, or an explicit abstention.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutingDecision {
    /// Ranked preference, most-preferred first. Entries are candidate `idx` values. The list MAY be
    /// a subset (a policy can drop a candidate); any omitted candidate is treated as LOWEST priority,
    /// NOT excluded — the failover loop can still reach it after the ranked ones are exhausted, so a
    /// broken policy never strands a healthy lane. Duplicates and unknown idxs are ignored.
    Prefer(Vec<usize>),
    /// "No preference" — fall back to the pool's default (weighted/SWRR). Identical to the policy not
    /// being configured. A timeout / error / malformed response is coerced to this (per `on_error`).
    Abstain,
    /// REJECT the request: no upstream is dispatched and the caller receives a dialect-native error.
    /// The verb that makes content-seeing hooks (`prompt: ro`/`rw`) useful — a PII screen or
    /// guardrail can stop a request before it leaves the network. The engine's transports produce
    /// this only via their fail-closed normalizer (status clamped to 4xx, message sanitized), and
    /// the forward seam RE-CLAMPS the status regardless — so no policy impl, shipped or future, can
    /// mint a 5xx, a success, or a header-injecting message through this path.
    Reject {
        /// The status code the caller receives (clamped to 4xx by the seam).
        status: u16,
        /// The sanitized message the caller receives.
        message: String,
    },
    /// RESTRICT the candidate set to members carrying ANY of these `tags` — a compliance gate ("only
    /// BAA-covered lanes"). Unlike `Prefer` (deprioritize-not-exclude), restrict EXCLUDES every
    /// non-matching member from the failover set entirely and persists across hops. An empty
    /// intersection is the gate's `on_empty` (default fail-closed reject), never allow-all.
    Restrict {
        /// A member survives when it carries ANY of these tags.
        tags_any: Vec<String>,
    },
}

impl RoutingDecision {
    /// Normalize a raw ranked list into a clean `Prefer`/`Abstain`: drop unknown idxs (not in
    /// `valid`), dedup while preserving first-seen order, and coerce an empty result to `Abstain`.
    /// Shared by every transport so the same liberal-in-what-you-accept rules hold everywhere.
    pub fn from_ranked(
        raw: impl IntoIterator<Item = usize>,
        valid: &std::collections::HashSet<usize>,
    ) -> RoutingDecision {
        let mut seen = std::collections::HashSet::new();
        let mut order = Vec::new();
        for idx in raw {
            if valid.contains(&idx) && seen.insert(idx) {
                order.push(idx);
            }
        }
        if order.is_empty() {
            RoutingDecision::Abstain
        } else {
            RoutingDecision::Prefer(order)
        }
    }
}

/// A parsed, validated `rewrite` reply: the replacement message body and any injected tools. Both are
/// opaque dialect-agnostic JSON arrays busbar re-renders per target protocol. FAIL-CLOSED —
/// the engine's parser returns `None` for a malformed rewrite so the caller proceeds with the
/// ORIGINAL body, never a corrupted one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewriteReply {
    /// The replacement message list, dialect-agnostic JSON.
    pub messages: Vec<serde_json::Value>,
    /// The replacement tool list, dialect-agnostic JSON.
    pub tools: Vec<serde_json::Value>,
}

/// The outcome of a REWRITE-phase (`transform`) call. A `prompt: rw` gate's reply may carry ANY
/// gate verb — in particular `reject` (a compressor that also screens for PII returns
/// `{"reject": ...}`). Dropping that reject silently (the pre-1.3 behavior) was a fail-OPEN from
/// the hook author's view: the request the hook tried to stop got routed. Precedence on the
/// transform path: Reject > Rewrite > Abstain. (`restrict`/`order` remain decide-path verbs and
/// are still ignored on transform — documented in the wire contract.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransformOutcome {
    /// Replace the request body (the rewrite arm; fail-closed parsed).
    Rewrite(RewriteReply),
    /// Reject the request outright — same clamped/sanitized semantics as a decide-path reject.
    Reject {
        /// The status code the caller receives (clamped to 4xx by the seam).
        status: u16,
        /// The sanitized message the caller receives.
        message: String,
    },
    /// No opinion / unsupported (proceed with the ORIGINAL body). A genuine "nothing to say".
    Abstain,
    /// The hook COULD NOT ANSWER: its own dependency failed, timed out, or it refuses to act on what
    /// it got. The rewrite-path twin of `HookReply::Failed` on the decide path.
    ///
    /// This arm did not exist, so a `prompt: rw` gate's transport failure collapsed into `Abstain` —
    /// indistinguishable from a compressor that looked at the body and had no changes to make. The
    /// request then proceeded with its original body and the operator's `on_error` chain, whose
    /// terminal can be `reject`, never fired. A gate deliberately configured to fail CLOSED failed
    /// OPEN, silently. `decide` has had this distinction since `HookReply::Failed` landed; the
    /// rewrite pass simply had no arm to carry it into.
    ///
    /// The message is for the operator's log. It must not carry request content.
    Failed {
        /// The operator-facing reason; never request content.
        message: String,
    },
}

/// A hook's self-reported OBSERVED state — the `status` management reply (control plane): the
/// settings it is actually running (vs busbar's desired-state registry copy), their version, and
/// its own operational metrics (e.g. a compressor's `tokens_compressed_total`). Every field
/// optional; a hook that doesn't implement `status` simply never produces one.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct HookStatus {
    /// The settings version the hook reports it is running.
    pub settings_version: Option<u64>,
    // settings-leak-lint: allow — NON-PROJECTION engine type. This struct derives no `Serialize`:
    // it is the parsed INBOUND `status` reply (the twin of `hooks::wire::StatusReply`, which
    // carries the same marker for the same reason), held so the engine can compare key names. The
    // one control-plane read behind it, `GET /hooks/{name}/status`, serves `HookStatusView`, whose
    // `reported` side is `HookReportedStatus { settings_keys, settings_version }` — key names only,
    // projected through the control surface's `settings_keys`, with drift computed by
    // `hooks::settings_drift_keys`, which also compares names. No wire member carries this bag.
    /// The settings the hook reports it is running (key names are what the engine compares).
    pub settings: Option<serde_json::Map<String, serde_json::Value>>,
    /// Raw metrics ARRAY (each entry `{name, type, value, labels?, quantiles?, ...}`); the engine
    /// validates + bounds entries before exposing them.
    pub metrics: Option<Vec<serde_json::Value>>,
}

/// THE transport-agnostic contract. webhook / socket / native all implement this.
#[async_trait::async_trait]
pub trait RoutingPolicy: Send + Sync + 'static {
    /// Rank candidates for this request. MUST be cancel-safe and SHOULD respect `budget` (a
    /// wall-clock deadline; the caller also wraps the call in a hard `timeout`). Returning `Err` or
    /// exceeding the deadline is handled by the caller per `on_error`; an impl SHOULD prefer
    /// `Ok(Abstain)` over erroring when it simply has no opinion.
    async fn decide(
        &self,
        req: &RoutingRequest<'_>,
        candidates: &[Candidate<'_>],
        ctx: &RoutingContext<'_>,
        budget: std::time::Duration,
    ) -> PolicyResult;

    /// Stable transport/policy name for metrics + the `x-busbar-route` header
    /// (e.g. `"webhook"`, `"socket"`, `"weighted"`, `"cheapest"`).
    fn name(&self) -> &'static str;

    /// REWRITE phase (`prompt: rw` gate): send the request projection and return the hook's `rewrite`
    /// reply — the replacement message body (+ optional injected tools), FAIL-CLOSED (`None` = proceed
    /// with the ORIGINAL body). Distinct from `decide` (which ranks): this is the transform-pass call.
    /// DEFAULT `None`: in-process ranking hooks never rewrite; only the out-of-process socket/webhook
    /// transports override it. The caller enforces the `rw` grant (only a `rw` hook reaches here) and
    /// applies the returned body; a malformed/oversize/timed-out rewrite yields `None`.
    async fn transform(
        &self,
        _req: &RoutingRequest<'_>,
        _budget: std::time::Duration,
    ) -> TransformOutcome {
        TransformOutcome::Abstain
    }

    /// PUSH a settings map to the hook (the control surface's `PATCH .../hooks/{name}/settings`): send the
    /// `configure` message and wait for the ack, bounded by `budget`. `Ok(())` = the hook
    /// acknowledged (the caller commits); any error/nack/timeout = NOT committed. Default: this
    /// transport cannot be configured (in-process natives have no settings).
    async fn configure(
        &self,
        _hook_name: &str,
        _settings: &serde_json::Map<String, serde_json::Value>,
        _settings_version: u64,
        _budget: std::time::Duration,
    ) -> Result<(), PolicyError> {
        Err("this hook transport does not support configure".into())
    }

    /// Ask the hook to DESCRIBE its settings schema (the control surface's `GET .../hooks/{name}/schema`).
    /// `None` = the transport/hook doesn't answer describe. Proxied verbatim.
    async fn describe(&self, _budget: std::time::Duration) -> Option<serde_json::Value> {
        None
    }

    /// Ask the hook for its STATUS (observed settings + self-reported metrics — the control-plane
    /// read behind the control surface's `GET .../hooks/{name}/status`). `None` = the transport/hook doesn't
    /// answer (fail-open: never affects any request). Default: in-process natives have no status.
    async fn status(&self, _budget: std::time::Duration) -> Option<HookStatus> {
        None
    }

    /// TAP (fire-and-forget): WRITE the pre-serialized request projection (JSON bytes, no trailing
    /// newline — the transport frames it) to the hook and return. A tap is write-only in steady
    /// state, so NO reply is read. Best-effort and bounded by `budget`; ANY error is swallowed,
    /// because a tap can NEVER delay or fail the served request (the caller SPAWNS this off the
    /// request path, which is why it takes owned bytes, not a borrowed projection). DEFAULT no-op:
    /// in-process policies are not taps; only the out-of-process socket/webhook transports override it.
    async fn notify(&self, _projection: &[u8], _budget: std::time::Duration) {}
}
