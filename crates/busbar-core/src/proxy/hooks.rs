use super::*;

/// The coerced result of running a routing policy at the seam — what the ordered walk should do.
pub(crate) enum PolicyOutcome {
    /// Use this ranked order (the policy returned `Prefer`, or `on_error == first` produced the
    /// config member order). `name` is the policy/transport name for the transparency header.
    Order {
        order: Vec<usize>,
        name: &'static str,
    },
    /// Fall through to today's SWRR (the policy Abstained, or an error coerced to `on_error: weighted`).
    Weighted,
    /// Fail closed with a 503 (`on_error: reject` and the policy errored / timed out).
    Reject,
    /// The policy DELIBERATELY rejected the request (the hook's `reject` verb — a guardrail said
    /// no). Distinct from `Reject` above: that is a degraded "policy unavailable" 503, this is a
    /// first-class 4xx decision. `status` is clamped and `message` sanitized AT THE SEAM that
    /// constructs this variant (`decide_policy_order`'s mapping arm), so the guarantee holds for
    /// every producer of a rejection — wire-backed or direct-constructed.
    RejectRequest {
        status: u16,
        message: String,
        name: &'static str,
    },
    /// The hook's RESTRICT verb: the failover candidate set must be intersected with members carrying
    /// one of `tags_any` BEFORE selection, and that restriction persists across hops. An EMPTY
    /// intersection is fail-closed (`on_empty` default reject) — never allow-all. `tags_any` may be
    /// empty (a fail-closed-normalized malformed restrict), which forces the empty intersection.
    Restrict {
        tags_any: Vec<String>,
        name: &'static str,
        /// Behavior when the intersection is empty: `Reject` (default, fail-closed 503) or `Weighted`
        /// (advisory escape — SWRR over the FULL pool). `First` is treated as `Reject` (a restrict
        /// with no eligible member has no "first" to fall to).
        on_empty: crate::config::PolicyOnError,
    },
}

/// Apply a hook's `rewrite` reply to the INGRESS body. The reply carries `{role, content}` messages
/// in the canonical vocabulary the hook was projected in; each dialect frames conversation content
/// differently, and that framing belongs to the PROTOCOL WRITER — this seam names no dialect and
/// holds no per-protocol arm, so a newly registered protocol gets a correct write-back with no work
/// here. Fail-safe throughout: a body without the dialect's conversation container, an unregistered
/// ingress protocol, or a rewrite message whose content isn't plain text where the dialect needs
/// re-framing, leaves the body untouched and returns `false` — never a corrupted request.
pub(crate) fn apply_rewrite_to_body(
    v: &mut Value,
    rewrite: &crate::hooks::wire::RewriteReply,
    ingress_protocol: &str,
) -> bool {
    if rewrite.messages.is_empty() {
        return false;
    }
    let Some(obj) = v.as_object_mut() else {
        return false;
    };
    let Some(protocol) = crate::proto::protocol_for(ingress_protocol) else {
        return false;
    };
    protocol
        .writer()
        .apply_rewrite_to_ingress_body(obj, &rewrite.messages, &rewrite.tools)
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE HOOK SEAM READS THE IR — AND NOTHING ELSE
//
// Everything below replaces a second implementation of "what is the text in this request". The
// projection used to be re-derived from the raw ingress body with its own content flattening and
// its own per-dialect dispatch, so a `prompt: ro` gate could be handed a different payload than the
// one that went upstream. There is now ONE answer: the protocol's own reader produces the IR, and
// `ir::facts` projects it. No `PROTO_*` comparison survives on this seam.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// What the hook seam knows about a request, read from the IR.
// The variants differ in size by the width of a whole `IrRequest`, and boxing to even them out
// would be the wrong trade: `Chat` is the overwhelmingly common case, this value is a per-request
// LOCAL that is never stored in a collection and never moved after it is built, and a `Box` here
// would add one heap allocation to every hooked request to shrink a stack temporary. The lint is
// right about the shape and wrong about the cost.
#[allow(clippy::large_enum_variant)]
pub(crate) enum HookFacts {
    /// A conversation request the ingress protocol's reader understood.
    Chat(crate::ir::IrRequest),
    /// The body carries no readable conversation facts because it is not a JSON object at all — a
    /// multipart/binary request, or the engine's absent-body sentinel. Projects as the zeroed shape
    /// with no content, which is exactly what the seam projected for such a body before the cutover.
    /// This is NOT the parse-failure case: a body the reader REFUSES is [`HookIrRejected`].
    Absent,
}

/// The ingress protocol's reader refused the body.
///
/// The old raw-body projection could not fail: it screened a malformed request as best it could and
/// the request went upstream anyway. On the IR a read is a `Result`, and the ruling is that **the
/// parse failure is the request's failure**. If a reader cannot read a body, busbar cannot claim to
/// understand it, and forwarding it upstream while telling a guardrail it saw `role: ""` is the
/// fail-OPEN shape. Callers turn this into a 400.
#[derive(Debug)]
pub(crate) struct HookIrRejected;

/// Read the request facts the hook seam projects from — the ONE read, through the protocol's own
/// reader.
///
/// A non-object body is [`HookFacts::Absent`] rather than a rejection: it is a request whose payload
/// this seam never claimed to understand (a multipart upload, or the engine's `Value::Null`
/// stand-in), and rejecting it would fail requests that have nothing to do with hooks. An
/// unregistered protocol name is `Absent` for the same reason — there is no reader to ask.
///
/// # ONE READ PER SEAM TODAY, ONE READ PER REQUEST NEXT
///
/// Each seam that projects — the gate chain, the rewrite chain, the request-stage taps — calls this
/// once. A deployment that configures several of them therefore reads the body more than once per
/// request, which is correct but not yet cheap. Memoizing the read on the body handle, so the whole
/// request pays exactly one, is the lazy-IR seam's job and lands beside `ensure_dom`; nothing here
/// has to change for it, because every caller already goes through this one function. A deployment
/// with no hook configured pays nothing either way: no projection is built, so this is never called.
pub(crate) fn read_hook_facts(
    v: &Value,
    ingress_protocol: &str,
) -> Result<HookFacts, HookIrRejected> {
    if !v.is_object() {
        return Ok(HookFacts::Absent);
    }
    let Some(protocol) = crate::proto::protocol_for(ingress_protocol) else {
        return Ok(HookFacts::Absent);
    };
    match protocol.reader().read_request(v) {
        Ok(ir) => Ok(HookFacts::Chat(ir)),
        Err(_) => Err(HookIrRejected),
    }
}

impl HookFacts {
    /// The shape/size signal bucket every hook gets, granted or not.
    pub(crate) fn shape(&self) -> crate::ir::facts::Shape {
        match self {
            HookFacts::Chat(ir) => {
                use crate::ir::facts::IrFacts;
                ir.shape()
            }
            HookFacts::Absent => crate::ir::facts::Shape::EMPTY,
        }
    }

    /// The end-user identifier for the `user: ro` identity projection, normalized by the reader from
    /// whichever field its dialect spells it in.
    pub(crate) fn end_user(&self) -> Option<String> {
        match self {
            HookFacts::Chat(ir) => {
                use crate::ir::facts::IrFacts;
                ir.end_user().map(str::to_string)
            }
            HookFacts::Absent => None,
        }
    }

    /// The content projection a `prompt: ro|rw` grant receives: the system slot's text, and one
    /// `(role, text)` entry per conversation turn in request order.
    ///
    /// # The alignment contract, restated
    ///
    /// Entries index against `IrRequest::messages`, NOT against the wire `messages` array. Every
    /// reader hoists system-role content into the system slot, so a body carrying its system prompt
    /// in-band contributes to `system` here and not to a turn — which is the divergence being
    /// closed, and is precisely what would have prevented a shipped hook from shredding operator
    /// instructions on the dialects that carry the system prompt inside the turns array. A turn that
    /// yields no items still yields an entry with empty text: a screening hook must never see fewer
    /// turns than the provider does.
    pub(crate) fn prompt(&self) -> crate::hooks::PromptProjection<'_> {
        use crate::ir::facts::{ContentItem, Slot};
        use std::borrow::Cow;
        let HookFacts::Chat(ir) = self else {
            return crate::hooks::PromptProjection {
                system: None,
                messages: Vec::new(),
            };
        };
        // Group the flat item stream the way `ir::facts::project` documents: the system slot is its
        // own bucket, every other item joins the turn it is attributed to. One piece borrows; two or
        // more allocate the join, exactly as the flattening this replaces did.
        let mut system: Vec<Cow<'_, str>> = Vec::new();
        let mut turns: Vec<(&'static str, Vec<Cow<'_, str>>)> = Vec::new();
        for item in crate::ir::facts::project(ir) {
            let piece = match item {
                ContentItem::Text { ref text, .. } => match text {
                    Cow::Borrowed(t) => Cow::Borrowed(*t),
                    Cow::Owned(t) => Cow::Owned(t.clone()),
                },
                ref other => Cow::Owned(other.screenable_text().into_owned()),
            };
            match item.slot() {
                Slot::System => system.push(piece),
                slot => {
                    let i = slot.turn_index().unwrap_or(0);
                    while turns.len() <= i {
                        turns.push((role_name(ir.messages[turns.len()].role), Vec::new()));
                    }
                    turns[i].1.push(piece);
                }
            }
        }
        crate::hooks::PromptProjection {
            system: join_pieces(system).filter(|s| !s.is_empty()),
            messages: turns
                .into_iter()
                .map(|(role, pieces)| {
                    (
                        Cow::Borrowed(role),
                        join_pieces(pieces).unwrap_or(Cow::Borrowed("")),
                    )
                })
                .collect(),
        }
    }
}

/// The canonical role vocabulary the hook contract promises on EVERY dialect. It is the IR's own
/// enum rendered as text, so a dialect's native spelling (an assistant turn spelled `model` on one
/// wire) can never reach a hook and can never be echoed back into a corrupted turn.
fn role_name(role: crate::ir::IrRole) -> &'static str {
    match role {
        crate::ir::IrRole::System => "system",
        crate::ir::IrRole::User => "user",
        crate::ir::IrRole::Assistant => "assistant",
        crate::ir::IrRole::Tool => "tool",
    }
}

/// Join one bucket's pieces with a newline, BORROWING the single-piece case (the common one). The
/// separator is not counted by the size signal — a flattened rendering can therefore be longer than
/// `total_chars` by one char per join, exactly as it was before the cutover.
fn join_pieces(mut pieces: Vec<std::borrow::Cow<'_, str>>) -> Option<std::borrow::Cow<'_, str>> {
    match pieces.len() {
        0 => None,
        1 => pieces.pop(),
        _ => Some(std::borrow::Cow::Owned(pieces.join("\n"))),
    }
}

/// The DEFAULT ceiling, in bytes, on the content a hook is shown in one projection.
///
/// Informed by nothing measured, deliberately conservative, and paired with a counter
/// (`busbar_hook_content_truncated_total`) so the number can be chosen by a metric rather than by a
/// guess. It matters most for the largest untrusted blob in a modern agent request — a tool result —
/// which is bounded by neither a context window nor a token count.
pub(crate) const DEFAULT_HOOK_CONTENT_MAX_BYTES: usize = 64 * 1024;

/// The effective content ceiling for this config generation, resolved once at config apply
/// (`limits.hook_content_max_bytes`) and read here with a single relaxed load — never recomputed per
/// request, and never consulted at all on a deployment with no content-granted hook, because no
/// content projection is built there.
static HOOK_CONTENT_MAX_BYTES: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(DEFAULT_HOOK_CONTENT_MAX_BYTES);

/// Install the generation's content ceiling. Called at boot and on every config apply.
pub(crate) fn set_hook_content_max_bytes(bytes: usize) {
    HOOK_CONTENT_MAX_BYTES.store(bytes, std::sync::atomic::Ordering::Relaxed);
}

/// Enforce the content ceiling on a built projection, on SERIALIZED BYTES and BEFORE the call.
///
/// Over-cap content is OMITTED WHOLE, never truncated mid-value: a guardrail that screens half a
/// payload and passes it is worse than one that refuses.
///
/// # How the omission is visible to the hook, and why it must be
///
/// The grant is still honoured — the projection stays PRESENT and becomes EMPTY (`messages: []`),
/// which the wire contract already distinguishes from an absent (ungranted) projection. Together
/// with the always-present size bucket that is an explicit statement rather than a silence: a hook
/// that is shown zero content for a request whose `total_chars` says otherwise has been told, in the
/// payload, that there is content here it was not given. Silently handing a screening hook less
/// content than exists is the fail-open shape this whole change closes, so the omission is never
/// allowed to look like an empty request. `busbar_hook_content_truncated_total` counts it, so the
/// default ceiling can be chosen by a metric rather than by a guess.
pub(crate) fn enforce_content_cap(
    prompt: Option<crate::hooks::PromptProjection<'_>>,
) -> Option<crate::hooks::PromptProjection<'_>> {
    let p = prompt?;
    let cap = HOOK_CONTENT_MAX_BYTES.load(std::sync::atomic::Ordering::Relaxed);
    if cap == 0 {
        // Explicitly unlimited — the operator turned the ceiling off.
        return Some(p);
    }
    let bytes = p.system.as_deref().map(str::len).unwrap_or(0)
        + p.messages
            .iter()
            .map(|(role, text)| role.len() + text.len())
            .sum::<usize>();
    if bytes <= cap {
        return Some(p);
    }
    metrics::counter!(crate::metrics::HOOK_CONTENT_TRUNCATED_TOTAL).increment(1);
    tracing::warn!(
        content_bytes = bytes,
        cap,
        "hook content projection exceeded limits.hook_content_max_bytes; the content is OMITTED \
         whole (never truncated mid-value) and the hook is sent an empty content projection"
    );
    Some(crate::hooks::PromptProjection {
        system: None,
        messages: Vec::new(),
    })
}

/// Build the request projection a rewrite (`prompt: rw`) gate receives. The prompt is ALWAYS sent (a
/// rewrite hook is a content hook); identity is omitted (rewrite operates on content, not caller
/// identity — the `user` grant projection for rewrite hooks is a follow-up). Borrows from `facts`.
pub(crate) fn build_rewrite_request<'a>(
    facts: &'a HookFacts,
    requested_model: Option<&'a str>,
    pool_name: &'a str,
    ingress_protocol: &'a str,
    wants_stream: bool,
    with_prompt: bool,
    request_id: u64,
) -> crate::hooks::RoutingRequest<'a> {
    let shape = facts.shape();
    crate::hooks::RoutingRequest {
        request_id,
        pool: pool_name,
        ingress_protocol,
        requested_model,
        message_count: shape.turn_count,
        tool_count: shape.tool_count,
        has_tools: shape.has_tools,
        total_chars: shape.text_chars,
        system_chars: shape.system_chars,
        max_tokens: shape.max_tokens,
        stream: wants_stream,
        // A `prompt: rw` rewrite gate needs the prompt content (`with_prompt`). A TAP gets the
        // shape-only default bucket (`with_prompt == false`) — a per-grant prompt projection for
        // `prompt: ro` taps is a follow-up; shape-only never OVER-shares, so the grant holds.
        prompt: enforce_content_cap(with_prompt.then(|| facts.prompt())),
        identity: None,
        // The rewrite (transform) pass is a content seam, not a decide seam — it has no candidate
        // set to read candidate-phase catalog signals from, and no request-phase compute fn is
        // wired to this builder in this pass. Empty (never allocated).
        signals: Default::default(),
    }
}

/// The GLOBAL REWRITE (transform) pass: fire each `prompt: rw` gate in PRIORITY order, each seeing the
/// prior gate's output (the projection is rebuilt from the CURRENT body every iteration — a true
/// transform chain), and apply its rewrite to the body in place. FAIL-SAFE end to end: a hook that
/// errors/times out/abstains yields `None` (`transform`) and is skipped; `apply_rewrite_to_body` only
/// touches a chat-shaped body. Zero cost when no rewrite hook is configured (the caller guards on the
/// empty list before calling).
/// Returns `Ok(applied)` — whether ANY rewrite actually committed to the body (the caller must
/// then invalidate every retained copy of the ORIGINAL bytes: the same-protocol pristine
/// short-circuit and the failover re-parse both read them, or the rewrite silently vanishes on
/// those paths) — or `Err((status, message))` when a hook REJECTED the request:
/// reject > rewrite > abstain on the transform path too; a rw gate that also screens must be able
/// to stop the request — dropping its reject would be fail-OPEN from the hook author's view.
pub(crate) async fn apply_global_rewrites(
    rewrite_hooks: &[(
        std::time::Duration,
        std::sync::Arc<dyn crate::hooks::RoutingPolicy>,
    )],
    v: &mut Value,
    pool_name: &str,
    ingress_protocol: &str,
    wants_stream: bool,
    request_id: u64,
) -> Result<bool, (u16, String)> {
    let mut applied = false;
    for (timeout, hook) in rewrite_hooks {
        // Re-READ the IR from the current body so a later hook sees the earlier rewrite — a true
        // transform chain. A body the reader refuses is the REQUEST's failure, not a best-effort
        // projection: screening a request busbar cannot read, and forwarding it anyway, is the
        // fail-open shape.
        let facts = match read_hook_facts(v, ingress_protocol) {
            Ok(f) => f,
            Err(HookIrRejected) => return Err((400, unreadable_body_message().to_string())),
        };
        // `with_prompt = true` is sound by construction: `hooks::admits_rewrite` gates membership of
        // this slice on effective `rw`, which implies read.
        let req = build_rewrite_request(
            &facts,
            v.get("model").and_then(Value::as_str),
            pool_name,
            ingress_protocol,
            wants_stream,
            true,
            request_id,
        );
        let outcome = hook.transform(&req, *timeout).await;
        drop(req); // end the immutable borrow of `v` before mutating it
        match outcome {
            busbar_api::TransformOutcome::Rewrite(rw) => {
                applied |= apply_rewrite_to_body(v, &rw, ingress_protocol);
            }
            busbar_api::TransformOutcome::Reject { status, message } => {
                // Already status-clamped + message-sanitized at the wire seam.
                return Err((status, message));
            }
            busbar_api::TransformOutcome::Abstain => {}
        }
    }
    Ok(applied)
}

/// The client-facing message for a body the ingress protocol's reader refuses. Deliberately
/// content-free: it names the failure, never the field or the value that caused it.
pub(crate) fn unreadable_body_message() -> &'static str {
    "request body could not be read as a valid request for this endpoint"
}

/// Map a hook-chosen reject status to the closest dialect error KIND, so an SDK caller catches the
/// right typed exception: a hook 429 must surface as a rate-limit error, not a permission error.
/// Statuses without a natural kind (400, 422, 451, ...) read as invalid-request; 403 (the reject
/// default) stays a permission error.
pub(crate) fn reject_kind_for_status(status: u16) -> &'static str {
    match status {
        401 => KIND_AUTHENTICATION,
        403 => KIND_PERMISSION,
        404 => KIND_NOT_FOUND,
        408 => KIND_TIMEOUT,
        429 => KIND_RATE_LIMIT,
        _ => KIND_INVALID_REQUEST,
    }
}

/// Build the routing projection (request + candidates + context) and run the resolved policy ONCE,
/// bounded by its configured timeout, coercing the result to a `PolicyOutcome` per `on_error`.
///
/// This runs ONLY for a pool with a non-default `route:` — the zero-cost default path never calls it
/// and never constructs any of these projection types. Every signal is REAL data: `cost_per_mtok`
/// from member config, `latency_ms` from the per-lane EWMA, `available_concurrency` from the lane
/// semaphore, `budget_remaining` from the lane budget, and `rate_headroom` from the caller key's
/// governance rate window. A policy error/timeout NEVER reaches the client: it degrades per `on_error`
/// (weighted / reject / first).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn decide_policy_order(
    app: &Arc<App>,
    resolved: &crate::hooks::ResolvedPolicy,
    cands: &[WeightedLane],
    request_ctx: &RequestCtx,
    v: &Value,
    pool_name: &str,
    ingress_protocol: &str,
    wants_stream: bool,
    caller_token: Option<&str>,
    resolved_gov_key: Option<&std::sync::Arc<crate::governance::VirtualKey>>,
) -> PolicyOutcome {
    use crate::hooks::{
        Candidate, ResolvedPolicy, RoutingContext, RoutingDecision, RoutingRequest,
    };

    // A weighted/default pool resolves to `None` at config load (no policy object is constructed), so
    // the only `ResolvedPolicy` that can reach this seam is a constructed `Policy`.
    let (policy, on_error, on_error_chain, timeout, send_prompt, send_user, on_empty) =
        match resolved {
            ResolvedPolicy::Policy {
                policy,
                on_error,
                on_error_chain,
                timeout,
                send_prompt,
                send_user,
                on_empty,
            } => (
                policy,
                on_error,
                on_error_chain,
                *timeout,
                *send_prompt,
                *send_user,
                on_empty,
            ),
        };

    // The candidate set the policy ranks over = this pool's members MINUS the already-excluded ones
    // (configured exclusions). `idx` is the stable lane handle the ordered walk speaks.
    let mut live_buf: Vec<&WeightedLane> = Vec::with_capacity(cands.len());
    request_ctx.fill_candidates(cands, &mut live_buf);
    let live = &live_buf;
    if live.is_empty() {
        // Nothing to rank — let the loop's exhaustion handling take over (SWRR will also find none).
        return PolicyOutcome::Weighted;
    }

    // ONE governance key serves both consumers: the per-key rate headroom (always, same value
    // across candidates today — rate limits are per-key; see `Candidate.rate_headroom`) and, behind
    // `policy.send_user`, the caller identity projection. Prefer `resolved_gov_key` — the SAME key
    // `auth::mod`'s middleware already resolved and installed as `GovCtx.key` — over re-deriving it
    // here. Auth's resolution is authoritative: it consults the revocation denylist internally
    // (`verify_token`) and otherwise falls through to a SYNTHESIZED principal key for a GROUP/SSO
    // caller. The fallback below is reached only by the `#[cfg(test)]` bytes-only
    // `forward_with_pool` helper: every production ingress route installs a `GovCtx` via
    // `forward_with_pool_keyed` (`engine/mod.rs`), so `resolved_gov_key` is always `Some` whenever
    // `app.governance` is `Some` and this closure never runs there. Cfg-gated rather than deleted
    // per the house rule against dead code — the branch is provably unreachable outside tests (many
    // tests DO exercise the raw token-resolution path without building a full `GovCtx`), so it is
    // compiled out of the production binary entirely instead of shipping unreachable logic behind a
    // live-looking arm.
    let gov = app.governance.as_ref();
    let gov_key = resolved_gov_key.cloned().or_else(|| {
        #[cfg(test)]
        {
            match (gov, caller_token) {
                // Test-only raw-token resolution rides the DATA-PLANE boundary (no audience).
                (Some(g), Some(tok)) => g.verify_token(tok, crate::store::now(), None),
                _ => None,
            }
        }
        #[cfg(not(test))]
        {
            let _ = caller_token;
            None
        }
    });
    let rate_headroom: Option<f64> = match (gov, gov_key.as_ref()) {
        (Some(g), Some(key)) => g.rate_headroom(&app.cost, key, Some(pool_name), now()),
        _ => None,
    };

    // THE ONE READ. Everything this seam projects — counts, sizes, the caller's cap, the end-user
    // id, and the content itself — comes from the IR the ingress protocol's own reader produced. A
    // body that reader REFUSES is the request's failure, surfaced as the gate's own first-class
    // rejection rather than screened as best-effort and forwarded upstream anyway.
    let facts = match read_hook_facts(v, ingress_protocol) {
        Ok(f) => f,
        Err(HookIrRejected) => {
            return PolicyOutcome::RejectRequest {
                status: 400,
                message: unreadable_body_message().to_string(),
                name: policy.name(),
            }
        }
    };
    let shape = facts.shape();

    // `policy.send_user` opt-in (default off): project the caller identity — the virtual key's
    // id/name (from the resolved record, NEVER the token) plus the request's end-user field,
    // normalized by the reader from whichever field its dialect spells it in.
    let identity = if send_user {
        Some(crate::hooks::CallerIdentity {
            key_id: gov_key.as_ref().map(|k| k.id.clone()),
            key_name: gov_key.as_ref().map(|k| k.name.clone()),
            user: facts.end_user(),
        })
    } else {
        None
    };

    // `policy.send_prompt` opt-in (default off): project the prompt content for the hook. The
    // allocation cost lives entirely behind the flag — a shape-only pool never runs this.
    let prompt = enforce_content_cap(send_prompt.then(|| facts.prompt()));

    let member_meta = app.pool_runtime.get(pool_name).map(|r| &r.members);

    let req = RoutingRequest {
        request_id: request_ctx.request_id,
        pool: pool_name,
        ingress_protocol,
        // The one scalar still read off the pristine body: the requested model is a ROUTING noun
        // rather than a conversation fact, and the chat IR does not model it (a path-model dialect
        // never carries it in the body at all, and reads `None` here exactly as it did before).
        requested_model: v.get("model").and_then(|m| m.as_str()),
        message_count: shape.turn_count,
        tool_count: shape.tool_count,
        has_tools: shape.has_tools,
        total_chars: shape.text_chars,
        system_chars: shape.system_chars,
        // Normalized by the reader from whichever field its dialect spells the cap in — including
        // the nested config object one dialect uses, which the raw-body projection could not see.
        // A SIZE signal, not a limit.
        max_tokens: shape.max_tokens,
        stream: wants_stream,
        prompt,
        identity,
        // Request-phase catalog signals: none wired to the decide path in this pass (the existing
        // core fields above already cover every request-shape signal a route policy reads today).
        signals: Default::default(),
    };

    // "Decision observability": the config generation's declared-signal
    // bitmask, resolved ONCE at config apply (`hooks::requested_signals`) and read here with a
    // single `u64` comparison — never recomputed per request. `is_empty()` short-circuits the
    // WHOLE candidate-signal loop below on the zero-cost default (no hook anywhere declared a
    // catalog signal): no `SignalBag` is ever pushed to, so it never spills its inline capacity.
    let requested = app.requested_signals;
    let now_ts = now();

    let candidates: Vec<Candidate> = live
        .iter()
        .map(|wl| {
            let lane = &app.lanes[wl.idx];
            let meta = member_meta.and_then(|m| m.get(&wl.idx));
            let mut signals = busbar_api::SignalBag::new();
            if !requested.is_empty() {
                // Both are PURE projections of state the breaker FSM already maintains on every
                // request/outcome regardless of declaration (see `LaneRuntime::
                // breaker_state_snapshot_in`/`error_rate_in`'s doc comments) — the gate below is
                // the compute-the-sliver check: the read runs ONLY when
                // declared, never call-then-discard.
                if requested.wants(crate::hooks::Signal::CandidateBreakerState) {
                    let label = match app.store.breaker_state_snapshot_in(pool_name, wl.idx) {
                        crate::store::BreakerState::Closed => "closed",
                        crate::store::BreakerState::Open { .. } => "open",
                        crate::store::BreakerState::HalfOpen => "half_open",
                    };
                    signals.push(
                        crate::hooks::Signal::CandidateBreakerState,
                        busbar_api::SignalValue::Str(std::borrow::Cow::Borrowed(label)),
                    );
                }
                if requested.wants(crate::hooks::Signal::CandidateErrorRate) {
                    if let Some(rate) = app.store.error_rate_in(pool_name, wl.idx, now_ts) {
                        signals.push(
                            crate::hooks::Signal::CandidateErrorRate,
                            busbar_api::SignalValue::F64(rate),
                        );
                    }
                }
            }
            Candidate {
                idx: wl.idx,
                model: &lane.model,
                provider: &lane.provider,
                weight: wl.weight,
                context_max: lane.context_max,
                tier: meta.and_then(|m| m.tier.as_deref()),
                cost_per_mtok: meta.and_then(|m| m.cost_per_mtok),
                tags: meta.map(|m| m.tags.as_slice()).unwrap_or(&[]),
                latency_ms: app.store.lane_latency_ms(wl.idx),
                available_concurrency: app.store.available_permits(wl.idx),
                budget_remaining: app.store.lane_budget_remaining(wl.idx),
                rate_headroom,
                signals,
            }
        })
        .collect();

    // The HOOK SEAM's budget projection: for the caller key and each ancestor
    // budget group, {bucket_id, spend_micros_at_current_rate, remaining_micros, window} - derived
    // fresh from the token ledger x the CURRENT rate card at this moment. Built ONLY here (a
    // routing-policy pool; the zero-cost default path never runs this fn), so its allocation stays
    // off the default hot path. Busbar exposes the READ surface only; downshifting to a cheaper
    // model on it is the hook's policy, never core's.
    let budget_chain: Vec<busbar_api::BudgetBucketState> = match (gov, gov_key.as_ref()) {
        (Some(g), Some(key)) => g.budget_state(&app.cost, key, now()),
        _ => Vec::new(),
    };
    let ctx = RoutingContext {
        pool: pool_name,
        // Lane-health-shaped budget signal (legacy v1 field): still not fed - the per-request
        // budget signal now rides the structured `budget` chain below.
        budget_remaining: None,
        budget: &budget_chain,
    };

    // Run the decision under a HARD wall-clock timeout (the policy is also asked to respect `budget`).
    // A timeout or an `Err` is coerced to `on_error`; an impl that simply has no opinion returns
    // `Ok(Abstain)`. The decision NEVER blocks past `timeout` and NEVER propagates an error to the
    // client.
    let decision: RoutingDecision = match tokio::time::timeout(
        timeout,
        policy.decide(&req, &candidates, &ctx, timeout),
    )
    .await
    {
        Ok(Ok(d)) => d,
        // Policy errored: apply on_error — but LOG the error first. A hook binary that is down,
        // deadline-exceeded, or replying garbage would otherwise fail silently on every request
        // (the pool degrades to on_error with no operator-visible signal that the hook is broken).
        Ok(Err(e)) => {
            tracing::warn!(
                policy = policy.name(),
                pool = pool_name,
                error = %e,
                "routing policy failed; applying on_error fallback"
            );
            return run_on_error_chain(
                on_error_chain,
                on_error,
                &req,
                &candidates,
                &ctx,
                policy.name(),
                pool_name,
            )
            .await;
        }
        // Timed out at the seam's own hard deadline: same fallback, same visibility. The policy/
        // transport stays cancel-safe — a dropped future on timeout is fine.
        Err(_) => {
            tracing::warn!(
                policy = policy.name(),
                pool = pool_name,
                timeout_ms = timeout.as_millis() as u64,
                "routing policy deadline exceeded; applying on_error fallback"
            );
            return run_on_error_chain(
                on_error_chain,
                on_error,
                &req,
                &candidates,
                &ctx,
                policy.name(),
                pool_name,
            )
            .await;
        }
    };

    map_decision(decision, policy.name(), &candidates, on_empty)
}

/// Walk a failed gate's resolved `on_error` fallback CHAIN: fire each fallback in order (bounded by
/// ITS deadline, projected per ITS grants — a fallback never sees prompt/identity its own grants
/// don't allow), and let the FIRST one that answers decide, exactly as a primary decision would.
/// Every link failing lands on the chain's reserved TERMINAL (weighted/reject/first). The common
/// case — `on_error: weighted` etc. — has an EMPTY chain and goes straight to the terminal.
pub(crate) async fn run_on_error_chain(
    chain: &[crate::hooks::FallbackHook],
    terminal: &crate::config::PolicyOnError,
    req: &crate::hooks::RoutingRequest<'_>,
    candidates: &[crate::hooks::Candidate<'_>],
    ctx: &crate::hooks::RoutingContext<'_>,
    failed_policy_name: &'static str,
    pool_name: &str,
) -> PolicyOutcome {
    for fb in chain {
        // Re-project per the FALLBACK's grants: it may see at most what the primary projection
        // built AND its own grants allow (never over-shares; a fallback with a grant the primary
        // lacked gets shape-only — the projection was never built).
        let fb_req = crate::hooks::RoutingRequest {
            prompt: if fb.send_prompt {
                req.prompt.clone()
            } else {
                None
            },
            identity: if fb.send_user {
                req.identity.clone()
            } else {
                None
            },
            ..req.clone()
        };
        match tokio::time::timeout(
            fb.timeout,
            fb.policy.decide(&fb_req, candidates, ctx, fb.timeout),
        )
        .await
        {
            Ok(Ok(decision)) => {
                tracing::info!(
                    policy = failed_policy_name,
                    fallback = fb.policy.name(),
                    pool = pool_name,
                    "on_error fallback hook answered for the failed gate"
                );
                return map_decision(decision, fb.policy.name(), candidates, &fb.on_empty);
            }
            // This link failed too — follow the chain to the next (its own on_error was flattened
            // into this chain at resolution).
            Ok(Err(e)) => {
                tracing::warn!(
                    fallback = fb.policy.name(),
                    pool = pool_name,
                    error = %e,
                    "on_error fallback hook failed; continuing down the chain"
                );
            }
            Err(_) => {
                tracing::warn!(
                    fallback = fb.policy.name(),
                    pool = pool_name,
                    timeout_ms = fb.timeout.as_millis() as u64,
                    "on_error fallback hook deadline exceeded; continuing down the chain"
                );
            }
        }
    }
    coerce_on_error(terminal, candidates, failed_policy_name)
}

/// Map a policy's `RoutingDecision` to the seam's `PolicyOutcome` — shared by the primary decision
/// and every on_error fallback, so a fallback's reject/restrict/order carries the same clamping,
/// sanitizing, and normalization guarantees as a primary's.
pub(crate) fn map_decision(
    decision: crate::hooks::RoutingDecision,
    policy_name: &'static str,
    candidates: &[crate::hooks::Candidate<'_>],
    on_empty: &crate::config::PolicyOnError,
) -> PolicyOutcome {
    use crate::hooks::RoutingDecision;

    match decision {
        RoutingDecision::Prefer(order) => {
            // Normalize against the valid candidate idxs (drop unknown, dedup). An empty result is
            // Abstain — fall through to SWRR.
            let valid: std::collections::HashSet<usize> =
                candidates.iter().map(|c| c.idx).collect();
            match RoutingDecision::from_ranked(order, &valid) {
                RoutingDecision::Prefer(o) => PolicyOutcome::Order {
                    order: o,
                    name: policy_name,
                },
                RoutingDecision::Abstain => PolicyOutcome::Weighted,
                // `from_ranked` only ever produces Prefer/Abstain — it normalizes an order, it
                // cannot invent a rejection or a restriction.
                RoutingDecision::Reject { .. } => unreachable!("from_ranked never rejects"),
                RoutingDecision::Restrict { .. } => {
                    unreachable!("from_ranked never restricts")
                }
            }
        }
        // Abstain is the clean "no opinion" — today's exact SWRR (NOT coerced via on_error).
        RoutingDecision::Abstain => PolicyOutcome::Weighted,
        // The hook's reject verb: a deliberate first-class decision (a guardrail said no), NOT an
        // error — `on_error` does not apply. The shipped transports produce Reject only through
        // `wire::normalize` (clamped + sanitized), but the trait lets ANY policy impl construct
        // the variant directly — so the seam re-clamps the status to 400..=499 (else 403) AND
        // re-sanitizes the message (same shared sanitizer, idempotent on already-clean input) as
        // defense in depth: no policy, present or future, can mint a success/redirect/5xx or a
        // log/client-injecting message through this path.
        RoutingDecision::Reject { status, message } => PolicyOutcome::RejectRequest {
            status: crate::hooks::wire::clamp_reject_status(status),
            message: crate::hooks::wire::sanitize_reject_message(&message),
            name: policy_name,
        },
        // The hook's RESTRICT verb: keep only candidates carrying one of `tags_any` (a compliance
        // gate). The intersection + on_empty are applied at the failover-set seam in `forward_with_
        // pool`; here we just carry the tag set through. An empty `tags_any` (malformed restrict,
        // normalized fail-closed) forces the empty intersection → on_empty, never allow-all.
        RoutingDecision::Restrict { tags_any } => PolicyOutcome::Restrict {
            tags_any,
            name: policy_name,
            on_empty: on_empty.clone(),
        },
    }
}

/// Coerce an `on_error` fallback into a `PolicyOutcome` when the policy errored / timed out:
/// `weighted` ⇒ SWRR, `first` ⇒ the config member order (a deterministic degraded pick), `reject`
/// ⇒ a 503. `first` advertises the policy name so the degraded pick is still observable.
pub(crate) fn coerce_on_error(
    on_error: &crate::config::PolicyOnError,
    candidates: &[crate::hooks::Candidate<'_>],
    policy_name: &'static str,
) -> PolicyOutcome {
    use crate::config::PolicyOnError;
    match on_error {
        PolicyOnError::Weighted => PolicyOutcome::Weighted,
        PolicyOnError::Reject => PolicyOutcome::Reject,
        PolicyOnError::First => PolicyOutcome::Order {
            order: candidates.iter().map(|c| c.idx).collect(),
            name: policy_name,
        },
    }
}

/// Shape scalars captured ONCE per request for the STAGE tap payloads (candidate/routing/response).
/// All owned/`'static`-free scalars except the pool/protocol names (which outlive the request), so
/// the capture survives `v` being consumed by the first dispatch hop. Stage taps are SHAPE-ONLY in
/// this increment: the default signal bucket plus the stage object — never prompt content or caller
/// identity, regardless of grant (never over-shares; a granted tap still gets content at the
/// `request` stage).
pub(crate) struct StageShape<'a> {
    /// The request correlation id (`RequestCtx::request_id`) — carried on the shape so every stage
    /// tap (candidate/routing/response) notification for this request stamps the SAME join-key value
    /// a `decide`/`transform` payload for the same request carries.
    request_id: u64,
    pool: &'a str,
    ingress_protocol: &'a str,
    message_count: usize,
    has_tools: bool,
    total_chars: usize,
    max_tokens: Option<u32>,
    stream: bool,
}

/// Capture the stage-tap shape from the parsed body (`None` = an opaque/binary body: zeroed shape).
pub(crate) fn capture_stage_shape<'a>(
    v: Option<&Value>,
    pool: &'a str,
    ingress_protocol: &'a str,
    stream: bool,
    request_id: u64,
) -> StageShape<'a> {
    // Read through the IR like every other hook projection. A body the reader REFUSES yields the
    // zeroed shape rather than failing anything: a stage tap is fire-and-forget OBSERVATION and can
    // never fail a request. The request itself is still rejected — by the gate/rewrite seams, which
    // read the same IR and do surface the parse failure — so this is not a fail-open hole, it is an
    // observation path declining to invent facts it does not have.
    let shape = match v {
        Some(v) => read_hook_facts(v, ingress_protocol)
            .map(|f| f.shape())
            .unwrap_or(crate::ir::facts::Shape::EMPTY),
        None => crate::ir::facts::Shape::EMPTY,
    };
    StageShape {
        request_id,
        pool,
        ingress_protocol,
        message_count: shape.turn_count,
        has_tools: shape.has_tools,
        total_chars: shape.text_chars,
        max_tokens: shape.max_tokens,
        stream,
    }
}

/// Fire one STAGE's taps (candidate/routing/response) fire-and-forget: serialize the shape-only
/// projection + stage object ONCE, then spawn one detached task per tap. A tap can never delay,
/// reorder, or fail the request; a serialization failure silently skips the fire (observation is
/// best-effort). ZERO COST when the stage has no taps (first-line empty check).
pub(crate) fn fire_stage_taps(
    taps: &[crate::hooks::TapEntry],
    shape: &StageShape<'_>,
    stage: crate::hooks::wire::HookStageProjection<'_>,
    // The caller's `groups:` binding + the groups tree (1.5.3 SELECTION): a stage tap fires only for
    // a caller in its `groups:` scope (empty = every caller). Walked self + ancestors.
    caller_group: Option<&str>,
    groups_tree: &std::collections::BTreeMap<String, crate::config::GroupCfg>,
) {
    if taps.is_empty() {
        return;
    }
    let hook_req = crate::hooks::wire::HookRequest {
        op: crate::hooks::wire::OP_NOTIFY,
        request: crate::hooks::wire::HookReqProjection {
            request_id: shape.request_id,
            pool: shape.pool,
            ingress_protocol: shape.ingress_protocol,
            message_count: shape.message_count,
            has_tools: shape.has_tools,
            total_chars: shape.total_chars,
            max_tokens: shape.max_tokens,
            stream: shape.stream,
            system: None,
            messages: None,
            user: None,
            // Stage taps (candidate/routing/response) project no catalog signals in this
            // pass (the response-phase outcome seam those signals need is a separate,
            // not-yet-built increment — see `Signal::ResponseTokensOut`'s doc comment). Empty
            // (never allocated), so the wire is byte-identical to before this change.
            signals: Default::default(),
        },
        candidates: Vec::new(),
        context: crate::hooks::wire::HookContext {
            budget: &[],
            budget_remaining: None,
        },
        stage: Some(stage),
    };
    let Ok(bytes) = crate::json::to_vec(&hook_req) else {
        return;
    };
    let bytes = std::sync::Arc::new(bytes);
    for (timeout, _send_prompt, hook, groups) in taps {
        // SELECTION: skip a stage tap whose `groups:` scope does not admit this caller.
        if !crate::config::caller_in_hook_groups(caller_group, groups, groups_tree) {
            continue;
        }
        let policy = hook.clone();
        let budget = *timeout;
        let proj = bytes.clone();
        crate::hooks::tap::spawn_bounded_tap(async move { policy.notify(&proj, budget).await });
    }
}

/// Response-extension marker set by every GATE-produced rejection return, so the response-stage
/// taps can report the SYNTHETIC `rejected_by_gate` outcome (audit taps see denials) instead of a
/// generic `failed`.
#[derive(Clone)]
pub(crate) struct GateRejected;

/// Tag a gate-produced rejection response with the [`GateRejected`] marker.
pub(crate) fn gate_rejected(mut resp: Response) -> Response {
    resp.extensions_mut().insert(GateRejected);
    resp
}
