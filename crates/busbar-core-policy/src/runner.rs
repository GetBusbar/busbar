// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE NEUTRAL HOOK RUNNER — the projection / rewrite / decision-mapping half of the hook seam.
//!
//! This module is the seam a served request crosses on its way to a configured hook, and back:
//! it READS the request's neutral facts through the protocol's own reader
//! ([`busbar_substrate::ir::facts::IrFacts`]), PROJECTS them into the hook contract's
//! [`busbar_contract::RoutingRequest`] under the grants the operator configured, ENFORCES the
//! content ceiling, APPLIES a `rewrite` reply back onto the ingress body through the protocol's
//! own writer, WALKS a failed hook's `on_error` fallback chain, and MAPS what a hook answered
//! onto the neutral [`PolicyOutcome`] the caller acts on.
//!
//! IT IS NEUTRAL, AND THAT IS THE WHOLE POINT. It moved here BY IDENTITY out of the routing
//! engine beside one protocol, where it read as that protocol's private seam while naming
//! nothing of it. Every type it touches is the hook CONTRACT's or the neutral substrate's: no
//! plane, no dialect, no transport, no protocol writer and no routing engine appears in it. A
//! dialect is reached only as `busbar_substrate::proto::decl_for(..).dialect()` — the registry's
//! answer for whatever protocol served the request, never a named one — which is exactly what
//! "the runner runs every plane's hooks the same way" means, and it is checkable by reading the
//! imports below.
//!
//! WHAT IS NOT HERE. Deciding the ORDER a routing policy asks for over a set of live candidates
//! needs the routing engine's own tables, and that seam stays with the engine until the engine
//! itself moves.

use serde_json::Value;

use busbar_substrate::proxy::{
    APPLICATION_JSON, KIND_AUTHENTICATION, KIND_INVALID_REQUEST, KIND_NOT_FOUND, KIND_OVERLOADED,
    KIND_PERMISSION, KIND_RATE_LIMIT, KIND_TIMEOUT,
};

use busbar_substrate::diagnostics::{
    ON_ERROR_FALLBACK_ANSWERED, ON_ERROR_FALLBACK_DEADLINE_EXCEEDED, ON_ERROR_FALLBACK_HOOK_FAILED,
};
use busbar_substrate::{diag_debug, diag_warn};

/// The coerced result of running a routing policy at the seam — what the ordered walk should do.
pub enum PolicyOutcome {
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
        on_empty: busbar_substrate::config::PolicyOnError,
    },
}

/// Apply a hook's `rewrite` reply to the INGRESS body. The reply carries `{role, content}` messages
/// in the canonical vocabulary the hook was projected in; each dialect frames conversation content
/// differently, and that framing belongs to the PROTOCOL WRITER — this seam names no dialect and
/// holds no per-protocol arm, so a newly registered protocol gets a correct write-back with no work
/// here. Fail-safe throughout: a body without the dialect's conversation container, an unregistered
/// ingress protocol, or a rewrite message whose content isn't plain text where the dialect needs
/// re-framing, leaves the body untouched and returns `false` — never a corrupted request.
pub fn apply_rewrite_to_body(
    v: &mut Value,
    rewrite: &busbar_contract::RewriteReply,
    ingress_protocol: &str,
) -> bool {
    if rewrite.messages.is_empty() {
        return false;
    }
    let Some(obj) = v.as_object_mut() else {
        return false;
    };
    let Some(dialect) =
        busbar_substrate::proto::decl_for(ingress_protocol).and_then(|d| d.dialect())
    else {
        return false;
    };
    dialect.apply_rewrite_to_ingress_body(obj, &rewrite.messages, &rewrite.tools)
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
//
// `Chat` holds the request behind the neutral [`busbar_substrate::ir::facts::IrFacts`] trait, NOT a concrete
// `IrRequest`: this seam consumes only the projection (`shape`/`end_user`/`content`), so naming the
// concrete request type here would be the runner reaching into a protocol writer's own representation
// for no gain. The box is the price of the trait object, and it is the RIGHT price: the concrete IR
// belongs to whichever crate WROTE that protocol, and a hooked request already pays a body read, so
// one pointer indirection on the path that is only taken when a hook is configured is not a cost
// worth naming a protocol writer's type to save.
pub enum HookFacts {
    /// A request the ingress OPERATION's reader understood, seen through its neutral facts. Named
    /// `Facts` and not `Chat` because the seam is operation-general now: a chat body reaches it as
    /// `IrReq::Chat`, an embeddings/image/audio/rerank/moderation/subscribe body as its own family's
    /// IR, and every one of them is screened through the SAME [`busbar_substrate::ir::facts::IrFacts`] projection
    /// — closing the hole where a non-chat operation forwarded past a content gate that saw nothing.
    Facts(Box<dyn busbar_substrate::ir::facts::IrFacts + Send + Sync>),
    /// The body carries no readable facts for this seam: a JSON body with no resolvable operation
    /// handler, an unregistered protocol, or the engine's absent-body sentinel with no bytes to read.
    /// Projects as the zeroed shape with no content, which is exactly what the seam projected for such
    /// a body before the cutover. This is NOT the parse-failure case: a body the reader REFUSES is
    /// [`HookIrRejected`].
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
pub struct HookIrRejected;

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
pub fn read_hook_facts(
    v: &Value,
    body: &[u8],
    content_type: &str,
    ingress_protocol: &str,
    operation: Option<busbar_contract::operation::Operation>,
) -> Result<HookFacts, HookIrRejected> {
    // The op-less pre-routing site (auth's completion-tap capture, `operation == None`) never
    // resolved an operation, so there is nothing to read and nothing to reject — the zeroed shape,
    // exactly as before.
    let Some(operation) = operation else {
        return Ok(HookFacts::Absent);
    };
    // Resolve THIS operation's codec: the same reader the cross-protocol translate path and the
    // lazy-IR seam use, so the hook sees exactly the IR that will be built from these bytes. No
    // handler (an unregistered protocol, or a protocol that does not serve this operation) is
    // `Absent`: there is no reader to ask, which is not the same as a reader refusing.
    let Some(handler) = busbar_substrate::handlers::request_handler(ingress_protocol)
        .and_then(|rh| rh.operation_handler(operation))
    else {
        return Ok(HookFacts::Absent);
    };
    // A JSON OBJECT body projects through the value reader (chat overrides it to call its proto
    // reader directly — byte-identical to the pre-change seam). A non-object body is either a
    // multipart/binary payload (transcription/speech audio) whose caller text is reachable ONLY
    // through the byte reader, or the engine's absent-body sentinel with no bytes at all.
    use busbar_substrate::handlers::TranslateCodec;
    // THE ONE READ, through the codec cell's neutral `read_facts` entrypoint — the same reader the
    // cross-protocol translate path uses, projected straight to `IrFacts` so this seam never holds the
    // concrete IR. A JSON OBJECT body takes the value-codec fast path (chat calls its proto reader
    // directly — no re-serialize); a non-object body is either the byte-reader path (multipart /
    // binary) or the absent-body sentinel.
    let facts = if v.is_object() {
        handler.read_facts_value(v)
    } else if body.is_empty() {
        // Genuinely bodyless / the `Value::Null` sentinel: nothing to read, nothing to reject.
        return Ok(HookFacts::Absent);
    } else {
        handler.read_facts(body, content_type)
    };
    match facts {
        Ok(facts) => Ok(HookFacts::Facts(facts)),
        // A body the operation's own reader REFUSES is the request's failure, per-operation — the
        // same fail-closed ruling the chat seam already applied (parse-failure = request failure).
        Err(_) => Err(HookIrRejected),
    }
}

impl HookFacts {
    /// The shape/size signal bucket every hook gets, granted or not.
    pub fn shape(&self) -> busbar_substrate::ir::facts::Shape {
        match self {
            HookFacts::Facts(ir) => ir.shape(),
            HookFacts::Absent => busbar_substrate::ir::facts::Shape::EMPTY,
        }
    }

    /// The end-user identifier for the `user: ro` identity projection, normalized by the reader from
    /// whichever field its dialect spells it in.
    pub fn end_user(&self) -> Option<String> {
        match self {
            HookFacts::Facts(ir) => ir.end_user().map(str::to_string),
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
    pub fn prompt(&self) -> busbar_contract::PromptProjection<'_> {
        use busbar_substrate::ir::facts::{ContentItem, Slot};
        use std::borrow::Cow;
        let HookFacts::Facts(ir) = self else {
            return busbar_contract::PromptProjection {
                system: None,
                messages: Vec::new(),
            };
        };
        // Group the flat item stream the way `ir::facts::project` documents: the system slot is its
        // own bucket, every other item joins the turn it is attributed to. One piece borrows; two or
        // more allocate the join, exactly as the flattening this replaces did.
        let mut system: Vec<Cow<'_, str>> = Vec::new();
        let mut turns: Vec<(&'static str, Vec<Cow<'_, str>>)> = Vec::new();
        for item in ir.content() {
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
                        // The turn label comes from the projected item's own neutral author, not from
                        // `IrRequest::messages[i].role`: `project` guarantees one item per turn in turn
                        // order (the empty-turn rule), so the item creating turn `i` is a turn-`i` item
                        // and its `author()` is exactly what `author_of(messages[i].role)` produced.
                        // That keeps this seam off the concrete IR — it reads only the trait projection.
                        turns.push((item.author(), Vec::new()));
                    }
                    turns[i].1.push(piece);
                }
            }
        }
        busbar_contract::PromptProjection {
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

// The DEFAULT/effective content-ceiling knob (`DEFAULT_HOOK_CONTENT_MAX_BYTES`, the process-wide
// `HOOK_CONTENT_MAX_BYTES` cell, `set_hook_content_max_bytes`/`hook_content_max_bytes`) is NEUTRAL
// vocabulary that STAYS in core (`busbar_substrate::proxy::proxy_vocab`); the enforcer below reads the
// installed ceiling straight off the substrate, `busbar_substrate::proxy::hook_content_max_bytes()`.

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
pub fn enforce_content_cap(
    prompt: Option<busbar_contract::PromptProjection<'_>>,
) -> Option<busbar_contract::PromptProjection<'_>> {
    let p = prompt?;
    let cap = busbar_substrate::proxy::hook_content_max_bytes();
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
    metrics::counter!(busbar_substrate::metrics::HOOK_CONTENT_TRUNCATED_TOTAL).increment(1);
    // Per-request condition on a configured ceiling; the HOOK_CONTENT_TRUNCATED_TOTAL counter above
    // is the operator-facing signal, so log the detail at `debug!` rather than warn-spamming per call.
    tracing::debug!(
        content_bytes = bytes,
        cap,
        "hook content projection exceeded limits.hook_content_max_bytes; the content is OMITTED \
         whole (never truncated mid-value) and the hook is sent an empty content projection"
    );
    Some(busbar_contract::PromptProjection {
        system: None,
        messages: Vec::new(),
    })
}

/// Build the request projection a rewrite (`prompt: rw`) gate receives. The prompt is ALWAYS sent (a
/// rewrite hook is a content hook); identity is omitted (rewrite operates on content, not caller
/// identity — the `user` grant projection for rewrite hooks is a follow-up). Borrows from `facts`.
pub fn build_rewrite_request<'a>(
    facts: &'a HookFacts,
    requested_model: Option<&'a str>,
    pool_name: &'a str,
    ingress_protocol: &'a str,
    wants_stream: bool,
    with_prompt: bool,
    request_id: u64,
) -> busbar_contract::RoutingRequest<'a> {
    let shape = facts.shape();
    busbar_contract::RoutingRequest {
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
pub async fn apply_global_rewrites(
    rewrite_hooks: &[(
        std::time::Duration,
        std::sync::Arc<dyn busbar_contract::RoutingPolicy>,
    )],
    v: &mut Value,
    pool_name: &str,
    ingress_protocol: &str,
    operation: busbar_contract::operation::Operation,
    wants_stream: bool,
    request_id: u64,
) -> Result<bool, (u16, String)> {
    let mut applied = false;
    for (timeout, hook) in rewrite_hooks {
        // Re-READ the IR from the current body so a later hook sees the earlier rewrite — a true
        // transform chain. A body the reader refuses is the REQUEST's failure, not a best-effort
        // projection: screening a request busbar cannot read, and forwarding it anyway, is the
        // fail-open shape. A rewrite chain only runs on a materialized JSON-object body (the caller
        // gates on `v.as_mut()`), so the byte-reader arm of `read_hook_facts` is never taken here —
        // the operation's value reader projects the current (post-rewrite) tree directly.
        let facts =
            match read_hook_facts(v, &[], APPLICATION_JSON, ingress_protocol, Some(operation)) {
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
            busbar_contract::TransformOutcome::Rewrite(rw) => {
                applied |= apply_rewrite_to_body(v, &rw, ingress_protocol);
            }
            busbar_contract::TransformOutcome::Reject { status, message } => {
                // Already status-clamped + message-sanitized at the wire seam.
                return Err((status, message));
            }
            busbar_contract::TransformOutcome::Abstain => {}
            // The hook could not answer. Reaching this arm IS the PROCEED disposition: a failed
            // call to a hook the operator declared load-bearing (`on_error: reject`) was turned
            // into a `Reject` by the resolver's decorator and returned above, before any firing
            // site saw it. What is left here is the hook whose disposition says to carry on —
            // logged, so a rewrite gate that is down leaves an operator-visible signal instead of
            // looking exactly like a compressor with nothing to change.
            busbar_contract::TransformOutcome::Failed { message } => {
                tracing::warn!(
                    hook = hook.name(),
                    pool = pool_name,
                    error = %message,
                    "rewrite hook could not answer; proceeding with the original body"
                );
            }
        }
    }
    Ok(applied)
}

/// The client-facing message for a body the ingress protocol's reader refuses. Deliberately
/// content-free: it names the failure, never the field or the value that caused it.
pub fn unreadable_body_message() -> &'static str {
    "request body could not be read as a valid request for this endpoint"
}

/// Map a hook-chosen reject status to the closest dialect error KIND, so an SDK caller catches the
/// right typed exception: a hook 429 must surface as a rate-limit error, not a permission error.
/// Statuses without a natural kind (400, 422, 451, ...) read as invalid-request; 403 (the reject
/// default) stays a permission error. 503 is the ONE non-4xx status this map sees: a hook's own
/// reject reply is clamped to 400..=499 at the wire seam, so 503 arrives only from the `on_error:
/// reject` disposition of a FAILED call — a transient condition, which must read as retryable
/// (the same kind the read-only seat renders for the same condition), never as a client error.
pub fn reject_kind_for_status(status: u16) -> &'static str {
    match status {
        401 => KIND_AUTHENTICATION,
        403 => KIND_PERMISSION,
        404 => KIND_NOT_FOUND,
        408 => KIND_TIMEOUT,
        429 => KIND_RATE_LIMIT,
        busbar_substrate::hooks::REQUIRED_HOOK_UNAVAILABLE_STATUS => KIND_OVERLOADED,
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
/// Process-lifetime warn-once latch for routing-policy fault windows, keyed `policy@pool`. A broken
/// hook (down / deadline-exceeded / replying garbage) fails on EVERY request, so an unlatched `warn!`
/// spams per request; the bounded ROUTE_POLICY counters carry the per-request volume. A key present
/// in the set is "currently in a fault window": the first failure warns and inserts; subsequent
/// failures log `debug!`; the first SUCCESS removes the key so the next fault re-warns.
static POLICY_FAULT_WINDOW: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashSet<String>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashSet::new()));

/// Enter the fault window for `key`; returns `true` if this is the transition INTO the window (warn),
/// `false` if it was already open (debug).
pub fn policy_fault_enter(key: &str) -> bool {
    let mut set = POLICY_FAULT_WINDOW
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    set.insert(key.to_string())
}

/// Clear the fault window for `key` on a success, so the next fault re-warns. Cheap no-op when the
/// key was never in a fault window (the steady-state healthy path).
pub fn policy_fault_clear(key: &str) {
    let mut set = POLICY_FAULT_WINDOW
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if !set.is_empty() {
        set.remove(key);
    }
}

/// Walk a failed gate's resolved `on_error` fallback CHAIN: fire each fallback in order (bounded by
/// ITS deadline, projected per ITS grants — a fallback never sees prompt/identity its own grants
/// don't allow), and let the FIRST one that answers decide, exactly as a primary decision would.
/// Every link failing lands on the chain's reserved TERMINAL (weighted/reject/first). The common
/// case — `on_error: weighted` etc. — has an EMPTY chain and goes straight to the terminal.
pub async fn run_on_error_chain(
    chain: &[busbar_substrate::hooks::FallbackHook],
    terminal: &busbar_substrate::config::PolicyOnError,
    req: &busbar_contract::RoutingRequest<'_>,
    candidates: &[busbar_contract::Candidate<'_>],
    ctx: &busbar_contract::RoutingContext<'_>,
    failed_policy_name: &'static str,
    pool_name: &str,
) -> PolicyOutcome {
    for fb in chain {
        // Re-project per the FALLBACK's grants: it may see at most what the primary projection
        // built AND its own grants allow (never over-shares; a fallback with a grant the primary
        // lacked gets shape-only — the projection was never built).
        let fb_req = busbar_contract::RoutingRequest {
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
                // Success clears this fallback's fault window so a future fault re-warns.
                policy_fault_clear(&format!("{}@{}", fb.policy.name(), pool_name));
                diag_debug!(
                    ON_ERROR_FALLBACK_ANSWERED,
                    policy = failed_policy_name,
                    fallback = fb.policy.name(),
                    pool = pool_name,
                    "on_error fallback hook answered for the failed gate"
                );
                return map_decision(decision, fb.policy.name(), candidates, &fb.on_empty);
            }
            // This link failed too — follow the chain to the next (its own on_error was flattened
            // into this chain at resolution). Warn ONCE per fallback fault window (reset on the next
            // success); continued failures log `debug!`.
            Ok(Err(e)) => {
                let key = format!("{}@{}", fb.policy.name(), pool_name);
                if policy_fault_enter(&key) {
                    diag_warn!(
                        ON_ERROR_FALLBACK_HOOK_FAILED,
                        fallback = fb.policy.name(),
                        pool = pool_name,
                        error = %e,
                        "on_error fallback hook failed; continuing down the chain"
                    );
                } else {
                    diag_debug!(
                        ON_ERROR_FALLBACK_HOOK_FAILED,
                        fallback = fb.policy.name(),
                        pool = pool_name,
                        error = %e,
                        "on_error fallback hook still failing; continuing down the chain"
                    );
                }
            }
            Err(_) => {
                let key = format!("{}@{}", fb.policy.name(), pool_name);
                if policy_fault_enter(&key) {
                    diag_warn!(
                        ON_ERROR_FALLBACK_DEADLINE_EXCEEDED,
                        fallback = fb.policy.name(),
                        pool = pool_name,
                        timeout_ms = fb.timeout.as_millis() as u64,
                        "on_error fallback hook deadline exceeded; continuing down the chain"
                    );
                } else {
                    diag_debug!(
                        ON_ERROR_FALLBACK_DEADLINE_EXCEEDED,
                        fallback = fb.policy.name(),
                        pool = pool_name,
                        timeout_ms = fb.timeout.as_millis() as u64,
                        "on_error fallback hook deadline still exceeded; continuing down the chain"
                    );
                }
            }
        }
    }
    coerce_on_error(terminal, candidates, failed_policy_name)
}

/// Map a policy's `RoutingDecision` to the seam's `PolicyOutcome` — shared by the primary decision
/// and every on_error fallback, so a fallback's reject/restrict/order carries the same clamping,
/// sanitizing, and normalization guarantees as a primary's.
pub fn map_decision(
    decision: busbar_contract::RoutingDecision,
    policy_name: &'static str,
    candidates: &[busbar_contract::Candidate<'_>],
    on_empty: &busbar_substrate::config::PolicyOnError,
) -> PolicyOutcome {
    use busbar_contract::RoutingDecision;

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
            status: busbar_substrate::hooks::wire::clamp_reject_status(status),
            message: busbar_substrate::hooks::wire::sanitize_reject_message(&message),
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
///
/// The REFUSE/PROCEED half of this decision is not made here: it is asked of
/// `busbar_substrate::hooks::failed_call_refuses`, the one rule the read-write (transform) seat's
/// decorator also asks. Only the shape of "proceed" is seat-specific — this seat has a candidate
/// set to fall back over, the rewrite seat has a body to leave alone.
pub fn coerce_on_error(
    on_error: &busbar_substrate::config::PolicyOnError,
    candidates: &[busbar_contract::Candidate<'_>],
    policy_name: &'static str,
) -> PolicyOutcome {
    use busbar_substrate::config::PolicyOnError;
    if busbar_substrate::hooks::failed_call_refuses(on_error) {
        return PolicyOutcome::Reject;
    }
    match on_error {
        PolicyOnError::First => PolicyOutcome::Order {
            order: candidates.iter().map(|c| c.idx).collect(),
            name: policy_name,
        },
        // `Weighted` — and `Reject`, which `failed_call_refuses` already took above.
        PolicyOnError::Weighted | PolicyOnError::Reject => PolicyOutcome::Weighted,
    }
}

// The STAGE-tap primitives are NEUTRAL vocabulary that lives in `busbar_substrate::proxy::proxy_vocab`:
// the shape struct, the fire-and-forget tap fan-out, the bounded spawn guard, and the gate-rejection
// marker. Only `capture_stage_shape` below (which reads the request IR to fill the shape) is written
// here, and
// it fills the neutral `StageShape` (its fields are `pub`) across the crate boundary.
//
// WEDGE 3 (THE FLIP): `fire_stage_taps` and `spawn_bounded_tap` now name the NEUTRAL substrate twins
// directly — the wedge-3 forward thread provides the `host: &dyn EngineHost` the substrate
// `fire_stage_taps` reads the group-scope seam through, and unifying the bounded-spawn on the substrate
// `spawn_bounded_tap` keeps stage + global taps (and core's own auth-denial tap) on ONE 1024-permit
// gate. The pre-flip twins beside the retiring router are retired with this flip.
pub use busbar_substrate::proxy::proxy_vocab::{
    fire_stage_taps, gate_rejected, spawn_bounded_tap, GateRejected, StageShape,
};

/// Capture the stage-tap shape from the parsed body. `v == None` is an opaque/binary body (a
/// multipart transcription/speech upload) OR the op-less pre-routing capture: the byte reader
/// projects the former's shape when an operation + bytes are present, and the latter stays zeroed
/// (`operation == None`).
#[allow(clippy::too_many_arguments)]
pub fn capture_stage_shape<'a>(
    v: Option<&Value>,
    body: &[u8],
    content_type: &str,
    pool: &'a str,
    ingress_protocol: &'a str,
    operation: Option<busbar_contract::operation::Operation>,
    stream: bool,
    request_id: u64,
) -> StageShape<'a> {
    // Read through the IR like every other hook projection. A body the reader REFUSES yields the
    // zeroed shape rather than failing anything: a stage tap is fire-and-forget OBSERVATION and can
    // never fail a request. The request itself is still rejected — by the gate/rewrite seams, which
    // read the same IR and do surface the parse failure — so this is not a fail-open hole, it is an
    // observation path declining to invent facts it does not have. `v == None` stands in as
    // `Value::Null` (a non-object body): with an op + bytes the byte reader engages (multipart), and
    // with `operation == None` the seam short-circuits to the zeroed shape before any read.
    let null = Value::Null;
    let shape = read_hook_facts(
        v.unwrap_or(&null),
        body,
        content_type,
        ingress_protocol,
        operation,
    )
    .map(|f| f.shape())
    .unwrap_or(busbar_substrate::ir::facts::Shape::EMPTY);
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

// `fire_stage_taps`, the bounded-tap spawn guard (`spawn_bounded_tap`), the `GateRejected` marker, and
// the `gate_rejected` tagger are NEUTRAL vocabulary; the `StageShape`/`GateRejected`/`gate_rejected`
// trio is named straight off `busbar_substrate::proxy::proxy_vocab` (imported above), while
// `fire_stage_taps`/`spawn_bounded_tap` are named off the same substrate module since wedge 3 (see
// the import note above). The engine names all of them at their historical short paths.
