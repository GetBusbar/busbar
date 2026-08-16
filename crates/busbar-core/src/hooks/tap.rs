// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE REQUEST TAP, FIRED FROM ANY PROTOCOL — the OBSERVE twin of [`crate::hooks::gate::decide`],
//! over the same subject, the same projection and the same wire.
//!
//! # The cells this closes, and the belief that kept them open
//!
//! `hooks-tap x {mcp-client, mcp-server, a2a-client, a2a-server}` were four `missing` cells in
//! `qa/capability-equality.json`, and the recorded reason was a design one rather than an oversight:
//! *"tap/rewrite is structurally LLM-shaped ... no external protocol plugin could ever reach
//! hooks-tap, because the payload contract is a chat body."*
//!
//! **That is true of the REWRITE verb and false of this one.** A rewrite REPLACES a body, and its
//! reply type is `{messages, tools}` — a chat body, which genuinely cannot express *"replace this
//! invocation's `arguments`"*, so extending it is a wire-contract change and is recorded as owed
//! work, not as an inapplicable cell. An OBSERVATION only has to PRESENT a request, and
//! [`crate::ir::facts::IrFacts`] is that presentation: the family-blind seam every protocol already
//! implements and which [`crate::hooks::gate`] has carried MCP tool calls and A2A submissions
//! through since it landed. The tap needed no new payload contract. It needed a firing site.
//!
//! # What a tap is sent, and why it is byte-identical to what the gate is sent
//!
//! [`crate::hooks::subject::project`], the same function, behind each tap's own `prompt:` grant.
//! Two projections at most (shape-only and with-prompt) regardless of tap count, exactly as
//! `proxy::engine::fire_global_taps` builds them for the model plane. A tap shown a DIFFERENT
//! projection from the gate would be an audit record of something other than what was screened —
//! and an audit tap that disagrees with the screen is worse than no audit tap.
//!
//! `identity` is absent (`send_user: false`), which is parity with the model plane's tap and not an
//! omission here: `TapEntry` carries only the prompt grant, so there is no `user: ro` grant on a tap
//! to honour and projecting the caller's key off the back of a different grant would be a
//! disclosure the operator never made.
//!
//! # Fire-and-forget, and what that costs the request
//!
//! Nothing, by construction. Each tap is spawned detached through
//! [`spawn_bounded_tap`] — the same bounded gate the model plane's taps go
//! through, so a slow or unreachable tap endpoint cannot accumulate tasks — and its reply is never
//! read. A tap can never delay, reorder or fail the request it observes. ZERO COST when nothing is
//! attached: the empty-slice early return happens before any content walk.

use crate::hooks::subject::{project, RequestSubject};
use crate::hooks::{RoutingContext, TapEntry};

/// FIRE the request-stage taps over this request, fire-and-forget.
///
/// `caller_group` / `groups_tree` are the 1.5.3 SELECTION axis, applied exactly as the model plane
/// applies it: a tap fires for this caller iff its `groups:` scope admits it (an empty scope admits
/// everyone). Passing the caller's own group rather than `None` is what stops a scoped audit tap
/// from being silently plane-dependent.
pub(crate) fn fire(
    taps: &[TapEntry],
    subject: &RequestSubject<'_>,
    caller_group: Option<&str>,
    groups_tree: &std::collections::BTreeMap<String, crate::config::GroupCfg>,
) {
    if taps.is_empty() {
        return;
    }
    let fires =
        |groups: &[String]| crate::config::caller_in_hook_groups(caller_group, groups, groups_tree);
    // The content items are materialised ONCE and borrowed by both projections: the walk is over the
    // IR and cannot differ between taps. Same argument as `gate::decide`'s single walk.
    let items = subject.facts.content();
    let ctx = RoutingContext {
        pool: subject.container,
        // No pool-scoped budget signal on these planes — the same fact `gate::decide` records: the
        // budget a request here spends is the caller key's, metered by the plane's own admission.
        budget_remaining: None,
        budget: &[],
    };
    let build = |with_prompt: bool| {
        // `send_user: false` — see the module header. A tap grant is a prompt grant only.
        let req = project(subject, &items, with_prompt, false);
        crate::json::to_vec(&crate::hooks::wire::build(
            crate::hooks::wire::OP_NOTIFY,
            &req,
            &[],
            &ctx,
        ))
        .ok()
        .map(std::sync::Arc::new)
    };
    // Build each bucket at most once, and only if a tap that will actually FIRE wants it. A tap
    // filtered out by its caller-group scope is not counted: it will not fire, so its projection
    // need not be built.
    let any_prompt = taps
        .iter()
        .any(|(_, send_prompt, _, groups)| *send_prompt && fires(groups));
    let any_shape = taps
        .iter()
        .any(|(_, send_prompt, _, groups)| !*send_prompt && fires(groups));
    let shape_proj = if any_shape { build(false) } else { None };
    let prompt_proj = if any_prompt { build(true) } else { None };
    for (timeout, send_prompt, hook, groups) in taps {
        if !fires(groups) {
            continue;
        }
        // A granted tap prefers the prompt projection and falls back to shape-only if that failed to
        // serialize: never over-share, always the safe direction.
        let proj = if *send_prompt {
            prompt_proj.clone().or_else(|| shape_proj.clone())
        } else {
            shape_proj.clone()
        };
        if let Some(proj) = proj {
            let policy = hook.clone();
            let budget = *timeout;
            spawn_bounded_tap(async move { policy.notify(&proj, budget).await });
        }
    }
}

/// Hard cap on concurrently in-flight fire-and-forget tap notifications. Taps fan out per stage x per
/// tap hook x per request, so a slow/unreachable tap endpoint could otherwise accumulate unbounded
/// Tokio tasks under load (OOM/DoS). Mirrors the bounded webhook-delivery guard in `observability`.
const MAX_INFLIGHT_TAP_NOTIFICATIONS: usize = 1024;
static TAP_INFLIGHT: std::sync::OnceLock<crate::limits::admission::AdmissionGate> =
    std::sync::OnceLock::new();
fn tap_inflight() -> &'static crate::limits::admission::AdmissionGate {
    TAP_INFLIGHT.get_or_init(|| {
        crate::limits::admission::AdmissionGate::new(MAX_INFLIGHT_TAP_NOTIFICATIONS, "tap")
    })
}

/// Spawn a bounded fire-and-forget tap notification: at most MAX_INFLIGHT_TAP_NOTIFICATIONS run
/// concurrently; when saturated the notification is dropped (metric) instead of accumulating tasks.
/// The owned permit rides straight into the spawned task, so the slot is returned (by the permit's
/// own `Drop`) even on a task panic.
pub(crate) fn spawn_bounded_tap<F>(fut: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let Some(permit) = tap_inflight().try_enter() else {
        metrics::counter!(crate::metrics::TAP_NOTIFICATIONS_DROPPED_TOTAL).increment(1);
        return;
    };
    tokio::spawn(async move {
        let _permit = permit;
        fut.await;
    });
}
