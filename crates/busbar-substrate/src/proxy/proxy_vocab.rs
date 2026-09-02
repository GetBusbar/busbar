// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The NEUTRAL stage-tap fan-out vocabulary (App-retype WEDGE 2e). The per-request shape capture
//! [`StageShape`], the fire-and-forget stage-tap fan-out [`fire_stage_taps`], the bounded spawn guard
//! [`spawn_bounded_tap`], and the [`GateRejected`] rejection marker are all dialect-blind: they name
//! no dialect and touch no `busbar-core` type, so a plane crate fires stage taps through this seam
//! without reaching BACK into core.
//!
//! Relocated DOWN off `busbar_core::proxy::proxy_vocab` so the residual `busbar-llm` request path
//! names them at `busbar_substrate::proxy::proxy_vocab::*`; core re-exports each at its historical
//! `busbar_core::proxy::*` path (identity), so every in-core call site is unchanged.
//!
//! [`fire_stage_taps`] here reads the caller's `groups:` scope through the neutral
//! [`EngineHost::caller_in_hook_groups`](crate::plane_host::EngineHost::caller_in_hook_groups) seam
//! instead of walking the raw `&App::groups_registry` tree — byte-behavior-identical to core's
//! version (the host seam folds `&App::groups_registry` in and performs the SAME self+ancestors walk),
//! so a group-scoped tap fires for an in-group caller and NOT for an out-of-group one exactly as
//! before. Core's `proxy_vocab::fire_stage_taps` (the `groups_tree`-taking twin) stays until wedge 3
//! threads the host through the forward loop and flips the pipeline call sites onto this version.

use axum::response::Response;

/// Shape scalars captured ONCE per request for the STAGE tap payloads (candidate/routing/response).
/// All owned/`'static`-free scalars except the pool/protocol names (which outlive the request), so
/// the capture survives `v` being consumed by the first dispatch hop. Stage taps are SHAPE-ONLY in
/// this increment: the default signal bucket plus the stage object — never prompt content or caller
/// identity, regardless of grant.
///
/// Fields are `pub` so the relocated engine's `capture_stage_shape` (which reads the IR to fill them)
/// builds the shape across the crate boundary, and core's own auth-denial tap builds the zeroed shape
/// directly via [`StageShape::zeroed`].
pub struct StageShape<'a> {
    /// The request correlation id (`RequestCtx::request_id`) — carried on the shape so every stage
    /// tap notification for this request stamps the SAME join-key value a `decide`/`transform`
    /// payload for the same request carries.
    pub request_id: u64,
    pub pool: &'a str,
    pub ingress_protocol: &'a str,
    pub message_count: usize,
    pub has_tools: bool,
    pub total_chars: usize,
    pub max_tokens: Option<u32>,
    pub stream: bool,
}

impl<'a> StageShape<'a> {
    /// The ZEROED shape: the default signal bucket for a request with no readable body / no resolved
    /// operation (a pre-routing auth denial). Only the correlation id and the pool/protocol labels are
    /// carried; every shape scalar is its empty default.
    pub fn zeroed(
        request_id: u64,
        pool: &'a str,
        ingress_protocol: &'a str,
        stream: bool,
    ) -> StageShape<'a> {
        StageShape {
            request_id,
            pool,
            ingress_protocol,
            message_count: 0,
            has_tools: false,
            total_chars: 0,
            max_tokens: None,
            stream,
        }
    }
}

/// Fire one STAGE's taps (candidate/routing/response) fire-and-forget: serialize the shape-only
/// projection + stage object ONCE, then spawn one detached task per tap. A tap can never delay,
/// reorder, or fail the request; a serialization failure silently skips the fire (observation is
/// best-effort). ZERO COST when the stage has no taps (first-line empty check).
///
/// WEDGE 2e: the neutral, host-taking twin of core's `proxy_vocab::fire_stage_taps`. The caller passes
/// the stage's tap slice (in wedge 3, one of `host.tap_hooks_response()`/`_routing()`/`_candidate()`)
/// and the `host`; each tap's `groups:` scope is honored via
/// [`host.caller_in_hook_groups`](crate::plane_host::EngineHost::caller_in_hook_groups) — the neutral
/// fold of the `&App::groups_registry` self+ancestors walk — so this is byte-behavior-identical to
/// core's raw-tree-walk version.
pub fn fire_stage_taps(
    taps: &[crate::hooks::TapEntry],
    shape: &StageShape<'_>,
    stage: crate::hooks::wire::HookStageProjection<'_>,
    // The caller's `groups:` binding: a stage tap fires only for a caller in its `groups:` scope
    // (empty = every caller). Resolved against this deployment's group registry through the host seam
    // (self + ancestors), never a raw `&App::groups_registry` tree.
    caller_group: Option<&str>,
    host: &dyn crate::plane_host::EngineHost,
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
            // pass. Empty (never allocated), so the wire is byte-identical to before this change.
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
        // SELECTION: skip a stage tap whose `groups:` scope does not admit this caller. The host seam
        // performs the SAME self+ancestors registry walk core's `caller_in_hook_groups` free fn does.
        if !host.caller_in_hook_groups(caller_group, groups) {
            continue;
        }
        let policy = hook.clone();
        let budget = *timeout;
        let proj = bytes.clone();
        spawn_bounded_tap(async move { policy.notify(&proj, budget).await });
    }
}

/// Hard cap on concurrently in-flight fire-and-forget tap notifications. Taps fan out per stage x per
/// tap hook x per request, so a slow/unreachable tap endpoint could otherwise accumulate unbounded
/// Tokio tasks under load (OOM/DoS). Mirrors the bounded webhook-delivery guard in `observability`.
const MAX_INFLIGHT_TAP_NOTIFICATIONS: usize = 1024;
static TAP_INFLIGHT: std::sync::OnceLock<std::sync::Arc<tokio::sync::Semaphore>> =
    std::sync::OnceLock::new();
fn tap_inflight() -> &'static std::sync::Arc<tokio::sync::Semaphore> {
    TAP_INFLIGHT.get_or_init(|| {
        std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_INFLIGHT_TAP_NOTIFICATIONS))
    })
}

/// Spawn a bounded fire-and-forget tap notification: at most MAX_INFLIGHT_TAP_NOTIFICATIONS run
/// concurrently; when saturated the notification is dropped (metric) instead of accumulating tasks.
/// The owned permit rides straight into the spawned task, so the slot is returned (by the permit's
/// own `Drop`) even on a task panic.
///
/// WEDGE 2e: the neutral twin of core's `proxy_vocab::spawn_bounded_tap`. The `1024`-permit cap and
/// the two saturation metrics (`busbar_tap_notifications_dropped_total` plus the shared
/// `busbar_admission_denied_total{gate="tap"}` denial counter core's `AdmissionGate` emits) are
/// replicated exactly so the bounded-spawn behavior is byte-identical to core's.
pub fn spawn_bounded_tap<F>(fut: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let Ok(permit) = tap_inflight().clone().try_acquire_owned() else {
        // Saturated: replicate BOTH counters core's `AdmissionGate::try_enter` + `spawn_bounded_tap`
        // emit on a dropped tap, so the operator's pressure signal is byte-identical after the move.
        metrics::counter!(TAP_NOTIFICATIONS_DROPPED_TOTAL).increment(1);
        metrics::counter!(ADMISSION_DENIED_TOTAL, "gate" => TAP_GATE_NAME).increment(1);
        return;
    };
    crate::detached::spawn_detached(async move {
        let _permit = permit;
        fut.await;
    });
}

/// The `gate` metric-label value for the tap-admission gate, matching core's `AdmissionGate::new(_,
/// "tap")` name so `busbar_admission_denied_total{gate="tap"}` is one series across the move.
const TAP_GATE_NAME: &str = "tap";
/// Metric names — byte-identical to core's `metrics::{TAP_NOTIFICATIONS_DROPPED_TOTAL,
/// ADMISSION_DENIED_TOTAL}` (those stay in core for its own gates; the strings are pinned equal here).
const TAP_NOTIFICATIONS_DROPPED_TOTAL: &str = "busbar_tap_notifications_dropped_total";
const ADMISSION_DENIED_TOTAL: &str = "busbar_admission_denied_total";

/// Response-extension marker set by every GATE-produced rejection return, so the response-stage
/// taps can report the SYNTHETIC `rejected_by_gate` outcome (audit taps see denials) instead of a
/// generic `failed`.
#[derive(Clone)]
pub struct GateRejected;

/// Tag a gate-produced rejection response with the [`GateRejected`] marker.
pub fn gate_rejected(mut resp: Response) -> Response {
    resp.extensions_mut().insert(GateRejected);
    resp
}
