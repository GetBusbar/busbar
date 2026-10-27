// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STAGE TAPS — the hook kind's fire-and-forget notifications at a unit's candidate, routing and
//! response stages: the shape-only view a stage tap is shown ([`StageShape`]), the fan-out that
//! honours each tap's `groups:` scope ([`fire_stage_taps_where`]), and the one bounded spawn every
//! tap rides ([`spawn_bounded_tap`]), with its 1024-permit cap and saturation counters.
//!
//! Kind-level: a stage tap sees the 1.5.5 hook wire's shape fields (`busbar_contract::hooks`), the
//! same for every plane, never content or identity.

/// Shape scalars captured ONCE per request for the STAGE tap payloads (candidate/routing/response).
/// All owned/`'static`-free scalars except the pool/protocol names (which outlive the request), so
/// the capture survives `v` being consumed by the first dispatch hop. Stage taps are SHAPE-ONLY in
/// this increment: the default signal bucket plus the stage object — never prompt content or caller
/// identity, regardless of grant.
///
/// Fields are `pub` so a stage's caller fills them, and the auth-denial tap builds the zeroed shape
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

/// Fire one STAGE's taps (candidate/routing/response) fire-and-forget: build the shape-only tap
/// view + stage ONCE, then spawn one detached task per tap whose `groups:` scope `fires` admits. A
/// tap can never delay, reorder, or fail the request. ZERO COST when the stage has no taps
/// (first-line empty check). The ONE stage-tap fire, for the plane driver and the auth-denial tap
/// alike.
pub fn fire_stage_taps_where(
    taps: &[crate::hooks::TapEntry],
    shape: &StageShape<'_>,
    stage: busbar_contract::hook_wire::HookStageProjection<'_>,
    signals: busbar_contract::signal::SignalBag,
    fires: &dyn Fn(&[String]) -> bool,
) {
    if taps.is_empty() {
        return;
    }
    // The stage's tap view, built ONCE (shape only: a stage tap never sees the prompt) and shared
    // by every tap this stage fires.
    let req = busbar_contract::hooks::RoutingRequest {
        request_id: shape.request_id,
        pool: shape.pool,
        ingress_protocol: shape.ingress_protocol,
        requested_model: None,
        message_count: shape.message_count,
        tool_count: 0,
        has_tools: shape.has_tools,
        total_chars: shape.total_chars,
        system_chars: 0,
        max_tokens: shape.max_tokens,
        stream: shape.stream,
        prompt: None,
        identity: None,
        signals,
        session: None,
    };
    let tap = busbar_contract::abi::host::hook::NotifyFrame::build(&req, Some(&stage), false);
    for (timeout, _send_prompt, hook, groups) in taps {
        // SELECTION: skip a stage tap whose `groups:` scope does not admit this caller (the host
        // seam performs the SAME self+ancestors registry walk `caller_in_hook_groups` does).
        if !fires(groups) {
            continue;
        }
        let policy = hook.clone();
        let budget = *timeout;
        let tap = tap.clone();
        spawn_bounded_tap(async move { policy.notify(tap, budget).await });
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
/// The `1024`-permit cap and the two saturation metrics (`busbar_tap_notifications_dropped_total` plus
/// the shared `busbar_admission_denied_total{gate="tap"}` denial counter `AdmissionGate` emits) are
/// the one tap gate every stage tap shares.
pub fn spawn_bounded_tap<F>(fut: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let Ok(permit) = tap_inflight().clone().try_acquire_owned() else {
        // Saturated: BOTH counters `AdmissionGate::try_enter` emits on a dropped tap.
        metrics::counter!(TAP_NOTIFICATIONS_DROPPED_TOTAL).increment(1);
        metrics::counter!(crate::snapshot::ADMISSION_DENIED_TOTAL, "gate" => TAP_GATE_NAME)
            .increment(1);
        return;
    };
    crate::detached::spawn_detached(async move {
        let _permit = permit;
        fut.await;
    });
}

/// The `gate` metric-label value for the tap-admission gate, matching `AdmissionGate::new(_,
/// "tap")` name so `busbar_admission_denied_total{gate="tap"}` is one series across the move.
const TAP_GATE_NAME: &str = "tap";
/// Metric name — byte-identical to the kernel's `TAP_NOTIFICATIONS_DROPPED_TOTAL` series (the
/// string is pinned equal here).
const TAP_NOTIFICATIONS_DROPPED_TOTAL: &str = "busbar_tap_notifications_dropped_total";
