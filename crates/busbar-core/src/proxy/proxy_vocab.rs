// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The NEUTRAL proxy vocabulary that STAYS in `busbar-core` once the LLM engine moves to the
//! `busbar-llm` plane (1.6.0 money-path Phase 3-4 C). Everything here is dialect-blind: the capped
//! upstream-body read, the tight upstream-buffer cap, the hook-content ceiling knob, the fire-and-
//! forget STAGE usage-tap primitives, and the agnostic ingress-error shaper. Core's own staying call
//! sites (`egress_auth`, `egress::seam`, `preflight`, `auth`, `config`, `appbuild`) name these at
//! their historical `crate::proxy::*` paths (re-exported from `proxy/mod.rs`), and the relocated
//! engine names them across the crate boundary as `busbar_core::proxy::*` — neither reaches for a
//! dialect, so the plane can be dropped from the build without taking any of this with it.

use axum::{
    body::Body,
    http::header::CONTENT_TYPE,
    response::{IntoResponse, Response},
};
use http::StatusCode;

use crate::proxy::APPLICATION_JSON;

// THE CAPPED READ and its `ReadEnd` outcome live in the neutral `busbar-substrate` crate (both
// core's egress/auth paths and the relocated proxy engine read upstream bodies this way, and a plane
// crate names them without reaching into core). Re-exported here so every core `crate::proxy::{
// read_capped, ReadEnd}` call site resolves unchanged.
pub use busbar_substrate::proxy::{read_capped, ReadEnd};

/// Upper bound on a buffered UPSTREAM ERROR body (4xx/5xx envelopes). Operator-tunable via
/// `limits.upstream_error_body_max_bytes` (defaults to 256 KiB). A function (not a `const`) so the
/// process-wide installed value is read at each use site; falls back to the historical default when
/// the limits aren't installed (e.g. unit tests).
pub fn max_upstream_buffered_bytes() -> usize {
    crate::limits::upstream_error_body_max_bytes()
}

/// The DEFAULT ceiling, in bytes, on the content a hook is shown in one projection.
///
/// `0` = UNLIMITED (the default): the LLM prompt projection is sent UNCAPPED, byte-for-byte as
/// v1.5.4 did. A non-zero ceiling is an OPT-IN an operator sets via `limits.hook_content_max_bytes`.
pub const DEFAULT_HOOK_CONTENT_MAX_BYTES: usize = 0;

/// The effective content ceiling for this config generation, resolved once at config apply
/// (`limits.hook_content_max_bytes`) and read with a single relaxed load — never recomputed per
/// request.
static HOOK_CONTENT_MAX_BYTES: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(DEFAULT_HOOK_CONTENT_MAX_BYTES);

/// Install the generation's content ceiling. Called at boot and on every config apply.
pub fn set_hook_content_max_bytes(bytes: usize) {
    HOOK_CONTENT_MAX_BYTES.store(bytes, std::sync::atomic::Ordering::Relaxed);
}

/// Read the generation's content ceiling. `0` = UNLIMITED. Named across the crate boundary by the
/// relocated hook-projection enforcer, which caps SERIALIZED BYTES against this value.
pub fn hook_content_max_bytes() -> usize {
    HOOK_CONTENT_MAX_BYTES.load(std::sync::atomic::Ordering::Relaxed)
}

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
pub fn fire_stage_taps(
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
        // SELECTION: skip a stage tap whose `groups:` scope does not admit this caller.
        if !crate::config::caller_in_hook_groups(caller_group, groups, groups_tree) {
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
pub fn spawn_bounded_tap<F>(fut: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let Some(permit) = tap_inflight().try_enter() else {
        metrics::counter!(crate::metrics::TAP_NOTIFICATIONS_DROPPED_TOTAL).increment(1);
        return;
    };
    crate::state::spawn_detached(async move {
        let _permit = permit;
        fut.await;
    });
}

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

/// The agnostic ingress-error shaper: project a `(status, kind, msg)` into the caller-dialect error
/// response, attaching the protocol-appropriate headers via the resolved writer vtable. When
/// `ingress` resolves to no protocol the body is core's OWN [`agnostic_error_envelope`] and no
/// protocol headers are attached — the shape that survives every LLM dialect being dropped with the
/// `busbar-llm` plane. `crate::proto::decl_for` names no dialect literally; it reads whatever
/// registry the resident planes populated.
pub fn ingress_error(ingress: &str, status: StatusCode, kind: &str, msg: &str) -> Response {
    let dialect = crate::proto::decl_for(ingress).and_then(|d| d.dialect());
    let envelope = match &dialect {
        Some(di) => di.write_error(status.as_u16(), kind, msg),
        None => agnostic_error_envelope(kind, msg),
    };
    let body = crate::json::to_string(&envelope)
        .unwrap_or_else(|_| agnostic_error_envelope(kind, msg).to_string());
    let mut resp = Response::builder()
        .status(status)
        .header(CONTENT_TYPE, APPLICATION_JSON)
        .body(Body::from(body))
        .unwrap_or_else(|_| status.into_response());
    if let Some(di) = &dialect {
        di.attach_error_response_headers(resp.headers_mut(), kind, &envelope);
    }
    resp
}

/// CORE'S OWN ERROR ENVELOPE — the body for an ingress name that resolves to no protocol. The
/// plainest `{"error": {"message", "type"}}` object, stated ONCE here so the spellings cannot drift,
/// and core's, so it survives every LLM dialect being dropped from the build.
pub fn agnostic_error_envelope(kind: &str, msg: &str) -> serde_json::Value {
    serde_json::json!({ "error": { "message": msg, "type": kind } })
}
