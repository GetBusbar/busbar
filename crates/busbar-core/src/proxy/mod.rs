// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::{
    body::Body,
    http::header::{ACCEPT, CONTENT_TYPE, USER_AGENT},
    response::IntoResponse,
    response::Response,
};
use bytes::Bytes;
use futures::Stream;
use reqwest::StatusCode;
use serde_json::Value;

use crate::breaker::{classify as classify_disposition, normalize_raw_error, Disposition};
use crate::config::OnExhausted;
// NOTE THE ABSENCE. This module used to import six `PROTO_*` constants for the hook seam's own
// content flattening. That second implementation is gone: the hook projection reads the IR the
// protocol's own reader produced, so nothing under `proxy/` names a dialect to decide what a
// request SAYS any more.
use crate::proto::{convert_headers, openai_family, StatusClass};
use crate::state::{App, WeightedLane};
use crate::store::{now, Permit};

// NOTE: cross-protocol max-tokens defaulting lives in `IrReq::prepare_for_egress` — the IR owns its
// cross-protocol semantics; the engine is operation-blind. Precedence unit tests drive the IR method.

/// The two `x-busbar-*` TRANSPARENCY response headers stamped when a non-default routing policy
/// chose the target lane: the policy name and the chosen lane's model. Hoisted to consts so the
/// emit site and any future readers cannot drift on spelling.
const HDR_ROUTE_POLICY: &str = "x-busbar-route-policy";
const HDR_ROUTE_TARGET: &str = "x-busbar-route-target";

/// Whether the operator opted in to the `x-busbar-route-policy` / `-target` TRANSPARENCY headers
/// (`advanced.response_headers.route_policy`; default `false`). Set SYNCHRONOUSLY once at
/// boot by [`configure_route_policy_headers`], mirroring `metrics::ENABLED` / `metrics::enabled()`:
/// a settled decision read at every emission site, never rebuilt by a config apply (restart-to-apply,
/// same as `advanced.response_headers.server_timing`). Unset ⇒ `false`: any test or build that never
/// calls `configure_route_policy_headers` has the headers off, matching the documented default.
static ROUTE_POLICY_HEADERS_ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

/// Apply the operator's `advanced.response_headers.route_policy` decision. Called exactly once, at
/// boot, before the router is built (see `main.rs::run`); `OnceLock::set` silently no-ops on any
/// later call, which is fine — the flag is documented restart-to-apply.
pub fn configure_route_policy_headers(enabled: bool) {
    let _ = ROUTE_POLICY_HEADERS_ENABLED.set(enabled);
}

/// Did the operator opt in to the `x-busbar-route-*` headers? Gates
/// [`wire::maybe_attach_route_policy`] — the header is a fingerprintable observable (same class as
/// `Server-Timing: busbar`), so it defaults OFF.
pub(crate) fn route_policy_headers_enabled() -> bool {
    ROUTE_POLICY_HEADERS_ENABLED.get().copied().unwrap_or(false)
}

// APPLICATION_JSON, TEXT_EVENT_STREAM, DISPOSITION_TRANSIENT, POOL_LABEL_UNRESOLVED and
// PROVIDER_CODE_CONTEXT_LENGTH now live in the neutral substrate (busbar_substrate::proxy) so the
// plane crates name them without reaching into busbar-core; re-exported below for core's own
// `crate::proxy::*` call sites.
pub use busbar_substrate::proxy::{
    APPLICATION_JSON, DISPOSITION_TRANSIENT, EGRESS_UA_DEFAULT, POOL_LABEL_UNRESOLVED,
    PROVIDER_CODE_CONTEXT_LENGTH, TEXT_EVENT_STREAM,
};

/// Canonical error-KIND tokens: produced by `cross_protocol_error_kind` / passed to
/// `ingress_error` as the `kind` argument. Each string is the protocol-agnostic discriminant that
/// the per-protocol writer maps to its native error category (e.g. Bedrock `__type`, Gemini
/// `error.status`). Values shared with the OpenAI-family/anthropic/admin vocabularies alias their
/// canonical home in `proto::openai_family`; only the two forward-specific tokens (`overloaded`,
/// `timeout`) are defined here.
pub(crate) const KIND_AUTHENTICATION: &str = openai_family::ERR_TYPE_AUTHENTICATION;
pub(crate) const KIND_PERMISSION: &str = openai_family::ERR_TYPE_PERMISSION;
pub(crate) const KIND_RATE_LIMIT: &str = openai_family::ERR_TYPE_RATE_LIMIT;
pub(crate) const KIND_INVALID_REQUEST: &str = openai_family::ERR_TYPE_INVALID_REQUEST;
pub(crate) const KIND_NOT_FOUND: &str = openai_family::ERR_TYPE_NOT_FOUND;
pub const KIND_API_ERROR: &str = openai_family::ERR_TYPE_API_ERROR;
/// Bare `overloaded` — DELIBERATELY distinct from `openai_family::ERR_TYPE_OVERLOADED`
/// ("overloaded_error", the Anthropic wire spelling): this is busbar's own agnostic kind for a
/// relayed upstream 503.
pub const KIND_OVERLOADED: &str = "overloaded";
/// Bare `timeout` — distinct from the Anthropic wire's `timeout_error` spelling.
pub const KIND_TIMEOUT: &str = "timeout";
pub(crate) const KIND_INSUFFICIENT_QUOTA: &str = openai_family::ERR_TYPE_INSUFFICIENT_QUOTA;
pub const KIND_SERVER_ERROR: &str = openai_family::ERR_TYPE_SERVER_ERROR;
pub(crate) const KIND_REQUEST_TOO_LARGE: &str = openai_family::ERR_TYPE_REQUEST_TOO_LARGE;

/// Network-transient `err_type` values passed to `record_transient_in`.  These are distinct from
/// the error-KIND tokens above: they label the *category* of network failure recorded in the
/// breaker store, not the protocol-level error kind surfaced to the caller.
pub(crate) const ERR_NET_CONNECT: &str = "connect";
pub(crate) const ERR_NET_TIMEOUT: &str = "timeout";
const ERR_NET_TRANSPORT: &str = "transport";
/// `err_type` recorded when a HalfOpen probe's degraded forward returns a non-2xx (bumps cooldown).
const ERR_DEGRADED_NON2XX: &str = "degraded-non2xx";

/// A single attempt's budget-clamped transport timeout fired (retryable within the request).
pub(crate) const DISPOSITION_ATTEMPT_TIMEOUT: &str = "attempt_timeout";
pub(crate) const DISPOSITION_HARD_DOWN: &str = "hard_down";
pub(crate) const DISPOSITION_CONTEXT_LENGTH: &str = "context_length";

tokio::task_local! {
    /// Per-request slot the `server_timing` middleware reads to compute Busbar's INTERNAL
    /// processing time (= total request wall-clock − upstream round-trip), reported as a
    /// `Server-Timing: busbar;dur=<ms>` response header. Set via `.scope()` by the middleware;
    /// written by `record_upstream_rtt` when an upstream call returns. Microseconds; the
    /// `u64::MAX` sentinel means "no upstream hop on this request" (admin/health/early error),
    /// in which case the middleware reports the full request time.
    pub(crate) static UPSTREAM_RTT_US: std::sync::Arc<std::sync::atomic::AtomicU64>;
}

mod egress;
mod egress_client;
mod engine;
mod hooks;
mod lazy_body;
// THE MODEL PLANE'S CONTRIBUTION TO THE ONE AUDIT CHAIN — a record type, nothing more. `pub(crate)`
// because the append happens at the plane's single terminal (`ingress::finish_inner`), which is
// where the plane's metrics and its refund decision are already made.
pub(crate) mod reqlog;
mod response_body;
mod select;
pub(crate) mod usage;
mod wire;
pub use egress::*;
pub(crate) use egress_client::*;
pub(crate) use engine::*;
pub(crate) use hooks::*;
pub use lazy_body::*;
pub(crate) use response_body::*;
pub(crate) use select::*;
pub(crate) use usage::*;
pub use wire::*;

// THE PLANE'S AUDIT CHAIN, DRIVEN THROUGH THE REAL ROUTER. Mounted from the plane rather than from
// `reqlog.rs` (which has its own record-level battery) for the reason the file's header gives: the
// claim is that a CUSTOMER'S REQUEST reaches the chain, and only a test that goes through
// `crate::build_router` and a real socket can see that. A record-level test would pass just as
// happily against a log with no production call site — which is the state this plane was in.
#[cfg(test)]
#[path = "tests/reqlog_dispatch_tests.rs"]
mod reqlog_dispatch_tests;

#[cfg(test)]
#[path = "tests/usage_tap_tests.rs"]
mod usage_tap_tests;

#[cfg(test)]
#[path = "tests/hook_non_chat_projection_tests.rs"]
mod hook_non_chat_projection_tests;

// There is no byte-scanning usage tap to unit-test here: billing sources `IrUsage` directly from the
// per-protocol IR readers, which carry their OWN per-reader usage tests (usage extraction across
// protocols, message_start input-token counting, terminal-error detection, eventstream
// metadata/exception), and the billing-parity tests below cover all four
// {stream,non-stream}×{same,cross} combos end to end.

#[cfg(test)]
#[path = "tests/cross_protocol_extra_tests.rs"]
mod cross_protocol_extra_tests;

#[cfg(test)]
#[path = "tests/bedrock_eventstream_tests.rs"]
mod bedrock_eventstream_tests;

#[cfg(test)]
#[path = "tests/auth_style_tests.rs"]
mod auth_style_tests;

#[cfg(test)]
#[path = "tests/egress_target_tests.rs"]
mod egress_target_tests;

#[cfg(test)]
#[path = "tests/translate_offload_tests.rs"]
mod translate_offload_tests;

#[cfg(test)]
#[path = "tests/attempt_timeout_precedence_tests.rs"]
mod attempt_timeout_precedence_tests;

#[cfg(test)]
#[path = "tests/max_tokens_precedence_tests.rs"]
mod max_tokens_precedence_tests;

#[cfg(test)]
#[path = "tests/on_exhausted_tests.rs"]
mod on_exhausted_tests;

/// REQUEST short-circuit. Proves that a same-protocol passthrough request whose
/// body triggers none of invalidators #1-#4 is re-emitted BYTE-IDENTICAL to the retained original
/// (`hop_bytes`), and that each invalidator individually forces NON-pristine and the correct
/// rewritten bytes. Cross-protocol behaviour is exercised elsewhere; here we pin the same-proto path.
#[cfg(test)]
#[path = "tests/request_short_circuit_tests.rs"]
mod request_short_circuit_tests;

/// BILLING PARITY GATE. Asserts the IR-derived usage (`StreamTranslate::usage()`, the value billing
/// is routed through) produces EXACTLY the billed (input, output) tokens for
/// every {streaming, non-stream} × {same-proto, cross-proto} path. Responses STREAMING is the
/// subtlest case: it nests usage under `response.usage` rather than at the top level, so a reader
/// that looks only at the top level reports 0 and under-bills. The asserted number pins the
/// correctly-nested read.
#[cfg(test)]
#[path = "tests/billing_parity_tests.rs"]
mod billing_parity_tests;

#[cfg(test)]
#[path = "tests/mid_stream_error_tests.rs"]
mod mid_stream_error_tests;

#[cfg(test)]
#[path = "tests/ingress_indistinguishability_tests.rs"]
mod ingress_indistinguishability_tests;

#[cfg(test)]
#[path = "tests/forward_once_pool_cell_tests.rs"]
mod forward_once_pool_cell_tests;

#[cfg(test)]
#[path = "tests/pool_upstream_creds_tests.rs"]
mod pool_upstream_creds_tests;

#[cfg(test)]
#[path = "tests/ordered_walk_tests.rs"]
mod ordered_walk_tests;

#[cfg(test)]
#[path = "tests/reroute_pool_tests.rs"]
mod reroute_pool_tests;

#[cfg(test)]
#[path = "tests/lane_availability_proptest.rs"]
mod lane_availability_proptest;

#[cfg(test)]
#[path = "tests/probe_guard_tests.rs"]
mod probe_guard_tests;

#[cfg(test)]
#[path = "tests/probe_release_owner_tests.rs"]
mod probe_release_owner_tests;

#[cfg(test)]
#[path = "tests/hook_opt_in_projection_tests.rs"]
mod hook_opt_in_projection_tests;

// THE DIFFERENTIAL TEST, INVERTED. It was built to compare the two implementations of "what is the
// text in this request" and it went red on nine fixtures. The second implementation is gone, so the
// same corpus now pins the surviving projection against a golden and re-asserts those nine as the
// behaviour that SHIPPED — which is where the sibling characterisation suite's content went when it
// was retired: a file that pinned "both sides, including where today's behaviour is wrong" has
// nothing left to pin once there is one side.
#[cfg(test)]
#[path = "tests/hook_ir_differential_tests.rs"]
mod hook_ir_differential_tests;

#[cfg(test)]
#[path = "tests/hook_seam_tests.rs"]
mod hook_seam_tests;

#[cfg(test)]
#[path = "tests/ingress_reject_response_tests.rs"]
mod ingress_reject_response_tests;

#[cfg(test)]
#[path = "tests/signal_catalog_tests.rs"]
mod signal_catalog_tests;

/// FAIL-CLOSED multi-candidate / batch-embeddings edge reject. Pins that a cross-protocol request
/// asking for more than one candidate (OpenAI `n` / Gemini `candidateCount`) is REJECTED up front
/// v1.5.4-restored multi-candidate cross-protocol degrade. Pins that a cross-protocol `n>1` /
/// `candidateCount>1` request is FORWARDED and returns the first candidate at HTTP 200 (the
/// single-candidate IR reads candidate `[0]`), not rejected with a 400, while a same-protocol
/// `n>1` request is left untouched (served verbatim, all N preserved). Also pins the multi-input
/// embeddings → Gemini `:embedContent` first-input degrade.
#[cfg(test)]
#[path = "tests/multi_candidate_degrade_tests.rs"]
mod multi_candidate_degrade_tests;

/// v1.5.4-restored stop-sequence-cap cross-protocol degrade. Pins that a cross-protocol request
/// whose stop sequences exceed the egress dialect's published cap (Cohere: 5, Gemini: 5, OpenAI: 4)
/// is CLAMPED to the cap (with a `warn!`) and forwarded at HTTP 200 — not rejected with a 400. A
/// same-protocol request to any of the three is left untouched (served verbatim), leaving the cap
/// to that vendor's own native 400.
#[cfg(test)]
#[path = "tests/stop_sequence_cap_degrade_tests.rs"]
mod stop_sequence_cap_degrade_tests;

/// AUDIT-AND-ALLOW for the two cross-dialect egress controls with no native target representation
/// (`response_format`, `tool_choice:none`): the request still forwards, but each drop is recorded as
/// a first-class `egress.control_unrepresentable` / `degraded` audit event, not just a `warn!`.
#[cfg(test)]
#[path = "tests/egress_dropped_controls_audit_tests.rs"]
mod egress_dropped_controls_audit_tests;

/// THE EGRESS DIFFERENTIAL HARNESS: both outbound stacks (the owned hyper engine and the pinned
/// reqwest client) driven against the same recording fixtures, their observable outcomes —
/// status, body, observed peer SPKI, error CLASS — compared row by row. This is the gate every
/// step of the one-egress-stack migration re-runs; the fixtures live in
/// `busbar_substrate::egress::fixtures` so the substrate engine tests drive the same servers.
#[cfg(test)]
#[path = "tests/egress_differential_tests.rs"]
mod egress_differential_tests;

/// THE ALLOCATION-COUNT PERF GATE (deterministic CI perf-regression gate). Drives one openai>openai
/// passthrough request through the real forward path and asserts the per-request heap-allocation
/// count has not regressed past a committed bound — so a stray per-request allocation (the "FIX-9"
/// class: a redundant `Box::new` on the hot path, e.g. re-resolving `decl_for(..).dialect()` a
/// second time) turns CI red. Machine-independent + fast, unlike a wall-clock RPS gate. jemalloc-
/// only (`not(target_env = "msvc")`), the same target guard the telemetry-counter tests carry.
#[cfg(all(test, not(target_env = "msvc")))]
#[path = "tests/alloc_gate.rs"]
mod alloc_gate;
