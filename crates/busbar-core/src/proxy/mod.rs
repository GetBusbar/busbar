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

/// The `application/json` media type — the default `Content-Type`/`Accept` for the JSON REST
/// surfaces. Hoisted to one const so the literal isn't repeated across egress/health/observability.
pub(crate) const APPLICATION_JSON: &str = "application/json";

/// Streaming MIME type for SSE (Server-Sent Events) responses — the `Content-Type` value that
/// signals an open event-stream to the client. Placed next to `APPLICATION_JSON` so all
/// protocol-boundary content-types are declared in one spot.
pub const TEXT_EVENT_STREAM: &str = "text/event-stream";

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
pub(crate) const KIND_API_ERROR: &str = openai_family::ERR_TYPE_API_ERROR;
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

/// Metric-label values for the `disposition` dimension on `UPSTREAM_FAILURES_TOTAL` and the
/// `reason` dimension on `FAILOVERS_TOTAL`.
pub(crate) const DISPOSITION_TRANSIENT: &str = "transient_upstream";
/// A single attempt's budget-clamped transport timeout fired (retryable within the request).
pub(crate) const DISPOSITION_ATTEMPT_TIMEOUT: &str = "attempt_timeout";
pub(crate) const DISPOSITION_HARD_DOWN: &str = "hard_down";
pub(crate) const DISPOSITION_CONTEXT_LENGTH: &str = "context_length";

/// Bounded `pool` metric-label sentinel used for every pre-routing failure (malformed body,
/// unresolved model, governance rejection) so the label space stays finite (metrics.rs).
pub(crate) const POOL_LABEL_UNRESOLVED: &str = "unresolved";

/// Provider error-code token emitted when a request exceeds the model's context-window limit.
/// Returned by `client_fault_kind` for `StatusClass::ContextLength` and drives the per-protocol
/// writer to emit the native context-length error category.
pub const PROVIDER_CODE_CONTEXT_LENGTH: &str = "context_length_exceeded";

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
mod engine;
mod hooks;
mod lazy_body;
mod response_body;
mod select;
pub(crate) mod usage;
mod wire;
pub use egress::*;
pub(crate) use engine::*;
pub(crate) use hooks::*;
pub(crate) use lazy_body::*;
pub(crate) use response_body::*;
pub(crate) use select::*;
pub(crate) use usage::*;
pub(crate) use wire::*;

#[cfg(test)]
#[path = "tests/usage_tap_tests.rs"]
mod usage_tap_tests;

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
#[path = "tests/ordered_walk_tests.rs"]
mod ordered_walk_tests;

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
