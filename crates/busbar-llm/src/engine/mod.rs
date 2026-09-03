// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LLM MONEY-PATH ENGINE, relocated from busbar-core (1.6.0 money-path Phase 3-4 C — THE PIVOT).
//!
//! The pool/lane/failover/egress routing tables ([`tables`]), the egress pipeline
//! ([`pipeline`]/[`walk`]/[`select`]/[`wire`]/[`egress`]/[`response_body`]/[`lazy_body`]/[`usage`]/
//! [`hooks`]), the active-probe health loop ([`health`]) and the native fallback plane now live in the
//! plane crate. Core is a plane-agnostic router: it reaches these only through the neutral
//! `busbar_substrate::plane_host::EngineTablesView` seam and the fallback plane decl's `build_runtime`
//! / `viewer` fn-pointers. This engine calls DOWN into core (`busbar_core::…`) — the allowed plane→core
//! edge.

// THE ENGINE PRELUDE — the successor to core `proxy/mod.rs`'s top-level `use` block. Every engine
// submodule opens with `use super::*`, and (Rust's descendant-visibility rule) inherits these
// private `use` bindings through it, so the moved call sites keep naming `StatusCode`/`Bytes`/
// `Value`/`Disposition`/`OnExhausted`/`StatusClass`/`App`/`now`/`Permit`/… at their historical short
// paths. The core-staying items are named DOWN across the crate boundary (the allowed plane→core
// edge); the relocated `WeightedLane`/`Lane`/… come from the submodule globs below.
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
use http::StatusCode;
use serde_json::Value;

#[cfg_attr(not(test), allow(unused_imports))]
use busbar_substrate::breaker::StatusClass;
use busbar_substrate::breaker::{
    classify as classify_disposition, normalize_raw_error, Disposition,
};
use busbar_substrate::plane_host::OnExhaustedInput as OnExhausted;
use busbar_substrate::proto::convert_headers;
// App-retype WEDGE 3 (THE FLIP): the engine no longer names `busbar_core::state::App`. The forward
// path threads the neutral `host: &Arc<dyn EngineHost>` (minted core-side, carried on the arrival) and
// the plane's own `rt: &Arc<NativeRuntime>` (resolved off the host slot) instead. Every `app.X` reach
// flipped to the host seam (`host.X()`) or the runtime tables (`EngineTables::new(rt)`).
use busbar_substrate::plane_host::EngineHost;
use busbar_substrate::store::{now, Permit};

pub(crate) mod build_runtime;
pub(crate) mod tables;

pub(crate) mod egress;
pub(crate) mod health;
pub(crate) mod hooks;
pub(crate) mod lazy_body;
pub(crate) mod pipeline;
pub(crate) mod response_body;
pub(crate) mod select;
pub(crate) mod usage;
pub(crate) mod walk;
pub(crate) mod wire;

// The flattened engine namespace — the successor to core `proxy/mod.rs`'s `pub(crate) use <mod>::*`
// unification, so intra-engine `crate::engine::<symbol>` paths resolve regardless of which submodule
// defines the symbol.
pub(crate) use egress::*;
pub(crate) use hooks::*;
pub(crate) use lazy_body::*;
pub(crate) use pipeline::*;
pub(crate) use response_body::*;
pub(crate) use select::*;
pub(crate) use tables::*;
pub(crate) use usage::*;
pub(crate) use walk::*;
pub(crate) use wire::*;

// NEUTRAL route-policy vocabulary that STAYS in core: the `x-busbar-route-*` response-header names,
// the operator opt-in gate, and the per-request upstream-RTT task-local the router reads. Re-exported
// into the flattened engine namespace so the relocated wire/pipeline call sites keep naming them at
// their historical short paths (`crate::engine::{route_policy_headers_enabled, HDR_ROUTE_POLICY,
// HDR_ROUTE_TARGET, UPSTREAM_RTT_US}`).
pub(crate) use busbar_substrate::proxy::{
    route_policy_headers_enabled, HDR_ROUTE_POLICY, HDR_ROUTE_TARGET, UPSTREAM_RTT_US,
};

// NEUTRAL egress-engine primitives the pipeline drives. Named at their TRUE substrate home
// (`busbar_substrate::egress::engine`) — core merely re-exports these verbatim, so the plane names the
// neutral ABI crate directly rather than reaching backwards through `busbar_core::proxy`. The
// historical `EgressClientSpec`/`EgressError` short names are preserved via the same aliases core used.
#[cfg_attr(not(test), allow(unused_imports))]
pub(crate) use busbar_substrate::egress::engine::{
    egress_request, install_proxy_tunnel_if_configured, EngineError as EgressError,
    EngineSpec as EgressClientSpec,
};

// The NEUTRAL content-type / disposition / error-KIND vocabulary named at its TRUE substrate home
// (`busbar_substrate::proxy`) — the plane names the neutral ABI crate directly. Re-exported into the
// flattened engine namespace so the moved classification/error-envelope call sites keep naming them at
// their historical short paths (`crate::engine::{KIND_*, DISPOSITION_TRANSIENT, APPLICATION_JSON, …}`).
pub(crate) use busbar_substrate::proxy::{
    APPLICATION_JSON, EGRESS_UA_DEFAULT, POOL_LABEL_UNRESOLVED, PROVIDER_CODE_CONTEXT_LENGTH,
    TEXT_EVENT_STREAM,
};
#[cfg_attr(not(test), allow(unused_imports))]
pub(crate) use busbar_substrate::proxy::{
    DISPOSITION_ATTEMPT_TIMEOUT, DISPOSITION_CONTEXT_LENGTH, DISPOSITION_HARD_DOWN,
    DISPOSITION_TRANSIENT, ERR_DEGRADED_NON2XX, ERR_NET_CONNECT, ERR_NET_TIMEOUT,
    ERR_NET_TRANSPORT, KIND_API_ERROR, KIND_AUTHENTICATION, KIND_INSUFFICIENT_QUOTA,
    KIND_INVALID_REQUEST, KIND_NOT_FOUND, KIND_OVERLOADED, KIND_PERMISSION, KIND_RATE_LIMIT,
    KIND_TIMEOUT,
};
// The NEUTRAL hook-content ceiling knob + the egress-client builder now live in the neutral substrate
// (`busbar_substrate::proxy`) — re-exported into the flattened engine namespace so the relocated tests
// (which named them at `proxy::…`) keep resolving at `crate::engine::…`.
#[cfg_attr(not(test), allow(unused_imports))]
pub(crate) use busbar_substrate::proxy::{
    build_egress_client, set_hook_content_max_bytes, DEFAULT_HOOK_CONTENT_MAX_BYTES,
};

// ── THE MONEY-PATH ENGINE TESTS ──────────────────────────────────────────────────────────────────
// Relocated from core `proxy/mod.rs` WITH the engine they drive (money-path Phase 3-4 C). Declared
// here under `engine/` (`#[path]` relative to this dir → `tests/…`); `super::*` in each file
// resolves against the flattened engine namespace globbed above, exactly as `proxy::*` used to. The
// per-submodule tests (`lazy_body_tests`, `wire_tests`) stay declared in their own modules; the four
// engine-level tests (`inject_include_usage_tests`, `crossproto_delivery_billing_tests`,
// `send_envelope_tests`, `future_size_probe`) are declared in `pipeline.rs` under `engine_tests/`.
#[cfg(test)]
#[path = "tests/attempt_timeout_precedence_tests.rs"]
mod attempt_timeout_precedence_tests;
#[cfg(test)]
#[path = "tests/auth_dispatch_tests.rs"]
mod auth_dispatch_tests;
#[cfg(test)]
#[path = "tests/auth_style_tests.rs"]
mod auth_style_tests;
#[cfg(test)]
#[path = "tests/client_header_forwarding_tests.rs"]
mod client_header_forwarding_tests;
#[cfg(test)]
#[path = "tests/egress_differential_tests.rs"]
mod egress_differential_tests;
#[cfg(test)]
#[path = "tests/egress_dropped_controls_audit_tests.rs"]
mod egress_dropped_controls_audit_tests;
#[cfg(test)]
#[path = "tests/egress_target_tests.rs"]
mod egress_target_tests;
#[cfg(test)]
#[path = "tests/engine_identity_witness_tests.rs"]
mod engine_identity_witness_tests;
#[cfg(test)]
#[path = "tests/forward_once_pool_cell_tests.rs"]
mod forward_once_pool_cell_tests;
#[cfg(test)]
#[path = "tests/forward_pool_integration_tests.rs"]
mod forward_pool_integration_tests;
#[cfg(test)]
#[path = "tests/hook_non_chat_projection_tests.rs"]
mod hook_non_chat_projection_tests;
#[cfg(test)]
#[path = "tests/hook_opt_in_projection_tests.rs"]
mod hook_opt_in_projection_tests;
#[cfg(test)]
#[path = "tests/hook_seam_tests.rs"]
mod hook_seam_tests;
#[cfg(test)]
#[path = "tests/ingress_indistinguishability_tests.rs"]
mod ingress_indistinguishability_tests;
#[cfg(test)]
#[path = "tests/ingress_integration_tests.rs"]
mod ingress_integration_tests;
#[cfg(test)]
#[path = "tests/ingress_reject_response_tests.rs"]
mod ingress_reject_response_tests;
#[cfg(test)]
#[path = "tests/lane_availability_proptest_tests.rs"]
mod lane_availability_proptest;
#[cfg(test)]
#[path = "tests/mid_stream_error_tests.rs"]
mod mid_stream_error_tests;
#[cfg(test)]
#[path = "tests/multi_candidate_degrade_tests.rs"]
mod multi_candidate_degrade_tests;
#[cfg(test)]
#[path = "tests/on_exhausted_tests.rs"]
mod on_exhausted_tests;
#[cfg(test)]
#[path = "tests/ordered_walk_tests.rs"]
mod ordered_walk_tests;
#[cfg(test)]
#[path = "tests/pool_upstream_creds_tests.rs"]
mod pool_upstream_creds_tests;
#[cfg(test)]
#[path = "tests/probe_guard_tests.rs"]
mod probe_guard_tests;
#[cfg(test)]
#[path = "tests/probe_release_owner_tests.rs"]
mod probe_release_owner_tests;
#[cfg(test)]
#[path = "tests/reqlog_dispatch_tests.rs"]
mod reqlog_dispatch_tests;
#[cfg(test)]
#[path = "tests/request_short_circuit_tests.rs"]
mod request_short_circuit_tests;
#[cfg(test)]
#[path = "tests/reroute_pool_tests.rs"]
mod reroute_pool_tests;
#[cfg(test)]
#[path = "tests/response_model_fill_tests.rs"]
mod response_model_fill_tests;
#[cfg(test)]
#[path = "tests/runtime_carry_tests.rs"]
mod runtime_carry_tests;
#[cfg(test)]
#[path = "tests/scrape_queued_depth_tests.rs"]
mod scrape_queued_depth_tests;
#[cfg(test)]
#[path = "tests/signal_catalog_tests.rs"]
mod signal_catalog_tests;
#[cfg(test)]
#[path = "tests/stop_sequence_cap_degrade_tests.rs"]
mod stop_sequence_cap_degrade_tests;
#[cfg(test)]
#[path = "tests/translate_offload_tests.rs"]
mod translate_offload_tests;
#[cfg(test)]
#[path = "tests/usage_tap_tests.rs"]
mod usage_tap_tests;
// `alloc_gate` (the per-request allocation-count PERF gate) needs THIS crate's test binary to install
// the counting `#[global_allocator]` its instrument reads (`crate::CountingJemalloc`), ported below in
// `lib.rs` under the same target gate.
#[cfg(all(test, not(target_env = "msvc")))]
#[path = "tests/alloc_gate_tests.rs"]
mod alloc_gate_tests;
