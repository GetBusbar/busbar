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

use busbar_core::breaker::{classify as classify_disposition, normalize_raw_error, Disposition};
use busbar_core::config::OnExhausted;
use busbar_core::proto::{convert_headers, openai_family, StatusClass};
use busbar_core::state::App;
use busbar_core::store::{now, Permit};

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
pub(crate) use busbar_core::proxy::{
    route_policy_headers_enabled, UPSTREAM_RTT_US, HDR_ROUTE_POLICY, HDR_ROUTE_TARGET,
};

// NEUTRAL egress-engine primitives the pipeline drives, re-exported from core (which itself re-exports
// them from `busbar_substrate::egress::engine`) at their historical short paths so the moved call sites
// keep resolving.
pub(crate) use busbar_core::proxy::{
    egress_request, install_proxy_tunnel_if_configured, EgressClient, EgressClientSpec,
    EgressConnector, EgressError,
};

// The NEUTRAL error-KIND / network-transient / disposition / content-type vocabulary that STAYS in
// core (`busbar_core::proxy`, itself re-exporting the substrate leaf). Re-exported into the flattened
// engine namespace so the moved classification/error-envelope call sites keep naming them at their
// historical short paths (`crate::engine::{KIND_*, ERR_NET_*, DISPOSITION_*, APPLICATION_JSON, …}`).
pub(crate) use busbar_core::proxy::{
    DISPOSITION_ATTEMPT_TIMEOUT, DISPOSITION_CONTEXT_LENGTH, DISPOSITION_HARD_DOWN,
    DISPOSITION_TRANSIENT, ERR_DEGRADED_NON2XX, ERR_NET_CONNECT, ERR_NET_TIMEOUT, ERR_NET_TRANSPORT,
    KIND_API_ERROR, KIND_AUTHENTICATION, KIND_INSUFFICIENT_QUOTA, KIND_INVALID_REQUEST, KIND_NOT_FOUND,
    KIND_OVERLOADED, KIND_PERMISSION, KIND_RATE_LIMIT, KIND_REQUEST_TOO_LARGE, KIND_SERVER_ERROR,
    KIND_TIMEOUT,
};
pub(crate) use busbar_core::proxy::{
    APPLICATION_JSON, EGRESS_UA_DEFAULT, POOL_LABEL_UNRESOLVED, PROVIDER_CODE_CONTEXT_LENGTH,
    TEXT_EVENT_STREAM,
};
