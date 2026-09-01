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
