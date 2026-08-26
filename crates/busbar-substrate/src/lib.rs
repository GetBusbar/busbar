// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The busbar NEUTRAL SUBSTRATE — the transport-agnostic value families and helpers a plane crate
//! (`busbar-mcp`, `busbar-a2a`) names without reaching into `busbar-core`.
//!
//! The Phase-B plane extraction inverts the old dependency direction: instead of the planes living
//! inside core and reaching for core-private types, the neutral pieces they share — trust value
//! families, egress-authorisation decisions, failover walk types, and the transport-neutral ingress
//! helpers — move DOWN into this crate. It depends only on the plugin contracts (`busbar-api`) and
//! the plugin ABI (`busbar-plugin`), both leaves, so a plane crate can depend on it with no path
//! back to core and no dependency cycle.
//!
//! B0-b relocates the Tier-0 leaves here (the guarded-fetch network primitives, the diagnostics
//! catalog, the audit vocabulary, the transport-neutral JSON-RPC envelope reader, the wire-format
//! names, and the capped upstream-body read); B1 the trust/egress/failover families. Core
//! re-exports each relocated item during the transition so the in-core call sites do not change in
//! the same commit.

pub mod diagnostics;
pub mod net_guard;
pub mod audit {
    pub mod vocab;
}
pub mod ingress {
    pub mod jsonrpc;
    // B1: the transport-neutral JSON-RPC ingress SEQUENCE (`serve`), the core-refusal vocabulary and
    // the RFC 9728 metadata render. The `App`/`CurrentApp`-facing half (`ResourceMetadata`,
    // `metadata_handler`) stays in core and re-exports these.
    pub mod protocol;
}
pub mod breaker;
pub mod duration;
pub mod egress;
pub mod plane;
// D1: the NEUTRAL HOST SEAM — the `EngineHost` trait a plane calls to reach engine host capabilities
// without naming a core type, plus the relocated lifecycle-scope arena (`DispatchScope` et al.) those
// capabilities register handles into. Core implements `EngineHost` over its live `App` and re-exports
// the scope types, so its own call sites are unchanged.
pub mod plane_host;
// S4a: the NEUTRAL ROUTE-MOUNT SEAM — the `PlaneRouteSpec` / `PlaneReqCtx` vocabulary a plane uses to
// declare its data routes without naming `CoreRouter` / `Arc<AppHandle>`, so `PlaneDecl`'s route
// field can be typed `fn(&dyn Any) -> Vec<PlaneRouteSpec>` and eventually travel to this crate.
pub mod plane_routes;
pub mod proxy;

// ── Phase-B B1: the trust value families + decision engines, the egress gate, the catalogue and the
// failover walk types + the lane-availability taxonomy. Each depends only on `busbar-api`
// (`VirtualKey`) and `busbar-plugin` (`hot::VerifyDecision`) — both leaves — plus this crate's own
// audit vocabulary. Core re-exports each relocated item so the in-core call sites do not change.
pub mod transport;
pub mod trust;
pub mod egress_auth {
    pub mod gate;
}
pub mod catalogue;
pub mod failover;
pub mod store;
