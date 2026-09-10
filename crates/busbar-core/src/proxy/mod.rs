// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

// NOTE THE ABSENCE. This module used to import six `PROTO_*` constants for the hook seam's own
// content flattening. That second implementation is gone: the hook projection reads the IR the
// protocol's own reader produced, so nothing under `proxy/` names a dialect to decide what a
// request SAYS any more.
// The NEUTRAL proxy vocabulary that stays in core once the LLM engine moved to `busbar-llm`. Core's
// own staying call sites name these at `crate::proxy::*` via the re-export below; the relocated
// engine names them across the crate boundary as `busbar_core::proxy::*`.
pub mod proxy_vocab;
pub use proxy_vocab::{
    agnostic_error_envelope, gate_rejected, hook_content_max_bytes, ingress_error,
    max_upstream_buffered_bytes, read_capped, set_hook_content_max_bytes, GateRejected, ReadEnd,
    StageShape, DEFAULT_HOOK_CONTENT_MAX_BYTES,
};

// NOTE: cross-protocol max-tokens defaulting lives in `IrReq::prepare_for_egress` — the IR owns its
// cross-protocol semantics; the engine is operation-blind. Precedence unit tests drive the IR method.

// The two `x-busbar-*` TRANSPARENCY response-header NAMES, the operator opt-in gate, and the opt-in
// setter now live in the neutral substrate (`busbar_substrate::proxy`) so the plane crates name them
// without reaching into busbar-core; re-exported here for core's own `crate::proxy::*` call sites
// (`router.rs`, `admin`, `main.rs`'s `configure_route_policy_headers`).
pub use busbar_substrate::proxy::{
    configure_route_policy_headers, route_policy_headers_enabled, HDR_ROUTE_POLICY,
    HDR_ROUTE_TARGET,
};

// APPLICATION_JSON, TEXT_EVENT_STREAM, DISPOSITION_TRANSIENT, POOL_LABEL_UNRESOLVED and
// PROVIDER_CODE_CONTEXT_LENGTH now live in the neutral substrate (busbar_substrate::proxy) so the
// plane crates name them without reaching into busbar-core; re-exported below for core's own
// `crate::proxy::*` call sites.
pub use busbar_substrate::proxy::{
    APPLICATION_JSON, DISPOSITION_TRANSIENT, EGRESS_UA_DEFAULT, POOL_LABEL_UNRESOLVED,
    PROVIDER_CODE_CONTEXT_LENGTH, TEXT_EVENT_STREAM,
};

// Canonical error-KIND tokens: produced by `cross_protocol_error_kind` / passed to `ingress_error`
// as the `kind` argument. Each string is the protocol-agnostic discriminant that the per-protocol
// writer maps to its native error category. RELOCATED DOWN to the neutral `busbar_substrate::proxy`
// leaf (so the `busbar-llm` dialect writers name them without reaching into `busbar-core`) and
// re-exported here at their historical `crate::proxy::KIND_*` paths; the values are byte-identical
// (each aliases the ERR_TYPE_* bank at its substrate home).
pub use busbar_substrate::proxy::{
    KIND_API_ERROR, KIND_AUTHENTICATION, KIND_INSUFFICIENT_QUOTA, KIND_INVALID_REQUEST,
    KIND_NOT_FOUND, KIND_OVERLOADED, KIND_PERMISSION, KIND_RATE_LIMIT, KIND_REQUEST_TOO_LARGE,
    KIND_SERVER_ERROR, KIND_TIMEOUT,
};

// Network-transient `err_type` values passed to `record_transient_in` (the *category* of network
// failure recorded in the breaker store), and the failure-DISPOSITION metric-label values. RELOCATED
// DOWN to `busbar_substrate::proxy` so the relocated LLM engine names them without reaching into
// `busbar-core`; re-exported here for core's own call sites.
pub use busbar_substrate::proxy::{
    DISPOSITION_ATTEMPT_TIMEOUT, DISPOSITION_CONTEXT_LENGTH, DISPOSITION_HARD_DOWN,
    ERR_DEGRADED_NON2XX, ERR_NET_CONNECT, ERR_NET_TIMEOUT, ERR_NET_TRANSPORT,
};

// The per-request upstream-RTT task-local the `server_timing` middleware scopes and the forward path
// writes now lives in the neutral substrate (`busbar_substrate::proxy`) — single-compiled, so the
// router's `.scope()` and the plane's `.try_with()` read the ONE task-local. Re-exported here for
// core's own `proxy::UPSTREAM_RTT_US` call sites (`router.rs`).
pub use busbar_substrate::proxy::UPSTREAM_RTT_US;

// THE EGRESS ENGINE moved to the neutral substrate (`busbar_substrate::egress::engine`) — the
// one-egress-stack ruling's home for the owned outbound client every plane builds from. Core
// re-exports the engine names at their old `crate::proxy::` paths so every call site (state.rs's
// `EgressClient as Client`, appbuild's builder, the forward/health request assembly, the tests)
// keeps resolving unchanged. `pub` rather than `pub(crate)` deliberately: some of these names
// (`EgressConnector`) have no remaining in-core reader after the move, and an externally-visible
// re-export cannot rot into an unused-import warning while the path contract stands.
pub use busbar_substrate::egress::engine::{
    egress_request, install_proxy_tunnel_if_configured, EngineClient as EgressClient,
    EngineConnector as EgressConnector, EngineError as EgressError, EngineSpec as EgressClientSpec,
};

// The infallible LLM-lane egress-client shim now lives in the neutral substrate
// (`busbar_substrate::proxy::build_egress_client`) so a plane crate builds its egress client without
// reaching into `busbar-core`; re-exported here for core's own `crate::proxy::build_egress_client`
// call sites (`preflight`, `auth::token`, `egress_auth`, `export::webhook`, `engine_facade`).
pub use busbar_substrate::proxy::build_egress_client;

// THE MODEL PLANE'S RECORD IS NOT HERE, and no longer needs to be. The audit step is served once,
// for every plane, by `busbar-unit-audit`: the unit the composition root drives seals the one fixed
// record onto the node's own chain, through both of its terminals. What used to sit beside this
// module was a second answer to the same question, in RAM, with no durable byte and no production
// reader — so it recorded nothing an operator could rely on and could not be compared with a row
// any other plane wrote.

// THE MONEY-PATH ENGINE TESTS (usage_tap / on_exhausted / egress_differential / forward_once_pool_cell
// / pool_upstream_creds / ordered_walk / reroute_pool / probe_* / hook_seam / signal_catalog /
// *_degrade / egress_dropped_controls_audit / alloc_gate / … ) RELOCATED to `busbar-llm`
// (`src/engine/tests/`, declared under `engine/mod.rs`) with the engine they drive
// (`forward_with_pool` et al.).
