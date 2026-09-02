// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The neutral wire-format NAMES the plane spine and the served-card boundary compare against.
//!
//! These are the canonical spellings of the wire formats busbar's mounted planes speak. They live
//! in the neutral substrate because a plane crate names them without reaching into `busbar-core`,
//! and because a literal spelled per site is how two answers that must agree start to differ. The
//! plane spine (`busbar_core::plane`) re-exports them unchanged.

// D3 Phase-C: the neutral per-call record INPUT and the ask-state seal PODs a plane names when it
// reaches the call-log / approval host seams. Both name only `std` + crypto, so they live here; core
// re-exports them so its own call sites are unchanged.
pub mod approvals;
pub mod calllog;

// The NEUTRAL plane-observe response marker `Counted` — the one type a plane's handler and core's
// `plane::observe` boundary both name. It carries nothing and names no engine type, so it lives
// here; core re-exports it from `busbar_core::plane::observe` so its middleware reads the same type.
pub mod observe;

// The plane store seam's narrowing adapter: the `PlaneStore` trait a plane persists through and the
// `PlaneStoreView` that narrows a real `busbar_api::Store` to it. Both name only `busbar_api` leaf
// types, so they live here; core re-exports them from `busbar_core::plane::store`.
pub mod store;

// Phase-C config-seam: the NEUTRAL config-seam CONTRACTS a plane's config section is read through
// (`PlaneCfg`/`PlaneEndpointCfg`/`ContainerGateInputs`) and the parse-time bare-hook-reference rule
// (`refuse_cross_plane_reference`). They name only `busbar_api::SecretRef` + `serde_json`/`std`, so
// they live here; core re-exports them. The registry-coupled READER half (`split_section`,
// `config_sections`, the reserved-key literal) stays core.
pub mod config;

// S4b: the NEUTRAL PLANE-REGISTRY SURFACE — the plane VOCABULARY/SEAM declaration `PlaneDecl`, the
// `BuildCtx` its `build` reads, the neutral `PlaneBootCtx` boot-context trait + its `RestoredSummary`
// return, and the `BootHook` alias. Relocated here so an extracted plane crate constructs its own
// `PlaneDecl` and every seam type its fields name without a path back to core. Core re-exports each
// from `busbar_core::plane::registry`, and keeps the population glue + the concrete `BootCtx` (which
// borrows the core-live `App`) that implements `PlaneBootCtx`.
pub mod registry;

// SEAM-FIX #1 (axis-C): the NEUTRAL DURABLE-HANDLE ENGINE — the plane-agnostic async-handle /
// durable-session capability (registry of cross-request handles, durable write-through, retention
// sweep, boot rehydrate, inbound-push cursor, scoped anti-enumeration read). Lifted here out of the
// A2A plane's task store so every plane consumes ONE substrate-single-compiled engine rather than
// reaching into another plane. It names no plane noun: a plane's row is held opaquely behind
// `Arc<dyn Any>` beside a neutral `HandleMeta` projection, and the plane supplies its shape/statuses/
// vocab/digest through the entry-point callbacks.
pub mod handle_engine;

/// A PLANE'S OAUTH RESOURCE-SERVER ADMISSION FACTS — the audience a token must carry to be spent on
/// this plane's mount, and the RFC 9728 metadata URL a refused caller is pointed at. A neutral POD so
/// a plane crate contributes its admission across the mount seam without naming a core type; core
/// re-exports it, so `busbar_core::plane::PlaneAdmission` still resolves there.
///
/// The confused-deputy defence (RFC 8707) is "a token minted for someone else must not be spendable
/// here". Keeping the audience beside the MOUNT (not in a handler) means the check is a property of
/// the door, so every path behind that door inherits it and a new handler cannot forget.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlaneAdmission {
    /// RFC 8707 resource indicator: the exact `aud` an admitted token must carry. Compared for
    /// EQUALITY, never prefix or suffix — a resource indicator is an opaque identifier, and treating
    /// it as a namespace is how `https://gw.example.com/mcp` starts admitting tokens minted for
    /// `https://gw.example.com/mcp-staging`.
    pub audience: String,
    /// The absolute URL of this resource's RFC 9728 protected-resource metadata document, quoted
    /// verbatim in the `resource_metadata` parameter of the `WWW-Authenticate` challenge. This is
    /// the whole of an MCP client's discovery story: it arrives with no credential, reads this URL
    /// out of the `401`, and follows it to the operator's authorization server.
    pub resource_metadata: String,
}

/// THE WIRE FORMAT both mounted planes speak: JSON-RPC 2.0. Named once, here, because it is read
/// twice as a `wire_format_names` entry and once more by the error-shaping boundary, which
/// decides that a refusal on a mounted plane is a JSON-RPC error object rather than a vendor
/// envelope. A literal spelled per site is how those two answers start to differ.
pub const WIRE_JSONRPC: &str = "jsonrpc";

/// THE SECOND WIRE FORMAT THE A2A PLANE SPEAKS: A2A's HTTP+JSON binding, where the REQUEST LINE
/// names the operation rather than a body member. Named once, here, because it is read three ways
/// and all three must agree — as a `wire_format_names` entry, as the
/// `busbar_core::transport::Transport::HttpJson` label, and (upper-cased by
/// `a2a::serve::servable_bindings`) as the `protocolBinding` a served agent card advertises. The
/// card spelling is `HTTP+JSON`, so this is that string lower-cased and nothing else.
pub const WIRE_HTTP_JSON: &str = "http+json";

/// The A2A specification's gRPC binding, as a wire-format name. Lower-case here and upper-cased
/// once, by `busbar_core::a2a::serve::servable_bindings`, into the `GRPC` an agent card advertises
/// — so the card cannot claim a binding the plane does not list, which is the whole reason that
/// function reads this list rather than writing one of its own.
pub const WIRE_GRPC: &str = "grpc";
