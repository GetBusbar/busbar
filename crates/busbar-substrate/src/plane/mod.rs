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

// Phase-C config-seam: the NEUTRAL config-seam CONTRACTS a plane's config section is read through
// (`PlaneCfg`/`PlaneEndpointCfg`/`ContainerGateInputs`) and the parse-time bare-hook-reference rule
// (`refuse_cross_plane_reference`). They name only `busbar_api::SecretRef` + `serde_json`/`std`, so
// they live here; core re-exports them. The registry-coupled READER half (`split_section`,
// `config_sections`, the reserved-key literal) stays core.
pub mod config;

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
