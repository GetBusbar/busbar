// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! busbar-mcp — the Model Context Protocol, as ONE plugin crate.
//!
//! WHAT THIS CRATE HOLDS TODAY. The MCP protocol codec — the [`codec`] module: the
//! [`ProtocolDecl`](busbar_substrate::proto::ProtocolDecl) ([`PROTO_DECL`]), the JSON-RPC dialect, and
//! the `tools/call` and subscription operation cells that core resolves through the support matrix.
//! This is the whole of what `busbar-core/src/handlers/mcp.rs` was and what the standalone
//! `busbar-proto-mcp` crate carried before it folded in here.
//!
//! WHAT THIS CRATE ALSO HOLDS. The MCP plane (today's former `crates/busbar-core/src/mcp`, ~18k
//! lines: the catalogue, the call log, the client pool and its transports, the config sections,
//! boot hydration, the router mount and the admin API). MCP the protocol and MCP the plane are the
//! same protocol, so they sit behind ONE on/off switch, not two — an operator's choice is "can
//! this busbar speak MCP", never "can it speak the wire format but not run the plane behind it".
//! The plane folded in beside the codec as a later step of the plane split; it lives in the
//! [`mcp`] module below.
//!
//! ONE PLUGIN PER PROTOCOL, the same rule `busbar-llm` states for its six LLM dialects: nothing
//! about the seam changes because this plugin happens to also carry a plane's worth of state.
//! Everything the codec consumes from the engine comes through `busbar-core`'s public surface;
//! nothing in `busbar-core` names this crate in production, and the `busbar` BINARY — the
//! composition root — links it and hands [`PROTO_DECL`] to
//! `busbar_core::proto::registry::install_protocols` at boot.

pub mod codec;
pub mod diagnostics;
pub mod mcp;
pub mod record;

/// THE MCP PLANE'S OWN DURABLE RECORD TYPES — relocated here from `busbar-api` (1.7.0 plane
/// extraction), re-exported at the crate root so `busbar_mcp::McpCallRecord` /
/// `busbar_mcp::McpDemotionRow` resolve. The neutral crates name neither.
pub use record::{McpCallRecord, McpDemotionRow};

/// THE MCP PLANE'S TEST-KIT (feature `test-support` only): the fixture builders that name MCP plane
/// types, kept on the plane so busbar-core's neutral `test_support::TestApp` names none of them. This
/// is the seam that lets core drop the `#[path]` dual-compile of `src/mcp` for its own tests.
#[cfg(feature = "test-support")]
pub mod testkit;

/// MCP'S PLANE DECLARATION — the `&'static PlaneDecl` the composition root installs at boot so the
/// `busbar` binary names one stable path (`busbar_mcp::PLANE_DECL`). See [`mcp`] for the declaration.
pub use mcp::PLANE_DECL;

/// MCP'S PLANE-CONTRIBUTED DIAGNOSTICS — the `&'static [&'static Diagnostic]` the composition root
/// hands to `busbar_substrate::diagnostics::install_diagnostics` at boot, re-exported at the crate
/// root so the `busbar` binary names one stable path (`busbar_mcp::DIAGNOSTICS`). See [`diagnostics`].
pub use diagnostics::DIAGNOSTICS;

/// MCP'S PROTOCOL DECLARATION — the `&'static ProtocolDecl` the composition root installs. Re-exported
/// at the crate root so the `busbar` binary names one stable path (`busbar_mcp::PROTO_DECL`) and does
/// not reach into the `codec` module for it. See [`codec::DECL`] for the declaration itself.
pub use codec::DECL as PROTO_DECL;
