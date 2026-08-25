// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! busbar-mcp — the Model Context Protocol, as ONE plugin crate.
//!
//! WHAT THIS CRATE HOLDS TODAY. The MCP protocol codec — the [`codec`] module: the
//! [`ProtocolDecl`](busbar_core::proto::ProtocolDecl) ([`PROTO_DECL`]), the JSON-RPC dialect, and
//! the `tools/call` and subscription operation cells that core resolves through the support matrix.
//! This is the whole of what `busbar-core/src/handlers/mcp.rs` was and what the standalone
//! `busbar-proto-mcp` crate carried before it folded in here.
//!
//! WHAT THIS CRATE WILL ALSO HOLD. The MCP plane — today's `crates/busbar-core/src/mcp` (~18k
//! lines: the catalogue, the call log, the client pool and its transports, the config sections,
//! boot hydration, the router mount and the admin API). MCP the protocol and MCP the plane are the
//! same protocol, so they end up behind ONE on/off switch, not two — an operator's choice is "can
//! this busbar speak MCP", never "can it speak the wire format but not run the plane behind it".
//! The plane has NOT moved here yet; that is a later step of the plane split, and it lands beside
//! the codec below.
//!
//! ONE PLUGIN PER PROTOCOL, the same rule `busbar-llm` states for its six LLM dialects: nothing
//! about the seam changes because this plugin happens to also carry a plane's worth of state.
//! Everything the codec consumes from the engine comes through `busbar-core`'s public surface;
//! nothing in `busbar-core` names this crate in production, and the `busbar` BINARY — the
//! composition root — links it and hands [`PROTO_DECL`] to
//! `busbar_core::proto::registry::install_protocols` at boot.

pub mod codec;
pub mod mcp;

/// MCP'S PLANE DECLARATION — the `&'static PlaneDecl` the composition root installs at boot so the
/// `busbar` binary names one stable path (`busbar_mcp::PLANE_DECL`). See [`mcp`] for the declaration.
pub use mcp::PLANE_DECL;

/// MCP'S PROTOCOL DECLARATION — the `&'static ProtocolDecl` the composition root installs. Re-exported
/// at the crate root so the `busbar` binary names one stable path (`busbar_mcp::PROTO_DECL`) and does
/// not reach into the `codec` module for it. See [`codec::DECL`] for the declaration itself.
pub use codec::DECL as PROTO_DECL;
