// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MCP WIRE CODEC — the pure half of the Model Context Protocol plugin.
//!
//! `busbar-mcp` held two things behind one name: this codec — the protocol declaration, the
//! JSON-RPC dialect and notification pair, the `tools/call` and subscription operation cells, the
//! content sanitizer and the structured-output schema check — and the MCP plane that carries them
//! over the network (the axum route mount, the stdio serve loop, the client pool and its tokio
//! transports, the upstream token exchange). The plane crate `busbar-plane-mcp` adapts the codec
//! and must not link the server: a plane is a PURE kind whose whole transitive closure is scanned,
//! and the server stack put `hyper`, `reqwest`, `axum` and a socket-capable `tokio` in it.
//!
//! So the codec lives here, naming only the pure half of the neutral ABI
//! (`busbar-substrate-values` / `busbar-api`) plus `http` for the two status codes the declaration
//! carries. `busbar-mcp` depends on this crate and re-exports every module that moved under its old
//! path, so `busbar_mcp::codec::…`, `busbar_mcp::record::…` and `busbar_mcp::McpCallRecord`
//! resolve exactly what they always did. The split is a MOVE: no item changed shape crossing it.

pub mod codec;
pub mod outputschema;
pub mod record;
pub mod sanitize;

/// THE MCP PLANE'S DURABLE RECORD TYPES, re-exported at the crate root exactly as `busbar-mcp`
/// exposes them — so the parent crate's own root re-export is a forward of this one and there is
/// one definition rather than two spellings of it.
pub use record::{McpCallRecord, McpDemotionRow};

/// MCP'S PROTOCOL DECLARATION — the `&'static ProtocolDecl` the composition root installs.
/// `busbar-mcp` re-exports this as `busbar_mcp::PROTO_DECL`, which is the path the `busbar` binary
/// names.
pub use codec::DECL as PROTO_DECL;

/// THE REGISTRY KEY MCP IS KNOWN BY, in the protocol registry and in the plane registry alike.
///
/// Named ONCE, here, on the codec side of the split, because three declarations read it and all
/// three must agree: this crate's [`codec::DECL`]`.name`, `busbar-mcp`'s `PLANE_DECL.key`, and the
/// `busbar-plane-mcp` contract plane's `KEY`. The plane crate is a pure kind and cannot name
/// `busbar-mcp` at all, so a key spelled on the server side would be a key the plane could only
/// copy — which is how two answers to "what is this plane called" start to differ.
pub const PLANE_KEY: &str = "mcp";
