// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! busbar-mcp — the Model Context Protocol, as ONE plugin crate. SHELL ONLY, so far.
//!
//! Step 3.A.0 of the plane split creates this crate empty on purpose: the manifest and this doc
//! comment, wired into the workspace and into `crates/busbar/Cargo.toml` behind a `plane-mcp`
//! feature that nothing yet turns on and nothing yet consumes. No plane or codec code has moved
//! here — that is later steps in the same split.
//!
//! WHAT THIS CRATE WILL HOLD. The MCP protocol codec — today's `busbar-proto-mcp` (the
//! `ProtocolDecl`, the JSON-RPC dialect, the `tools/call` and subscription operation cells) — folded
//! TOGETHER with the MCP plane — today's `crates/busbar-core/src/mcp` (~18k lines: the catalogue,
//! the call log, the client pool and its transports, the config sections, boot hydration, the
//! router mount and the admin API). MCP the protocol and MCP the plane are the same protocol, so
//! they end up behind ONE on/off switch, not two — an operator's choice is "can this busbar speak
//! MCP", never "can it speak the wire format but not run the plane behind it".
//!
//! ONE PLUGIN PER PROTOCOL, the same rule `busbar-llm` states for its six LLM dialects: nothing
//! about the seam changes because this plugin happens to also carry a plane's worth of state.
