// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MCP PROTOCOL CODEC — the `codec` module of `busbar-mcp`.
//!
//! The MCP dialect, on the seam the LLM protocol crate proved. The files here are the per-dialect
//! template `one-core-mcp-a2a-as-protocols.md` bars — this file (the declaration, the dialect's
//! wire vocabulary and the notification codec), `handler.rs` (which operations it serves),
//! `invoke.rs` and `subscribe.rs` (the two cells), and `tests/` (its own tests, nobody else's).
//! Everything it consumes from the engine comes through `busbar-core`'s public surface; nothing in
//! `busbar-core` names this crate in production (`git grep busbar_mcp crates/busbar-core/src` is
//! pinned at zero) — the `busbar` BINARY, the composition root, links `busbar-mcp` and hands
//! [`DECL`] (which `busbar-mcp` re-exports as its `PROTO_DECL`) to
//! the substrate's protocol registry (`busbar_substrate_values::proto::install_protocols`) at boot. Delete the dependency edge and busbar
//! still builds, boots, refuses `protocol: mcp` config with the unknown-protocol refusal, and
//! serves the remaining dialects — that build is a gate, not a thought experiment.
//!
//! ## WHAT THIS MODULE IS, AND — SAID PLAINLY — WHAT IT IS NOT
//!
//! This module is MCP **the protocol**: the registry declaration, the JSON-RPC dialect, and the two
//! operation cells (`tools/call` and the subscription pair) that core resolves through the support
//! matrix. That is the whole of what `handlers/mcp.rs` was, and it moved here intact.
//!
//! It is distinct from the `mcp` PLANE — the sibling `mcp` module of `busbar-mcp` (~18k lines:
//! the catalogue, the call log, the client pool and its transports, the config sections, the
//! ask/approval state, the admin projections). That surface once wired into core through `AppState`
//! fields, the `tools:` config section, boot hydration, the router mount and the admin API — call
//! edges none of which a `&'static ProtocolDecl` could carry, because a `ProtocolDecl` deliberately
//! takes a handle to nothing (`design/protocol-plugin-abi.md` §"Not one method takes a handle to
//! anything"). The plane extraction neutralized every one of those edges onto the neutral
//! `busbar-substrate` seams (the plane-host trait, the config-section split, the hostless-egress and
//! task seams), and the plane folded into `busbar-mcp` beside this codec — ONE plugin per protocol.
//! MCP the protocol and MCP the plane are the same protocol, behind the one `plane-mcp` switch.
//!
//! **The consequence for the deletion gate, stated rather than discovered:** compiling this crate
//! out removes MCP as a *protocol* — `protocol: mcp` stops resolving and its two cells stop
//! existing. It does not remove the `tools:` plane's `/mcp` mount, which is gated by its own config
//! section. Deleting the plane is the plane-kind seam's job, not this codec's, and the gate here
//! measures exactly the edge this codec owns.
//!
//! ## DUAL COMPILATION
//!
//! Stated so the `#[path]` in core is not read as a leak: `busbar-core`'s test/`test-support`
//! builds compile these same sources back in as `handlers::mcp` (via `extern crate self as
//! busbar_kernel`), so the pre-extraction fixture surface keeps proving what it always proved without
//! core's PRODUCTION build knowing this dialect exists. That is why every core reference in these
//! files is spelled through the neutral crates (`busbar_substrate_values::` / `busbar_api::`) and every self
//! reference is relative.

pub mod handler;
mod invoke;
mod subscribe;

/// MCP'S DECLARATION — and the asymmetry in it is the point. MCP declares a HANDLER and NO CODEC:
/// its IR is its own, there is no cross-dialect translation into or out of it, and it point-reads no
/// top-level body key on the pre-materialized path (its method lives in the JSON-RPC envelope, which
/// `busbar_substrate_values::ingress::jsonrpc` parses). A registry that could only hold six-of-a-kind would have
/// had to grow a special case for it; this one holds a declaration that says `None` four times.
///
/// Handed to `install_protocols` by the composition root (the `busbar` binary); in `busbar-core`'s
/// test/`test-support` builds it is instead the cfg-gated built-in row, so the fixture registry the
/// tests see matches the registry a shipped binary has.
pub const DECL: busbar_substrate_values::proto::ProtocolDecl =
    busbar_substrate_values::proto::ProtocolDecl {
        handler: Some(&handler::McpRequestHandler),
        verbs: &[
            busbar_api::operation::Operation::INVOKE,
            busbar_api::operation::Operation::SUBSCRIBE,
        ],
        // EVERY OTHER FIELD IS THE NEUTRAL ROW (`ProtocolDecl::named`), stated once beside the struct
        // rather than copied here — and each one is exactly what MCP means:
        // - no codec, no head keys, no stream content type, no array-stream shim, no native tool-id
        //   prefix: MCP declares a HANDLER and nothing a cross-dialect translation would read;
        // - the default ingress auth scheme, and no egress credential builder: the shared schemes stay
        //   in `egress_auth::resolve`, because MCP presents no dialect-specific egress credential
        //   shaping of its own;
        // - no path ingress (`has_model_in_url` false): the model is in the BODY, so this dialect
        //   registers no arrival and the catch-all resolves its operation through the
        //   `RequestHandler` on the universal ingress;
        // - every promoted writer fact (G6 step A1) is the `ProtocolWriter` trait DEFAULT: MCP has no
        //   writer, so these are inert, but the declaration must state them;
        // - the neutral SSE `egress_stream_accept`, never consulted (no translated egress);
        // - no `/v1/models` envelope or list-models fingerprint: MCP serves no model discovery;
        // - no router or residual claim, not the residual default, no vendor response metadata: MCP
        //   is identified by its EXPLICIT mount (`/mcp`), never by a wire fingerprint.
        // `the_mcp_decl_is_the_neutral_row_but_for_its_handler_and_verbs` pins each of these.
        ..busbar_substrate_values::proto::ProtocolDecl::named(busbar_plane_mcp::PLANE_KEY)
    };

#[cfg(test)]
#[path = "tests/mcp_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/decl_tests.rs"]
mod decl_tests;
