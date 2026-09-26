// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! busbar-mcp — the Model Context Protocol, as ONE plugin crate.
//!
//! WHAT THIS CRATE HOLDS TODAY. The MCP protocol codec — the [`codec`] module: the
//! [`ProtocolDecl`](busbar_kernel::proto::ProtocolDecl) ([`PROTO_DECL`]), the JSON-RPC dialect, and
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
//! the substrate's protocol registry (`busbar_kernel::proto::install_protocols`) at boot.

/// THE CODEC, THE RECORD VOCABULARY AND THE TWO PURE CONTENT PASSES, RE-EXPORTED FROM
/// `busbar-plane-mcp`.
///
/// The protocol declaration, the JSON-RPC dialect and notification pair, the `tools/call` and
/// subscription operation cells, the durable record types, the content sanitizer and the
/// structured-output schema check all live in `busbar-plane-mcp` now — the pure half of this
/// plugin, split out so `busbar-plane-mcp` can name the codec without linking this crate's axum
/// routes, stdio serve loop and tokio transports. They are re-exported HERE, under their old names,
/// so every caller that spells `busbar_mcp::codec::…` or `busbar_mcp::record::…` resolves exactly
/// what it always did. The split is a MOVE: no item changed shape crossing it.
pub mod codec;
pub mod record;
pub use busbar_plane_mcp::{outputschema, sanitize};

/// THE MCP PLANE'S DIAGNOSTICS CATALOG.
///
/// The `MCP_*` catalog entries and the `DIAGNOSTICS` slice previously lived in the standalone
/// `busbar-plane-mcp-host` crate (the first byte-safe step of the fat-crate collapse — DECISIONS
/// #19/#20/#21) and re-exported here under this path; that crate has since folded back into this
/// one (#19/#39: `busbar-plane-mcp-host` is named for deletion explicitly), so the module lives here
/// directly now. Every `busbar_mcp::diagnostics::…` / `crate::diagnostics::…` caller still resolves
/// exactly what it always did.
pub mod diagnostics;

pub mod mcp;

/// THE SDK-IDENTITY PIN FOR THE CODEC'S WIRE VOCABULARY. It lives here, not in the codec crate,
/// because `rmcp` hard-depends on `tokio` and the codec crate is in a PURE plane kind's transitive
/// closure — see the module header.
#[cfg(test)]
#[path = "tests/sdk_vocabulary_tests.rs"]
mod sdk_vocabulary_tests;

/// THE MCP PLANE'S OWN DURABLE RECORD TYPES — relocated here from `busbar-api` (1.7.0 plane
/// extraction), then out again with the codec, re-exported at the crate root so
/// `busbar_mcp::McpCallRecord` / `busbar_mcp::McpDemotionRow` resolve. The neutral crates name
/// neither.
pub use record::{McpCallRecord, McpDemotionRow};

/// THE MCP PLANE'S TEST-KIT (feature `test-support` only): the fixture builders that name MCP plane
/// types, kept on the plane so busbar-core's neutral `test_support::TestApp` names none of them. This
/// is the seam that lets core drop the `#[path]` dual-compile of `src/mcp` for its own tests.
#[cfg(feature = "test-support")]
pub mod testkit;

/// MCP'S PLANE DECLARATION — the contract data the composition root registers
/// (`busbar_mcp::PLANE_DECLARATION`) and the behaviour table the kernel joins to it
/// (`PLANE_HOOKS`, through `PlaneDecl::assemble`). See [`mcp`] for both.
pub use mcp::{PLANE_DECLARATION, PLANE_HOOKS};

/// MCP'S PLANE-CONTRIBUTED DIAGNOSTICS — the `&'static [&'static Diagnostic]` the composition root
/// hands to `busbar_substrate_values::diagnostics::install_diagnostics` at boot, re-exported at the crate
/// root so the `busbar` binary names one stable path (`busbar_mcp::DIAGNOSTICS`). See [`diagnostics`].
pub use diagnostics::DIAGNOSTICS;

/// MCP'S PROTOCOL DECLARATION — the `&'static ProtocolDecl` the composition root installs. Re-exported
/// at the crate root so the `busbar` binary names one stable path (`busbar_mcp::PROTO_DECL`) and does
/// not reach into the `codec` module for it. See [`codec::DECL`] for the declaration itself.
pub use codec::DECL as PROTO_DECL;

/// MCP'S PLANE CAPABILITY KEY (`"mcp"`) — the string the composition root flips onto the unified
/// kernel loop ([`busbar_kernel::plane_host::register_gauntlet_runner`]) and the same string the
/// `tools/call` plane reports from its `GauntletPlane::capability_key`. Re-exported at the crate root
/// so the `busbar` binary names ONE stable path (`busbar_mcp::PLANE_KEY`) and the plane and the flip
/// cannot drift onto two different literals.
pub use busbar_plane_mcp::PLANE_KEY;

/// THE ONE ENTRY THIS PLUGIN IS REGISTERED THROUGH — everything a composition root that linked it
/// wires, one item per registration axis, read off the crate rather than spelled at the root. The
/// root's manifest names this crate and the axes it registers on
/// (`[package.metadata.busbar.linked-axes]`: the plane, the JSON-RPC protocol declaration, the
/// plane's owned diagnostics, the governed outbound hop it drives through the root-bound egress seam,
/// and the stdio serve mode); its build script turns that into one table per axis over these items,
/// and the root's source names no item of this crate.
pub mod linked {
    /// The plane axis: the contract declaration, joined kernel-side to the behaviour table.
    pub use crate::mcp::{PLANE_DECLARATION, PLANE_HOOKS};
    /// The protocol axis: the one JSON-RPC declaration.
    pub static PROTOCOLS: &[&busbar_substrate_values::proto::ProtocolDecl] = &[&crate::PROTO_DECL];
    /// The stdio serve mode: frames on stdin/stdout instead of a listener; the exit code.
    pub use crate::mcp::serve_stdio_boxed as stdio_serve;
    /// The diagnostics axis.
    pub use crate::DIAGNOSTICS;
    /// The CLI-help axis: this plane's rows of `busbar --help`, as declared data — `("flag", lines)`
    /// is a row of the `Flags:` block whose first word is the flag the binary accepts.
    pub const CLI_HELP: &[(&str, &str)] = &[("flag", busbar_plane_mcp::meta::HELP_FLAGS)];
    /// The claims axis: the pure plane the composition root's boot seal registers, and the claims it
    /// declares.
    pub const PLANE: busbar_plane_mcp::McpPlane = busbar_plane_mcp::McpPlane::EMPTY;
    /// The bytes that plane claims.
    pub const CLAIMS: &[busbar_contract::grammar::Claim] =
        <busbar_plane_mcp::McpPlane as busbar_contract::plane::PlaneMeta>::CLAIMS;
}
