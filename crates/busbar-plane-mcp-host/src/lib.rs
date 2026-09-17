// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! busbar-plane-mcp-host — the MCP plane's IMPURE HOST crate.
//!
//! The fat `busbar-mcp` splits four ways (DECISIONS #19/#20/#21/#1): the pure wire codec
//! (`busbar-mcp-codec`), the shared transport crates, the purity-scanned contract adapter
//! (`busbar-plane-mcp`), and THIS crate — the impure, bridged-ABI host that holds the substrate
//! `PlaneDecl` (`PLANE_DECL`), the runtime slot (`McpResource`/`McpRuntime`), `serve_stdio`, the
//! plane test-kit, the plane-contributed diagnostics and the engine glue. `busbar-mcp` the NAME is
//! now a thin re-export shim over this crate: every caller that spells `busbar_mcp::…` resolves the
//! item HERE, unchanged.
//!
//! ## What lives here
//!
//! The whole MCP plane — the former `busbar-mcp/src/mcp` (~18k lines: the catalogue, the call log,
//! the client pool and its transports, the config sections, boot hydration, the router mount, the
//! admin API, and the money files `method.rs`/`sampling.rs`) — lives in the [`mcp`] module below.
//! This is the single strongly-connected component welded to the money files: `method.rs` reaches
//! `super::runtime_of`, `super::config`, `super::envelope`, `super::callerask`, and `McpRuntime`
//! holds a `sampling::SamplingSpend`, so it moves as ONE unit (the oracle-gated money cell) and its
//! internal `super::`/`crate::mcp::…` relationships are unchanged by the move.
//!
//! The plane's DIAGNOSTICS catalog (the `MCP_*` entries the composition root installs via
//! [`install_diagnostics`](busbar_substrate::diagnostics::install_diagnostics)) lives in the
//! [`diagnostics`] module — the first byte-safe leaf that landed here in the earlier cell.
//!
//! ## The codec, re-exported
//!
//! The protocol declaration, the JSON-RPC dialect, the `tools/call` and subscription operation
//! cells, the durable record types, the content sanitizer and the structured-output schema check
//! live in `busbar-mcp-codec` (the pure half). They are re-exported HERE under their old names so
//! the plane's own modules spell `crate::codec::…` / `crate::record::…` / `crate::PROTO_DECL` exactly
//! as they did when they lived in `busbar-mcp`, and so the `busbar-mcp` shim can forward them onward.

/// THE CODEC, THE RECORD VOCABULARY AND THE TWO PURE CONTENT PASSES, RE-EXPORTED FROM
/// `busbar-mcp-codec`.
///
/// The protocol declaration, the JSON-RPC dialect and notification pair, the `tools/call` and
/// subscription operation cells, the durable record types, the content sanitizer and the
/// structured-output schema check all live in `busbar-mcp-codec` — the pure half of this plugin,
/// split out so `busbar-plane-mcp` can name the codec without linking this crate's axum routes,
/// stdio serve loop and tokio transports. They are re-exported HERE, under their old names, so every
/// module in the plane — and every `busbar_mcp::codec::…` / `busbar_mcp::record::…` caller through
/// the shim — resolves exactly what it always did. The split is a MOVE: no item changed shape.
pub use busbar_mcp_codec::{codec, outputschema, record, sanitize};

/// THE MCP PLANE'S DIAGNOSTICS CATALOG — the `MCP_*` entries this plane owns and the [`DIAGNOSTICS`]
/// slice the composition root installs. Relocated here from `busbar-mcp/src/diagnostics.rs` byte for
/// byte; the `busbar-mcp` shim re-exports the module under its old path.
pub mod diagnostics;

/// The plane-contributed diagnostics slice, re-exported at the crate root so the `busbar` binary — and
/// the `busbar-mcp` shim, which re-exports it onward — names one stable path.
pub use diagnostics::DIAGNOSTICS;

/// THE MCP PLANE — the catalogue, the call log, the client pool and its transports, the config
/// sections, boot hydration, the router mount, the admin API and the money files. Relocated here from
/// `busbar-mcp/src/mcp` byte for byte as one strongly-connected unit.
pub mod mcp;

/// THE SDK-IDENTITY PIN FOR THE CODEC'S WIRE VOCABULARY. It lives here, not in the codec crate,
/// because `rmcp` hard-depends on `tokio` and the codec crate is in a PURE plane kind's transitive
/// closure — see the module header.
#[cfg(test)]
#[path = "tests/sdk_vocabulary_tests.rs"]
mod sdk_vocabulary_tests;

/// THE MCP PLANE'S OWN DURABLE RECORD TYPES — relocated here from `busbar-api` (1.7.0 plane
/// extraction), then out again with the codec, re-exported at the crate root so
/// `busbar_mcp::McpCallRecord` / `busbar_mcp::McpDemotionRow` (through the shim) resolve. The neutral
/// crates name neither.
pub use busbar_mcp_codec::{McpCallRecord, McpDemotionRow};

/// THE MCP PLANE'S TEST-KIT (feature `test-support` only): the fixture builders that name MCP plane
/// types, kept on the plane so busbar-core's neutral `test_support::TestApp` names none of them. This
/// is the seam that lets core drop the `#[path]` dual-compile of `src/mcp` for its own tests.
#[cfg(feature = "test-support")]
pub mod testkit;

/// MCP'S PLANE DECLARATION — the `&'static PlaneDecl` the composition root installs at boot so the
/// `busbar` binary names one stable path (`busbar_mcp::PLANE_DECL`). See [`mcp`] for the declaration.
pub use mcp::PLANE_DECL;

/// MCP'S PROTOCOL DECLARATION — the `&'static ProtocolDecl` the composition root installs. Re-exported
/// at the crate root so the `busbar` binary names one stable path (`busbar_mcp::PROTO_DECL`, through
/// the shim) and does not reach into the `codec` module for it. See [`codec::DECL`].
pub use busbar_mcp_codec::PROTO_DECL;
