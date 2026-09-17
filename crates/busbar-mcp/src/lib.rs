// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! busbar-mcp — the Model Context Protocol plugin NAME, now a thin RE-EXPORT SHIM.
//!
//! The fat crate has drained (DECISIONS #19/#20/#21/#1). What `busbar-mcp` held splits four ways:
//! the pure wire codec (`busbar-mcp-codec`), the shared transport crates, the purity-scanned
//! contract adapter (`busbar-plane-mcp`), and the impure bridged-ABI host (`busbar-plane-mcp-host`) —
//! which now holds the whole MCP plane: the substrate `PlaneDecl` (`PLANE_DECL`), the runtime slot
//! (`McpResource`/`McpRuntime`), `serve_stdio`, the plane test-kit, the plane-contributed diagnostics,
//! the money files and the engine glue.
//!
//! This crate keeps the NAME alive as a shim so every caller that spells `busbar_mcp::…` — the
//! `busbar` binary's `busbar_mcp::PROTO_DECL` / `PLANE_DECL` / `DIAGNOSTICS` install sites, and the
//! `busbar_mcp::mcp::…` / `busbar_mcp::testkit::…` / `busbar_mcp::codec::…` / `busbar_mcp::record::…`
//! test references — resolves exactly what it always did. Every re-export below is a forward of the
//! item's one definition in `busbar-plane-mcp-host` (or, for the codec, transitively in
//! `busbar-mcp-codec`); no item changed shape, so the split is a MOVE. The name is deleted once every
//! caller repoints onto `busbar-plane-mcp-host` directly.

/// THE CODEC, THE RECORD VOCABULARY AND THE TWO PURE CONTENT PASSES — forwarded from the host crate
/// (which re-exports them from `busbar-mcp-codec`), so `busbar_mcp::codec::…` / `busbar_mcp::record::…`
/// resolve exactly what they always did.
pub use busbar_plane_mcp_host::{codec, outputschema, record, sanitize};

/// THE MCP PLANE'S DIAGNOSTICS CATALOG, re-exported from `busbar-plane-mcp-host` so every
/// `busbar_mcp::diagnostics::…` caller resolves what it always did.
pub use busbar_plane_mcp_host::diagnostics;

/// THE MCP PLANE — the whole `mcp` module, re-exported from `busbar-plane-mcp-host` so every
/// `busbar_mcp::mcp::…` caller (the config types, `McpResource`, `serve_stdio`, `admin_view`, the
/// envelope constants) resolves what it always did.
pub use busbar_plane_mcp_host::mcp;

/// THE MCP PLANE'S OWN DURABLE RECORD TYPES, re-exported at the crate root so
/// `busbar_mcp::McpCallRecord` / `busbar_mcp::McpDemotionRow` resolve.
pub use busbar_plane_mcp_host::{McpCallRecord, McpDemotionRow};

/// THE MCP PLANE'S TEST-KIT (feature `test-support` only), forwarded from the host crate so
/// `busbar_mcp::testkit::…` resolves under the same feature it always did.
#[cfg(feature = "test-support")]
pub use busbar_plane_mcp_host::testkit;

/// MCP'S PLANE DECLARATION — the `&'static PlaneDecl` the composition root installs at boot, forwarded
/// so the `busbar` binary names one stable path (`busbar_mcp::PLANE_DECL`).
pub use busbar_plane_mcp_host::PLANE_DECL;

/// MCP'S PLANE-CONTRIBUTED DIAGNOSTICS — the `&'static [&'static Diagnostic]` the composition root
/// hands to `busbar_substrate::diagnostics::install_diagnostics` at boot, forwarded so the `busbar`
/// binary names one stable path (`busbar_mcp::DIAGNOSTICS`).
pub use busbar_plane_mcp_host::DIAGNOSTICS;

/// MCP'S PROTOCOL DECLARATION — the `&'static ProtocolDecl` the composition root installs, forwarded
/// so the `busbar` binary names one stable path (`busbar_mcp::PROTO_DECL`).
pub use busbar_plane_mcp_host::PROTO_DECL;
