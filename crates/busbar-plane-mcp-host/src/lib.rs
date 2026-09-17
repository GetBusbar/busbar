// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! busbar-plane-mcp-host — the MCP plane's IMPURE HOST crate.
//!
//! The fat `busbar-mcp` splits four ways (DECISIONS #19/#20/#21/#1): the pure wire codec
//! (`busbar-mcp-codec`), the shared transport crates, the purity-scanned contract adapter
//! (`busbar-plane-mcp`), and THIS crate — the impure, bridged-ABI host that holds the substrate
//! `PlaneDecl` (`PLANE_DECL`), the runtime slot (`McpResource`/`McpRuntime`), `serve_stdio`, the
//! plane test-kit, the plane-contributed diagnostics and the engine glue. `busbar-mcp` the NAME
//! ultimately drains into here and is deleted.
//!
//! ## What lives here today
//!
//! The MCP plane's DIAGNOSTICS catalog — the `MCP_*` entries the composition root installs via
//! [`install_diagnostics`](busbar_substrate::diagnostics::install_diagnostics). This is the one
//! byte-safe, non-money, cycle-free leaf of the host surface: it names nothing in `busbar-mcp`, so it
//! moves down here cleanly while `busbar-mcp` re-exports it under its old paths
//! (`busbar_mcp::DIAGNOSTICS`, `busbar_mcp::diagnostics::…`) so every caller resolves what it always
//! did.
//!
//! ## What does NOT live here yet, and why
//!
//! The rest of the host surface — `PLANE_DECL`, `McpResource`, `McpRuntime`, `serve_stdio`, the
//! test-kit, and the `config`/`callerask`/`envelope`/`admin_view` modules — is a single
//! strongly-connected component welded to the money files (`busbar-mcp`'s `method.rs`,
//! `sampling.rs`): `method.rs` reaches `super::runtime_of`, `super::config`, `super::envelope`,
//! `super::callerask`, and `McpRuntime` holds a `sampling::SamplingSpend`. It cannot leave
//! `busbar-mcp` byte-safely while the money files stay — so it moves as one unit in the oracle-gated
//! money cell, not this byte-safe one.

/// THE MCP PLANE'S DIAGNOSTICS CATALOG — the `MCP_*` entries this plane owns and the [`DIAGNOSTICS`]
/// slice the composition root installs. Relocated here from `busbar-mcp/src/diagnostics.rs` byte for
/// byte; `busbar-mcp` re-exports the module under its old path.
pub mod diagnostics;

/// The plane-contributed diagnostics slice, re-exported at the crate root so the `busbar` binary — and
/// `busbar-mcp`, which re-exports it onward — names one stable path.
pub use diagnostics::DIAGNOSTICS;
