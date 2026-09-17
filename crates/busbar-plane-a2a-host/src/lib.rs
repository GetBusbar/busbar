// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! busbar-plane-a2a-host — the A2A plane's IMPURE HOST crate.
//!
//! The fat `busbar-a2a` splits (mirroring busbar-mcp's four-way collapse, DECISIONS #19/#20/#21/#1):
//! the pure wire codec (`busbar-a2a-codec`), the shared transport crates, the purity-scanned
//! contract adapter (`busbar-plane-a2a`), and THIS crate — the impure, bridged-ABI host that holds
//! the substrate `PlaneDecl` (`PLANE_DECL`), the runtime slot (the `A2aPlane` runtime), `serve`, the
//! plane test-kit, the plane-contributed diagnostics and the engine glue. `busbar-a2a` the NAME
//! ultimately drains into here and is deleted.
//!
//! ## What lives here today
//!
//! The A2A plane's DIAGNOSTICS catalog — the `A2A_*` entries the composition root installs via
//! [`install_diagnostics`](busbar_substrate::diagnostics::install_diagnostics). This is the one
//! byte-safe, non-money, cycle-free leaf of the host surface: it names nothing in `busbar-a2a`, so it
//! moves down here cleanly while `busbar-a2a` re-exports it under its old paths
//! (`busbar_a2a::DIAGNOSTICS`, `busbar_a2a::diagnostics::…`) so every caller resolves what it always
//! did.
//!
//! ## What does NOT live here yet, and why
//!
//! The rest of the host surface — `PLANE_DECL`, the `A2aPlane` runtime slot, `serve`, the test-kit,
//! and the `receive`/`inbound` admission path with its `config`/`admin_view` modules — is a single
//! strongly-connected component welded to the money/receive files: `receive.rs` reaches
//! `meter_charge`, `run_gauntlet`, `GauntletPlane`/`A2aInvokePlane`, and the private
//! `inbound::Dispatch` admission struct that the §11a audit flags for the shared `PlaneDecl::dispatch`
//! seam. It cannot leave `busbar-a2a` byte-safely while the money files stay — so it moves as one unit
//! in the oracle-gated money cell, not this byte-safe one.

/// THE A2A PLANE'S DIAGNOSTICS CATALOG — the `A2A_*` entries this plane owns and the [`DIAGNOSTICS`]
/// slice the composition root installs. Relocated here from `busbar-a2a/src/diagnostics.rs` byte for
/// byte; `busbar-a2a` re-exports the module under its old path.
pub mod diagnostics;

/// The plane-contributed diagnostics slice, re-exported at the crate root so the `busbar` binary — and
/// `busbar-a2a`, which re-exports it onward — names one stable path.
pub use diagnostics::DIAGNOSTICS;
