// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The diagnostics catalog: every operator-facing `warn!`/`error!` carries a stable
//! `BUSBAR-NNNN` code an operator can paste into the docs and land on an entry that says what
//! it means, whether it needs action, and what to do.
//!
//! The catalog itself — [`Class`], [`Severity`], [`Diagnostic`], [`Banner`], [`REGISTRY`],
//! [`by_code`], and the `docs/diagnostics.{md,json}` renderers — AND the `diag_warn!`/`diag_error!`/
//! `diag_debug!` emit macros now live in the neutral pure-half `busbar-substrate-values` crate
//! (§11a #19 deletion-wave; they had been duplicated here as crate-local twins). This module is a
//! byte-safe re-export shim so every in-core call site keeps using `crate::diagnostics::…`. What
//! stays local to core is only the coverage lint that scans core's own tree (see [`tests`]).
//!
//! ## Emitting
//!
//! Use [`diag_warn!`], [`diag_error!`], [`diag_debug!`] instead of the bare `tracing` macros. They
//! attach the `diag = "BUSBAR-NNNN"` field so the code shows in every line and is greppable:
//!
//! ```ignore
//! use crate::diagnostics::{diag_warn, DURABLE_WRITETHROUGH_BELOW_FLOOR};
//! diag_warn!(DURABLE_WRITETHROUGH_BELOW_FLOOR, seq, durable_floor, "seq predates the durable floor");
//! ```

// The catalog (consts, `Class`/`Severity`/`Diagnostic`/`Banner`, `REGISTRY`, `by_code`, the doc
// renderers). Glob of the DIAGNOSTICS MODULE only — the `#[macro_export]` emit macros are hoisted to
// the substrate-values crate ROOT, not this module, so this glob never carries them (nothing to
// shadow / no crate-root pollution).
pub use busbar_substrate_values::diagnostics::*;

// The three emit macros, re-exported at their historical `crate::diagnostics::…` path so every
// in-crate `use crate::diagnostics::diag_warn;` caller is unchanged. `#[macro_export]` in
// substrate-values put them at THAT crate's root, so they are named there (not under `diagnostics`).
// The expansion is byte-identical to core's retired copies (`::tracing::warn!(diag = %DIAG.banner(),
// …)`); core supplies `tracing` at the call site exactly as before.
pub use busbar_substrate_values::{diag_debug, diag_error, diag_warn};

#[cfg(test)]
mod tests;
