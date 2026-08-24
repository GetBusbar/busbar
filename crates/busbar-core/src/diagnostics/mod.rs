// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The diagnostics catalog: every operator-facing `warn!`/`error!` carries a stable
//! `BUSBAR-NNNN` code an operator can paste into the docs and land on an entry that says what
//! it means, whether it needs action, and what to do.
//!
//! The catalog itself — [`Class`], [`Severity`], [`Diagnostic`], [`Banner`], [`REGISTRY`],
//! [`by_code`], and the `docs/diagnostics.{md,json}` renderers — now lives in the neutral
//! `busbar-substrate` crate and is re-exported here unchanged, so every in-core call site keeps
//! using `crate::diagnostics::…`. What stays local to core are the emit macros, because a
//! `macro_rules!` macro cannot be re-exported across a crate boundary without `#[macro_export]`
//! polluting the crate root, and the coverage lint that scans core's own tree.
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

pub use busbar_substrate::diagnostics::*;

#[cfg(test)]
mod tests;

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Emit macros. `pub(crate)` — internal to busbar-core (a `macro_rules!` macro cannot be re-exported
// across crates via `pub use` without `#[macro_export]`, which would pollute the crate root). The
// `busbar` bin therefore emits coded diagnostics with the equivalent banner form directly:
// `tracing::warn!(diag = %busbar_core::diagnostics::CONST.banner(), <fields>, "msg")`. Sites in this
// crate use `use crate::diagnostics::diag_warn;`.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// `warn!` carrying the `diag = "BUSBAR-NNNN"` field. First arg is the [`Diagnostic`] const.
macro_rules! diag_warn {
    ($diag:expr, $($rest:tt)*) => {
        ::tracing::warn!(diag = %$diag.banner(), $($rest)*)
    };
}
/// `error!` carrying the `diag = "BUSBAR-NNNN"` field.
macro_rules! diag_error {
    ($diag:expr, $($rest:tt)*) => {
        ::tracing::error!(diag = %$diag.banner(), $($rest)*)
    };
}
/// `debug!` carrying the `diag = "BUSBAR-NNNN"` field (the benign-recurring / latched-quiet arm).
macro_rules! diag_debug {
    ($diag:expr, $($rest:tt)*) => {
        ::tracing::debug!(diag = %$diag.banner(), $($rest)*)
    };
}
pub(crate) use {diag_debug, diag_error, diag_warn};
