// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE PLACE A CORE TOKIO RUNTIME IS BUILT (LINT-RULES R40 `per-request-task`).
//!
//! Every core runtime starts from one of these builders, so the per-request work-count gate has
//! one seam to count the tasks each request spawns (PER-REQUEST-WORK-INVENTORY §8.1). The source
//! rule `rt_builders_only_in_rt` (busbar-contract `tests/source_rules`) fails on any core runtime
//! built anywhere else.

/// A current-thread runtime builder.
#[must_use]
pub fn current_thread() -> tokio::runtime::Builder {
    tokio::runtime::Builder::new_current_thread()
}

/// A multi-thread runtime builder.
#[must_use]
pub fn multi_thread() -> tokio::runtime::Builder {
    tokio::runtime::Builder::new_multi_thread()
}

/// The runtime these builders build. A core holder names it here (R40): every core runtime is
/// still built only by [`current_thread`] or [`multi_thread`].
pub type Runtime = tokio::runtime::Runtime;
