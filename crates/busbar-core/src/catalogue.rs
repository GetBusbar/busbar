// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Re-export shim. THE CATALOGUE — the "what may this caller SEE" walk and its judgement — moved
//! DOWN into `busbar-substrate` in Phase-B B1; this module re-exports it (glob) so every
//! `crate::catalogue::…` name resolves unchanged and hosts the core-only catalogue tests, which name
//! `crate::trust::validate::validate_visibility` (resolved here through core's own `trust::validate`
//! re-export).

// The catalogue serves whichever protocol planes are installed and nothing else; with none installed
// the glob re-export names nothing any in-core caller uses, exactly as the pre-split module read dead
// there. `unused_imports` rather than `dead_code` because this is now a re-export; unconditional (the
// neutral seam names no plane feature — the re-export is public API whichever planes are compiled in).
#![allow(unused_imports)]

pub use busbar_substrate::catalogue::*;

#[cfg(test)]
#[path = "tests/catalogue_tests.rs"]
mod catalogue_tests;
