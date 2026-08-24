// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Re-export shim. THE CATALOGUE — the "what may this caller SEE" walk and its judgement — moved
//! DOWN into `busbar-substrate` in Phase-B B1; this module re-exports it (glob) so every
//! `crate::catalogue::…` name resolves unchanged and hosts the core-only catalogue tests, which name
//! `crate::trust::validate::validate_visibility` (resolved here through core's own `trust::validate`
//! re-export).

// The catalogue serves the MCP and/or A2A plane and nothing else; with BOTH compiled out the glob
// re-export names nothing any in-core caller uses, exactly as the pre-split module read dead there.
// Same cfg the original carried, `unused_imports` rather than `dead_code` because this is now a
// re-export.
#![cfg_attr(
    not(any(feature = "plane-mcp", feature = "plane-a2a")),
    allow(unused_imports)
)]

pub(crate) use busbar_substrate::catalogue::*;

#[cfg(test)]
#[path = "tests/catalogue_tests.rs"]
mod catalogue_tests;
