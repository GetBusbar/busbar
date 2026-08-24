// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Re-export shim. THE EGRESS GATE moved DOWN into `busbar-substrate` in Phase-B B1; this module
//! re-exports it (glob) so every `crate::egress_auth::gate::…` name resolves unchanged and hosts the
//! core-only gate tests, which name `crate::admin::audit` and `crate::audit`.

// The gate serves the MCP and A2A egress paths and nothing else; with BOTH compiled out the glob
// re-export names nothing any in-core caller uses, exactly as the pre-split module read dead there.
#![cfg_attr(
    not(any(feature = "plane-mcp", feature = "plane-a2a")),
    allow(unused_imports)
)]

pub(crate) use busbar_substrate::egress_auth::gate::*;

#[cfg(test)]
#[path = "tests/gate_tests.rs"]
mod gate_tests;
