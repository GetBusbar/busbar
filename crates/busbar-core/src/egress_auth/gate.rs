// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Re-export shim. THE EGRESS GATE moved DOWN into `busbar-substrate` in Phase-B B1; this module
//! re-exports it (glob) so every `crate::egress_auth::gate::…` name resolves unchanged and hosts the
//! core-only gate tests, which name `crate::admin::audit` and `crate::audit`.

// This outbound trust/egress auth gate is served only by a trust-fronting plane; with none such
// compiled in the glob re-export names nothing any in-core caller uses, exactly as the pre-split
// module read dead there. Gated on the neutral `egress-auth-gate` CAPABILITY marker (naming a
// capability, not a plane, per plane-purity §2.1) — enabled transitively by `plane-mcp`/`plane-a2a`,
// so `not(feature = "egress-auth-gate")` is byte-identical to the original
// `not(any(feature = "plane-mcp", feature = "plane-a2a"))` gate this replaced.
#![cfg_attr(not(feature = "egress-auth-gate"), allow(unused_imports))]

pub use busbar_substrate::egress_auth::gate::*;

#[cfg(test)]
#[path = "tests/gate_tests.rs"]
mod gate_tests;
