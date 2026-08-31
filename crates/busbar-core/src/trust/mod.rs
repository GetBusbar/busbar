// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Re-export shim. THE TRUST VALUE FAMILIES and the two transport-neutral DECISION ENGINES
//! (`declared`, `reverify`, and the ordered request validator's neutral half) moved DOWN into the
//! neutral `busbar-substrate` crate in Phase-B B1; every in-core call site keeps naming
//! `crate::trust::…` unchanged through the re-exports below.
//!
//! What stays in core is the part that names a core type: the `GovState`-facing standing-permission
//! primitive ([`validate::Standing`]). The verify-on-call gate ([`verify::VerifyGate`]) has since
//! moved DOWN into substrate too — it depends only on the neutral `reverify` arithmetic and the
//! substrate diagnostics — and is re-exported below so its in-core (A2A) call sites are unchanged. The
//! dependency is one-directional: substrate never names a core type.

// NO PRODUCTION CALLER for some of these yet (the standing-permission `Snapshot::PinnedTo` is
// exercised only by tests until a poll-loop caller lands), landed ahead of one deliberately — the
// same posture the pre-split trust module carried. This module-level allowance propagated to the
// child modules then and does so now; it keeps the STAY halves (`validate::Standing`, `verify`) from
// reading dead when a consumer is compiled out, exactly as before B1.
#![cfg_attr(not(test), allow(dead_code))]

// THE VALUE FAMILIES — `PinnedArtifact`, `CapabilityApproval`, `Observation`, `Sighting`,
// `TrustState`, `Drift`, `TrustError`, `Approval` — relocated to substrate; this glob keeps every
// `crate::trust::X` path resolving. Glob (not an explicit list) so the re-export never reads as an
// unused import when a plane consumer is compiled out.
pub use busbar_substrate::trust::*;

// THE ORDERED REQUEST VALIDATOR — its neutral half is in substrate and re-exported here; the core
// half (`Standing`/`Snapshot`/`Lapsed`, which read `crate::governance::GovState`) lives in this
// module. An explicit `mod validate` shadows the glob-imported substrate `validate` above.
pub mod validate;

// VERIFY-ON-CALL — relocated to substrate (it names only the neutral `reverify` arithmetic and the
// substrate diagnostics). A thin core shim (`trust/verify.rs`) re-exports the gate so
// `crate::trust::verify::VerifyGate` resolves unchanged for the A2A plane, and keeps the gate's own
// plane-neutral batteries at home in core. `pub` (like the sibling `validate`/`reverify` shims) so it
// matches the visibility of the substrate `verify` module the glob above re-exports.
pub mod verify;

/// The verify-on-call gate type, re-exported so an EXTRACTED plane crate (busbar-mcp) names
/// `busbar_substrate::trust::VerifyGate` while the in-core A2A plane keeps `crate::trust::verify::
/// VerifyGate`. Each plane OWNS its own coalescer on its per-generation runtime object (MCP folds it
/// into `busbar_mcp::mcp::McpRuntime`, reached via `ctx.slot`; A2A rides it on the `App`).
pub use verify::VerifyGate;

/// THE RE-VERIFICATION CADENCE — relocated to substrate in Phase-B B1. A thin core module (`trust/
/// reverify.rs`, rather than a bare `use`) so `crate::trust::reverify::*` resolves unchanged AND the
/// core-only re-verification tests, which name `busbar_a2a::a2a::pin`, keep their home in core. An
/// explicit `mod reverify` shadows the glob-imported substrate `reverify` above.
pub mod reverify;
