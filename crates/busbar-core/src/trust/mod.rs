// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! RETIRING re-export shim (D33 wave 5, row `trust/`). THE TRUST VALUE FAMILIES and the
//! transport-neutral DECISION ENGINES (`declared`, `reverify`, `verify`, and the ordered request
//! validator's neutral half) live in the neutral `busbar-substrate` crate. Core declares no trust
//! value and no trust decision of its own.
//!
//! Every in-core caller was repointed at `busbar_substrate::trust::…` directly, and the verify-on-call
//! shim was DELETED with its 621 lines of plane-neutral battery, which travelled verbatim to sit
//! beside `VerifyGate` in `busbar-substrate/src/trust/tests/`. What is left below is not a spelling;
//! it is the two pieces that CANNOT leave core yet, each for a stated reason:
//!
//! - [`validate`] carries `impl GovResolve for crate::governance::GovState`. The trait is substrate's
//!   and the type is core's, so the orphan rule fixes the impl in core: it can only move when
//!   `governance::GovState` does. Its battery additionally names `crate::audit::vocab`.
//! - [`reverify`] hosts the re-verification tests, which name `busbar_a2a::a2a::pin`. Substrate must
//!   not depend on a plane crate, so they cannot travel there; they move when the A2A pin walk lands
//!   in `busbar-unit-trust`.

// NO PRODUCTION CALLER for some of these yet (the standing-permission `Snapshot::PinnedTo` is
// exercised only by tests until a poll-loop caller lands), landed ahead of one deliberately — the
// same posture the pre-split trust module carried. This module-level allowance propagated to the
// child modules then and does so now; it keeps the STAY half (`validate::Standing`) from reading dead
// when a consumer is compiled out, exactly as before B1.
#![cfg_attr(not(test), allow(dead_code))]

// THE VALUE FAMILIES — `PinnedArtifact`, `CapabilityApproval`, `Observation`, `Sighting`,
// `TrustState`, `Drift`, `TrustError`, `Approval` — live in substrate. This glob remains only so the
// two surviving child modules' own batteries keep resolving `crate::trust::X`; it has no production
// consumer left in this crate and goes with them.
pub use busbar_substrate::trust::*;

// THE ORDERED REQUEST VALIDATOR — its neutral half is in substrate; the ONE core-side piece is the
// orphan-rule-bound `GovResolve` impl over `crate::governance::GovState`. An explicit `mod validate`
// shadows the glob-imported substrate `validate` above.
pub mod validate;

/// THE RE-VERIFICATION CADENCE — in substrate. This module survives only to host the core-only
/// re-verification tests, which name `busbar_a2a::a2a::pin`. An explicit `mod reverify` shadows the
/// glob-imported substrate `reverify` above.
pub mod reverify;
