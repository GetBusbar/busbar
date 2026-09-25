// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `EgressPrep` — the resolved-primitives param bag a cross-protocol egress hop threads into a
//! request handle, and a lane's declared request-shape capabilities (`LaneCaps`, `MaxOutputKey`).
//!
//! A SHAPE (DECISIONS #83: contract = shapes): the definitions moved, module-path-only, to
//! `busbar_contract::ir::egress_prep` (SD-1 of the #83a split). This module re-exports every item under its
//! historical `busbar_substrate_values::ir::egress_prep` path, so every caller compiles unchanged.

pub use busbar_contract::ir::egress_prep::*;
