// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SUBSCRIBE IR data — the `Operation::SUBSCRIBE` request/response pair and its `IrFacts` walk.
//!
//! A SHAPE (DECISIONS #83: contract = shapes): the definitions moved, module-path-only, to
//! `busbar_contract::ir::subscribe` (SD-1 of the #83a split). This module re-exports every item under its
//! historical `busbar_substrate_values::ir::subscribe` path, so every caller compiles unchanged.

pub use busbar_contract::ir::subscribe::*;
