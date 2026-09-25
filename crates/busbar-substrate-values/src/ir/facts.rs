// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `ir::facts` — THE ONE PROJECTION. What the shared pipeline is allowed to know about a request,
//! read from the IR and from nothing else.
//!
//! A SHAPE (DECISIONS #83: contract = shapes): the definitions moved, module-path-only, to
//! `busbar_contract::ir::facts` (SD-1 of the #83a split). This module re-exports every item under its
//! historical `busbar_substrate_values::ir::facts` path, so every caller compiles unchanged.

pub use busbar_contract::ir::facts::*;
