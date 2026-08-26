// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `EgressPrep` — the resolved-primitives param bag the cross-protocol request seam threads into
//! `IrHandle::prepare_for_egress`. NEUTRAL: every field is a primitive — it names ZERO concrete LLM
//! IR — and the core driver (`proxy/wire.rs`) is what *constructs* it from lane config.
//!
//! The type DEFINITION RELOCATED to `busbar-substrate` (`busbar_substrate::ir::egress_prep`) at
//! Batch C-1 so a plane crate names it without reaching into `busbar-core`; core re-exports it from
//! this historical path (`crate::ir::egress_prep::EgressPrep`) so every in-core caller is unchanged.

pub use busbar_substrate::ir::egress_prep::EgressPrep;
