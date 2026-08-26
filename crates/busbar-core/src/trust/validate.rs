// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ORDERED REQUEST VALIDATOR — its transport-neutral half lives in
//! [`busbar_substrate::trust::validate`], and as of D3 so does the standing-permission primitive
//! [`Standing`] (with [`Snapshot`], [`Lapsed`] and the [`GovResolve`] re-resolution trait). This
//! module re-exports that half unchanged so every `crate::trust::validate::*` call site resolves as
//! before, and supplies the ONE core-side piece the neutral primitive needs: the [`GovResolve`] impl
//! over [`crate::governance::GovState`], which re-resolves a principal by id against the live
//! registry. `Standing::still_permitted` drives that impl, so the primitive names no core type.

use std::sync::Arc;

use busbar_api::VirtualKey;

// Glob, so a name only a plane consumer or a test uses (e.g. `reason`, `Ask`, `Standing`, `Lapsed`)
// never reads as an unused import when that consumer is compiled out. The standing-permission types
// (`Standing`/`Snapshot`/`Lapsed`/`GovResolve`) now arrive through this glob from the substrate.
pub use busbar_substrate::trust::validate::*;

/// Core-side [`GovResolve`]: re-resolve a principal by its stable subject id against the LIVE
/// governance registry. This is the one core capability a [`Standing`] re-ask needs; threading it as
/// a trait keeps the standing primitive itself transport-neutral (it holds an `id`, re-asks through
/// this, and never names `GovState`). An in-memory index read — no store round trip, nothing to
/// await — exactly as the pre-relocation `Standing::still_permitted` performed inline.
impl GovResolve for crate::governance::GovState {
    fn resolve_by_sub(&self, sub: &str) -> Option<Arc<VirtualKey>> {
        self.lookup_by_sub(sub)
    }
}

#[cfg(test)]
#[path = "tests/validate_tests.rs"]
mod validate_tests;
