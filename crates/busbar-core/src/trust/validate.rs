// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ORDERED REQUEST VALIDATOR — its transport-neutral half lives in
//! [`busbar_substrate::trust::validate`], and as of D3 so does the standing-permission primitive
//! [`Standing`] (with [`Snapshot`], [`Lapsed`] and the [`GovResolve`] re-resolution trait). This
//! module re-exports that half unchanged so every `crate::trust::validate::*` call site resolves as
//! before.
//!
//! The core-side [`GovResolve`] impl over `GovState` USED to live here. It now lives beside the
//! state it resolves against, in [`crate::governance`] — the orphan rule puts it in core (the trait
//! is the substrate's, the type is core's), and `lookup_by_sub` is the governance module's own.

// Glob, so a name only a plane consumer or a test uses (e.g. `reason`, `Ask`, `Standing`, `Lapsed`)
// never reads as an unused import when that consumer is compiled out. The standing-permission types
// (`Standing`/`Snapshot`/`Lapsed`/`GovResolve`) now arrive through this glob from the substrate.
pub use busbar_substrate::trust::validate::*;
