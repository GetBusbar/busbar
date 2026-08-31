// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The lifecycle SCOPES a plane's host handles live at — RELOCATED to
//! [`busbar_substrate::plane_host::scope`], re-exported here so in-core call sites are unchanged.
//!
//! The scope types ([`DispatchScope`], [`DurableScope`], [`SessionScope`] and their supporting
//! `SettleAdmission` / `EgressFaultDetail` vocabulary) name only [`busbar_plugin::hot`] + `std`, so
//! they are neutral and now live in the substrate. This module re-exports them unchanged, so every
//! in-core call site (`plane_host`'s own veneers, `a2a`) and the host `HostState` that materializes
//! over a `DispatchScope` are untouched — the move is a pure relocation, not a code change.

pub use busbar_substrate::plane_host::scope::*;
