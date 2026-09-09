// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Re-export shim. VERIFY-ON-CALL — the lazy single-flight freshness gate — relocated DOWN into the
//! neutral `busbar-substrate` crate so the extracted plane crates (busbar-mcp) can NAME it without
//! reaching back into core. It depends only on the (already-neutral) `trust::reverify` arithmetic and
//! the substrate diagnostics, so nothing about it needed to stay in core.
//!
//! This module re-exports the relocated [`VerifyGate`] so every in-core call site — the A2A plane's
//! `crate::trust::verify::VerifyGate` field, its `ensure_fresh`/`report`/`retain` drivers, and the
//! carry tests — keeps naming `crate::trust::verify::*` unchanged. The gate's unit batteries went
//! DOWN with it (D33 §7.5): they name only `VerifyGate` and the `reverify` arithmetic beside it and
//! never a core type, so they were always substrate proofs, and they now live beside the gate.

pub use busbar_substrate::trust::VerifyGate;
