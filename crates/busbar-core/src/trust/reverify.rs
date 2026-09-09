// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Re-export shim. THE RE-VERIFICATION CADENCE moved DOWN into `busbar-substrate` in Phase-B B1;
//! this module re-exports it (glob) so every `crate::trust::reverify::…` name resolves unchanged.
//! The core-only re-verification battery it used to host moved to `plane_host/trust.rs`, beside the
//! one core funnel for the `due` arithmetic it drives (D33 §7.5).

pub use busbar_substrate::trust::reverify::*;
