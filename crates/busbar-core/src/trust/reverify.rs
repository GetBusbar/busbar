// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Re-export shim. THE RE-VERIFICATION CADENCE moved DOWN into `busbar-substrate` in Phase-B B1;
//! this module re-exports it (glob) so every `crate::trust::reverify::…` name resolves unchanged and
//! hosts the core-only re-verification tests, which name `crate::a2a::pin`.

pub use busbar_substrate::trust::reverify::*;

#[cfg(test)]
#[path = "tests/reverify_tests.rs"]
mod reverify_tests;
