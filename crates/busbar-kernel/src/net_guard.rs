// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Re-export shim. THE GUARDED FETCH and its pure network-address primitives moved DOWN into the
//! neutral `busbar-substrate` crate in Phase-B B0-b; every in-core call site keeps naming
//! `crate::net_guard::…` unchanged through this glob.

pub use busbar_substrate::net_guard::*;
