// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TRANSPORT KIND'S ABI: its version and its table (the design's locked plugin ABI: one
//! mechanism, every shape in `abi/`). Only the skeleton lands in M0 — the table is the shared
//! lifecycle head; the kind's own operations and data shapes are appended here in M3.

use super::mechanism::lifecycle::OpsHead;

/// The transport kind's ABI version: new in 1.6.0 (v1.5.5 had no transport kind ABI), so it ships `1`.
pub const ABI_VERSION: u32 = 1;

/// The transport kind's ops table. Leads with the shared [`OpsHead`]; the kind's own slots follow it.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Ops {
    /// The lifecycle.
    pub head: OpsHead,
}
