// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Slots: the one token table, shared by chains and sessions, and the plugin instance the shims build
//! (IF §6.5, r35). The table, `pack`/`unpack`, `Inst` and the chain box moved into busbar-ffi, where their
//! `unsafe` is pinned (UNSAFE-MIN r3.1); this module keeps the frozen path and re-exports them. The chain
//! poll guard and `CURRENT` moved with them (`busbar_ffi::ChainBytes` reads them), so the stub `bridge`
//! module is gone.

#[doc(hidden)]
pub use busbar_ffi::{ChainBox, ChainRef, Inst, OwnedSlot, Slots, pack, unpack};
