// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The persistence facade's sealed authority to mint slotted commit keys.
//!
//! A slotted [`CommitKey`](crate::persistence::CommitKey) names a queue position that only the
//! kernel's persistence facade leases. The key constructor therefore takes a [`SlotSeal`]. The type
//! is defined in `busbar-seal` and re-exported here; its only constructor is the free function
//! `busbar_seal::mint_slot`, which only a crate listing `busbar-seal` in its manifest can name (the
//! kernel; see [`crate::caps::token`] for the rule that holds the manifests to that). Every other
//! crate (migrations, the loader, plugins) cannot make a slotted commit.

pub use busbar_seal::SlotSeal;
