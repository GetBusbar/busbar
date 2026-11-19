// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The persistence facade's mint of slotted commit keys (STORE-TRANSACTIONS decision 164). The slot
//! seal comes from `busbar_seal::mint_slot`, which only a crate that lists `busbar-seal` can name,
//! so no crate but the kernel can make a slotted commit key; inside the kernel this is the one call,
//! private to the persistence facade. The seal has no size: minting one per key allocates nothing.

use busbar_contract::persistence::CommitKey;

/// Mint the key of one leased queue slot. Only the facade leases slots.
pub(in crate::persistence) fn slotted(slot: u32, seq: u64) -> Option<CommitKey> {
    CommitKey::slotted(slot, seq, &busbar_seal::mint_slot())
}
