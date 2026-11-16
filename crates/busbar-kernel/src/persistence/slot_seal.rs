// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The persistence facade's private holder of the slotted-key root token
//! (STORE-TRANSACTIONS decision 164). `busbar-kernel::persistence` defines the root
//! symbol; the holder type is private here, so no other crate can open the box the
//! contract hands out.

use busbar_contract::caps::SlotSeal;
use busbar_contract::persistence::CommitKey;

#[cfg(not(test))]
struct Held(SlotSeal);

#[cfg(not(test))]
fn acquire() -> SlotSeal {
    match SlotSeal::deliver().downcast::<Held>() {
        Ok(held) => {
            let Held(seal) = *held;
            seal
        }
        Err(_) => unreachable!("the persistence root returned a foreign holder"),
    }
}

/// The root symbol `busbar_contract::caps::SlotSeal::deliver` calls. Defined exactly once.
#[cfg(not(test))]
#[allow(unsafe_code)]
#[no_mangle]
pub fn __busbar_persistence_root(seal: SlotSeal) -> Box<dyn std::any::Any + Send + Sync> {
    Box::new(Held(seal))
}

#[cfg(test)]
fn acquire() -> SlotSeal {
    SlotSeal::acquire_for_tests()
}

static SEAL: std::sync::LazyLock<SlotSeal> = std::sync::LazyLock::new(acquire);

/// Mint the key of one leased queue slot. Only the facade leases slots.
pub(in crate::persistence) fn slotted(slot: u32, seq: u64) -> Option<CommitKey> {
    CommitKey::slotted(slot, seq, &SEAL)
}
