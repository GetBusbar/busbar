// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The persistence facade's sealed authority to mint slotted commit keys.
//!
//! A slotted [`CommitKey`](crate::persistence::CommitKey) names a queue position that
//! only the kernel's persistence facade leases. The key constructor therefore takes a
//! [`SlotSeal`], and the only release-build source of one is [`SlotSeal::deliver`],
//! which hands it to `__busbar_persistence_root`: a symbol that only
//! `busbar-kernel::persistence` defines, wrapping the seal in a holder no other crate
//! can name. Every other crate (migrations, the loader, plugins) holds at most the
//! boxed holder it cannot open, so it cannot make a slotted commit.

/// Root token for minting slotted commit keys. Not `Clone`, never lent by value.
pub struct SlotSeal(());

impl SlotSeal {
    /// Hand a seal to the persistence facade's root symbol, and to nothing else.
    ///
    /// `#[inline]` so the symbol is referenced only by the crate that calls this.
    #[doc(hidden)]
    #[inline]
    #[must_use]
    pub fn deliver() -> Box<dyn std::any::Any + Send + Sync> {
        crate::abi::persistence_root(Self(()))
    }

    /// Test-only seal; the `test-seal` feature is enabled only by dev-dependencies.
    #[doc(hidden)]
    #[cfg(any(test, feature = "test-seal"))]
    #[must_use]
    pub fn acquire_for_tests() -> Self {
        Self(())
    }
}

impl std::fmt::Debug for SlotSeal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SlotSeal")
    }
}
