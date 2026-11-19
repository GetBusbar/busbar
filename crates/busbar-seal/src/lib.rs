// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The capability seals and the one place they are minted.
//!
//! **Why this is a crate of its own.** It holds a key and nothing else. [`KernelSeal`] mints every
//! capability token (`busbar_contract::caps::{Pass, Grant, CallId}`) and [`SlotSeal`] mints every
//! slotted commit key. Rust cannot say "this public function may be called by one other crate", but
//! it can say "a crate that does not list this one in its manifest cannot name it". So the mint is
//! two FREE functions, [`mint_kernel`] and [`mint_slot`], in a crate only two manifests may list:
//!
//! - `busbar-kernel`, which mints (its `seal` and `persistence` modules call the two functions);
//! - `busbar-contract`, which defines the tokens the seals mint and re-exports the two TYPES only.
//!   A re-exported type carries its associated functions with it, a free function does not, so
//!   `busbar_contract::caps::KernelSeal` gives a caller a name for the seal and no way to make one.
//!
//! The rule that keeps the manifests honest is the `busbar-seal` row of `deny.toml`
//! (`wrappers = ["busbar-contract", "busbar-kernel"]`, cargo-deny's bans) and the test
//! `only_the_named_crates_may_depend_on_the_seal_and_the_kernel` in `tools/ci-checks`, which walks
//! every manifest in the repository and fails if any other one names this crate, or if the row
//! changes. Every other crate cannot mint: the compiler refuses the name (`busbar-ports` holds the
//! `compile_fail` fixture).
//!
//! Without that row this crate is bloat; with it, it is the only thing between "depends on the
//! contract" and "can mint a capability". Do not add anything here that is not a seal.
//!
#![cfg_attr(not(feature = "test-seal"), doc = include_str!("no_release_seal.md"))]
#![forbid(unsafe_code)]
#![doc(test(attr(forbid(unsafe_code))))]
#![deny(missing_docs)]
#![deny(missing_debug_implementations)]

/// The proof that the caller is the kernel: every `Pass`, `Grant` and `CallId` is minted with one.
/// Neither `Clone` nor `Copy`, and its field is private: [`mint_kernel`] is the only constructor.
pub struct KernelSeal(());

/// The persistence facade's authority to mint slotted commit keys. Neither `Clone` nor `Copy`, and
/// its field is private: [`mint_slot`] is the only constructor.
pub struct SlotSeal(());

/// Mint a kernel seal. Only a crate that lists `busbar-seal` in its manifest can name this.
#[must_use]
pub fn mint_kernel() -> KernelSeal {
    KernelSeal(())
}

/// Mint a slot seal. Only a crate that lists `busbar-seal` in its manifest can name this.
#[must_use]
pub fn mint_slot() -> SlotSeal {
    SlotSeal(())
}

impl KernelSeal {
    /// A seal for TESTS. It exists only under the dev-only `test-seal` feature, which
    /// `busbar-contract/tests/test_seal_is_dev_only.rs` keeps off every non-dev dependency edge, so
    /// no release build has it (`busbar-contract`'s `fixtures/no_release_seal.md` is the
    /// `compile_fail` proof).
    #[doc(hidden)]
    #[cfg(feature = "test-seal")]
    #[must_use]
    pub fn acquire_for_kernel() -> Self {
        mint_kernel()
    }
}

impl SlotSeal {
    /// A slot seal for TESTS; the same dev-only `test-seal` feature as
    /// [`KernelSeal::acquire_for_kernel`].
    #[doc(hidden)]
    #[cfg(feature = "test-seal")]
    #[must_use]
    pub fn acquire_for_tests() -> Self {
        mint_slot()
    }
}

impl std::fmt::Debug for KernelSeal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KernelSeal")
    }
}

impl std::fmt::Debug for SlotSeal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SlotSeal")
    }
}

#[cfg(test)]
mod tests {
    /// The seals carry no data: minting one costs nothing and allocates nothing.
    #[test]
    fn both_seals_have_no_size() {
        assert_eq!(std::mem::size_of::<super::KernelSeal>(), 0);
        assert_eq!(std::mem::size_of::<super::SlotSeal>(), 0);
        assert_eq!(format!("{:?}", super::mint_kernel()), "KernelSeal");
        assert_eq!(format!("{:?}", super::mint_slot()), "SlotSeal");
    }
}
