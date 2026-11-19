// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The kernel's capability seal. The kernel mints it with `busbar_seal::mint_kernel`, which only a
//! crate that lists `busbar-seal` can name (the kernel and the contract; `deny.toml` and
//! `tools/ci-checks` hold the manifests to that).
//!
//! This module is public, so every crate that lists `busbar-kernel` can obtain a seal through it:
//! the composition roots (`busbar`, `busbar-default`), core's own crates (`busbar-core-admin`,
//! `busbar-core-connector`, `busbar-core-oauth2`, `busbar-migrate`) and the test harnesses. That
//! list is closed by the `busbar-kernel` row of `deny.toml` and the same `tools/ci-checks` test.

use busbar_contract::caps::KernelSeal;

/// A kernel seal. Zero-sized: minting it allocates nothing.
#[must_use]
pub fn acquire() -> KernelSeal {
    busbar_seal::mint_kernel()
}

/// The signing grant, minted with a fresh seal.
#[must_use]
pub fn lend() -> busbar_contract::caps::Grant<busbar_contract::caps::Sign> {
    busbar_contract::caps::Grant::mint(&acquire())
}
