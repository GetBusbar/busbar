// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ROOT LEGACY TABLE (`BUSBAR-1.6.0.md` §2: "Retired names … and migrations for plugins that are
//! not in the build … live in the root legacy table, `[package.metadata.busbar.legacy]`, generated
//! from `plugins.yaml`"). The table in this crate's manifest is the render of `plugins.yaml` (its
//! tests are red on drift) and `build.rs` emits it as [`LEGACY_ROWS`]; [`install`] hands it to the
//! kernel before any configuration is read, as the operator credential's words are handed in.

include!(concat!(env!("OUT_DIR"), "/legacy.rs"));

/// Hand the table to the kernel (`busbar_kernel::config::legacy`). The first install stands.
pub fn install() {
    busbar_kernel::config::legacy::install(LEGACY_ROWS);
}

#[cfg(test)]
#[path = "tests/legacy.rs"]
mod tests;
