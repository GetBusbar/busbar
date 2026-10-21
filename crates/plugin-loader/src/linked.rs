// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LINKED DOOR-ROOT DOORS, safely (status row 195; coordinator ruling (a), `BUSBAR-1.6.0.md`
//! l.272-274: the composition root is `forbid(unsafe_code)`). A compiled-in crate the door-root
//! table names (this crate's `[package.metadata.busbar.door-root]`, its edge behind
//! its implicit feature) is admitted ONCE, by `dispatch::load::open_linked` (the one `unsafe` entry,
//! sharing the `dlopen` path's checks), on the first read of this table; the root reaches its door
//! only here, as the [`LoadedDoor`] the loader admitted, or as the loader's refusal: the same
//! [`LoadError`] the same door earns dropped in.

use std::sync::OnceLock;

use crate::dispatch::{LoadError, LoadedDoor};

/// Every door-root crate this build links, its door admitted or refused, read once.
fn rows() -> &'static [(&'static str, Result<LoadedDoor, LoadError>)] {
    static ROWS: OnceLock<Vec<(&'static str, Result<LoadedDoor, LoadError>)>> = OnceLock::new();
    ROWS.get_or_init(crate::dispatch::load::linked_rows)
}

/// The door of door-root crate `krate`, admitted as a dropped-in door is.
///
/// # Errors
///
/// The loader's refusal of its door, or `krate` is no door-root crate this build links.
pub fn door(krate: &str) -> Result<LoadedDoor, LoadError> {
    rows()
        .iter()
        .find(|(k, _)| *k == krate)
        .map(|(_, admitted)| admitted.clone())
        .unwrap_or_else(|| {
            Err(LoadError::NoDoor(format!(
                "`{krate}` is no door-root crate this build links"
            )))
        })
}

/// Every door-root crate this build links, in table order.
#[must_use]
pub fn linked() -> Vec<&'static str> {
    rows().iter().map(|(k, _)| *k).collect()
}

/// Every crate the door-root table names, linked in this build or not.
#[must_use]
pub fn named() -> &'static [&'static str] {
    crate::dispatch::load::DOOR_ROOT_CRATES
}

#[cfg(test)]
#[path = "tests/linked_tests.rs"]
mod tests;
