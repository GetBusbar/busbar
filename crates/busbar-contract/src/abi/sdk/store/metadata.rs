// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Per-open store properties over the existing lifecycle reply-extension carrier. No ABI layout
//! or kind version changes. An older door omitting the property retains its Statement mark.

use crate::abi::mechanism::extensions;

/// The opened store's ephemerality: exactly one byte, `0` durable or `1` ephemeral.
pub const EPHEMERAL: &str = "busbar.store.ephemeral/1";
const INVALID: &str = "store instance returned invalid durability metadata";

/// Metadata for one opened instance, independent of the backend's compile-time capabilities.
#[must_use]
pub fn encode(ephemeral: bool) -> Vec<u8> {
    extensions::encode(&[(EPHEMERAL, &[u8::from(ephemeral)])])
}

/// Decode the optional property, refusing malformed or duplicate answers rather than declaring
/// an unknown instance durable. Unknown well-formed extensions remain forward compatible.
pub fn decode(bytes: &[u8]) -> Result<Option<bool>, &'static str> {
    let mut consumed = 0;
    let mut value = None;
    for (key, data) in extensions::entries(bytes) {
        consumed += 2 + key.len() + 4 + data.len();
        if key != EPHEMERAL.as_bytes() {
            continue;
        }
        if value.is_some() {
            return Err(INVALID);
        }
        value = Some(match data {
            [0] => false,
            [1] => true,
            _ => return Err(INVALID),
        });
    }
    if consumed != bytes.len() {
        return Err(INVALID);
    }
    Ok(value)
}

#[cfg(test)]
#[path = "../tests/store_metadata_tests.rs"]
mod tests;
