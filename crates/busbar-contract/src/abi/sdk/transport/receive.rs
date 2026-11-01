// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Framer-owned input still waiting to be consumed or yielded. This optional reply metadata
//! contributes to the host's existing receive backpressure; it grants no authority or new limit.
//! Report after selecting the yield, on READY and PENDING, including zero after draining.
//! Bytes already yielded must not also be counted here. Parser-owned bounded buffers and bodies
//! deliberately collected under an admitted policy's body bound are not unread carrier input.

use crate::abi::mechanism::extensions;

const KEY: &str = "framer.retained_input";

/// Encode the current byte count in the existing reply extensions envelope.
#[must_use]
pub fn encode(bytes: u64) -> Vec<u8> {
    extensions::encode(&[(KEY, &bytes.to_le_bytes())])
}

/// Copy a counter from a reply while its lease is still live. An absent key leaves the previous
/// report unchanged (including during a policy control recall).
///
/// # Errors
/// A present counter that is not exactly one little-endian u64.
pub fn decode(blob: &[u8]) -> Result<Option<u64>, &'static str> {
    extensions::get(blob, KEY)
        .map(|bytes| {
            bytes
                .try_into()
                .map(u64::from_le_bytes)
                .map_err(|_| "invalid framer retained-input count")
        })
        .transpose()
}
