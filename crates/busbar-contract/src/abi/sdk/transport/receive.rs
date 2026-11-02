// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Framer-owned input still waiting to be consumed or yielded. This optional reply metadata

use crate::abi::mechanism::extensions;

const KEY: &str = "framer.retained_input";

/// Encode the current byte count in the existing reply extensions envelope.
#[must_use]
pub fn encode(bytes: u64) -> Vec<u8> {
    extensions::encode(&[(KEY, &bytes.to_le_bytes())])
}

/// Copy a counter from a reply while its lease is still live. An absent key leaves the previous
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
