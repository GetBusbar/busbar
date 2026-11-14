// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Explicit migration into an empty Store overlay, never a runtime file fallback.

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(in crate::config) struct Receipt {
    pub(in crate::config) version: u32,
    pub(in crate::config) source_sha256: [u8; 32],
    pub(in crate::config) overlay_sha256: [u8; 32],
}

pub(in crate::config) fn check_receipt(bytes: &[u8], expected: &Receipt) -> Result<(), String> {
    let receipt: Receipt =
        serde_json::from_slice(bytes).map_err(|_| "overlay migration receipt is unreadable")?;
    if &receipt != expected {
        return Err("overlay migration source or converted configuration differs from the committed receipt".into());
    }
    Ok(())
}

pub(in crate::config) fn canonicalize(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            let ordered: std::collections::BTreeMap<_, _> =
                std::mem::take(map).into_iter().collect();
            for (key, mut child) in ordered {
                canonicalize(&mut child);
                map.insert(key, child);
            }
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(canonicalize),
        _ => {}
    }
}

#[cfg(test)]
#[path = "tests/overlay_import_tests.rs"]
mod tests;
