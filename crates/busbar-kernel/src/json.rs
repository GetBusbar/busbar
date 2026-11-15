// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//

use busbar_contract::spans::{exceeds_max_depth, MAX_JSON_DEPTH};

/// Read one JSON document into `T`, numbers in binary64 (`u64`, `i64` or `f64`), as the kernel
/// always has. The workspace's sonic-rs carries `arbitrary_precision` for `busbar_contract::json`,
/// under which sonic's own `from_slice` hands `deserialize_any` (a `serde_json::Value`, an untagged
/// or flattened field) the exact-number token map instead of a number. Exact reads go through the
/// facade.
#[inline]
pub fn parse<'de, T: serde::Deserialize<'de>>(bytes: &'de [u8]) -> Result<T, sonic_rs::Error> {
    if exceeds_max_depth(bytes, MAX_JSON_DEPTH) {
        return sonic_rs::from_slice::<T>(b"");
    }
    // Every byte is checked here: sonic checks UTF-8 only in the strings it decodes.
    let text = std::str::from_utf8(bytes).map_err(|_| refused("invalid UTF-8 in JSON"))?;
    binary64(text)
}

/// [`parse`] for text.
#[inline]
pub fn parse_str<'de, T: serde::Deserialize<'de>>(s: &'de str) -> Result<T, sonic_rs::Error> {
    if exceeds_max_depth(s.as_bytes(), MAX_JSON_DEPTH) {
        return sonic_rs::from_slice::<T>(b"");
    }
    binary64(s)
}

/// One whole document, no `use_rawnumber`: numbers reach `T` in binary64.
fn binary64<'de, T: serde::Deserialize<'de>>(text: &'de str) -> Result<T, sonic_rs::Error> {
    if u32::try_from(text.len()).is_err() {
        return Err(refused("JSON documents above 4 GiB are not read"));
    }
    let mut reader = sonic_rs::Deserializer::from_str(text);
    let value = T::deserialize(&mut reader)?;
    reader.end()?;
    Ok(value)
}

#[cold]
fn refused(message: &str) -> sonic_rs::Error {
    <sonic_rs::Error as serde::de::Error>::custom(message)
}

#[inline]
pub fn to_vec<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, sonic_rs::Error> {
    sonic_rs::to_vec(value)
}

#[inline]
pub fn to_string<T: serde::Serialize>(value: &T) -> Result<String, sonic_rs::Error> {
    sonic_rs::to_string(value)
}

#[inline]
pub fn parse_err_log(bytes_len: usize) -> String {
    crate::cold::host::json_parse_err_log(bytes_len)
}

#[cfg(test)]
#[path = "tests/depth_guard_tests.rs"]
mod depth_guard_tests;

#[cfg(test)]
#[path = "tests/json_sort_keys_tests.rs"]
mod json_sort_keys_tests;
