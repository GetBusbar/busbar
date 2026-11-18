// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EXTENSIONS BLOB'S BYTES (THE DESIGN, the shared mechanism: "every operation carries the

/// The entries `entries` encode to, in order. An entry whose key or value is past its length
#[must_use]
pub fn encode(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(&mut out, entries);
    out
}

/// [`encode`], appended to `out`: no buffer of its own.
pub fn encode_into(out: &mut Vec<u8>, entries: &[(&str, &[u8])]) {
    for (key, value) in entries {
        let (Ok(k), Ok(v)) = (u16::try_from(key.len()), u32::try_from(value.len())) else {
            continue;
        };
        out.extend_from_slice(&k.to_le_bytes());
        out.extend_from_slice(key.as_bytes());
        out.extend_from_slice(&v.to_le_bytes());
        out.extend_from_slice(value);
    }
}

/// The length of the one entry `key` and `value` encode to: what [`entry`] is sized by.
#[must_use]
pub const fn entry_len(key: &str, value: &[u8]) -> usize {
    2 + key.len() + 4 + value.len()
}

/// ONE ENTRY, built at compile time: the bytes [`encode`] writes for `[(key, value)]`, as an array a
#[must_use]
pub const fn entry<const N: usize>(key: &str, value: &[u8]) -> [u8; N] {
    assert!(N == entry_len(key, value), "N is not entry_len(key, value)");
    assert!(key.len() <= u16::MAX as usize, "the key is past u16");
    assert!(value.len() <= u32::MAX as usize, "the value is past u32");
    let mut out = [0u8; N];
    let k = (key.len() as u16).to_le_bytes();
    out[0] = k[0];
    out[1] = k[1];
    let key = key.as_bytes();
    let mut i = 0;
    while i < key.len() {
        out[2 + i] = key[i];
        i += 1;
    }
    let at = 2 + key.len();
    let v = (value.len() as u32).to_le_bytes();
    let mut i = 0;
    while i < 4 {
        out[at + i] = v[i];
        i += 1;
    }
    let mut i = 0;
    while i < value.len() {
        out[at + 4 + i] = value[i];
        i += 1;
    }
    out
}

pub use busbar_artifact_metadata::extensions::entries;

/// A strict lookup requires complete framing and at most one entry for its key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupError {
    Truncated,
    Duplicate,
}

/// Read one unique entry, rejecting malformed framing anywhere in the blob.
/// Repeated unrelated keys remain the owning feature's responsibility.
pub fn unique<'a>(blob: &'a [u8], key: &str) -> Result<Option<&'a [u8]>, LookupError> {
    let mut read = 0usize;
    let mut found = None;
    for (name, value) in entries(blob) {
        read += 6 + name.len() + value.len();
        if name == key.as_bytes() && found.replace(value).is_some() {
            return Err(LookupError::Duplicate);
        }
    }
    if read != blob.len() {
        return Err(LookupError::Truncated);
    }
    Ok(found)
}

/// Detect a named key even when its value is truncated. Bytes inside values never count.
/// This is feature detection, not framing validation; use [`unique`] before consuming a value.
#[must_use]
pub fn present(mut blob: &[u8], names: &[&str]) -> bool {
    while blob.len() >= 2 {
        let len = usize::from(u16::from_le_bytes([blob[0], blob[1]]));
        let Some(key) = blob.get(2..2 + len) else {
            return false;
        };
        if names.iter().any(|name| key == name.as_bytes()) {
            return true;
        }
        let Some(size) = blob.get(2 + len..6 + len) else {
            return false;
        };
        let size = u32::from_le_bytes(size.try_into().expect("four bytes")) as usize;
        let Some(rest) = (6 + len).checked_add(size).and_then(|end| blob.get(end..)) else {
            return false;
        };
        blob = rest;
    }
    false
}

pub use busbar_artifact_metadata::extensions::{
    get, reference_fields, EXT_DECLARES, EXT_REFERENCE_FIELDS,
};

/// The full span records' key in an export door's `Statement::extensions`.
pub const EXT_SPAN_RECORDS: &str = "span_records";

/// The whole-batch carriage key in an export door's `Statement::extensions`.
pub const EXT_WHOLE_BATCHES: &str = "whole_batches";

pub use crate::export_calls::{EXT_PERSISTENT_ROUTES, EXT_PUBLIC_ROUTES};

/// Read a route-path list from Statement extensions. An absent entry declares none.
pub fn route_paths(extensions: &[u8], key: &str) -> Result<Vec<String>, String> {
    let Some(value) = get(extensions, key) else {
        return Ok(Vec::new());
    };
    let paths: Vec<String> = serde_json::from_slice(value)
        .map_err(|_| format!("extensions.{key} is not a JSON list of route paths"))?;
    for (i, path) in paths.iter().enumerate() {
        if !path.starts_with('/') || path.contains(['?', '#']) || paths[..i].contains(path) {
            return Err(format!(
                "extensions.{key} contains an invalid or repeated route path"
            ));
        }
    }
    Ok(paths)
}

/// Whether a Statement's extensions state the door takes full span records
pub fn span_records(extensions: &[u8]) -> Result<bool, String> {
    get(extensions, EXT_SPAN_RECORDS).map_or(Ok(false), |value| {
        serde_json::from_slice(value)
            .map_err(|_| format!("extensions.{EXT_SPAN_RECORDS} is not a JSON boolean"))
    })
}

/// Whether a Statement's extensions state the door carries each DELIVER as one unit (one request
/// or one write for the whole batch), so no line in a batch waits for another. Absent is false.
pub fn whole_batches(extensions: &[u8]) -> Result<bool, String> {
    match get(extensions, EXT_WHOLE_BATCHES) {
        None | Some(b"false") => Ok(false),
        Some(b"true") => Ok(true),
        Some(_) => Err(format!(
            "extensions.{EXT_WHOLE_BATCHES} is not a JSON boolean"
        )),
    }
}

/// The length of the bytes [`encode`] writes for `entries`: what [`concat`] is sized by.
#[must_use]
pub const fn entries_len(entries: &[(&str, &[u8])]) -> usize {
    let mut n = 0;
    let mut i = 0;
    while i < entries.len() {
        n += entry_len(entries[i].0, entries[i].1);
        i += 1;
    }
    n
}

/// EVERY ENTRY, built at compile time: the bytes [`encode`] writes for `entries`, in order, as an
#[must_use]
pub const fn concat<const N: usize>(entries: &[(&str, &[u8])]) -> [u8; N] {
    assert!(N == entries_len(entries), "N is not entries_len(entries)");
    let mut a = 0;
    while a < entries.len() {
        let mut b = a + 1;
        while b < entries.len() {
            assert!(
                !same_key(entries[a].0, entries[b].0),
                "two Statement extensions entries name one key"
            );
            b += 1;
        }
        a += 1;
    }
    let mut out = [0u8; N];
    let mut at = 0;
    let mut e = 0;
    while e < entries.len() {
        let (key, value) = entries[e];
        assert!(key.len() <= u16::MAX as usize, "the key is past u16");
        assert!(value.len() <= u32::MAX as usize, "the value is past u32");
        let k = (key.len() as u16).to_le_bytes();
        out[at] = k[0];
        out[at + 1] = k[1];
        at += 2;
        let key = key.as_bytes();
        let mut i = 0;
        while i < key.len() {
            out[at + i] = key[i];
            i += 1;
        }
        at += key.len();
        let v = (value.len() as u32).to_le_bytes();
        let mut i = 0;
        while i < 4 {
            out[at + i] = v[i];
            i += 1;
        }
        at += 4;
        let mut i = 0;
        while i < value.len() {
            out[at + i] = value[i];
            i += 1;
        }
        at += value.len();
        e += 1;
    }
    out
}

/// Whether `a` and `b` are one key, byte for byte (`str` equality is not `const`).
const fn same_key(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// `bytes` as a Statement's extensions blob ([`BLOB_OCTETS`](super::call::BLOB_OCTETS)).
#[must_use]
pub const fn statement_blob(bytes: &'static [u8]) -> super::call::Blob {
    super::call::Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt: super::call::BLOB_OCTETS,
        flags: 0,
    }
}

/// The `declares` document a Statement's extensions state under [`EXT_DECLARES`]; `None` when they
#[must_use]
pub fn declares(extensions: &[u8]) -> Option<&[u8]> {
    get(extensions, EXT_DECLARES)
}

/// THE ONE CALL A PLUGIN WRITES ITS STATEMENT'S EXTENSIONS WITH: a `const` [`Blob`] named `$name`
/// holding every `(key, value)` entry, built at compile time, for `Statement::extensions`.
///
/// ```text
/// busbar_contract::statement_extensions!(EXTENSIONS: [
///     (busbar_contract::abi::mechanism::extensions::EXT_DECLARES, include_bytes!("../declares.json")),
/// ]);
/// // ...
/// pub const STATEMENT: Statement = Statement { extensions: EXTENSIONS, ..statement(NAME, VERSION, MAX) };
/// ```
///
/// [`Blob`]: super::call::Blob
#[macro_export]
macro_rules! statement_extensions {
    ($(#[$meta:meta])* $vis:vis $name:ident: [$(($key:expr, $value:expr)),+ $(,)?]) => {
        $(#[$meta])*
        $vis const $name: $crate::abi::mechanism::call::Blob = {
            const BYTES: &[u8] = &$crate::abi::mechanism::extensions::concat::<
                { $crate::abi::mechanism::extensions::entries_len(&[$(($key as &str, $value as &[u8])),+]) },
            >(&[$(($key as &str, $value as &[u8])),+]);
            $crate::abi::mechanism::extensions::statement_blob(BYTES)
        };
    };
}

#[cfg(test)]
#[path = "../tests/extensions_tests.rs"]
mod tests;
