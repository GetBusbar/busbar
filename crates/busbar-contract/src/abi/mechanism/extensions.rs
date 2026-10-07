// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EXTENSIONS BLOB'S BYTES (THE DESIGN, the shared mechanism: "every operation carries the
//! `extensions` blob"; its extensions rule: absent unless a field is pending, unknown keys ignored;
//! its data-struct evolution rule: a new field lives here first).
//!
//! [`InHead::extensions`](super::call::InHead) and [`OutHead::extensions`](super::call::OutHead)
//! are a [`BLOB_OCTETS`](super::call::BLOB_OCTETS) blob of keyed entries, each
//! `key length (u16, little-endian) | key (UTF-8) | value length (u32, little-endian) | value`, in
//! order. A reader takes the keys it knows and passes over the rest; a key named twice answers its
//! first entry; an entry cut short ends the blob (what came before it still reads). No layout
//! changes: an op that grows a field states it under a key here, and an op that never reads the key
//! is unchanged.

/// The entries `entries` encode to, in order. An entry whose key or value is past its length
/// field's range is left out (no key or value the host states comes near either bound).
#[must_use]
pub fn encode(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (key, value) in entries {
        let (Ok(k), Ok(v)) = (u16::try_from(key.len()), u32::try_from(value.len())) else {
            continue;
        };
        out.extend_from_slice(&k.to_le_bytes());
        out.extend_from_slice(key.as_bytes());
        out.extend_from_slice(&v.to_le_bytes());
        out.extend_from_slice(value);
    }
    out
}

/// Every whole entry of `blob`, in order: `(key, value)`.
pub fn entries(blob: &[u8]) -> impl Iterator<Item = (&[u8], &[u8])> {
    let mut at = 0usize;
    std::iter::from_fn(move || {
        let k = usize::from(u16::from_le_bytes(blob.get(at..at + 2)?.try_into().ok()?));
        let key = blob.get(at + 2..at + 2 + k)?;
        let v_at = at + 2 + k;
        let v = u32::from_le_bytes(blob.get(v_at..v_at + 4)?.try_into().ok()?);
        let v = usize::try_from(v).ok()?;
        let value = blob.get(v_at + 4..(v_at + 4).checked_add(v)?)?;
        at = v_at + 4 + v;
        Some((key, value))
    })
}

/// The value `blob` states under `key` (its first entry so named); `None` when it states none.
#[must_use]
pub fn get<'a>(blob: &'a [u8], key: &str) -> Option<&'a [u8]> {
    entries(blob)
        .find(|(k, _)| *k == key.as_bytes())
        .map(|(_, v)| v)
}

#[cfg(test)]
#[path = "../tests/extensions_tests.rs"]
mod tests;
