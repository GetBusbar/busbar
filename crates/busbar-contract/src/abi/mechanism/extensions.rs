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

/// The length of the one entry `key` and `value` encode to: what [`entry`] is sized by.
#[must_use]
pub const fn entry_len(key: &str, value: &[u8]) -> usize {
    2 + key.len() + 4 + value.len()
}

/// ONE ENTRY, built at compile time: the bytes [`encode`] writes for `[(key, value)]`, as an array a
/// `'static` Statement can point at (a door's `Statement::extensions` is `const` data).
///
/// # Panics
///
/// `N` is not [`entry_len`] of `key` and `value`, or either is past its length field's range; in a
/// `const`, that is a compile error.
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

/// THE `declares` DOCUMENT'S KEY in a door's `Statement::extensions` (ARCHITECT ruling 2026-10-21
/// on the door-only gaps; BUSBAR-1.6.0.md l.246, the One Statement table: the Statement's `declares`
/// row is "metric series, diagnostics, structured answers", diagnostics in full; l.3574's
/// "diagnostic ids" is the indexed view of the same document). The WHOLE document travels here as a
/// JSON payload (catalog entries, metric families with `shed`, the disk need of the host's bounded disk lane (the Q-DISK ruling),
/// `breaker`), read ONCE at load and never per request ("JSON only as a payload"). It rides the
/// shared mechanism's extensions blob, not a `repr(C)` field: a field would change the Statement's
/// layout and its ABI version. `contract_abi` is not part of it: the Statement's own `kind_abi`
/// states the version. A linked row and a dropped-in copy are read by the same code off the same
/// Statement bytes (Part 2 #2 rule (1)).
pub const EXT_DECLARES: &str = "declares";

/// THE REFERENCE-CAPABLE, NOT-SECRET SETTINGS FIELDS' KEY in a door's `Statement::extensions` (lead
/// ruling item 7a). Its value is a JSON list of `.`-separated settings paths (`*` = any key or index,
/// as in [`crate::secret_fields`]): at such a path a secret reference (`{env:}`, `{file:}`,
/// `{module:}`) is resolved IN PLACE to its string, and a literal passes as written. The value is
/// never a secret: it is never lent, and no literal is refused there. A path the Statement's
/// `secret_refs` also names is a contradiction, refused at load. It rides the extensions blob, not
/// a `repr(C)` field, so the Statement's layout and its ABI version are unchanged; it is rendered
/// and signed with the rest of the blob.
pub const EXT_REFERENCE_FIELDS: &str = "reference_fields";

/// The reference-capable paths a Statement's extensions state under [`EXT_REFERENCE_FIELDS`];
/// empty when they state none.
///
/// # Errors
///
/// The value is not a JSON list of non-empty strings.
pub fn reference_fields(extensions: &[u8]) -> Result<Vec<String>, String> {
    let Some(value) = get(extensions, EXT_REFERENCE_FIELDS) else {
        return Ok(Vec::new());
    };
    let paths: Vec<String> = serde_json::from_slice(value).map_err(|_| {
        format!("extensions.{EXT_REFERENCE_FIELDS} is not a JSON list of settings paths")
    })?;
    if paths.iter().any(String::is_empty) {
        return Err(format!(
            "extensions.{EXT_REFERENCE_FIELDS} names an empty settings path"
        ));
    }
    Ok(paths)
}

/// THE FULL SPAN RECORDS' KEY in an export door's `Statement::extensions` (status row 173). Its
/// value is the JSON `true` when the door takes each `traces` line's full span record as its
/// reserved `span` member (everything the previous release's exporter sent for a span: attributes,
/// events, status), whatever `fields:` selected; `false`, or no entry, takes none. It rides the
/// extensions blob, not a `repr(C)` field, so the Statement's layout and its ABI version are
/// unchanged; it is rendered and signed with the rest of the blob.
pub const EXT_SPAN_RECORDS: &str = "span_records";

/// Whether a Statement's extensions state the door takes full span records
/// ([`EXT_SPAN_RECORDS`]); `false` when they state nothing.
///
/// # Errors
///
/// The value is not a JSON boolean.
pub fn span_records(extensions: &[u8]) -> Result<bool, String> {
    get(extensions, EXT_SPAN_RECORDS).map_or(Ok(false), |value| {
        serde_json::from_slice(value)
            .map_err(|_| format!("extensions.{EXT_SPAN_RECORDS} is not a JSON boolean"))
    })
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
/// array a `'static` Statement can point at. [`crate::statement_extensions!`] is the one call that
/// sizes and builds it.
///
/// # Panics
///
/// `N` is not [`entries_len`] of `entries`, two entries name one key (a reader would answer the
/// first and never see the second, so a Statement that states a key twice is refused where it is
/// written), or a key or value is past its length field's range; in a `const`, each is a compile
/// error.
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
/// state none.
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
