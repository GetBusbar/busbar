// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::{encode, entries, entry, entry_len, get};

/// A SCOPE ROUND-TRIPS: what the host encodes under a key reads back byte for byte, beside a key
/// the reader does not know (passed over), and a key named twice answers its first entry.
#[test]
fn a_scope_round_trips_beside_keys_the_reader_does_not_know() {
    let blob = encode(&[
        ("unknown", b"\x00\x01binary"),
        (crate::abi::auth::EXT_SCOPE, b"fs_read_file fs_write_file"),
        (crate::abi::auth::EXT_SCOPE, b"second"),
    ]);
    assert_eq!(
        get(&blob, crate::abi::auth::EXT_SCOPE),
        Some(&b"fs_read_file fs_write_file"[..])
    );
    assert_eq!(get(&blob, "unknown"), Some(&b"\x00\x01binary"[..]));
    assert_eq!(get(&blob, "absent"), None);
    assert_eq!(entries(&blob).count(), 3);
    // An empty value is a stated value, not an absent one.
    let empty = encode(&[(crate::abi::auth::EXT_SCOPE, b"")]);
    assert_eq!(get(&empty, crate::abi::auth::EXT_SCOPE), Some(&b""[..]));
    assert_eq!(get(&[], crate::abi::auth::EXT_SCOPE), None);
}

/// AN ENTRY CUT SHORT ENDS THE BLOB: what came before it still reads, nothing past it is invented.
#[test]
fn an_entry_cut_short_ends_the_blob() {
    let mut blob = encode(&[("a", b"one"), ("b", b"two")]);
    blob.truncate(blob.len() - 1);
    assert_eq!(get(&blob, "a"), Some(&b"one"[..]));
    assert_eq!(get(&blob, "b"), None);
    assert_eq!(entries(&[0xff]).count(), 0);
}

/// AN ENTRY BUILT AT COMPILE TIME is the entry `encode` writes: a `const` Statement's extensions read
/// back exactly as a host-encoded blob does.
#[test]
fn an_entry_built_at_compile_time_is_the_encoded_entry() {
    const KEY: &str = "shape";
    const VALUE: &[u8] = b"{\"a\":1}";
    const BLOB: [u8; entry_len(KEY, VALUE)] = entry(KEY, VALUE);
    assert_eq!(BLOB.to_vec(), encode(&[(KEY, VALUE)]));
    assert_eq!(get(&BLOB, KEY), Some(VALUE));
    let empty: [u8; entry_len("e", b"")] = entry("e", b"");
    assert_eq!(get(&empty, "e"), Some(&b""[..]));
}
