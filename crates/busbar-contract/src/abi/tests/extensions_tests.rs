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

/// THE ONE-CALL WRITER (`statement_extensions!` over `concat`): the bytes built at compile time are
/// the bytes `encode` writes for the same entries, the blob states their length as octets, and the
/// `declares` document reads back off them by its key. RED: a writer that drops or reorders an
/// entry, or a reader that misses `EXT_DECLARES`.
#[test]
fn the_statement_extensions_writer_is_encode_at_compile_time() {
    const DECLARES: &[u8] = br#"{"breaker":{"bench_below_trip_threshold":false}}"#;
    const ENTRIES: &[(&str, &[u8])] = &[
        ("other", b"\x01\x02".as_slice()),
        (super::EXT_DECLARES, DECLARES),
    ];
    const BYTES: [u8; super::entries_len(ENTRIES)] = super::concat(ENTRIES);
    assert_eq!(BYTES.as_slice(), encode(ENTRIES).as_slice());
    assert_eq!(super::declares(&BYTES), Some(DECLARES));
    assert_eq!(super::declares(&encode(&[("other", b"x")])), None);
    crate::statement_extensions!(EXT: [
        ("other", b"\x01\x02"),
        (super::EXT_DECLARES, DECLARES),
    ]);
    assert_eq!(EXT.fmt, crate::abi::mechanism::call::BLOB_OCTETS);
    assert_eq!(EXT.len, BYTES.len());
}

/// A MISSING KEY: a blob that states no `declares` entry answers `None` (the Statement states none),
/// beside an empty blob and one whose only entry is another key. RED: a reader that answers the
/// first entry whatever its key.
#[test]
fn a_statement_stating_no_declares_answers_none() {
    assert_eq!(super::declares(&[]), None);
    const ENTRIES: &[(&str, &[u8])] = &[("other", b"{}".as_slice())];
    const BYTES: [u8; super::entries_len(ENTRIES)] = super::concat(ENTRIES);
    assert_eq!(super::declares(&BYTES), None);
    assert_eq!(get(&BYTES, "other"), Some(&b"{}"[..]));
}

/// A DUPLICATE KEY IS REFUSED where the extensions are written: two entries naming one key would
/// leave a reader answering the first and never the second, so the writer refuses them (in a
/// `const`, a compile error; called here at run time, a panic). Distinct keys of one length pass.
/// RED: a writer that encodes both.
#[test]
fn a_duplicate_key_is_refused_by_the_writer() {
    let twice: &[(&str, &[u8])] = &[
        (super::EXT_DECLARES, b"{}".as_slice()),
        (super::EXT_DECLARES, b"{}".as_slice()),
    ];
    let refused = std::panic::catch_unwind(|| super::concat::<{ 2 * (2 + 8 + 4 + 2) }>(twice));
    assert!(refused.is_err(), "a key stated twice must be refused");
    let distinct: &[(&str, &[u8])] = &[("aa", b"1".as_slice()), ("ab", b"2".as_slice())];
    let built = super::concat::<{ 2 * (2 + 2 + 4 + 1) }>(distinct);
    assert_eq!(built.as_slice(), encode(distinct).as_slice());
}
