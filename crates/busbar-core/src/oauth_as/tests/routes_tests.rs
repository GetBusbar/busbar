// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/oauth_as/routes.rs`.

use super::percent_decode;

/// `percent_decode` runs on a caller-supplied query string and MUST NOT PANIC on one.
///
/// The reachable path is `GET/POST {issuer}/consent` -> `consent_page` -> `client_and_scope_of` ->
/// `form_urlencoded_pairs` -> here. The `return` parameter is only shape-checked by `is_local_path`
/// (leading `/`, no `//`, no `\`); its QUERY STRING is arbitrary UTF-8, and axum's `Query` extractor
/// has already undone the outer percent-encoding by the time this sees it, so a literal multi-byte
/// character genuinely arrives.
///
/// The decoder walked `s.as_bytes()` but then sliced the `&str` — `&s[i + 1..i + 3]`. `i + 1` is
/// always a char boundary (it follows the ASCII `%`), but `i + 3` is not when the byte after the
/// `%` begins a 2-, 3- or 4-byte UTF-8 sequence: the slice lands INSIDE that character and `&str`
/// indexing panics. The workspace is `panic = "unwind"` with no catch-panic layer, so the handler
/// task unwound and the operator got a dropped connection instead of the 400 page the function was
/// about to render.
#[test]
fn percent_decode_never_panics_on_a_multibyte_char_after_a_stray_percent() {
    // One case per UTF-8 length class, since the panic depends on how far past `i + 1` the
    // character's bytes run.
    for probe in ["%€", "%é", "%𝄞", "a=%€&b=1", "%%€", "%e", "%"] {
        let decoded = percent_decode(probe);
        // A stray `%` is kept verbatim (the documented rule: dropping it would let two different
        // query strings decode to one value), so nothing is lost either.
        assert!(
            decoded.contains('%'),
            "a stray `%` must survive decoding verbatim; {probe:?} decoded to {decoded:?}"
        );
    }
}

/// The ordinary decoding contract still holds: real escapes decode, `+` is a space, and a
/// well-formed multi-byte escape sequence round-trips through the UTF-8 reassembly.
#[test]
fn percent_decode_decodes_real_escapes() {
    assert_eq!(percent_decode("a%2Fb"), "a/b");
    assert_eq!(percent_decode("a+b"), "a b");
    assert_eq!(percent_decode("%E2%82%AC"), "€");
    assert_eq!(percent_decode("plain"), "plain");
}
